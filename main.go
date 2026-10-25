// go-data-server: a small key-value/blob store that several projects can share.
//
// Each app gets its own token and its own key space under /api/{app}/{key...}. HTTPS uses
// a certificate file that something else (lego) renews; the server reloads it on change.
// A built-in web page at /ui manages the stored data, from allowed networks only.
// Standard library only.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultAddr      = "127.0.0.1:9696"
	defaultMaxBody   = 50 << 20
	defaultAllowCIDR = "127.0.0.0/8,::1/128" // loopback only: the UI works through an SSH tunnel
	certCheckEvery   = time.Minute
)

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	if len(os.Args) > 1 {
		if os.Args[1] != "newtoken" {
			fmt.Fprintf(os.Stderr, "usage: %s [newtoken <app>]\n", os.Args[0])
			os.Exit(2)
		}
		if err := runNewToken(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		return
	}
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// runNewToken prints a fresh token once, with the line to add to the apps file.
func runNewToken(args []string) error {
	if len(args) != 1 || (args[0] != adminApp && !validApp(args[0])) {
		return fmt.Errorf("usage: newtoken <app>   (app: a-z, 0-9 and -, up to 64 characters; or %s)", adminApp)
	}
	token, hash, err := newToken()
	if err != nil {
		return err
	}
	fmt.Printf("token (shown once, give it to the app):\n%s\n\nline for the apps file:\n%s %s\n", token, args[0], hash)
	return nil
}

func run() error {
	addr := getenv("DATA_ADDR", defaultAddr)
	dataDir := getenv("DATA_DIR", "./data")
	appsFile := getenv("DATA_APPS_FILE", "./apps")
	certFile, keyFile := os.Getenv("DATA_TLS_CERT"), os.Getenv("DATA_TLS_KEY")
	useTLS := certFile != "" && keyFile != ""
	if (certFile == "") != (keyFile == "") {
		return errors.New("DATA_TLS_CERT and DATA_TLS_KEY must be set together")
	}

	maxBody := int64(defaultMaxBody)
	if v := os.Getenv("DATA_MAX_BODY"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return fmt.Errorf("DATA_MAX_BODY must be a positive number of bytes, got %q", v)
		}
		maxBody = n
	}
	allowNets, err := parseCIDRs(getenv("DATA_UI_ALLOW_CIDR", defaultAllowCIDR))
	if err != nil {
		return fmt.Errorf("DATA_UI_ALLOW_CIDR: %w", err)
	}

	if !useTLS && !isLoopback(addr) && os.Getenv("DATA_ALLOW_INSECURE") != "1" {
		return fmt.Errorf("refusing to serve plain HTTP on %s: tokens would cross the network unencrypted. "+
			"Set DATA_TLS_CERT and DATA_TLS_KEY, or DATA_ALLOW_INSECURE=1 if you really mean it", addr)
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	tokens, err := LoadAppTokens(appsFile)
	if err != nil {
		return fmt.Errorf("load apps file: %w", err)
	}
	if len(tokens.Names()) == 0 {
		log.Printf("warning: %s lists no apps yet; create one with `newtoken <app>`", appsFile)
	}

	cfg := &Config{
		Store:     NewStore(dataDir),
		Tokens:    tokens,
		MaxBody:   maxBody,
		UI:        getenv("DATA_UI", "1") != "0",
		AllowNets: allowNets,
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           newHandler(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second, // blob handlers extend this for their own transfer
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var reloader *certReloader
	if useTLS {
		reloader, err = newCertReloader(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("load certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{GetCertificate: reloader.GetCertificate, MinVersion: tls.VersionTLS12}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if reloader != nil {
		go reloader.Run(ctx, certCheckEvery)
	}

	// SIGHUP (systemctl reload) re-reads the apps file and checks the certificate now.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := tokens.Reload(appsFile); err != nil {
				log.Printf("apps file not reloaded, keeping the old tokens: %v", err)
			} else {
				log.Printf("apps file reloaded: %d apps", len(tokens.Names()))
			}
			if reloader != nil {
				reloader.check()
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Printf("go-data-server listening on %s://%s, data in %s, UI %v (allowed from %v)", scheme, addr, dataDir, cfg.UI, allowNets)
	if useTLS {
		err = srv.ListenAndServeTLS("", "") // certificates come from TLSConfig.GetCertificate
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// isLoopback reports whether addr (host:port) only accepts connections from this machine.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
