package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
)

//go:embed ui/index.html ui/app.js ui/style.css ui/favicon.svg
var uiFS embed.FS

var uiAssets = map[string]struct{ file, contentType string }{
	"index.html":  {"ui/index.html", "text/html; charset=utf-8"},
	"app.js":      {"ui/app.js", "text/javascript; charset=utf-8"},
	"style.css":   {"ui/style.css", "text/css; charset=utf-8"},
	"favicon.svg": {"ui/favicon.svg", "image/svg+xml"},
}

// No inline script or style anywhere, so nothing but our own files can run in the page.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
	"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

func (c *Config) registerUI(mux *http.ServeMux) {
	index := c.uiGate(c.serveAsset("index.html"))
	mux.HandleFunc("GET /{$}", c.uiGate(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	}))
	mux.HandleFunc("GET /ui", index)
	mux.HandleFunc("GET /ui/{$}", index)
	mux.HandleFunc("GET /ui/{name}", c.uiGate(func(w http.ResponseWriter, r *http.Request) {
		c.serveAsset(r.PathValue("name"))(w, r)
	}))
}

func (c *Config) serveAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		asset, ok := uiAssets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := uiFS.ReadFile(asset.file)
		if err != nil {
			log.Printf("ui asset %s: %v", name, err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h := w.Header()
		h.Set("Content-Type", asset.contentType)
		h.Set("Content-Security-Policy", uiCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}

// uiGate answers 404 to anyone outside the allowed networks, so the UI is not
// even visible from the internet. The refused address is logged to help configure the list.
func (c *Config) uiGate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !c.fromAllowedNet(r) {
			log.Printf("ui denied from %s", r.RemoteAddr)
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// fromAllowedNet checks the TCP peer address. No proxy headers are trusted: nothing
// sits in front of this server, and a header would be trivial to forge.
func (c *Config) fromAllowedNet(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return containsAddr(c.AllowNets, ap.Addr())
}

func containsAddr(nets []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap() // an IPv4 peer on a dual-stack socket arrives as ::ffff:a.b.c.d
	for _, p := range nets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseCIDRs reads a comma-separated list of networks; a bare address means that single host.
func parseCIDRs(s string) ([]netip.Prefix, error) {
	var nets []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			nets = append(nets, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not a network (like 10.8.1.0/24) or an address", part)
		}
		nets = append(nets, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return nets, nil
}
