package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// certReloader serves the certificate lego writes to disk and picks up renewals
// without a restart. A bad new file never replaces a working certificate.
type certReloader struct {
	certFile, keyFile string
	cur               atomic.Pointer[tls.Certificate]

	mu       sync.Mutex // guards the fields below
	lastSum  [sha256.Size]byte
	badSum   [sha256.Size]byte
	lastWarn time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.refresh(); err != nil {
		return nil, err
	}
	if r.cur.Load() == nil {
		return nil, fmt.Errorf("no certificate loaded from %s", certFile)
	}
	return r, nil
}

// refresh reloads the files if their content changed. It returns true when a new
// certificate is now being served. A broken pair is reported once, not every minute.
func (r *certReloader) refresh() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certPEM, err := os.ReadFile(r.certFile)
	if err != nil {
		return false, err
	}
	keyPEM, err := os.ReadFile(r.keyFile)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(bytes.Join([][]byte{certPEM, keyPEM}, []byte{0}))
	if r.cur.Load() != nil && sum == r.lastSum {
		return false, nil
	}
	if sum == r.badSum {
		return false, nil
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	}
	if err != nil {
		r.badSum = sum
		return false, fmt.Errorf("load %s: %w", r.certFile, err)
	}
	r.cur.Store(&cert)
	r.lastSum = sum
	return true, nil
}

// GetCertificate ignores the client's SNI: browsers and HTTP clients send none when
// the URL is a bare IP address, and the one certificate covers that address.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cur.Load(), nil
}

func (r *certReloader) expiresWithin(d time.Duration) bool {
	return time.Until(r.cur.Load().Leaf.NotAfter) < d
}

// Run checks for renewed files every interval until ctx ends, and warns when the
// certificate is close to expiring, which means renewal has stopped working.
func (r *certReloader) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.check()
		}
	}
}

// check is also what SIGHUP triggers.
func (r *certReloader) check() {
	changed, err := r.refresh()
	switch {
	case err != nil:
		log.Printf("certificate reload failed, keeping the current one: %v", err)
	case changed:
		log.Printf("certificate reloaded, valid until %s", r.cur.Load().Leaf.NotAfter.Format(time.RFC3339))
	}
	if r.expiresWithin(48 * time.Hour) {
		r.mu.Lock()
		warn := time.Since(r.lastWarn) > time.Hour
		if warn {
			r.lastWarn = time.Now()
		}
		r.mu.Unlock()
		if warn {
			log.Printf("WARNING: certificate expires %s; is the lego renewal job running?", r.cur.Load().Leaf.NotAfter.Format(time.RFC3339))
		}
	}
}
