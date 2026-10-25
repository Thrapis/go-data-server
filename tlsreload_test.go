package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert writes a self-signed certificate for 127.0.0.1 with the given serial
// and returns it, so tests can tell which one a server is presenting.
func writeCert(t *testing.T, certFile, keyFile string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// serveTLS accepts TLS connections using only GetCertificate (no static Certificates,
// exactly like main.go) and returns the listener's address.
func serveTLS(t *testing.T, r *certReloader) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

func servedSerial(t *testing.T, addr string) int64 {
	t.Helper()
	// No ServerName: clients connecting to a bare IP send no SNI.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func TestCertReloaderServesNewCertificateWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile, 1)

	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveTLS(t, r)

	if got := servedSerial(t, addr); got != 1 {
		t.Fatalf("initial serial = %d, want 1", got)
	}
	if changed, err := r.refresh(); changed || err != nil {
		t.Errorf("refresh with unchanged files = %v, %v; want false, nil", changed, err)
	}

	writeCert(t, certFile, keyFile, 2)
	if changed, err := r.refresh(); !changed || err != nil {
		t.Fatalf("refresh after swap = %v, %v; want true, nil", changed, err)
	}
	if got := servedSerial(t, addr); got != 2 {
		t.Errorf("serial after reload = %d, want 2", got)
	}
}

func TestCertReloaderKeepsOldCertificateWhenNewFilesAreBroken(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile, 1)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := r.refresh(); changed || err == nil {
		t.Fatalf("refresh with a corrupt file = %v, %v; want false and an error", changed, err)
	}
	cert, err := r.GetCertificate(nil)
	if err != nil || cert.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("after failed reload GetCertificate = %v, %v; want the old certificate", cert, err)
	}
	if changed, err := r.refresh(); changed || err != nil {
		t.Errorf("same broken files again = %v, %v; want false, nil (reported once)", changed, err)
	}

	writeCert(t, certFile, keyFile, 3)
	if changed, err := r.refresh(); !changed || err != nil {
		t.Fatalf("refresh after repair = %v, %v; want true, nil", changed, err)
	}
	if cert, _ := r.GetCertificate(nil); cert.Leaf.SerialNumber.Int64() != 3 {
		t.Errorf("serial after repair = %d, want 3", cert.Leaf.SerialNumber.Int64())
	}
}

func TestNewCertReloaderFailsWithoutValidFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCertReloader(filepath.Join(dir, "nope.pem"), filepath.Join(dir, "nope.key")); err == nil {
		t.Error("newCertReloader with missing files succeeded, want an error")
	}
}

func TestCertExpiresSoon(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile, 1) // valid for one hour
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !r.expiresWithin(48 * time.Hour) {
		t.Error("a certificate with an hour left should count as expiring within 48h")
	}
	if r.expiresWithin(time.Minute) {
		t.Error("a certificate with an hour left should not expire within a minute")
	}
}
