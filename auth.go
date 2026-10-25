package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync/atomic"
)

// adminApp is the reserved name of the token that may manage every app (from allowed networks only).
const adminApp = "_admin"

// AppTokens maps app names to the sha256 of their bearer token. The file only ever
// holds hashes, so it can't be turned back into tokens. It can be swapped at runtime.
type AppTokens struct {
	hashes atomic.Pointer[map[string][32]byte]
}

// ParseAppTokens reads lines of "<app> <sha256-hex>"; blank lines and #-comments are skipped.
func ParseAppTokens(r io.Reader) (*AppTokens, error) {
	hashes, err := parseHashes(r)
	if err != nil {
		return nil, err
	}
	t := &AppTokens{}
	t.hashes.Store(&hashes)
	return t, nil
}

func parseHashes(r io.Reader) (map[string][32]byte, error) {
	hashes := map[string][32]byte{}
	seen := map[[32]byte]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: want \"<app> <sha256-hex>\"", n)
		}
		app, hexSum := fields[0], fields[1]
		if app != adminApp && !validApp(app) {
			return nil, fmt.Errorf("line %d: invalid app name %q", n, app)
		}
		raw, err := hex.DecodeString(hexSum)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("line %d: %q is not a sha256 hex digest", n, hexSum)
		}
		var sum [32]byte
		copy(sum[:], raw)
		if _, dup := hashes[app]; dup {
			return nil, fmt.Errorf("line %d: app %q listed twice", n, app)
		}
		if other, dup := seen[sum]; dup {
			return nil, fmt.Errorf("line %d: apps %q and %q share a token", n, other, app)
		}
		hashes[app] = sum
		seen[sum] = app
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

// LoadAppTokens reads path; Reload re-reads it, keeping the old tokens if the new file is bad.
func LoadAppTokens(path string) (*AppTokens, error) {
	t := &AppTokens{}
	if err := t.Reload(path); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *AppTokens) Reload(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hashes, err := parseHashes(f)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	t.hashes.Store(&hashes)
	return nil
}

// Lookup returns the app a token belongs to. It checks every entry so the time taken
// doesn't reveal which one matched.
func (t *AppTokens) Lookup(token string) (string, bool) {
	sum := sha256.Sum256([]byte(token))
	var match string
	var found bool
	for app, h := range *t.hashes.Load() {
		if subtle.ConstantTimeCompare(sum[:], h[:]) == 1 {
			match, found = app, true
		}
	}
	return match, found
}

// Names lists the regular apps (not _admin) that have a token, sorted.
func (t *AppTokens) Names() []string {
	names := []string{}
	for app := range *t.hashes.Load() {
		if app != adminApp {
			names = append(names, app)
		}
	}
	sort.Strings(names)
	return names
}

// newToken returns a random 256-bit hex token and the hash to store in the apps file.
func newToken() (token, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}
