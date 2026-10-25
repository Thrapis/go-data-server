package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrPrecondition = errors.New("precondition failed")
	ErrInvalid      = errors.New("invalid app or key")
	ErrConflict     = errors.New("key conflicts with an existing key")
)

const maxKeyLen = 512

// These are literal /api routes, so an app with one of these names could never be reached.
var reservedApps = map[string]bool{"whoami": true, "system": true}

var (
	appRe = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	segRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func validApp(app string) bool { return appRe.MatchString(app) && !reservedApps[app] }

// validKey allows "/"-separated segments of [A-Za-z0-9._-], none of them "." or "..".
// That keeps every key inside its app's directory.
func validKey(key string) bool {
	if key == "" || len(key) > maxKeyLen {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." || !segRe.MatchString(seg) {
			return false
		}
	}
	return true
}

// Meta describes a stored blob. ETag is the quoted sha256 of the body.
type Meta struct {
	Key         string    `json:"key,omitempty"` // filled in by List only
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
	ETag        string    `json:"etag"`
	Modified    time.Time `json:"modified"`
}

// Cond carries the If-Match / If-None-Match preconditions of a write.
type Cond struct {
	IfMatch        string // "" = none; "*" = must exist; otherwise an ETag list
	IfNoneMatchAny bool   // If-None-Match: * — create only
}

// Store keeps blobs on disk as <root>/<app>/blobs/<key>, with a metadata file at
// <root>/<app>/meta/<key>.json and uploads staged in <root>/<app>/tmp.
type Store struct {
	root string
	mu   sync.Mutex // serialises the check-then-replace part of Put and Delete
}

func NewStore(root string) *Store { return &Store{root: root} }

func (s *Store) blobPath(app, key string) string {
	return filepath.Join(s.root, app, "blobs", filepath.FromSlash(key))
}

func (s *Store) metaPath(app, key string) string {
	return filepath.Join(s.root, app, "meta", filepath.FromSlash(key)+".json")
}

func (s *Store) readMeta(app, key string) (Meta, error) {
	b, err := os.ReadFile(s.metaPath(app, key))
	if errors.Is(err, fs.ErrNotExist) {
		return Meta{}, ErrNotFound
	}
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("corrupt metadata for %s/%s: %w", app, key, err)
	}
	return m, nil
}

// Put streams body into a temp file while hashing it, then swaps it into place.
// Only the final check-and-rename holds the lock, so slow uploads don't block others.
// A failed or aborted upload leaves the previous version untouched.
func (s *Store) Put(app, key, contentType string, body io.Reader, c Cond) (Meta, bool, error) {
	if !validApp(app) || !validKey(key) {
		return Meta{}, false, ErrInvalid
	}
	tmpDir := filepath.Join(s.root, app, "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return Meta{}, false, err
	}
	tmp, err := os.CreateTemp(tmpDir, "upload-*.tmp")
	if err != nil {
		return Meta{}, false, err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed

	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, sum), body)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Meta{}, false, fmt.Errorf("receive body: %w", err)
	}

	m := Meta{
		Size:        n,
		ContentType: contentType,
		ETag:        `"` + hex.EncodeToString(sum.Sum(nil)) + `"`,
		Modified:    time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	old, err := s.readMeta(app, key)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Meta{}, false, err
	}
	if c.IfNoneMatchAny && exists {
		return Meta{}, false, ErrPrecondition
	}
	if c.IfMatch != "" && (!exists || !etagMatches(c.IfMatch, old.ETag)) {
		return Meta{}, false, ErrPrecondition
	}
	if err := s.checkConflict(app, key); err != nil {
		return Meta{}, false, err
	}

	blob := s.blobPath(app, key)
	if err := os.MkdirAll(filepath.Dir(blob), 0o700); err != nil {
		return Meta{}, false, err
	}
	if err := os.Rename(tmp.Name(), blob); err != nil {
		return Meta{}, false, err
	}
	meta, err := json.Marshal(m)
	if err != nil {
		return Meta{}, false, err
	}
	if err := writeAtomic(s.metaPath(app, key), meta); err != nil {
		return Meta{}, false, err
	}
	return m, !exists, nil
}

// checkConflict refuses a key that would need a file to also be a directory
// ("a" together with "a/b").
func (s *Store) checkConflict(app, key string) error {
	p := filepath.Join(s.root, app, "blobs")
	parts := strings.Split(key, "/")
	for i, seg := range parts {
		p = filepath.Join(p, seg)
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		last := i == len(parts)-1
		if (last && fi.IsDir()) || (!last && !fi.IsDir()) {
			return ErrConflict
		}
	}
	return nil
}

// Open returns the metadata and an open blob. The caller closes the file.
func (s *Store) Open(app, key string) (Meta, *os.File, error) {
	if !validApp(app) || !validKey(key) {
		return Meta{}, nil, ErrInvalid
	}
	m, err := s.readMeta(app, key)
	if err != nil {
		return Meta{}, nil, err
	}
	f, err := os.Open(s.blobPath(app, key))
	if errors.Is(err, fs.ErrNotExist) {
		return Meta{}, nil, ErrNotFound
	}
	if err != nil {
		return Meta{}, nil, err
	}
	return m, f, nil
}

func (s *Store) Delete(app, key, ifMatch string) error {
	if !validApp(app) || !validKey(key) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	m, err := s.readMeta(app, key)
	if err != nil {
		return err
	}
	if ifMatch != "" && !etagMatches(ifMatch, m.ETag) {
		return ErrPrecondition
	}
	blob, meta := s.blobPath(app, key), s.metaPath(app, key)
	if err := os.Remove(blob); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Remove(meta); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	pruneEmptyDirs(filepath.Dir(blob), filepath.Join(s.root, app, "blobs"))
	pruneEmptyDirs(filepath.Dir(meta), filepath.Join(s.root, app, "meta"))
	return nil
}

// pruneEmptyDirs removes dir and its parents up to (not including) stop, while they are empty.
func pruneEmptyDirs(dir, stop string) {
	for dir != stop && strings.HasPrefix(dir, stop) {
		if os.Remove(dir) != nil { // fails once a directory is not empty
			return
		}
		dir = filepath.Dir(dir)
	}
}

// List returns the app's blobs whose key starts with prefix, sorted by key.
func (s *Store) List(app, prefix string) ([]Meta, error) {
	if !validApp(app) {
		return nil, ErrInvalid
	}
	out := []Meta{}
	root := filepath.Join(s.root, app, "meta")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil // directories, and any half-written *.tmp files
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		key := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		if !strings.HasPrefix(key, prefix) {
			return nil
		}
		m, err := s.readMeta(app, key)
		if err != nil {
			log.Printf("list %s: skipping %s: %v", app, key, err)
			return nil
		}
		m.Key = key
		out = append(out, m)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Apps lists the apps that have a data directory, sorted.
func (s *Store) Apps() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	apps := []string{}
	for _, e := range entries {
		if e.IsDir() && validApp(e.Name()) {
			apps = append(apps, e.Name())
		}
	}
	sort.Strings(apps)
	return apps, nil
}

// Usage counts the stored blobs and their total size across all apps.
func (s *Store) Usage() (files int, bytes int64, err error) {
	apps, err := s.Apps()
	if err != nil {
		return 0, 0, err
	}
	for _, app := range apps {
		items, err := s.List(app, "")
		if err != nil {
			return 0, 0, err
		}
		for _, m := range items {
			files++
			bytes += m.Size
		}
	}
	return files, bytes, nil
}

// etagMatches reports whether header (an If-Match style list, or "*") matches etag.
// Weak validators ("W/...") are compared by their opaque tag.
func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "W/")
		if part == "*" || part == etag {
			return true
		}
	}
	return false
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
