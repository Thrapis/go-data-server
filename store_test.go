package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir())
}

func mustPut(t *testing.T, s *Store, app, key, ct, body string) Meta {
	t.Helper()
	m, _, err := s.Put(app, key, ct, strings.NewReader(body), Cond{})
	if err != nil {
		t.Fatalf("Put(%s/%s): %v", app, key, err)
	}
	return m
}

func readAll(t *testing.T, s *Store, app, key string) (Meta, string) {
	t.Helper()
	m, f, err := s.Open(app, key)
	if err != nil {
		t.Fatalf("Open(%s/%s): %v", app, key, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return m, string(b)
}

func TestPutThenOpenRoundTripsBodyAndMetadata(t *testing.T) {
	s := newTestStore(t)
	sum := sha256.Sum256([]byte("hello"))
	wantETag := `"` + hex.EncodeToString(sum[:]) + `"`

	m, created, err := s.Put("alpha", "dir/file.txt", "text/plain", strings.NewReader("hello"), Cond{})
	if err != nil || !created {
		t.Fatalf("Put = created %v, err %v", created, err)
	}
	if m.ETag != wantETag || m.Size != 5 || m.ContentType != "text/plain" {
		t.Fatalf("meta = %+v", m)
	}
	got, body := readAll(t, s, "alpha", "dir/file.txt")
	if body != "hello" || got.ETag != wantETag || got.ContentType != "text/plain" {
		t.Fatalf("Open = %q %+v", body, got)
	}
}

func TestPutOverwriteIsNotCreated(t *testing.T) {
	s := newTestStore(t)
	mustPut(t, s, "alpha", "k", "text/plain", "one")
	_, created, err := s.Put("alpha", "k", "text/plain", strings.NewReader("two"), Cond{})
	if err != nil || created {
		t.Fatalf("overwrite = created %v, err %v", created, err)
	}
	if _, body := readAll(t, s, "alpha", "k"); body != "two" {
		t.Fatalf("body = %q", body)
	}
}

func TestPutPreconditions(t *testing.T) {
	s := newTestStore(t)
	first := mustPut(t, s, "alpha", "k", "text/plain", "one")

	if _, _, err := s.Put("alpha", "k", "text/plain", strings.NewReader("x"), Cond{IfNoneMatchAny: true}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("create-only on existing key = %v, want ErrPrecondition", err)
	}
	if _, _, err := s.Put("alpha", "new", "text/plain", strings.NewReader("x"), Cond{IfNoneMatchAny: true}); err != nil {
		t.Errorf("create-only on new key = %v", err)
	}
	if _, _, err := s.Put("alpha", "k", "text/plain", strings.NewReader("x"), Cond{IfMatch: `"nope"`}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("wrong If-Match = %v, want ErrPrecondition", err)
	}
	if _, _, err := s.Put("alpha", "missing", "text/plain", strings.NewReader("x"), Cond{IfMatch: first.ETag}); !errors.Is(err, ErrPrecondition) {
		t.Errorf("If-Match on missing key = %v, want ErrPrecondition", err)
	}
	if _, _, err := s.Put("alpha", "k", "text/plain", strings.NewReader("two"), Cond{IfMatch: first.ETag}); err != nil {
		t.Errorf("right If-Match = %v", err)
	}
	if _, body := readAll(t, s, "alpha", "k"); body != "two" {
		t.Errorf("body after precondition tests = %q", body)
	}
}

type failingReader struct{ n int }

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, errors.New("connection reset")
	}
	k := min(len(p), r.n)
	r.n -= k
	return k, nil
}

func TestFailedUploadLeavesNothingBehind(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Put("alpha", "k", "text/plain", &failingReader{n: 100}, Cond{}); err == nil {
		t.Fatal("Put with failing body succeeded")
	}
	if _, _, err := s.Open("alpha", "k"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open after failed upload = %v, want ErrNotFound", err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, "alpha", "tmp"))
	if len(entries) != 0 {
		t.Errorf("stray temp files: %v", entries)
	}
}

func TestFailedUploadKeepsPreviousVersion(t *testing.T) {
	s := newTestStore(t)
	mustPut(t, s, "alpha", "k", "text/plain", "keep me")
	if _, _, err := s.Put("alpha", "k", "text/plain", &failingReader{n: 10}, Cond{}); err == nil {
		t.Fatal("Put with failing body succeeded")
	}
	if _, body := readAll(t, s, "alpha", "k"); body != "keep me" {
		t.Errorf("body = %q, want the previous version", body)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	m := mustPut(t, s, "alpha", "a/b/c.txt", "text/plain", "x")

	if err := s.Delete("alpha", "a/b/c.txt", `"nope"`); !errors.Is(err, ErrPrecondition) {
		t.Errorf("wrong If-Match = %v, want ErrPrecondition", err)
	}
	if err := s.Delete("alpha", "a/b/c.txt", m.ETag); err != nil {
		t.Fatalf("Delete = %v", err)
	}
	if err := s.Delete("alpha", "a/b/c.txt", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete = %v, want ErrNotFound", err)
	}
	if _, _, err := s.Open("alpha", "a/b/c.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Open after Delete = %v, want ErrNotFound", err)
	}
	if _, err := os.Stat(filepath.Join(s.root, "alpha", "blobs", "a")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("empty parent directories were not pruned: %v", err)
	}
}

func TestListFiltersByPrefixAndSorts(t *testing.T) {
	s := newTestStore(t)
	mustPut(t, s, "alpha", "b.txt", "text/plain", "1")
	mustPut(t, s, "alpha", "logs/2.txt", "text/plain", "22")
	mustPut(t, s, "alpha", "logs/1.txt", "text/plain", "333")
	mustPut(t, s, "beta", "other", "text/plain", "x")

	all, err := s.List("alpha", "")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, m := range all {
		keys = append(keys, m.Key)
	}
	if got := strings.Join(keys, ","); got != "b.txt,logs/1.txt,logs/2.txt" {
		t.Errorf("keys = %s", got)
	}
	logs, _ := s.List("alpha", "logs/")
	if len(logs) != 2 || logs[0].Size != 3 {
		t.Errorf("prefix list = %+v", logs)
	}
	none, err := s.List("gamma", "")
	if err != nil || none == nil || len(none) != 0 {
		t.Errorf("list of unknown app = %v, %v; want empty non-nil slice", none, err)
	}
}

func TestAppsListsDirectoriesWithData(t *testing.T) {
	s := newTestStore(t)
	mustPut(t, s, "beta", "k", "text/plain", "x")
	mustPut(t, s, "alpha", "k", "text/plain", "x")
	got, err := s.Apps()
	if err != nil || strings.Join(got, ",") != "alpha,beta" {
		t.Errorf("Apps = %v, %v", got, err)
	}
}

func TestValidation(t *testing.T) {
	for _, app := range []string{"alpha", "a-1", strings.Repeat("a", 64)} {
		if !validApp(app) {
			t.Errorf("validApp(%q) = false", app)
		}
	}
	for _, app := range []string{"", "Alpha", "a_b", "a/b", "..", "_admin", "whoami", "system", strings.Repeat("a", 65)} {
		if validApp(app) {
			t.Errorf("validApp(%q) = true", app)
		}
	}
	for _, key := range []string{"a", "a/b", "dir/file.txt", ".hidden", "a-b_c.d", strings.Repeat("a", 512)} {
		if !validKey(key) {
			t.Errorf("validKey(%q) = false", key)
		}
	}
	for _, key := range []string{"", "/abs", "a//b", "a/", "../x", "a/../b", "a/./b", ".", "..", "a b", "a\\b", "a\x00b", "é", strings.Repeat("a", 513)} {
		if validKey(key) {
			t.Errorf("validKey(%q) = true", key)
		}
	}
}

func TestStoreRejectsInvalidAppsAndKeys(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.Put("alpha", "../escape", "text/plain", strings.NewReader("x"), Cond{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Put traversal = %v, want ErrInvalid", err)
	}
	if _, _, err := s.Open("Bad_App", "k"); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open bad app = %v, want ErrInvalid", err)
	}
	if err := s.Delete("alpha", "a/../b", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("Delete traversal = %v, want ErrInvalid", err)
	}
	if _, err := s.List("Bad_App", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("List bad app = %v, want ErrInvalid", err)
	}
}

func TestKeyCannotBeBothFileAndDirectory(t *testing.T) {
	s := newTestStore(t)
	mustPut(t, s, "alpha", "a", "text/plain", "file")
	if _, _, err := s.Put("alpha", "a/b", "text/plain", strings.NewReader("x"), Cond{}); !errors.Is(err, ErrConflict) {
		t.Errorf("a/b under file a = %v, want ErrConflict", err)
	}
	mustPut(t, s, "alpha", "d/e", "text/plain", "x")
	if _, _, err := s.Put("alpha", "d", "text/plain", strings.NewReader("x"), Cond{}); !errors.Is(err, ErrConflict) {
		t.Errorf("d over directory d = %v, want ErrConflict", err)
	}
}
