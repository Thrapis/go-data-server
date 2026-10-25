package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func TestStoreUsageSumsAllApps(t *testing.T) {
	s := newTestStore(t)
	if files, bytes, err := s.Usage(); err != nil || files != 0 || bytes != 0 {
		t.Fatalf("Usage of an empty store = %d files, %d bytes, %v; want zeros", files, bytes, err)
	}
	mustPut(t, s, "alpha", "k1", "text/plain", "12345")
	mustPut(t, s, "alpha", "dir/k2", "text/plain", "123")
	mustPut(t, s, "beta", "k", "text/plain", "1234567")

	files, bytes, err := s.Usage()
	if err != nil || files != 3 || bytes != 15 {
		t.Errorf("Usage = %d files, %d bytes, %v; want 3 files, 15 bytes", files, bytes, err)
	}
}

func TestDiskUsageOfAnExistingDirectory(t *testing.T) {
	free, total, err := diskUsage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || free > total {
		t.Errorf("diskUsage = free %d, total %d; want 0 < total and free <= total", free, total)
	}
	if _, _, err := diskUsage(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("diskUsage of a missing directory succeeded, want an error")
	}
}

func TestSystemInfoIsAdminOnly(t *testing.T) {
	h := newHandler(newTestConfig(t))
	putAs(t, h, adminToken, "/api/alpha/a", "12345")
	putAs(t, h, adminToken, "/api/beta/b", "123")

	rec := do(h, "GET", "/api/system", "", bearer(adminToken), from(vpnAddr))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /api/system = %d %s", rec.Code, rec.Body)
	}
	var info struct {
		Disk *struct {
			Free  uint64 `json:"free"`
			Total uint64 `json:"total"`
		} `json:"disk"`
		StoredBytes int64 `json:"stored_bytes"`
		StoredFiles int   `json:"stored_files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("body %s: %v", rec.Body, err)
	}
	if info.Disk == nil || info.Disk.Total == 0 || info.Disk.Free > info.Disk.Total {
		t.Errorf("disk = %+v, want a total and a free size", info.Disk)
	}
	if info.StoredBytes != 8 || info.StoredFiles != 2 {
		t.Errorf("stored = %d bytes in %d files, want 8 in 2", info.StoredBytes, info.StoredFiles)
	}

	for name, opts := range map[string][]reqOpt{
		"app token":          {bearer(alphaToken), from(vpnAddr)},
		"admin from outside": {bearer(adminToken), from(outsideAddr)},
		"wrong token":        {bearer("wrong"), from(vpnAddr)},
		"no token":           {from(vpnAddr)},
	} {
		if rec := do(h, "GET", "/api/system", "", opts...); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: GET /api/system = %d, want 401", name, rec.Code)
		}
	}
}
