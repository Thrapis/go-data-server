package main

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestParseCIDRs(t *testing.T) {
	nets, err := parseCIDRs(" 10.9.0.0/24 , fd00::/64,192.0.2.7 ,, ")
	if err != nil || len(nets) != 3 {
		t.Fatalf("parseCIDRs = %v, %v; want 3 prefixes", nets, err)
	}
	for _, addr := range []string{"10.9.0.200", "fd00::1", "192.0.2.7", "::ffff:10.9.0.1"} {
		if !containsAddr(nets, netip.MustParseAddr(addr)) {
			t.Errorf("%s should be allowed", addr)
		}
	}
	for _, addr := range []string{"10.9.1.1", "192.0.2.8", "fd01::1", "2001:db8::1"} {
		if containsAddr(nets, netip.MustParseAddr(addr)) {
			t.Errorf("%s should not be allowed", addr)
		}
	}
	for _, bad := range []string{"nonsense", "10.9.0.0/33", "10.9.0.0/24;10.8.0.0/24", "example.com"} {
		if _, err := parseCIDRs(bad); err == nil {
			t.Errorf("parseCIDRs(%q) succeeded, want an error", bad)
		}
	}
	if nets, err := parseCIDRs("  "); err != nil || len(nets) != 0 {
		t.Errorf("parseCIDRs(blank) = %v, %v; want empty", nets, err)
	}
}

func TestUIIsServedToAllowedNetworks(t *testing.T) {
	h := newHandler(newTestConfig(t))

	for path, wantType := range map[string]string{
		"/ui":             "text/html",
		"/ui/":            "text/html",
		"/ui/app.js":      "text/javascript",
		"/ui/style.css":   "text/css",
		"/ui/favicon.svg": "image/svg+xml",
	} {
		rec := do(h, "GET", path, "", from(vpnAddr))
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), wantType) || rec.Body.Len() == 0 {
			t.Errorf("GET %s = %d %q (%d bytes)", path, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("GET %s CSP = %q", path, csp)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("GET %s headers = %v", path, rec.Header())
		}
	}

	if rec := do(h, "GET", "/ui/nope.js", "", from(vpnAddr)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown asset = %d, want 404", rec.Code)
	}
	if rec := do(h, "GET", "/", "", from(vpnAddr)); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/ui" {
		t.Errorf("GET / = %d -> %q, want redirect to /ui", rec.Code, rec.Header().Get("Location"))
	}
}

func TestUIHTMLHasNoInlineCodeOrStyle(t *testing.T) {
	rec := do(newHandler(newTestConfig(t)), "GET", "/ui", "", from(vpnAddr))
	page := strings.ToLower(rec.Body.String())
	for _, banned := range []string{" onclick=", " onload=", " style=", "javascript:"} {
		if strings.Contains(page, banned) {
			t.Errorf("index.html contains %q, which the CSP would block", banned)
		}
	}
	if strings.Contains(page, "<script>") || strings.Contains(page, "<style>") {
		t.Error("index.html has inline <script>/<style>, which the CSP would block")
	}
	if !strings.Contains(page, `rel="icon"`) || !strings.Contains(page, "/ui/favicon.svg") {
		t.Error("index.html does not link the favicon")
	}
}

func TestFaviconIsAnSVGWithoutScript(t *testing.T) {
	rec := do(newHandler(newTestConfig(t)), "GET", "/ui/favicon.svg", "", from(vpnAddr))
	body := strings.ToLower(rec.Body.String())
	if !strings.HasPrefix(strings.TrimSpace(body), "<svg") || strings.Contains(body, "<script") {
		t.Errorf("favicon is not a plain SVG: %.80s", body)
	}
}

func TestUIIsNotFoundOutsideAllowedNetworks(t *testing.T) {
	h := newHandler(newTestConfig(t))
	for _, path := range []string{"/", "/ui", "/ui/", "/ui/app.js", "/ui/style.css"} {
		if rec := do(h, "GET", path, "", from(outsideAddr)); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s from outside = %d, want 404", path, rec.Code)
		}
	}
	if rec := do(h, "GET", "/healthz", "", from(outsideAddr)); rec.Code != http.StatusOK {
		t.Errorf("healthz from outside = %d, want 200", rec.Code)
	}
}

func TestUIDisabled(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.UI = false
	h := newHandler(cfg)
	for _, path := range []string{"/", "/ui", "/ui/app.js"} {
		if rec := do(h, "GET", path, "", from(vpnAddr)); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s with UI disabled = %d, want 404", path, rec.Code)
		}
	}
}
