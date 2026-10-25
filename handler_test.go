package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

const (
	vpnAddr      = "10.9.0.5"  // inside the allowed network
	outsideAddr  = "192.0.2.1" // httptest's default peer, outside it
	maxTestBody  = 1024
	alphaToken   = "alpha-token"
	betaToken    = "beta-token"
	adminToken   = "admin-token"
	contentPlain = "text/plain"
)

func newTestConfig(t *testing.T) *Config {
	t.Helper()
	src := "alpha " + hashOf(alphaToken) + "\nbeta " + hashOf(betaToken) + "\n_admin " + hashOf(adminToken) + "\n"
	tokens, err := ParseAppTokens(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	nets, err := parseCIDRs("10.9.0.0/24,fd00::/64")
	if err != nil {
		t.Fatal(err)
	}
	return &Config{Store: NewStore(t.TempDir()), Tokens: tokens, MaxBody: maxTestBody, UI: true, AllowNets: nets}
}

type reqOpt func(*http.Request)

func bearer(token string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func header(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }

func from(addr string) reqOpt {
	return func(r *http.Request) { r.RemoteAddr = netip.AddrPortFrom(netip.MustParseAddr(addr), 5555).String() }
}

func do(h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func putAs(t *testing.T, h http.Handler, token, path, body string) string {
	t.Helper()
	rec := do(h, "PUT", path, body, bearer(token), header("Content-Type", contentPlain), from(vpnAddr))
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("PUT %s = %d %s", path, rec.Code, rec.Body)
	}
	var out struct{ ETag string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ETag == "" {
		t.Fatalf("PUT body = %s (%v)", rec.Body, err)
	}
	return out.ETag
}

func TestHealthzNeedsNoToken(t *testing.T) {
	h := newHandler(newTestConfig(t))
	if rec := do(h, "GET", "/healthz", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("healthz = %d %s", rec.Code, rec.Body)
	}
}

func TestAppRoutesRequireTheAppsOwnToken(t *testing.T) {
	h := newHandler(newTestConfig(t))
	for _, auth := range []reqOpt{
		func(*http.Request) {},
		bearer("wrong"),
		bearer(betaToken), // valid, but for another app
		header("Authorization", alphaToken),
		header("Authorization", "Basic YWxwaGE6eA=="),
	} {
		for _, route := range [][2]string{{"GET", "/api/alpha"}, {"GET", "/api/alpha/k"}, {"HEAD", "/api/alpha/k"}, {"PUT", "/api/alpha/k"}, {"DELETE", "/api/alpha/k"}} {
			if rec := do(h, route[0], route[1], "x", auth); rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s = %d, want 401", route[0], route[1], rec.Code)
			}
		}
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	h := newHandler(newTestConfig(t))

	rec := do(h, "PUT", "/api/alpha/dir/file.txt", "hello", bearer(alphaToken), header("Content-Type", contentPlain))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first PUT = %d %s", rec.Code, rec.Body)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" || !strings.Contains(rec.Body.String(), "etag") {
		t.Fatalf("PUT response lacks an etag: %v %s", rec.Header(), rec.Body)
	}

	get := do(h, "GET", "/api/alpha/dir/file.txt", "", bearer(alphaToken))
	if get.Code != http.StatusOK || get.Body.String() != "hello" || get.Header().Get("ETag") != etag || get.Header().Get("Content-Type") != contentPlain {
		t.Fatalf("GET = %d %q headers %v", get.Code, get.Body, get.Header())
	}

	if rec := do(h, "PUT", "/api/alpha/dir/file.txt", "hello again", bearer(alphaToken)); rec.Code != http.StatusOK {
		t.Errorf("overwriting PUT = %d, want 200", rec.Code)
	}
	if get := do(h, "GET", "/api/alpha/dir/file.txt", "", bearer(alphaToken)); get.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("default Content-Type = %q", get.Header().Get("Content-Type"))
	}
	if get := do(h, "GET", "/api/alpha/missing", "", bearer(alphaToken)); get.Code != http.StatusNotFound {
		t.Errorf("GET missing = %d, want 404", get.Code)
	}
}

func TestBlobResponsesCannotRunScriptInOurOrigin(t *testing.T) {
	h := newHandler(newTestConfig(t))
	putAs(t, h, alphaToken, "/api/alpha/page.html", "<script>alert(1)</script>")

	rec := do(h, "GET", "/api/alpha/page.html", "", bearer(alphaToken))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Errorf("blob headers = %v, want nosniff and CSP sandbox", rec.Header())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("Content-Disposition without ?download = %q", cd)
	}

	dl := do(h, "GET", "/api/alpha/page.html?download=1", "", bearer(alphaToken))
	if cd := dl.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "page.html") {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestHeadAndConditionalGet(t *testing.T) {
	h := newHandler(newTestConfig(t))
	etag := putAs(t, h, alphaToken, "/api/alpha/k", "hello")

	head := do(h, "HEAD", "/api/alpha/k", "", bearer(alphaToken))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("ETag") != etag {
		t.Errorf("HEAD = %d body %q headers %v", head.Code, head.Body, head.Header())
	}
	if rec := do(h, "GET", "/api/alpha/k", "", bearer(alphaToken), header("If-None-Match", etag)); rec.Code != http.StatusNotModified {
		t.Errorf("GET with matching If-None-Match = %d, want 304", rec.Code)
	}
	if rec := do(h, "GET", "/api/alpha/k", "", bearer(alphaToken), header("If-None-Match", `"other"`)); rec.Code != http.StatusOK {
		t.Errorf("GET with other If-None-Match = %d, want 200", rec.Code)
	}
}

func TestPutPreconditionsOverHTTP(t *testing.T) {
	h := newHandler(newTestConfig(t))
	etag := putAs(t, h, alphaToken, "/api/alpha/k", "one")

	cases := []struct {
		name string
		opt  reqOpt
		path string
		want int
	}{
		{"create-only on existing", header("If-None-Match", "*"), "/api/alpha/k", http.StatusPreconditionFailed},
		{"create-only on new", header("If-None-Match", "*"), "/api/alpha/new", http.StatusCreated},
		{"wrong If-Match", header("If-Match", `"nope"`), "/api/alpha/k", http.StatusPreconditionFailed},
		{"If-Match on missing", header("If-Match", etag), "/api/alpha/gone", http.StatusPreconditionFailed},
		{"right If-Match", header("If-Match", etag), "/api/alpha/k", http.StatusOK},
	}
	for _, c := range cases {
		if rec := do(h, "PUT", c.path, "two", bearer(alphaToken), c.opt); rec.Code != c.want {
			t.Errorf("%s = %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestDeleteOverHTTP(t *testing.T) {
	h := newHandler(newTestConfig(t))
	etag := putAs(t, h, alphaToken, "/api/alpha/k", "x")

	if rec := do(h, "DELETE", "/api/alpha/k", "", bearer(alphaToken), header("If-Match", `"nope"`)); rec.Code != http.StatusPreconditionFailed {
		t.Errorf("DELETE with wrong If-Match = %d, want 412", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/alpha/k", "", bearer(alphaToken), header("If-Match", etag)); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE = %d, want 204", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/alpha/k", "", bearer(alphaToken)); rec.Code != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", rec.Code)
	}
}

func TestListOverHTTP(t *testing.T) {
	h := newHandler(newTestConfig(t))

	empty := do(h, "GET", "/api/alpha", "", bearer(alphaToken))
	if empty.Code != http.StatusOK || strings.TrimSpace(empty.Body.String()) != "[]" {
		t.Fatalf("empty list = %d %q, want []", empty.Code, empty.Body)
	}

	putAs(t, h, alphaToken, "/api/alpha/logs/1.txt", "a")
	putAs(t, h, alphaToken, "/api/alpha/logs/2.txt", "bb")
	putAs(t, h, alphaToken, "/api/alpha/top.txt", "ccc")

	rec := do(h, "GET", "/api/alpha?prefix=logs/", "", bearer(alphaToken))
	var items []struct {
		Key         string `json:"key"`
		Size        int64  `json:"size"`
		ContentType string `json:"content_type"`
		ETag        string `json:"etag"`
		Modified    string `json:"modified"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil {
		t.Fatalf("list body %s: %v", rec.Body, err)
	}
	if len(items) != 2 || items[0].Key != "logs/1.txt" || items[1].Size != 2 || items[0].ETag == "" || items[0].Modified == "" || items[0].ContentType != contentPlain {
		t.Errorf("items = %+v", items)
	}
}

func TestInvalidInputIsRejected(t *testing.T) {
	h := newHandler(newTestConfig(t))
	for _, path := range []string{"/api/alpha/", "/api/alpha/a%20b", "/api/alpha/a%00b", "/api/alpha/%C3%A9", "/api/alpha/a%5Cb"} {
		if rec := do(h, "PUT", path, "x", bearer(alphaToken)); rec.Code != http.StatusBadRequest {
			t.Errorf("PUT %s = %d, want 400", path, rec.Code)
		}
	}
	if rec := do(h, "PUT", "/api/Bad_App/k", "x", bearer(adminToken), from(vpnAddr)); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT to invalid app name = %d, want 400", rec.Code)
	}
	if rec := do(h, "PUT", "/api/alpha/k", "x", bearer(alphaToken), header("Content-Type", "not a media type")); rec.Code != http.StatusBadRequest {
		t.Errorf("PUT with bad Content-Type = %d, want 400", rec.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	cfg := newTestConfig(t)
	h := newHandler(cfg)
	big := strings.Repeat("x", maxTestBody+1)

	if rec := do(h, "PUT", "/api/alpha/big", big, bearer(alphaToken)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared oversize = %d, want 413", rec.Code)
	}
	unknownLength := httptest.NewRequest("PUT", "/api/alpha/big2", strings.NewReader(big))
	unknownLength.ContentLength = -1
	unknownLength.Header.Set("Authorization", "Bearer "+alphaToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, unknownLength)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("undeclared oversize = %d, want 413", rec.Code)
	}

	if rec := do(h, "GET", "/api/alpha", "", bearer(alphaToken)); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("oversize uploads left data behind: %s", rec.Body)
	}
	if rec := do(h, "PUT", "/api/alpha/exact", strings.Repeat("x", maxTestBody), bearer(alphaToken)); rec.Code != http.StatusCreated {
		t.Errorf("upload of exactly the limit = %d, want 201", rec.Code)
	}
}

func TestAdminTokenWorksOnEveryAppButOnlyFromAllowedNetworks(t *testing.T) {
	h := newHandler(newTestConfig(t))

	for i, addr := range []string{vpnAddr, "fd00::5", "::ffff:10.9.0.5"} {
		for _, app := range []string{"alpha", "beta"} {
			path := fmt.Sprintf("/api/%s/k%d", app, i) // a fresh key each time, so every PUT creates
			if rec := do(h, "PUT", path, "x", bearer(adminToken), from(addr)); rec.Code != http.StatusCreated {
				t.Errorf("admin PUT %s from %s = %d, want 201", path, addr, rec.Code)
			}
			if rec := do(h, "GET", "/api/"+app, "", bearer(adminToken), from(addr)); rec.Code != http.StatusOK {
				t.Errorf("admin list %s from %s = %d, want 200", app, addr, rec.Code)
			}
		}
	}

	for _, addr := range []string{outsideAddr, "2001:db8::1", "10.9.1.5"} {
		if rec := do(h, "GET", "/api/alpha", "", bearer(adminToken), from(addr)); rec.Code != http.StatusUnauthorized {
			t.Errorf("admin from %s = %d, want 401", addr, rec.Code)
		}
	}
	if rec := do(h, "GET", "/api/alpha", "", bearer(alphaToken), from(outsideAddr)); rec.Code != http.StatusOK {
		t.Errorf("app token from outside = %d, want 200 (apps must work from anywhere)", rec.Code)
	}
}

func TestWhoami(t *testing.T) {
	cfg := newTestConfig(t)
	h := newHandler(cfg)
	putAs(t, h, adminToken, "/api/gamma/k", "x") // a data directory with no token

	type who struct {
		Admin   bool     `json:"admin"`
		App     *string  `json:"app"`
		Apps    []string `json:"apps"`
		MaxBody int64    `json:"max_body"`
	}
	get := func(opts ...reqOpt) (int, who) {
		rec := do(h, "GET", "/api/whoami", "", opts...)
		var w who
		_ = json.Unmarshal(rec.Body.Bytes(), &w)
		return rec.Code, w
	}

	code, w := get(bearer(alphaToken), from(outsideAddr))
	if code != 200 || w.Admin || w.App == nil || *w.App != "alpha" || strings.Join(w.Apps, ",") != "alpha" || w.MaxBody != maxTestBody {
		t.Errorf("app whoami = %d %+v", code, w)
	}
	code, w = get(bearer(adminToken), from(vpnAddr))
	if code != 200 || !w.Admin || w.App != nil || strings.Join(w.Apps, ",") != "alpha,beta,gamma" {
		t.Errorf("admin whoami = %d %+v, want admin with apps alpha,beta,gamma", code, w)
	}
	if code, _ := get(bearer(adminToken), from(outsideAddr)); code != http.StatusUnauthorized {
		t.Errorf("admin whoami from outside = %d, want 401", code)
	}
	if code, _ := get(bearer("wrong")); code != http.StatusUnauthorized {
		t.Errorf("wrong token whoami = %d, want 401", code)
	}
	if code, _ := get(); code != http.StatusUnauthorized {
		t.Errorf("no token whoami = %d, want 401", code)
	}
}
