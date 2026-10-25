package main

import (
	"encoding/json"
	"errors"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"sort"
	"strings"
	"time"
)

// transferTimeout is how long a single upload or download may take. The server-wide
// timeouts stay short; blob handlers extend their own deadlines.
const transferTimeout = 5 * time.Minute

type Config struct {
	Store     *Store
	Tokens    *AppTokens
	MaxBody   int64
	UI        bool           // serve the /ui web interface
	AllowNets []netip.Prefix // networks allowed to use the UI and the _admin token
}

func newHandler(c *Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /api/whoami", c.whoami)
	mux.HandleFunc("GET /api/system", c.system)
	mux.HandleFunc("GET /api/{app}", c.appRoute(c.list))
	mux.HandleFunc("GET /api/{app}/{key...}", c.appRoute(c.get)) // also answers HEAD
	mux.HandleFunc("PUT /api/{app}/{key...}", c.appRoute(c.put))
	mux.HandleFunc("DELETE /api/{app}/{key...}", c.appRoute(c.del))
	if c.UI {
		c.registerUI(mux)
	}
	return logRequests(mux)
}

type principal struct {
	app   string
	admin bool
}

func (p principal) can(app string) bool { return p.admin || p.app == app }

// authenticate checks the bearer token. The _admin token is only honoured from the
// allowed networks; from anywhere else it is treated like a wrong token.
func (c *Config) authenticate(r *http.Request) (principal, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return principal{}, false
	}
	app, ok := c.Tokens.Lookup(token)
	if !ok {
		return principal{}, false
	}
	if app == adminApp {
		if !c.fromAllowedNet(r) {
			return principal{}, false
		}
		return principal{admin: true}, true
	}
	return principal{app: app}, true
}

func (c *Config) appRoute(next func(w http.ResponseWriter, r *http.Request, app string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app := r.PathValue("app")
		if p, ok := c.authenticate(r); !ok || !p.can(app) {
			writeJSON(w, http.StatusUnauthorized, errorBody("invalid or missing token"))
			return
		}
		next(w, r, app)
	}
}

func (c *Config) whoami(w http.ResponseWriter, r *http.Request) {
	p, ok := c.authenticate(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid or missing token"))
		return
	}
	out := struct {
		Admin   bool     `json:"admin"`
		App     *string  `json:"app"`
		Apps    []string `json:"apps"`
		MaxBody int64    `json:"max_body"`
	}{Admin: p.admin, Apps: []string{p.app}, MaxBody: c.MaxBody}
	if p.admin {
		stored, err := c.Store.Apps()
		if err != nil {
			c.fail(w, err)
			return
		}
		// Apps with a token but no data yet are listed too, so the UI can upload the first blob.
		set := map[string]bool{}
		for _, a := range append(c.Tokens.Names(), stored...) {
			set[a] = true
		}
		out.Apps = out.Apps[:0]
		for a := range set {
			out.Apps = append(out.Apps, a)
		}
		sort.Strings(out.Apps)
	} else {
		out.App = &p.app
	}
	body, _ := json.Marshal(out)
	writeJSON(w, http.StatusOK, body)
}

// system reports how full the machine's disk is and how much the apps have stored.
// Admin only (so, from the allowed networks only).
func (c *Config) system(w http.ResponseWriter, r *http.Request) {
	if p, ok := c.authenticate(r); !ok || !p.admin {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid or missing token"))
		return
	}
	files, bytes, err := c.Store.Usage()
	if err != nil {
		c.fail(w, err)
		return
	}
	type disk struct {
		Free  uint64 `json:"free"`
		Total uint64 `json:"total"`
	}
	out := struct {
		Disk        *disk `json:"disk"` // null where the platform can't tell
		StoredBytes int64 `json:"stored_bytes"`
		StoredFiles int   `json:"stored_files"`
	}{StoredBytes: bytes, StoredFiles: files}
	if free, total, err := diskUsage(c.Store.root); err == nil {
		out.Disk = &disk{Free: free, Total: total}
	} else {
		log.Printf("disk usage of %s: %v", c.Store.root, err)
	}
	body, _ := json.Marshal(out)
	writeJSON(w, http.StatusOK, body)
}

func (c *Config) list(w http.ResponseWriter, r *http.Request, app string) {
	items, err := c.Store.List(app, r.URL.Query().Get("prefix"))
	if err != nil {
		c.fail(w, err)
		return
	}
	body, _ := json.Marshal(items)
	writeJSON(w, http.StatusOK, body)
}

func (c *Config) get(w http.ResponseWriter, r *http.Request, app string) {
	key := r.PathValue("key")
	m, f, err := c.Store.Open(app, key)
	if err != nil {
		c.fail(w, err)
		return
	}
	defer f.Close()

	h := w.Header()
	h.Set("Content-Type", m.ContentType)
	h.Set("ETag", m.ETag)
	h.Set("Cache-Control", "private, no-cache")
	// Stored files are untrusted: stop them running script or being sniffed as HTML
	// in this origin, which is where the web UI keeps its token.
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox")
	if r.URL.Query().Get("download") == "1" {
		h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(key)}))
	}
	extendDeadlines(w)
	http.ServeContent(w, r, "", m.Modified, f) // handles HEAD, If-None-Match and Range
}

func (c *Config) put(w http.ResponseWriter, r *http.Request, app string) {
	key := r.PathValue("key")
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	} else if _, _, err := mime.ParseMediaType(contentType); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid Content-Type"))
		return
	}
	if r.ContentLength > c.MaxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody("body too large"))
		return
	}
	extendDeadlines(w)
	cond := Cond{
		IfMatch:        strings.TrimSpace(r.Header.Get("If-Match")),
		IfNoneMatchAny: strings.TrimSpace(r.Header.Get("If-None-Match")) == "*",
	}
	m, created, err := c.Store.Put(app, key, contentType, http.MaxBytesReader(w, r.Body, c.MaxBody), cond)
	if err != nil {
		c.fail(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.Header().Set("ETag", m.ETag)
	body, _ := json.Marshal(struct {
		ETag string `json:"etag"`
		Size int64  `json:"size"`
	}{m.ETag, m.Size})
	writeJSON(w, status, body)
}

func (c *Config) del(w http.ResponseWriter, r *http.Request, app string) {
	if err := c.Store.Delete(app, r.PathValue("key"), strings.TrimSpace(r.Header.Get("If-Match"))); err != nil {
		c.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// fail maps store and transfer errors to HTTP responses; anything else is a 500.
func (c *Config) fail(w http.ResponseWriter, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.Is(err, ErrInvalid):
		writeJSON(w, http.StatusBadRequest, errorBody("invalid app or key"))
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorBody("not found"))
	case errors.Is(err, ErrPrecondition):
		writeJSON(w, http.StatusPreconditionFailed, errorBody("precondition failed"))
	case errors.Is(err, ErrConflict):
		writeJSON(w, http.StatusConflict, errorBody(err.Error()))
	case errors.As(err, &tooBig):
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody("body too large"))
	default:
		log.Printf("internal error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorBody("internal error"))
	}
}

// extendDeadlines gives one transfer more time than the server-wide timeouts allow.
// ResponseWriters that can't do this (e.g. test recorders) are left alone.
func extendDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(transferTimeout)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func errorBody(msg string) []byte {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return b
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the real writer (for transfer deadlines).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
