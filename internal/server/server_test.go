package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func newTestHandler(t *testing.T, auth Credentials) http.Handler {
	t.Helper()
	return newTestHandlerWithMaxBody(t, auth, 1<<20)
}

func newTestHandlerWithUploadLimit(t *testing.T, limit int) http.Handler {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := cache.New(blobs, meta)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	return New(Config{Cache: c, Metrics: m, Registry: reg, MaxBodyBytes: 1 << 20, MaxConcurrentUploads: limit})
}

func newTestHandlerWithMaxBody(t *testing.T, auth Credentials, maxBody int64) http.Handler {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := cache.New(blobs, meta)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	return New(Config{Cache: c, Metrics: m, Registry: reg, Auth: auth, MaxBodyBytes: maxBody})
}

// mustReq builds a request and fails the test on error.
func mustReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}

// doReq sends req, fails the test on transport error, and registers the
// response body to be closed at test cleanup — so every call site gets a
// checked Close without repeating the boilerplate.
func doReq(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	t.Cleanup(func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	})
	return resp
}

func TestPutThenGetRoundTrip(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/mykey", "hello"))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201", resp.StatusCode)
	}

	resp = doReq(t, mustReq(t, http.MethodGet, srv.URL+"/mykey", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	buf := make([]byte, 5)
	n, _ := resp.Body.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Fatalf("body = %q, want hello", buf[:n])
	}
}

func TestGetMissingReturns404(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/nope", ""))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestHeadReportsExistenceAndSize(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", "abcde"))

	resp := doReq(t, mustReq(t, http.MethodHead, srv.URL+"/k", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", resp.StatusCode)
	}
	if resp.ContentLength != 5 {
		t.Fatalf("Content-Length = %d, want 5", resp.ContentLength)
	}

	resp = doReq(t, mustReq(t, http.MethodHead, srv.URL+"/missing", ""))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD missing status = %d, want 404", resp.StatusCode)
	}
}

func TestBasicAuthRequiredWhenConfigured(t *testing.T) {
	h := newTestHandler(t, Credentials{Username: "maven", Password: "s3cret"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// No credentials -> 401.
	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/k", ""))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET status = %d, want 401", resp.StatusCode)
	}

	// Wrong credentials -> 401.
	req := mustReq(t, http.MethodGet, srv.URL+"/k", "")
	req.SetBasicAuth("maven", "wrong")
	resp = doReq(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-password GET status = %d, want 401", resp.StatusCode)
	}

	// Correct credentials on PUT then GET -> success.
	req = mustReq(t, http.MethodPut, srv.URL+"/k", "v")
	req.SetBasicAuth("maven", "s3cret")
	resp = doReq(t, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("authenticated PUT status = %d, want 201", resp.StatusCode)
	}
}

func TestAuthDisabledWhenCredentialsEmpty(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/anything", ""))
	// No auth configured: request reaches the cache handler and gets a
	// normal 404 for a missing key, never a 401.
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (auth should be a no-op)", resp.StatusCode)
	}
}

func TestInvalidKeyReturns400(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/..%2f..%2fetc%2fpasswd", "x"))
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		// Go's net/http cleans ".." out of the URL path before the handler
		// ever sees it (net/url path cleaning), so this may resolve to a
		// different, still-invalid path rather than reach our validator
		// directly. Either a 400 from our validator or the mux's own
		// not-found handling for a cleaned/redirected path is acceptable;
		// what must never happen is a 200/201.
		t.Fatalf("status = %d, want 400 or 404", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodDelete, srv.URL+"/k", ""))
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestHealthzUnauthenticated(t *testing.T) {
	h := newTestHandler(t, Credentials{Username: "u", Password: "p"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/healthz", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (healthz must not require auth)", resp.StatusCode)
	}
}

func TestMetricsEndpointExposesFscacheMetrics(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", "v"))
	doReq(t, mustReq(t, http.MethodGet, srv.URL+"/k", ""))

	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/metrics", ""))
	buf := make([]byte, 64<<10)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "fscache_http_requests_total") {
		t.Fatalf("metrics output missing fscache_http_requests_total:\n%s", body)
	}
}

// TestPutOverMaxBodyBytesReturns413 exercises the MaxBodyBytes cap end to
// end, over real HTTP. Previously this fixture existed (newTestHandler set
// MaxBodyBytes) but no test ever actually sent an oversized body, so the
// 413 path was unverified despite looking covered.
func TestPutOverMaxBodyBytesReturns413(t *testing.T) {
	const limit = 16
	h := newTestHandlerWithMaxBody(t, Credentials{}, limit)
	srv := httptest.NewServer(h)
	defer srv.Close()

	oversized := strings.Repeat("x", limit+1)
	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", oversized))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}

	// The oversized write must not have landed: a key that was never
	// successfully PUT should still read as missing.
	resp = doReq(t, mustReq(t, http.MethodGet, srv.URL+"/k", ""))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after rejected oversized PUT: status = %d, want 404", resp.StatusCode)
	}
}

func TestPutAtExactlyMaxBodyBytesSucceeds(t *testing.T) {
	const limit = 16
	h := newTestHandlerWithMaxBody(t, Credentials{}, limit)
	srv := httptest.NewServer(h)
	defer srv.Close()

	exact := strings.Repeat("x", limit)
	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", exact))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body exactly at the limit should be accepted)", resp.StatusCode)
	}
}

// TestMetricsReportsStoreBytesAndEntries is a regression test for an audit
// finding: fscache_store_bytes and fscache_store_entries were registered
// but never Set(), so they permanently reported 0 regardless of actual
// cache contents.
func TestMetricsReportsStoreBytesAndEntries(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	doReq(t, mustReq(t, http.MethodPut, srv.URL+"/a", "12345"))
	doReq(t, mustReq(t, http.MethodPut, srv.URL+"/b", "67"))

	resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/metrics", ""))
	buf := make([]byte, 64<<10)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "fscache_store_bytes 7") {
		t.Fatalf("expected fscache_store_bytes 7 (5+2 bytes across 2 entries), got:\n%s", body)
	}
	if !strings.Contains(body, "fscache_store_entries 2") {
		t.Fatalf("expected fscache_store_entries 2, got:\n%s", body)
	}
}

func newTestHandlerWithRO(t *testing.T, auth, ro Credentials) http.Handler {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := cache.New(blobs, meta)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	return New(Config{Cache: c, Metrics: m, Registry: reg, Auth: auth, ROAuth: ro, MaxBodyBytes: 1 << 20})
}

// REQ-AUTH-005-AC1: read-only credentials read exactly like read-write
// ones and can never change the store.
func TestReadOnlyCredentialsReadButNeverWrite(t *testing.T) {
	rw := Credentials{Username: "ci", Password: "writer-pw"}
	ro := Credentials{Username: "dev", Password: "reader-pw"}
	h := newTestHandlerWithRO(t, rw, ro)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Seed a key with the read-write pair.
	req := mustReq(t, http.MethodPut, srv.URL+"/k", "v")
	req.SetBasicAuth(rw.Username, rw.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusCreated {
		t.Fatalf("read-write PUT status = %d, want 201", resp.StatusCode)
	}

	// Read-only GET and HEAD succeed identically to read-write.
	req = mustReq(t, http.MethodGet, srv.URL+"/k", "")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("read-only GET status = %d, want 200", resp.StatusCode)
	}
	req = mustReq(t, http.MethodHead, srv.URL+"/k", "")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("read-only HEAD status = %d, want 200", resp.StatusCode)
	}

	// Read-only PUT is 403 and stores nothing.
	req = mustReq(t, http.MethodPut, srv.URL+"/k2", "poison")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only PUT status = %d, want 403", resp.StatusCode)
	}
	req = mustReq(t, http.MethodGet, srv.URL+"/k2", "")
	req.SetBasicAuth(rw.Username, rw.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET of read-only-attempted key = %d, want 404 (nothing stored)", resp.StatusCode)
	}

	// Read-only DELETE is 403 and the key survives.
	req = mustReq(t, http.MethodDelete, srv.URL+"/k", "")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only DELETE status = %d, want 403", resp.StatusCode)
	}
	req = mustReq(t, http.MethodGet, srv.URL+"/k", "")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET after refused DELETE = %d, want 200", resp.StatusCode)
	}

	// The read-write pair still writes.
	req = mustReq(t, http.MethodPut, srv.URL+"/k3", "v3")
	req.SetBasicAuth(rw.Username, rw.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusCreated {
		t.Fatalf("read-write PUT after RO traffic = %d, want 201", resp.StatusCode)
	}
}

// REQ-AUTH-005-AC2: wrong credentials are 401 (identity refused); valid
// read-only credentials are never 401, and their 403 carries no
// WWW-Authenticate - the identity was accepted, the verb was refused.
func TestReadOnlyCredentialsAuthSemantics(t *testing.T) {
	rw := Credentials{Username: "ci", Password: "writer-pw"}
	ro := Credentials{Username: "dev", Password: "reader-pw"}
	h := newTestHandlerWithRO(t, rw, ro)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Wrong password on the read-only username: 401 with WWW-Authenticate.
	req := mustReq(t, http.MethodGet, srv.URL+"/k", "")
	req.SetBasicAuth(ro.Username, "wrong")
	resp := doReq(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-password status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 without WWW-Authenticate")
	}

	// Valid read-only GET of a missing key: 404, never 401.
	req = mustReq(t, http.MethodGet, srv.URL+"/missing", "")
	req.SetBasicAuth(ro.Username, ro.Password)
	if resp := doReq(t, req); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("read-only GET missing = %d, want 404", resp.StatusCode)
	}

	// The 403 is an authorization answer, not an authentication challenge.
	req = mustReq(t, http.MethodPut, srv.URL+"/k", "v")
	req.SetBasicAuth(ro.Username, ro.Password)
	resp = doReq(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only PUT status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Fatal("403 carries WWW-Authenticate - retrying with the same valid credentials cannot help")
	}
}

func newTestHandlerWithCap(t *testing.T, capBytes, maxBody int64) http.Handler {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := cache.New(blobs, meta, cache.WithMaxBytes(capBytes))
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	return New(Config{Cache: c, Metrics: m, Registry: reg, MaxBytes: capBytes, MaxBodyBytes: maxBody})
}

// REQ-EVICT-002-AC1: an entry larger than the whole cache cap is 413
// with the documented reject header, stores nothing, and evicts nothing.
func TestOversizedEntryRejectedNotChurned(t *testing.T) {
	h := newTestHandlerWithCap(t, 1024, 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/small", strings.Repeat("a", 100)))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("small PUT status = %d, want 201", resp.StatusCode)
	}

	resp = doReq(t, mustReq(t, http.MethodPut, srv.URL+"/big", strings.Repeat("b", 2000)))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized PUT status = %d, want 413", resp.StatusCode)
	}
	if got := resp.Header.Get("X-FSCache-Reject"); got != "entry-exceeds-cache-cap" {
		t.Fatalf("X-FSCache-Reject = %q, want entry-exceeds-cache-cap", got)
	}

	resp = doReq(t, mustReq(t, http.MethodGet, srv.URL+"/big", ""))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET of rejected key = %d, want 404 (nothing stored)", resp.StatusCode)
	}
	resp = doReq(t, mustReq(t, http.MethodGet, srv.URL+"/small", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET of pre-existing key = %d, want 200 (nothing evicted)", resp.StatusCode)
	}
}

// REQ-EVICT-002-AC1, streaming half: a chunked upload with no declared
// length must be rejected the moment it exceeds the cap, with the same
// header - a lying or absent Content-Length cannot smuggle an oversized
// entry into the store.
func TestOversizedChunkedEntryRejected(t *testing.T) {
	h := newTestHandlerWithCap(t, 1024, 1<<20)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPut, srv.URL+"/chunky", strings.NewReader(strings.Repeat("c", 4096)))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = -1 // force chunked transfer encoding
	resp := doReq(t, req)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("chunked oversized PUT status = %d, want 413", resp.StatusCode)
	}
	if got := resp.Header.Get("X-FSCache-Reject"); got != "entry-exceeds-cache-cap" {
		t.Fatalf("X-FSCache-Reject = %q, want entry-exceeds-cache-cap", got)
	}
	resp = doReq(t, mustReq(t, http.MethodGet, srv.URL+"/chunky", ""))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET of rejected chunked key = %d, want 404", resp.StatusCode)
	}
}

// REQ-EVICT-002-AC2: the body-limit 413 and the cache-cap 413 stay
// distinguishable - only the latter carries the reject header.
func TestBodyLimitRejectionCarriesNoRejectHeader(t *testing.T) {
	h := newTestHandlerWithCap(t, 1<<20, 512)
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/toobig", strings.Repeat("d", 600)))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-body-limit PUT status = %d, want 413", resp.StatusCode)
	}
	if got := resp.Header.Get("X-FSCache-Reject"); got != "" {
		t.Fatalf("body-limit 413 carries X-FSCache-Reject %q; the two rejections must stay distinguishable", got)
	}
}
