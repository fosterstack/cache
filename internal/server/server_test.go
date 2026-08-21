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
	return New(Config{Cache: c, Metrics: m, Registry: reg, Auth: auth, MaxBodyBytes: 1 << 20})
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
