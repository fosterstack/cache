package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// newTestHandlerWithStore returns the handler AND the cache behind it so a
// test can prove nothing was stored.
func newTestHandlerWithStore(t *testing.T, auth Credentials) (http.Handler, *cache.Cache) {
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
	return New(Config{Cache: c, Metrics: m, Registry: reg, Auth: auth, MaxBodyBytes: 1 << 20}), c
}

// noRedirectClient never follows redirects, so a 3xx is observed directly.
func doReqNoRedirect(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func mustEntryCount(t *testing.T, c *cache.Cache) int {
	t.Helper()
	n, err := c.EntryCount()
	if err != nil {
		t.Fatalf("EntryCount: %v", err)
	}
	return n
}

// REQ-PROTO-003-AC1: malformed cache paths — raw dot-segments and empty
// segments — must be rejected 400 through the real router, never
// normalized or redirected, and must store nothing.
func TestMalformedPathsRejectedNoRedirect(t *testing.T) {
	h, c := newTestHandlerWithStore(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, raw := range []string{
		"/x/../alias",
		"/x/./alias",
		"/x//alias",
		"/x/%2e%2e/alias",
		"/x/%2e/alias",
		"/x/%2f/alias",
	} {
		req := mustReq(t, http.MethodPut, srv.URL+raw, "payload")
		resp := doReqNoRedirect(t, req)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT %s: status = %d, want 400 (no redirect)", raw, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("PUT %s: got redirect to %q; malformed paths must not redirect", raw, loc)
		}
	}
	if n := mustEntryCount(t, c); n != 0 {
		t.Fatalf("store holds %d entries; malformed PUTs must store nothing", n)
	}
}

// REQ-PROTO-007-AC1: PUT and DELETE to the reserved application paths
// return 405 with Allow: GET, HEAD and store nothing; the endpoints keep
// answering GET.
func TestReservedPathsRefuseWritesAndStoreNothing(t *testing.T) {
	h, c := newTestHandlerWithStore(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	reserved := []string{"/", "/healthz", "/metrics", "/statusz"}
	for _, p := range reserved {
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			req := mustReq(t, method, srv.URL+p, "payload")
			resp := doReqNoRedirect(t, req)
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: status = %d, want 405", method, p, resp.StatusCode)
			}
			if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
				t.Errorf("%s %s: Allow = %q, want \"GET, HEAD\"", method, p, allow)
			}
		}
	}
	if n := mustEntryCount(t, c); n != 0 {
		t.Fatalf("store holds %d entries; writes to reserved paths must store nothing", n)
	}

	// The endpoints still answer GET.
	for _, p := range []string{"/healthz", "/metrics", "/"} {
		resp := doReqNoRedirect(t, mustReq(t, http.MethodGet, srv.URL+p, ""))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s after reserved-write attempts: status = %d, want 200", p, resp.StatusCode)
		}
	}
}

// Reserved-path writes must be refused even before authentication is
// considered, and the read-only identity must not be able to write them
// either — the refusal is by method, uniformly.
func TestReservedPathsRefuseWritesUnderAuth(t *testing.T) {
	rw := Credentials{Username: "ci", Password: "w"}
	h, c := newTestHandlerWithStore(t, rw)
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := mustReq(t, http.MethodPut, srv.URL+"/healthz", "x")
	req.SetBasicAuth("ci", "w")
	resp := doReqNoRedirect(t, req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated PUT /healthz = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want \"GET, HEAD\"", got)
	}
	if n := mustEntryCount(t, c); n != 0 {
		t.Fatalf("store holds %d entries", n)
	}
}

// rawPathIsMalformed is unexported; unit-test its branches directly,
// including the ones the front controller cannot route to (the bare root
// is handled as a reserved path before this is called, and an undecodable
// escape rarely survives an HTTP client).
func TestRawPathIsMalformed(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/", false},            // bare root: handled as reserved, not here
		{"/valid/key-1", false}, // ordinary multi-segment key
		{"/x/../y", true},       // literal ..
		{"/x/./y", true},        // literal .
		{"/x//y", true},         // empty segment
		{"/x/%2e%2e/y", true},   // encoded ..
		{"/trailing/", true},    // trailing slash -> empty segment
		{"/x/%zz/y", true},      // undecodable percent-escape
	}
	for _, tc := range cases {
		if got := rawPathIsMalformed(tc.path); got != tc.want {
			t.Errorf("rawPathIsMalformed(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
