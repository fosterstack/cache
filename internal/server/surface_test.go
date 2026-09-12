package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ-PROTO-002-AC1: a nested path round-trips over HTTP as one key, and
// the bytes are not visible under any other path.
func TestNestedKeyRoundTripOverHTTP(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	if r := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/a/nested/key", "nested-bytes")); r.StatusCode != http.StatusCreated {
		t.Fatalf("PUT nested: %d", r.StatusCode)
	}
	r := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/a/nested/key", ""))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET nested: %d", r.StatusCode)
	}
	if got := readAll(t, r.Body); got != "nested-bytes" {
		t.Errorf("GET returned %q", got)
	}
	for _, other := range []string{"/key", "/nested/key", "/a/nested", "/a/key"} {
		if r := doReq(t, mustReq(t, http.MethodGet, srv.URL+other, "")); r.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (bytes leaked to another path)", other, r.StatusCode)
		}
	}
}

// REQ-AUTH-004-AC1: a client that sends credentials to a server with auth
// DISABLED gets normal service — the header is ignored, so one client
// config works against test and production instances.
func TestCredentialsIgnoredByNoAuthServer(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := mustReq(t, http.MethodPut, srv.URL+"/with-creds", "payload")
	req.SetBasicAuth("someone", "something")
	if r := doReq(t, req); r.StatusCode != http.StatusCreated {
		t.Fatalf("PUT with unnecessary creds: %d, want 201", r.StatusCode)
	}
	get := mustReq(t, http.MethodGet, srv.URL+"/with-creds", "")
	get.SetBasicAuth("someone", "something")
	r := doReq(t, get)
	if r.StatusCode != http.StatusOK || readAll(t, r.Body) != "payload" {
		t.Fatalf("GET with unnecessary creds failed: %d", r.StatusCode)
	}
}

// REQ-OBS-005-AC1: the route surface is exactly the cache namespace plus
// four read-only application endpoints; nothing accepts a state-changing
// verb beyond cache PUT.
func TestRouteSurfaceIsCachePlusReadOnlyEndpoints(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// The four application endpoints answer GET.
	for _, p := range []string{"/healthz", "/metrics", "/statusz", "/"} {
		if r := doReq(t, mustReq(t, http.MethodGet, srv.URL+p, "")); r.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, r.StatusCode)
		}
	}
	// No state-changing verb is accepted outside cache PUT: DELETE and
	// POST are refused on cache paths and on every reserved path.
	for _, p := range []string{"/somekey", "/healthz", "/metrics", "/statusz", "/"} {
		for _, m := range []string{http.MethodDelete, http.MethodPost} {
			r := doReq(t, mustReq(t, m, srv.URL+p, "x"))
			if r.StatusCode != http.StatusMethodNotAllowed && r.StatusCode != http.StatusBadRequest {
				t.Errorf("%s %s = %d, want a refusal (405/400)", m, p, r.StatusCode)
			}
		}
	}
}
