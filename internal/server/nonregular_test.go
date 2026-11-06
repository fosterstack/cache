package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ-PROTO-003-AC5: a key that was never stored whose path in the store is
// a directory answers 404 to HEAD and GET, never 200. Key "ab" lives at the
// path ab/ab, which becomes a directory once "ab/ab" is stored.
func TestNeverStoredKeyOnADirectoryPathIs404(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	if resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/ab/ab", "inner")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT /ab/ab status = %d, want 201", resp.StatusCode)
	}
	for _, m := range []string{http.MethodHead, http.MethodGet} {
		resp := doReq(t, mustReq(t, m, srv.URL+"/ab", ""))
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s /ab status = %d, want 404", m, resp.StatusCode)
		}
	}
	if resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/ab/ab", "")); resp.StatusCode != http.StatusOK {
		t.Errorf("GET /ab/ab status = %d, want 200", resp.StatusCode)
	}
}
