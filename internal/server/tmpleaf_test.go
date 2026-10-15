package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ-PROTO-003-AC4: over the HTTP handler, keys whose leaf starts with
// ".tmp-" (top level, nested, and shaped exactly like a generated
// temporary name) are stored and read back with the same bytes.
func TestTmpLeafKeysOverHTTP(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	keys := []string{".tmp-x", "a/b/.tmp-y", ".tmp-0123456789abcdef0123456789abcdef", "ab/.tmp-0123456789abcdef0123456789abcdef"}
	for _, k := range keys {
		resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/"+k, "body:"+k))
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("PUT /%s status = %d, want 201", k, resp.StatusCode)
		}
	}
	for _, k := range keys {
		resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/"+k, ""))
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET /%s status = %d, want 200", k, resp.StatusCode)
			continue
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read /%s: %v", k, err)
		}
		if string(b) != "body:"+k {
			t.Errorf("GET /%s = %q, want %q", k, b, "body:"+k)
		}
	}
	for _, k := range []string{"+tmp/x", "%2Btmp/x"} {
		resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/"+k, "x"))
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT /%s status = %d, want 400 (no key reaches the temporary directory)", k, resp.StatusCode)
		}
	}
}
