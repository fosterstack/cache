package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ-PROTO-003-AC3: over the HTTP handler, keys whose leaf starts with
// '..' are stored and read back (PUT 201, GET 200 with the same bytes),
// and two such keys in different directories keep their own content.
func TestDotLeafKeysOverHTTP(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	keys := []string{"...", "..x", "..0", "a/..x", "a/..b", "x/..b"}
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
}
