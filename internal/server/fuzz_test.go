package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzHTTPSurface sends an arbitrary method, path and body through the real handler: it must never panic and never answer 5xx.
// The seed corpus below runs in plain `go test`; `go test -fuzz FuzzHTTPSurface ./internal/server` explores further.
func FuzzHTTPSurface(f *testing.F) {
	f.Add("PUT", "/ab/cdef", "hello")
	f.Add("GET", "/ab/cdef", "")
	f.Add("HEAD", "/", "")
	f.Add("DELETE", "/a/../b", "x")
	f.Add("PUT", "/%2e%2e/%2e%2e/etc/passwd", "x")
	f.Add("GET", "/status", "")
	f.Add("GET", "/metrics", "")
	f.Add("POST", "/ab/cdef?x=y", "body")
	f.Fuzz(func(t *testing.T, method, path, body string) {
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n\x00") || strings.ContainsAny(method, " \r\n\x00") || method == "" {
			t.Skip()
		}
		h := newTestHandler(t, Credentials{})
		req, err := http.NewRequest(method, "http://example.invalid"+path, bytes.NewReader([]byte(body)))
		if err != nil {
			t.Skip()
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code >= 500 {
			t.Fatalf("%s %q -> %d %q", method, path, rr.Code, rr.Body.String())
		}
	})
}
