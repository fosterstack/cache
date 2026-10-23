package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/fosterstack/cache/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// REQ-OBS-002-AC1 (fscache_http_requests_total by method and status): the
// method label is bounded, so a client sending arbitrary method tokens
// cannot grow the series set for the life of the process (release-candidate
// review, server area).
func TestMethodLabelIsBounded(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	h := New(Config{Cache: newTestCache(t), Metrics: m, Registry: reg})

	for i := 0; i < 500; i++ {
		req := httptest.NewRequest("X"+strconv.Itoa(i), "/some/key", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/some/key", nil))
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	methods := map[string]bool{}
	for _, f := range families {
		name := f.GetName()
		if name != "fscache_http_requests_total" && name != "fscache_http_request_duration_seconds" {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "method" {
					methods[l.GetValue()] = true
				}
			}
		}
	}
	allowed := map[string]bool{"GET": true, "HEAD": true, "PUT": true, "other": true}
	for got := range methods {
		if !allowed[got] {
			t.Errorf("method label %q is outside GET/HEAD/PUT/other", got)
		}
	}
	if !methods["other"] || !methods["GET"] || !methods["HEAD"] || !methods["PUT"] {
		t.Errorf("method labels = %v, want GET, HEAD, PUT and other all present", methods)
	}
}
