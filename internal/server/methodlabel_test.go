package server

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/fosterstack/cache/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// REQ-OBS-002-AC12: the method label is bounded, so a client sending
// arbitrary method tokens cannot grow the series set for the life of the
// process (release-candidate review, server area).
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
	byName := map[string]*dto.MetricFamily{}
	for _, f := range families {
		byName[f.GetName()] = f
	}
	allowed := map[string]bool{"GET": true, "HEAD": true, "PUT": true, "other": true}
	for _, name := range []string{"fscache_http_requests_total", "fscache_http_request_duration_seconds"} {
		f := byName[name]
		if f == nil {
			t.Fatalf("family %s missing from the scrape", name)
		}
		seen := map[string]bool{}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "method" {
					seen[l.GetValue()] = true
				}
			}
		}
		for got := range seen {
			if !allowed[got] {
				t.Errorf("%s: method label %q is outside GET/HEAD/PUT/other", name, got)
			}
		}
		for want := range allowed {
			if !seen[want] {
				t.Errorf("%s: method label %q missing (have %v)", name, want, seen)
			}
		}
	}

	var other float64
	for _, metric := range byName["fscache_http_requests_total"].GetMetric() {
		for _, l := range metric.GetLabel() {
			if l.GetName() == "method" && l.GetValue() == "other" {
				other += metric.GetCounter().GetValue()
			}
		}
	}
	if other != 500 {
		t.Errorf("requests_total counted %v requests under other, want 500", other)
	}
}
