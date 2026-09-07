package server

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// readAll drains a response body and fails the test on error.
func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// decodeStatus fetches /statusz as JSON and decodes it.
func decodeStatus(t *testing.T, base string, auth *Credentials) Status {
	t.Helper()
	req := mustReq(t, "GET", base+"/statusz", "")
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	resp := doReq(t, req)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /statusz: status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("GET /statusz: Content-Type = %q, want JSON", ct)
	}
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatalf("decode /statusz: %v", err)
	}
	return st
}

func TestStatuszReportsCacheStateAsJSON(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	// Two puts and one hit and one miss, so every counter has a value that
	// could only come from real traffic.
	for _, k := range []string{"alpha", "beta"} {
		if resp := doReq(t, mustReq(t, "PUT", srv.URL+"/"+k, "payload")); resp.StatusCode != 201 {
			t.Fatalf("PUT %s: status = %d, want 201", k, resp.StatusCode)
		}
	}
	doReq(t, mustReq(t, "GET", srv.URL+"/alpha", ""))
	doReq(t, mustReq(t, "GET", srv.URL+"/nothing-here", ""))

	st := decodeStatus(t, srv.URL, nil)

	if st.StoreEntries != 2 {
		t.Errorf("StoreEntries = %d, want 2", st.StoreEntries)
	}
	if want := int64(len("payload") * 2); st.StoreBytes != want {
		t.Errorf("StoreBytes = %d, want %d", st.StoreBytes, want)
	}
	if st.CacheHits != 1 {
		t.Errorf("CacheHits = %v, want 1", st.CacheHits)
	}
	if st.CacheMisses != 1 {
		t.Errorf("CacheMisses = %v, want 1", st.CacheMisses)
	}
	if st.HitRatio == nil || *st.HitRatio != 0.5 {
		t.Errorf("HitRatio = %v, want 0.5", st.HitRatio)
	}
	if st.UptimeSeconds <= 0 {
		t.Errorf("UptimeSeconds = %v, want > 0", st.UptimeSeconds)
	}
	if st.AuthEnabled {
		t.Error("AuthEnabled = true, want false for a no-auth server")
	}
	// FIPS140Note must always say something: "off" is a real answer, an
	// empty string is a broken one.
	if st.FIPS140Note == "" {
		t.Error("FIPS140Note is empty; the field must always report a posture")
	}
}

// The status page must agree with /metrics, because it claims to show the
// same counters. Reading them from two places that could drift is exactly
// the failure this guards.
func TestStatuszAgreesWithMetrics(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	doReq(t, mustReq(t, "PUT", srv.URL+"/k1", "abc"))
	doReq(t, mustReq(t, "GET", srv.URL+"/k1", ""))
	doReq(t, mustReq(t, "GET", srv.URL+"/k1", ""))
	doReq(t, mustReq(t, "GET", srv.URL+"/absent", ""))

	st := decodeStatus(t, srv.URL, nil)

	resp := doReq(t, mustReq(t, "GET", srv.URL+"/metrics", ""))
	body := readAll(t, resp.Body)

	for _, tc := range []struct {
		line string
		got  float64
	}{
		{"fscache_cache_hits_total 2", st.CacheHits},
		{"fscache_cache_misses_total 1", st.CacheMisses},
	} {
		if !strings.Contains(body, tc.line) {
			t.Errorf("/metrics missing %q", tc.line)
		}
	}
	if st.CacheHits != 2 || st.CacheMisses != 1 {
		t.Errorf("statusz hits/misses = %v/%v, want 2/1", st.CacheHits, st.CacheMisses)
	}
}

func TestStatuszServesHTMLToBrowsers(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req := mustReq(t, "GET", srv.URL+"/statusz", "")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp := doReq(t, req)

	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := readAll(t, resp.Body)
	for _, want := range []string{"<!doctype html>", "FosterStack Cache", "/metrics"} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML status page missing %q", want)
		}
	}
	// The page is read-only on purpose (#8b/#8d): no form, no button, no
	// state-changing method anywhere in it.
	for _, forbidden := range []string{"<form", "<button", "method=\"post\"", "purge"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("status page contains %q; it must expose no admin surface", forbidden)
		}
	}
}

// The bare root used to return 400 "invalid key" — the cache handler reads
// the path as the key and an empty key is invalid — so a browser pointed at
// a perfectly healthy server got an error page.
func TestRootServesLandingPageNot400(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp := doReq(t, mustReq(t, "GET", srv.URL+"/", ""))
	if resp.StatusCode != 200 {
		t.Fatalf("GET /: status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(readAll(t, resp.Body), "/statusz") {
		t.Error("landing page does not link to /statusz")
	}
}

// The landing page must not have eaten the cache protocol: real keys still
// route to the cache handler, and non-GET verbs on the root are unchanged.
func TestRootLandingDoesNotShadowCacheKeys(t *testing.T) {
	h := newTestHandler(t, Credentials{})
	srv := httptest.NewServer(h)
	defer srv.Close()

	if resp := doReq(t, mustReq(t, "PUT", srv.URL+"/realkey", "bytes")); resp.StatusCode != 201 {
		t.Fatalf("PUT /realkey: status = %d, want 201", resp.StatusCode)
	}
	resp := doReq(t, mustReq(t, "GET", srv.URL+"/realkey", ""))
	if resp.StatusCode != 200 {
		t.Fatalf("GET /realkey: status = %d, want 200", resp.StatusCode)
	}
	if got := readAll(t, resp.Body); got != "bytes" {
		t.Errorf("GET /realkey returned %q, want the stored bytes", got)
	}

	// A PUT to the root is still an invalid (empty) key, not a landing page.
	if resp := doReq(t, mustReq(t, "PUT", srv.URL+"/", "x")); resp.StatusCode != 400 {
		t.Errorf("PUT /: status = %d, want 400 (empty key)", resp.StatusCode)
	}
}

// #8d: the status surfaces are read-only, so the client credential is an
// acceptable gate for looking — but they must not be readable without it
// when auth is on.
func TestStatusSurfacesRespectBasicAuth(t *testing.T) {
	creds := Credentials{Username: "u", Password: "p"}
	h := newTestHandler(t, creds)
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/statusz", "/"} {
		if resp := doReq(t, mustReq(t, "GET", srv.URL+path, "")); resp.StatusCode != 401 {
			t.Errorf("GET %s without credentials: status = %d, want 401", path, resp.StatusCode)
		}
		req := mustReq(t, "GET", srv.URL+path, "")
		req.SetBasicAuth("u", "p")
		if resp := doReq(t, req); resp.StatusCode != 200 {
			t.Errorf("GET %s with credentials: status = %d, want 200", path, resp.StatusCode)
		}
	}

	if st := decodeStatus(t, srv.URL, &creds); !st.AuthEnabled {
		t.Error("AuthEnabled = false, want true when credentials are configured")
	}
}

// Documented in gradle.md/kubernetes.md: Prometheus scrapers and liveness
// probes do NOT need credentials. Asserted here so the docs cannot drift
// away from the behaviour.
func TestMetricsAndHealthzStayOpenWhenAuthEnabled(t *testing.T) {
	h := newTestHandler(t, Credentials{Username: "u", Password: "p"})
	srv := httptest.NewServer(h)
	defer srv.Close()

	for _, path := range []string{"/healthz", "/metrics"} {
		if resp := doReq(t, mustReq(t, "GET", srv.URL+path, "")); resp.StatusCode != 200 {
			t.Errorf("GET %s without credentials: status = %d, want 200", path, resp.StatusCode)
		}
	}
}
