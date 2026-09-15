package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// failingWriter is an http.ResponseWriter whose Write always fails — a
// client that hung up mid-response. It records the headers and status so
// tests can still assert on what the handler tried to send.
type failingWriter struct {
	header http.Header
	status int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *failingWriter) WriteHeader(status int) { w.status = status }

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("client went away")
}

// captureLogger returns a logger writing to the returned buffer, so tests
// can assert that error paths actually log.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// newTestCache builds a real cache backed by temp dirs, closed at cleanup.
func newTestCache(t *testing.T) *cache.Cache {
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
	return c
}

// gaugeValue reads a gauge's current value through its dto self-report,
// the same mechanism counterValue uses — no extra test dependencies.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		t.Fatalf("gauge Write: %v", err)
	}
	return m.GetGauge().GetValue()
}

// New must run without Metrics, Registry, or Log configured: nil Metrics
// makes withMetrics a passthrough, nil Registry defaults to the global
// gatherer, and requests still get real answers.
func TestNewWithNilMetricsRegistryAndLog(t *testing.T) {
	h := New(Config{Cache: newTestCache(t)})
	srv := httptest.NewServer(h)
	defer srv.Close()

	if resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/healthz", "")); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz: status = %d, want 200", resp.StatusCode)
	}
	// A cache round-trip goes through the metrics-free wrapper untouched.
	if resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", "v")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201", resp.StatusCode)
	}
	if resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/k", "")); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	if resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/missing", "")); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET missing status = %d, want 404 (miss with nil metrics must not panic)", resp.StatusCode)
	}
	// The nil-Registry default serves the global gatherer at /metrics.
	if resp := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/metrics", "")); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: status = %d, want 200", resp.StatusCode)
	}
}

// A client that disconnects mid-download must be logged as a short write,
// not surfaced as a handler failure.
func TestHandleGetLogsShortWriteToClient(t *testing.T) {
	c := newTestCache(t)
	if _, err := c.Put(t.Context(), "k", strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	log, buf := captureLogger()
	cfg := Config{Cache: c, Log: log}

	w := &failingWriter{}
	handleGet(w, httptest.NewRequest(http.MethodGet, "/k", nil), cfg, "k")

	if got := w.Header().Get("Content-Length"); got != "7" {
		t.Errorf("Content-Length = %q, want 7 (headers set before the body write failed)", got)
	}
	if !strings.Contains(buf.String(), "short write to client") {
		t.Errorf("log = %q, want a short-write warning", buf.String())
	}
}

// updateStoreGauges against a closed cache must leave the gauges at their
// previous values and log both failures — never crash the PUT that
// triggered the refresh.
func TestUpdateStoreGaugesLogsAndLeavesGaugesOnError(t *testing.T) {
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := cache.New(blobs, meta)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	m.StoreBytesTotal.Set(42)
	m.StoreEntries.Set(7)
	log, buf := captureLogger()

	updateStoreGauges(Config{Cache: c, Metrics: m, Log: log})

	if got := gaugeValue(t, m.StoreBytesTotal); got != 42 {
		t.Errorf("StoreBytesTotal = %v, want 42 (left alone on error)", got)
	}
	if got := gaugeValue(t, m.StoreEntries); got != 7 {
		t.Errorf("StoreEntries = %v, want 7 (left alone on error)", got)
	}
	for _, want := range []string{"store_bytes gauge update failed", "store_entries gauge update failed"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log = %q, want it to contain %q", buf.String(), want)
		}
	}
}

// An unrecognized store error is a 500 and is logged with method and key —
// the operator's only clue that the store itself is unhealthy.
func TestWriteStoreErrorUnknownErrorIs500AndLogged(t *testing.T) {
	log, buf := captureLogger()
	rec := httptest.NewRecorder()

	writeStoreError(rec, Config{Log: log}, errors.New("disk on fire"), "PUT", "somekey")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	logged := buf.String()
	for _, want := range []string{"store error", "PUT", "somekey", "disk on fire"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log = %q, want it to contain %q", logged, want)
		}
	}
}

// The remaining writeStoreError branches, asserted directly so each
// mapping is pinned: not-found (with the GET miss counter), invalid key,
// entry-too-large with its reject header, and the body-limit 413.
func TestWriteStoreErrorBranchMapping(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	log, _ := captureLogger()
	cfg := Config{Metrics: m, Log: log}

	rec := httptest.NewRecorder()
	writeStoreError(rec, cfg, blobstore.ErrNotFound, "GET", "k")
	if rec.Code != http.StatusNotFound {
		t.Errorf("ErrNotFound status = %d, want 404", rec.Code)
	}
	if got := counterValue(m.CacheMissTotal); got != 1 {
		t.Errorf("CacheMissTotal = %v, want 1 after a GET miss", got)
	}

	// A HEAD miss is still 404 but must not count as a cache miss.
	rec = httptest.NewRecorder()
	writeStoreError(rec, cfg, blobstore.ErrNotFound, "HEAD", "k")
	if rec.Code != http.StatusNotFound {
		t.Errorf("HEAD ErrNotFound status = %d, want 404", rec.Code)
	}
	if got := counterValue(m.CacheMissTotal); got != 1 {
		t.Errorf("CacheMissTotal = %v, want still 1 (HEAD is not a miss)", got)
	}

	rec = httptest.NewRecorder()
	writeStoreError(rec, cfg, blobstore.ErrInvalidKey, "PUT", "k")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ErrInvalidKey status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	writeStoreError(rec, cfg, cache.ErrEntryTooLarge, "PUT", "k")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("ErrEntryTooLarge status = %d, want 413", rec.Code)
	}
	if got := rec.Header().Get("X-FSCache-Reject"); got != "entry-exceeds-cache-cap" {
		t.Errorf("X-FSCache-Reject = %q, want entry-exceeds-cache-cap", got)
	}

	rec = httptest.NewRecorder()
	writeStoreError(rec, cfg, &http.MaxBytesError{Limit: 10}, "PUT", "k")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("MaxBytesError status = %d, want 413", rec.Code)
	}
	if got := rec.Header().Get("X-FSCache-Reject"); got != "" {
		t.Errorf("body-limit 413 carries X-FSCache-Reject %q, want none", got)
	}
}

// counterValue: nil is 0, a live counter reports its exact value, and a
// counter whose Write fails degrades to 0 rather than poisoning /statusz.
func TestCounterValue(t *testing.T) {
	if got := counterValue(nil); got != 0 {
		t.Errorf("counterValue(nil) = %v, want 0", got)
	}

	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counter_value_total"})
	c.Inc()
	c.Inc()
	if got := counterValue(c); got != 2 {
		t.Errorf("counterValue = %v, want 2", got)
	}

	if got := counterValue(errWriteCounter{c}); got != 0 {
		t.Errorf("counterValue(failing Write) = %v, want 0", got)
	}
}

// errWriteCounter is a prometheus.Counter whose Write always fails,
// covering counterValue's degraded path.
type errWriteCounter struct{ prometheus.Counter }

func (errWriteCounter) Write(*dto.Metric) error { return errors.New("write failed") }

// A browser client that disconnects while the status page renders must be
// logged, not ignored: template.Execute's error is the only signal.
func TestHandleStatusLogsTemplateWriteFailure(t *testing.T) {
	log, buf := captureLogger()
	s := &statusSource{cfg: Config{Log: log}, started: time.Now()}

	req := httptest.NewRequest(http.MethodGet, "/statusz", nil)
	req.Header.Set("Accept", "text/html")
	s.handleStatus(&failingWriter{}, req)

	if !strings.Contains(buf.String(), "status template") {
		t.Errorf("log = %q, want a status-template error", buf.String())
	}
}

// Same for the landing page.
func TestHandleRootLogsTemplateWriteFailure(t *testing.T) {
	log, buf := captureLogger()
	s := &statusSource{cfg: Config{Log: log}, started: time.Now()}

	w := &failingWriter{}
	s.handleRoot(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", got)
	}
	if !strings.Contains(buf.String(), "landing template") {
		t.Errorf("log = %q, want a landing-template error", buf.String())
	}
}

// view prepares Status for display: humanised sizes, a used percentage
// only when a cap exists, and a hit percentage only when there was
// traffic.
func TestStatusView(t *testing.T) {
	t.Run("capped store with hit ratio", func(t *testing.T) {
		r := 0.756
		v := Status{StoreBytes: 512, MaxBytes: 1024, HitRatio: &r}.view()
		if v.StoreHuman != "512 B" {
			t.Errorf("StoreHuman = %q, want 512 B", v.StoreHuman)
		}
		if v.MaxHuman != "1.0 KiB" {
			t.Errorf("MaxHuman = %q, want 1.0 KiB", v.MaxHuman)
		}
		if v.UsedPct != "50.0%" {
			t.Errorf("UsedPct = %q, want 50.0%%", v.UsedPct)
		}
		if v.HitPct != "75.6%" {
			t.Errorf("HitPct = %q, want 75.6%%", v.HitPct)
		}
	})

	t.Run("unlimited store, no traffic", func(t *testing.T) {
		v := Status{StoreBytes: 100}.view()
		if v.MaxHuman != "unlimited" {
			t.Errorf("MaxHuman = %q, want unlimited", v.MaxHuman)
		}
		if v.UsedPct != "" {
			t.Errorf("UsedPct = %q, want empty with no cap", v.UsedPct)
		}
		if v.HitPct != "n/a" {
			t.Errorf("HitPct = %q, want n/a with no traffic", v.HitPct)
		}
	})
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1<<20 - 1, "1024.0 KiB"},
		{1 << 20, "1.0 MiB"},
		{5 << 20, "5.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{1 << 40, "1.0 TiB"},
		{1 << 50, "1.0 PiB"},
		{1 << 60, "1.0 EiB"},
		{3<<60 + 5<<50, "3.0 EiB"},
	}
	for _, tc := range cases {
		if got := humanBytes(tc.n); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}
