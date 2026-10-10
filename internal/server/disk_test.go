package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/metrics"
	"github.com/fosterstack/cache/internal/storesample"
	"github.com/prometheus/client_golang/prometheus"
)

// ---- test doubles ---------------------------------------------------------------------------------------------------------------------------

// srvDisk is the injected disk for the shared store sample: every probe and
// statfs call is counted, any step can fail.
type srvDisk struct {
	mu      sync.Mutex
	avail   uint64
	statErr error
	syncErr error
	openErr error
	probes  atomic.Int64
	statfs  atomic.Int64
}

type srvFile struct{ d *srvDisk }

func (f srvFile) Write(p []byte) (int, error) { return len(p), nil }
func (f srvFile) Sync() error                 { f.d.mu.Lock(); defer f.d.mu.Unlock(); return f.d.syncErr }
func (f srvFile) Close() error                { return nil }

func (d *srvDisk) deps(now *atomic.Int64) storesample.Deps {
	return storesample.Deps{
		Statfs: func(string) (uint64, error) {
			d.statfs.Add(1)
			d.mu.Lock()
			defer d.mu.Unlock()
			return d.avail, d.statErr
		},
		OpenProbe: func(string) (storesample.ProbeFile, error) {
			d.probes.Add(1)
			d.mu.Lock()
			defer d.mu.Unlock()
			if d.openErr != nil {
				return nil, d.openErr
			}
			return srvFile{d}, nil
		},
		Remove: func(string) error { return nil },
		Now:    func() time.Time { return time.Unix(now.Load(), 0) },
	}
}

func (d *srvDisk) set(f func(*srvDisk)) { d.mu.Lock(); f(d); d.mu.Unlock() }

// faultStore wraps the real cache and makes Put fail with a chosen error.
type faultStore struct {
	Store
	mu     sync.Mutex
	putErr error
}

func (f *faultStore) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	f.mu.Lock()
	err := f.putErr
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.Store.Put(ctx, key, r)
}

func (f *faultStore) fail(err error) { f.mu.Lock(); f.putErr = err; f.mu.Unlock() }

type obsEnv struct {
	srv   *httptest.Server
	disk  *srvDisk
	clock *atomic.Int64
	store *faultStore
	log   *bytes.Buffer
	smp   *storesample.Sampler
}

type obsOpt func(*Config)

func newObsEnv(t *testing.T, opts ...obsOpt) *obsEnv {
	t.Helper()
	disk := &srvDisk{avail: 5 << 30}
	clock := &atomic.Int64{}
	clock.Store(1_000_000)
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	smp := storesample.New(t.TempDir(), disk.deps(clock), storesample.Options{Log: log, WaitBudget: time.Second})
	smp.Start()
	fs := &faultStore{Store: newTestCache(t)}
	reg := prometheus.NewRegistry()
	cfg := Config{Cache: fs, Metrics: metrics.New(reg), Registry: reg, Log: log, MaxBodyBytes: 1 << 20, Sampler: smp}
	for _, o := range opts {
		o(&cfg)
	}
	srv := httptest.NewServer(New(cfg))
	t.Cleanup(srv.Close)
	return &obsEnv{srv: srv, disk: disk, clock: clock, store: fs, log: &buf, smp: smp}
}

func (e *obsEnv) advance(sec int64) { e.clock.Add(sec) }

func (e *obsEnv) get(t *testing.T, path string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (e *obsEnv) put(t *testing.T, key, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/"+key, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

func (e *obsEnv) metrics(t *testing.T) string {
	t.Helper()
	_, b, _ := e.get(t, "/metrics")
	return b
}

// mval returns the value of one exposition line (name with its labels), or "" when absent.
func mval(body, series string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, series+" ") {
			return strings.TrimSpace(strings.TrimPrefix(l, series+" "))
		}
	}
	return ""
}

var reasons = []string{"no_space", "read_only", "too_large", "client_aborted", "other"}

func putErrors(t *testing.T, e *obsEnv) map[string]string {
	t.Helper()
	body := e.metrics(t)
	out := map[string]string{}
	for _, r := range reasons {
		out[r] = mval(body, fmt.Sprintf(`fscache_put_errors_total{reason=%q}`, r))
	}
	return out
}

func statusJSON(t *testing.T, e *obsEnv) map[string]any {
	t.Helper()
	_, b, _ := e.get(t, "/statusz")
	m := map[string]any{}
	if err := json.Unmarshal([]byte(b), &m); err != nil {
		t.Fatalf("statusz is not JSON: %v\n%s", err, b)
	}
	return m
}

// ---- REQ-OBS-001: /healthz is liveness only ---------------------------------------------------------------------------------

func TestHealthzStays200OnReadOnlyAndFullDisk(t *testing.T) {
	e := newObsEnv(t)
	e.disk.set(func(d *srvDisk) { d.openErr = syscall.EROFS })
	e.advance(10)
	if code, body, _ := e.get(t, "/healthz"); code != 200 || body != "ok" {
		t.Fatalf("read-only disk: /healthz = %d %q; want 200 ok", code, body)
	}
	e.disk.set(func(d *srvDisk) { d.openErr = nil; d.syncErr = syscall.ENOSPC })
	e.store.fail(syscall.ENOSPC)
	e.advance(10)
	if code, body, _ := e.get(t, "/healthz"); code != 200 || body != "ok" {
		t.Fatalf("full disk: /healthz = %d %q; want 200 ok", code, body)
	}
}

func TestHealthzTouchesNoFilesystem(t *testing.T) {
	e := newObsEnv(t)
	probes, stats := e.disk.probes.Load(), e.disk.statfs.Load()
	e.disk.set(func(d *srvDisk) { d.statErr = errors.New("gone"); d.openErr = errors.New("gone") })
	e.advance(60)
	for i := 0; i < 20; i++ {
		if code, body, _ := e.get(t, "/healthz"); code != 200 || body != "ok" {
			t.Fatalf("/healthz = %d %q", code, body)
		}
	}
	if e.disk.probes.Load() != probes || e.disk.statfs.Load() != stats {
		t.Fatalf("/healthz touched the disk: probes %d->%d, statfs %d->%d", probes, e.disk.probes.Load(), stats, e.disk.statfs.Load())
	}
}

func TestDocsSayHealthzIsLivenessOnly(t *testing.T) {
	for _, f := range []string{"../../docs/kubernetes.md", "../../docs/docker-deploy.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		for _, want := range []string{"liveness only", "fscache_store_writable", "fscache_store_free_bytes", "fscache_put_errors_total"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not contain %q", f, want)
			}
		}
	}
}

// ---- REQ-OBS-002: the gauges ----------------------------------------------------------------------------------------------------

func TestWritableGaugeHealthyIsOneAndDocumented(t *testing.T) {
	e := newObsEnv(t)
	body := e.metrics(t)
	if mval(body, "fscache_store_writable") != "1" {
		t.Fatalf("fscache_store_writable = %q; want 1\n%s", mval(body, "fscache_store_writable"), body)
	}
	if !strings.Contains(body, "# TYPE fscache_store_writable gauge") {
		t.Error("fscache_store_writable is not a gauge")
	}
	if !regexp.MustCompile(`# HELP fscache_store_writable .*create, sync and delete`).MatchString(body) {
		t.Error("help text does not say create, sync and delete")
	}
}

func TestWritableGaugeZeroOnFullDiskAndRecovers(t *testing.T) {
	e := newObsEnv(t)
	e.disk.set(func(d *srvDisk) { d.syncErr = syscall.ENOSPC })
	if mval(e.metrics(t), "fscache_store_writable") != "1" {
		t.Fatal("the sample is fresh: it must not be re-measured before it expires")
	}
	e.advance(6)
	if got := mval(e.metrics(t), "fscache_store_writable"); got != "0" {
		t.Fatalf("full disk: writable = %q; want 0", got)
	}
	e.disk.set(func(d *srvDisk) { d.syncErr = nil })
	e.advance(6)
	if got := mval(e.metrics(t), "fscache_store_writable"); got != "1" {
		t.Fatalf("after the fix: writable = %q; want 1", got)
	}
}

func TestWritableGaugeZeroOnReadOnlyDir(t *testing.T) {
	e := newObsEnv(t)
	e.disk.set(func(d *srvDisk) { d.openErr = syscall.EROFS })
	e.advance(6)
	if got := mval(e.metrics(t), "fscache_store_writable"); got != "0" {
		t.Fatalf("read-only dir: writable = %q; want 0", got)
	}
}

func TestFailedPutMarksTheSampleStale(t *testing.T) {
	e := newObsEnv(t)
	e.disk.set(func(d *srvDisk) { d.syncErr = syscall.ENOSPC })
	e.store.fail(syscall.ENOSPC)
	if resp := e.put(t, "k", "v"); resp.StatusCode != 500 {
		t.Fatalf("PUT = %d; want 500", resp.StatusCode)
	}
	// no clock advance: the failed PUT alone makes the next read measure again
	if got := mval(e.metrics(t), "fscache_store_writable"); got != "0" {
		t.Fatalf("after a no_space PUT the gauge = %q; want 0 without waiting for expiry", got)
	}
}

func TestFreeBytesGaugeAndStatfsFailure(t *testing.T) {
	e := newObsEnv(t)
	e.disk.set(func(d *srvDisk) { d.avail = 123456789 })
	e.advance(6)
	body := e.metrics(t)
	if got := mval(body, "fscache_store_free_bytes"); got != "1.23456789e+08" && got != "123456789" {
		t.Fatalf("fscache_store_free_bytes = %q; want 123456789", got)
	}
	if !strings.Contains(body, "# TYPE fscache_store_free_bytes gauge") {
		t.Error("fscache_store_free_bytes is not a gauge")
	}
	e.disk.set(func(d *srvDisk) { d.statErr = errors.New("statfs failed") })
	e.advance(6)
	body = e.metrics(t)
	if mval(body, "fscache_store_free_bytes") != "0" || mval(body, "fscache_store_writable") != "0" {
		t.Fatalf("statfs failure: free=%q writable=%q; want 0 and 0", mval(body, "fscache_store_free_bytes"), mval(body, "fscache_store_writable"))
	}
}

func TestProbeNotRunWhileSampleFresh(t *testing.T) {
	e := newObsEnv(t)
	for i := 0; i < 50; i++ {
		e.metrics(t)
		statusJSON(t, e)
	}
	if n := e.disk.probes.Load(); n != 1 {
		t.Fatalf("%d probes for 100 reads within one sample; want 1 (the startup probe)", n)
	}
}

// ---- REQ-OBS-002: the PUT error counter ------------------------------------------------------------------------------------

func TestPutErrorSeriesExistAtZeroAndNoOthers(t *testing.T) {
	e := newObsEnv(t)
	body := e.metrics(t)
	for _, r := range reasons {
		if got := mval(body, fmt.Sprintf(`fscache_put_errors_total{reason=%q}`, r)); got != "0" {
			t.Errorf("reason %s = %q at start; want 0", r, got)
		}
	}
	n := strings.Count(body, "\nfscache_put_errors_total{")
	if n != len(reasons) {
		t.Errorf("%d fscache_put_errors_total series; want exactly %d", n, len(reasons))
	}
}

func TestPutErrorTaxonomyAndResponsesUnchanged(t *testing.T) {
	type row struct {
		name   string
		err    error
		reason string
		status int
		hdr    string
	}
	rows := []row{
		{"enospc", &os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}, "no_space", 500, ""},
		{"edquot wrapped", fmt.Errorf("blob: %w", syscall.EDQUOT), "no_space", 500, ""},
		{"erofs", &os.PathError{Op: "create", Path: "x", Err: syscall.EROFS}, "read_only", 500, ""},
		{"eacces", fmt.Errorf("cache: %w", &os.PathError{Op: "open", Path: "x", Err: syscall.EACCES}), "read_only", 500, ""},
		{"eperm", syscall.EPERM, "read_only", 500, ""},
		{"too large", fmt.Errorf("cache: %w", cache.ErrEntryTooLarge), "too_large", 413, "entry-exceeds-cache-cap"},
		{"max bytes", &http.MaxBytesError{Limit: 10}, "too_large", 413, ""},
		{"eio", syscall.EIO, "other", 500, ""},
		{"unknown type", errors.New("disk on fire"), "other", 500, ""},
		{"joined ENOSPC and EACCES counts no_space only", errors.Join(syscall.EACCES, syscall.ENOSPC), "no_space", 500, ""},
		{"context canceled", fmt.Errorf("copy: %w", context.Canceled), "client_aborted", 500, ""},
		{"unexpected EOF", fmt.Errorf("body: %w", io.ErrUnexpectedEOF), "client_aborted", 500, ""},
	}
	for _, r := range rows {
		e := newObsEnv(t)
		e.store.fail(r.err)
		resp := e.put(t, "k", "v")
		if resp.StatusCode != r.status {
			t.Errorf("%s: status %d; want %d", r.name, resp.StatusCode, r.status)
		}
		if got := resp.Header.Get("X-FSCache-Reject"); got != r.hdr {
			t.Errorf("%s: X-FSCache-Reject %q; want %q", r.name, got, r.hdr)
		}
		got := putErrors(t, e)
		for _, reason := range reasons {
			want := "0"
			if reason == r.reason {
				want = "1"
			}
			if got[reason] != want {
				t.Errorf("%s: reason %s = %q; want %s (exactly one series moves, by one)", r.name, reason, got[reason], want)
			}
		}
	}
}

func TestPutErrorsTooLargeByDeclaredChunkedAndBodyLimit(t *testing.T) {
	e := newObsEnv(t, func(c *Config) {
		c.MaxBytes = 10
		c.MaxBodyBytes = 0
		c.Cache = &faultStore{Store: newCappedCache(t, 10)}
	})
	big := strings.Repeat("x", 64)
	if resp := e.put(t, "declared", big); resp.StatusCode != 413 {
		t.Fatalf("declared over cap: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/chunked", io.NopCloser(strings.NewReader(big)))
	req.ContentLength = -1
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("chunked over cap: %d", resp.StatusCode)
	}
	e2 := newObsEnv(t, func(c *Config) { c.MaxBodyBytes = 8 })
	if resp := e2.put(t, "limited", big); resp.StatusCode != 413 {
		t.Fatalf("over body limit: %d", resp.StatusCode)
	}
	if got := putErrors(t, e)["too_large"]; got != "2" {
		t.Errorf("declared + chunked: too_large = %q; want 2", got)
	}
	if got := putErrors(t, e2)["too_large"]; got != "1" {
		t.Errorf("body limit: too_large = %q; want 1", got)
	}
}

func TestClientAbortMidBodyCountsClientAborted(t *testing.T) {
	e := newObsEnv(t)
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(conn)
	fmt.Fprintf(w, "PUT /aborted HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n0123456789")
	_ = w.Flush()
	_ = conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if putErrors(t, e)["client_aborted"] == "1" {
			if o := putErrors(t, e)["other"]; o != "0" {
				t.Fatalf("an aborted upload also counted as other (%s)", o)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("a client that hung up mid-body was not counted as client_aborted: %v", putErrors(t, e))
}

func TestNonStoreRefusalsAndSuccessDoNotCount(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{}, 1)
	e := newObsEnv(t, func(c *Config) {
		c.Auth = Credentials{Username: "rw", Password: "pw"}
		c.ROAuth = Credentials{Username: "ro", Password: "pw2"}
		c.MaxConcurrentUploads = 1
		c.Cache = &blockingStore{Store: c.Cache, block: block, started: started}
	})
	do := func(method, path, user, pass, body string) int {
		req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("PUT", "/a/../b", "rw", "pw", "x"); c != 400 {
		t.Fatalf("bad key: %d", c)
	}
	if c := do("PUT", "/k", "bad", "bad", "x"); c != 401 {
		t.Fatalf("bad credentials: %d", c)
	}
	if c := do("PUT", "/k", "ro", "pw2", "x"); c != 403 {
		t.Fatalf("read-only credential: %d", c)
	}
	done := make(chan int, 1)
	go func() { done <- do("PUT", "/slow", "rw", "pw", "x") }()
	<-started
	if c := do("PUT", "/second", "rw", "pw", "x"); c != 429 {
		t.Fatalf("upload bound: %d", c)
	}
	close(block)
	if c := <-done; c != 201 {
		t.Fatalf("successful PUT: %d", c)
	}
	body := e.metrics(t)
	for _, r := range reasons {
		if got := mval(body, fmt.Sprintf(`fscache_put_errors_total{reason=%q}`, r)); got != "0" {
			t.Errorf("reason %s = %q after only non-store refusals and a success; want 0", r, got)
		}
	}
}

type blockingStore struct {
	Store
	block   chan struct{}
	started chan struct{}
}

func (b *blockingStore) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	if key == "slow" {
		b.started <- struct{}{}
		<-b.block
	}
	return b.Store.Put(ctx, key, r)
}

func TestClassifyPutErrorTable(t *testing.T) {
	cases := []struct {
		err     error
		ctxErr  error
		reason  string
		counted bool
	}{
		{blobstore.ErrInvalidKey, nil, "", false},
		{nil, nil, "", false},
		{syscall.ENOSPC, nil, "no_space", true},
		{errors.Join(syscall.ENOSPC, syscall.EACCES, cache.ErrEntryTooLarge), nil, "no_space", true},
		{errors.Join(syscall.EACCES, cache.ErrEntryTooLarge), nil, "read_only", true},
		{errors.New("x"), context.Canceled, "client_aborted", true}, // the request context is done and the failure is not a disk error
		{syscall.ENOSPC, context.Canceled, "no_space", true},
		{struct{ error }{errors.New("opaque")}, nil, "other", true},
	}
	for i, c := range cases {
		reason, counted := classifyPutError(c.err, c.ctxErr)
		if reason != c.reason || counted != c.counted {
			t.Errorf("case %d (%v): got (%q,%v); want (%q,%v)", i, c.err, reason, counted, c.reason, c.counted)
		}
	}
}

// ---- REQ-OBS-002: the probe is invisible; startup -------------------------------------------------------------------------

func TestProbeFileIsNotAKeyNotCountedAndSweptAtStartup(t *testing.T) {
	dir := t.TempDir()
	blobs, err := blobstore.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	c := cache.New(blobs, meta)
	t.Cleanup(func() { _ = c.Close() })
	leftName := ""
	smp := storesample.New(dir, storesample.Deps{
		OpenProbe: func(path string) (storesample.ProbeFile, error) {
			leftName = filepath.Base(path)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, err
			}
			_ = f.Close()
			return nil, syscall.ENOSPC // the probe fails midway and leaves the file behind
		},
		Remove: func(string) error { return nil }, // the failed probe cannot clean up
	}, storesample.Options{})
	smp.Start()
	reg := prometheus.NewRegistry()
	h := New(Config{Cache: c, Metrics: metrics.New(reg), Registry: reg, Sampler: smp})
	srv := httptest.NewServer(h)
	defer srv.Close()
	if leftName == "" || !strings.HasPrefix(leftName, ".tmp-") {
		t.Fatalf("probe file name %q must carry the .tmp- prefix", leftName)
	}
	for _, m := range []string{"GET", "HEAD"} {
		req, _ := http.NewRequest(m, srv.URL+"/"+leftName, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("%s of the probe file's name = %d; want 404 (no key reaches it)", m, resp.StatusCode)
		}
	}
	st := statusFrom(t, srv.URL)
	if st.StoreBytes != 0 || st.StoreEntries != 0 {
		t.Errorf("probe counted: %d bytes, %d entries", st.StoreBytes, st.StoreEntries)
	}
	stale, err := blobs.Walk(func(string, int64) error { t.Error("the probe file was reported as a blob"); return nil })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range stale {
		if filepath.Base(s) == leftName {
			found = true
		}
	}
	if !found {
		t.Errorf("the startup sweep does not see the leftover probe file (stale temp files: %v)", stale)
	}
}

func statusFrom(t *testing.T, base string) Status {
	t.Helper()
	resp, err := http.Get(base + "/statusz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var st Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestGaugesSeededAtStartupHealthyAndBroken(t *testing.T) {
	e := newObsEnv(t)
	body := e.metrics(t)
	if mval(body, "fscache_store_writable") != "1" || mval(body, "fscache_store_free_bytes") == "" || mval(body, "fscache_store_free_bytes") == "0" {
		t.Fatalf("healthy start: writable=%q free=%q", mval(body, "fscache_store_writable"), mval(body, "fscache_store_free_bytes"))
	}
	disk := &srvDisk{avail: 4096, openErr: syscall.EROFS}
	clock := &atomic.Int64{}
	clock.Store(1)
	smp := storesample.New(t.TempDir(), disk.deps(clock), storesample.Options{})
	smp.Start()
	c := newTestCache(t)
	if _, err := c.Put(context.Background(), "present", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	srv := httptest.NewServer(New(Config{Cache: c, Metrics: metrics.New(reg), Registry: reg, Sampler: smp}))
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/metrics")
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if mval(string(b), "fscache_store_writable") != "0" || mval(string(b), "fscache_store_free_bytes") != "4096" {
		t.Fatalf("broken start: writable=%q free=%q; want 0 and 4096", mval(string(b), "fscache_store_writable"), mval(string(b), "fscache_store_free_bytes"))
	}
	g, err := http.Get(srv.URL + "/present")
	if err != nil {
		t.Fatal(err)
	}
	_ = g.Body.Close()
	if g.StatusCode != 200 {
		t.Fatalf("GET on a read-only start = %d; the server must still serve", g.StatusCode)
	}
}

// ---- REQ-OBS-003: /statusz ---------------------------------------------------------------------------------------------------

func TestStatuszHasDiskFields(t *testing.T) {
	e := newObsEnv(t)
	m := statusJSON(t, e)
	if w, ok := m["store_writable"].(bool); !ok || !w {
		t.Errorf("store_writable = %v; want true", m["store_writable"])
	}
	if f, ok := m["store_free_bytes"].(float64); !ok || f <= 0 {
		t.Errorf("store_free_bytes = %v; want a positive number", m["store_free_bytes"])
	}
	pe, ok := m["put_errors"].(map[string]any)
	if !ok || len(pe) != len(reasons) {
		t.Fatalf("put_errors = %v; want an object with exactly %v", m["put_errors"], reasons)
	}
	for _, r := range reasons {
		if _, ok := pe[r].(float64); !ok {
			t.Errorf("put_errors.%s missing or not a number", r)
		}
	}
	for _, old := range []string{"version", "store_bytes", "store_entries", "cache_hits", "evicted_entries", "auth_enabled"} {
		if _, ok := m[old]; !ok {
			t.Errorf("the existing field %s is gone", old)
		}
	}
}

func TestStatuszAgreesWithMetricsOnDiskSignalsInEveryState(t *testing.T) {
	states := map[string]func(*obsEnv){
		"healthy":   func(e *obsEnv) {},
		"read-only": func(e *obsEnv) { e.disk.set(func(d *srvDisk) { d.openErr = syscall.EROFS }); e.advance(6) },
		"full disk": func(e *obsEnv) {
			e.disk.set(func(d *srvDisk) { d.syncErr = syscall.ENOSPC; d.avail = 0 })
			e.advance(6)
		},
		"after one failed PUT of each reason": func(e *obsEnv) {
			for _, err := range []error{syscall.ENOSPC, syscall.EROFS, cache.ErrEntryTooLarge, context.Canceled, errors.New("x")} {
				e.store.fail(err)
				e.put(t, "k", "v")
			}
		},
	}
	for name, setup := range states {
		e := newObsEnv(t)
		setup(e)
		body := e.metrics(t)
		m := statusJSON(t, e)
		wantW := "0"
		if m["store_writable"] == true {
			wantW = "1"
		}
		if mval(body, "fscache_store_writable") != wantW {
			t.Errorf("%s: writable gauge %q vs statusz %v", name, mval(body, "fscache_store_writable"), m["store_writable"])
		}
		if got, want := fmt.Sprintf("%.0f", m["store_free_bytes"]), fmt.Sprintf("%s", mval(body, "fscache_store_free_bytes")); got != want && !strings.Contains(want, "e+") {
			t.Errorf("%s: free bytes statusz %s vs metrics %s", name, got, want)
		}
		pe := m["put_errors"].(map[string]any)
		for _, r := range reasons {
			if fmt.Sprintf("%.0f", pe[r]) != mval(body, fmt.Sprintf(`fscache_put_errors_total{reason=%q}`, r)) {
				t.Errorf("%s: put_errors.%s statusz %v vs metrics %s", name, r, pe[r], mval(body, fmt.Sprintf(`fscache_put_errors_total{reason=%q}`, r)))
			}
		}
	}
}

func TestStatuszAndMetricsShareOneSample(t *testing.T) {
	for _, order := range []string{"metrics-first", "statusz-first"} {
		e := newObsEnv(t)
		e.disk.set(func(d *srvDisk) { d.syncErr = syscall.ENOSPC })
		e.advance(6)
		before := e.disk.probes.Load()
		if order == "metrics-first" {
			e.metrics(t)
			statusJSON(t, e)
		} else {
			statusJSON(t, e)
			e.metrics(t)
		}
		if n := e.disk.probes.Load() - before; n != 1 {
			t.Errorf("%s: %d probes for one /metrics and one /statusz; want 1", order, n)
		}
	}
}

func TestStatuszHTMLShowsDataDirRow(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*obsEnv)
		want string
	}{
		{"healthy", func(*obsEnv) {}, "writable"},
		{"read-only", func(e *obsEnv) { e.disk.set(func(d *srvDisk) { d.openErr = syscall.EROFS }); e.advance(6) }, "NOT writable"},
	} {
		e := newObsEnv(t)
		tc.mod(e)
		req, _ := http.NewRequest("GET", e.srv.URL+"/statusz", nil)
		req.Header.Set("Accept", "text/html")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		page := string(b)
		if !strings.Contains(page, "Data directory") || !strings.Contains(page, tc.want) || !strings.Contains(page, "GiB free") {
			t.Errorf("%s: page lacks the Data directory row (%q, GiB free)", tc.name, tc.want)
		}
		if tc.name == "healthy" && strings.Contains(page, "NOT writable") {
			t.Error("healthy page says NOT writable")
		}
		for _, bad := range []string{"<form", "<button", "<input"} {
			if strings.Contains(page, bad) {
				t.Errorf("%s: page contains %s", tc.name, bad)
			}
		}
		for _, r := range reasons {
			if !strings.Contains(page, r) {
				t.Errorf("%s: page does not show the %s count", tc.name, r)
			}
		}
	}
}

func TestAuthSurfaceUnchangedWithDiskSignals(t *testing.T) {
	e := newObsEnv(t, func(c *Config) { c.Auth = Credentials{Username: "u", Password: "p"} })
	if code, _, _ := e.get(t, "/statusz"); code != 401 {
		t.Errorf("/statusz without credentials = %d; want 401", code)
	}
	if code, _, _ := e.get(t, "/metrics"); code != 200 {
		t.Errorf("/metrics without credentials = %d; want 200", code)
	}
	if code, _, _ := e.get(t, "/healthz"); code != 200 {
		t.Errorf("/healthz without credentials = %d; want 200", code)
	}
}

// newCappedCache is a real cache with a store cap (the cap lives in the cache; the chunked-body backstop is its capped reader).
func newCappedCache(t *testing.T, capBytes int64) *cache.Cache {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	c := cache.New(blobs, meta, cache.WithMaxBytes(capBytes))
	t.Cleanup(func() { _ = c.Close() })
	return c
}
