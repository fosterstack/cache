package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fosterstack/cache/internal/cache"
)

var (
	errTestReconcile   = errors.New("test: reconcile failed")
	errTestClose       = errors.New("test: close failed")
	errTestShutdown    = errors.New("test: shutdown failed")
	errTestClearMarker = errors.New("test: clear marker failed")
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// freshRegistry points the metrics seams at a private registry for this
// test, so repeated serve() invocations don't collide on the global one.
func freshRegistry(t *testing.T) {
	t.Helper()
	reg := prometheus.NewRegistry()
	origR, origG := metricsRegisterer, metricsGatherer
	metricsRegisterer, metricsGatherer = reg, reg
	t.Cleanup(func() { metricsRegisterer, metricsGatherer = origR, origG })
}

// freePort grabs an ephemeral port and returns "127.0.0.1:<port>" after
// closing the listener, so serve can bind it.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// serve should start, then shut down gracefully when the context is
// cancelled via the ready hook, returning nil.
func TestServeGracefulShutdown(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, quietLogger(), func() { cancel() })
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down within 10s")
	}
	// The clean shutdown must have cleared the marker.
	if present, _ := markerPresent(uncleanMarkerPath(dir)); present {
		t.Error("unclean marker still present after a clean shutdown")
	}
}

// A bad listen address makes the server goroutine error; serve returns
// that error rather than blocking forever.
func TestServeListenError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "256.256.256.256:99999") // unbindable
	err := serve(context.Background(), quietLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "serve") {
		t.Fatalf("serve error = %v, want a serve error", err)
	}
}

// A marker present at startup triggers reconciliation before serving.
func TestServeReconcilesOnUncleanMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	// Pre-place the marker to simulate an unclean prior shutdown.
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, quietLogger(), func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve with reconcile returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
}

// Config errors surface before any store is opened.
func TestServeConfigError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_MAX_BYTES", "not-a-number")
	if err := serve(context.Background(), quietLogger(), nil); err == nil {
		t.Fatal("serve accepted an invalid config")
	}
}

// An unwritable data dir fails the blob-store open (after the marker
// write, which also fails first on the same unwritable dir).
func TestServeOpenError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	clearEnv(t)
	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil { // read+execute, no write
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("FSCACHE_DATA_DIR", filepath.Join(locked, "data"))
	t.Setenv("FSCACHE_ADDR", freePort(t))
	if err := serve(context.Background(), quietLogger(), nil); err == nil {
		t.Fatal("serve succeeded against an unwritable data dir")
	}
}

// runMain maps a config error to exit code 1 and logs it.
func TestRunMainReturnsOneOnError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_MAX_BYTES", "-5")
	if code := runMain(); code != 1 {
		t.Fatalf("runMain = %d, want 1", code)
	}
}

// runMain returns 0 after a graceful shutdown driven by a real SIGTERM,
// covering run's own signal-context path.
func TestRunMainReturnsZeroOnSignal(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", freePort(t))
	done := make(chan int, 1)
	go func() { done <- runMain() }()
	// Give it a moment to bind and install the signal handler, then ask
	// it to stop. run() installs a SIGTERM handler, so this is caught,
	// not fatal to the test process.
	time.Sleep(1500 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runMain = %d, want 0 after graceful shutdown", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runMain did not return after SIGTERM")
	}
}

// main() delegates to runMain and passes the code to osExit. Override the
// exit seam so the test process survives.
func TestMainDelegatesToExit(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_MAX_BYTES", "garbage") // force runMain -> 1
	var got int
	var once sync.Once
	orig := osExit
	osExit = func(code int) { once.Do(func() { got = code }) }
	defer func() { osExit = orig }()
	main()
	if got != 1 {
		t.Fatalf("main exited %d, want 1", got)
	}
}

// markerPresent surfaces a stat error that is not "not exist" (a path
// whose parent is not a directory).
func TestMarkerPresentStatError(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Stat of afile/marker fails with ENOTDIR, not IsNotExist.
	_, err := markerPresent(filepath.Join(notDir, "marker"))
	if err == nil {
		t.Fatal("markerPresent returned nil error for a non-directory parent")
	}
}

// writeMarker surfaces a MkdirAll failure.
func TestWriteMarkerMkdirError(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := writeMarker(filepath.Join(notDir, "sub", "marker")); err == nil {
		t.Fatal("writeMarker returned nil for an impossible directory")
	}
}

// MAX_CONCURRENT_UPLOADS invalid is rejected by loadConfig.
func TestLoadConfigInvalidUploads(t *testing.T) {
	clearEnv(t)
	t.Setenv("FSCACHE_MAX_CONCURRENT_UPLOADS", "-1")
	if _, err := loadConfig(); err == nil {
		t.Fatal("loadConfig accepted a negative upload bound")
	}
}

// serve fails when the blob store cannot be opened (a file sits where the
// blobs directory must be).
func TestServeBlobOpenError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blobs"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	if err := serve(context.Background(), quietLogger(), nil); err == nil ||
		!strings.Contains(err.Error(), "blob store") {
		t.Fatalf("serve error = %v, want a blob store open error", err)
	}
}

// serve fails when the metadata store cannot be opened (a directory sits
// where meta.db must be a file).
func TestServeMetaOpenError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "meta.db"), 0o750); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	if err := serve(context.Background(), quietLogger(), nil); err == nil ||
		!strings.Contains(err.Error(), "metadata store") {
		t.Fatalf("serve error = %v, want a metadata store open error", err)
	}
}

// An unclean marker plus a reconcile that fails aborts startup before
// serving.
func TestServeReconcileError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	orig := cacheReconcile
	cacheReconcile = func(*cache.Cache, context.Context) (cache.ReconcileStats, error) {
		return cache.ReconcileStats{}, errTestReconcile
	}
	defer func() { cacheReconcile = orig }()
	if err := serve(context.Background(), quietLogger(), nil); err == nil ||
		!strings.Contains(err.Error(), "reconciliation") {
		t.Fatalf("serve error = %v, want a reconciliation error", err)
	}
}

// A store Close failure at shutdown is logged and keeps the marker.
func TestServeCloseErrorKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	orig := cacheClose
	cacheClose = func(c *cache.Cache) error { _ = orig(c); return errTestClose }
	defer func() { cacheClose = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, quietLogger(), func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v; the Close error is logged, not returned", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	// Close failed, so the marker must still be present.
	if present, _ := markerPresent(uncleanMarkerPath(dir)); !present {
		t.Error("marker was cleared despite a Close failure")
	}
}

// A Shutdown failure surfaces as a shutdown error.
func TestServeShutdownError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	orig := httpShutdown
	httpShutdown = func(*http.Server, context.Context) error { return errTestShutdown }
	defer func() { httpShutdown = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, quietLogger(), func() { cancel() }) }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "shutdown") {
			t.Fatalf("serve error = %v, want a shutdown error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}

// markerPresent failing at startup (a non-directory in the data path)
// aborts serve before anything is opened.
func TestServeMarkerCheckError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	notDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Setenv("FSCACHE_DATA_DIR", filepath.Join(notDir, "data"))
	t.Setenv("FSCACHE_ADDR", freePort(t))
	if err := serve(context.Background(), quietLogger(), nil); err == nil ||
		!strings.Contains(err.Error(), "shutdown marker") {
		t.Fatalf("serve error = %v, want a shutdown-marker check error", err)
	}
}

// Auth configured plus real eviction under a tiny cap covers the
// enabled-auth startup line and the onEvict metrics callback.
func TestServeAuthAndEviction(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	t.Setenv("FSCACHE_USERNAME", "u")
	t.Setenv("FSCACHE_PASSWORD", "p")
	t.Setenv("FSCACHE_MAX_BYTES", "64") // holds one small entry, evicts on the next

	// Read the bound address back via the ready hook by resolving the env.
	addr := os.Getenv("FSCACHE_ADDR")
	evicted := make(chan bool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, quietLogger(), func() {
			defer cancel()
			// Wait for the listener to actually accept before driving
			// traffic (ready() fires at goroutine handoff, which can
			// precede the bind - the source of a CI-only flake).
			ready := false
			for range 100 {
				resp, err := http.Get("http://" + addr + "/healthz")
				if err == nil {
					_ = resp.Body.Close()
					ready = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				evicted <- false
				return
			}
			// Two authenticated 40-byte PUTs against a 64-byte cap: the
			// second must evict the first, firing the onEvict callback.
			put := func(k string) {
				req, _ := http.NewRequest(http.MethodPut, "http://"+addr+"/"+k,
					strings.NewReader(strings.Repeat("x", 40)))
				req.SetBasicAuth("u", "p")
				if resp, err := http.DefaultClient.Do(req); err == nil {
					_ = resp.Body.Close()
				}
			}
			put("k1")
			put("k2")
			// The oversized-for-the-cap pair must have evicted k1.
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/k1", nil)
			req.SetBasicAuth("u", "p")
			resp, err := http.DefaultClient.Do(req)
			gone := err == nil && resp.StatusCode == http.StatusNotFound
			if resp != nil {
				_ = resp.Body.Close()
			}
			evicted <- gone
		})
	}()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if !<-evicted {
		t.Fatal("expected k1 to be evicted (onEvict callback path); it was not")
	}
}

// A clearMarker failure during a clean shutdown is logged, not returned.
func TestServeClearMarkerError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", freePort(t))
	orig := clearMarkerFn
	clearMarkerFn = func(string) error { return errTestClearMarker }
	defer func() { clearMarkerFn = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, quietLogger(), func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned %v; a clearMarker error is logged, not returned", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
}
