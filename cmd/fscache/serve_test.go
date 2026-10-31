package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
	"github.com/fosterstack/cache/internal/server"
)

var (
	errTestReconcile   = errors.New("test: reconcile failed")
	errTestClose       = errors.New("test: close failed")
	errTestShutdown    = errors.New("test: shutdown failed")
	errTestClearMarker = errors.New("test: clear marker failed")
	errTestServe       = errors.New("test: serve failed")
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
// closing the listener. Another process can take the port before it is
// bound again, so use it only where serve fails before it binds, or where
// the test needs an address it cannot learn from a running serve.
// Everywhere else set FSCACHE_ADDR to 127.0.0.1:0 and read the bound
// address with boundAddr.
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

// boundAddr returns the address named by the "fscache: starting" record in
// logs, a JSON log of the serve under test. serve binds before it logs that
// record and before it calls ready, so call this from the ready hook.
func boundAddr(t *testing.T, logs fmt.Stringer) string {
	t.Helper()
	for _, line := range strings.Split(logs.String(), "\n") {
		var rec struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "fscache: starting" {
			return rec.Addr
		}
	}
	t.Errorf("no \"fscache: starting\" record in the log:\n%s", logs)
	return ""
}

// serve should start, then shut down gracefully when the context is
// cancelled via the ready hook, returning nil.
func TestServeGracefulShutdown(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")

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

// A bad listen address is refused at startup (REQ-CFG-004).
func TestServeListenError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "256.256.256.256:99999") // unbindable
	err := serve(context.Background(), quietLogger(), nil)
	if err == nil || !strings.Contains(err.Error(), "FSCACHE_ADDR") {
		t.Fatalf("serve error = %v, want a refusal naming FSCACHE_ADDR", err)
	}
}

// A marker present at startup triggers reconciliation before serving.
func TestServeReconcilesOnUncleanMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	if err := serve(context.Background(), quietLogger(), nil); err == nil ||
		!strings.Contains(err.Error(), "metadata store") {
		t.Fatalf("serve error = %v, want a metadata store open error", err)
	}
}

// REQ-STORE-005-AC4: an unclean marker plus a reconcile that fails aborts
// startup before serving, naming the reconciliation failure; the stores
// are closed and the marker is still present, so the next start
// reconciles again.
func TestServeReconcileError(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	orig := cacheReconcile
	cacheReconcile = func(*cache.Cache, context.Context) (cache.ReconcileStats, error) {
		return cache.ReconcileStats{}, errTestReconcile
	}
	defer func() { cacheReconcile = orig }()
	origClose := cacheClose
	closes := 0
	cacheClose = func(c *cache.Cache) error { closes++; return origClose(c) }
	defer func() { cacheClose = origClose }()

	served := false
	if err := serve(context.Background(), quietLogger(), func() { served = true }); err == nil ||
		!strings.Contains(err.Error(), "reconciliation") {
		t.Fatalf("serve error = %v, want a reconciliation error", err)
	}
	if served {
		t.Error("serve reached the serving stage after a failed reconcile")
	}
	if closes != 1 {
		t.Errorf("stores closed %d times, want 1", closes)
	}
	// The index can be opened again: the failed start released it.
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("reopen the index after the failed start: %v", err)
	}
	if err := meta.Close(); err != nil {
		t.Fatalf("close the reopened index: %v", err)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a failed reconcile, want true", present, err)
	}
}

// REQ-STORE-005-AC4, the same mechanism for a panic inside the startup
// reconcile: the panic is not swallowed, the stores are closed and the
// marker is still present, so the next start reconciles again.
func TestServeReconcilePanicKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	const boom = "test: reconcile panicked"
	orig := cacheReconcile
	cacheReconcile = func(*cache.Cache, context.Context) (cache.ReconcileStats, error) { panic(boom) }
	defer func() { cacheReconcile = orig }()
	origClose := cacheClose
	closes := 0
	cacheClose = func(c *cache.Cache) error { closes++; return origClose(c) }
	defer func() { cacheClose = origClose }()

	recovered := func() (r any) {
		defer func() { r = recover() }()
		_ = serve(context.Background(), quietLogger(), nil)
		return nil
	}()
	if recovered != boom {
		t.Fatalf("recovered %v from serve, want the reconcile panic %q to propagate", recovered, boom)
	}
	if closes != 1 {
		t.Errorf("stores closed %d times, want 1", closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a panic in reconcile, want true", present, err)
	}
}

// REQ-STORE-005-AC4, the resume: a first start whose reconcile changes the
// index (one blob indexed) and then fails leaves the marker, so the second
// start runs the real reconcile, logs the reconciled line, adopts the rest
// and removes the stale temporary file left in +tmp.
func TestServeReconcileResumesAfterAFailedStart(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")

	// Three blobs with no index records, as after a crash between the writes.
	blobs, err := blobstore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("open blob store: %v", err)
	}
	keys := []string{"orphan-one", "orphan-two", "orphan-three"}
	for _, k := range keys {
		if _, err := blobs.Put(k, strings.NewReader("bytes of "+k)); err != nil {
			t.Fatalf("seed blob %s: %v", k, err)
		}
	}
	if err := blobs.Close(); err != nil {
		t.Fatalf("close blob store: %v", err)
	}
	// A temporary file from an interrupted write, in the store's +tmp directory.
	stray := filepath.Join(dir, "blobs", "+tmp", ".tmp-cafecafecafecafecafecafecafecafe")
	if err := os.MkdirAll(filepath.Dir(stray), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	// First start: the reconcile indexes one blob, then fails.
	orig := cacheReconcile
	cacheReconcile = func(c *cache.Cache, ctx context.Context) (cache.ReconcileStats, error) {
		if _, err := c.Put(ctx, keys[0], strings.NewReader("bytes of "+keys[0])); err != nil {
			return cache.ReconcileStats{}, err
		}
		return cache.ReconcileStats{AdoptedBlobs: 1}, errTestReconcile
	}
	err = serve(context.Background(), quietLogger(), nil)
	cacheReconcile = orig
	if err == nil || !strings.Contains(err.Error(), "reconciliation") {
		t.Fatalf("first start error = %v, want a reconciliation error", err)
	}
	if present, _ := markerPresent(uncleanMarkerPath(dir)); !present {
		t.Fatal("marker gone after the failed first start")
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("stale temp file gone before the resumed reconcile (stat err %v): the test would prove nothing", err)
	}

	// Second start: the real reconcile runs and adopts the other two.
	freshRegistry(t)
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, log, func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("second start returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second start did not shut down")
	}
	out := logs.String()
	if !strings.Contains(out, "fscache: reconciled") || !strings.Contains(out, "adopted_blobs=2") {
		t.Errorf("second start log lacks the reconciled line with adopted_blobs=2:\n%s", out)
	}
	if !strings.Contains(out, "removed_temp_files=1") {
		t.Errorf("second start log lacks removed_temp_files=1:\n%s", out)
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Errorf("stale temp file still in +tmp after the resumed reconcile (stat err %v)", err)
	}
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("reopen the index: %v", err)
	}
	defer func() {
		if err := meta.Close(); err != nil {
			t.Errorf("close the index: %v", err)
		}
	}()
	if n, err := meta.Count(); err != nil || n != len(keys) {
		t.Errorf("index holds %d entries (err %v), want %d", n, err, len(keys))
	}
	if present, _ := markerPresent(uncleanMarkerPath(dir)); present {
		t.Error("marker still present after the clean second run")
	}
}

// A store Close failure at shutdown is logged and keeps the marker.
func TestServeCloseErrorKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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

// countCloses wraps the cacheClose seam and counts the calls.
func countCloses(t *testing.T) *int {
	t.Helper()
	orig := cacheClose
	n := new(int)
	cacheClose = func(c *cache.Cache) error { *n++; return orig(c) }
	t.Cleanup(func() { cacheClose = orig })
	return n
}

// REQ-STORE-005-AC5, the serving error: after the startup reconcile
// completed, Serve fails; serve returns an error naming it, the stores are
// closed once and the marker is still present.
func TestServeErrorKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil { // the reconcile runs and completes
		t.Fatalf("seed marker: %v", err)
	}
	closes := countCloses(t)
	orig := httpServe
	httpServe = func(*http.Server, net.Listener) error { return errTestServe }
	defer func() { httpServe = orig }()

	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	err := serve(context.Background(), log, nil)
	if err == nil || !errors.Is(err, errTestServe) || !strings.Contains(err.Error(), "serve:") {
		t.Fatalf("serve error = %v, want a serve error wrapping %v", err, errTestServe)
	}
	if !strings.Contains(logs.String(), "fscache: reconciled") {
		t.Fatalf("the startup reconcile did not complete first:\n%s", logs.String())
	}
	if *closes != 1 {
		t.Errorf("stores closed %d times, want 1", *closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a serving error, want true", present, err)
	}
}

// REQ-STORE-005-AC5, the shutdown error with an upload in flight: a PUT
// whose body has not finished arriving holds a handler open; the shutdown
// fails (the grace period expired), the HTTP server is forced closed before
// the handler finishes, and the marker is still present.
func TestServeShutdownErrorWithUploadInFlightKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	closes := countCloses(t)
	orig := httpShutdown
	httpShutdown = func(*http.Server, context.Context) error { return context.DeadlineExceeded }
	defer func() { httpShutdown = orig }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs syncBuffer
	var addr string
	readyc := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() { addr = boundAddr(t, &logs); close(readyc) })
	}()
	select {
	case <-readyc:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not become ready")
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// Ten of the declared hundred bytes: the handler waits for the rest.
	if _, err := io.WriteString(conn, "PUT /in-flight-key HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\n0123456789"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// The blob store creates its temporary file before it reads the body:
	// once one exists, the handler is in flight.
	tmpDir := filepath.Join(dir, "blobs", "+tmp")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if entries, _ := os.ReadDir(tmpDir); len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the upload never reached the blob store")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-errc:
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "shutdown:") {
			t.Fatalf("serve error = %v, want a shutdown error wrapping %v", err, context.DeadlineExceeded)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return")
	}
	if *closes != 1 {
		t.Errorf("stores closed %d times, want 1", *closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a shutdown error with an upload in flight, want true", present, err)
	}
}

// REQ-STORE-005-AC5, the orphan: an upload whose blob was renamed into
// place but never indexed when the stores closed after a shutdown error
// (its record and its rollback delete both meet closed stores). The marker
// is still present, so the next start reconciles, adopts the blob
// (adopted_blobs=1) and, after its clean shutdown, clears the marker.
func TestServeShutdownErrorOrphanAdoptedOnNextStart(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")

	origShutdown := httpShutdown
	httpShutdown = func(*http.Server, context.Context) error { return context.DeadlineExceeded }
	origClose := cacheClose
	// The stores close after the forced HTTP close; at that moment the
	// in-flight upload's blob is in place with no index record. A second
	// handle on the same blob directory puts it there, the way the
	// handler's rename did.
	cacheClose = func(c *cache.Cache) error {
		b, err := blobstore.New(filepath.Join(dir, "blobs"))
		if err != nil {
			return err
		}
		if _, err := b.Put("orphan-key", strings.NewReader("stored, never indexed")); err != nil {
			return err
		}
		if err := b.Close(); err != nil {
			return err
		}
		return origClose(c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := serve(ctx, quietLogger(), func() { cancel() })
	httpShutdown, cacheClose = origShutdown, origClose
	if err == nil || !strings.Contains(err.Error(), "shutdown:") {
		t.Fatalf("first run error = %v, want a shutdown error", err)
	}
	if present, _ := markerPresent(uncleanMarkerPath(dir)); !present {
		t.Fatal("marker gone after the shutdown error")
	}

	// Next start: reconcile adopts the orphan; a clean shutdown clears the marker.
	freshRegistry(t)
	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx2, cancel2 := context.WithCancel(context.Background())
	if err := serve(ctx2, log, func() { cancel2() }); err != nil {
		t.Fatalf("next start returned %v", err)
	}
	out := logs.String()
	if !strings.Contains(out, "fscache: reconciled") || !strings.Contains(out, "adopted_blobs=1") {
		t.Errorf("next start log lacks the reconciled line with adopted_blobs=1:\n%s", out)
	}
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatalf("reopen the index: %v", err)
	}
	defer func() {
		if err := meta.Close(); err != nil {
			t.Errorf("close the index: %v", err)
		}
	}()
	if n, err := meta.Count(); err != nil || n != 1 {
		t.Errorf("index holds %d entries (err %v), want the adopted orphan", n, err)
	}
	if present, _ := markerPresent(uncleanMarkerPath(dir)); present {
		t.Error("marker still present after the clean next run")
	}
}

// proves: REQ-STORE-005-AC5 — end to end over real sockets, plain and TLS: an upload held in flight, a real serving error, then a restart on the same data directory
//
// Nothing here stands in for the server: Serve / ServeTLS are the real
// methods (the seam only hands the test the listener they were given), the
// upload is a real PUT whose body the test holds open after its first ten
// bytes, and the serving error is real: the listener is closed under the
// running server, whose accept loop then fails with net.ErrClosed. serve
// returns that error, the stores are closed once, and the marker is kept.
// A second serve on the same data directory finds the marker, reconciles
// before it serves, keeps the upload that completed before the error (served,
// counted the same by /statusz and /metrics), and does not adopt the held,
// partial upload (404, adopted_blobs=0, no temporary file left behind).
// The first run starts without a marker; the startup reconcile is the second start's.
//
// What it does not hold open: the window between a completed upload's
// rename and its index record is a few instructions inside cache.Put, with
// no point a socket can block on, so a real handler cannot be parked there.
// The adoption of such a blob is TestServeShutdownErrorOrphanAdoptedOnNextStart.
func TestServeRealServingErrorWithUploadInFlightThenRestart(t *testing.T) {
	for _, withTLS := range []bool{false, true} {
		name := "plain"
		if withTLS {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) { realServingErrorThenRestart(t, withTLS) })
	}
}

func realServingErrorThenRestart(t *testing.T, withTLS bool) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	var addr string // set by each run's ready hook, which runs before the test reads it
	scheme := "http"
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	dial := func() (net.Conn, error) { return net.DialTimeout("tcp", addr, 10*time.Second) }
	if withTLS {
		p := writePair(t, t.TempDir(), "ac5e2e", "MARKER-AC5E2E-7f3d9c")
		t.Setenv("FSCACHE_TLS_CERT", p.certPath)
		t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
		scheme = "https"
		client = tlsTestClient(p.leaf)
		pool := x509.NewCertPool()
		pool.AddCert(p.leaf)
		dial = func() (net.Conn, error) {
			d := &net.Dialer{Timeout: 10 * time.Second}
			return tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
		}
	}
	do := func(method, path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, scheme+"://"+addr+path, strings.NewReader(body))
		if err != nil {
			t.Fatalf("request %s %s: %v", method, path, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s %s: %v", method, path, err)
		}
		return resp.StatusCode, string(b)
	}

	// The real Serve / ServeTLS, with the listener handed to the test. The
	// other one fails the test if serve calls it.
	lnc := make(chan net.Listener, 2)
	origPlain, origTLS := httpServe, httpServeTLS
	t.Cleanup(func() { httpServe, httpServeTLS = origPlain, origTLS })
	wrong := func(*http.Server, net.Listener) error {
		t.Error("serve chose the wrong serving path")
		return nil
	}
	httpServe, httpServeTLS = func(s *http.Server, l net.Listener) error {
		lnc <- l
		return origPlain(s, l)
	}, wrong
	if withTLS {
		httpServe, httpServeTLS = wrong, func(s *http.Server, l net.Listener) error {
			lnc <- l
			return origTLS(s, l)
		}
	}

	// First run: no marker at start, so no reconcile; the marker is written.
	closes := countCloses(t)
	var logs1 syncBuffer
	readyc := make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		errc <- serve(context.Background(), slog.New(slog.NewJSONHandler(&logs1, nil)), func() { addr = boundAddr(t, &logs1); close(readyc) })
	}()
	select {
	case <-readyc:
	case <-time.After(10 * time.Second):
		t.Fatal("first run did not become ready")
	}
	var ln net.Listener
	select {
	case ln = <-lnc:
	case <-time.After(10 * time.Second):
		t.Fatal("the serving goroutine never received the listener")
	}

	// An upload that completes before the error: stored and indexed.
	const doneBody = "completed before the serving error"
	if code, _ := do(http.MethodPut, "/done-key", doneBody); code != http.StatusCreated {
		t.Fatalf("PUT /done-key answered %d, want 201", code)
	}

	// The held upload: ten of the declared hundred bytes, then nothing.
	held, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = held.Close() }()
	if _, err := io.WriteString(held, "PUT /held-key HTTP/1.1\r\nHost: test\r\nContent-Length: 100\r\n\r\n0123456789"); err != nil {
		t.Fatalf("write the held request: %v", err)
	}
	// The blob store creates its temporary file before it copies the body,
	// so the file existing is not enough: wait until it holds the ten bytes
	// sent so far. Then the handler is in flight, mid-copy, held on the rest.
	const heldSent = 10
	tmpDir := filepath.Join(dir, "blobs", "+tmp")
	var heldSize int64 = -1
	deadline := time.Now().Add(10 * time.Second)
	for {
		if entries, _ := os.ReadDir(tmpDir); len(entries) == 1 {
			if fi, err := entries[0].Info(); err == nil {
				heldSize = fi.Size()
			}
		}
		if heldSize == heldSent {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the held upload's temporary file holds %d bytes after 10s (-1: none), want the %d sent", heldSize, heldSent)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if heldSize != heldSent {
		t.Fatalf("held upload size = %d, want %d", heldSize, heldSent)
	}

	// The real serving error: the listener fails under the running server.
	if err := ln.Close(); err != nil {
		t.Fatalf("close the listener: %v", err)
	}
	select {
	case err := <-errc:
		if err == nil || !errors.Is(err, net.ErrClosed) || !strings.Contains(err.Error(), "serve:") {
			t.Fatalf("first run error = %v, want a serve error wrapping %v", err, net.ErrClosed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first run did not return on the serving error")
	}
	if *closes != 1 {
		t.Errorf("stores closed %d times, want 1", *closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Fatalf("unclean marker present = %v (err %v) after a serving error with an upload in flight, want true", present, err)
	}
	// The held upload was cut, never answered: the server closed its
	// connection before the handler finished.
	if err := held.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	got, rerr := io.ReadAll(held)
	var ne net.Error
	if errors.As(rerr, &ne) && ne.Timeout() {
		t.Fatal("the held upload's connection is still open after serve returned")
	}
	if len(got) != 0 {
		t.Errorf("the held upload was answered: %q", got)
	}
	_ = held.Close()

	// Second run on the same data directory.
	freshRegistry(t)
	var logs syncBuffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ready2 := make(chan struct{})
	errc2 := make(chan error, 1)
	go func() { errc2 <- serve(ctx2, log, func() { addr = boundAddr(t, &logs); close(ready2) }) }()
	select {
	case <-ready2:
	case err := <-errc2:
		t.Fatalf("second run returned before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("second run did not become ready")
	}
	select {
	case <-lnc:
	case <-time.After(10 * time.Second):
		t.Fatal("the second run's serving goroutine never received the listener")
	}
	out := logs.String() // the reconcile runs before ready
	if !strings.Contains(out, "unclean shutdown detected") || !strings.Contains(out, "fscache: reconciled") {
		t.Fatalf("second run did not reconcile before serving:\n%s", out)
	}
	if !strings.Contains(out, `"adopted_blobs":0`) {
		t.Errorf("second run adopted a blob; the held upload was partial:\n%s", out)
	}
	if code, body := do(http.MethodGet, "/done-key", ""); code != http.StatusOK || body != doneBody {
		t.Errorf("GET /done-key = %d %q, want 200 %q", code, body, doneBody)
	}
	if code, _ := do(http.MethodGet, "/held-key", ""); code != http.StatusNotFound {
		t.Errorf("GET /held-key = %d, want 404: a partial upload is not a hit", code)
	}
	if entries, err := os.ReadDir(tmpDir); err != nil || len(entries) != 0 {
		t.Errorf("temporary files after the reconcile: %d (err %v), want none", len(entries), err)
	}
	_, statusBody := do(http.MethodGet, "/statusz", "")
	var st struct {
		Bytes   int64 `json:"store_bytes"`
		Entries int   `json:"store_entries"`
	}
	if err := json.Unmarshal([]byte(statusBody), &st); err != nil {
		t.Fatalf("decode /statusz: %v\n%s", err, statusBody)
	}
	_, scrape := do(http.MethodGet, "/metrics", "")
	if st.Entries != 1 || st.Bytes != int64(len(doneBody)) {
		t.Errorf("/statusz entries=%d bytes=%d, want 1 and %d", st.Entries, st.Bytes, len(doneBody))
	}
	if got, want := metricLine(scrape, "fscache_store_entries "), fmt.Sprintf("fscache_store_entries %d", st.Entries); got != want {
		t.Errorf("/metrics %q, /statusz says %q", got, want)
	}
	if got, want := metricLine(scrape, "fscache_store_bytes "), fmt.Sprintf("fscache_store_bytes %d", st.Bytes); got != want {
		t.Errorf("/metrics %q, /statusz says %q", got, want)
	}

	cancel2()
	select {
	case err := <-errc2:
		if err != nil {
			t.Fatalf("second run returned %v on a clean shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second run did not shut down")
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || present {
		t.Errorf("unclean marker present = %v (err %v) after the clean second run, want false", present, err)
	}
}

// recoverServe runs serve and returns what it panicked with (nil if it
// returned normally).
func recoverServe(ctx context.Context, ready func()) (r any) {
	defer func() { r = recover() }()
	_ = serve(ctx, quietLogger(), ready)
	return nil
}

// REQ-STORE-005 (the marker is removed on clean shutdown only): a panic
// after the startup reconcile and before the serving loop, here in the
// ready callback, is not a clean shutdown. The panic propagates, the
// stores are closed once and the marker is still present.
func TestServePanicInReadyKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	closes := countCloses(t)
	const boom = "test: ready panicked"
	if r := recoverServe(context.Background(), func() { panic(boom) }); r != boom {
		t.Fatalf("recovered %v from serve, want the panic %q to propagate", r, boom)
	}
	if *closes != 1 {
		t.Errorf("stores closed %d times, want 1", *closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a panic in ready, want true", present, err)
	}
}

// The same for a panic while the HTTP handler is built (server.New).
func TestServePanicInServerNewKeepsMarker(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	closes := countCloses(t)
	const boom = "test: server.New panicked"
	orig := serverNew
	serverNew = func(server.Config) http.Handler { panic(boom) }
	defer func() { serverNew = orig }()
	if r := recoverServe(context.Background(), nil); r != boom {
		t.Fatalf("recovered %v from serve, want the panic %q to propagate", r, boom)
	}
	if *closes != 1 {
		t.Errorf("stores closed %d times, want 1", *closes)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a panic in server.New, want true", present, err)
	}
}

// REQ-STORE-005-AC5, the select race: the shutdown signal is taken first,
// Shutdown returns nil, and the serving goroutine then reports a serving
// error. The error is not swallowed: serve returns it and the marker stays.
func TestServeErrorAfterShutdownSignalIsReturned(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	release := make(chan struct{})
	origServe, origShutdown := httpServe, httpShutdown
	// Serve blocks until Shutdown runs, so the select can only take the
	// cancelled context; then Serve fails with a serving error.
	httpServe = func(_ *http.Server, l net.Listener) error {
		<-release
		_ = l.Close()
		return errTestServe
	}
	httpShutdown = func(*http.Server, context.Context) error { close(release); return nil }
	defer func() { httpServe, httpShutdown = origServe, origShutdown }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := serve(ctx, quietLogger(), nil)
	if err == nil || !errors.Is(err, errTestServe) || !strings.Contains(err.Error(), "serve:") {
		t.Fatalf("serve error = %v, want the serving error %v", err, errTestServe)
	}
	if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || !present {
		t.Errorf("unclean marker present = %v (err %v) after a serving error during shutdown, want true", present, err)
	}
}

// proves: REQ-STORE-005-AC5 — with TLS on, a listener error, a serving error after the shutdown signal and a shutdown error each keep the marker; only the clean return clears it
//
// The same exits as the plain-HTTP tests above, taken through ServeTLS: the
// plain Serve seam fails the test if it is called, so every case runs on the
// HTTPS path. The listener error is real: the listener is closed under
// ServeTLS, which then returns net.ErrClosed, not http.ErrServerClosed. The
// serving error after the shutdown signal is real too: the real ServeTLS,
// shown accepting by a real TLS handshake, fails on its closed listener after
// the signal was taken and before the real Shutdown runs.
func TestServeTLSErrorsKeepMarker(t *testing.T) {
	p := writePair(t, t.TempDir(), "ac5", "MARKER-AC5-1a2b3c")
	realTLS := httpServeTLS
	for _, tc := range []struct {
		name      string
		raceStop  bool // ServeTLS fails only after the shutdown signal was taken
		noSignal  bool // no shutdown signal: serve must return on the error alone
		serveTLS  func(*http.Server, net.Listener) error
		shutdown  func(*http.Server, context.Context) error
		wantErr   error
		wantInErr string
		keep      bool
	}{
		{
			name: "listener error",
			serveTLS: func(s *http.Server, l net.Listener) error {
				_ = l.Close()
				return realTLS(s, l)
			},
			noSignal: true, wantErr: net.ErrClosed, wantInErr: "serve:", keep: true,
		},
		{name: "serving error after the shutdown signal", raceStop: true, wantErr: net.ErrClosed, wantInErr: "serve:", keep: true},
		{
			name:     "shutdown error",
			serveTLS: realTLS,
			shutdown: func(*http.Server, context.Context) error { return errTestShutdown },
			wantErr:  errTestShutdown, wantInErr: "shutdown:", keep: true,
		},
		{name: "clean return", serveTLS: realTLS, keep: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dir := t.TempDir()
			t.Setenv("FSCACHE_DATA_DIR", dir)
			t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
			t.Setenv("FSCACHE_TLS_CERT", p.certPath)
			t.Setenv("FSCACHE_TLS_KEY", p.keyPath)
			closes := countCloses(t)

			origPlain, origTLS, origShutdown := httpServe, httpServeTLS, httpShutdown
			t.Cleanup(func() { httpServe, httpServeTLS, httpShutdown = origPlain, origTLS, origShutdown })
			httpServe = func(*http.Server, net.Listener) error {
				t.Error("plain Serve called with TLS configured")
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var logs syncBuffer
			ready := func() { cancel() }
			if tc.noSignal {
				ready = nil
			}
			serveTLS := tc.serveTLS
			if tc.shutdown != nil {
				httpShutdown = tc.shutdown
			}
			if tc.raceStop {
				// The real ServeTLS. A real TLS handshake proves it is
				// accepting; only then is the shutdown signal given, so the
				// select can only take the cancelled context. The Shutdown
				// seam then closes the listener under the running ServeTLS,
				// waits for its real accept error (net.ErrClosed: the server
				// is not yet shutting down) and runs the real Shutdown.
				lnc := make(chan net.Listener, 1)
				returned := make(chan struct{})
				serveTLS = func(s *http.Server, l net.Listener) error {
					lnc <- l
					defer close(returned)
					return realTLS(s, l)
				}
				httpShutdown = func(s *http.Server, c context.Context) error {
					_ = (<-lnc).Close()
					<-returned
					return origShutdown(s, c)
				}
				pool := x509.NewCertPool()
				pool.AddCert(p.leaf)
				ready = func() {
					d := &net.Dialer{Timeout: 10 * time.Second}
					conn, err := tls.DialWithDialer(d, "tcp", boundAddr(t, &logs), &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
					if err != nil {
						t.Errorf("TLS handshake with the running ServeTLS: %v", err)
					} else {
						_ = conn.Close()
					}
					cancel()
				}
			}
			var tlsCalls atomic.Int32
			httpServeTLS = func(s *http.Server, l net.Listener) error { tlsCalls.Add(1); return serveTLS(s, l) }

			errc := make(chan error, 1)
			go func() { errc <- serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), ready) }()
			var err error
			select {
			case err = <-errc:
			case <-time.After(10 * time.Second):
				t.Fatal("serve did not return")
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("serve: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("serve error = %v, want %q wrapping %v", err, tc.wantInErr, tc.wantErr)
			}
			if n := tlsCalls.Load(); n != 1 {
				t.Errorf("ServeTLS called %d times, want 1", n)
			}
			if *closes != 1 {
				t.Errorf("stores closed %d times, want 1", *closes)
			}
			if present, err := markerPresent(uncleanMarkerPath(dir)); err != nil || present != tc.keep {
				t.Errorf("unclean marker present = %v (err %v), want %v", present, err, tc.keep)
			}
		})
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	t.Setenv("FSCACHE_USERNAME", "u")
	t.Setenv("FSCACHE_PASSWORD", "p")
	t.Setenv("FSCACHE_MAX_BYTES", "64") // holds one small entry, evicts on the next

	var logs syncBuffer
	evicted := make(chan bool, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
			defer cancel()
			addr := boundAddr(t, &logs)
			health, err := http.Get("http://" + addr + "/healthz")
			if err != nil {
				t.Errorf("healthz: %v", err)
				evicted <- false
				return
			}
			_ = health.Body.Close()
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
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
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

// serve() takes the first store sample BEFORE the listener opens: the first scrape, with no request before it, already holds measured values (REQ-OBS-002-AC10).
func TestServeSeedsTheDiskGaugesBeforeAnyRequest(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	var logs syncBuffer
	var body string
	go func() {
		errc <- serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
			addr := boundAddr(t, &logs)
			resp, err := http.Get("http://" + addr + "/metrics")
			if err != nil {
				t.Errorf("scrape: %v", err)
			} else {
				b, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				body = string(b)
			}
			cancel()
		})
	}()
	select {
	case <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if !strings.Contains(body, "fscache_store_writable 1\n") {
		t.Errorf("the first scrape does not show fscache_store_writable 1:\n%s", body)
	}
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "fscache_store_free_bytes ") && (strings.HasSuffix(l, " 0")) {
			t.Errorf("fscache_store_free_bytes is 0 on a healthy start: %q", l)
		}
	}
	if !strings.Contains(body, "fscache_store_free_bytes ") {
		t.Errorf("fscache_store_free_bytes is absent from the first scrape")
	}
}

// The first sample is taken at start, before the listener opens: with a data directory that cannot be written the "not writable" line is already in the log
// when the ready hook runs, before any scrape could have triggered a lazy measurement (REQ-OBS-002-AC10).
func TestServeTakesTheFirstSampleBeforeReady(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "blobs"), 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(filepath.Join(dir, "blobs"), 0o700) }()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var atReady string
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, log, func() { atReady = buf.String(); cancel() }) }()
	select {
	case <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if !strings.Contains(atReady, "store_writable") {
		t.Errorf("no 'store_writable' line was logged before the server announced it was ready:\n%s", atReady)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// REQ-OBS-002-AC10, first case, on the REAL path: a server that started healthy and whose volume then stops accepting writes (here the blobs directory becomes
// read-only for the process) reports fscache_store_writable 0 with the real free bytes within one refresh, counts the failed PUTs, and keeps serving GETs.
func TestServeHealthyStartThenTheVolumeGoesBadKeepsServingGets(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs syncBuffer
	var addr string // set in the ready hook, before do is used
	var putOK, putBad, getCode int
	var body string
	do := func(method, path, data string) (int, string) {
		req, _ := http.NewRequest(method, "http://"+addr+path, strings.NewReader(data))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, ""
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, slog.New(slog.NewJSONHandler(&logs, nil)), func() {
			addr = boundAddr(t, &logs)
			if c, _ := do(http.MethodGet, "/healthz", ""); c != 200 {
				t.Errorf("healthz status = %d, want 200", c)
			}
			putOK, _ = do(http.MethodPut, "/kgood", "good data")
			_ = os.Chmod(filepath.Join(dir, "blobs"), 0o500) // the volume stops accepting writes
			defer func() { _ = os.Chmod(filepath.Join(dir, "blobs"), 0o700) }()
			putBad, _ = do(http.MethodPut, "/kbad", "bad data")
			for i := 0; i < 100; i++ { // the failed PUT marked the sample stale: the next scrape measures again
				_, body = do(http.MethodGet, "/metrics", "")
				if strings.Contains(body, "fscache_store_writable 0\n") {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			getCode, _ = do(http.MethodGet, "/kgood", "")
			cancel()
		})
	}()
	select {
	case <-errc:
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not shut down")
	}
	if putOK != http.StatusCreated && putOK != http.StatusOK && putOK != http.StatusNoContent {
		t.Fatalf("the healthy PUT answered %d", putOK)
	}
	if putBad < 400 {
		t.Errorf("the PUT on the bad volume answered %d; want an error", putBad)
	}
	if !strings.Contains(body, "fscache_store_writable 0\n") {
		t.Errorf("the gauge does not read 0 after the volume went bad:\n%s", body)
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	fsFree := float64(st.Bavail) * float64(st.Bsize) // #nosec G115 -- block counts of a test filesystem fit a float64
	var gauge float64
	if _, err := fmt.Sscanf(metricLine(body, "fscache_store_free_bytes "), "fscache_store_free_bytes %g", &gauge); err != nil || gauge <= 0 {
		t.Errorf("fscache_store_free_bytes is absent or not positive: %q\n%s", metricLine(body, "fscache_store_free_bytes "), body)
	} else if d := gauge - fsFree; d > 256<<20 || d < -(256<<20) { // the disk keeps changing under the test: a generous tolerance, far below any wrong constant
		t.Errorf("fscache_store_free_bytes %.0f is not close to the filesystem's %.0f", gauge, fsFree)
	}
	if got := metricLine(body, `fscache_put_errors_total{reason="read_only"} `); got != `fscache_put_errors_total{reason="read_only"} 1` {
		t.Errorf("the failed PUT must count exactly once under read_only; got %q\n%s", got, body)
	}
	for _, other := range []string{"no_space", "too_large", "client_aborted", "other"} {
		if got := metricLine(body, `fscache_put_errors_total{reason="`+other+`"} `); got != `fscache_put_errors_total{reason="`+other+`"} 0` {
			t.Errorf("reason %s moved: %q", other, got)
		}
	}
	if getCode != http.StatusOK {
		t.Errorf("GET of a stored blob answered %d on the bad volume; want 200", getCode)
	}
}

// REQ-OBS-002-AC10, second case, on the REAL path: a server asked to START on a read-only data directory exits at start with the fatal error naming the failed
// write, serves nothing and never reports writable 1 for a volume it could not write.
func TestServeStartOnAReadOnlyDirectoryFailsFastAndServesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	var serveCalls atomic.Int32
	origPlain, origTLS := httpServe, httpServeTLS
	t.Cleanup(func() { httpServe, httpServeTLS = origPlain, origTLS })
	httpServe = func(*http.Server, net.Listener) error { serveCalls.Add(1); return errTestServe }
	httpServeTLS = func(*http.Server, net.Listener) error { serveCalls.Add(1); return errTestServe }
	ready := false
	err := serve(context.Background(), quietLogger(), func() { ready = true })
	if err == nil || !strings.Contains(err.Error(), "write shutdown marker") {
		t.Fatalf("serve error = %v; want the fatal naming the failed write (write shutdown marker)", err)
	}
	if ready {
		t.Error("the ready hook ran: the server started on a directory it could not write")
	}
	if n := serveCalls.Load(); n != 0 {
		t.Errorf("the server was started %d times on a directory it could not write", n)
	}
}

// metricLine returns the first line of a scrape that starts with prefix, or "".
func metricLine(body, prefix string) string {
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}
