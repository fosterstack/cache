// Fault-injection tests for the error and edge paths that the happy-path
// suites in cache_test.go and reconcile_test.go cannot reach. Failures
// are injected two ways: for real, by closing a store underneath the
// cache or locking directories with os.Chmod; and — only where the
// filesystem and bbolt cannot produce the failure on demand (Close and
// Delete errors, a metadata write failing mid-reconcile) — by wrapping
// the real store in a fault* decorator via the blobStore/metaStore seam.
package cache

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.etcd.io/bbolt"
)

// captureLogger returns a logger whose output the test can assert on —
// the observable effect of WithLogger.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, nil)), buf
}

// faultBlobs wraps a real blobStore and fails the configured operations.
type faultBlobs struct {
	blobStore
	deleteErr error
	closeErr  error
}

func (f *faultBlobs) Delete(key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.blobStore.Delete(key)
}

func (f *faultBlobs) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.blobStore.Close()
}

// faultMeta wraps a real metaStore and fails the configured operations.
type faultMeta struct {
	metaStore
	recordErr error
	deleteErr error
	closeErr  error
}

func (f *faultMeta) Record(key string, size int64) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	return f.metaStore.Record(key, size)
}

func (f *faultMeta) Delete(key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.metaStore.Delete(key)
}

func (f *faultMeta) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.metaStore.Close()
}

// WithLogger must route the cache's diagnostics to the supplied logger,
// observable in what the logger captured.
func TestWithLoggerRoutesDiagnostics(t *testing.T) {
	logger, buf := captureLogger()
	c := newTestCache(t, WithLogger(logger))

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !strings.Contains(buf.String(), "reconciliation complete") {
		t.Errorf("supplied logger saw no reconciliation diagnostics; log output:\n%s", buf.String())
	}
}

// Reconcile must fail up front when the metadata index cannot be read.
func TestReconcileFailsWhenIndexUnreadable(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	defer func() { _ = blobs.Close() }()

	if err := meta.Close(); err != nil { // the injection
		t.Fatalf("closing metadata store: %v", err)
	}
	_, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("Reconcile succeeded although the metadata index could not be read")
	}
	if !strings.Contains(err.Error(), "read index") {
		t.Errorf("err = %v, want the read-index failure surfaced", err)
	}
}

// A cancelled context must stop the blob walk and surface the
// cancellation, not silently produce a partial reconciliation.
func TestReconcileHonorsContextCancellation(t *testing.T) {
	c := newTestCache(t)
	// At least one blob on disk so the walk callback (where ctx is
	// checked) actually runs.
	if _, err := c.blobs.Put("orphan/blob", strings.NewReader("bytes")); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stats, err := c.Reconcile(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if stats.AdoptedBlobs != 0 {
		t.Errorf("AdoptedBlobs = %d after cancellation, want 0", stats.AdoptedBlobs)
	}
}

// A failure to index an orphan blob must fail Reconcile with the key
// named — an adoption the operator believes happened but didn't is
// exactly the inconsistency Reconcile exists to remove.
func TestReconcileReportsAdoptionFailure(t *testing.T) {
	c := newTestCache(t)
	if _, err := c.blobs.Put("orphan/blob", strings.NewReader("bytes")); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	boom := errors.New("record failed")
	c.meta = &faultMeta{metaStore: c.meta, recordErr: boom} // the injection

	stats, err := c.Reconcile(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the injected record failure", err)
	}
	if !strings.Contains(err.Error(), `adopt "orphan/blob"`) {
		t.Errorf("err = %v, want the failed key named", err)
	}
	if stats.AdoptedBlobs != 0 {
		t.Errorf("AdoptedBlobs = %d, want 0 — the adoption did not happen", stats.AdoptedBlobs)
	}
}

// A failure to drop a dangling record must fail Reconcile with the key
// named, and the stats must not claim the drop happened.
func TestReconcileReportsDropFailure(t *testing.T) {
	c := newTestCache(t)
	if err := c.meta.Record("ghost/key", 4096); err != nil { // record, no blob
		t.Fatalf("seed record: %v", err)
	}
	boom := errors.New("delete failed")
	c.meta = &faultMeta{metaStore: c.meta, deleteErr: boom} // the injection

	stats, err := c.Reconcile(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the injected delete failure", err)
	}
	if !strings.Contains(err.Error(), `drop "ghost/key"`) {
		t.Errorf("err = %v, want the failed key named", err)
	}
	if stats.DroppedRecords != 0 {
		t.Errorf("DroppedRecords = %d, want 0 — the drop did not happen", stats.DroppedRecords)
	}
}

// A stale temp file from an interrupted write must be removed and
// counted.
func TestReconcileRemovesStaleTempFile(t *testing.T) {
	c := newTestCache(t)
	tmpPath := filepath.Join(c.blobs.Root(), ".tmp-deadbeef")
	if err := os.WriteFile(tmpPath, []byte("partial"), 0o600); err != nil {
		t.Fatalf("seed temp file: %v", err)
	}

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.RemovedTempFiles != 1 {
		t.Errorf("RemovedTempFiles = %d, want 1", stats.RemovedTempFiles)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("stale temp file still on disk (stat err = %v)", err)
	}
}

// A stale temp file that cannot be removed is logged and skipped — the
// rest of reconciliation must still succeed.
func TestReconcileLogsUnremovableStaleTempFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions don't block root, so this reproduction doesn't apply")
	}
	logger, buf := captureLogger()
	c := newTestCache(t, WithLogger(logger))

	// A temp file inside a read-only directory: the walk can list it
	// (r-x) but removal needs write permission on the parent.
	dir := filepath.Join(c.blobs.Root(), "aa")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".tmp-cafe"), []byte("partial"), 0o600); err != nil {
		t.Fatalf("seed temp file: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // the injection
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o750) })

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v — an unremovable temp file must not fail reconciliation", err)
	}
	if stats.RemovedTempFiles != 0 {
		t.Errorf("RemovedTempFiles = %d, want 0", stats.RemovedTempFiles)
	}
	if !strings.Contains(buf.String(), "stale temp file not removed") {
		t.Errorf("expected a warning about the unremovable temp file; log output:\n%s", buf.String())
	}
}

// A blob store Close failure must surface from Cache.Close — and the
// metadata store must still have been closed.
func TestCloseReportsBlobStoreError(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	boom := errors.New("blob close failed")
	c := New(blobs, meta)
	c.blobs = &faultBlobs{blobStore: blobs, closeErr: boom} // the injection

	err := c.Close()
	if !errors.Is(err, boom) {
		t.Fatalf("Close err = %v, want the blob store failure", err)
	}
	if !strings.Contains(err.Error(), "close blob store") {
		t.Errorf("err = %v, want the blob store named", err)
	}
	// "Closes both even if the first Close fails": the metadata store
	// must be closed — a write against it now fails.
	if recErr := meta.Record("k", 1); recErr == nil {
		t.Error("metadata store still accepts writes — it was not closed alongside the failing blob store")
	}
	_ = blobs.Close()
}

// A metadata Close failure must surface once the blob store closed
// cleanly.
func TestCloseReportsMetadataError(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	boom := errors.New("meta close failed")
	c := New(blobs, meta)
	c.meta = &faultMeta{metaStore: meta, closeErr: boom} // the injection
	defer func() { _ = meta.Close() }()

	err := c.Close()
	if !errors.Is(err, boom) {
		t.Fatalf("Close err = %v, want the metadata store failure", err)
	}
	if !strings.Contains(err.Error(), "close metadata store") {
		t.Errorf("err = %v, want the metadata store named", err)
	}
}

// When the metadata record fails AND the cleanup delete of the just-
// written blob also fails, Put must still report failure to the client
// and log the orphan for startup reconciliation to adopt.
func TestPutReportsWhenBlobCleanupAlsoFails(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	logger, buf := captureLogger()
	c := New(blobs, meta, WithLogger(logger))
	defer func() { _ = c.Close() }()

	recordBoom := errors.New("record failed")
	deleteBoom := errors.New("delete failed")
	c.meta = &faultMeta{metaStore: meta, recordErr: recordBoom}    // the injection
	c.blobs = &faultBlobs{blobStore: blobs, deleteErr: deleteBoom} // and its cleanup failing too

	_, err := c.Put(context.Background(), "doomed/key", strings.NewReader("bytes"))
	if !errors.Is(err, recordBoom) {
		t.Fatalf("Put err = %v, want the metadata record failure — the client must not be told 'stored'", err)
	}
	if !strings.Contains(buf.String(), "blob cleanup after metadata failure also failed") {
		t.Errorf("expected the orphaned blob to be logged for reconciliation; log output:\n%s", buf.String())
	}
	// The orphan really is on disk — exactly what Reconcile adopts later.
	if _, statErr := blobs.Stat("doomed/key"); statErr != nil {
		t.Errorf("orphan blob missing (stat err = %v) — the logged recovery path has nothing to recover", statErr)
	}
}

// A Touch failure must be logged but must not fail the read: the client
// still gets its bytes, only the recency bookkeeping is lost.
func TestGetLogsTouchFailureAndStillServes(t *testing.T) {
	logger, buf := captureLogger()
	c := newTestCache(t, WithLogger(logger))
	ctx := context.Background()
	if _, err := c.Put(ctx, "key1", strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.meta.Close(); err != nil { // the injection: Touch now fails
		t.Fatalf("closing metadata store: %v", err)
	}

	rc, size, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed although the blob is readable: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "payload" || size != 7 {
		t.Errorf("got %q size %d, want %q size 7", got, size, "payload")
	}
	if !strings.Contains(buf.String(), "metadata touch failed") {
		t.Errorf("expected the touch failure to be logged; log output:\n%s", buf.String())
	}
}

// A failed total-size lookup must abort the eviction pass with a log,
// not evict blindly on garbage numbers.
func TestEvictToFitLogsTotalSizeFailure(t *testing.T) {
	logger, buf := captureLogger()
	c := newTestCache(t, WithMaxBytes(5), WithLogger(logger))
	if err := c.meta.Close(); err != nil { // the injection
		t.Fatalf("closing metadata store: %v", err)
	}

	c.evictToFit(context.Background())
	if !strings.Contains(buf.String(), "total size lookup failed") {
		t.Errorf("expected the total-size failure to be logged; log output:\n%s", buf.String())
	}
}

// A cancelled request context must stop the eviction loop before it
// deletes anything on that pass.
func TestEvictToFitStopsOnCancelledContext(t *testing.T) {
	c := newTestCache(t) // unbounded, so Puts don't evict during setup
	ctx := context.Background()
	for _, k := range []string{"a", "b"} {
		if _, err := c.Put(ctx, k, strings.NewReader("0123456789")); err != nil {
			t.Fatalf("Put(%s): %v", k, err)
		}
	}
	c.maxBytes = 5 // now over cap, eviction has real work to refuse
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	c.evictToFit(cancelled)
	if n, err := c.EntryCount(); err != nil || n != 2 {
		t.Errorf("EntryCount = %d (err %v), want 2 — a cancelled context must not evict", n, err)
	}
}

// A failed LRU-candidate lookup must abort the eviction pass with a log.
// The injection is a genuinely corrupt metadata record: its size field
// decodes (so TotalSize succeeds and eviction starts) but its timestamp
// is out of int64 range (so LeastRecentlyUsed's full decode fails).
func TestEvictToFitLogsLRULookupFailure(t *testing.T) {
	metaPath := filepath.Join(t.TempDir(), "meta.db")
	db, err := bbolt.Open(metaPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("entries"))
		if err != nil {
			return err
		}
		val := make([]byte, 16)
		binary.BigEndian.PutUint64(val[0:8], 10)          // valid size: TotalSize works
		binary.BigEndian.PutUint64(val[8:16], ^uint64(0)) // timestamp > MaxInt64: decode fails
		return b.Put([]byte("corrupt/key"), val)
	})
	if err != nil {
		t.Fatalf("seed corrupt record: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("bbolt Close: %v", err)
	}

	blobs, meta := openTestStores(t, t.TempDir(), metaPath)
	logger, buf := captureLogger()
	c := New(blobs, meta, WithMaxBytes(5), WithLogger(logger))
	defer func() { _ = c.Close() }()

	c.evictToFit(context.Background()) // total 10 > cap 5, then LRU decode fails
	if !strings.Contains(buf.String(), "LRU lookup failed") {
		t.Errorf("expected the LRU lookup failure to be logged; log output:\n%s", buf.String())
	}
	if n, err := c.EntryCount(); err != nil || n != 1 {
		t.Errorf("EntryCount = %d (err %v), want 1 — nothing may be evicted on a failed lookup", n, err)
	}
}

// With the total over the cap but no candidates to evict, the loop must
// return rather than spin. The state is manufactured by calling
// evictToFit directly with a negative cap on an empty cache — the
// defensive "cap smaller than one entry" exit is unreachable through
// Put, which rejects such entries up front (REQ-EVICT-002).
func TestEvictToFitReturnsWhenNothingLeftToEvict(t *testing.T) {
	c := newTestCache(t)
	c.maxBytes = -1 // total (0) is "over cap" yet the index is empty

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.evictToFit(context.Background())
	}()
	select {
	case <-done:
	case <-timeAfter(5000):
		t.Fatal("evictToFit did not return with nothing left to evict — infinite loop")
	}
}

// When every candidate in every batch fails to evict, evictToFit must
// give up after maxFailedEvictionBatches and say so. Unlike
// TestEvictionGivesUpAfterRepeatedFailures (where the triggering Put's
// own fresh shard directory stays deletable, so eviction of the trigger
// itself makes progress), here every shard is locked and evictToFit is
// driven directly, so no batch can progress at all.
func TestEvictToFitGivesUpWhenNoBatchProgresses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions don't block root, so this reproduction doesn't apply")
	}
	logger, buf := captureLogger()
	c := newTestCache(t, WithLogger(logger)) // unbounded during setup
	ctx := context.Background()
	if _, err := c.Put(ctx, "onlykey", strings.NewReader("0123456789")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Lock every shard subdirectory so deleting the entry fails.
	root := c.blobs.Root()
	var lockedDirs []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root {
			lockedDirs = append(lockedDirs, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	for _, dir := range lockedDirs {
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod %s: %v", dir, err)
		}
	}
	t.Cleanup(func() {
		for _, dir := range lockedDirs {
			_ = os.Chmod(dir, 0o750)
		}
	})

	c.maxBytes = 5 // over cap; the only candidate is undeletable

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.evictToFit(ctx)
	}()
	select {
	case <-done:
	case <-timeAfter(5000):
		t.Fatal("evictToFit did not give up within 5s — looks like an infinite retry loop")
	}
	if !strings.Contains(buf.String(), "giving up after repeated failures") {
		t.Errorf("expected the give-up to be logged; log output:\n%s", buf.String())
	}
	if n, err := c.EntryCount(); err != nil || n != 1 {
		t.Errorf("EntryCount = %d (err %v), want 1 — the undeletable entry must still be tracked", n, err)
	}
}

// If the blob is deleted but its metadata record cannot be, evictOne
// must report it: a silently kept record would inflate totals forever.
func TestEvictOneReportsMetadataDeleteFailure(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()
	if _, err := c.Put(ctx, "key1", strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := c.meta.Close(); err != nil { // the injection: metadata Delete now fails
		t.Fatalf("closing metadata store: %v", err)
	}

	err := c.evictOne("key1")
	if err == nil {
		t.Fatal("evictOne succeeded although the metadata record could not be deleted")
	}
	if !strings.Contains(err.Error(), "delete metadata") {
		t.Errorf("err = %v, want the metadata delete named", err)
	}
	// The blob itself was deleted before the metadata failure.
	if _, statErr := c.blobs.Stat("key1"); statErr != ErrNotFound {
		t.Errorf("blob stat err = %v, want ErrNotFound — the blob delete happens first", statErr)
	}
}
