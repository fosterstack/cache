package cache

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/metadata"
)

// openTestStores builds stores in caller-controlled dirs so tests can
// close and reopen them — the restart-shaped scenarios REQ-STORE-001 and
// REQ-STORE-005 describe.
func openTestStores(t *testing.T, blobDir, metaPath string) (*blobstore.Store, *metadata.Store) {
	t.Helper()
	blobs, err := blobstore.New(blobDir)
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(metaPath)
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	return blobs, meta
}

func put(t *testing.T, c *Cache, key, body string) {
	t.Helper()
	if _, err := c.Put(context.Background(), key, strings.NewReader(body)); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
}

// REQ-STORE-001-AC1: a cleanly closed store serves the same bytes after
// reopen, with totals intact.
func TestRestartPersistence(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	put(t, c, "restart/key", "survives")
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	blobs2, meta2 := openTestStores(t, blobDir, metaPath)
	c2 := New(blobs2, meta2)
	defer func() { _ = c2.Close() }()
	rc, size, err := c2.Get(context.Background(), "restart/key")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	defer func() { _ = rc.Close() }()
	b, _ := io.ReadAll(rc)
	if string(b) != "survives" || size != int64(len("survives")) {
		t.Errorf("got %q (size %d) after restart", b, size)
	}
	if total, _ := c2.TotalSize(); total != int64(len("survives")) {
		t.Errorf("TotalSize after restart = %d", total)
	}
}

// REQ-STORE-004-AC1: metadata failure fails the PUT and removes the blob.
// Injection is real, not mocked: the metadata store is closed underneath
// the cache, so Record fails exactly as it would on a full disk or a
// closed database.
func TestPutFailsAndRemovesBlobWhenMetadataFails(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	defer func() { _ = blobs.Close() }()

	if err := meta.Close(); err != nil { // the injection
		t.Fatalf("closing metadata store: %v", err)
	}
	_, err := c.Put(context.Background(), "doomed/key", strings.NewReader("bytes"))
	if err == nil {
		t.Fatal("Put succeeded although the metadata record could not be written — the client was told 'stored' for an entry the index will never see")
	}
	if _, statErr := blobs.Stat("doomed/key"); statErr == nil {
		t.Error("the blob was left on disk after the failed PUT — an untracked orphan by construction")
	}
}

// REQ-STORE-005-AC1: an orphan blob is adopted — counted, retrievable,
// evictable.
func TestReconcileAdoptsOrphanBlob(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	// Crash-shaped state: blob written, record never made.
	if _, err := blobs.Put("orphan/blob", strings.NewReader("orphan-bytes")); err != nil {
		t.Fatalf("seed blob: %v", err)
	}
	c := New(blobs, meta)
	defer func() { _ = c.Close() }()

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.AdoptedBlobs != 1 {
		t.Errorf("AdoptedBlobs = %d, want 1", stats.AdoptedBlobs)
	}
	if total, _ := c.TotalSize(); total != int64(len("orphan-bytes")) {
		t.Errorf("TotalSize after adopt = %d, want %d", total, len("orphan-bytes"))
	}
	if n, _ := c.EntryCount(); n != 1 {
		t.Errorf("EntryCount after adopt = %d, want 1", n)
	}
}

// REQ-STORE-005-AC2: a dangling record is dropped and leaves the totals.
func TestReconcileDropsDanglingRecord(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	if err := meta.Record("ghost/key", 4096); err != nil { // record, no blob
		t.Fatalf("seed record: %v", err)
	}
	c := New(blobs, meta)
	defer func() { _ = c.Close() }()

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.DroppedRecords != 1 {
		t.Errorf("DroppedRecords = %d, want 1", stats.DroppedRecords)
	}
	if total, _ := c.TotalSize(); total != 0 {
		t.Errorf("TotalSize after drop = %d, want 0", total)
	}
}

// Both inconsistencies at once, plus a healthy entry that must survive.
func TestReconcileMixedStateTotalsCorrect(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	defer func() { _ = c.Close() }()
	put(t, c, "healthy/key", "abc")                                             // consistent
	if _, err := blobs.Put("orphan/k", strings.NewReader("dddd")); err != nil { // orphan
		t.Fatal(err)
	}
	if err := meta.Record("ghost/k", 999); err != nil { // dangling
		t.Fatal(err)
	}

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.AdoptedBlobs != 1 || stats.DroppedRecords != 1 {
		t.Errorf("stats = %+v, want 1 adopted, 1 dropped", stats)
	}
	if total, _ := c.TotalSize(); total != int64(len("abc")+len("dddd")) {
		t.Errorf("TotalSize = %d, want %d", total, len("abc")+len("dddd"))
	}
}

// An adopted blob participates in eviction like any other entry
// (REQ-STORE-005-AC1's "evictable" clause, plus eviction-after-restart).
func TestAdoptedBlobParticipatesInEviction(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	if _, err := blobs.Put("orphan/old", strings.NewReader("0123456789")); err != nil {
		t.Fatal(err)
	}
	c := New(blobs, meta, WithMaxBytes(12))
	defer func() { _ = c.Close() }()
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 10 bytes adopted; a 6-byte put must evict the adopted entry to fit.
	put(t, c, "fresh/key", "abcdef")
	if _, statErr := blobs.Stat("orphan/old"); statErr == nil {
		t.Error("adopted blob was not evicted although the cap demanded it")
	}
	if total, _ := c.TotalSize(); total > 12 {
		t.Errorf("TotalSize %d exceeds cap after eviction", total)
	}
}
