package cache

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/metadata"
)

func newTestCache(t *testing.T, opts ...Option) *Cache {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	c := New(blobs, meta, opts...)
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

func TestPutGetRoundTrip(t *testing.T) {
	c := newTestCache(t)
	ctx := context.Background()

	if _, err := c.Put(ctx, "key1", strings.NewReader("payload")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, size, err := c.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "payload" || size != 7 {
		t.Fatalf("got %q size %d", got, size)
	}
}

func TestGetMissingReturnsErrNotFound(t *testing.T) {
	c := newTestCache(t)
	_, _, err := c.Get(context.Background(), "missing")
	if err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestEvictionKeepsUnderCapAndKeepsNewest(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(25))
	ctx := context.Background()

	// Each entry is 10 bytes; cap is 25, so at most 2 fit.
	put := func(key string) {
		if _, err := c.Put(ctx, key, strings.NewReader("0123456789")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
		time.Sleep(2 * time.Millisecond) // ensure distinct last-access ordering
	}
	put("a")
	put("b")
	put("c")

	total, err := c.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total > 25 {
		t.Fatalf("TotalSize = %d, want <= 25", total)
	}

	// Oldest (a) should have been evicted; newest (c) must survive.
	if _, _, err := c.Get(ctx, "a"); err != ErrNotFound {
		t.Fatalf("expected a to be evicted, got err = %v", err)
	}
	if _, _, err := c.Get(ctx, "c"); err != nil {
		t.Fatalf("expected c to survive eviction, got err = %v", err)
	}
}

func TestGetTouchProtectsFromEviction(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(25))
	ctx := context.Background()

	put := func(key string) {
		if _, err := c.Put(ctx, key, strings.NewReader("0123456789")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	put("a")
	put("b")

	// Touch "a" so it's now more recently used than "b".
	rc, _, err := c.Get(ctx, "a")
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	time.Sleep(2 * time.Millisecond)

	put("c") // pushes total to 30, over the 25 cap; least-recent ("b") should go

	if _, _, err := c.Get(ctx, "a"); err != nil {
		t.Fatalf("expected a (recently touched) to survive, got err = %v", err)
	}
	if _, _, err := c.Get(ctx, "b"); err != ErrNotFound {
		t.Fatalf("expected b to be evicted, got err = %v", err)
	}
}

func TestNoCapMeansNoEviction(t *testing.T) {
	c := newTestCache(t) // maxBytes defaults to 0 == unbounded
	ctx := context.Background()
	for _, k := range []string{"a", "b", "c", "d"} {
		if _, err := c.Put(ctx, k, strings.NewReader("0123456789")); err != nil {
			t.Fatalf("Put(%s): %v", k, err)
		}
	}
	n, err := c.EntryCount()
	if err != nil {
		t.Fatalf("EntryCount: %v", err)
	}
	if n != 4 {
		t.Fatalf("EntryCount = %d, want 4 (no eviction expected)", n)
	}
}

func TestStatDoesNotAffectEvictionOrdering(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(25))
	ctx := context.Background()

	put := func(key string) {
		if _, err := c.Put(ctx, key, strings.NewReader("0123456789")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	put("a")
	put("b")

	// Stat "a" repeatedly — a Maven HEAD-style existence check — must NOT
	// count as usage and must not save it from LRU eviction.
	for i := 0; i < 5; i++ {
		if _, err := c.Stat("a"); err != nil {
			t.Fatalf("Stat: %v", err)
		}
	}
	put("c") // over cap; "a" is still the least-recently-used

	if _, _, err := c.Get(ctx, "a"); err != ErrNotFound {
		t.Fatalf("expected a to be evicted despite Stat calls, got err = %v", err)
	}
}

// TestConcurrentPutEvictsExactlyEnoughUnderCap is a regression test for an
// audit finding: without serializing evictToFit, concurrent Puts each read
// a stale total, select overlapping LRU-candidate batches, and "succeed" at
// deleting the same already-gone entries (blobstore/metadata Delete are
// idempotent) — the cap is never violated, but the eviction count and the
// onEvict-driven Prometheus counter come out wildly inflated relative to
// what was actually necessary. This asserts both the cap and the count.
func TestConcurrentPutEvictsExactlyEnoughUnderCap(t *testing.T) {
	const (
		numPuts   = 40
		entrySize = 10
		capBytes  = 50 // room for at most 5 entries
	)
	var evictedCount int64
	c := newTestCache(t, WithMaxBytes(capBytes), WithOnEvict(func(key string, size int64) {
		atomic.AddInt64(&evictedCount, 1)
	}))
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < numPuts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%03d", i)
			if _, err := c.Put(ctx, key, strings.NewReader("0123456789")); err != nil {
				t.Errorf("Put(%s): %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	total, err := c.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total > capBytes {
		t.Fatalf("TotalSize = %d, want <= %d", total, capBytes)
	}

	survivors, err := c.EntryCount()
	if err != nil {
		t.Fatalf("EntryCount: %v", err)
	}
	wantEvicted := int64(numPuts - survivors)
	gotEvicted := atomic.LoadInt64(&evictedCount)
	if gotEvicted != wantEvicted {
		t.Fatalf("evicted count = %d, want exactly %d (numPuts=%d - survivors=%d); "+
			"a mismatch means concurrent eviction passes are doing redundant work",
			gotEvicted, wantEvicted, numPuts, survivors)
	}
}

// TestEvictionGivesUpAfterRepeatedFailures is a regression test for an
// audit finding: if every candidate in every LRU batch fails to evict
// (e.g. a permission problem on the data directory), evictToFit used to
// loop forever for the lifetime of the request context instead of giving
// up — a resource-exhaustion path. This makes the shard directory
// unwritable so Delete fails for everything in it, then asserts
// evictToFit returns instead of hanging.
func TestEvictionGivesUpAfterRepeatedFailures(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions don't block root, so this reproduction doesn't apply")
	}
	c := newTestCache(t, WithMaxBytes(5)) // cap smaller than one entry
	ctx := context.Background()

	if _, err := c.Put(ctx, "onlykey", strings.NewReader("0123456789")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Lock down every existing shard subdirectory under the blob store
	// root (deletion needs write permission on a file's immediate parent,
	// which — because of content-key sharding — is a subdirectory, not
	// the root itself). Deliberately leave the root itself writable so a
	// *new* key (a different, not-yet-existing shard) can still be
	// written — this test wants eviction of the existing entry to fail
	// repeatedly, not the triggering write itself to fail. Restore
	// permissions in cleanup so t.TempDir can remove the tree afterward.
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := c.Put(ctx, "trigger", strings.NewReader("0123456789")); err != nil {
			t.Errorf("Put: %v", err)
		}
	}()

	select {
	case <-done:
		// evictToFit gave up after maxFailedEvictionBatches, as expected.
	case <-time.After(5 * time.Second):
		t.Fatal("evictToFit did not return within 5s — looks like an infinite retry loop, not a bounded give-up")
	}
}
