package cache

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/metadata"
)

func newLockTestCache(t *testing.T) *Cache {
	t.Helper()
	blobs, err := blobstore.New(t.TempDir())
	if err != nil {
		t.Fatalf("blobstore.New: %v", err)
	}
	meta, err := metadata.Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("metadata.Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	return New(blobs, meta)
}

// Rule 3 (tryLockKey): when it returns ok, it holds the lock, so a lockKey of the same key waits for the release.
func TestTryLockKeyHoldsLock(t *testing.T) {
	c := newLockTestCache(t)
	release, ok := c.tryLockKey("k")
	if !ok {
		t.Fatal("tryLockKey on an idle key returned ok=false")
	}
	var acquired atomic.Bool
	done := make(chan struct{})
	go func() {
		rel := c.lockKey("k")
		acquired.Store(true)
		rel()
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	if acquired.Load() {
		t.Fatal("lockKey acquired while tryLockKey held the key")
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("lockKey never acquired after release")
	}
}

// Rule 3: tryLockKey ok=true means no other caller holds the key; holders never exceeds 1 under contention.
func TestTryLockKeyExcludesLockKey(t *testing.T) {
	c := newLockTestCache(t)
	const rounds = 20000
	var holders, tries, bad atomic.Int32
	enter := func() {
		if holders.Add(1) != 1 {
			bad.Add(1)
		}
		holders.Add(-1)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if rel, ok := c.tryLockKey("k"); ok {
				tries.Add(1)
				enter()
				rel()
			}
		}
	}()
	for y := 0; y < 3; y++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				rel := c.lockKey("k")
				enter()
				rel()
			}
		}()
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Errorf("key lock held by two callers at once, %d times (%d tryLockKey successes)", n, tries.Load())
	}
}
