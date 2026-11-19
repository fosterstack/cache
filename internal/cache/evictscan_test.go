package cache

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/metadata"
)

// lruCounter counts the index loads an eviction makes.
type lruCounter struct {
	metaStore
	calls atomic.Int64
}

func (l *lruCounter) LeastRecentlyUsed(n int) ([]metadata.Entry, error) {
	l.calls.Add(1)
	return l.metaStore.LeastRecentlyUsed(n)
}

// fillOrdered puts n one-byte entries k000.. in order, uncapped, so their
// last-access times rise with the key, and installs the counting wrapper.
func fillOrdered(t *testing.T, n int) (*Cache, *lruCounter) {
	t.Helper()
	c := newLockTestCache(t)
	for i := 0; i < n; i++ {
		if _, err := c.Put(context.Background(), fmt.Sprintf("k%03d", i), strings.NewReader("x")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	lc := &lruCounter{metaStore: c.meta}
	c.meta = lc
	return c, lc
}

// Rule: eviction loads and sorts the index once, not once per batch of 64,
// and removes the oldest entries.
func TestEvictToFitLoadsIndexOnce(t *testing.T) {
	c, lc := fillOrdered(t, 300)
	c.maxBytes = 100
	c.evictToFit(context.Background())

	if got := lc.calls.Load(); got != 1 {
		t.Errorf("LeastRecentlyUsed called %d times, want 1", got)
	}
	if n, err := c.EntryCount(); err != nil || n != 100 {
		t.Errorf("EntryCount = %d, %v; want 100", n, err)
	}
	for _, k := range []string{"k000", "k063", "k064", "k150", "k199"} {
		if _, err := c.Stat(k); err == nil {
			t.Errorf("old key %s survived", k)
		}
	}
	for _, k := range []string{"k200", "k250", "k299"} {
		if _, err := c.Stat(k); err != nil {
			t.Errorf("recent key %s was evicted: %v", k, err)
		}
	}
}

// Rule: eviction steps past entries whose key lock a Put holds and goes on
// to later entries.
func TestEvictToFitStepsPastLockedKeys(t *testing.T) {
	c, _ := fillOrdered(t, 300)
	var releases []func()
	for i := 0; i < 70; i++ {
		releases = append(releases, c.lockKey(fmt.Sprintf("k%03d", i)))
	}
	released := false
	release := func() {
		if !released {
			released = true
			for _, r := range releases {
				r()
			}
		}
	}
	t.Cleanup(release)

	c.maxBytes = 100
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.evictToFit(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("evictToFit hung on locked keys")
	}

	total, err := c.TotalSize()
	if err != nil || total > 100 {
		t.Errorf("TotalSize = %d, %v; want <= 100", total, err)
	}
	for i := 0; i < 70; i++ {
		k := fmt.Sprintf("k%03d", i)
		if _, err := c.Stat(k); err != nil {
			t.Errorf("locked key %s was evicted: %v", k, err)
		}
	}
	release()
}
