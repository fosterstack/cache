package cache

import (
	"context"
	"io"
	"path/filepath"
	"strings"
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
