// Package cache wires the blob store and metadata index together and
// enforces a size cap with least-recently-used eviction. This is the
// "eviction policies, size limits" layer the product brief calls out as
// what a paid customer got from the deprecated Build Cache Node beyond a
// dumb HTTP endpoint — it lives in the MIT core (Community tier: "full
// cache server"), not behind a license key.
package cache

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/metadata"
)

// ErrNotFound is returned by Get for a key with no stored blob.
var ErrNotFound = blobstore.ErrNotFound

// ErrInvalidKey is returned when a key fails validation.
var ErrInvalidKey = blobstore.ErrInvalidKey

// Cache is a size-capped, LRU-evicting content store.
type Cache struct {
	blobs    *blobstore.Store
	meta     *metadata.Store
	maxBytes int64
	log      *slog.Logger
	onEvict  func(key string, size int64)
}

// Option configures a Cache.
type Option func(*Cache)

// WithMaxBytes sets the size cap that triggers eviction after a Put. Zero
// (the default) means unbounded — the operator must size the volume.
func WithMaxBytes(n int64) Option {
	return func(c *Cache) { c.maxBytes = n }
}

// WithLogger sets the logger used for eviction diagnostics. Defaults to
// slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(c *Cache) { c.log = l }
}

// WithOnEvict registers a callback invoked once per evicted entry (used to
// feed the eviction metric without the cache package importing metrics).
func WithOnEvict(f func(key string, size int64)) Option {
	return func(c *Cache) { c.onEvict = f }
}

// New builds a Cache over an already-open blob store and metadata index.
func New(blobs *blobstore.Store, meta *metadata.Store, opts ...Option) *Cache {
	c := &Cache{blobs: blobs, meta: meta, log: slog.Default()}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Close releases the underlying blob store and metadata index. It closes
// both even if the first Close fails, and reports the first error.
func (c *Cache) Close() error {
	blobsErr := c.blobs.Close()
	metaErr := c.meta.Close()
	if blobsErr != nil {
		return fmt.Errorf("cache: close blob store: %w", blobsErr)
	}
	if metaErr != nil {
		return fmt.Errorf("cache: close metadata store: %w", metaErr)
	}
	return nil
}

// Put stores payload under key, records it in the metadata index, and — if
// a size cap is configured and now exceeded — evicts least-recently-used
// entries until back under the cap. Eviction failures are logged, not
// returned: a failed eviction pass must never fail the write that
// triggered it (writes fail safe; the cache degrades toward "too big",
// never toward "lost the client's data").
func (c *Cache) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	n, err := c.blobs.Put(key, r)
	if err != nil {
		return 0, err
	}
	if err := c.meta.Record(key, n); err != nil {
		// The blob is safely on disk; only bookkeeping failed. Log and
		// continue — a missing metadata record just means this key won't
		// be considered for eviction until the next successful write.
		c.log.Error("cache: metadata record failed", "key", key, "error", err)
	}
	if c.maxBytes > 0 {
		c.evictToFit(ctx)
	}
	return n, nil
}

// Get returns the blob stored under key and touches its last-access time.
func (c *Cache) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	rc, size, err := c.blobs.Get(key)
	if err != nil {
		return nil, 0, err
	}
	if err := c.meta.Touch(key); err != nil {
		c.log.Error("cache: metadata touch failed", "key", key, "error", err)
	}
	return rc, size, nil
}

// Stat reports whether key exists and its size, without touching recency
// (used for HEAD requests — the Maven remote-cache existence check — which
// should not count as cache usage for eviction purposes).
func (c *Cache) Stat(key string) (int64, error) {
	return c.blobs.Stat(key)
}

// evictToFit removes least-recently-used entries until total recorded size
// is at or under maxBytes, or there is nothing left to evict.
func (c *Cache) evictToFit(ctx context.Context) {
	total, err := c.meta.TotalSize()
	if err != nil {
		c.log.Error("cache: eviction: total size lookup failed", "error", err)
		return
	}
	if total <= c.maxBytes {
		return
	}

	const batchSize = 64
	evicted := 0
	for total > c.maxBytes {
		select {
		case <-ctx.Done():
			return
		default:
		}
		candidates, err := c.meta.LeastRecentlyUsed(batchSize)
		if err != nil {
			c.log.Error("cache: eviction: LRU lookup failed", "error", err)
			return
		}
		if len(candidates) == 0 {
			return // nothing left to evict; cap is smaller than one entry
		}
		for _, entry := range candidates {
			if total <= c.maxBytes {
				break
			}
			if err := c.evictOne(entry.Key); err != nil {
				c.log.Error("cache: eviction: failed", "key", entry.Key, "error", err)
				continue
			}
			total -= entry.Size
			evicted++
			if c.onEvict != nil {
				c.onEvict(entry.Key, entry.Size)
			}
		}
	}
	if evicted > 0 {
		c.log.Info("cache: evicted entries to fit size cap", "count", evicted, "max_bytes", c.maxBytes)
	}
}

func (c *Cache) evictOne(key string) error {
	if err := c.blobs.Delete(key); err != nil {
		return fmt.Errorf("delete blob: %w", err)
	}
	if err := c.meta.Delete(key); err != nil {
		return fmt.Errorf("delete metadata: %w", err)
	}
	return nil
}

// TotalSize returns the current recorded total size of the cache.
func (c *Cache) TotalSize() (int64, error) { return c.meta.TotalSize() }

// EntryCount returns the number of tracked entries.
func (c *Cache) EntryCount() (int, error) { return c.meta.Count() }
