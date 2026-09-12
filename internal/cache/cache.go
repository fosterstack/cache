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
	"sync"

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

	// evictMu serializes eviction passes. Without it, concurrent Puts each
	// read a stale total, all select overlapping LRU candidates, and all
	// "successfully" delete the same already-deleted (idempotent) entries
	// — correctness of the cap survives, but onEvict fires many times over
	// for a single real eviction and every extra pass is wasted I/O.
	// Serializing only the evict-and-recheck loop (not the blob write
	// itself) keeps writes concurrent while making eviction bookkeeping
	// exact.
	evictMu sync.Mutex
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

// ReconcileStats reports what a startup reconciliation found and fixed.
type ReconcileStats struct {
	AdoptedBlobs     int // blobs with no metadata record, now indexed
	DroppedRecords   int // records with no blob, now removed
	RemovedTempFiles int
}

// Reconcile repairs the metadata index against the blob store after an
// unclean shutdown (REQ-STORE-005): blobs are truth, the index is
// rebuildable. Blobs with no record are adopted (size from disk, recency
// now); records with no blob are dropped; stale temp files from
// interrupted writes are removed. Totals correct themselves because
// Record and Delete maintain them.
func (c *Cache) Reconcile(ctx context.Context) (ReconcileStats, error) {
	var stats ReconcileStats

	indexed := map[string]bool{}
	entries, err := c.meta.All()
	if err != nil {
		return stats, fmt.Errorf("cache: reconcile: read index: %w", err)
	}
	for _, e := range entries {
		indexed[e.Key] = true
	}

	onDisk := map[string]bool{}
	staleTemp, err := c.blobs.Walk(func(key string, size int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		onDisk[key] = true
		if !indexed[key] {
			if err := c.meta.Record(key, size); err != nil {
				return fmt.Errorf("adopt %q: %w", key, err)
			}
			stats.AdoptedBlobs++
		}
		return nil
	})
	if err != nil {
		return stats, fmt.Errorf("cache: reconcile: %w", err)
	}

	for _, e := range entries {
		if !onDisk[e.Key] {
			if err := c.meta.Delete(e.Key); err != nil {
				return stats, fmt.Errorf("cache: reconcile: drop %q: %w", e.Key, err)
			}
			stats.DroppedRecords++
		}
	}

	for _, tmp := range staleTemp {
		if err := c.blobs.RemoveStaleTemp(tmp); err != nil {
			c.log.Warn("cache: reconcile: stale temp file not removed", "path", tmp, "error", err)
			continue
		}
		stats.RemovedTempFiles++
	}

	c.log.Info("cache: reconciliation complete",
		"adopted_blobs", stats.AdoptedBlobs,
		"dropped_records", stats.DroppedRecords,
		"removed_temp_files", stats.RemovedTempFiles)
	return stats, nil
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
		// REQ-STORE-004: a cache that says "stored" has stored it. An
		// unindexed blob is invisible to eviction and totals, so the write
		// is undone and the client told the truth. The delete is
		// best-effort — if it also fails, startup reconciliation adopts
		// the orphan later, which is the recovery path for exactly this.
		if delErr := c.blobs.Delete(key); delErr != nil {
			c.log.Error("cache: blob cleanup after metadata failure also failed; startup reconciliation will adopt it",
				"key", key, "record_error", err, "delete_error", delErr)
		}
		return 0, fmt.Errorf("cache: metadata record for %q failed, entry not stored: %w", key, err)
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

// maxFailedEvictionBatches bounds how many consecutive all-failed batches
// evictToFit tolerates before giving up. Without this, a persistent
// failure (e.g. a read-only data directory) turns "evict until under cap"
// into an unbounded busy loop for the lifetime of the triggering request's
// context — a resource-exhaustion path, not just a cosmetic bug.
const maxFailedEvictionBatches = 3

// evictToFit removes least-recently-used entries until total recorded size
// is at or under maxBytes, or there is nothing left to evict. Callers must
// hold no other lock on c; evictToFit takes evictMu itself so concurrent
// Puts serialize here rather than each acting on a stale size snapshot.
func (c *Cache) evictToFit(ctx context.Context) {
	c.evictMu.Lock()
	defer c.evictMu.Unlock()

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
	failedBatches := 0
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
		progressed := false
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
			progressed = true
			if c.onEvict != nil {
				c.onEvict(entry.Key, entry.Size)
			}
		}
		if progressed {
			failedBatches = 0
			continue
		}
		failedBatches++
		if failedBatches >= maxFailedEvictionBatches {
			c.log.Error("cache: eviction: giving up after repeated failures",
				"consecutive_failed_batches", failedBatches, "total_bytes", total, "max_bytes", c.maxBytes)
			return
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
