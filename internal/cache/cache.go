// Package cache wires the blob store and metadata index together and
// enforces a size cap with least-recently-used eviction.
package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/metadata"
)

// ErrNotFound is returned by Get for a key with no stored blob.
var ErrNotFound = blobstore.ErrNotFound

// ErrInvalidKey is returned when a key fails validation.
var ErrInvalidKey = blobstore.ErrInvalidKey

// blobStore and metaStore name what Cache needs from its two stores. They are
// interfaces only so tests can wrap the real stores to inject failures the
// filesystem and bbolt cannot produce on demand (a Close or Delete error, a
// metadata write that fails mid-reconcile); New takes the concrete types.
type blobStore interface {
	Put(key string, r io.Reader) (int64, error)
	Get(key string) (io.ReadCloser, int64, error)
	Stat(key string) (int64, error)
	Delete(key string) error
	Walk(fn func(key string, size int64) error) (staleTemp []string, err error)
	RemoveStaleTemp(rel string) error
	Root() string
	Close() error
}

type metaStore interface {
	Record(key string, size int64) error
	Touch(key string) error
	Lookup(key string) (metadata.Entry, bool, error)
	Delete(key string) error
	TotalSize() (int64, error)
	LeastRecentlyUsed(n int) ([]metadata.Entry, error)
	Count() (int, error)
	All() ([]metadata.Entry, error)
	Close() error
}

// Cache is a size-capped, LRU-evicting content store.
type Cache struct {
	blobs    blobStore
	meta     metaStore
	maxBytes int64
	log      *slog.Logger
	onEvict  func(key string, size int64)

	// evictMu serializes eviction passes. Without it concurrent Puts each read
	// a stale total and select the same LRU candidates, repeating the candidate
	// selection and lookups for one real eviction. Only the evict-and-recheck
	// loop is serialized, not the blob write.
	evictMu sync.Mutex

	// keyMu guards keys, the per-key locks that order a key's blob replace and
	// its index record (REQ-STORE-001-AC2): without them two Puts of one key
	// can record in the opposite order to their replaces, leaving a size the
	// retrievable bytes do not have. Puts of different keys stay concurrent.
	keyMu sync.Mutex
	keys  map[string]*keyLock
}

// keyLock is one key's lock and the number of Puts holding or waiting for
// it; the entry leaves the map when the count reaches zero.
type keyLock struct {
	mu   sync.Mutex
	refs int
}

// lockKey takes key's lock and returns the function that releases it. The lock
// is named by the lower-cased key: keys differing only in case can name one
// blob on a case-insensitive filesystem (REQ-PROTO-003-AC4). On a
// case-sensitive one this merely serializes two distinct blobs.
func (c *Cache) lockKey(key string) func() {
	key = strings.ToLower(key)
	c.keyMu.Lock()
	kl := c.keys[key]
	if kl == nil {
		kl = &keyLock{}
		c.keys[key] = kl
	}
	kl.refs++
	c.keyMu.Unlock()
	kl.mu.Lock()
	return c.unlocker(key, kl)
}

// tryLockKey takes key's lock only if no Put holds it or waits for it; ok is
// false otherwise. Eviction uses it: a Put holds the lock for its whole upload,
// eviction must never wait for a client, and a key being rewritten is recent
// anyway.
func (c *Cache) tryLockKey(key string) (release func(), ok bool) {
	key = strings.ToLower(key)
	c.keyMu.Lock()
	if c.keys[key] != nil {
		c.keyMu.Unlock()
		return nil, false
	}
	kl := &keyLock{refs: 1}
	c.keys[key] = kl
	c.keyMu.Unlock()
	kl.mu.Lock() // a new entry: nobody else can hold it
	return c.unlocker(key, kl), true
}

func (c *Cache) unlocker(key string, kl *keyLock) func() {
	return func() {
		kl.mu.Unlock()
		c.keyMu.Lock()
		if kl.refs--; kl.refs == 0 {
			delete(c.keys, key)
		}
		c.keyMu.Unlock()
	}
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
	c := &Cache{blobs: blobs, meta: meta, log: slog.Default(), keys: map[string]*keyLock{}}
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
	CorrectedSizes   int // records whose size differed from the bytes on disk, now corrected
}

// Reconcile repairs the metadata index against the blob store after an
// unclean shutdown (REQ-STORE-005): blobs are truth, the index is
// rebuildable. Blobs with no record are adopted (size from disk, recency
// now); records whose size differs from the blob's are corrected; records
// with no blob are dropped; stale temp files from interrupted writes are
// removed. Nothing keeps a running total: TotalSize and EntryCount are
// computed from the index on each call, so correcting the index corrects them.
func (c *Cache) Reconcile(ctx context.Context) (ReconcileStats, error) {
	var stats ReconcileStats

	indexed := map[string]int64{}
	entries, err := c.meta.All()
	if err != nil {
		return stats, fmt.Errorf("cache: reconcile: read index: %w", err)
	}
	for _, e := range entries {
		indexed[e.Key] = e.Size
	}

	onDisk := map[string]bool{}
	staleTemp, err := c.blobs.Walk(func(key string, size int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		onDisk[key] = true
		recorded, isIndexed := indexed[key]
		switch {
		case !isIndexed:
			if err := c.meta.Record(key, size); err != nil {
				return fmt.Errorf("adopt %q: %w", key, err)
			}
			stats.AdoptedBlobs++
		case recorded != size:
			// The blob is truth (REQ-STORE-001-AC2): a record whose size differs from the
			// bytes on disk is what a lost same-key race leaves behind; it would skew
			// totals and the cap for good.
			if err := c.meta.Record(key, size); err != nil {
				return fmt.Errorf("correct size of %q: %w", key, err)
			}
			stats.CorrectedSizes++
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

// ErrEntryTooLarge reports a PUT whose entry exceeds the configured cache cap
// (REQ-EVICT-002). The entry can never live in the cache, so it is rejected up
// front (nothing stored, nothing evicted) rather than written and then
// churning every resident entry out.
var ErrEntryTooLarge = errors.New("cache: entry exceeds the configured cache cap")

// capReader fails the read with ErrEntryTooLarge once more than limit
// bytes have been consumed, so a chunked or mis-declared upload is
// stopped at the cap rather than trusted for its Content-Length.
type capReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (cr *capReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.read += int64(n)
	if cr.read > cr.limit {
		return n, ErrEntryTooLarge
	}
	return n, err
}

// Put stores r under key, records it in the metadata index, and, if a size cap
// is set and now exceeded, evicts least-recently-used entries until back under
// it. Eviction failures are logged, never returned: a failed eviction must not
// fail the write that triggered it (the cache degrades toward "too big", never
// toward losing the client's data).
func (c *Cache) Put(ctx context.Context, key string, r io.Reader) (int64, error) {
	if c.maxBytes > 0 {
		r = &capReader{r: r, limit: c.maxBytes}
	}
	n, err := c.putLocked(key, r)
	if err != nil {
		return 0, err
	}
	if c.maxBytes > 0 {
		c.evictToFit(ctx)
	}
	return n, nil
}

// putLocked is the replace-and-record step of Put under the key's lock; the
// deferred unlock releases it on every return, a panicking reader included.
func (c *Cache) putLocked(key string, r io.Reader) (int64, error) {
	defer c.lockKey(key)()
	n, err := c.blobs.Put(key, r)
	if err != nil {
		return 0, err
	}
	if err := c.meta.Record(key, n); err != nil {
		// REQ-STORE-004: a cache that says "stored" has stored it. An unindexed
		// blob is invisible to eviction and totals, so the write is undone (the
		// blob and the record the key had before this overwrite, whose blob is
		// gone) and the client is told the truth. The deletes are best-effort:
		// if one fails, reconciliation after an unclean shutdown adopts the
		// orphan blob or drops the dangling record. A clean shutdown does not
		// reconcile, so until then an orphan blob counts toward nothing.
		if delErr := c.blobs.Delete(key); delErr != nil {
			c.log.Error("cache: blob cleanup after metadata failure also failed; startup reconciliation will adopt it",
				"key", key, "record_error", err, "delete_error", delErr)
		}
		if delErr := c.meta.Delete(key); delErr != nil {
			c.log.Error("cache: record cleanup after metadata failure also failed; startup reconciliation will drop it",
				"key", key, "record_error", err, "delete_error", delErr)
		}
		return 0, fmt.Errorf("cache: metadata record for %q failed, entry not stored: %w", key, err)
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

// Stat reports whether key exists and its size, without touching recency: HEAD
// requests (the Maven remote-cache existence check) are not cache usage.
func (c *Cache) Stat(key string) (int64, error) {
	return c.blobs.Stat(key)
}

// maxFailedEvictionBatches bounds consecutive all-failed batches in evictToFit.
// Without it a persistent failure (a read-only data directory) turns "evict
// until under cap" into a busy loop for the life of the request's context.
const maxFailedEvictionBatches = 3

// evictToFit removes least-recently-used entries until the recorded total is at
// or under maxBytes, or nothing is left to evict. It takes evictMu itself, so
// callers must hold no other lock on c.
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
			if err := c.evictOne(entry); err != nil {
				if errors.Is(err, errEntryChanged) {
					continue // a Put of the key replaced it after it was selected: it is recent now, not evicted
				}
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

// errEntryChanged reports that the entry selected for eviction is no longer
// what was selected (replaced by a Put, or already gone).
var errEntryChanged = errors.New("cache: entry changed since it was selected for eviction")

// evictOne removes entry's blob and record under the key's lock (the one a Put
// holds between its blob replace and its record), and only if the record is
// still the one selected: a Put that replaced the key made it recent, so its
// new blob and record are kept (REQ-STORE-001-AC2, REQ-EVICT-001-AC1).
func (c *Cache) evictOne(entry metadata.Entry) error {
	release, ok := c.tryLockKey(entry.Key)
	if !ok {
		return errEntryChanged // a Put holds the key's lock: it is being rewritten, so it is recent
	}
	defer release()
	cur, ok, err := c.meta.Lookup(entry.Key)
	if err != nil {
		return fmt.Errorf("lookup record: %w", err)
	}
	if !ok || cur.Size != entry.Size || !cur.LastAccess.Equal(entry.LastAccess) {
		return errEntryChanged
	}
	if err := c.blobs.Delete(entry.Key); err != nil {
		return fmt.Errorf("delete blob: %w", err)
	}
	if err := c.meta.Delete(entry.Key); err != nil {
		return fmt.Errorf("delete metadata: %w", err)
	}
	return nil
}

// TotalSize returns the current recorded total size of the cache.
func (c *Cache) TotalSize() (int64, error) { return c.meta.TotalSize() }

// EntryCount returns the number of tracked entries.
func (c *Cache) EntryCount() (int, error) { return c.meta.Count() }
