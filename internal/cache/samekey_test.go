package cache

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/metadata"
)

// holdMeta pauses the FIRST Record of one key until release() returns, so a test can order two concurrent
// same-key Puts exactly: the first has replaced the blob and not yet recorded its size.
type holdMeta struct {
	metaStore
	key     string
	calls   atomic.Int32
	reached chan struct{} // closed when the first Record of key is paused
	release func()
}

func (h *holdMeta) Record(key string, size int64) error {
	if key == h.key && h.calls.Add(1) == 1 {
		close(h.reached)
		h.release()
	}
	return h.metaStore.Record(key, size)
}

// REQ-STORE-001-AC2: two PUTs of different sizes replace one key concurrently; the first has replaced the blob
// and is paused before it records its size while the second runs. When both have completed, the index records
// the size of the bytes now retrievable under the key and the store total equals the sum of the indexed sizes.
// Without a per-key ordering of replace and record, the first PUT records last and the index keeps 1 byte for
// a 100-byte blob (a 100-byte cap is then exceeded by a later 99-byte PUT with 199 bytes on disk).
func TestSameKeyConcurrentPutsKeepIndexEqualToBytes(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(100))
	secondDone := make(chan struct{})
	h := &holdMeta{metaStore: c.meta, key: "k", reached: make(chan struct{})}
	h.release = func() {
		select {
		case <-secondDone: // unordered code: the second PUT finished while the first was paused
		case <-time.After(400 * time.Millisecond): // ordered code: the second PUT waits for the first, so the pause ends by itself
		}
	}
	c.meta = h
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := c.Put(ctx, "k", strings.NewReader("a")); err != nil {
			t.Errorf("first Put: %v", err)
		}
	}()
	<-h.reached
	go func() {
		defer wg.Done()
		defer close(secondDone)
		if _, err := c.Put(ctx, "k", strings.NewReader(strings.Repeat("b", 100))); err != nil {
			t.Errorf("second Put: %v", err)
		}
	}()
	wg.Wait()

	onDisk, err := c.Stat("k")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	entries, err := c.meta.All()
	if err != nil || len(entries) != 1 {
		t.Fatalf("index entries = %v, err %v; want exactly one", entries, err)
	}
	total, _ := c.meta.TotalSize()
	if entries[0].Size != onDisk || total != onDisk {
		t.Fatalf("index records %d bytes (total %d) for a key holding %d bytes", entries[0].Size, total, onDisk)
	}
	// the cap is real again: a 99-byte PUT must evict the 100-byte entry, never sit beside it
	if _, err := c.Put(ctx, "other", strings.NewReader(strings.Repeat("c", 99))); err != nil {
		t.Fatalf("Put other: %v", err)
	}
	if _, err := c.Stat("k"); err == nil {
		t.Fatalf("k still stored beside the 99-byte entry: committed bytes exceed the 100-byte cap")
	}
}

// REQ-STORE-001-AC2 (repair): a recorded size that differs from the bytes on disk is corrected by reconciliation,
// counted, and not found again at the next start.
func TestReconcileCorrectsRecordedSizeMismatch(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	defer func() { _ = c.Close() }()
	put(t, c, "k", strings.Repeat("x", 100))
	if err := meta.Record("k", 1); err != nil { // the state a lost same-key race leaves behind
		t.Fatalf("Record: %v", err)
	}

	st, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if st.CorrectedSizes != 1 {
		t.Fatalf("CorrectedSizes = %d, want 1", st.CorrectedSizes)
	}
	if total, _ := meta.TotalSize(); total != 100 {
		t.Fatalf("total after reconcile = %d, want 100", total)
	}
	st, err = c.Reconcile(context.Background())
	if err != nil || st.CorrectedSizes != 0 {
		t.Fatalf("second Reconcile: %+v, %v; want nothing left to correct", st, err)
	}
}

// REQ-STORE-001-AC2 (repair failure): a size correction that cannot be recorded fails Reconcile with the key
// named and the stats do not claim the correction.
func TestReconcileReportsSizeCorrectionFailure(t *testing.T) {
	c := newTestCache(t)
	put(t, c, "k", strings.Repeat("x", 100))
	if err := c.meta.Record("k", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}
	boom := errors.New("record failed")
	c.meta = &faultMeta{metaStore: c.meta, recordErr: boom} // the injection

	stats, err := c.Reconcile(context.Background())
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), `correct size of "k"`) {
		t.Fatalf("err = %v, want the injected failure with the key named", err)
	}
	if stats.CorrectedSizes != 0 {
		t.Errorf("CorrectedSizes = %d, want 0 — the correction did not happen", stats.CorrectedSizes)
	}
}

// pauseRecord holds the FIRST Record of key until release() returns and logs the order of every Record, so a test can pin a Put between its blob
// replace and its index record.
type pauseRecord struct {
	metaStore
	key     string
	calls   atomic.Int32
	reached chan struct{}
	release func()
	mu      sync.Mutex
	order   []string
}

func (p *pauseRecord) Record(key string, size int64) error {
	if key == p.key && p.calls.Add(1) == 1 {
		close(p.reached)
		p.release()
	}
	p.mu.Lock()
	p.order = append(p.order, key)
	p.mu.Unlock()
	return p.metaStore.Record(key, size)
}

// bothStoresAgree fails the test unless every indexed key is retrievable at its recorded size, every stored blob is indexed, and the total is the sum.
func bothStoresAgree(t *testing.T, c *Cache) {
	t.Helper()
	entries, err := c.meta.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	var sum int64
	indexed := map[string]bool{}
	for _, e := range entries {
		indexed[e.Key] = true
		sum += e.Size
		if got, err := c.Stat(e.Key); err != nil || got != e.Size {
			t.Errorf("index records %q at %d bytes; the store holds %d (err %v)", e.Key, e.Size, got, err)
		}
	}
	if _, err := c.blobs.Walk(func(key string, size int64) error {
		if !indexed[key] {
			t.Errorf("blob %q (%d bytes) is stored and not indexed", key, size)
		}
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if total, _ := c.meta.TotalSize(); total != sum {
		t.Errorf("total %d != sum of indexed sizes %d", total, sum)
	}
}

// REQ-STORE-001-AC2 / REQ-EVICT-001-AC1: eviction selects the least recently used key k while a Put of k has replaced the blob and not yet
// recorded; eviction must not delete the new blob and the old record under it. (Codex A1/B1 on cache#553.)
func TestEvictionDoesNotRaceAPutOfTheSameKey(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(100))
	ctx := context.Background()
	put(t, c, "k", strings.Repeat("a", 50))
	otherDone := make(chan struct{})
	p := &pauseRecord{metaStore: c.meta, key: "k", reached: make(chan struct{})}
	p.release = func() {
		select {
		case <-otherDone: // unordered code: eviction ran to the end while the Put of k was paused
		case <-time.After(400 * time.Millisecond): // ordered code: eviction waits for k's Put, so the pause ends by itself
		}
	}
	p.calls.Store(0)
	c.meta = p
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := c.Put(ctx, "k", strings.NewReader(strings.Repeat("b", 100))); err != nil {
			t.Errorf("Put k: %v", err)
		}
	}()
	<-p.reached
	go func() {
		defer wg.Done()
		defer close(otherDone)
		if _, err := c.Put(ctx, "other", strings.NewReader(strings.Repeat("c", 100))); err != nil {
			t.Errorf("Put other: %v", err)
		}
	}()
	wg.Wait()
	bothStoresAgree(t, c)
	if total, _ := c.meta.TotalSize(); total > 100 {
		t.Errorf("committed bytes %d exceed the 100-byte cap", total)
	}
}

// REQ-STORE-004-AC1: a PUT that overwrites an existing key and whose record step fails leaves the entry absent from BOTH stores, the old record included.
// (Codex B2 on cache#553.)
func TestFailedOverwriteLeavesNoRecord(t *testing.T) {
	c := newTestCache(t)
	put(t, c, "k", "old")
	boom := errors.New("record failed")
	c.meta = &faultMeta{metaStore: c.meta, recordErr: boom}
	if _, err := c.Put(context.Background(), "k", strings.NewReader("newer")); !errors.Is(err, boom) {
		t.Fatalf("Put err = %v, want the injected failure", err)
	}
	c.meta = c.meta.(*faultMeta).metaStore
	if _, err := c.Stat("k"); err == nil {
		t.Error("the blob of the failed overwrite is still stored")
	}
	if entries, _ := c.meta.All(); len(entries) != 0 {
		t.Errorf("index still holds %v after the failed overwrite", entries)
	}
}

// A reader that panics (recovered by the caller) must not leave its key locked: the next Put of the key completes and no lock entry is retained.
// (Codex B4 on cache#553: the unlock was not deferred.)
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("reader failed") }

func TestPanickingReaderDoesNotLockTheKey(t *testing.T) {
	c := newTestCache(t)
	func() {
		defer func() { _ = recover() }()
		_, _ = c.Put(context.Background(), "k", panicReader{})
	}()
	done := make(chan error, 1)
	go func() { _, err := c.Put(context.Background(), "k", strings.NewReader("fine")); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second Put: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the second Put of the key blocks: the first Put's panic left the key locked")
	}
	c.keyMu.Lock()
	n := len(c.keys)
	c.keyMu.Unlock()
	if n != 0 {
		t.Errorf("%d key lock entries retained", n)
	}
}

// Keys that differ only in case can name one blob (a case-insensitive filesystem, REQ-PROTO-003-AC4), so their Puts take ONE lock: the second Record never
// runs while the first Put is between its blob replace and its record. (Codex A2/B3 on cache#553.)
func TestCaseAliasedKeysShareOneLock(t *testing.T) {
	c := newTestCache(t)
	secondDone := make(chan struct{})
	p := &pauseRecord{metaStore: c.meta, key: "Abc", reached: make(chan struct{})}
	p.release = func() {
		select {
		case <-secondDone:
		case <-time.After(400 * time.Millisecond):
		}
	}
	c.meta = p
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); put(t, c, "Abc", "a") }()
	<-p.reached
	go func() { defer wg.Done(); defer close(secondDone); put(t, c, "abc", strings.Repeat("b", 100)) }()
	wg.Wait()
	p.mu.Lock()
	order := strings.Join(p.order, ",")
	p.mu.Unlock()
	if order != "Abc,abc" {
		t.Fatalf("Record order = %s; the aliased Puts ran their record steps out of order (want Abc,abc)", order)
	}
}

// evictOne refuses an entry that is gone or no longer the record that was selected, and reports a record it cannot read.
func TestEvictOneSkipsChangedAndReportsLookupFailure(t *testing.T) {
	c := newTestCache(t)
	put(t, c, "k", "old")
	entry, ok, err := c.meta.Lookup("k")
	if err != nil || !ok {
		t.Fatalf("Lookup: %v %v", ok, err)
	}
	put(t, c, "k", "newer and longer") // replaced after it was selected
	if err := c.evictOne(entry); !errors.Is(err, errEntryChanged) {
		t.Fatalf("evictOne(stale entry) = %v, want errEntryChanged", err)
	}
	if _, err := c.Stat("k"); err != nil {
		t.Fatalf("the replaced entry was evicted: %v", err)
	}
	if err := c.evictOne(metadata.Entry{Key: "gone", Size: 1}); !errors.Is(err, errEntryChanged) {
		t.Fatalf("evictOne(absent) = %v, want errEntryChanged", err)
	}
	c.meta = &lookupFails{metaStore: c.meta}
	if err := c.evictOne(entry); err == nil || !strings.Contains(err.Error(), "lookup record") {
		t.Fatalf("evictOne with a failing Lookup = %v, want the lookup named", err)
	}
}

type lookupFails struct{ metaStore }

func (lookupFails) Lookup(string) (metadata.Entry, bool, error) {
	return metadata.Entry{}, false, errors.New("lookup failed")
}

// blockingReader blocks its first Read until released: a slow client upload.
type blockingReader struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingReader) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return 0, io.EOF
}

// Eviction must never wait on a client's upload: a slow re-PUT of the key eviction selected holds that key's lock for the whole upload, so eviction skips
// a key whose lock is held (it is being rewritten, hence recent) instead of blocking every capped Put behind evictMu. (Opus on cache#553 round 2.)
func TestEvictionDoesNotWaitForASlowUploadOfTheSelectedKey(t *testing.T) {
	c := newTestCache(t, WithMaxBytes(100))
	ctx := context.Background()
	put(t, c, "old", strings.Repeat("a", 50))
	put(t, c, "mid", strings.Repeat("b", 40))
	slow := &blockingReader{started: make(chan struct{}), release: make(chan struct{})}
	slowDone := make(chan struct{})
	go func() { defer close(slowDone); _, _ = c.Put(ctx, "old", slow) }()
	<-slow.started
	done := make(chan error, 1)
	go func() { _, err := c.Put(ctx, "new", strings.NewReader(strings.Repeat("c", 30))); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Put new: %v", err)
		}
	case <-time.After(3 * time.Second):
		close(slow.release)
		<-slowDone
		t.Fatal("a capped Put is stuck behind the slow upload of the key eviction selected")
	}
	close(slow.release)
	<-slowDone
}
