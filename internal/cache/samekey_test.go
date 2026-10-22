package cache

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
