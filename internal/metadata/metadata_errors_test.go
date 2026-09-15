package metadata

import (
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// putRaw writes raw bytes directly into the entries bucket, bypassing encode,
// to simulate an on-disk corrupt record.
// putRaw injects raw bytes under a fixed key so decode-path tests can
// surface a malformed record. The key is constant on purpose - callers
// only need one corrupt entry present.
func putRaw(t *testing.T, s *Store, val []byte) {
	t.Helper()
	const key = "bad"
	err := s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketName).Put([]byte(key), val)
	})
	if err != nil {
		t.Fatalf("putRaw(%s): %v", key, err)
	}
}

// corruptRecord returns a full-width record whose size field exceeds
// math.MaxInt64, which decode and decodeSize must reject.
func corruptRecord() []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], math.MaxUint64)
	binary.BigEndian.PutUint64(buf[8:16], 0)
	return buf
}

func TestOpenUnwritableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; directory permissions are not enforced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("restore Chmod: %v", err)
		}
	})
	s, err := Open(filepath.Join(dir, "meta.db"))
	if err == nil {
		_ = s.Close()
		t.Fatal("Open in unwritable dir: want error, got nil")
	}
	if !strings.Contains(err.Error(), "metadata: open:") {
		t.Fatalf("Open error = %q, want it wrapped with %q", err, "metadata: open:")
	}
}

func TestOpenInitBucketFailure(t *testing.T) {
	// Create a valid database file first so a read-only open can succeed.
	path := filepath.Join(t.TempDir(), "meta.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Force the database to open read-only so the bucket-init Update fails.
	orig := openDB
	openDB = func(p string, mode os.FileMode, _ *bbolt.Options) (*bbolt.DB, error) {
		return bbolt.Open(p, mode, &bbolt.Options{ReadOnly: true, Timeout: 5 * time.Second})
	}
	t.Cleanup(func() { openDB = orig })

	s2, err := Open(path)
	if err == nil {
		_ = s2.Close()
		t.Fatal("Open with read-only db: want init bucket error, got nil")
	}
	if !strings.Contains(err.Error(), "metadata: init bucket:") {
		t.Fatalf("Open error = %q, want it wrapped with %q", err, "metadata: init bucket:")
	}
}

func TestEncodeRejectsNegativeSize(t *testing.T) {
	if _, err := encode(-1, time.Now()); err == nil {
		t.Fatal("encode(-1, now): want error, got nil")
	}
}

func TestEncodeRejectsPreEpochTimestamp(t *testing.T) {
	if _, err := encode(1, time.Unix(0, -1)); err == nil {
		t.Fatal("encode with pre-epoch timestamp: want error, got nil")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	when := time.Unix(0, 1_700_000_000_123_456_789)
	buf, err := encode(42, when)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(buf) != 16 {
		t.Fatalf("encoded length = %d, want 16", len(buf))
	}
	e, err := decode("k", buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if e.Key != "k" || e.Size != 42 || !e.LastAccess.Equal(when) {
		t.Fatalf("round trip = %+v, want key k, size 42, lastAccess %v", e, when)
	}
}

func TestDecodeRejectsOutOfRangeSize(t *testing.T) {
	if _, err := decode("k", corruptRecord()); err == nil {
		t.Fatal("decode with out-of-range size: want error, got nil")
	}
}

func TestDecodeRejectsOutOfRangeTimestamp(t *testing.T) {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], 1)
	binary.BigEndian.PutUint64(buf[8:16], math.MaxUint64)
	if _, err := decode("k", buf); err == nil {
		t.Fatal("decode with out-of-range timestamp: want error, got nil")
	}
}

func TestDecodeSizeRejectsOutOfRangeSize(t *testing.T) {
	if _, err := decodeSize(corruptRecord()); err == nil {
		t.Fatal("decodeSize with out-of-range size: want error, got nil")
	}
}

func TestRecordRejectsNegativeSize(t *testing.T) {
	s := newTestStore(t)
	if err := s.Record("a", -1); err == nil {
		t.Fatal("Record with negative size: want error, got nil")
	}
	count, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Fatalf("failed Record still created an entry: count = %d", count)
	}
}

func TestTouchSurfacesCorruptRecord(t *testing.T) {
	s := newTestStore(t)
	putRaw(t, s, corruptRecord())
	if err := s.Touch("bad"); err == nil {
		t.Fatal("Touch on corrupt record: want error, got nil")
	}
}

func TestTouchSurfacesEncodeFailure(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 1)

	// A clock that predates the Unix epoch makes encode reject the new
	// timestamp inside Touch.
	orig := now
	now = func() time.Time { return time.Unix(0, -1) }
	t.Cleanup(func() { now = orig })

	if err := s.Touch("a"); err == nil {
		t.Fatal("Touch with pre-epoch clock: want error, got nil")
	}
}

func TestTotalSizeEmpty(t *testing.T) {
	s := newTestStore(t)
	total, err := s.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total != 0 {
		t.Fatalf("TotalSize on empty store = %d, want 0", total)
	}
}

func TestTotalSizeSurfacesCorruptRecord(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "good", 10)
	putRaw(t, s, corruptRecord())
	if _, err := s.TotalSize(); err == nil {
		t.Fatal("TotalSize with corrupt record: want error, got nil")
	}
}

func TestLeastRecentlyUsedEmpty(t *testing.T) {
	s := newTestStore(t)
	lru, err := s.LeastRecentlyUsed(5)
	if err != nil {
		t.Fatalf("LeastRecentlyUsed: %v", err)
	}
	if len(lru) != 0 {
		t.Fatalf("LeastRecentlyUsed on empty store = %v, want empty", lru)
	}
}

func TestLeastRecentlyUsedSurfacesCorruptRecord(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "good", 10)
	putRaw(t, s, corruptRecord())
	if _, err := s.LeastRecentlyUsed(5); err == nil {
		t.Fatal("LeastRecentlyUsed with corrupt record: want error, got nil")
	}
}

func TestAllReturnsEveryEntry(t *testing.T) {
	s := newTestStore(t)
	all, err := s.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("All on empty store = %v, want empty", all)
	}

	mustRecord(t, s, "a", 1)
	mustRecord(t, s, "b", 2)
	all, err = s.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("All returned %d entries, want 2", len(all))
	}
	sizes := map[string]int64{}
	for _, e := range all {
		sizes[e.Key] = e.Size
		if e.LastAccess.IsZero() {
			t.Fatalf("entry %q has zero LastAccess", e.Key)
		}
	}
	if sizes["a"] != 1 || sizes["b"] != 2 {
		t.Fatalf("All sizes = %v, want a:1 b:2", sizes)
	}
}

func TestAllSurfacesCorruptRecord(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "good", 10)
	putRaw(t, s, corruptRecord())
	if _, err := s.All(); err == nil {
		t.Fatal("All with corrupt record: want error, got nil")
	}
}
