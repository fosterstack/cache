package metadata

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "meta.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func mustRecord(t *testing.T, s *Store, key string, size int64) {
	t.Helper()
	if err := s.Record(key, size); err != nil {
		t.Fatalf("Record(%s, %d): %v", key, size, err)
	}
}

func TestRecordAndTotalSize(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 100)
	mustRecord(t, s, "b", 200)
	total, err := s.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total != 300 {
		t.Fatalf("TotalSize = %d, want 300", total)
	}
}

func TestRecordOverwriteUpdatesSize(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 100)
	mustRecord(t, s, "a", 50)
	total, err := s.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total != 50 {
		t.Fatalf("TotalSize = %d, want 50", total)
	}
}

func TestDeleteRemovesFromTotal(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 100)
	mustRecord(t, s, "b", 200)
	if err := s.Delete("a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	total, err := s.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total != 200 {
		t.Fatalf("TotalSize = %d, want 200", total)
	}
}

func TestLeastRecentlyUsedOrdering(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "oldest", 1)
	time.Sleep(2 * time.Millisecond)
	mustRecord(t, s, "middle", 1)
	time.Sleep(2 * time.Millisecond)
	mustRecord(t, s, "newest", 1)

	lru, err := s.LeastRecentlyUsed(2)
	if err != nil {
		t.Fatalf("LeastRecentlyUsed: %v", err)
	}
	if len(lru) != 2 {
		t.Fatalf("got %d entries, want 2", len(lru))
	}
	if lru[0].Key != "oldest" || lru[1].Key != "middle" {
		t.Fatalf("order = %v, want [oldest, middle]", lru)
	}
}

func TestTouchUpdatesRecencyNotSize(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 42)
	time.Sleep(2 * time.Millisecond)
	mustRecord(t, s, "b", 1)
	time.Sleep(2 * time.Millisecond)

	if err := s.Touch("a"); err != nil {
		t.Fatalf("Touch: %v", err)
	}

	lru, err := s.LeastRecentlyUsed(2)
	if err != nil {
		t.Fatalf("LeastRecentlyUsed: %v", err)
	}
	if lru[0].Key != "b" {
		t.Fatalf("after touching a, oldest should be b; got %v", lru)
	}
	total, err := s.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	if total != 43 {
		t.Fatalf("Touch changed recorded size: total = %d, want 43", total)
	}
}

func TestTouchOnUnknownKeyIsNoop(t *testing.T) {
	s := newTestStore(t)
	if err := s.Touch("never-recorded"); err != nil {
		t.Fatalf("Touch unknown key: %v", err)
	}
	count, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Fatalf("Touch on unknown key created an entry: count = %d", count)
	}
}

func TestCount(t *testing.T) {
	s := newTestStore(t)
	mustRecord(t, s, "a", 1)
	mustRecord(t, s, "b", 1)
	mustRecord(t, s, "c", 1)
	n, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 3 {
		t.Fatalf("Count = %d, want 3", n)
	}
}
