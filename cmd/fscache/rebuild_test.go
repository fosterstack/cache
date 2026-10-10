package main

// RED TESTS for REQ-STORE-006 (backlog item 16): an empty metadata index
// over existing blobs is rebuilt at startup. This file is committed
// BEFORE the implementation so the review can read the rules as tests
// first; against the tree without the implementation the tests marked
// RED below fail and the rest are guards that hold on both sides.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
	"github.com/fosterstack/cache/internal/cache"
	"github.com/fosterstack/cache/internal/metadata"
)

const (
	rebuildStartMsg = "fscache: index empty over existing blobs, rebuilding"
	rebuildDoneMsg  = "fscache: index empty over existing blobs, rebuilt"
)

// seedBlobs writes n blobs of size bytes each straight into the blob
// store under dir, with no index, as after a deleted meta.db.
func seedBlobs(t *testing.T, dir string, n, size int) []string {
	t.Helper()
	blobs, err := blobstore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	var keys []string
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("entry-%02d", i)
		if _, err := blobs.Put(key, bytes.NewReader(bytes.Repeat([]byte{byte('a' + i)}, size))); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	return keys
}

// indexState reads the index after a run: entry count and total size.
func indexState(t *testing.T, dir string) (int, int64) {
	t.Helper()
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer meta.Close()
	n, err := meta.Count()
	if err != nil {
		t.Fatal(err)
	}
	total, err := meta.TotalSize()
	if err != nil {
		t.Fatal(err)
	}
	return n, total
}

// diskTotal sums the blob sizes actually on disk.
func diskTotal(t *testing.T, dir string) int64 {
	t.Helper()
	blobs, err := blobstore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	defer blobs.Close()
	var sum int64
	if _, err := blobs.Walk(func(_ string, size int64) error { sum += size; return nil }); err != nil {
		t.Fatal(err)
	}
	return sum
}

// runServe starts serve on a fresh port against dir, calls during(base)
// once it is accepting, shuts down, and returns serve's error and the log.
func runServe(t *testing.T, dir string, during func(base string)) (error, string) {
	t.Helper()
	freshRegistry(t)
	addr := freePort(t)
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", addr)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- serve(ctx, log, func() {
			if during != nil {
				during("http://" + addr)
			}
			cancel()
		})
	}()
	select {
	case err := <-errc:
		return err, buf.String()
	case <-time.After(20 * time.Second):
		t.Fatal("serve did not return")
		return nil, ""
	}
}

func httpDo(t *testing.T, method, url string, body io.Reader) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func countReconciles(t *testing.T) *int {
	t.Helper()
	var calls int
	orig := cacheReconcile
	cacheReconcile = func(c *cache.Cache, ctx context.Context) (cache.ReconcileStats, error) {
		calls++
		return orig(c, ctx)
	}
	t.Cleanup(func() { cacheReconcile = orig })
	return &calls
}

// RED. REQ-STORE-006-AC1: N blobs, clean shutdown (no marker), meta.db
// deleted. Before serving the index holds all N; every blob is
// retrievable; a start line precedes a done line carrying the counts.
func TestRebuildAfterIndexDeleted(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	keys := seedBlobs(t, dir, 5, 100)
	var entriesDuring = -1
	err, logs := runServe(t, dir, func(base string) {
		req, _ := http.NewRequest("GET", base+"/statusz", nil)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("statusz: %v", err)
		} else {
			var st struct {
				StoreEntries int `json:"store_entries"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&st)
			resp.Body.Close()
			entriesDuring = st.StoreEntries
		}
		for _, k := range keys {
			if code, body := httpDo(t, "GET", base+"/"+k, nil); code != 200 || len(body) != 100 {
				t.Errorf("GET %s = %d (%d bytes), want 200 (100 bytes)", k, code, len(body))
			}
		}
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if entriesDuring != 5 {
		t.Errorf("/statusz store_entries while serving = %d, want 5", entriesDuring)
	}
	if n, total := indexState(t, dir); n != 5 || total != 500 {
		t.Errorf("index after start: %d entries, %d bytes; want 5 entries, 500 bytes", n, total)
	}
	start, done := strings.Index(logs, rebuildStartMsg), strings.Index(logs, rebuildDoneMsg)
	if start < 0 || done < 0 || start > done {
		t.Fatalf("want the start line before the done line; start=%d done=%d\n%s", start, done, logs)
	}
	for _, want := range []string{`"adopted_blobs":5`, `"dropped_records":0`, `"removed_temp_files":`} {
		if !strings.Contains(logs[done:], want) {
			t.Errorf("done line missing %s:\n%s", want, logs[done:])
		}
	}
}

// RED. REQ-STORE-006-AC2: meta.db exists but every record is gone.
func TestRebuildAfterIndexEmptied(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	keys := seedBlobs(t, dir, 3, 50)
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys { // index them, then empty it again
		if err := meta.Record(k, 50); err != nil {
			t.Fatal(err)
		}
		if err := meta.Delete(k); err != nil {
			t.Fatal(err)
		}
	}
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}
	if err, logs := runServe(t, dir, nil); err != nil {
		t.Fatalf("serve: %v", err)
	} else if !strings.Contains(logs, rebuildDoneMsg) {
		t.Errorf("no rebuild line:\n%s", logs)
	}
	if n, total := indexState(t, dir); n != 3 || total != 150 {
		t.Errorf("index after start: %d entries, %d bytes; want 3, 150", n, total)
	}
}

// RED (needs the rebuild: without it the 500 bytes on disk are never
// counted, so the index and the disk disagree). REQ-STORE-006-AC3: the adopted blobs count against the cap and are
// evicted until the store is within it.
func TestRebuiltBlobsParticipateInEviction(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	seedBlobs(t, dir, 5, 100)
	t.Setenv("FSCACHE_MAX_BYTES", "250")
	err, _ := runServe(t, dir, func(base string) {
		if code, _ := httpDo(t, "PUT", base+"/new-entry", strings.NewReader("0123456789")); code != 201 {
			t.Errorf("PUT = %d, want 201", code)
		}
	})
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	n, total := indexState(t, dir)
	disk := diskTotal(t, dir)
	if total > 250 || total == 0 || disk != total || n == 0 {
		t.Errorf("after eviction: index %d entries / %d bytes, disk %d bytes; want the index equal to disk and 0 < bytes <= 250", n, total, disk)
	}
}

// Guard. REQ-STORE-006-AC4: a non-empty index and no marker means no walk
// and no rebuild line. An orphan blob the index lacks is NOT adopted:
// partial index loss is out of scope (REQ-STORE-006 statement).
func TestNonEmptyIndexIsNotWalked(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	keys := seedBlobs(t, dir, 3, 20)
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := meta.Record(keys[0], 20); err != nil { // index knows ONE of three
		t.Fatal(err)
	}
	meta.Close()
	calls := countReconciles(t)
	err2, logs := runServe(t, dir, nil)
	if err2 != nil {
		t.Fatalf("serve: %v", err2)
	}
	if *calls != 0 || strings.Contains(logs, rebuildStartMsg) || strings.Contains(logs, rebuildDoneMsg) {
		t.Errorf("reconcile calls = %d, logs:\n%s; want none", *calls, logs)
	}
	if n, _ := indexState(t, dir); n != 1 {
		t.Errorf("index entries = %d, want 1 (partial loss is not repaired)", n)
	}
}

// Guard. REQ-STORE-006-AC5: a fresh data dir logs no rebuild line and
// does not reconcile.
func TestFreshDataDirDoesNotRebuild(t *testing.T) {
	clearEnv(t)
	calls := countReconciles(t)
	err, logs := runServe(t, t.TempDir(), nil)
	if err != nil {
		t.Fatalf("serve: %v", err)
	}
	if *calls != 0 || strings.Contains(logs, "index empty over existing blobs") {
		t.Errorf("calls = %d, logs:\n%s", *calls, logs)
	}
}

// RED. REQ-STORE-006-AC6: a walk that fails refuses the start with an
// error naming the reconcile step, serving nothing.
func TestRebuildWalkFailureRefusesStart(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	seedBlobs(t, dir, 2, 10)
	orig := cacheReconcile
	cacheReconcile = func(*cache.Cache, context.Context) (cache.ReconcileStats, error) {
		return cache.ReconcileStats{}, errTestReconcile
	}
	defer func() { cacheReconcile = orig }()
	served := false
	err, _ := runServe(t, dir, func(string) { served = true })
	if err == nil || !strings.Contains(err.Error(), "reconcil") {
		t.Fatalf("serve error = %v, want a reconcile error", err)
	}
	if served {
		t.Error("the server was serving despite a failed rebuild")
	}
}

// Guard. An unclean marker AND an empty index over blobs reconciles once,
// not twice.
func TestUncleanMarkerAndEmptyIndexReconcileOnce(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	seedBlobs(t, dir, 2, 10)
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil {
		t.Fatal(err)
	}
	calls := countReconciles(t)
	if err, _ := runServe(t, dir, nil); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if *calls != 1 {
		t.Errorf("reconcile ran %d times, want 1", *calls)
	}
	if n, _ := indexState(t, dir); n != 2 {
		t.Errorf("index entries = %d, want 2", n)
	}
}

// indexEmptyOverBlobs: the decision, and both of its failure modes
// (a closed index and a closed blob store both surface as errors).
func TestIndexEmptyOverBlobsDecision(t *testing.T) {
	dir := t.TempDir()
	blobs, err := blobstore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	meta, err := metadata.Open(filepath.Join(dir, "meta.db"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := indexEmptyOverBlobs(blobs, meta); err != nil || got {
		t.Fatalf("empty index, no blobs = %v, %v; want false", got, err)
	}
	if _, err := blobs.Put("k-1", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := indexEmptyOverBlobs(blobs, meta); err != nil || !got {
		t.Fatalf("empty index, one blob = %v, %v; want true", got, err)
	}
	if err := meta.Record("k-1", 1); err != nil {
		t.Fatal(err)
	}
	if got, err := indexEmptyOverBlobs(blobs, meta); err != nil || got {
		t.Fatalf("non-empty index = %v, %v; want false", got, err)
	}
	if err := meta.Delete("k-1"); err != nil {
		t.Fatal(err)
	}
	if err := blobs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := indexEmptyOverBlobs(blobs, meta); err == nil {
		t.Error("a closed blob store must surface an error")
	}
	if err := meta.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := indexEmptyOverBlobs(blobs, meta); err == nil {
		t.Error("a closed index must surface an error")
	}
}

// A failure of the check itself refuses the start (fail closed: the
// server does not guess whether blobs sit behind an empty index).
func TestIndexCheckFailureRefusesStart(t *testing.T) {
	clearEnv(t)
	orig := indexCheck
	indexCheck = func(*blobstore.Store, *metadata.Store) (bool, error) { return false, errTestReconcile }
	defer func() { indexCheck = orig }()
	err, _ := runServe(t, t.TempDir(), nil)
	if err == nil || !strings.Contains(err.Error(), "check index against blobs") {
		t.Fatalf("serve error = %v, want the index check error", err)
	}
}
