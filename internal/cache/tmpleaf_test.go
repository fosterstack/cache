package cache

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// REQ-PROTO-003-AC4: reconciliation keeps keys whose leaf starts with
// ".tmp-" (indexed, readable, at their paths) and removes only the stray
// files in the store's temporary directory.
func TestReconcileKeepsTmpLeafKeys(t *testing.T) {
	blobDir, metaPath := t.TempDir(), filepath.Join(t.TempDir(), "meta.db")
	blobs, meta := openTestStores(t, blobDir, metaPath)
	c := New(blobs, meta)
	defer func() { _ = c.Close() }()
	keys := map[string]string{ // key -> its path, as it has always been
		".tmp-x":                                ".t/.tmp-x",
		"a/b/.tmp-y":                            "a/b/.t/.tmp-y",
		".tmp-0123456789abcdef0123456789abcdef": ".t/.tmp-0123456789abcdef0123456789abcdef",
	}
	for k := range keys {
		put(t, c, k, "body:"+k)
	}
	strays := []string{filepath.Join(blobDir, "+tmp", ".tmp-cafecafecafecafecafecafecafecafe"), filepath.Join(blobDir, "+tmp", "other")}
	if err := os.MkdirAll(filepath.Join(blobDir, "+tmp"), 0o750); err != nil {
		t.Fatal(err)
	}
	for _, p := range strays {
		if err := os.WriteFile(p, []byte("interrupted"), 0o600); err != nil {
			t.Fatalf("seed stray: %v", err)
		}
	}

	stats, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if stats.RemovedTempFiles != len(strays) || stats.AdoptedBlobs != 0 || stats.DroppedRecords != 0 {
		t.Errorf("stats = %+v, want %d removed, 0 adopted, 0 dropped", stats, len(strays))
	}
	for _, p := range strays {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("stray %s still present (stat err = %v)", p, err)
		}
	}
	if n, _ := c.EntryCount(); n != len(keys) {
		t.Errorf("EntryCount = %d, want %d", n, len(keys))
	}
	for k, rel := range keys {
		rc, _, err := c.Get(context.Background(), k)
		if err != nil {
			t.Fatalf("Get %s after reconciliation: %v", k, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) != "body:"+k {
			t.Errorf("Get %s = %q", k, b)
		}
		if _, err := os.Stat(filepath.Join(blobDir, filepath.FromSlash(rel))); err != nil {
			t.Errorf("key %s not at its path %s: %v", k, rel, err)
		}
	}
}
