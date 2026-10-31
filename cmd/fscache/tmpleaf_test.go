package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fosterstack/cache/internal/blobstore"
)

// REQ-PROTO-003-AC4: keys whose leaf starts with ".tmp-", stored before an
// unclean shutdown, are still there and readable after the startup
// reconciliation; only the stray files in the store's temporary directory
// are removed.
func TestServeUncleanStartKeepsTmpLeafKeys(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	blobDir := filepath.Join(dir, "blobs")
	keys := []string{".tmp-x", "a/b/.tmp-y", ".tmp-0123456789abcdef0123456789abcdef"}

	seed, err := blobstore.New(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if _, err := seed.Put(k, strings.NewReader("body:"+k)); err != nil {
			t.Fatalf("seed %s: %v", k, err)
		}
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(blobDir, "+tmp", ".tmp-cafecafecafecafecafecafecafecafe")
	if err := os.MkdirAll(filepath.Dir(stray), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stray, []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeMarker(uncleanMarkerPath(dir)); err != nil { // the process before did not exit cleanly
		t.Fatalf("seed marker: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, quietLogger(), func() { cancel() }) }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve with reconcile returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not shut down")
	}

	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Errorf("stray temporary file still present (stat err = %v)", err)
	}
	after, err := blobstore.New(blobDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = after.Close() }()
	for _, k := range keys {
		rc, _, err := after.Get(k)
		if err != nil {
			t.Errorf("Get %s after the unclean start: %v", k, err)
			continue
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) != "body:"+k {
			t.Errorf("Get %s = %q", k, b)
		}
	}
}
