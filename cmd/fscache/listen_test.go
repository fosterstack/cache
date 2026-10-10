package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// REQ-CFG-004: configuration is validated, and the listen address bound,
// before anything under FSCACHE_DATA_DIR is created, opened or written.

// snapshotTree records every path under dir with its mode, size, content
// hash and modification time, so "byte-identical" is a comparison, not a
// hope.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		sum := ""
		if !d.IsDir() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum = fmt.Sprintf("%x", sha256.Sum256(b))
		}
		out[rel] = fmt.Sprintf("%v|%d|%s|%d", info.Mode(), info.Size(), sum, info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return out
}

// seedExistingDataDir builds a data directory the way a previous run
// would have left it after a clean shutdown: blobs, an index file, and no
// marker.
func seedExistingDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "ab"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "ab", "key1"), []byte("blob-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.db"), []byte("index-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

var badAddrs = []string{"8080", "localhost", ":99999", ":abc", "a:b:c", "256.256.256.256:80", "[::1"}

// REQ-CFG-004-AC1: a bad address is refused, naming FSCACHE_ADDR and the
// value, and a data directory that did not exist is still absent.
func TestBadAddressRefusedAndDataDirNotCreated(t *testing.T) {
	for _, addr := range badAddrs {
		t.Run(addr, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dir := filepath.Join(t.TempDir(), "never-created")
			t.Setenv("FSCACHE_DATA_DIR", dir)
			t.Setenv("FSCACHE_ADDR", addr)
			err := serve(context.Background(), quietLogger(), nil)
			if err == nil {
				t.Fatalf("FSCACHE_ADDR=%q: serve accepted it", addr)
			}
			if !strings.Contains(err.Error(), "FSCACHE_ADDR") || !strings.Contains(err.Error(), addr) {
				t.Errorf("error %q must name FSCACHE_ADDR and %q", err, addr)
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Errorf("data dir was created or touched (stat err = %v)", statErr)
			}
		})
	}
}

// REQ-CFG-004-AC2: with an existing data directory, a refused start leaves
// every file and directory exactly as found, and writes no marker.
func TestBadAddressLeavesExistingDataDirIdentical(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := seedExistingDataDir(t)
	before := snapshotTree(t, dir)
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", ":99999")
	if err := serve(context.Background(), quietLogger(), nil); err == nil {
		t.Fatal("serve accepted a bad address")
	}
	after := snapshotTree(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("data dir changed:\nbefore %v\nafter  %v", before, after)
	}
	if _, ok := after[".unclean-shutdown"]; ok {
		t.Error("an unclean-shutdown marker was written")
	}
}

// REQ-CFG-004-AC3: any other invalid configuration also leaves a
// nonexistent data directory uncreated.
func TestInvalidConfigDoesNotCreateDataDir(t *testing.T) {
	cases := map[string]map[string]string{
		"bad-max-bytes":  {"FSCACHE_MAX_BYTES": "20GiB"},
		"bad-uploads":    {"FSCACHE_MAX_CONCURRENT_UPLOADS": "lots"},
		"half-pair":      {"FSCACHE_USERNAME": "u"},
		"ro-without-rw":  {"FSCACHE_RO_USERNAME": "r", "FSCACHE_RO_PASSWORD": "p"},
		"bad-body-bytes": {"FSCACHE_MAX_BODY_BYTES": "-1"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)
			freshRegistry(t)
			dir := filepath.Join(t.TempDir(), "never-created")
			t.Setenv("FSCACHE_DATA_DIR", dir)
			t.Setenv("FSCACHE_ADDR", freePort(t))
			for k, v := range env {
				t.Setenv(k, v)
			}
			if err := serve(context.Background(), quietLogger(), nil); err == nil {
				t.Fatal("serve accepted an invalid configuration")
			}
			if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
				t.Errorf("data dir was created (stat err = %v)", statErr)
			}
		})
	}
}

// REQ-CFG-004-AC4: a taken port refuses the start, naming FSCACHE_ADDR and
// the address, and leaves the data directory unchanged - nonexistent stays
// nonexistent, existing stays byte-identical with no marker.
func TestTakenPortRefusedAndDataDirUnchanged(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer held.Close()
	addr := held.Addr().String()

	t.Run("nonexistent", func(t *testing.T) {
		clearEnv(t)
		freshRegistry(t)
		dir := filepath.Join(t.TempDir(), "never-created")
		t.Setenv("FSCACHE_DATA_DIR", dir)
		t.Setenv("FSCACHE_ADDR", addr)
		err := serve(context.Background(), quietLogger(), nil)
		if err == nil || !strings.Contains(err.Error(), "FSCACHE_ADDR") || !strings.Contains(err.Error(), addr) {
			t.Fatalf("serve error = %v, want a refusal naming FSCACHE_ADDR and %s", err, addr)
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("data dir was created (stat err = %v)", statErr)
		}
	})
	t.Run("existing", func(t *testing.T) {
		clearEnv(t)
		freshRegistry(t)
		dir := seedExistingDataDir(t)
		before := snapshotTree(t, dir)
		t.Setenv("FSCACHE_DATA_DIR", dir)
		t.Setenv("FSCACHE_ADDR", addr)
		if err := serve(context.Background(), quietLogger(), nil); err == nil {
			t.Fatal("serve started on a taken port")
		}
		if after := snapshotTree(t, dir); !reflect.DeepEqual(before, after) {
			t.Errorf("data dir changed:\nbefore %v\nafter  %v", before, after)
		}
	})
}

// The listener is released when startup fails after the bind (a store
// cannot open), so a failed start does not hold the port.
func TestListenerReleasedWhenStoreOpenFails(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blobs"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	addr := freePort(t)
	t.Setenv("FSCACHE_DATA_DIR", dir)
	t.Setenv("FSCACHE_ADDR", addr)
	if err := serve(context.Background(), quietLogger(), nil); err == nil {
		t.Fatal("serve succeeded with an unopenable blob store")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("port still held after a failed start: %v", err)
	}
	_ = ln.Close()
}

// A Serve failure after the bind surfaces as a serve error rather than
// blocking forever (the branch ListenAndServe used to exercise).
func TestServeFailureAfterBindIsReturned(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", freePort(t))
	orig := httpServe
	httpServe = func(*http.Server, net.Listener) error { return errTestShutdown }
	defer func() { httpServe = orig }()
	if err := serve(context.Background(), quietLogger(), nil); err == nil || !strings.Contains(err.Error(), "serve:") {
		t.Fatalf("serve error = %v, want a serve error", err)
	}
}

// Backlog R4: the startup line reports the address actually bound, so
// FSCACHE_ADDR=127.0.0.1:0 shows the real port, not ":0".
func TestStartupLineReportsBoundAddress(t *testing.T) {
	clearEnv(t)
	freshRegistry(t)
	t.Setenv("FSCACHE_DATA_DIR", t.TempDir())
	t.Setenv("FSCACHE_ADDR", "127.0.0.1:0")
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	if err := serve(ctx, log, func() { cancel() }); err != nil {
		t.Fatalf("serve: %v", err)
	}
	var addr string
	for _, line := range strings.Split(buf.String(), "\n") {
		var rec struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "fscache: starting" {
			addr = rec.Addr
		}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" || port == "0" || port == "" {
		t.Errorf("startup addr = %q, want 127.0.0.1:<the bound port>", addr)
	}
}
