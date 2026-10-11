//go:build unix

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// REQ-TLS-001-AC3 cases that need FIFOs (unix only).

// proves: REQ-TLS-001-AC3 — a FIFO, a directory or a device at either path is refused as not a regular file, at once (nothing blocks), and a symlink to a regular file still loads
func TestTLSPathMustBeRegularFile(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "regular", "MARKER-REG-8e8e8e")
	fifo := filepath.Join(dir, "fifo.pem")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	const C, K = "FSCACHE_TLS_CERT", "FSCACHE_TLS_KEY"
	fifoLink := filepath.Join(dir, "fifo-link.pem")
	if err := os.Symlink(fifo, fifoLink); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct{ name, path string }{{"FIFO", fifo}, {"FIFO behind a symlink", fifoLink}, {"directory", subdir}, {"device", os.DevNull}} {
		for _, side := range []string{C, K} {
			t.Run(bad.name+" at "+side, func(t *testing.T) {
				clearEnv(t)
				freshRegistry(t)
				dataDir := filepath.Join(t.TempDir(), "never-created")
				t.Setenv("FSCACHE_DATA_DIR", dataDir)
				t.Setenv("FSCACHE_ADDR", freePort(t))
				t.Setenv(C, p.certPath)
				t.Setenv(K, p.keyPath)
				t.Setenv(side, bad.path)
				type result struct {
					code int
					out  string
				}
				done := make(chan result, 1)
				go func() { c, o := runMainCaptured(t); done <- result{c, o} }()
				select {
				case r := <-done:
					if r.code != 1 {
						t.Fatalf("exit code %d, want 1", r.code)
					}
					want := fmt.Sprintf("%s=%q is not a regular file", side, bad.path)
					var rec struct{ Msg, Error string }
					for _, line := range strings.Split(strings.TrimSpace(r.out), "\n") {
						if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "fscache: fatal" {
							break
						}
					}
					if rec.Error != want {
						t.Errorf("startup error = %q, want exactly %q", rec.Error, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("startup blocked on a non-regular file")
				}
				if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
					t.Errorf("the data directory was created (stat err = %v)", err)
				}
			})
		}
	}

	// A symlink to a regular file (how a Kubernetes Secret volume presents
	// its files) still loads.
	certLink, keyLink := filepath.Join(dir, "link.crt"), filepath.Join(dir, "link.key")
	if err := os.Symlink(p.certPath, certLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p.keyPath, keyLink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadKeyPair(certLink, keyLink); err != nil {
		t.Errorf("symlinks to regular files were refused: %v", err)
	}
}

// proves: REQ-TLS-001-AC3 — a file swapped for a FIFO between the check and the open is refused at once: the open does not wait for a writer
func TestTLSFileSwappedForFIFOIsRefusedWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	p := writePair(t, dir, "swapfifo", "MARKER-SWAPFIFO-b1b1b1")
	orig := openTLSFile
	openTLSFile = func(path string) (*os.File, error) {
		// the path passed the stat as a regular file; it becomes a FIFO
		// with no writer before the real open runs
		if err := os.Remove(path); err != nil {
			return nil, err
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			return nil, err
		}
		return orig(path)
	}
	defer func() { openTLSFile = orig }()
	t.Cleanup(func() {
		// release an open that blocked (the red run) so no goroutine is left behind
		if w, err := os.OpenFile(p.certPath, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
	})

	done := make(chan error, 1)
	go func() {
		_, err := loadKeyPair(p.certPath, p.keyPath)
		done <- err
	}()
	select {
	case err := <-done:
		want := fmt.Sprintf("FSCACHE_TLS_CERT=%q is not a regular file", p.certPath)
		if err == nil || err.Error() != want {
			t.Fatalf("error = %v, want exactly %q", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the open blocked on a FIFO swapped in after the check")
	}
}
