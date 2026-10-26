package cache

import (
	"bytes"
	"context"
	"flag"
	"io"
	"sync"
	"testing"
)

// FuzzCacheOps drives random Put/Get/Stat sequences under a byte cap and checks, after every step, that the recorded total equals the sum of the
// entries' sizes, never exceeds the cap, and that Get returns the bytes of the last Put. The seed corpus runs in plain `go test`. A final phase of
// concurrent same-key Puts (the interleaving of pre-rc review finding V2) is timing-dependent and runs only under `go test -fuzz`, so CI never flakes.
func FuzzCacheOps(f *testing.F) {
	f.Add([]byte{0, 0, 10, 0, 1, 20, 1, 0, 0, 2, 1, 0})
	f.Add([]byte{0, 0, 100, 0, 1, 100, 0, 2, 100, 0, 3, 100, 0, 4, 100, 0, 0, 200})
	f.Fuzz(func(t *testing.T, ops []byte) {
		const maxBytes = 600
		c := newTestCache(t, WithMaxBytes(maxBytes))
		ctx := context.Background()
		content := map[string][]byte{}
		keys := []string{"aa11", "bb22", "cc33", "dd44", "ee55"}
		for i := 0; i+2 < len(ops) && i < 90; i += 3 {
			k := keys[int(ops[i+1])%len(keys)]
			switch ops[i] % 3 {
			case 0:
				data := bytes.Repeat([]byte{byte(i)}, int(ops[i+2]))
				if _, err := c.Put(ctx, k, bytes.NewReader(data)); err == nil {
					content[k] = data
				}
			case 1:
				rc, n, err := c.Get(ctx, k)
				if err == nil {
					b, _ := io.ReadAll(rc)
					_ = rc.Close()
					if want, ok := content[k]; ok && (!bytes.Equal(b, want) || n != int64(len(want))) {
						t.Fatalf("Get %s returned %d bytes (n=%d), last Put had %d", k, len(b), n, len(want))
					}
				}
			case 2:
				_, _ = c.Stat(k)
			}
			checkAccounting(t, c, keys, maxBytes)
		}
		if fl := flag.Lookup("test.fuzz"); fl == nil || fl.Value.String() == "" {
			return // plain `go test`: the sequential invariants above are the whole test
		}
		var wg sync.WaitGroup
		for g := 0; g < 3; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				sz := 1
				if len(ops) > g {
					sz = int(ops[g]) + 1
				}
				_, _ = c.Put(ctx, keys[0], bytes.NewReader(bytes.Repeat([]byte{'z'}, sz)))
			}(g)
		}
		wg.Wait()
		checkAccounting(t, c, keys, maxBytes)
	})
}

func checkAccounting(t *testing.T, c *Cache, keys []string, maxBytes int64) {
	t.Helper()
	total, err := c.TotalSize()
	if err != nil {
		t.Fatalf("TotalSize: %v", err)
	}
	var sum int64
	for _, k := range keys {
		if n, err := c.Stat(k); err == nil {
			sum += n
		}
	}
	if total != sum {
		t.Fatalf("accounting: TotalSize %d != sum of Stat %d", total, sum)
	}
	if total > maxBytes {
		t.Fatalf("over the cap: %d > %d", total, maxBytes)
	}
}
