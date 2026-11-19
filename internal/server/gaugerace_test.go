package server

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fosterstack/cache/internal/metrics"
)

// Rule: a scrape of /metrics refreshes store_bytes and store_entries; a
// PUT never does. When scrapes overlap, the gauges end at the store's totals.
// The first scrape's refresh is held after it has read the totals and before
// it sets the gauges (the seam), while a PUT and a second scrape complete.
func TestGaugesEndAtTheStoreTotalsWhenUploadsOverlap(t *testing.T) {
	h, c := newTestHandlerWithStore(t, Credentials{})
	_ = h
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	srv := httptest.NewServer(New(Config{Cache: c, Metrics: m, Registry: reg, MaxBodyBytes: 1 << 20}))
	defer srv.Close()

	entered := make(chan struct{})
	var first atomic.Bool
	prev := gaugesReadHook
	gaugesReadHook = func() {
		if first.CompareAndSwap(false, true) {
			close(entered)
			time.Sleep(300 * time.Millisecond)
		}
	}
	t.Cleanup(func() { gaugesReadHook = prev })

	put(t, srv.URL, "first", "aaaa")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scrape(t, srv.URL)
	}()
	<-entered // the first scrape's refresh has read one entry of 4 bytes and is held
	put(t, srv.URL, "second", "bbbbbbbb")
	scrape(t, srv.URL)
	wg.Wait()

	total, err := c.TotalSize()
	if err != nil {
		t.Fatal(err)
	}
	count, err := c.EntryCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 || total != 12 {
		t.Fatalf("store holds %d entries, %d bytes; want 2, 12", count, total)
	}
	if got := gaugeValue(t, m.StoreEntries); got != float64(count) {
		t.Errorf("store_entries gauge = %v, want %d", got, count)
	}
	if got := gaugeValue(t, m.StoreBytesTotal); got != float64(total) {
		t.Errorf("store_bytes gauge = %v, want %d", got, total)
	}
	text := scrape(t, srv.URL)
	if !strings.Contains(text, "fscache_store_entries 2\n") || !strings.Contains(text, "fscache_store_bytes 12\n") {
		t.Errorf("final scrape does not show 2 entries, 12 bytes:\n%s", text)
	}
}

// countingStore counts the reads a PUT must not make.
type countingStore struct {
	Store
	totals, counts atomic.Int64
}

func (s *countingStore) TotalSize() (int64, error) {
	s.totals.Add(1)
	return s.Store.TotalSize()
}

func (s *countingStore) EntryCount() (int, error) {
	s.counts.Add(1)
	return s.Store.EntryCount()
}

// Rule: a PUT does not read TotalSize or EntryCount; a scrape shows the
// stored totals.
func TestPutDoesNotRefreshGaugesScrapeDoes(t *testing.T) {
	_, c := newTestHandlerWithStore(t, Credentials{})
	cs := &countingStore{Store: c}
	reg := prometheus.NewRegistry()
	srv := httptest.NewServer(New(Config{Cache: cs, Metrics: metrics.New(reg), Registry: reg, MaxBodyBytes: 1 << 20}))
	defer srv.Close()
	cs.totals.Store(0) // New seeded the gauges once
	cs.counts.Store(0)

	var want int
	for i := 0; i < 20; i++ {
		body := strings.Repeat("x", i+1)
		want += len(body)
		put(t, srv.URL, fmt.Sprintf("k%d", i), body)
	}
	if n, m := cs.totals.Load(), cs.counts.Load(); n != 0 || m != 0 {
		t.Fatalf("20 PUTs made %d TotalSize and %d EntryCount calls, want 0 and 0", n, m)
	}
	text := scrape(t, srv.URL)
	if wantLine := fmt.Sprintf("fscache_store_bytes %d\n", want); !strings.Contains(text, wantLine) {
		t.Errorf("scrape lacks %q:\n%s", wantLine, text)
	}
	if !strings.Contains(text, "fscache_store_entries 20\n") {
		t.Errorf("scrape lacks fscache_store_entries 20:\n%s", text)
	}
}

func scrape(t *testing.T, base string) string {
	t.Helper()
	resp := doReq(t, mustReq(t, http.MethodGet, base+"/metrics", ""))
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("read /metrics: %v", err)
	}
	return string(b)
}

func put(t *testing.T, base, key, body string) {
	t.Helper()
	u, _ := url.JoinPath(base, key)
	resp := doReq(t, mustReq(t, http.MethodPut, u, body))
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT %s status = %d, want 201", key, resp.StatusCode)
	}
}
