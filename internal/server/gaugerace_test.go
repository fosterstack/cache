package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/fosterstack/cache/internal/metrics"
)

// REQ-OBS-003-AC8: when uploads overlap, the store_bytes and store_entries
// gauges end equal to the store's totals once the last upload has
// completed. The first refresh is held after it has read the totals and
// before it sets the gauges (the seam), while a second upload completes:
// without ordering, the first refresh then writes its older totals last.
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

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		put(t, srv.URL, "first", "aaaa")
	}()
	<-entered // the first upload's refresh has read one entry of 4 bytes and is held
	put(t, srv.URL, "second", "bbbbbbbb")
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
}

func put(t *testing.T, base, key, body string) {
	t.Helper()
	u, _ := url.JoinPath(base, key)
	resp := doReq(t, mustReq(t, http.MethodPut, u, body))
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("PUT %s status = %d, want 201", key, resp.StatusCode)
	}
}
