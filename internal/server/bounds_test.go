package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// REQ-HTTP-001-AC1: every timeout explicitly set — none left infinite.
func TestHTTPServerTimeoutsAreSet(t *testing.T) {
	srv := NewHTTPServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %v, want 10s", srv.ReadHeaderTimeout)
	}
	if srv.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want 120s", srv.IdleTimeout)
	}
	if srv.ReadTimeout != 20*time.Minute {
		t.Errorf("ReadTimeout = %v, want 20m (a stuck read must not wait forever)", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 20*time.Minute {
		t.Errorf("WriteTimeout = %v, want 20m", srv.WriteTimeout)
	}
}

// slowBody feeds one byte, then blocks until released — a slow client
// holding an upload slot.
type slowBody struct {
	release chan struct{}
	fedOne  bool
}

func (b *slowBody) Read(p []byte) (int, error) {
	if !b.fedOne {
		b.fedOne = true
		p[0] = 'x'
		return 1, nil
	}
	<-b.release
	return 0, io.EOF
}

// REQ-HTTP-002-AC1: with a concurrency bound of 1 and one slow upload in
// flight, a second PUT is refused with 429 + Retry-After and stores
// nothing; after the slot frees, PUTs succeed again.
func TestConcurrentUploadBoundRefusesExcessWith429(t *testing.T) {
	h := newTestHandlerWithUploadLimit(t, 1)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close) // registered BEFORE release so LIFO runs release first

	slow := &slowBody{release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(slow.release) }) }
	t.Cleanup(release) // a failed assertion must not deadlock server.Close
	firstDone := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/slow-key", slow)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				firstDone <- io.ErrUnexpectedEOF
				return
			}
		}
		firstDone <- err
	}()

	// Give the slow upload time to occupy the slot.
	time.Sleep(300 * time.Millisecond)

	resp := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/refused-key", "body"))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second PUT while slot busy: status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 without a Retry-After header")
	}
	if r := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/refused-key", "")); r.StatusCode != http.StatusNotFound {
		t.Errorf("refused PUT stored something: GET = %d, want 404", r.StatusCode)
	}

	release()
	wg.Wait()
	if err := <-firstDone; err != nil {
		t.Fatalf("slow upload should have completed normally: %v", err)
	}
	if r := doReq(t, mustReq(t, http.MethodGet, srv.URL+"/slow-key", "")); r.StatusCode != http.StatusOK {
		t.Errorf("slow upload's entry missing after completion: GET = %d", r.StatusCode)
	}

	if r := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/after-key", "ok")); r.StatusCode != http.StatusCreated {
		t.Errorf("PUT after slot freed: status = %d, want 201", r.StatusCode)
	}
}

// A zero bound means unbounded — the default keeps today's behavior
// unless configured.
func TestZeroUploadBoundMeansUnbounded(t *testing.T) {
	h := newTestHandlerWithUploadLimit(t, 0)
	srv := httptest.NewServer(h)
	defer srv.Close()
	if r := doReq(t, mustReq(t, http.MethodPut, srv.URL+"/k", "v")); r.StatusCode != http.StatusCreated {
		t.Fatalf("PUT with unbounded config: %d", r.StatusCode)
	}
}
