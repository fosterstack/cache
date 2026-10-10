// Package storesample measures whether the data directory can be written and
// how much room its filesystem has, and holds the result as ONE shared
// sample that /metrics and /statusz both read (REQ-OBS-002, REQ-OBS-003).
//
// The sample is taken once at startup and again, lazily, when a reader finds
// it older than five seconds (or a failed PUT marked it stale). At most one
// probe runs at a time; a reader that arrives during a probe waits only a
// small budget and otherwise gets the previous sample, so a slow disk can
// never hang a scrape. There is no timer thread: nobody scraping, no work.
package storesample

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Defaults (advisor step 5, 2026-10-09): a five-second sample life and a
// two-second probe limit.
const (
	DefaultFresh      = 5 * time.Second
	DefaultProbeLimit = 2 * time.Second
	DefaultWaitBudget = 50 * time.Millisecond
	probePrefix       = ".tmp-probe-" // the blob store's own temporary prefix: leftovers are swept at startup
)

// Sample is one measurement.
type Sample struct {
	Writable  bool
	FreeBytes uint64
}

// ProbeFile is the part of a file the probe uses.
type ProbeFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// Deps are the injectable operating-system seams. Zero fields use the real ones.
type Deps struct {
	Statfs    func(dir string) (availBytes uint64, err error)
	OpenProbe func(path string) (ProbeFile, error)
	Remove    func(path string) error
	Now       func() time.Time
}

// Options tune the sampler; zero values use the defaults.
type Options struct {
	Fresh      time.Duration
	ProbeLimit time.Duration
	WaitBudget time.Duration
	Log        *slog.Logger
}

// Sampler holds the shared sample.
type Sampler struct {
	dir   string
	d     Deps
	o     Options
	mu    sync.Mutex
	cur   Sample
	at    time.Time
	have  bool
	stale bool
	busy  bool          // a probe goroutine is running (possibly past its limit)
	done  chan struct{} // closed when the current refresh has published
	last  *bool         // last published writable state, for change logging
}

// New returns a Sampler for dir.
func New(dir string, d Deps, o Options) *Sampler {
	if d.Statfs == nil {
		d.Statfs = realStatfs
	}
	if d.OpenProbe == nil {
		d.OpenProbe = func(path string) (ProbeFile, error) {
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
	}
	if d.Remove == nil {
		d.Remove = os.Remove
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if o.Fresh == 0 {
		o.Fresh = DefaultFresh
	}
	if o.ProbeLimit == 0 {
		o.ProbeLimit = DefaultProbeLimit
	}
	if o.WaitBudget == 0 {
		o.WaitBudget = DefaultWaitBudget
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Sampler{dir: dir, d: d, o: o}
}

// Start takes the first sample and waits for it (the server does not accept
// requests before the gauges hold a measured value).
func (s *Sampler) Start() {
	ch := s.refreshIfNeeded()
	if ch != nil {
		<-ch
	}
}

// MarkStale makes the next Get measure again (a PUT failed with no space or
// a read-only error).
func (s *Sampler) MarkStale() {
	s.mu.Lock()
	s.stale = true
	s.mu.Unlock()
}

// Get returns the shared sample, measuring first if it has expired.
func (s *Sampler) Get() Sample {
	if ch := s.refreshIfNeeded(); ch != nil {
		t := time.NewTimer(s.o.WaitBudget)
		select {
		case <-ch:
		case <-t.C:
		}
		t.Stop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// refreshIfNeeded starts a refresh when the sample is missing, expired or
// stale and none is running; it returns the channel to wait on, or nil.
func (s *Sampler) refreshIfNeeded() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return s.done
	}
	if s.have && !s.stale && s.d.Now().Sub(s.at) < s.o.Fresh {
		return nil
	}
	s.busy = true
	s.stale = false
	s.done = make(chan struct{})
	done := s.done
	probeDone := make(chan error, 1)
	go func() {
		err := s.probe()
		s.mu.Lock()
		s.busy = false // the slot is free only when the probe has really returned
		s.mu.Unlock()
		probeDone <- err
	}()
	go func() {
		var werr error
		t := time.NewTimer(s.o.ProbeLimit)
		select {
		case werr = <-probeDone:
		case <-t.C:
			werr = errProbeLimit
			s.mu.Lock()
			s.busy = true // still held by the stuck probe goroutine until it returns
			s.mu.Unlock()
		}
		t.Stop()
		s.publish(werr)
		close(done)
	}()
	return done
}

type limitErr struct{}

func (limitErr) Error() string { return "the writability probe took longer than its limit" }

var errProbeLimit error = limitErr{}

func (s *Sampler) publish(probeErr error) {
	avail, serr := s.d.Statfs(s.dir)
	smp := Sample{Writable: probeErr == nil && serr == nil}
	if serr == nil {
		smp.FreeBytes = avail
	}
	s.mu.Lock()
	s.cur, s.at, s.have = smp, s.d.Now(), true
	prev := s.last
	w := smp.Writable
	s.last = &w
	s.mu.Unlock()
	if prev == nil && w {
		return
	}
	if prev == nil || *prev != w {
		err := probeErr
		if err == nil {
			err = serr
		}
		if w {
			s.o.Log.Info("store_writable: the data directory is writable again", "dir", s.dir, "free_bytes", smp.FreeBytes)
		} else {
			s.o.Log.Error("store_writable: the data directory is not writable", "dir", s.dir, "free_bytes", smp.FreeBytes, "error", err)
		}
	}
}

// probe creates, writes one byte to, syncs, closes and removes a file in the
// data directory. The sync is deliberate: without it a full disk can accept
// the byte into the page cache and report writable.
func (s *Sampler) probe() error {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	path := filepath.Join(s.dir, probePrefix+hex.EncodeToString(b[:]))
	f, err := s.d.OpenProbe(path)
	if err != nil {
		_ = s.d.Remove(path)
		return err
	}
	var first error
	if _, err := f.Write([]byte{0}); err != nil {
		first = err
	}
	if first == nil {
		if err := f.Sync(); err != nil {
			first = err
		}
	}
	if err := f.Close(); err != nil && first == nil {
		first = err
	}
	if err := s.d.Remove(path); err != nil && first == nil {
		first = err
	}
	return first
}
