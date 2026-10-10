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
	"strings"
	"sync"
	"time"
)

// Defaults (advisor step 5, 2026-10-09): a five-second sample life and a
// two-second probe limit.
const (
	DefaultFresh      = 5 * time.Second
	DefaultProbeLimit = 2 * time.Second
	DefaultWaitBudget = 10 * time.Millisecond
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
	// Sweep removes leftover probe files at start (a probe whose cleanup failed, then a clean restart); the default removes root-level .tmp-probe-* files.
	Sweep func(dir string)
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
	busy  bool     // a probe goroutine is running (possibly past its limit)
	rf    *refresh // the refresh in flight or last started; each refresh has its OWN state, so a stale goroutine can only touch its own
	last  *bool    // last published writable state, for change logging
	seq   uint64   // number of the latest publication (guarded by mu)

	logMu  sync.Mutex // orders the state-change log lines
	logged uint64     // seq of the latest line written (guarded by logMu)

	afterFinish func() // test seam only (nil in production)
}

// New returns a Sampler for dir.
func New(dir string, d Deps, o Options) *Sampler {
	if d.Statfs == nil {
		d.Statfs = realStatfs
	}
	if d.OpenProbe == nil {
		d.OpenProbe = func(path string) (ProbeFile, error) {
			return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is the sampler's own probe name inside the data directory
		}
	}
	if d.Remove == nil {
		d.Remove = os.Remove
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Sweep == nil {
		d.Sweep = sweepProbeFiles
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
	s.d.Sweep(s.dir)
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

// refresh is the state of ONE measurement. Both of its goroutines capture it, so a goroutine that outlives its refresh can never publish into, or close
// the channel of, a newer one.
type refresh struct {
	done      chan struct{} // closed once, when the refresh has published
	closeOnce sync.Once
	published bool // guarded by Sampler.mu: the refresh's sample is published (by the measuring goroutine or by the limit)
}

func (r *refresh) close() { r.closeOnce.Do(func() { close(r.done) }) }

// result is one finished measurement.
type result struct {
	probeErr error
	avail    uint64
	statErr  error
}

// refreshIfNeeded starts a refresh when the sample is missing, expired or
// stale and none is running; it returns the channel to wait on, or nil.
//
// busy is owned by the measuring goroutine alone: it is set when the goroutine
// starts and cleared when the goroutine really returns, so a probe stuck past
// its limit keeps the single slot. The limit only decides when to PUBLISH
// "not writable"; if the probe finishes later, its real result is published
// then (limited marks that case).
func (s *Sampler) refreshIfNeeded() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy {
		return s.rf.done
	}
	if s.have && !s.stale && s.d.Now().Sub(s.at) < s.o.Fresh {
		return nil
	}
	rf := &refresh{done: make(chan struct{})}
	s.busy, s.stale, s.rf = true, false, rf
	finished := make(chan struct{})
	go func() {
		r := result{probeErr: s.probe()}
		r.avail, r.statErr = s.d.Statfs(s.dir) // statfs is inside the measuring goroutine too: a hung statfs cannot hang a reader
		first := s.finish(rf, r, false)
		if s.afterFinish != nil {
			s.afterFinish() // test seam: the gap between releasing the slot and closing the channels
		}
		if first {
			rf.close()
		}
		close(finished)
	}()
	go func() {
		t := time.NewTimer(s.o.ProbeLimit)
		defer t.Stop()
		select {
		case <-finished:
		case <-t.C:
			s.mu.Lock()
			prev := s.cur.FreeBytes // keep the last known free bytes
			s.mu.Unlock()
			if s.finish(rf, result{probeErr: errProbeLimit, avail: prev}, true) {
				rf.close()
			}
		}
	}()
	return rf.done
}

// finish claims the refresh and publishes its sample in ONE critical section, so no ordering window exists. The first finisher publishes its result:
// the measuring goroutine normally, or the limit when the probe is still running ("not writable"). The measuring goroutine ALWAYS releases the slot here;
// when it finishes after the limit has fired, its answer is published as "not writable" with its own free bytes: a probe that took longer than the
// limit never reads writable, however it ends. A finisher of an older refresh finds that refresh already published and does nothing. It reports whether
// it was the first finisher of rf (the one that closes rf.done).
func (s *Sampler) finish(rf *refresh, r result, limit bool) (first bool) {
	s.mu.Lock()
	first = !rf.published
	if !limit && !first {
		r.probeErr = errProbeLimit
	}
	if limit && !first {
		s.mu.Unlock()
		return false
	}
	rf.published = true
	if !limit {
		s.busy = false
	}
	smp := Sample{Writable: r.probeErr == nil && r.statErr == nil}
	if r.statErr == nil {
		smp.FreeBytes = r.avail
	}
	s.cur, s.at, s.have = smp, s.d.Now(), true
	prev := s.last
	w := smp.Writable
	s.last = &w
	s.seq++
	mySeq := s.seq
	s.mu.Unlock()
	if prev != nil && *prev == w || prev == nil && w {
		return first
	}
	// the line is written under its own lock and only if no later transition has been logged yet, so the lines come out in the order of the states and
	// the last line never contradicts the gauge
	s.logMu.Lock()
	defer s.logMu.Unlock()
	if mySeq < s.logged {
		return first
	}
	s.logged = mySeq
	err := r.probeErr
	if err == nil {
		err = r.statErr
	}
	if w {
		s.o.Log.Info("store_writable: the data directory is writable again", "dir", s.dir, "free_bytes", smp.FreeBytes)
	} else {
		s.o.Log.Error("store_writable: the data directory is not writable", "dir", s.dir, "free_bytes", smp.FreeBytes, "error", err)
	}
	return first
}

type limitErr struct{}

func (limitErr) Error() string { return "the writability probe took longer than its limit" }

var errProbeLimit error = limitErr{}

// probe creates, writes one byte to, syncs, closes and removes a file in the
// data directory. The sync is deliberate: without it a full disk can accept
// the byte into the page cache and report writable.
func (s *Sampler) probe() error {
	var b [8]byte
	_, _ = rand.Read(b[:]) // never fails (crypto/rand panics instead)
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

// sweepProbeFiles removes the regular files named .tmp-probe-* directly in dir: leftovers of a probe whose own cleanup failed. It touches nothing else.
func sweepProbeFiles(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasPrefix(e.Name(), probePrefix) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
