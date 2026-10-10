package storesample

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeDisk is the injected disk: it records every operation in order, can
// fail any step, and can block the probe until released.
type fakeDisk struct {
	mu       sync.Mutex
	ops      []string
	names    []string
	avail    uint64
	statErr  error
	openErr  error
	writeErr error
	syncErr  error
	closeErr error
	rmErr    error
	block    chan struct{} // when non-nil, OpenProbe waits for it to close
	probes   atomic.Int64
}

type fakeFile struct{ d *fakeDisk }

func (f fakeFile) Write(p []byte) (int, error) {
	f.d.rec("write")
	if f.d.writeErr != nil {
		return 0, f.d.writeErr
	}
	return len(p), nil
}
func (f fakeFile) Sync() error  { f.d.rec("sync"); return f.d.syncErr }
func (f fakeFile) Close() error { f.d.rec("close"); return f.d.closeErr }

func (d *fakeDisk) rec(s string) { d.mu.Lock(); d.ops = append(d.ops, s); d.mu.Unlock() }
func (d *fakeDisk) opList() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.ops, ",")
}

func (d *fakeDisk) deps(now *time.Time) Deps {
	return Deps{
		Statfs: func(string) (uint64, error) { return d.avail, d.statErr },
		OpenProbe: func(path string) (ProbeFile, error) {
			d.probes.Add(1)
			d.mu.Lock()
			d.names = append(d.names, path)
			blk := d.block
			d.mu.Unlock()
			if blk != nil {
				<-blk
			}
			d.rec("open")
			if d.openErr != nil {
				return nil, d.openErr
			}
			return fakeFile{d}, nil
		},
		Remove: func(string) error { d.rec("remove"); return d.rmErr },
		Now:    func() time.Time { return *now },
	}
}

func newSampler(t *testing.T, d *fakeDisk, now *time.Time, opt ...func(*Options)) (*Sampler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	o := Options{Log: slog.New(slog.NewTextHandler(&buf, nil)), WaitBudget: 200 * time.Millisecond}
	for _, f := range opt {
		f(&o)
	}
	return New("/data/blobs", d.deps(now), o), &buf
}

// REQ-OBS-002-AC2, AC6: a healthy disk reads writable with the available bytes.
func TestHealthyDiskReadsWritableWithFreeBytes(t *testing.T) {
	d := &fakeDisk{avail: 12345}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now)
	s.Start()
	if got := s.Get(); !got.Writable || got.FreeBytes != 12345 {
		t.Fatalf("Get = %+v; want writable, 12345 free", got)
	}
}

// REQ-OBS-002-AC6: a failed statfs reads 0 free and NOT writable, even if
// the probe itself worked (fail loud, not silently healthy).
func TestStatfsFailureReadsZeroAndNotWritable(t *testing.T) {
	d := &fakeDisk{avail: 999, statErr: errors.New("statfs: boom")}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now)
	s.Start()
	if got := s.Get(); got.Writable || got.FreeBytes != 0 {
		t.Fatalf("Get = %+v; want not writable, 0 free", got)
	}
}

// REQ-OBS-002-AC3: each failing step reads 0; a failed sync (the full-disk
// case that a page-cache write hides) is one of them. Free bytes are still
// reported when only the write path fails.
func TestEachProbeStepFailureReadsNotWritable(t *testing.T) {
	for name, mod := range map[string]func(*fakeDisk){
		"open":  func(d *fakeDisk) { d.openErr = syscall.EROFS },
		"write": func(d *fakeDisk) { d.writeErr = syscall.ENOSPC },
		"sync":  func(d *fakeDisk) { d.syncErr = syscall.ENOSPC },
	} {
		d := &fakeDisk{avail: 77}
		mod(d)
		now := time.Unix(1000, 0)
		s, _ := newSampler(t, d, &now)
		s.Start()
		if got := s.Get(); got.Writable || got.FreeBytes != 77 {
			t.Errorf("%s failure: Get = %+v; want not writable, 77 free", name, got)
		}
	}
}

// REQ-OBS-002-AC4: the probe is create, write one byte, sync, close, remove,
// in that order, and removes its file even when a step fails. Its file name
// carries the store's temporary prefix so the startup sweep deletes leftovers.
func TestProbeStepsOrderAndTempName(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now)
	s.Start()
	if got := d.opList(); got != "open,write,sync,close,remove" {
		t.Fatalf("ops = %q; want open,write,sync,close,remove", got)
	}
	if len(d.names) != 1 || !strings.HasPrefix(filepath.Base(d.names[0]), ".tmp-probe-") || filepath.Dir(d.names[0]) != "/data/blobs" {
		t.Fatalf("probe path = %v; want /data/blobs/.tmp-probe-*", d.names)
	}
	d2 := &fakeDisk{avail: 1, syncErr: syscall.ENOSPC}
	s2, _ := newSampler(t, d2, &now)
	s2.Start()
	if got := d2.opList(); got != "open,write,sync,close,remove" {
		t.Fatalf("failing-sync ops = %q; the file must still be closed and removed", got)
	}
}

// REQ-OBS-002-AC5: no new probe while the sample is fresh; a new one after 5 s;
// a failed PUT (MarkStale) forces the next read to re-measure.
func TestFreshnessAndMarkStale(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now)
	s.Start()
	for i := 0; i < 100; i++ {
		now = now.Add(40 * time.Millisecond) // 4 s in total
		s.Get()
	}
	if n := d.probes.Load(); n != 1 {
		t.Fatalf("%d probes in 4 s; want 1", n)
	}
	now = now.Add(2 * time.Second) // 6 s old
	s.Get()
	if n := d.probes.Load(); n != 2 {
		t.Fatalf("%d probes after 6 s; want 2", n)
	}
	s.MarkStale()
	s.Get()
	if n := d.probes.Load(); n != 3 {
		t.Fatalf("%d probes after MarkStale; want 3", n)
	}
}

// REQ-OBS-002-AC3: a disk that recovers reads 1 again after the sample expires.
func TestRecoversAfterFix(t *testing.T) {
	d := &fakeDisk{avail: 1, syncErr: syscall.ENOSPC}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now)
	s.Start()
	if s.Get().Writable {
		t.Fatal("writable while the disk is full")
	}
	d.syncErr = nil
	now = now.Add(6 * time.Second)
	if !s.Get().Writable {
		t.Fatal("still not writable after the disk recovered and the sample expired (sticky)")
	}
}

// REQ-OBS-002-AC5: one probe at a time; a scrape during a probe gets the
// previous sample and does not wait for the disk beyond the small budget.
func TestOnlyOneProbeInFlightAndScrapeDoesNotWait(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now, func(o *Options) { o.WaitBudget = 20 * time.Millisecond; o.ProbeLimit = 5 * time.Second })
	s.Start() // healthy first sample
	d.mu.Lock()
	d.block = make(chan struct{})
	d.mu.Unlock()
	now = now.Add(6 * time.Second)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Get() }()
	}
	wg.Wait()
	if el := time.Since(start); el > time.Second {
		t.Fatalf("8 concurrent scrapes took %v while the probe was blocked", el)
	}
	if n := d.probes.Load(); n != 2 { // the startup probe and exactly one more
		t.Fatalf("%d probes started; want exactly 2 (one in flight at a time)", n)
	}
	if !s.Get().Writable {
		t.Fatal("a scrape during a blocked probe must return the previous sample (writable)")
	}
	close(d.block)
}

// REQ-OBS-002-AC5: a probe that runs longer than the limit yields writable 0,
// and the stuck probe is not joined by a second one.
func TestProbeOverLimitReadsZeroAndIsNotDuplicated(t *testing.T) {
	d := &fakeDisk{avail: 1, block: make(chan struct{})}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now, func(o *Options) { o.ProbeLimit = 30 * time.Millisecond; o.WaitBudget = 500 * time.Millisecond })
	s.Start()
	if s.Get().Writable {
		t.Fatal("a probe over the limit must read not writable")
	}
	now = now.Add(6 * time.Second)
	s.Get()
	if n := d.probes.Load(); n != 1 {
		t.Fatalf("%d probes; want 1 (the stuck one still holds the single slot)", n)
	}
	close(d.block)
}

// REQ-OBS-002-AC3: a change of state is logged once, not on every sample.
func TestStateChangeIsLoggedOnce(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, buf := newSampler(t, d, &now)
	s.Start()
	d.syncErr = syscall.ENOSPC
	for i := 0; i < 3; i++ {
		now = now.Add(6 * time.Second)
		s.Get()
	}
	if n := strings.Count(buf.String(), "store_writable"); n != 1 {
		t.Fatalf("%d log lines for the healthy->failing change; want 1:\n%s", n, buf.String())
	}
	d.syncErr = nil
	now = now.Add(6 * time.Second)
	s.Get()
	if n := strings.Count(buf.String(), "store_writable"); n != 2 {
		t.Fatalf("%d log lines after recovery; want 2:\n%s", n, buf.String())
	}
}

// The real probe: leaves nothing behind on success, fails on a read-only directory.
func TestRealProbeLeavesNoFileAndFailsOnReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, Deps{}, Options{})
	s.Start()
	got := s.Get()
	if !got.Writable || got.FreeBytes == 0 {
		t.Fatalf("real disk sample = %+v; want writable with free bytes", got)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("probe left %d entries in the data directory", len(ents))
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	s2 := New(dir, Deps{}, Options{})
	s2.Start()
	if s2.Get().Writable {
		t.Fatal("a read-only directory must read not writable")
	}
	_ = context.Background
}

// A probe that returns at about the limit must never leave the single slot held
// (found in review of PR 258: busy was written by two goroutines).
func TestNoWedgeWhenProbeReturnsAtTheLimit(t *testing.T) {
	var n atomic.Int64
	for i := 0; i < 300; i++ {
		d := &fakeDisk{avail: 1}
		now := time.Unix(1000, 0)
		deps := d.deps(&now)
		deps.OpenProbe = func(path string) (ProbeFile, error) {
			time.Sleep(time.Duration(1500+n.Add(1)%1000) * time.Microsecond) // about the 2 ms limit, with jitter
			return fakeFile{d}, nil
		}
		s := New("/data/blobs", deps, Options{ProbeLimit: 2 * time.Millisecond, WaitBudget: 50 * time.Millisecond, Fresh: time.Millisecond, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
		s.Get()
		time.Sleep(15 * time.Millisecond)
		s.mu.Lock()
		busy := s.busy
		s.mu.Unlock()
		if busy {
			t.Fatalf("iteration %d: busy stayed true after the probe returned (the sampler would never measure again)", i)
		}
	}
}

// A probe that finishes AFTER the limit never reads writable: the late answer keeps the gauge at 0 (REQ-OBS-002-AC5) and only refreshes the free bytes.
func TestLateProbeResultKeepsNotWritable(t *testing.T) {
	d := &fakeDisk{avail: 1, block: make(chan struct{})}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now, func(o *Options) { o.ProbeLimit = 20 * time.Millisecond; o.WaitBudget = 500 * time.Millisecond })
	s.Start()
	if s.Get().Writable {
		t.Fatal("over the limit must read not writable")
	}
	d.mu.Lock()
	d.avail = 99
	d.mu.Unlock()
	now = now.Add(4 * time.Second) // the late answer arrives 4 s after the limit's sample
	close(d.block)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		smp := s.Get()
		if smp.FreeBytes == 99 { // the late answer has arrived
			if smp.Writable {
				t.Fatal("the late, successful probe flipped the gauge back to writable")
			}
			// the late answer is a fresh sample: 2 s later it is still inside the 5 s life, so no new probe starts
			before := d.probes.Load()
			now = now.Add(2 * time.Second)
			s.Get()
			time.Sleep(20 * time.Millisecond)
			if d.probes.Load() != before {
				t.Fatal("the late answer kept an old timestamp: a new probe started although it was published 2 s ago")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the late answer never refreshed the free bytes")
}

// A volume whose probe ALWAYS takes longer than the limit reads 0 across many sample periods (it never flaps to 1).
func TestProbeAlwaysOverLimitStaysZero(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	deps := d.deps(&now)
	deps.OpenProbe = func(string) (ProbeFile, error) { time.Sleep(30 * time.Millisecond); return fakeFile{d}, nil }
	s := New("/data/blobs", deps, Options{ProbeLimit: 10 * time.Millisecond, WaitBudget: 100 * time.Millisecond, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	s.Start()
	for i := 0; i < 8; i++ {
		now = now.Add(6 * time.Second)
		for j := 0; j < 5; j++ {
			if s.Get().Writable {
				t.Fatalf("period %d: a probe that always exceeds the limit read writable", i)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// With a GOOD earlier sample, a probe over the limit turns the gauge to 0 (not merely "no sample yet").
func TestProbeOverLimitAfterAGoodSampleReadsZero(t *testing.T) {
	d := &fakeDisk{avail: 7}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now, func(o *Options) { o.ProbeLimit = 20 * time.Millisecond; o.WaitBudget = 500 * time.Millisecond })
	s.Start()
	if !s.Get().Writable {
		t.Fatal("the first sample must be good")
	}
	d.mu.Lock()
	d.block = make(chan struct{})
	d.mu.Unlock()
	now = now.Add(6 * time.Second)
	got := s.Get()
	if got.Writable {
		t.Fatal("a probe over the limit must turn the gauge to 0")
	}
	if got.FreeBytes != 7 {
		t.Fatalf("the limit's sample must keep the last known free bytes (7), got %d", got.FreeBytes)
	}
	close(d.block)
}

// Leftover probe files in the data directory root are removed at start; other files and directories are not touched.
func TestStartSweepsLeftoverProbeFiles(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".tmp-probe-dead", ".tmp-probe-beef", "keep.txt", ".tmp-other"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, ".tmp-probe-adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	s := New(dir, Deps{}, Options{})
	s.Start()
	for _, gone := range []string{".tmp-probe-dead", ".tmp-probe-beef"} {
		if _, err := os.Stat(filepath.Join(dir, gone)); !os.IsNotExist(err) {
			t.Errorf("%s survived the start sweep", gone)
		}
	}
	for _, kept := range []string{"keep.txt", ".tmp-other", ".tmp-probe-adir"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("%s was removed by the sweep", kept)
		}
	}
}

// A statfs that hangs cannot hang a reader beyond the wait budget, nor start a second measurement.
func TestHungStatfsDoesNotHangReaders(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	deps := d.deps(&now)
	hang := make(chan struct{})
	deps.Statfs = func(string) (uint64, error) { <-hang; return 1, nil }
	s := New("/data/blobs", deps, Options{ProbeLimit: 20 * time.Millisecond, WaitBudget: 20 * time.Millisecond})
	done := make(chan struct{})
	go func() { s.Start(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start hung on a hung statfs")
	}
	now = now.Add(10 * time.Second)
	s.Get()
	if n := d.probes.Load(); n != 1 {
		t.Fatalf("%d probes; want 1 (the hung measurement keeps the slot)", n)
	}
	close(hang)
}

// a close or remove that fails also reads not writable; a statfs on a missing directory is an error
func TestCloseAndRemoveFailuresReadNotWritable(t *testing.T) {
	for name, mod := range map[string]func(*fakeDisk){
		"close":  func(d *fakeDisk) { d.closeErr = syscall.EIO },
		"remove": func(d *fakeDisk) { d.rmErr = syscall.EROFS },
	} {
		d := &fakeDisk{avail: 1}
		mod(d)
		now := time.Unix(1000, 0)
		s, _ := newSampler(t, d, &now)
		s.Start()
		if s.Get().Writable {
			t.Errorf("%s failure: reads writable", name)
		}
	}
}

// The interleaving found in review of #258: the measuring goroutine of refresh 1 has released the slot but not yet closed its channels; a new refresh 2 starts;
// then refresh 1's LIMIT fires. It must touch only refresh 1 (already published): no panic (close of a closed channel), no publish into refresh 2.
// The seam makes the gap deterministic (no luck, no timing assumption beyond "the limit fires while the hook sleeps").
func TestStaleLimitGoroutineCannotTouchTheNextRefresh(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, _ := newSampler(t, d, &now, func(o *Options) { o.ProbeLimit = 20 * time.Millisecond; o.WaitBudget = 500 * time.Millisecond })
	var hooked atomic.Int64
	started := make(chan struct{})
	s.afterFinish = func() {
		if hooked.Add(1) != 1 {
			return // only the first refresh's gap
		}
		s.MarkStale()
		s.refreshIfNeeded() // refresh 2 starts in the gap (the slot is free)
		close(started)
		time.Sleep(80 * time.Millisecond) // refresh 1's limit fires here
	}
	s.Start() // refresh 1
	<-started
	time.Sleep(150 * time.Millisecond) // everything settles
	if !s.Get().Writable {
		t.Fatal("refresh 2's good answer was overwritten by refresh 1's stale limit")
	}
	if n := d.probes.Load(); n != 2 {
		t.Fatalf("%d probes; want exactly 2 (one per refresh)", n)
	}
}

// Review of #258 (round 4, R1): a refresh-1 limit that fires WHILE refresh 2 is still running must not publish into refresh 2. Refresh 1's probe takes 30 ms with
// a 40 ms limit, so its limit fires inside the hook; refresh 2 (started in the hook) has its probe blocked and released 20 ms later, inside refresh 2's own limit.
// A limit that used the CURRENT refresh instead of its own would publish "not writable" into refresh 2 and the sample would not read writable.
func TestStaleLimitFiringDuringTheNextRefreshDoesNotPublishIntoIt(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	deps := d.deps(&now)
	release := make(chan struct{})
	var calls atomic.Int64
	deps.OpenProbe = func(string) (ProbeFile, error) {
		d.probes.Add(1)
		if calls.Add(1) == 1 {
			time.Sleep(150 * time.Millisecond) // refresh 1: slow, but inside its limit (400 ms)
		} else {
			<-release // refresh 2: blocked until the test releases it
		}
		return fakeFile{d}, nil
	}
	s := New("/data/blobs", deps, Options{ProbeLimit: 400 * time.Millisecond, WaitBudget: 5 * time.Millisecond, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	var hooked atomic.Int64
	s.afterFinish = func() {
		if hooked.Add(1) != 1 {
			return
		}
		s.MarkStale()
		s.refreshIfNeeded()                // refresh 2 starts in the gap, its probe blocked
		time.Sleep(300 * time.Millisecond) // refresh 1's limit fires at 400 ms; refresh 2 (started at 150 ms) is released at about 450 ms, inside its own limit (550 ms)
		close(release)                     // refresh 2's probe ends inside its own limit
		time.Sleep(200 * time.Millisecond)
	}
	s.Start()
	time.Sleep(900 * time.Millisecond)
	if !s.Get().Writable {
		t.Fatal("refresh 1's stale limit published into refresh 2: the sample reads not writable although refresh 2 finished inside its own limit")
	}
	if n := d.probes.Load(); n != 2 {
		t.Fatalf("%d probes; want 2", n)
	}
}

// Review of #258 (round 4, R3): a state-change line that is overtaken by a later transition's line is not written, so the last line never contradicts the gauge.
func TestOvertakenStateChangeLineIsNotWritten(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	s, buf := newSampler(t, d, &now)
	s.Start() // first sample: writable, no line (a healthy start is silent)
	s.logMu.Lock()
	s.logged = 1 << 40 // a later transition has already been logged
	s.logMu.Unlock()
	rf := &refresh{done: make(chan struct{})}
	s.finish(rf, result{probeErr: syscall.ENOSPC}, false) // a change to not writable, numbered earlier than the line already written
	if buf.Len() != 0 {
		t.Fatalf("an overtaken transition wrote a line: %q", buf.String())
	}
	if s.Get().Writable {
		t.Fatal("the sample still reads writable after the failed probe")
	}
}

// Review of #258 (Codex): an open that fails because the probe name is already taken must not delete that existing file; any other open failure still cleans up.
func TestFailedOpenRemovesNothingButALaterFailureCleansUp(t *testing.T) {
	now := time.Unix(1000, 0)
	// a failed open (the name taken, or any other error) never removes the path: the file there is not ours
	for name, openErr := range map[string]error{"exists": &fs.PathError{Op: "open", Path: "p", Err: syscall.EEXIST}, "io": syscall.EIO} {
		d := &fakeDisk{avail: 1}
		deps := d.deps(&now)
		deps.OpenProbe = func(string) (ProbeFile, error) { d.rec("open"); return nil, openErr }
		s := New("/data/blobs", deps, Options{Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), WaitBudget: 200 * time.Millisecond})
		s.Start()
		if strings.Contains(d.opList(), "remove") {
			t.Fatalf("%s: a failed open removed the path: ops=%s", name, d.opList())
		}
		if s.Get().Writable {
			t.Fatalf("%s: a probe that could not create its file reads writable", name)
		}
	}
	// the file this call created IS removed when a later step fails
	for name, mod := range map[string]func(*fakeDisk){"write": func(d *fakeDisk) { d.writeErr = syscall.EIO }, "sync": func(d *fakeDisk) { d.syncErr = syscall.EIO }} {
		d := &fakeDisk{avail: 1}
		mod(d)
		s, _ := newSampler(t, d, &now)
		s.Start()
		if !strings.Contains(d.opList(), "remove") {
			t.Fatalf("%s failure after a successful open did not clean up: ops=%s", name, d.opList())
		}
	}
}

// Many readers, failing PUTs marking the sample stale, and a limit that fires right at the probe's end: nothing may panic, and the slot is always released.
func TestStressGetMarkStaleAtTheLimit(t *testing.T) {
	d := &fakeDisk{avail: 1}
	now := time.Unix(1000, 0)
	deps := d.deps(&now)
	deps.OpenProbe = func(string) (ProbeFile, error) { time.Sleep(60 * time.Microsecond); return fakeFile{d}, nil }
	s := New("/data/blobs", deps, Options{ProbeLimit: 60 * time.Microsecond, WaitBudget: time.Millisecond, Fresh: time.Nanosecond, Log: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				s.Get()
				s.MarkStale()
			}
		}()
	}
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
	s.mu.Lock()
	busy := s.busy
	s.mu.Unlock()
	if busy {
		t.Fatal("the slot was never released")
	}
}
