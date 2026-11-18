package watch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

func TestCursorStore(t *testing.T) {
	dir, err := securefile.OpenDir(filepath.Join(t.TempDir(), "s"), true, securefile.DefaultOwnerOf)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	c := NewCursorStore(dir)
	if got, err := c.Load(); got != "" || err != nil {
		t.Fatalf("missing file: %q, %v", got, err)
	}
	if err := c.Save(cur("1")); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Load(); got != cur("1") || err != nil {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	if err := c.Save(""); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Load(); got != "" || err != nil {
		t.Fatalf("cleared: %q, %v", got, err)
	}
	for _, bad := range []string{"a b", "a\nb", "a\x00b", "é", "a\x7fb", strings.Repeat("x", MaxCursorBytes)} {
		if err := c.Save(bad); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("Save(%q) = %v, want ErrInvalidCursor", bad, err)
		}
	}
	for _, content := range []string{"a b\n", "two\nlines\n", "x\x00y", strings.Repeat("x", MaxCursorBytes+1)} {
		if err := dir.WriteAtomic(CursorFile, []byte(content), 4096); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Load(); !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("Load of %q = %v, want ErrInvalidCursor", content[:min(len(content), 10)], err)
		}
	}
}

// An unusable cursor file is a lost cursor: audited, cleared, start at now.
func TestInvalidCursorFileIsResetAtStart(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		if err := h.dir.WriteAtomic(CursorFile, []byte("two words\n"), 4096); err != nil {
			t.Fatal(err)
		}
	}})
	h.script("", fake.Script{Follow: true})
	if err := h.runUntil("start", func() bool { return len(h.fs.Calls()) == 1 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.CursorReset) != 1 || h.savedCursor() != "" {
		t.Fatalf("kinds=%v cursor=%q", h.kinds(), h.savedCursor())
	}
}

// A cursor file that fails the trust checks is not a lost cursor: the daemon
// stops.
func TestUntrustedCursorFileIsFatal(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		target := filepath.Join(h.path, "elsewhere")
		if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(h.path, CursorFile)); err != nil {
			t.Fatal(err)
		}
	}})
	err := h.start().wait(t)
	if err == nil || errors.Is(err, ErrInvalidCursor) || len(h.fs.Calls()) != 0 {
		t.Fatalf("Run = %v, calls = %d", err, len(h.fs.Calls()))
	}
	if h.count(audit.DaemonError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

// Saving is due for a line with a signal at once, for other lines once per
// interval.
func TestCursorSaveThrottle(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{CursorInterval: 10 * time.Second}})
	feed := func(l string, wantSaved string) {
		t.Helper()
		if err := h.d.onLine([]byte(l)); err != nil {
			t.Fatal(err)
		}
		if got := h.savedCursor(); got != wantSaved {
			t.Fatalf("saved = %q, want %q", got, wantSaved)
		}
	}
	feed(plainLine(cur("1"), t0), cur("1"))                     // first save is due (nothing saved yet)
	feed(plainLine(cur("2"), t0), cur("1"))                     // inside the interval
	feed(sshLine(cur("3"), t0, "203.0.113.9"), cur("3"))        // a signal saves at once
	feed(plainLine(cur("4"), t0), cur("3"))                     // inside the interval again
	h.clk.add(11 * time.Second)                                 //
	feed(plainLine(cur("5"), t0.Add(11*time.Second)), cur("5")) // interval over
	if h.d.cur != cur("5") {
		t.Fatalf("cur = %q", h.d.cur)
	}
}

func TestOverlongLinesAreCounted(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Err: errors.New("x"), Lines: []string{plainLine(cur("1"), t0), strings.Repeat("a", execx.DefaultMaxLine+1), strings.Repeat("b", execx.DefaultMaxLine+1)}})
	h.script(cur("1"), fake.Script{Follow: true})
	if err := h.runUntil("restart", func() bool { return len(h.fs.Calls()) == 2 }); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range h.records() {
		if r.Kind == audit.JournalLineInvalid && strings.Contains(r.Summary, "over the size limit") {
			found = true
		}
	}
	if !found {
		t.Fatalf("records = %+v", h.records())
	}
}

func TestNewChecksDeps(t *testing.T) {
	h := newHarness(t, hopts{})
	good := h.d.deps
	for name, mut := range map[string]func(*Deps){
		"streamer":  func(d *Deps) { d.Streamer = nil },
		"clean":     func(d *Deps) { d.Clean = nil },
		"engine":    func(d *Deps) { d.Engine = nil },
		"incidents": func(d *Deps) { d.Incidents = nil },
		"audit":     func(d *Deps) { d.Audit = nil },
		"cursor":    func(d *Deps) { d.Cursor = nil },
	} {
		d := good
		mut(&d)
		if _, err := New(d, Options{}); err == nil {
			t.Errorf("New without %s succeeded", name)
		}
	}
	d := good
	d.Clock = nil
	if dm, err := New(d, Options{}); err != nil || dm.deps.Clock == nil {
		t.Errorf("a nil clock selects time.Now: %v", err)
	}
}

func TestRunTwiceFails(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	if err := h.d.Run(t.Context()); err == nil {
		t.Fatal("second Run succeeded")
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}

func TestOptionDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.Program != "journalctl" || o.BackoffMin != DefaultBackoffMin || o.BackoffMax != DefaultBackoffMax ||
		o.MaxRestarts != DefaultMaxRestarts || o.NoiseInterval != DefaultNoiseInterval || o.ClockSkew != DefaultClockSkew ||
		o.CursorInterval != DefaultCursorInterval || o.PerIncidentInterval != time.Hour || o.Sleep == nil {
		t.Fatalf("defaults = %+v", o)
	}
	if got := (Options{BackoffMin: time.Hour, BackoffMax: time.Second}).withDefaults(); got.BackoffMax != time.Hour {
		t.Fatalf("BackoffMax below BackoffMin = %v", got.BackoffMax)
	}
	if got := (Options{CursorInterval: -1}).withDefaults(); got.CursorInterval != -1 {
		t.Fatalf("negative CursorInterval = %v", got.CursorInterval)
	}
}

func TestNegativeIntervalSavesEveryLineAlsoWhenTheClockStepsBack(t *testing.T) {
	h := newHarness(t, hopts{})
	if err := h.d.onLine([]byte(plainLine(cur("1"), t0))); err != nil {
		t.Fatal(err)
	}
	h.clk.add(-time.Hour)
	if err := h.d.onLine([]byte(plainLine(cur("2"), t0))); err != nil {
		t.Fatal(err)
	}
	if got := h.savedCursor(); got != cur("2") {
		t.Fatalf("saved = %q, want every line saved", got)
	}
}

func TestHousekeepingSavesThePendingCursor(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{CursorInterval: time.Hour}})
	for _, i := range []string{"1", "2"} {
		if err := h.d.onLine([]byte(plainLine(cur(i), t0))); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.savedCursor(); got != cur("1") {
		t.Fatalf("saved = %q, want only the first", got)
	}
	housekeepOnce(t, h)
	if got := h.savedCursor(); got != cur("2") {
		t.Fatalf("saved after the pass = %q", got)
	}
}

// A run that lasted StableAfter made progress even if it delivered no line.
func TestStableRunResetsRestartBudget(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
	var calls atomic.Int32
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, _ func([]byte) error) (execx.StreamResult, error) {
		if calls.Add(1) <= 3 {
			return execx.StreamResult{ExitCode: 1, Duration: DefaultStableAfter}, nil
		}
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	waitFor(t, "fourth run", func() bool { return calls.Load() >= 4 })
	if err := r.stop(t); err != nil {
		t.Fatalf("Run = %v", err)
	}
}

// The cursor of lines handled but not yet saved reaches the disk when the
// stream ends, before the restart.
func TestStreamEndSavesCursorBeforeRestart(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{CursorInterval: time.Hour}})
	var onDisk string
	var calls atomic.Int32
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		if calls.Add(1) == 1 {
			for _, i := range []string{"1", "2"} {
				if err := on([]byte(plainLine(cur(i), t0))); err != nil {
					return execx.StreamResult{}, err
				}
			}
			return execx.StreamResult{ExitCode: 1}, nil
		}
		onDisk = h.savedCursor()
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	waitFor(t, "second run", func() bool { return calls.Load() >= 2 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if onDisk != cur("2") {
		t.Fatalf("cursor on disk when the restart began = %q, want %q", onDisk, cur("2"))
	}
}

// Progress is per stream: lines of an earlier run do not keep a later run
// from resetting a refused cursor.
func TestRefusedCursorAfterAnEarlierRunWithLines(t *testing.T) {
	h := newHarness(t, hopts{})
	var mu sync.Mutex
	var argvs [][]string
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, argv []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		mu.Lock()
		argvs = append(argvs, argv)
		n := len(argvs)
		mu.Unlock()
		switch n {
		case 1:
			if err := on([]byte(plainLine(cur("1"), t0))); err != nil {
				return execx.StreamResult{}, err
			}
			return execx.StreamResult{ExitCode: 1}, nil
		case 2:
			return execx.StreamResult{ExitCode: 1, Stderr: []byte("Failed to seek to cursor: gone")}, nil
		}
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	waitFor(t, "third run", func() bool { mu.Lock(); defer mu.Unlock(); return len(argvs) >= 3 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.CursorReset) != 1 || argvs[2][len(argvs[2])-1] != "--lines=0" {
		t.Fatalf("kinds = %v, third argv = %v", h.kinds(), argvs[2])
	}
}

// Shutdown waits for a queued notification (within DrainTimeout) and audits
// its result; one that cannot finish in time is dropped and audited.
func TestShutdownDrainsTheWorkerWithinABound(t *testing.T) {
	t.Run("a send that finishes is delivered", func(t *testing.T) {
		h := newHarness(t, hopts{opt: Options{DrainTimeout: 5 * time.Second}})
		started := make(chan struct{})
		h.d.deps.Worker.Notifier = notifierFunc(func(ctx context.Context, _ notify.Message) error {
			close(started)
			select {
			case <-time.After(150 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
		r := h.start()
		<-started
		began := time.Now()
		if err := r.stop(t); err != nil {
			t.Fatal(err)
		}
		if time.Since(began) > 2*time.Second {
			t.Fatalf("shutdown waited %v for a send that had finished", time.Since(began))
		}
		if h.count(audit.NotifySent) != 1 || h.count(audit.NotifyDropped) != 0 {
			t.Fatalf("kinds = %v", h.kinds())
		}
		if h.store.List()[0].NotifiedAt.IsZero() {
			t.Fatal("the delivered notification is not recorded")
		}
	})
	t.Run("a stuck send is dropped after the bound", func(t *testing.T) {
		h := newHarness(t, hopts{opt: Options{DrainTimeout: 100 * time.Millisecond}})
		started := make(chan struct{})
		h.d.deps.Worker.Notifier = notifierFunc(func(ctx context.Context, _ notify.Message) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		})
		h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
		r := h.start()
		<-started
		began := time.Now()
		if err := r.stop(t); err != nil {
			t.Fatal(err)
		}
		if time.Since(began) > 3*time.Second {
			t.Fatalf("shutdown took %v", time.Since(began))
		}
		if h.count(audit.NotifyDropped) != 1 || h.count(audit.NotifySent) != 0 {
			t.Fatalf("kinds = %v", h.kinds())
		}
		h.verify()
	})
}

type notifierFunc func(context.Context, notify.Message) error

func (f notifierFunc) Send(ctx context.Context, m notify.Message) error { return f(ctx, m) }

// The retry bookkeeping is bounded: expired entries are dropped at the cap.
func TestRetryBookkeepingIsBounded(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < maxTries; i++ {
		h.d.tries[itoa(int64(i))] = tryState{notBefore: t0.Add(-time.Hour)}
	}
	res, err := h.d.deps.Incidents.Apply(event.Signal{Fingerprint: event.FingerprintOf("x", "1"), Severity: result.High, Time: t0, Notify: true}, incident.Display{Title: "t", Summary: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.d.notifyIncident(res.Incident, false); err != nil {
		t.Fatal(err)
	}
	if n := len(h.d.tries); n != 1 {
		t.Fatalf("tries = %d, want the expired entries gone", n)
	}
}

// While a send is in flight, an update does not enqueue a second one, even
// when the retry gap has passed.
func TestNoSecondSendWhileOneIsInFlight(t *testing.T) {
	h := newHarness(t, hopts{})
	release := make(chan struct{})
	h.d.deps.Worker.Notifier = notifierFunc(func(ctx context.Context, _ notify.Message) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	oomKill := "Out of memory: Killed process 77 (worker) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:1kB oom_score_adj:0"
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		if err := on([]byte(kernLine(cur("1"), t0.Add(-11*time.Minute), oomKill))); err != nil {
			return execx.StreamResult{}, err
		}
		h.clk.add(11 * time.Minute) // the gap is over, the first send is still in flight
		if err := on([]byte(kernLine(cur("2"), t0, oomKill))); err != nil {
			return execx.StreamResult{}, err
		}
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	waitFor(t, "second line", func() bool { return h.savedCursor() == cur("2") })
	close(release)
	waitFor(t, "send audited", func() bool { return h.count(audit.NotifySent) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if n := len(h.notif.sent()) + h.count(audit.NotifyDropped); n != 0 {
		t.Fatalf("a second send was attempted while the first was in flight (%d)", n)
	}
}
