package watch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// Pending daemon notices that keep failing do not use up the limit of the
// incident notifications. During a notifier outage and after it, with
// notices that never get through, every incident is sent once the notifier
// is back, and none is marked notified without a message.
func TestFailingNoticesLeaveTheIncidentLimit(t *testing.T) {
	for _, g := range []int{1, 2, 6} {
		for notices := 1; notices <= 4; notices++ {
			t.Run(fmt.Sprintf("G=%d notices=%d", g, notices), func(t *testing.T) {
				failingNotices(t, g, notices)
			})
		}
	}
}

func failingNotices(t *testing.T, g, notices int) {
	// Retries are paced at 10m, so the last incident is due 14m30s after the
	// start; 24 passes after the outage reach 17m.
	const incidents, outage, passes = 5, 5 * time.Minute, 24
	opt := Options{GlobalPerMinute: g, PerIncidentInterval: 40 * time.Minute}
	h := newHarness(t, hopts{params: opt.AlertParams(16, 0), opt: opt})
	var mu sync.Mutex
	down := true
	h.worker.Notifier = notifierFunc(func(_ context.Context, m notify.Message) error {
		mu.Lock()
		defer mu.Unlock()
		if down || strings.HasPrefix(m.Title, "notice") {
			return errTransient
		}
		return nil
	})
	idle := func() {
		waitFor(t, "idle", func() bool {
			h.d.mu.Lock()
			defer h.d.mu.Unlock()
			return h.d.inflightTotal == 0 && len(h.d.results) == 0
		})
	}
	pass := func() {
		idle()
		h.clk.add(30 * time.Second)
		housekeepOnce(t, h)
		idle()
	}
	items := []any{func() {
		h.d.mu.Lock()
		for i := 0; i < notices; i++ {
			h.d.alertEvent(fmt.Sprintf("k%d", i), fmt.Sprintf("notice %d", i), "body")
		}
		h.d.mu.Unlock()
		idle()
	}}
	// The outage: one new incident per minute, a pass every 30 s.
	for k := 1; k <= incidents; k++ {
		items = append(items, sshLine(cur(itoa(int64(k))), t0, ipN("203.0.113", k)), pass, pass)
	}
	// The notifier is back for incidents; the notices keep failing.
	items = append(items, func() {
		mu.Lock()
		down = false
		mu.Unlock()
		for i := 0; i < passes; i++ {
			pass()
		}
	})
	h.steps(items...)
	r := h.start()
	waitForWithin(t, time.Minute, "the end", func() bool { return h.clk.now().Equal(t0.Add(outage + passes*30*time.Second)) })
	idle()
	h.d.mu.Lock()
	kept, pending := len(h.d.attempts), len(h.d.notices)
	h.d.mu.Unlock()
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	sent := map[string]bool{}
	for _, rec := range h.records() {
		if rec.Kind == audit.NotifySent && rec.IncidentID != "" {
			sent[rec.IncidentID] = true
		}
	}
	list := h.store.List()
	if len(list) != incidents {
		t.Fatalf("incidents = %d, want %d", len(list), incidents)
	}
	for _, in := range list {
		switch {
		case sent[in.ID]:
		case !in.NotifiedAt.IsZero():
			t.Errorf("incident %s was marked notified without a message", in.Title)
		default:
			t.Errorf("incident %s was not sent after the notifier came back", in.Title)
		}
	}
	// The notices were attempted to the end and are not in the count.
	if pending != notices {
		t.Fatalf("pending notices = %d, want %d: the notices did not keep failing", pending, notices)
	}
	if kept > g {
		t.Fatalf("counted attempts = %d, want at most GlobalPerMinute = %d", kept, g)
	}
}

// The attempt count does not grow while only notices are attempted.
func TestNoticeAttemptsAreNotCounted(t *testing.T) {
	h := newHarness(t, hopts{})
	h.notif.fail = func(int) error { return errTransient }
	h.steps(func() {
		h.d.mu.Lock()
		h.d.alertEvent("k", "notice", "body")
		h.d.mu.Unlock()
		for i := 0; i < 10; i++ {
			waitFor(t, "idle", func() bool { h.d.mu.Lock(); defer h.d.mu.Unlock(); return h.d.inflightTotal == 0 })
			housekeepOnce(t, h)
		}
	})
	if err := h.runUntil("attempts", func() bool { return len(h.notif.sent()) == 11 }); err != nil {
		t.Fatal(err)
	}
	if n := len(h.d.attempts); n != 0 {
		t.Fatalf("counted attempts = %d after 11 notice attempts, want 0", n)
	}
}

// stopAtLimit builds a daemon whose audit log is full at the third incident,
// after two incident notifications were sent in the same minute with
// GlobalPerMinute = 2. params builds the worker's parameters.
func stopAtLimit(t *testing.T, opt Options, params alert.Params) *harness {
	t.Helper()
	mk := func(max int64) *harness {
		h := newHarness(t, hopts{auditMax: max, params: params, opt: opt})
		h.steps(sshLine(cur("1"), t0, "203.0.113.1"), sshLine(cur("2"), t0, "203.0.113.2"), func() {
			waitFor(t, "two sent", func() bool { return h.count(audit.NotifySent) == 2 })
		}, sshLine(cur("3"), t0, "203.0.113.3"))
		return h
	}
	probe := mk(0)
	if err := probe.runUntil("lines", func() bool { return probe.savedCursor() == cur("3") }); err != nil {
		t.Fatal(err)
	}
	// The start record, two opens and two results come before the third line.
	var upto int64
	for _, sz := range lineSizes(probe)[:5] {
		upto += sz
	}
	return mk(audit.ReserveBytes + upto + 10)
}

// drops collects the reasons of the jobs the worker dropped.
type drops struct {
	mu      sync.Mutex
	reasons []alert.DropReason
}

func (d *drops) watch(h *harness) {
	inner := h.worker.OnResult
	h.worker.OnResult = func(r alert.Result) {
		if r.Status == alert.Dropped {
			d.mu.Lock()
			d.reasons = append(d.reasons, r.Reason)
			d.mu.Unlock()
		}
		inner(r)
	}
}

func (d *drops) count(reason alert.DropReason) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, r := range d.reasons {
		if r == reason {
			n++
		}
	}
	return n
}

// A stop because the audit log is full, in a minute in which incident
// notifications used up GlobalPerMinute.
func TestStopNoticeWhenIncidentsUsedTheGlobalLimit(t *testing.T) {
	const g = 2
	opt := Options{GlobalPerMinute: g, PerIncidentInterval: 40 * time.Minute, DrainTimeout: 3 * time.Second}
	bare := alert.Params{QueueSize: 16, PerIncidentInterval: 40 * time.Minute, GlobalPerMinute: g}
	pendingStop := func(h *harness) func() bool {
		return func() bool { h.d.mu.Lock(); defer h.d.mu.Unlock(); return len(h.d.notices) == 1 }
	}

	// With the worker parameters of AlertParams the notice has room in the
	// worker's limit. It is accepted at once and not handed on a second time
	// while its send runs.
	t.Run("the worker's limit has room for the notice", func(t *testing.T) {
		h := stopAtLimit(t, opt, opt.AlertParams(16, 0))
		var d drops
		d.watch(h)
		h.worker.Notifier = notifierFunc(func(ctx context.Context, m notify.Message) error {
			if strings.Contains(m.Title, "audit log is full") {
				// A send that takes a while and ends with the worker.
				select {
				case <-time.After(50 * time.Millisecond):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return h.notif.Send(ctx, m)
		})
		if err := h.start().wait(t); !errors.Is(err, ErrAuditFull) {
			t.Fatalf("Run = %v, kinds = %v", err, h.kinds())
		}
		if n := h.countTitle("audit log is full"); n != 1 {
			t.Fatalf("stop notices = %d (titles %v)", n, h.titles())
		}
		if len(d.reasons) != 0 {
			t.Fatalf("drops = %v, want none: the accepted notice was handed on again", d.reasons)
		}
	})

	// A worker whose limit is used up drops the notice. It is handed on again
	// and goes out as soon as the limit has room.
	t.Run("handed on again when the worker dropped it", func(t *testing.T) {
		h := stopAtLimit(t, opt, bare)
		r := h.start()
		waitFor(t, "the stop notice is pending", pendingStop(h))
		if n := h.countTitle("audit log is full"); n != 0 {
			t.Fatalf("the worker's limit did not drop the notice (titles %v)", h.titles())
		}
		h.clk.add(time.Minute)
		if err := r.wait(t); !errors.Is(err, ErrAuditFull) {
			t.Fatalf("Run = %v", err)
		}
		if n := h.countTitle("audit log is full"); n != 1 {
			t.Fatalf("stop notices = %d (titles %v)", n, h.titles())
		}
	})

	// A notice the worker never accepts ends the wait at DrainTimeout.
	t.Run("gives up after DrainTimeout", func(t *testing.T) {
		short := opt
		short.DrainTimeout = 300 * time.Millisecond
		h := stopAtLimit(t, short, bare)
		var d drops
		d.watch(h)
		began := time.Now()
		if err := h.start().wait(t); !errors.Is(err, ErrAuditFull) {
			t.Fatalf("Run = %v", err)
		}
		if took := time.Since(began); took < short.DrainTimeout {
			t.Fatalf("Run returned after %s, before DrainTimeout", took)
		}
		if n := d.count(alert.DropGlobal); n < 2 {
			t.Fatalf("the notice was handed on %d times, want more than once", n)
		}
		if n := h.countTitle("audit log is full"); n != 0 {
			t.Fatalf("stop notices = %d", n)
		}
		if k := h.kinds(); k[len(k)-1] != audit.DaemonError {
			t.Fatalf("kinds = %v", k)
		}
	})
}

// A stop because the audit log is full while the worker's queue is full: the
// notice is handed on again until the queue has room.
func TestStopNoticeWhenTheQueueIsFull(t *testing.T) {
	opt := Options{PerIncidentInterval: 40 * time.Minute, GlobalPerMinute: 6, DrainTimeout: 5 * time.Second}
	lines := []any{sshLine(cur("1"), t0, "203.0.113.1"), sshLine(cur("2"), t0, "203.0.113.2"), sshLine(cur("3"), t0, "203.0.113.3")}
	probe := newHarness(t, hopts{noWorker: true, opt: opt})
	probe.steps(lines...)
	if err := probe.runUntil("lines", func() bool { return probe.savedCursor() == cur("3") }); err != nil {
		t.Fatal(err)
	}
	sz := lineSizes(probe)
	// Full at the open record of the third incident.
	h := newHarness(t, hopts{auditMax: audit.ReserveBytes + sz[0] + sz[1] + sz[2] + 10, params: opt.AlertParams(1, 0), opt: opt})
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.worker.Notifier = notifierFunc(func(ctx context.Context, m notify.Message) error {
		once.Do(func() { close(entered); <-release })
		return h.notif.Send(ctx, m)
	})
	var d drops
	d.watch(h)
	// The first notification is being sent and the second fills the queue.
	h.steps(lines[0], func() { <-entered }, lines[1], lines[2])
	r := h.start()
	waitFor(t, "the notice was dropped", func() bool { return d.count(alert.DropQueueFull) >= 1 })
	close(release)
	if err := r.wait(t); !errors.Is(err, ErrAuditFull) {
		t.Fatalf("Run = %v, kinds = %v", err, h.kinds())
	}
	ts := h.titles()
	if len(ts) != 3 || !strings.Contains(ts[2], "audit log is full") {
		t.Fatalf("titles = %v, want two incidents and then the stop notice", ts)
	}
}

// A clean stop in which the record of a result fills the audit log while the
// daemon waits for the queue: the stop is one because the log is full, and
// its notice goes out.
func TestStopNoticeWhenAResultFillsTheLogDuringTheDrain(t *testing.T) {
	line := sshLine(cur("1"), t0, "203.0.113.9")
	probe := newHarness(t, hopts{noWorker: true})
	probe.steps(line)
	if err := probe.runUntil("line", func() bool { return probe.savedCursor() == cur("1") }); err != nil {
		t.Fatal(err)
	}
	sz := lineSizes(probe)
	// The start and the open record fit; the record of the result does not.
	h := newHarness(t, hopts{auditMax: audit.ReserveBytes + sz[0] + sz[1] + 10})
	entered, release, ended := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.worker.Notifier = notifierFunc(func(ctx context.Context, m notify.Message) error {
		once.Do(func() { close(entered); <-release })
		return h.notif.Send(ctx, m)
	})
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		if err := on([]byte(line)); err != nil {
			return execx.StreamResult{}, err
		}
		<-ctx.Done()
		close(ended)
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	<-entered
	r.cancel()
	<-ended
	// The stream has ended without an error; give Run the time to reach the
	// wait for the queue before the send returns.
	time.Sleep(100 * time.Millisecond)
	close(release)
	if err := r.wait(t); !errors.Is(err, ErrAuditFull) {
		t.Fatalf("Run = %v, kinds = %v", err, h.kinds())
	}
	if n := h.countTitle("audit log is full"); n != 1 {
		t.Fatalf("stop notices = %d (titles %v)", n, h.titles())
	}
	if k := h.kinds(); k[len(k)-1] != audit.DaemonError || h.count(audit.NotifySent) != 0 {
		t.Fatalf("kinds = %v", k)
	}
	if in := h.store.List(); len(in) != 1 || in[0].State != incident.StateOpen {
		t.Fatalf("store = %+v", in)
	}
}
