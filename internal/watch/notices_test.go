package watch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

func (h *harness) titles() []string {
	var out []string
	for _, m := range h.notif.sent() {
		out = append(out, m.Title)
	}
	return out
}

func (h *harness) countTitle(sub string) int {
	n := 0
	for _, t := range h.titles() {
		if strings.Contains(t, sub) {
			n++
		}
	}
	return n
}

// fillAudit writes records into the audit log of h until its size is at least
// target; the writer is closed again so the daemon opens it as after a stop.
func fillAudit(t *testing.T, h *harness, max, target int64) {
	t.Helper()
	aw, _, err := audit.Open(h.dir, audit.Options{MaxSize: max, Now: h.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	defer aw.Close()
	big := strings.Repeat("a", 2000)
	for aw.Size()+2400 < target {
		if _, err := aw.Append(audit.Record{Time: h.clk.now(), Kind: audit.InputError, Summary: big}); err != nil {
			t.Fatal(err)
		}
	}
	for aw.Size() < target {
		if _, err := aw.Append(audit.Record{Time: h.clk.now(), Kind: audit.InputError}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFillNoticeAtEightyPercentOncePerProcess(t *testing.T) {
	const max = 200_000
	h := newHarness(t, hopts{auditMax: max, setup: func(h *harness) { fillAudit(t, h, max, 158_000) }})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return h.count(audit.DaemonStart) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n := h.countTitle("80% full"); n != 0 {
		t.Fatalf("notice sent below 80 percent (%d)", n)
	}
	r.cancel()
	_ = r.wait(t)
	// A second process that writes more records crosses the line and sends once.
	h2 := newHarness(t, hopts{auditMax: max, setup: func(h *harness) { fillAudit(t, h, max, 158_000) }})
	h2.steps(append(floodLines("198.51.100", 1, 8), func() { h2.clk.add(2 * time.Minute) }, sshLine(cur("20"), t0, "203.0.113.50"))...)
	if err := h2.runUntil("notice", func() bool { return h2.countTitle("80% full") >= 1 && h2.savedCursor() == cur("20") }); err != nil {
		t.Fatal(err)
	}
	if n := h2.countTitle("80% full"); n != 1 {
		t.Fatalf("fill notices = %d, want 1 per process", n)
	}
	// A second notice would run into the worker's per-incident limit and show
	// up as a dropped notification.
	if n := h2.count(audit.NotifyDropped); n != 0 {
		t.Fatalf("notify_dropped records = %d: the fill notice was raised more than once", n)
	}
	for _, m := range h2.notif.sent() {
		if strings.Contains(m.Title, "80% full") && m.Priority != 4 {
			t.Errorf("priority = %d, want high", m.Priority)
		}
	}
}

func TestStopNoticeWhenTheAuditLogIsFull(t *testing.T) {
	t.Run("while running", func(t *testing.T) {
		h := newHarness(t, hopts{auditMax: audit.ReserveBytes + 600})
		h.script("", fake.Script{Follow: true, Lines: []string{
			sshLine(cur("1"), t0, "203.0.113.9"), sshLine(cur("2"), t0, "203.0.113.10"),
		}})
		err := h.start().wait(t)
		if !errors.Is(err, ErrAuditFull) {
			t.Fatalf("Run = %v", err)
		}
		if n := h.countTitle("audit log is full"); n != 1 {
			t.Fatalf("stop notices = %d (titles %v)", n, h.titles())
		}
		k := h.kinds()
		if k[len(k)-1] != audit.DaemonError {
			t.Fatalf("kinds = %v", k)
		}
	})
	t.Run("at start", func(t *testing.T) {
		max := int64(audit.ReserveBytes + 600)
		h := newHarness(t, hopts{auditMax: max, setup: func(h *harness) {
			aw, _, err := audit.Open(h.dir, audit.Options{MaxSize: max, Now: h.clk.now})
			if err != nil {
				t.Fatal(err)
			}
			defer aw.Close()
			for {
				if _, err := aw.Append(audit.Record{Time: h.clk.now(), Kind: audit.InputError, Summary: "x"}); err != nil {
					if !errors.Is(err, audit.ErrFull) {
						t.Fatal(err)
					}
					return
				}
			}
		}})
		err := h.start().wait(t)
		if !errors.Is(err, ErrAuditFull) {
			t.Fatalf("Run = %v", err)
		}
		if n := h.countTitle("audit log is full"); n != 1 {
			t.Fatalf("stop notices = %d", n)
		}
		if h.count(audit.DaemonStart) != 0 || h.count(audit.DaemonError) != 1 {
			t.Fatalf("kinds = %v", h.kinds())
		}
	})
}

func TestDaemonNoticeIsRetriedUntilSent(t *testing.T) {
	h := newHarness(t, hopts{recovery: &audit.Recovery{Offset: 1, Length: 2, Hash: "ab"}})
	h.notif.fail = func(n int) error {
		if n == 1 {
			return errTransient
		}
		return nil
	}
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "failed notice", func() bool { return h.count(audit.NotifyFailed) == 1 })
	step := func(d time.Duration) int {
		h.clk.add(d)
		housekeepOnce(t, h)
		time.Sleep(60 * time.Millisecond)
		return len(h.notif.sent())
	}
	// Every pass sends a notice that is not in flight again, without a gap.
	if n := step(time.Second); n != 2 {
		t.Fatalf("sends = %d after the next pass, want the retry", n)
	}
	waitFor(t, "sent", func() bool { return h.count(audit.NotifySent) == 1 })
	if n := step(time.Hour); n != 2 {
		t.Fatalf("sends = %d: a sent notice is not sent again", n)
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}

// A notice for an event that came again while the first was in flight is
// sent afterwards.
func TestNoticeThatRepeatsInFlightIsSentAgain(t *testing.T) {
	h := newHarness(t, hopts{})
	release := make(chan struct{})
	var mu sync.Mutex
	var seen []string
	h.d.deps.Worker.Notifier = notifierFunc(func(ctx context.Context, m notify.Message) error {
		mu.Lock()
		seen = append(seen, m.Title)
		mu.Unlock()
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	h.d.mu.Lock()
	h.d.alertEvent("k", "first", "body")
	h.d.alertEvent("k", "second", "body")
	h.d.mu.Unlock()
	close(release)
	waitFor(t, "first sent", func() bool { return h.count(audit.NotifySent) == 1 })
	h.clk.add(time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "second sent", func() bool { return h.count(audit.NotifySent) == 2 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "first" || seen[1] != "second" {
		t.Fatalf("titles = %v", seen)
	}
}

// Pending daemon notices are bounded.
func TestPendingNoticesAreBounded(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < maxNotices+5; i++ {
		h.d.alertEvent("k"+itoa(int64(i)), "t", "b")
	}
	if n := len(h.d.notices); n != maxNotices {
		t.Fatalf("pending notices = %d, want %d", n, maxNotices)
	}
}

// A notice in flight is not handed on again, neither when its event comes
// again nor by a housekeeping pass: the worker's per-incident limit would
// drop it and end it unsent.
func TestNoticeInFlightIsNotHandedOnAgain(t *testing.T) {
	h := newHarness(t, hopts{})
	release, called := make(chan struct{}), make(chan struct{}, 4)
	h.d.deps.Worker.Notifier = notifierFunc(func(ctx context.Context, m notify.Message) error {
		called <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	h.d.mu.Lock()
	h.d.alertEvent("k", "first", "body")
	h.d.mu.Unlock()
	<-called
	h.d.mu.Lock()
	h.d.alertEvent("k", "second", "body")
	h.d.mu.Unlock()
	housekeepOnce(t, h)
	time.Sleep(60 * time.Millisecond)
	if n := h.count(audit.NotifyDropped); n != 0 {
		t.Fatalf("notify_dropped records = %d: the notice in flight was handed on again", n)
	}
	h.d.mu.Lock()
	n, ok := h.d.notices[string(event.FingerprintOf("daemon", "k"))]
	h.d.mu.Unlock()
	if !ok || !n.again {
		t.Fatalf("notice = %+v, %v: the repeat must stay pending", n, ok)
	}
	close(release)
	waitFor(t, "first sent", func() bool { return h.count(audit.NotifySent) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}

// Notices go first: while one waits for a slot of the global limit, incident
// notifications are not handed on and stay unnotified; the next pass sends
// the notice, then the incident.
func TestNoticeGoesFirstWhenIncidentsUsedTheGlobalLimit(t *testing.T) {
	h := newHarness(t, hopts{
		params: alert.Params{QueueSize: 16, PerIncidentInterval: 40 * time.Minute, GlobalPerMinute: 2},
		opt:    Options{GlobalPerMinute: 2},
	})
	h.steps(sshLine(cur("1"), t0, "203.0.113.1"), sshLine(cur("2"), t0, "203.0.113.2"), func() {
		waitFor(t, "two sent", func() bool { return h.count(audit.NotifySent) == 2 })
		h.d.mu.Lock()
		h.d.alertEvent("k", "notice", "body")
		h.d.mu.Unlock()
	}, sshLine(cur("3"), t0, "203.0.113.3"))
	r := h.start()
	waitFor(t, "third line", func() bool { return h.savedCursor() == cur("3") })
	time.Sleep(60 * time.Millisecond)
	if n := len(h.notif.sent()); n != 2 {
		t.Fatalf("sends = %d, want the two incidents only", n)
	}
	for _, in := range h.store.List() {
		if strings.Contains(in.Title, "203.0.113.3") && !in.NotifiedAt.IsZero() {
			t.Fatalf("the third incident was marked notified while the notice waited")
		}
	}
	h.clk.add(61 * time.Second)
	housekeepOnce(t, h)
	waitFor(t, "notice and third incident", func() bool { return h.count(audit.NotifySent) == 4 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	ts := h.titles()
	if ts[2] != "notice" || !strings.Contains(ts[3], "203.0.113.3") {
		t.Fatalf("titles = %v, want the notice before the third incident", ts)
	}
}

// The daemon's own count bounds notification attempts per minute also when
// every send fails (the worker gives its slot back then).
func TestFailingSendsAreBoundedPerMinute(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{GlobalPerMinute: 2}})
	h.notif.fail = func(int) error { return errTransient }
	var items []any
	for i := 1; i <= 6; i++ {
		items = append(items, sshLine(cur(itoa(int64(i))), t0, ipN("203.0.113", i)), func() {
			waitFor(t, "idle", func() bool { h.d.mu.Lock(); defer h.d.mu.Unlock(); return h.d.inflightTotal == 0 })
		})
	}
	h.steps(items...)
	if err := h.runUntil("lines", func() bool { return h.savedCursor() == cur("6") }); err != nil {
		t.Fatal(err)
	}
	if n := len(h.notif.sent()); n != 2 {
		t.Fatalf("send attempts = %d within one minute, want 2", n)
	}
	if h.count(audit.NotifyDropped) == 0 {
		t.Fatal("the drops of the daemon's limit are not audited")
	}
}

// A notice that the worker's per-incident limit drops (the same notice went
// out within that interval) ends, so it does not hold incidents back.
func TestNoticeDroppedByThePerIncidentLimitEnds(t *testing.T) {
	h := newHarness(t, hopts{})
	h.steps(func() {
		h.d.mu.Lock()
		h.d.alertEvent("k", "notice", "body")
		h.d.mu.Unlock()
		waitFor(t, "notice sent", func() bool { return h.count(audit.NotifySent) == 1 })
		h.d.mu.Lock()
		h.d.alertEvent("k", "notice", "body")
		h.d.mu.Unlock()
	}, sshLine(cur("1"), t0, "203.0.113.1"))
	if err := h.runUntil("incident sent", func() bool { return h.count(audit.NotifySent) == 2 }); err != nil {
		t.Fatal(err)
	}
	if ts := h.titles(); len(ts) != 2 || !strings.Contains(ts[1], "203.0.113.1") {
		t.Fatalf("titles = %v", ts)
	}
}

// lineSizes are the sizes of the audit file's lines, newline included.
func lineSizes(h *harness) []int64 {
	var out []int64
	for _, l := range h.lines() {
		out = append(out, int64(l.size))
	}
	return out
}

// The stop notice goes out when the log fills up at a stream end, where the
// loop returns the error itself.
func TestStopNoticeWhenTheStreamEndFillsTheLog(t *testing.T) {
	for name, res := range map[string]execx.StreamResult{
		"stream end":    {ExitCode: 1, Stderr: []byte(strings.Repeat("x", 300))},
		"dropped lines": {ExitCode: 1, DroppedLines: 3},
	} {
		t.Run(name, func(t *testing.T) {
			probe := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
			probe.script("", fake.Script{Result: res})
			_ = probe.start().wait(t)
			start := lineSizes(probe)[0]
			h := newHarness(t, hopts{auditMax: audit.ReserveBytes + start + 10, opt: Options{MaxRestarts: 1}})
			h.script("", fake.Script{Result: res})
			err := h.start().wait(t)
			if !errors.Is(err, ErrAuditFull) {
				t.Fatalf("Run = %v", err)
			}
			if n := h.countTitle("audit log is full"); n != 1 {
				t.Fatalf("stop notices = %d (kinds %v)", n, h.kinds())
			}
		})
	}
}

// The stop notice goes out when the counts written at shutdown fill the log.
func TestStopNoticeWhenTheShutdownFlushFillsTheLog(t *testing.T) {
	bad := func(i string) string { return jline(cur(i), t0, map[string]string{"_PID": "x", "MESSAGE": "m"}) }
	lines := []string{bad("1"), bad("2"), bad("3")}
	probe := newHarness(t, hopts{})
	probe.script("", fake.Script{Follow: true, Lines: lines})
	if err := probe.runUntil("lines", func() bool { return probe.savedCursor() == cur("3") }); err != nil {
		t.Fatal(err)
	}
	sz := lineSizes(probe)
	h := newHarness(t, hopts{auditMax: audit.ReserveBytes + sz[0] + sz[1] + 10})
	h.script("", fake.Script{Follow: true, Lines: lines})
	r := h.start()
	waitFor(t, "lines", func() bool { return h.savedCursor() == cur("3") })
	if err := r.stop(t); !errors.Is(err, ErrAuditFull) {
		t.Fatalf("Run = %v", err)
	}
	if n := h.countTitle("audit log is full"); n != 1 {
		t.Fatalf("stop notices = %d (kinds %v)", n, h.kinds())
	}
	if k := h.kinds(); k[len(k)-1] != audit.DaemonError {
		t.Fatalf("kinds = %v", k)
	}
}
