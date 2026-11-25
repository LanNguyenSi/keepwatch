package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/requests"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func TestTokenNeverReachesTheAuditLog(t *testing.T) {
	tok := hostileToken
	spoolOf := func(items ...requests.Item) func() *spool {
		return func() *spool { return &spool{removeE: errors.New("busy"), batch: requests.Batch{Items: items}} }
	}
	cases := []struct {
		name string
		kind audit.Kind // a record of this kind must exist, with the redaction mark
		run  func(t *testing.T) *harness
	}{
		{"decode error text (line.go badLine)", audit.JournalLineInvalid, func(t *testing.T) *harness {
			h := newHarness(t, hopts{})
			h.script("", fake.Script{Follow: true, Lines: []string{jline(cur("1"), t0, map[string]string{"_PID": tok})}})
			_ = h.runUntil("record", func() bool { return h.count(audit.JournalLineInvalid) == 1 })
			return h
		}},
		{"notifier failure detail (alerts.go handleResult)", audit.NotifyFailed, func(t *testing.T) *harness {
			h := newHarness(t, hopts{})
			h.notif.fail = func(int) error { return &notify.Error{Class: notify.Permanent, Msg: "refused " + tok} }
			h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
			_ = h.runUntil("record", func() bool { return h.count(audit.NotifyFailed) == 1 })
			return h
		}},
		{"rejection detail (housekeeping.go requestsPass)", audit.RequestRejected, func(t *testing.T) *harness {
			sp := spoolOf(requests.Item{Name: "req-1", Rejection: &requests.Rejection{Reason: requests.ReasonMode, Detail: "mode " + tok}})()
			h := newHarness(t, hopts{reqs: sp.ops()})
			housekeepOnce(t, h)
			return h
		}},
		{"rejected request name (housekeeping.go requestsPass)", audit.RequestRejected, func(t *testing.T) *harness {
			sp := spoolOf(requests.Item{Name: "req-" + tok, Rejection: &requests.Rejection{Reason: requests.ReasonName, Detail: "d"}})()
			h := newHarness(t, hopts{reqs: sp.ops()})
			housekeepOnce(t, h)
			return h
		}},
		{"spool listing error (housekeeping.go requestsPass)", audit.InputError, func(t *testing.T) *harness {
			sp := &spool{err: errors.New("open " + tok)}
			h := newHarness(t, hopts{reqs: sp.ops()})
			housekeepOnce(t, h)
			return h
		}},
		{"sweep error (housekeeping.go requestsPass)", audit.InputError, func(t *testing.T) *harness {
			ops := (&spool{}).ops()
			ops.SweepTemp = func(time.Duration) (int, error) { return 0, errors.New("remove " + tok) }
			h := newHarness(t, hopts{reqs: ops})
			housekeepOnce(t, h)
			return h
		}},
		{"stream error text (stream.go streamEnded)", audit.InputError, func(t *testing.T) *harness {
			h := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
			h.script("", fake.Script{Err: errors.New("boom " + tok)})
			_ = h.start().wait(t)
			return h
		}},
		{"journalctl stderr (stream.go streamEnded)", audit.InputError, func(t *testing.T) *harness {
			h := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
			h.script("", fake.Script{Result: execx.StreamResult{ExitCode: 1, Stderr: []byte("denied " + tok)}})
			_ = h.start().wait(t)
			return h
		}},
		{"terminal record (record.go finish)", audit.DaemonError, func(t *testing.T) *harness {
			h := newHarness(t, hopts{})
			h.fs.AddError(args(""), fmt.Errorf("%w: "+tok, execx.ErrNotFound))
			_ = h.start().wait(t)
			return h
		}},
		{"cursor file error text (daemon.go start)", audit.CursorReset, func(t *testing.T) *harness {
			h := newHarness(t, hopts{dirName: tok, setup: func(h *harness) {
				if err := h.dir.WriteAtomic(CursorFile, []byte(strings.Repeat("a", MaxCursorBytes+1)), 4096); err != nil {
					t.Fatal(err)
				}
			}})
			h.script("", fake.Script{Follow: true})
			_ = h.runUntil("reset", func() bool { return h.count(audit.CursorReset) == 1 })
			return h
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := c.run(t)
			log, err := os.ReadFile(filepath.Join(h.path, audit.FileName))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(log), tok) || strings.Contains(string(log), "ghp_") {
				t.Fatalf("the audit log holds the raw token")
			}
			found := false
			for _, r := range h.records() {
				if r.Kind == c.kind && strings.Contains(r.Summary, "[REDACTED]") {
					found = true
				}
			}
			if !found {
				t.Fatalf("no %s record with a redaction mark (the case drove nothing): %v", c.kind, h.records())
			}
			for _, m := range h.notif.sent() {
				if strings.Contains(m.Title+m.Body, tok) {
					t.Fatalf("notifier got the raw token: %+v", m)
				}
			}
		})
	}
	t.Run("daemon notice (alerts.go alertEvent)", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.script("", fake.Script{Follow: true})
		r := h.start()
		waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
		h.d.mu.Lock()
		h.d.alertEvent("k", "title "+tok, "body "+tok)
		h.d.mu.Unlock()
		waitFor(t, "notice", func() bool { return len(h.notif.sent()) == 1 })
		_ = r.stop(t)
		m := h.notif.sent()[0]
		if strings.Contains(m.Title+m.Body, tok) || !strings.Contains(m.Title+m.Body, "[REDACTED]") {
			t.Fatalf("message = %+v", m)
		}
	})
}

// The stderr is cleaned before it is cut: a token that straddles the cut is
// redacted whole.
func TestStderrTokenStraddlingTheCutIsRedacted(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
	h.script("", fake.Script{Result: execx.StreamResult{ExitCode: 1, Stderr: []byte(strings.Repeat("x", 285) + hostileToken)}})
	_ = h.start().wait(t)
	log, _ := os.ReadFile(filepath.Join(h.path, audit.FileName))
	if strings.Contains(string(log), "ghp_") {
		t.Fatalf("part of the straddling token is in the audit log")
	}
}

func TestIncidentStoreFailureStopsTheDaemon(t *testing.T) {
	h := newHarness(t, hopts{})
	h.steps(func() { h.storeDir.Close() }, sshLine(cur("1"), t0, "203.0.113.9"))
	err := h.start().wait(t)
	if err == nil || !strings.Contains(err.Error(), "incident store") || errors.Is(err, ErrStreamEnded) {
		t.Fatalf("Run = %v, want the incident store error itself", err)
	}
	if h.count(audit.DaemonError) != 1 || h.savedCursor() != "" {
		t.Fatalf("kinds = %v, cursor = %q", h.kinds(), h.savedCursor())
	}
}

func TestCursorSaveFailureStopsTheDaemon(t *testing.T) {
	h := newHarness(t, hopts{})
	h.steps(func() { h.curDir.Close() }, sshLine(cur("1"), t0, "203.0.113.9"))
	err := h.start().wait(t)
	if err == nil || !strings.Contains(err.Error(), "cannot save the cursor") || errors.Is(err, ErrStreamEnded) {
		t.Fatalf("Run = %v", err)
	}
	if h.count(audit.DaemonError) != 1 || h.savedCursor() != "" {
		t.Fatalf("kinds = %v, cursor = %q", h.kinds(), h.savedCursor())
	}
	if h.count(audit.IncidentOpen) != 1 {
		t.Fatalf("the line was handled before its cursor failed to save: %v", h.kinds())
	}
}

func TestReopenedIncidentIsAuditedAndNotified(t *testing.T) {
	h := newHarness(t, hopts{})
	h.steps(oomAt(cur("1"), t0.Add(-11*time.Minute)),
		func() {
			waitFor(t, "first send", func() bool { return h.count(audit.NotifySent) == 1 })
			h.d.mu.Lock()
			defer h.d.mu.Unlock()
			in := h.store.List()[0]
			if _, err := h.store.Close(in.ID); err != nil {
				t.Fatal(err)
			}
			h.clk.add(time.Hour)
		},
		oomAt(cur("2"), t0))
	if err := h.runUntil("reopen", func() bool { return h.count(audit.NotifySent) == 2 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.IncidentReopen) != 1 || h.count(audit.IncidentUpdate) != 0 {
		t.Fatalf("kinds = %v", h.kinds())
	}
	if ts := h.titles(); len(ts) != 2 || !strings.Contains(ts[1], "Reopened") {
		t.Fatalf("titles = %v", ts)
	}
}

func TestInvalidSignalIsAuditedNotFatal(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	err := h.d.handleSignal(event.Signal{RuleID: "x", Fingerprint: "not hex", Severity: result.High, Time: t0})
	h.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if h.count(audit.InputError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

// Only a job that was accepted holds an in-flight slot, and only its
// shutdown drop gives one back.
func TestDropReleasesTheSlotOnlyOnShutdown(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	h.d.inflight["fp"], h.d.inflightTotal = 1, 1
	job := alert.Job{Fingerprint: "fp"}
	for _, reason := range []alert.DropReason{alert.DropIncident, alert.DropGlobal, alert.DropQueueFull, alert.DropInvalid, alert.DropWorkerEnded} {
		if err := h.d.handleResult(alert.Result{Job: job, Status: alert.Dropped, Reason: reason}); err != nil {
			t.Fatal(err)
		}
		if h.d.inflight["fp"] != 1 || h.d.inflightTotal != 1 {
			t.Fatalf("a %s drop freed the slot of the job in flight", reason)
		}
	}
	if err := h.d.handleResult(alert.Result{Job: job, Status: alert.Dropped, Reason: alert.DropShutdown}); err != nil {
		t.Fatal(err)
	}
	if h.d.inflight["fp"] != 0 || h.d.inflightTotal != 0 {
		t.Fatalf("a shutdown drop must free the slot")
	}
}

func TestRetryBookkeepingStaysWithinTheBoundInsideOneGap(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < maxTries+700; i++ {
		fp := event.FingerprintOf("flood", itoa(int64(i)))
		in := incident.Incident{ID: "id" + itoa(int64(i)), Fingerprint: fp, RuleID: "r", Severity: result.High, Title: "t", Summary: "s", Notify: true, Count: 1, FirstSeen: t0, LastSeen: t0}
		if _, err := h.d.notifyIncident(in, false); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.d.tries); n > maxTries {
		t.Fatalf("tries = %d, want at most %d", n, maxTries)
	}
}

func TestAlertParamsTakeTheLimitsFromTheOptions(t *testing.T) {
	// The worker's global limit is the daemon's plus the room for its notices.
	if got := (Options{}).AlertParams(8, time.Second); got.PerIncidentInterval != time.Hour || got.QueueSize != 8 || got.GlobalPerMinute != DefaultGlobalPerMinute+maxNotices || got.SendTimeout != time.Second {
		t.Fatalf("params = %+v", got)
	}
	if got := (Options{PerIncidentInterval: 5 * time.Minute, GlobalPerMinute: 3}).AlertParams(1, 0); got.PerIncidentInterval != 5*time.Minute || got.GlobalPerMinute != 3+maxNotices {
		t.Fatalf("params = %+v", got)
	}
}

// At the bound, with no expired entry, the entry with the oldest notBefore
// goes, and only that one.
func TestRetryBookkeepingEvictsTheOldestEntry(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < maxTries; i++ {
		// The oldest entry is in the middle, so neither map order nor the
		// first or last key finds it by chance.
		at := t0.Add(time.Duration(maxTries+i) * time.Minute)
		if i == maxTries/2 {
			at = t0.Add(time.Minute)
		}
		h.d.tries["fp"+itoa(int64(i))] = tryState{notBefore: at}
	}
	h.d.setTry("new", tryState{notBefore: t0.Add(time.Hour)})
	if _, ok := h.d.tries["fp"+itoa(int64(maxTries/2))]; ok || len(h.d.tries) != maxTries {
		t.Fatalf("tries = %d, oldest kept = %v", len(h.d.tries), ok)
	}
	if _, ok := h.d.tries["new"]; !ok {
		t.Fatal("the new entry is missing")
	}
}

// A Sent result whose job was built before a close and reopen names the
// pre-reopen generation: it does not mark the reopened incident notified and
// does not fail the daemon. The reopen notification stays due; the next
// housekeeping pass sends it, and only that result marks the incident.
func TestStaleSentResultLeavesTheReopenNotificationDue(t *testing.T) {
	h := newHarness(t, hopts{})
	sigAt := func(at time.Time) event.Signal {
		return event.Signal{RuleID: "r", Fingerprint: event.FingerprintOf("stale", "1"), Severity: result.High, Time: at, Notify: true}
	}
	h.d.mu.Lock()
	opened, err := h.store.Apply(sigAt(t0), incident.Display{Title: "t", Summary: "s"})
	if err != nil || opened.Outcome != incident.Opened {
		h.d.mu.Unlock()
		t.Fatalf("apply = %+v, %v", opened, err)
	}
	id := opened.Incident.ID
	// The job the worker took over for the first notification carries the
	// generation that was current when the job was built.
	job := alert.Job{IncidentID: id, Fingerprint: string(opened.Incident.Fingerprint), ReopenCount: opened.Incident.ReopenCount}
	if _, err := h.store.Close(id); err != nil {
		h.d.mu.Unlock()
		t.Fatal(err)
	}
	h.clk.add(time.Hour)
	reopened, err := h.store.Apply(sigAt(h.clk.now()), incident.Display{Title: "t", Summary: "s"})
	if err != nil || reopened.Outcome != incident.Reopened || reopened.Incident.ReopenCount != 1 {
		h.d.mu.Unlock()
		t.Fatalf("reopen = %+v, %v", reopened, err)
	}
	// The late result of the pre-reopen job: no mark, no daemon failure.
	if err := h.d.handleResult(alert.Result{Job: job, Status: alert.Sent, At: h.clk.now()}); err != nil {
		h.d.mu.Unlock()
		t.Fatalf("a stale mark must not fail the daemon: %v", err)
	}
	if in, _ := h.store.Get(id); !in.NotifiedAt.IsZero() {
		h.d.mu.Unlock()
		t.Fatal("the result of the pre-reopen job marked the reopened incident notified")
	}
	h.d.mu.Unlock()
	// Worker and result loop stand in for a daemon Run: the pass hands the
	// reopen notification on, and its result comes back through the loop.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.worker.Run(ctx)
	go h.d.resultLoop(make(chan struct{}))
	t.Cleanup(h.d.closeResults)
	housekeepOnce(t, h)
	waitFor(t, "the reopen notification marked the incident", func() bool {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		in, _ := h.store.Get(id)
		return !in.NotifiedAt.IsZero()
	})
	if n := len(h.notif.sent()); n != 1 {
		t.Fatalf("sends = %d, want the reopen notification (1)", n)
	}
}

// reopenOpened opens, closes and reopens one incident and returns its id and
// the reopened incident (ReopenCount >= 1). It runs under the caller's d.mu.
func reopenOpened(t *testing.T, h *harness, tag string) (string, incident.Incident) {
	t.Helper()
	sigAt := func(at time.Time) event.Signal {
		return event.Signal{RuleID: "r", Fingerprint: event.FingerprintOf(tag, "1"), Severity: result.High, Time: at, Notify: true}
	}
	opened, err := h.store.Apply(sigAt(t0), incident.Display{Title: "t", Summary: "s"})
	if err != nil || opened.Outcome != incident.Opened {
		t.Fatalf("apply = %+v, %v", opened, err)
	}
	id := opened.Incident.ID
	if _, err := h.store.Close(id); err != nil {
		t.Fatal(err)
	}
	h.clk.add(time.Hour)
	reopened, err := h.store.Apply(sigAt(h.clk.now()), incident.Display{Title: "t", Summary: "s"})
	if err != nil || reopened.Outcome != incident.Reopened || reopened.Incident.ReopenCount < 1 {
		t.Fatalf("reopen = %+v, %v", reopened, err)
	}
	return id, reopened.Incident
}

// The no-worker path marks the incident it is handed for the generation named
// in the incident: a reopened incident (ReopenCount >= 1) is marked, not
// refused as a stale mark, so it stops being pending instead of staying
// unnotified.
func TestSynchronousNoWorkerMarkNamesTheReopenedGeneration(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	id, reopened := reopenOpened(t, h, "sync-noworker")
	if _, err := h.d.notifyIncident(reopened, false); err != nil {
		t.Fatal(err)
	}
	if in, _ := h.store.Get(id); in.NotifiedAt.IsZero() {
		t.Fatal("the no-worker path left a reopened incident unnotified: a mark of count 0 was refused as stale")
	}
}

// The rate-limit drop path marks the incident for the generation named in the
// incident: a reopened incident is marked and stops being pending, so the next
// pass does not hand it on again once the limit has room.
func TestSynchronousRateLimitMarkNamesTheReopenedGeneration(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{GlobalPerMinute: 1}})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	id, reopened := reopenOpened(t, h, "sync-ratelimit")
	// The worker's limit is used up in this minute, so the send is dropped and
	// the incident counts as notified without a message.
	h.d.attempts = append(h.d.attempts, h.clk.now())
	if _, err := h.d.notifyIncident(reopened, false); err != nil {
		t.Fatal(err)
	}
	if in, _ := h.store.Get(id); in.NotifiedAt.IsZero() {
		t.Fatal("the rate-limit drop left a reopened incident unnotified: a mark of count 0 was refused as stale")
	}
	if n := h.d.inflightTotal; n != 0 {
		t.Fatalf("inflight = %d, the dropped send must not reach the worker", n)
	}
	// The mark ends the retry: once the limit has room again the next pass does
	// not hand the reopened incident on a second time.
	h.clk.add(2 * time.Minute)
	h.d.logged[id] = true
	if err := h.d.reconcileNotifications(); err != nil {
		t.Fatal(err)
	}
	if n := h.d.inflightTotal; n != 0 {
		t.Fatalf("inflight = %d after the next pass, the marked incident must not be re-sent", n)
	}
}
