package watch

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/LanNguyenSi/keepwatch/internal/requests"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
)

// writeIncidents writes an incident file with n open incidents of the given
// severity, last seen at seen.
func writeIncidents(t *testing.T, h *harness, n int, sev result.Severity, seen time.Time) {
	t.Helper()
	type item map[string]any
	var items []item
	for i := 0; i < n; i++ {
		fp := string(event.FingerprintOf("seed", itoa(int64(i))))
		items = append(items, item{
			"id": fp[:16], "fingerprint": fp, "rule_id": "seed", "severity": string(sev), "state": "open",
			"title": "seed", "summary": "seed", "count": 1, "first_seen": seen, "last_seen": seen,
			"notify": false, "reopen_count": 0, "notified_at": time.Time{},
		})
	}
	b, err := json.Marshal(map[string]any{"schema_version": incident.SchemaVersion, "incidents": items, "retired_ids": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.dir.WriteAtomic(incident.FileName, b, incident.MaxFileSize); err != nil {
		t.Fatal(err)
	}
}

// ---- journal_line_invalid ----

func TestInvalidLinesAreRateLimited(t *testing.T) {
	h := newHarness(t, hopts{})
	var lines []string
	for i := 1; i <= 5; i++ {
		lines = append(lines, jline(cur("bad"+itoa(int64(i))), t0, map[string]string{"_PID": "x", "MESSAGE": "m"}))
	}
	lines = append(lines, "not json", "{", "[1]")
	h.script("", fake.Script{Follow: true, Lines: lines})
	r := h.start()
	waitFor(t, "all bad lines handled", func() bool {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		return h.d.delivered == 8 && h.savedCursor() == cur("bad5")
	})
	if n := h.count(audit.JournalLineInvalid); n != 1 {
		t.Fatalf("journal_line_invalid = %d after 8 bad lines, want 1", n)
	}
	h.clk.add(2 * time.Minute)
	housekeepOnce(t, h) // the window ended: the pass writes the count
	recs := h.records()
	last := recs[len(recs)-1]
	if last.Kind != audit.JournalLineInvalid || !strings.Contains(last.Summary, "7 more") {
		t.Fatalf("aggregate = %+v", last)
	}
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	h.verify()
}

func TestLineWithoutTimestampIsNotEvaluated(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), time.Time{}, "203.0.113.9")}})
	if err := h.runUntil("cursor", func() bool { return h.savedCursor() == cur("1") }); err != nil {
		t.Fatal(err)
	}
	if len(h.store.List()) != 0 || h.count(audit.JournalLineInvalid) != 1 {
		t.Fatalf("incidents=%d kinds=%v", len(h.store.List()), h.kinds())
	}
}

// ---- clock ----

func TestSignalTimeSkewClamp(t *testing.T) {
	cases := []struct {
		name    string
		ahead   time.Duration
		clamped bool
	}{
		{"behind the clock", -time.Hour, false},
		{"inside the skew", 4 * time.Minute, false},
		{"exactly the skew", DefaultClockSkew, false},
		{"beyond the skew", DefaultClockSkew + time.Second, true},
		{"far ahead", 48 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			at := t0.Add(c.ahead)
			h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), at, "203.0.113.9")}})
			if err := h.runUntil("incident", func() bool { return h.savedCursor() == cur("1") }); err != nil {
				t.Fatal(err)
			}
			in := h.store.List()[0]
			want := at
			if c.clamped {
				want = t0
			}
			if !in.FirstSeen.Equal(want) {
				t.Fatalf("FirstSeen = %v, want %v", in.FirstSeen, want)
			}
			if got := h.count(audit.InputError); (got == 1) != c.clamped || got > 1 {
				t.Fatalf("input_error = %d, clamped = %v", got, c.clamped)
			}
		})
	}
}

// ---- audit policy ----

func TestAuditFullWritesTerminalRecordAndStops(t *testing.T) {
	h := newHarness(t, hopts{auditMax: audit.ReserveBytes + 600})
	h.script("", fake.Script{Follow: true, Lines: []string{
		sshLine(cur("1"), t0, "203.0.113.9"), sshLine(cur("2"), t0, "203.0.113.10"),
	}})
	err := h.start().wait(t)
	if !errors.Is(err, ErrAuditFull) {
		t.Fatalf("Run = %v, want ErrAuditFull", err)
	}
	h.verify()
	k := h.kinds()
	if k[len(k)-1] != audit.DaemonError || h.count(audit.DaemonError) != 1 {
		t.Fatalf("kinds = %v, want one terminal daemon_error last", k)
	}
	if !strings.Contains(h.records()[len(k)-1].Summary, "full") {
		t.Fatalf("terminal record = %+v", h.records()[len(k)-1])
	}
}

// A record the log refuses as invalid is audited as input_error and the
// daemon goes on.
func TestRefusedAuditRecordIsCountedNotFatal(t *testing.T) {
	clean := func(s string) string {
		if strings.Contains(s, "BADUTF") {
			return "\xff\xfe"
		}
		return s
	}
	h := newHarness(t, hopts{clean: clean})
	h.script("", fake.Script{Follow: true, Lines: []string{
		kernLine(cur("1"), t0, "Out of memory: Killed process 1 (BADUTF) total-vm:1kB"),
		sshLine(cur("2"), t0, "203.0.113.9"),
	}})
	if err := h.runUntil("second line", func() bool { return h.count(audit.IncidentOpen) == 1 }); err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if h.count(audit.InputError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
	h.verify()
}

// ---- notifications ----

func TestFailedSendIsRetriedAtTheDaemonsPace(t *testing.T) {
	h := newHarness(t, hopts{})
	h.notif.fail = func(n int) error {
		if n <= 2 {
			return errTransient
		}
		return nil
	}
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	r := h.start()
	waitFor(t, "failed send audited", func() bool { return h.count(audit.NotifyFailed) == 1 })
	if !h.store.List()[0].NotifiedAt.IsZero() {
		t.Fatal("a failed send must not mark the incident notified")
	}
	// step moves the clock and runs a housekeeping pass, then reports how many
	// sends the notifier has seen after the worker had time to act.
	step := func(d time.Duration) int {
		h.clk.add(d)
		housekeepOnce(t, h)
		time.Sleep(60 * time.Millisecond)
		return len(h.notif.sent())
	}
	// PerIncidentInterval/4 is 10m: a pass a minute later must not retry.
	if n := step(time.Minute); n != 1 {
		t.Fatalf("sends = %d after 1m, want 1 (retry is paced)", n)
	}
	if n := step(10 * time.Minute); n != 2 {
		t.Fatalf("sends = %d after 11m, want the first retry (2)", n)
	}
	// The retry failed too: the gap doubles to 20m.
	if n := step(11 * time.Minute); n != 2 {
		t.Fatalf("sends = %d, want 2: the gap after two failures is 20m", n)
	}
	if n := step(10 * time.Minute); n != 3 {
		t.Fatalf("sends = %d, want the second retry (3)", n)
	}
	waitFor(t, "sent audited", func() bool { return h.count(audit.NotifySent) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if h.store.List()[0].NotifiedAt.IsZero() {
		t.Fatal("the incident is not marked notified after the retry succeeded")
	}
	// The incident was logged when it opened: the retry adds no record for it.
	if h.count(audit.IncidentUpdate) != 0 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

// An update of the incident while a failed send is waiting for its gap does
// not send again.
func TestPendingUpdateIsPacedAfterFailure(t *testing.T) {
	h := newHarness(t, hopts{})
	h.notif.fail = func(int) error { return errTransient }
	oomKill := "Out of memory: Killed process 77 (worker) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:1kB oom_score_adj:0"
	h.d.deps.Streamer = streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		if err := on([]byte(kernLine(cur("1"), t0.Add(-11*time.Minute), oomKill))); err != nil {
			return execx.StreamResult{}, err
		}
		waitFor(t, "the failed send", func() bool { return h.count(audit.NotifyFailed) == 1 })
		// The rule reports the victim again (an update of the open incident).
		if err := on([]byte(kernLine(cur("2"), t0, oomKill))); err != nil {
			return execx.StreamResult{}, err
		}
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	r := h.start()
	waitFor(t, "second line", func() bool { return h.savedCursor() == cur("2") })
	time.Sleep(60 * time.Millisecond)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if n := len(h.notif.sent()); n != 1 {
		t.Fatalf("sends = %d, want 1: the update came before the retry gap ended", n)
	}
	if h.count(audit.IncidentUpdate) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

func TestRetryGapDoublesWithFailures(t *testing.T) {
	h := newHarness(t, hopts{})
	want := []time.Duration{10 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 40 * time.Minute}
	for i, w := range want {
		if got := h.d.gap(i); got != w && !(i == 0 && got == 10*time.Minute) {
			t.Errorf("gap(%d) = %v, want %v", i, got, w)
		}
	}
	small := newHarness(t, hopts{opt: Options{PerIncidentInterval: time.Minute}})
	if got := small.d.gap(1); got != 30*time.Second {
		t.Errorf("gap with a short interval = %v, want the ntfy Retry-After floor", got)
	}
	// Doubling stops at the interval, also when a doubling would pass it.
	odd := newHarness(t, hopts{opt: Options{PerIncidentInterval: 70 * time.Second}})
	for failures, want := range []time.Duration{30 * time.Second, 30 * time.Second, time.Minute, 70 * time.Second, 70 * time.Second} {
		if got := odd.d.gap(failures); got != want {
			t.Errorf("gap(%d) with a 70s interval = %v, want %v", failures, got, want)
		}
	}
}

// An update of an open incident that wants a notification and has none
// recorded (a crash before the enqueue) is notified: Pending.
func TestPendingIncidentIsNotifiedOnReplay(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		s, err := incident.Open(h.dir)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Apply(event.Signal{
			RuleID: rules.IDSSHBruteForce, Fingerprint: event.FingerprintOf(rules.IDSSHBruteForce, "203.0.113.9"),
			Severity: result.High, Time: t0.Add(-time.Hour), Notify: true,
		}, incident.Display{Title: "seed", Summary: "seed"})
		if err != nil {
			t.Fatal(err)
		}
	}})
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	if err := h.runUntil("replayed notification", func() bool { return h.count(audit.NotifySent) == 1 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.IncidentUpdate) != 1 || h.store.List()[0].NotifiedAt.IsZero() {
		t.Fatalf("kinds=%v incidents=%+v", h.kinds(), h.store.List())
	}
}

func TestNoNotifierStillMarksNotified(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	if err := h.runUntil("incident", func() bool { return h.savedCursor() == cur("1") }); err != nil {
		t.Fatal(err)
	}
	if h.store.List()[0].NotifiedAt.IsZero() {
		t.Fatal("without a notifier the incident must still count as notified")
	}
}

// A send that a rate limit drops counts as notified: the limit decided there
// will be no message now. Each limit on its own.
func TestRateLimitedSendMarksNotified(t *testing.T) {
	cases := []struct {
		name   string
		params alert.Params
		// second names the signal that the limit drops.
		same bool
	}{
		{"per-incident interval", alert.Params{QueueSize: 8, PerIncidentInterval: time.Hour}, true},
		{"global per minute", alert.Params{QueueSize: 8, GlobalPerMinute: 1}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{params: c.params})
			h.script("", fake.Script{Follow: true})
			r := h.start()
			waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
			apply := func(key string) incident.Incident {
				h.d.mu.Lock()
				defer h.d.mu.Unlock()
				res, err := h.d.deps.Incidents.Apply(event.Signal{Fingerprint: event.FingerprintOf("x", key), Severity: result.High, Time: h.clk.now(), Notify: true}, incident.Display{Title: "t", Summary: "s"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.d.notifyIncident(res.Incident, false); err != nil {
					t.Fatal(err)
				}
				return res.Incident
			}
			first := apply("1")
			waitFor(t, "first send", func() bool { return h.count(audit.NotifySent) == 1 })
			h.clk.add(30 * time.Second)
			second := first
			if !c.same {
				second = apply("2")
			} else {
				h.d.mu.Lock()
				_, err := h.d.notifyIncident(first, false)
				h.d.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, "drop audited", func() bool { return h.count(audit.NotifyDropped) == 1 })
			h.d.mu.Lock()
			got, _ := h.d.deps.Incidents.Get(second.ID)
			_, paced := h.d.tries[string(second.Fingerprint)]
			h.d.mu.Unlock()
			if paced {
				t.Fatal("the pacing entry of a send that a limit dropped must go")
			}
			if !got.NotifiedAt.Equal(t0.Add(30 * time.Second)) {
				t.Fatalf("NotifiedAt = %v, want the time of the dropped send", got.NotifiedAt)
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecoveryIsNotifiedWithHighPriority(t *testing.T) {
	h := newHarness(t, hopts{recovery: &audit.Recovery{Offset: 5, Length: 7, Hash: "ab12", Terminated: true}})
	h.script("", fake.Script{Follow: true})
	if err := h.runUntil("recovery notice", func() bool { return len(h.notif.sent()) == 1 && h.count(audit.NotifySent) == 1 }); err != nil {
		t.Fatal(err)
	}
	m := h.notif.sent()[0]
	if m.Priority != 4 || !strings.Contains(m.Title, "audit") || !strings.Contains(m.Body, "ab12") {
		t.Fatalf("message = %+v", m)
	}
	if r := h.records(); r[len(r)-2].IncidentID != "" {
		t.Fatalf("records = %+v", r)
	}
}

// ---- incident store results ----

func TestRefusedSignalIsAuditedAndNotifiedUnderTheLimit(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) { writeIncidents(t, h, incident.MaxIncidents, result.Critical, t0.Add(-time.Minute)) }})
	h.steps(oomAt(cur("1"), t0.Add(-11*time.Minute)),
		func() { waitFor(t, "first send", func() bool { return h.count(audit.NotifySent) == 1 }) },
		oomAt(cur("2"), t0))
	if err := h.runUntil("refused signal", func() bool { return h.count(audit.NotifyDropped) == 1 && h.savedCursor() == cur("2") }); err != nil {
		t.Fatal(err)
	}
	if n := len(h.store.List()); n != incident.MaxIncidents {
		t.Fatalf("incidents = %d", n)
	}
	if h.count(audit.InputError) != 2 { // the first refusal, and the count of the second at shutdown
		t.Fatalf("kinds = %v", h.kinds())
	}
	if n := len(h.notif.sent()); n != 1 {
		t.Fatalf("sends = %d, want 1 (the second refusal is inside the per-fingerprint limit)", n)
	}
	// The refused job is not about a stored incident: its record names none.
	for _, r := range h.records() {
		if r.Kind == audit.NotifySent && r.IncidentID != "" {
			t.Fatalf("notify_sent of a refused signal names the incident %q", r.IncidentID)
		}
	}
}

// A refused signal is paced like any retry: with a failing notifier four
// refusals inside one gap send once.
func TestRefusedSignalIsPacedAfterFailure(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) { writeIncidents(t, h, incident.MaxIncidents, result.Critical, t0.Add(-time.Minute)) }})
	h.notif.fail = func(int) error { return errTransient }
	h.steps(oomAt(cur("1"), t0.Add(-33*time.Minute)),
		func() { waitFor(t, "failed send", func() bool { return h.count(audit.NotifyFailed) == 1 }) },
		oomAt(cur("2"), t0.Add(-22*time.Minute)), oomAt(cur("3"), t0.Add(-11*time.Minute)), oomAt(cur("4"), t0))
	if err := h.runUntil("four refusals", func() bool { return h.savedCursor() == cur("4") }); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if n := len(h.notif.sent()); n != 1 {
		t.Fatalf("sends = %d, want 1: the refused path is paced like the Pending path", n)
	}
}

func TestEvictedIncidentIsAudited(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) { writeIncidents(t, h, incident.MaxIncidents, result.Low, t0.Add(-time.Minute)) }})
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	if err := h.runUntil("eviction", func() bool { return h.count(audit.IncidentOpen) == 1 }); err != nil {
		t.Fatal(err)
	}
	var evicted int
	for _, r := range h.records() {
		if r.Kind == audit.IncidentClose && strings.Contains(r.Summary, "evicted") {
			evicted++
		}
	}
	if evicted != 1 {
		t.Fatalf("evicted records = %d, kinds = %v", evicted, h.kinds())
	}
}

func TestAutoClosedIncidentsAreAudited(t *testing.T) {
	prefill := func(h *harness) { writeIncidents(t, h, 2, result.Low, t0.Add(-2*time.Hour)) }
	t.Run("on apply", func(t *testing.T) {
		h := newHarness(t, hopts{store: []incident.Option{incident.WithIdleClose(time.Hour)}, setup: prefill})
		h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
		if err := h.runUntil("open", func() bool { return h.count(audit.IncidentOpen) == 1 }); err != nil {
			t.Fatal(err)
		}
		if n := h.count(audit.IncidentClose); n != 2 {
			t.Fatalf("incident_close = %d, want 2", n)
		}
	})
	t.Run("on housekeeping", func(t *testing.T) {
		h := newHarness(t, hopts{store: []incident.Option{incident.WithIdleClose(time.Hour)}, setup: prefill})
		h.script("", fake.Script{Follow: true})
		r := h.start()
		waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
		h.d.mu.Lock()
		err := h.d.housekeep()
		h.d.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := r.stop(t); err != nil {
			t.Fatal(err)
		}
		if n := h.count(audit.IncidentClose); n != 2 {
			t.Fatalf("incident_close = %d, want 2", n)
		}
	})
}

// ---- rules input ----

// The OOM rule sees every kernel line, in order: an unrelated kernel line
// ends a group kill episode, so the Killed process line after it is a kill of
// its own. Without that line it belongs to the episode and gives no signal.
func TestKernelLinesReachTheOOMRuleUnfiltered(t *testing.T) {
	group := "Tasks in /system.slice/app.service are going to be killed due to memory.oom.group set"
	killed := "Out of memory: Killed process 77 (worker) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:1kB oom_score_adj:0"
	run := func(lines ...string) int {
		h := newHarness(t, hopts{})
		var ls []string
		for i, l := range lines {
			ls = append(ls, kernLine(cur(itoa(int64(i+1))), t0, l))
		}
		h.script("", fake.Script{Follow: true, Lines: ls})
		if err := h.runUntil("lines", func() bool { return h.savedCursor() == cur(itoa(int64(len(lines)))) }); err != nil {
			t.Fatal(err)
		}
		return len(h.store.List())
	}
	if n := run(group, killed); n != 0 {
		t.Fatalf("control: the episode must swallow the Killed line, incidents = %d", n)
	}
	if n := run(group, "usb 1-1: new high-speed USB device number 4", killed); n != 1 {
		t.Fatalf("an unrelated kernel line must end the episode, incidents = %d", n)
	}
}

// ---- requests ----

type spool struct {
	batch   requests.Batch
	err     error
	removeE error
	removed []string
	sweeps  int
}

func (s *spool) ops() *RequestOps {
	return &RequestOps{
		Pending: func() (requests.Batch, error) { return s.batch, s.err },
		Remove: func(name string) error {
			s.removed = append(s.removed, name)
			return s.removeE
		},
		SweepTemp: func(time.Duration) (int, error) { s.sweeps++; return 0, nil },
	}
}

func rejected(name string) requests.Item {
	return requests.Item{Name: name, Rejection: &requests.Rejection{Reason: requests.ReasonMode, Detail: "mode 0666"}}
}

func housekeepOnce(t *testing.T, h *harness) {
	t.Helper()
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	if err := h.d.housekeep(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectedRequestAuditedOncePerName(t *testing.T) {
	sp := &spool{removeE: errors.New("busy"), batch: requests.Batch{Items: []requests.Item{rejected("req-1\x1b[31m")}}}
	h := newHarness(t, hopts{reqs: sp.ops()})
	for i := 0; i < 3; i++ {
		housekeepOnce(t, h)
	}
	if n := h.count(audit.RequestRejected); n != 1 {
		t.Fatalf("request_rejected = %d after 3 passes with a failing Remove, want 1", n)
	}
	if len(sp.removed) != 3 || sp.removed[0] != "req-1\x1b[31m" {
		t.Fatalf("Remove calls = %q, want 3 with the raw name", sp.removed)
	}
	if rec := h.records()[0]; strings.Contains(rec.Summary, "\x1b") {
		t.Fatalf("raw name in the audit record: %q", rec.Summary)
	}
	// Once removed, the name is forgotten: the same name audits again.
	sp.removeE = nil
	housekeepOnce(t, h) // Remove works now; the name is forgotten
	if n := h.count(audit.RequestRejected); n != 1 {
		t.Fatalf("request_rejected = %d, want 1 (record kept from the earlier pass)", n)
	}
	sp.batch = requests.Batch{}
	housekeepOnce(t, h)
	sp.batch = requests.Batch{Stray: []requests.Item{rejected("req-1\x1b[31m")}}
	housekeepOnce(t, h)
	if n := h.count(audit.RequestRejected); n != 2 {
		t.Fatalf("request_rejected = %d, want 2 after the name came back", n)
	}
	h.verify()
}

func TestOverfullSpoolAuditedAndNotifiedOncePerEpisode(t *testing.T) {
	sp := &spool{batch: requests.Batch{Overfull: true}}
	h := newHarness(t, hopts{reqs: sp.ops()})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	housekeepOnce(t, h)
	housekeepOnce(t, h)
	waitFor(t, "notice", func() bool { return h.count(audit.NotifySent) == 1 })
	sp.batch = requests.Batch{}
	housekeepOnce(t, h)
	sp.batch = requests.Batch{Overfull: true}
	h.clk.add(time.Hour) // outside the worker's per-fingerprint interval
	housekeepOnce(t, h)
	waitFor(t, "second episode", func() bool { return h.count(audit.NotifySent) == 2 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if n := h.count(audit.RequestRejected); n != 2 {
		t.Fatalf("request_rejected = %d, want 2 (one per episode)", n)
	}
}

func TestSweepTempRunsPeriodically(t *testing.T) {
	sp := &spool{}
	h := newHarness(t, hopts{reqs: sp.ops()})
	housekeepOnce(t, h)
	housekeepOnce(t, h)
	if sp.sweeps != 1 {
		t.Fatalf("sweeps = %d, want 1 within the interval", sp.sweeps)
	}
	h.clk.add(DefaultTempSweepInterval)
	housekeepOnce(t, h)
	if sp.sweeps != 2 {
		t.Fatalf("sweeps = %d, want 2 after the interval", sp.sweeps)
	}
}

func TestPendingErrorIsAudited(t *testing.T) {
	sp := &spool{err: errors.New("open /state/requests: " + hostileToken)}
	h := newHarness(t, hopts{reqs: sp.ops()})
	housekeepOnce(t, h)
	if h.count(audit.InputError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
	if b, _ := os.ReadFile(filepath.Join(h.path, audit.FileName)); strings.Contains(string(b), hostileToken) {
		t.Fatal("raw text in the audit log")
	}
}
