package watch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func ipN(prefix string, n int) string { return fmt.Sprintf("%s.%d", prefix, n) }

func floodLines(prefix string, from, count int) []any {
	var out []any
	for i := 0; i < count; i++ {
		out = append(out, sshLine(cur(itoa(int64(from+i))), t0, ipN(prefix, 1+i)))
	}
	return out
}

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

// ---- F1: audit volume ----

// Distinct fingerprints open incidents at will; the log writes at most the
// budget of incident_open records per interval and counts the rest.
func TestIncidentOpenRecordsAreBudgeted(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	items := floodLines("198.51.100", 1, 60)
	items = append(items, func() { h.clk.add(2 * time.Minute); housekeepOnce(t, h) })
	items = append(items, floodLines("203.0.113", 101, 60)...)
	h.steps(items...)
	if err := h.runUntil("both floods", func() bool { return h.savedCursor() == cur(itoa(160)) }); err != nil {
		t.Fatal(err)
	}
	if n := len(h.store.List()); n != 120 {
		t.Fatalf("incidents = %d: the store must keep every incident", n)
	}
	var opens, aggregates int
	for _, r := range h.records() {
		if r.Kind != audit.IncidentOpen {
			continue
		}
		opens++
		if strings.Contains(r.Summary, "more within") {
			aggregates++
			if !strings.HasPrefix(r.Summary, "50 more within") {
				t.Errorf("aggregate = %q", r.Summary)
			}
		}
	}
	// Per interval: the budget (10) plus one count record. Two intervals.
	if opens != 2*(DefaultAuditBudget+1) || aggregates != 2 {
		t.Fatalf("incident_open records = %d (aggregates %d), want %d", opens, aggregates, 2*(DefaultAuditBudget+1))
	}
}

func TestEvictionRecordsAreBudgeted(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true, setup: func(h *harness) { writeIncidents(t, h, incident.MaxIncidents, result.Low, t0.Add(-time.Minute)) }})
	h.steps(floodLines("198.51.100", 1, 40)...)
	if err := h.runUntil("flood", func() bool { return h.savedCursor() == cur("40") }); err != nil {
		t.Fatal(err)
	}
	var evicted, closeAgg int
	for _, r := range h.records() {
		if r.Kind != audit.IncidentClose {
			continue
		}
		if strings.HasPrefix(r.Summary, "evicted") {
			evicted++
		}
		if strings.HasPrefix(r.Summary, "30 more within") {
			closeAgg++
		}
	}
	if evicted != DefaultAuditBudget || closeAgg != 1 {
		t.Fatalf("eviction records = %d, count records = %d, kinds = %d", evicted, closeAgg, len(h.records()))
	}
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
	h.steps(floodLines("198.51.100", 1, 3)...)
	r := h.start()
	waitFor(t, "start", func() bool { return h.count(audit.DaemonStart) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n := h.countTitle("80% full"); n != 0 {
		t.Fatalf("notice sent below 80 percent (%d)", n)
	}
	r.cancel()
	_ = r.wait(t)
	// A second process with more incidents crosses the line and sends once.
	h2 := newHarness(t, hopts{auditMax: max, setup: func(h *harness) { fillAudit(t, h, max, 158_000) }})
	h2.steps(append(floodLines("198.51.100", 1, 8), func() { h2.clk.add(2 * time.Minute) }, sshLine(cur("20"), t0, "203.0.113.50"))...)
	if err := h2.runUntil("notice", func() bool { return h2.countTitle("80% full") >= 1 && h2.savedCursor() == cur("20") }); err != nil {
		t.Fatal(err)
	}
	if n := h2.countTitle("80% full"); n != 1 {
		t.Fatalf("fill notices = %d, want 1 per process", n)
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

// ---- F2: pending daemon notices ----

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
	if n := step(time.Minute); n != 1 {
		t.Fatalf("sends = %d inside the gap, want 1", n)
	}
	if n := step(10 * time.Minute); n != 2 {
		t.Fatalf("sends = %d after the gap, want the retry", n)
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

// ---- F3: cursor reset wording and gap detection ----

func TestCursorResetRecordSaysInvalid(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.cur, h.d.saved = cur("1"), cur("1")
	if _, _, err := h.d.streamEnded(execx.StreamResult{ExitCode: 1, Stderr: []byte("Failed to seek to cursor: Invalid argument")}, nil, cur("1")); err != nil {
		t.Fatal(err)
	}
	rs := h.records()
	if s := rs[len(rs)-1].Summary; rs[len(rs)-1].Kind != audit.CursorReset || !strings.Contains(s, "as invalid") || strings.Contains(s, "vacuum") || strings.Contains(s, "rotat") {
		t.Fatalf("record = %+v", rs[len(rs)-1])
	}
}

func curS(s, i string) string { return "s=" + s + ";i=" + i + ";b=2;m=3;t=4;x=5" }

func TestJournalGapAfterRestart(t *testing.T) {
	cases := []struct {
		name  string
		saved string
		first string
		want  string // substring of the gap record, "" for none
	}{
		{"next entry", curS("1", "5"), curS("1", "6"), ""},
		{"hex numbers, next entry", curS("1", "9"), curS("1", "a"), ""},
		{"one entry missing", curS("1", "5"), curS("1", "7"), "1 journal entries"},
		{"hex numbers, one missing", curS("1", "a"), curS("1", "c"), "1 journal entries"},
		{"many missing", curS("1", "13d"), curS("1", "146"), "8 journal entries"},
		{"same entry", curS("1", "5"), curS("1", "5"), ""},
		{"seqnum goes back", curS("1", "5"), curS("1", "2"), ""},
		{"journal replaced", curS("1", "5"), curS("2", "6"), "seqnum id changed"},
		{"saved cursor without i", "s=1;b=2", curS("1", "9"), ""},
		{"first cursor without s", curS("1", "5"), "i=9;b=2", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{setup: func(h *harness) {
				if err := h.cursor.Save(c.saved); err != nil {
					t.Fatal(err)
				}
			}})
			h.script(c.saved, fake.Script{Follow: true, Lines: []string{plainLine(c.first, t0)}})
			if err := h.runUntil("line", func() bool { return h.savedCursor() == c.first }); err != nil {
				t.Fatal(err)
			}
			var got string
			for _, r := range h.records() {
				if r.Kind == KindJournalGap {
					got = r.Summary
				}
			}
			if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
				t.Fatalf("journal_gap record = %q, want %q", got, c.want)
			}
			if len(h.notif.sent()) != 0 {
				t.Fatal("a gap is audited, not notified")
			}
		})
	}
}

// The comparison is made once per stream, and again after a restart.
func TestJournalGapIsCheckedOncePerStream(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Err: errors.New("x"), Lines: []string{plainLine(curS("1", "5"), t0)}})
	h.script(curS("1", "5"), fake.Script{Follow: true, Lines: []string{plainLine(curS("1", "9"), t0), plainLine(curS("1", "20"), t0)}})
	if err := h.runUntil("lines", func() bool { return h.savedCursor() == curS("1", "20") }); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range h.records() {
		if r.Kind == KindJournalGap {
			n++
			if !strings.Contains(r.Summary, "3 journal entries") {
				t.Errorf("record = %q", r.Summary)
			}
		}
	}
	if n != 1 {
		t.Fatalf("journal_gap records = %d, want 1 (the first stream had no saved cursor, the second compares once)", n)
	}
}

// ---- F4: the redaction boundary at every site ----

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

// ---- F5: fail closed on a failing store ----

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

// ---- F6, F8: the housekeeping retry takes over only what qualifies ----

type seed struct {
	state    incident.State
	notify   bool
	notified bool
}

func writeSeeds(t *testing.T, h *harness, seeds []seed) []string {
	t.Helper()
	var items []map[string]any
	var ids []string
	for i, s := range seeds {
		fp := string(event.FingerprintOf("seed", itoa(int64(i))))
		notified := time.Time{}
		if s.notified {
			notified = t0.Add(-time.Hour)
		}
		items = append(items, map[string]any{
			"id": fp[:16], "fingerprint": fp, "rule_id": "seed", "severity": "high", "state": string(s.state),
			"title": "seed title", "summary": "seed summary", "count": 1, "first_seen": t0.Add(-2 * time.Hour), "last_seen": t0.Add(-time.Hour),
			"notify": s.notify, "reopen_count": 0, "notified_at": notified,
		})
		ids = append(ids, fp[:16])
	}
	b, err := json.Marshal(map[string]any{"schema_version": incident.SchemaVersion, "incidents": items, "retired_ids": []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.dir.WriteAtomic(incident.FileName, b, incident.MaxFileSize); err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestHousekeepingRetryTakesOverOnlyWhatQualifies(t *testing.T) {
	var ids []string
	h := newHarness(t, hopts{setup: func(h *harness) {
		ids = writeSeeds(t, h, []seed{
			{incident.StateOpen, true, true},    // already notified
			{incident.StateOpen, false, false},  // wants no notification
			{incident.StateAcked, true, false},  // acked
			{incident.StateClosed, true, false}, // closed
			{incident.StateOpen, true, false},   // the one that qualifies
		})
	}})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	housekeepOnce(t, h)
	waitFor(t, "send", func() bool { return h.count(audit.NotifySent) == 1 })
	time.Sleep(60 * time.Millisecond)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if n := len(h.notif.sent()); n != 1 {
		t.Fatalf("sends = %d, want only the qualifying incident", n)
	}
	var found []string
	for _, rec := range h.records() {
		if rec.Kind == audit.IncidentUpdate && strings.Contains(rec.Summary, "found without a recorded notification") {
			found = append(found, rec.IncidentID)
		}
	}
	if len(found) != 1 || found[0] != ids[4] {
		t.Fatalf("takeover records = %v, want one for %s", found, ids[4])
	}
}

// ---- F7 ----

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

// ---- F11 ----

func TestRetryBookkeepingStaysWithinTheBoundInsideOneGap(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < maxTries+700; i++ {
		fp := event.FingerprintOf("flood", itoa(int64(i)))
		in := incident.Incident{ID: "id" + itoa(int64(i)), Fingerprint: fp, RuleID: "r", Severity: result.High, Title: "t", Summary: "s", Notify: true, Count: 1, FirstSeen: t0, LastSeen: t0}
		if err := h.d.notifyIncident(in, false); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.d.tries); n > maxTries {
		t.Fatalf("tries = %d, want at most %d", n, maxTries)
	}
}

// ---- F12, F13 ----

func TestOverlongLinesAreCountedAtShutdown(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true, Lines: []string{strings.Repeat("a", execx.DefaultMaxLine+1)}})
	if err := h.runUntil("start", func() bool { return len(h.fs.Calls()) == 1 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.JournalLineInvalid) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

func TestLineWithAnUnusableCursorIsABadLine(t *testing.T) {
	for name, c := range map[string]string{
		"space": "s=1;i=1;b=a b", "non-ASCII": "s=1;i=1;b=é", "too long": "s=1;i=1;b=" + strings.Repeat("a", MaxCursorBytes),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.script("", fake.Script{Follow: true, Lines: []string{plainLine(c, t0), plainLine(cur("2"), t0)}})
			if err := h.runUntil("good line", func() bool { return h.savedCursor() == cur("2") }); err != nil {
				t.Fatalf("Run = %v, want nil: a bad cursor must not stop the daemon", err)
			}
			if h.count(audit.JournalLineInvalid) != 1 {
				t.Fatalf("kinds = %v", h.kinds())
			}
		})
	}
	t.Run("only the bad line", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.script("", fake.Script{Follow: true, Lines: []string{plainLine("a b", t0)}})
		if err := h.runUntil("line", func() bool { return h.count(audit.JournalLineInvalid) == 1 }); err != nil {
			t.Fatal(err)
		}
		if h.savedCursor() != "" {
			t.Fatalf("cursor = %q, must not move past a line it cannot save", h.savedCursor())
		}
	})
	t.Run("error line with an unusable cursor", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.script("", fake.Script{Follow: true, Lines: []string{jline("a b", t0, map[string]string{"_PID": "x"})}})
		if err := h.runUntil("line", func() bool { return h.count(audit.JournalLineInvalid) == 1 }); err != nil {
			t.Fatal(err)
		}
		if h.savedCursor() != "" {
			t.Fatalf("cursor = %q", h.savedCursor())
		}
	})
}

// ---- F15 ----

func TestSleepErrorEndsTheLoopWithThatError(t *testing.T) {
	boom := errors.New("sleep broke")
	h := newHarness(t, hopts{opt: Options{Sleep: func(context.Context, time.Duration) error { return boom }}})
	h.script("", fake.Script{Result: execx.StreamResult{ExitCode: 1}})
	err := h.start().wait(t)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the sleep error", err)
	}
	if h.count(audit.DaemonStop) != 0 || h.count(audit.DaemonError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

func TestAlertParamsTakeTheIntervalFromTheOptions(t *testing.T) {
	if got := (Options{}).AlertParams(8, 3, time.Second); got.PerIncidentInterval != time.Hour || got.QueueSize != 8 || got.GlobalPerMinute != 3 || got.SendTimeout != time.Second {
		t.Fatalf("params = %+v", got)
	}
	if got := (Options{PerIncidentInterval: 5 * time.Minute}).AlertParams(1, 0, 0); got.PerIncidentInterval != 5*time.Minute {
		t.Fatalf("params = %+v", got)
	}
}
