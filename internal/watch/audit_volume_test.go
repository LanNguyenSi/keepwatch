package watch

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
)

func ipN(prefix string, n int) string { return fmt.Sprintf("%s.%d", prefix, n) }

func floodLines(prefix string, from, count int) []any {
	var out []any
	for i := 0; i < count; i++ {
		out = append(out, sshLine(cur(itoa(int64(from+i))), t0, ipN(prefix, 1+i)))
	}
	return out
}

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

// The takeover record is written once per incident and process, also when the
// notification fails and is retried.
func TestTakeoverRecordIsWrittenOncePerIncident(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) { writeSeeds(t, h, []seed{{incident.StateOpen, true, false}}) }})
	h.notif.fail = func(int) error { return errTransient }
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "failed", func() bool { return h.count(audit.NotifyFailed) == 1 })
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "failed again", func() bool { return h.count(audit.NotifyFailed) == 2 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rec := range h.records() {
		if rec.Kind == audit.IncidentUpdate {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("takeover records = %d, want 1", n)
	}
}

// oomPid is the kernel line of the OOM kill of process pid named comm.
func oomPid(c string, at time.Time, pid int, comm string) string {
	return kernLine(c, at, fmt.Sprintf("Out of memory: Killed process %d (%s) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:1kB oom_score_adj:0", pid, comm))
}

// auditLine is one line of the audit file with its size.
type auditLine struct {
	rec  audit.Record
	size int
}

func (h *harness) lines() []auditLine {
	h.t.Helper()
	var out []auditLine
	recs := h.records()
	for i, l := range strings.SplitAfter(h.file(audit.FileName), "\n") {
		if l == "" {
			continue
		}
		if i >= len(recs) {
			h.t.Fatalf("line %d has no record", i)
		}
		out = append(out, auditLine{rec: recs[i], size: len(l)})
	}
	if len(out) != len(recs) {
		h.t.Fatalf("%d lines, %d records", len(out), len(recs))
	}
	return out
}

// minuteOf is the index of the minute after t0 in which a record was written.
func minuteOf(r audit.Record) int { return int(r.Time.Sub(t0) / time.Minute) }

func incidentKind(k audit.Kind) bool {
	return k == audit.IncidentOpen || k == audit.IncidentUpdate || k == audit.IncidentReopen || k == audit.IncidentClose
}

// worstCaseBytes is the ceiling of the package comment: 4 rules with their
// budget and count record, G records over the budget and G results of
// incident notifications, the notices, and two records for each of the 17
// rate-limited keys, at 1536 bytes per record line.
func worstCaseBytes(budget, g int) int {
	return (4*(budget+1) + 2*g + maxNotices*3 + 2*17) * 1536
}

// A flood of every signal shape the rules give (new fingerprints that evict
// stored incidents, one fingerprint with changing victims, a close and a
// reopen) stays under the documented ceiling in every interval, and its
// incident records under the budget of the rules plus the notifications the
// worker accepted.
func TestAuditBytesPerIntervalStayUnderTheCeiling(t *testing.T) {
	const g, intervals = 3, 4
	h := newHarness(t, hopts{opt: Options{GlobalPerMinute: g}, setup: func(h *harness) {
		writeIncidents(t, h, incident.MaxIncidents, result.Low, t0.Add(-time.Minute))
	}})
	h.notif.fail = func(int) error { return errTransient }
	var items []any
	n := 0
	next := func() string { n++; return cur(itoa(int64(n))) }
	for i := 0; i < intervals; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		for k := 0; k < 12; k++ {
			items = append(items, sshLine(next(), at, ipN(fmt.Sprintf("198.51.%d", i), k+1)))
			items = append(items, oomPid(next(), at, 1000*(i+1)+k, "worker"))
		}
		for k := 0; k < 10; k++ {
			items = append(items, oomPid(next(), at, 500+k, fmt.Sprintf("comm%d-%d", i, k)))
		}
		items = append(items, func() {
			h.d.mu.Lock()
			defer h.d.mu.Unlock()
			for _, in := range h.store.List() {
				if in.RuleID == rules.IDOOMKill && strings.Contains(in.Title, "worker") && in.State == incident.StateOpen {
					if _, err := h.store.Close(in.ID); err != nil {
						t.Error(err)
					}
				}
			}
		}, oomPid(next(), at, 9000+i, "worker"))
		items = append(items, func() {
			waitForWithin(t, time.Minute, "no job in flight", func() bool { h.d.mu.Lock(); defer h.d.mu.Unlock(); return h.d.inflightTotal == 0 })
			h.clk.add(time.Minute)
			housekeepOnce(t, h)
			waitForWithin(t, time.Minute, "no job in flight", func() bool { h.d.mu.Lock(); defer h.d.mu.Unlock(); return h.d.inflightTotal == 0 })
		})
	}
	h.steps(items...)
	// The flood rewrites a full incident store for every signal, which takes
	// longer than the usual wait under the race detector on a busy machine.
	r := h.start()
	waitForWithin(t, 2*time.Minute, "flood", func() bool {
		return h.savedCursor() == cur(itoa(int64(n))) && h.clk.now().Equal(t0.Add(intervals*time.Minute))
	})
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	bytes := map[int]int{}
	incRecs := map[int]int{}
	counted := map[int]int{}
	updates := map[[2]any]int{}
	mentioned := map[string]bool{}
	for _, l := range h.lines() {
		r := l.rec
		m := minuteOf(r)
		bytes[m] += l.size
		if incidentKind(r.Kind) && r.IncidentID != "" {
			incRecs[m]++
			if r.Kind != audit.IncidentClose {
				mentioned[r.IncidentID] = true
			}
		}
		if r.IncidentID == "" && strings.Contains(r.Summary, "were counted, not written one by one") {
			counted[m]++
		}
		if r.Kind == audit.IncidentUpdate && r.IncidentID != "" {
			updates[[2]any{m, r.IncidentID}]++
		}
	}
	ceiling := worstCaseBytes(DefaultAuditBudget, g)
	for m := 0; m < intervals; m++ {
		if bytes[m] > ceiling {
			t.Errorf("minute %d: %d audit bytes, ceiling %d", m, bytes[m], ceiling)
		}
		// Two rules flood: their budgets plus what the worker accepted.
		if incRecs[m] > 2*DefaultAuditBudget+g {
			t.Errorf("minute %d: %d incident records, want at most %d", m, incRecs[m], 2*DefaultAuditBudget+g)
		}
		if counted[m] == 0 && m > 0 {
			t.Errorf("minute %d: no count record, the flood did not exceed the budget", m)
		}
	}
	for k, c := range updates {
		if c > 1 {
			t.Errorf("incident %v: %d incident_update records in one interval", k, c)
		}
	}
	for _, l := range h.lines() {
		if (l.rec.Kind == audit.NotifyFailed || l.rec.Kind == audit.NotifySent) && l.rec.IncidentID != "" && !mentioned[l.rec.IncidentID] {
			t.Errorf("a notification for incident %s, which the log does not mention", l.rec.IncidentID)
		}
	}
	if total := len(h.lines()); total < 50 || len(mentioned) == 0 || incRecs[1] == 0 {
		t.Fatalf("%d records, %d incidents mentioned: the flood did not run", total, len(mentioned))
	}
}

// One rule's flood does not use up another rule's budget.
func TestOneRulesFloodLeavesAnotherRulesRecords(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	items := floodLines("198.51.100", 1, 3*DefaultAuditBudget)
	items = append(items, oomAt(cur("100"), t0))
	h.steps(items...)
	if err := h.runUntil("lines", func() bool { return h.savedCursor() == cur("100") }); err != nil {
		t.Fatal(err)
	}
	var oomID string
	for _, in := range h.store.List() {
		if in.RuleID == rules.IDOOMKill {
			oomID = in.ID
		}
	}
	found, counted := false, false
	for _, r := range h.records() {
		if r.Kind == audit.IncidentOpen && r.IncidentID == oomID {
			found = true
		}
		if r.Summary == fmt.Sprintf("%d more within 1m0s: %s", 2*DefaultAuditBudget, (&Daemon{}).aggText(rules.IDSSHBruteForce)) {
			counted = true
		}
	}
	if oomID == "" || !found || !counted {
		t.Fatalf("the OOM incident %q has no open record or the ssh flood no count: %v", oomID, h.records())
	}
}

// One OOM victim after another under the same process name: the store counts
// every one, the log has at most one update per interval.
func TestSameFingerprintFloodWritesOneUpdatePerInterval(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	var items []any
	for i := 0; i < 30; i++ {
		items = append(items, oomPid(cur(itoa(int64(i+1))), t0, 100+i, "worker"))
		if i == 15 {
			// A pass inside the interval does not lift the limit.
			items = append(items, func() { housekeepOnce(t, h) })
		}
	}
	items = append(items, func() { h.clk.add(time.Minute); housekeepOnce(t, h) })
	for i := 30; i < 60; i++ {
		items = append(items, oomPid(cur(itoa(int64(i+1))), t0.Add(time.Minute), 100+i, "worker"))
	}
	h.steps(items...)
	if err := h.runUntil("flood", func() bool { return h.savedCursor() == cur("60") }); err != nil {
		t.Fatal(err)
	}
	if in := h.store.List(); len(in) != 1 || in[0].Count != 60 {
		t.Fatalf("store = %+v, want one incident counted 60 times", in)
	}
	opens, updates := 0, map[int]int{}
	for _, r := range h.records() {
		switch {
		case r.IncidentID == "":
		case r.Kind == audit.IncidentOpen:
			opens++
		case r.Kind == audit.IncidentUpdate:
			updates[minuteOf(r)]++
		}
	}
	// One open and one update in the first interval, one update in the second.
	if opens != 1 || updates[0] != 1 || updates[1] != 1 || len(updates) != 2 {
		t.Fatalf("opens = %d, updates by minute = %v, kinds = %v", opens, updates, h.kinds())
	}
	// Update times that limit nothing any more are forgotten.
	h.clk.add(2 * time.Minute)
	housekeepOnce(t, h)
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	if n := len(h.d.updated); n != 0 {
		t.Fatalf("update times kept = %d", n)
	}
}

// A rule's window ends by itself when the next event comes after the
// interval, without a housekeeping pass.
func TestNoiseWindowEndsAtTheNextEvent(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	defer h.d.mu.Unlock()
	for i := 0; i < 3; i++ {
		if err := h.d.noise("k", audit.InputError, "event"); err != nil {
			t.Fatal(err)
		}
	}
	h.clk.add(2 * time.Minute)
	if err := h.d.noise("k", audit.InputError, "event"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range h.records() {
		got = append(got, r.Summary)
	}
	if len(got) != 3 || got[0] != "event" || !strings.HasPrefix(got[1], "2 more within") || got[2] != "event" {
		t.Fatalf("records = %q", got)
	}
}

// Every incident whose record was written stays known as mentioned, so the
// housekeeping retry writes no takeover record for it.
func TestLoggedIncidentsGetNoTakeoverRecord(t *testing.T) {
	h := newHarness(t, hopts{})
	h.notif.fail = func(int) error { return errTransient }
	h.steps(sshLine(cur("1"), t0, "203.0.113.1"), sshLine(cur("2"), t0, "203.0.113.2"))
	r := h.start()
	waitFor(t, "two failures", func() bool { return h.count(audit.NotifyFailed) == 2 })
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "retries", func() bool { return h.count(audit.NotifyFailed) == 4 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	for _, rec := range h.records() {
		if strings.Contains(rec.Summary, "found without a recorded notification") {
			t.Fatalf("takeover record for an incident the log mentions: %+v", rec)
		}
	}
}

// An incident whose record was over the budget and whose notification was
// not handed on (a daemon notice waited) is not mentioned: the housekeeping
// retry writes its takeover record.
func TestIncidentOverTheBudgetIsTakenOverWithARecord(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{AuditBudget: 1}})
	h.notif.fail = func(n int) error {
		if n == 2 {
			return errTransient
		}
		return nil
	}
	h.steps(sshLine(cur("1"), t0, "203.0.113.1"), func() {
		waitFor(t, "first sent", func() bool { return h.count(audit.NotifySent) == 1 })
		h.d.mu.Lock()
		h.d.alertEvent("k", "notice", "body")
		h.d.mu.Unlock()
		waitFor(t, "notice failed", func() bool { return h.count(audit.NotifyFailed) == 1 })
	}, sshLine(cur("2"), t0, "203.0.113.2"))
	r := h.start()
	waitFor(t, "second line", func() bool { return h.savedCursor() == cur("2") })
	if n := h.count(audit.IncidentOpen); n != 1 || len(h.notif.sent()) != 2 {
		t.Fatalf("incident_open records = %d, sends = %d, want only the first of each", n, len(h.notif.sent()))
	}
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "takeover", func() bool { return h.count(audit.NotifySent) == 3 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	var second string
	for _, in := range h.store.List() {
		if strings.Contains(in.Title, "203.0.113.2") {
			second = in.ID
		}
	}
	found := false
	for _, rec := range h.records() {
		if rec.IncidentID == second && strings.Contains(rec.Summary, "found without a recorded notification") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no takeover record for %s: %v", second, h.records())
	}
}

// Over the budget, the record of an incident whose notification the worker
// accepted is still written.
func TestAcceptedNotificationKeepsItsRecordOverTheBudget(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{AuditBudget: 1}})
	h.steps(sshLine(cur("1"), t0, "203.0.113.1"), sshLine(cur("2"), t0, "203.0.113.2"))
	if err := h.runUntil("sends", func() bool { return h.count(audit.NotifySent) == 2 }); err != nil {
		t.Fatal(err)
	}
	if n := h.count(audit.IncidentOpen); n != 2 {
		t.Fatalf("incident_open records = %d, want 2: both notifications were accepted", n)
	}
}

// The update limit applies to updates only: a reopen right after an update
// is written.
func TestReopenRightAfterAnUpdateIsWritten(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	h.steps(oomPid(cur("1"), t0, 100, "worker"), oomPid(cur("2"), t0, 101, "worker"), func() {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		if _, err := h.store.Close(h.store.List()[0].ID); err != nil {
			t.Error(err)
		}
	}, oomPid(cur("3"), t0, 102, "worker"))
	if err := h.runUntil("lines", func() bool { return h.savedCursor() == cur("3") }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.IncidentReopen) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

// Idle closes of the housekeeping pass go through the same budget.
func TestIdleClosesAreBudgeted(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true, setup: func(h *harness) {
		writeIncidents(t, h, 3*DefaultAuditBudget, result.Low, t0.Add(-8*24*time.Hour))
	}})
	housekeepOnce(t, h)
	h.d.mu.Lock()
	err := h.d.flushNoise(true)
	h.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	closes, counted := 0, false
	for _, r := range h.records() {
		if r.Kind == audit.IncidentClose {
			closes++
		}
		if strings.HasPrefix(r.Summary, itoa(int64(2*DefaultAuditBudget))+" more within") {
			counted = true
		}
	}
	if closes != DefaultAuditBudget || !counted {
		t.Fatalf("close records = %d, counted = %v: %v", closes, counted, h.kinds())
	}
}

// Every ordinary summary is cut to maxRecordSummary bytes.
func TestRecordSummariesAreCut(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.mu.Lock()
	err := h.d.record(audit.InputError, "", "", strings.Repeat("a", 3000))
	h.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if rs := h.records(); len(rs) != 1 || len(rs[0].Summary) != maxRecordSummary {
		t.Fatalf("records = %d, summary length = %d", len(rs), len(rs[0].Summary))
	}
}

// The package comment's arithmetic is written for these values.
func TestAuditArithmeticValues(t *testing.T) {
	if maxNotices != 8 || DefaultAuditBudget != 10 || maxRecordSummary != 512 || DefaultNoiseInterval != time.Minute || DefaultHousekeepingInterval != 30*time.Second {
		t.Fatal("a value of the audit volume arithmetic changed: update the package comment")
	}
}

// Takeover records of one pass go through the budget of their rule too: over
// it, only the incidents whose notification was accepted get one.
func TestTakeoverRecordsAreBudgeted(t *testing.T) {
	const g = 2
	seeds := make([]seed, DefaultAuditBudget+5)
	for i := range seeds {
		seeds[i] = seed{incident.StateOpen, true, false}
	}
	h := newHarness(t, hopts{opt: Options{GlobalPerMinute: g}, setup: func(h *harness) { writeSeeds(t, h, seeds) }})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h)
	waitFor(t, "sends", func() bool { return h.count(audit.NotifySent) == g })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rec := range h.records() {
		if strings.Contains(rec.Summary, "found without a recorded notification") {
			n++
		}
	}
	if n < DefaultAuditBudget || n > DefaultAuditBudget+g {
		t.Fatalf("takeover records = %d, want between %d and %d", n, DefaultAuditBudget, DefaultAuditBudget+g)
	}
}

// A limited update does not use up the budget of its rule: after a flood of
// updates of one incident, new incidents of the same rule still get their
// open records.
func TestLimitedUpdatesLeaveTheRuleBudget(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	var items []any
	n := 0
	next := func() string { n++; return cur(itoa(int64(n))) }
	for i := 0; i < 3*DefaultAuditBudget; i++ {
		items = append(items, oomPid(next(), t0, 100+i, "worker"))
	}
	const fresh = DefaultAuditBudget - 2
	for i := 0; i < fresh; i++ {
		items = append(items, oomPid(next(), t0, 500+i, fmt.Sprintf("other%d", i)))
	}
	h.steps(items...)
	if err := h.runUntil("flood", func() bool { return h.savedCursor() == cur(itoa(int64(n))) }); err != nil {
		t.Fatal(err)
	}
	opens, updates := 0, 0
	for _, r := range h.records() {
		switch {
		case r.IncidentID == "":
		case r.Kind == audit.IncidentOpen:
			opens++
		case r.Kind == audit.IncidentUpdate:
			updates++
		}
	}
	// The flooded incident has its open and its one update of the interval;
	// the rest of the budget went to the new incidents, not to the updates
	// the limit kept out.
	if opens != 1+fresh || updates != 1 {
		t.Fatalf("opens = %d, updates = %d, want %d and 1: %v", opens, updates, 1+fresh, h.kinds())
	}
}

// The closes one signal causes share the budget of the signal's rule: an
// Apply that closes more idle incidents than the budget allows writes the
// budget and counts the rest.
func TestAutoClosesOfOneSignalShareTheRuleBudget(t *testing.T) {
	const idle = DefaultAuditBudget + 5
	h := newHarness(t, hopts{noWorker: true, store: []incident.Option{incident.WithIdleClose(time.Hour)}, setup: func(h *harness) {
		writeIncidents(t, h, idle, result.Low, t0.Add(-2*time.Hour))
	}})
	h.steps(sshLine(cur("1"), t0, "203.0.113.9"))
	if err := h.runUntil("line", func() bool { return h.savedCursor() == cur("1") }); err != nil {
		t.Fatal(err)
	}
	closes, counted := 0, false
	for _, r := range h.records() {
		if r.Kind == audit.IncidentClose {
			closes++
		}
		// The closes over the budget and the open record of the signal itself.
		if strings.HasPrefix(r.Summary, itoa(int64(idle-DefaultAuditBudget+1))+" more within") {
			counted = true
		}
	}
	if closes != DefaultAuditBudget || !counted {
		t.Fatalf("close records = %d, counted = %v: %v", closes, counted, h.kinds())
	}
}
