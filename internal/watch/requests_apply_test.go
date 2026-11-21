package watch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/requests"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// openIncident stores an open incident of key with the given title; notify
// sets whether it wants a notification.
func openIncident(t *testing.T, h *harness, key, title string, notify bool) incident.Incident {
	t.Helper()
	res, err := h.store.Apply(event.Signal{RuleID: "r", Fingerprint: event.FingerprintOf("x", key), Severity: result.High, Time: h.clk.now(), Notify: notify},
		incident.Display{Title: title, Summary: "s"})
	if err != nil {
		t.Fatal(err)
	}
	return res.Incident
}

func accepted(name string, a requests.Action, id, note string) requests.Item {
	return requests.Item{Name: name, Request: requests.Request{Action: a, IncidentID: id, Note: note, RequestedAt: t0.Add(-time.Hour)}}
}

func stateOf(t *testing.T, h *harness, id string) incident.State {
	t.Helper()
	in, ok := h.store.Get(id)
	if !ok {
		t.Fatalf("incident %s is gone", id)
	}
	return in.State
}

// recordsOf returns the records of kind k.
func recordsOf(h *harness, k audit.Kind) []audit.Record {
	var out []audit.Record
	for _, r := range h.records() {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

// An ack and then a close through the real spool: each is applied, audited
// with the incident's id and fingerprint, and its file is removed; the log
// verifies.
func TestRequestAckAndCloseRoundTrip(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	h.d.deps.Requests = StateRequests(h.path)
	in := openIncident(t, h, "1", "t", false)
	for _, c := range []struct {
		action requests.Action
		kind   audit.Kind
		state  incident.State
	}{
		{requests.ActionAck, audit.IncidentAck, incident.StateAcked},
		{requests.ActionClose, audit.IncidentClose, incident.StateClosed},
	} {
		name, err := requests.Submit(h.path, requests.Request{Action: c.action, IncidentID: in.ID, Note: "seen", RequestedAt: t0.Add(-time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		housekeepOnce(t, h)
		if s := stateOf(t, h, in.ID); s != c.state {
			t.Fatalf("%s: state = %s, want %s", c.action, s, c.state)
		}
		recs := recordsOf(h, c.kind)
		if len(recs) != 1 || recs[0].IncidentID != in.ID || recs[0].Fingerprint != string(in.Fingerprint) || !strings.Contains(recs[0].Summary, name) {
			t.Fatalf("%s records = %+v", c.kind, recs)
		}
		if b, err := requests.Pending(h.path); err != nil || len(b.Items) != 0 {
			t.Fatalf("spool after the pass: %+v, %v", b, err)
		}
	}
	if n := h.count(audit.RequestRejected); n != 0 {
		t.Fatalf("request_rejected = %d, want 0", n)
	}
	h.verify()
}

// A Remove that keeps failing for an applied request: the request is neither
// applied nor audited again, Remove is tried on every pass, and the name is
// forgotten once it leaves the listing.
func TestAppliedRequestNotReappliedWhileRemoveFails(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	in := openIncident(t, h, "1", "t", false)
	sp := &spool{removeE: errors.New("busy"), batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}}
	h.d.deps.Requests = sp.ops()
	for i := 0; i < 3; i++ {
		housekeepOnce(t, h)
	}
	if a, r := h.count(audit.IncidentAck), h.count(audit.RequestRejected); a != 1 || r != 0 {
		t.Fatalf("incident_ack = %d, request_rejected = %d after 3 passes, want 1 and 0", a, r)
	}
	if len(sp.removed) != 3 {
		t.Fatalf("Remove calls = %q, want 3", sp.removed)
	}
	sp.batch = requests.Batch{}
	housekeepOnce(t, h)
	if len(h.d.rejAudited) != 0 {
		t.Fatalf("memory = %v after the name left the listing", h.d.rejAudited)
	}
	h.verify()
}

// The replay after a crash between the record and Remove (a new process has
// no memory): the target state is reached, so the replay writes
// request_rejected "already acked", never a second incident_ack.
func TestReplayedRequestWritesNoSecondAck(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	in := openIncident(t, h, "1", "t", false)
	sp := &spool{removeE: errors.New("crash"), batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}}
	h.d.deps.Requests = sp.ops()
	housekeepOnce(t, h)
	clear(h.d.rejAudited) // the restart
	sp.removeE = nil
	housekeepOnce(t, h)
	rej := recordsOf(h, audit.RequestRejected)
	if h.count(audit.IncidentAck) != 1 || len(rej) != 1 || !strings.Contains(rej[0].Summary, "already acked") {
		t.Fatalf("records = %+v", h.records())
	}
	h.verify()
}

// A request the store refuses is audited once as request_rejected with the
// reason, changes nothing and is removed.
func TestInvalidRequestRejectedOnceAndRemoved(t *testing.T) {
	cases := []struct {
		name   string
		action requests.Action
		state  incident.State // the state the incident is put in first
		id     string         // overrides the incident's id
		reason string
		known  bool // the record carries the incident's id and fingerprint
	}{
		{"unknown id", requests.ActionAck, incident.StateOpen, "abcdef0123456789", "no such incident", false},
		{"ack of a closed incident", requests.ActionAck, incident.StateClosed, "", "cannot move from closed to acked", true},
		{"close of a closed incident", requests.ActionClose, incident.StateClosed, "", "already closed", true},
		{"ack of an acked incident", requests.ActionAck, incident.StateAcked, "", "already acked", true},
		{"unknown action", requests.Action("reopen"), incident.StateOpen, "", "neither ack nor close", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{noWorker: true})
			in := openIncident(t, h, "1", "t", false)
			switch c.state {
			case incident.StateAcked:
				_, _ = h.store.Ack(in.ID)
			case incident.StateClosed:
				_, _ = h.store.Close(in.ID)
			}
			id := in.ID
			if c.id != "" {
				id = c.id
			}
			sp := &spool{removeE: errors.New("busy"), batch: requests.Batch{Items: []requests.Item{accepted("req-a", c.action, id, "")}}}
			h.d.deps.Requests = sp.ops()
			housekeepOnce(t, h)
			housekeepOnce(t, h)
			rej := recordsOf(h, audit.RequestRejected)
			if len(rej) != 1 || !strings.Contains(rej[0].Summary, c.reason) {
				t.Fatalf("request_rejected = %+v, want one with %q", rej, c.reason)
			}
			if h.count(audit.IncidentAck)+h.count(audit.IncidentClose) != 0 {
				t.Fatalf("kinds = %v", h.kinds())
			}
			// The incident's own history (audit show by incident) holds the
			// refusal of a known incident, and nothing for an unknown id.
			byID := 0
			for _, r := range rej {
				if (audit.Filter{IncidentID: in.ID}).Match(r) && r.Fingerprint == string(in.Fingerprint) {
					byID++
				}
			}
			if want := map[bool]int{true: 1, false: 0}[c.known]; byID != want || (!c.known && rej[0].IncidentID != "") {
				t.Fatalf("records of incident %s = %d, want %d: %+v", in.ID, byID, want, rej)
			}
			if s := stateOf(t, h, in.ID); s != c.state {
				t.Fatalf("state = %s, want %s unchanged", s, c.state)
			}
			if len(sp.removed) != 2 || sp.removed[0] != "req-a" {
				t.Fatalf("Remove calls = %q", sp.removed)
			}
		})
	}
}

// A hostile note (control bytes, a token, too long) reaches the audit log
// only cleaned and then cut: the cleaned text of 300 control bytes is longer
// than the limit, so cutting before cleaning would exceed it.
func TestRequestNoteCleanedThenCut(t *testing.T) {
	for _, note := range []string{
		"\x1b[31m" + hostileToken + " " + strings.Repeat("x", 900),
		strings.Repeat("\x01", 300),
	} {
		h := newHarness(t, hopts{noWorker: true})
		in := openIncident(t, h, "1", "t", false)
		sp := &spool{batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, note)}}}
		h.d.deps.Requests = sp.ops()
		housekeepOnce(t, h)
		recs := recordsOf(h, audit.IncidentAck)
		if len(recs) != 1 {
			t.Fatalf("records = %+v", h.records())
		}
		s := recs[0].Summary
		if strings.ContainsAny(s, "\x1b\x01") || strings.Contains(s, hostileToken) {
			t.Fatalf("raw note in the audit record: %q", s)
		}
		_, part, ok := strings.Cut(s, "; note: ")
		if !ok || len(part) > maxRequestNote || len(part) < maxRequestNote-8 {
			t.Fatalf("note part is %d bytes, want cut to about %d: %q", len(part), maxRequestNote, s)
		}
		if strings.HasPrefix(note, "\x1b") && !strings.Contains(s, "[REDACTED]") {
			t.Fatalf("token not redacted: %q", s)
		}
	}
}

// RequestedAt is the writer's claim: it is in the summary as such, and the
// record time is the daemon clock.
func TestRequestedAtIsAClaimNotTheRecordTime(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	in := openIncident(t, h, "1", "t", false)
	it := accepted("req-a", requests.ActionAck, in.ID, "")
	it.Request.RequestedAt = time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	h.d.deps.Requests = (&spool{batch: requests.Batch{Items: []requests.Item{it}}}).ops()
	housekeepOnce(t, h)
	recs := recordsOf(h, audit.IncidentAck)
	if len(recs) != 1 || !recs[0].Time.Equal(h.clk.now()) || !strings.Contains(recs[0].Summary, "requested at 2001-02-03T04:05:06Z (the writer's claim)") {
		t.Fatalf("records = %+v", recs)
	}
}

// One pass applies at most requests.MaxPending requests; the rest wait for
// the next pass, and the ones applied are not applied again.
func TestRequestsBoundedPerPass(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	var items []requests.Item
	for i := 0; i < requests.MaxPending+5; i++ {
		items = append(items, accepted(fmt.Sprintf("req-%03d", i), requests.ActionAck, "abcdef0123456789", ""))
	}
	sp := &spool{batch: requests.Batch{Items: items}}
	h.d.deps.Requests = sp.ops()
	housekeepOnce(t, h)
	if n := h.count(audit.RequestRejected); n != requests.MaxPending || len(sp.removed) != requests.MaxPending {
		t.Fatalf("request_rejected = %d, removed = %d after one pass, want %d", n, len(sp.removed), requests.MaxPending)
	}
	sp.removeE = errors.New("busy") // the listing stays the same
	housekeepOnce(t, h)
	if n := h.count(audit.RequestRejected); n != requests.MaxPending+5 {
		t.Fatalf("request_rejected = %d after the second pass, want %d", n, requests.MaxPending+5)
	}
}

// The records of applied requests are not held to the per-rule budget of
// admit: three acks of one rule's incidents with a budget of one are all
// written.
func TestRequestRecordsOutsideTheRuleBudget(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true, opt: Options{AuditBudget: 1}})
	var items []requests.Item
	for i := 0; i < 3; i++ {
		in := openIncident(t, h, fmt.Sprint(i), "t", false)
		items = append(items, accepted(fmt.Sprintf("req-%d", i), requests.ActionAck, in.ID, ""))
	}
	h.d.deps.Requests = (&spool{batch: requests.Batch{Items: items}}).ops()
	housekeepOnce(t, h)
	if n := h.count(audit.IncidentAck); n != 3 {
		t.Fatalf("incident_ack = %d, want 3: %v", n, h.kinds())
	}
}

// An ack or a close stops a notification still pending for the incident: the
// retry that is due in the same pass is not sent. The other incident, whose
// retry is due as well, shows the pass did retry.
func TestAckOrCloseStopsPendingNotification(t *testing.T) {
	for _, a := range []requests.Action{requests.ActionAck, requests.ActionClose} {
		t.Run(string(a), func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.notif.fail = func(n int) error {
				if n <= 2 {
					return errTransient
				}
				return nil
			}
			h.script("", fake.Script{Follow: true})
			r := h.start()
			waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
			h.d.mu.Lock()
			ia := openIncident(t, h, "a", "incident-A", true)
			openIncident(t, h, "b", "incident-B", true)
			h.d.mu.Unlock()
			housekeepOnce(t, h) // both are taken over and fail
			waitFor(t, "failures", func() bool { return h.count(audit.NotifyFailed) == 2 })
			h.d.mu.Lock()
			h.d.deps.Requests = (&spool{batch: requests.Batch{Items: []requests.Item{accepted("req-a", a, ia.ID, "")}}}).ops()
			h.d.mu.Unlock()
			h.clk.add(2 * time.Hour) // both retries are due
			housekeepOnce(t, h)
			waitFor(t, "retry of B", func() bool { return h.count(audit.NotifySent) == 1 })
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			var titles []string
			for _, m := range h.notif.sent() {
				titles = append(titles, m.Title)
			}
			if len(titles) != 3 || strings.Contains(titles[2], "incident-A") {
				t.Fatalf("sent = %q, want two failures and one retry of B only", titles)
			}
		})
	}
}

// restartDaemon builds a new process on the stores of h: a new daemon with
// a new worker and no memory, whose stream delivers items (see steps).
func restartDaemon(t *testing.T, h *harness, items ...any) {
	t.Helper()
	w, err := alert.NewWorker(h.notif, alert.Params{QueueSize: 16, PerIncidentInterval: 40 * time.Minute}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Clock = h.clk.now
	deps := h.d.deps
	deps.Worker = w
	d, err := New(deps, h.d.opt)
	if err != nil {
		t.Fatal(err)
	}
	h.d, h.worker = d, w
	h.steps(items...)
}

// A request whose Remove failed is replayed by the next process in its
// first request pass, at start, before a line of the new process can reopen
// the incident: the replay meets the state the previous process left and is
// rejected, the reopened incident is not closed or acked by the stale
// request, and its notification goes out.
func TestReplayAtStartMeetsTheStateBeforeAReopen(t *testing.T) {
	for _, c := range []struct {
		action requests.Action
		kind   audit.Kind
		reason string
	}{
		{requests.ActionClose, audit.IncidentClose, "already closed"},
		{requests.ActionAck, audit.IncidentAck, "cannot move from closed to acked"},
	} {
		t.Run(string(c.action), func(t *testing.T) {
			h := newHarness(t, hopts{})
			sp := &spool{removeE: errors.New("crash")}
			h.d.deps.Requests = sp.ops()
			h.steps(oomAt(cur("1"), t0))
			r := h.start()
			waitFor(t, "first occurrence", func() bool { return h.count(audit.NotifySent) == 1 })
			h.d.mu.Lock()
			id := h.store.List()[0].ID
			sp.batch = requests.Batch{Items: []requests.Item{accepted("req-a", c.action, id, "")}}
			h.d.mu.Unlock()
			housekeepOnce(t, h) // applied and audited, Remove fails
			if c.action == requests.ActionAck {
				h.d.mu.Lock()
				_, err := h.store.Close(id) // closed meanwhile, as by the idle sweep
				h.d.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			sp.removeE = errors.New("still failing")
			h.clk.add(3 * time.Hour)
			restartDaemon(t, h, oomAt(cur("2"), t0.Add(3*time.Hour)))
			r = h.start()
			waitFor(t, "reopen notified", func() bool { return h.count(audit.NotifySent) == 2 })
			housekeepOnce(t, h) // the first housekeeping pass of the new process
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			if n := h.count(c.kind); n != 1 {
				t.Fatalf("%s = %d, want 1 (no replay after the reopen): %v", c.kind, n, h.kinds())
			}
			rej := recordsOf(h, audit.RequestRejected)
			if len(rej) != 1 || !strings.Contains(rej[0].Summary, c.reason) {
				t.Fatalf("request_rejected = %+v, want one with %q", rej, c.reason)
			}
			var reopen audit.Record
			for _, r := range h.records() {
				if r.Kind == audit.IncidentReopen {
					reopen = r
				}
			}
			if reopen.Seq == 0 || rej[0].Seq > reopen.Seq {
				t.Fatalf("the replay was not handled at start, before the reopen: %v", h.kinds())
			}
			if s := stateOf(t, h, id); s != incident.StateOpen {
				t.Fatalf("state = %s, want open", s)
			}
			h.verify()
		})
	}
}

// A request record the audit log has no room for stops the pass with
// ErrAuditFull: the request is neither removed nor remembered, so it stays
// for the next start.
func TestRequestRecordAtTheAuditLimitIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true, auditMax: audit.ReserveBytes + 100})
	in := openIncident(t, h, "1", "t", false)
	sp := &spool{batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}}
	h.d.deps.Requests = sp.ops()
	h.d.mu.Lock()
	err := h.d.housekeep()
	h.d.mu.Unlock()
	if !errors.Is(err, ErrAuditFull) {
		t.Fatalf("housekeep = %v, want ErrAuditFull", err)
	}
	if len(sp.removed) != 0 || len(h.d.rejAudited) != 0 {
		t.Fatalf("removed = %q, memory = %v", sp.removed, h.d.rejAudited)
	}
}

// A store that cannot save stops the pass with the store's error: no record
// is written, and the request is neither removed nor remembered.
func TestRequestWithAFailingStoreIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	in := openIncident(t, h, "1", "t", false)
	sp := &spool{batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}}
	h.d.deps.Requests = sp.ops()
	h.storeDir.Close()
	h.d.mu.Lock()
	err := h.d.housekeep()
	h.d.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "incident store") {
		t.Fatalf("housekeep = %v, want the incident store error", err)
	}
	if h.count(audit.IncidentAck) != 0 || len(sp.removed) != 0 || len(h.d.rejAudited) != 0 {
		t.Fatalf("kinds = %v, removed = %q, memory = %v", h.kinds(), sp.removed, h.d.rejAudited)
	}
}

// The request name and the incident id are untrusted and reach the audit log
// only cleaned: each carries the token and a control byte.
func TestRequestNameAndIncidentIDCleaned(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	it := accepted("req-\x1b[31m"+hostileToken, requests.ActionAck, hostileToken+"\x01", "")
	sp := &spool{batch: requests.Batch{Items: []requests.Item{it}}}
	h.d.deps.Requests = sp.ops()
	housekeepOnce(t, h)
	rej := recordsOf(h, audit.RequestRejected)
	if len(rej) != 1 {
		t.Fatalf("records = %+v", h.records())
	}
	s := rej[0].Summary
	if strings.ContainsAny(s, "\x1b\x01") || strings.Contains(s, hostileToken) || strings.Count(s, "[REDACTED]") < 2 {
		t.Fatalf("name or id not cleaned: %q", s)
	}
	if b, _ := os.ReadFile(filepath.Join(h.path, audit.FileName)); strings.Contains(string(b), hostileToken) {
		t.Fatal("raw token in the audit log")
	}
	if len(sp.removed) != 1 || sp.removed[0] != it.Name {
		t.Fatalf("Remove calls = %q, want the raw name", sp.removed)
	}
}

// A closed tick source ends the housekeeping loop: no pass runs after the
// one at start, where a receive from the closed channel would run passes
// without end.
func TestClosedHousekeepingTickEndsTheLoop(t *testing.T) {
	var calls atomic.Int64
	ops := (&spool{}).ops()
	ops.Pending = func() (requests.Batch, error) { calls.Add(1); return requests.Batch{}, nil }
	tick := make(chan time.Time)
	close(tick)
	h := newHarness(t, hopts{noWorker: true, reqs: ops, opt: Options{HousekeepingTick: tick}})
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start pass", func() bool { return calls.Load() >= 1 })
	time.Sleep(100 * time.Millisecond)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("request passes = %d, want 1 (the one at start)", n)
	}
}

// The housekeeping pass runs on the injected tick source.
func TestHousekeepingRunsOnTheInjectedTick(t *testing.T) {
	tick := make(chan time.Time, 1)
	h := newHarness(t, hopts{noWorker: true, opt: Options{HousekeepingTick: tick}})
	in := openIncident(t, h, "1", "t", false)
	sp := &spool{}
	h.d.deps.Requests = sp.ops()
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	// The request arrives after the pass at start; only a tick applies it.
	h.d.mu.Lock()
	sp.batch = requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}
	h.d.mu.Unlock()
	tick <- t0
	waitFor(t, "ack", func() bool { return h.count(audit.IncidentAck) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}
