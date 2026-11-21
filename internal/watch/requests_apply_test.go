package watch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
	}{
		{"unknown id", requests.ActionAck, incident.StateOpen, "abcdef0123456789", "no such incident"},
		{"ack of a closed incident", requests.ActionAck, incident.StateClosed, "", "cannot move from closed to acked"},
		{"close of a closed incident", requests.ActionClose, incident.StateClosed, "", "already closed"},
		{"ack of an acked incident", requests.ActionAck, incident.StateAcked, "", "already acked"},
		{"unknown action", requests.Action("reopen"), incident.StateOpen, "", "neither ack nor close"},
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

// The housekeeping pass runs on the injected tick source.
func TestHousekeepingRunsOnTheInjectedTick(t *testing.T) {
	tick := make(chan time.Time, 1)
	h := newHarness(t, hopts{noWorker: true, opt: Options{HousekeepingTick: tick}})
	in := openIncident(t, h, "1", "t", false)
	h.d.deps.Requests = (&spool{batch: requests.Batch{Items: []requests.Item{accepted("req-a", requests.ActionAck, in.ID, "")}}}).ops()
	h.script("", fake.Script{Follow: true})
	r := h.start()
	tick <- t0
	waitFor(t, "ack", func() bool { return h.count(audit.IncidentAck) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}
