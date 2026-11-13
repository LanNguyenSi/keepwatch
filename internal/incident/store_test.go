package incident

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func openDir(t *testing.T) (*securefile.Dir, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	d, err := securefile.OpenDir(p, true, securefile.DefaultOwnerOf)
	if err != nil {
		t.Fatalf("OpenDir: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d, p
}

func newStore(t *testing.T) (*Store, *securefile.Dir, string) {
	t.Helper()
	d, p := openDir(t)
	s, err := Open(d)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, d, p
}

func fp(n int) event.Fingerprint {
	return event.Fingerprint(fmt.Sprintf("%064x", n))
}

func sig(f event.Fingerprint, notify bool, at time.Time) event.Signal {
	return event.Signal{RuleID: "r", Fingerprint: f, Severity: result.Medium, Time: at, Notify: notify}
}

var disp = Display{Title: "title", Summary: "summary"}

func mustApply(t *testing.T, s *Store, sg event.Signal, d Display) Result {
	t.Helper()
	r, err := s.Apply(sg, d)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return r
}

// setState puts the incident into a state through the store's own edges.
func setState(t *testing.T, s *Store, id string, st State) {
	t.Helper()
	switch st {
	case StateAcked:
		if _, err := s.Ack(id); err != nil {
			t.Fatal(err)
		}
	case StateClosed:
		if _, err := s.Close(id); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplyOpensUnknownFingerprint(t *testing.T) {
	for _, notify := range []bool{true, false} {
		s, _, _ := newStore(t)
		r := mustApply(t, s, sig(fp(1), notify, t0), disp)
		if r.Outcome != Opened {
			t.Fatalf("outcome = %v", r.Outcome)
		}
		in := r.Incident
		if in.State != StateOpen || in.Count != 1 || !in.FirstSeen.Equal(t0) || !in.LastSeen.Equal(t0) ||
			in.Title != "title" || in.Summary != "summary" || in.RuleID != "r" || in.Severity != result.Medium ||
			in.Fingerprint != fp(1) || in.ReopenCount != 0 || in.Notify != notify {
			t.Fatalf("incident = %+v", in)
		}
		if r.Notify != notify {
			t.Fatalf("notify = %v for signal notify %v", r.Notify, notify)
		}
		if got, ok := s.Get(in.ID); !ok || got != in {
			t.Fatalf("Get = %+v %v", got, ok)
		}
	}
}

func TestApplyUpdatesOpenAndAckedNeverNotifies(t *testing.T) {
	for _, st := range []State{StateOpen, StateAcked} {
		s, _, _ := newStore(t)
		id := mustApply(t, s, sig(fp(1), true, t0), disp).Incident.ID
		setState(t, s, id, st)
		t1 := t0.Add(time.Minute)
		r := mustApply(t, s, sig(fp(1), true, t1), Display{Title: "t2", Summary: "s2"})
		if r.Outcome != Updated || r.Notify {
			t.Fatalf("%s: outcome %v notify %v", st, r.Outcome, r.Notify)
		}
		in := r.Incident
		if in.State != st || in.Count != 2 || !in.LastSeen.Equal(t1) || !in.FirstSeen.Equal(t0) ||
			in.Title != "t2" || in.Summary != "s2" || in.ID != id || in.ReopenCount != 0 {
			t.Fatalf("%s: incident = %+v", st, in)
		}
		if len(s.List()) != 1 {
			t.Fatalf("list = %d", len(s.List()))
		}
	}
}

func TestApplyLastSeenNeverMovesBackwards(t *testing.T) {
	s, _, _ := newStore(t)
	mustApply(t, s, sig(fp(1), false, t0), disp)
	r := mustApply(t, s, sig(fp(1), false, t0.Add(-time.Hour)), disp)
	if !r.Incident.LastSeen.Equal(t0) || r.Incident.Count != 2 {
		t.Fatalf("incident = %+v", r.Incident)
	}
}

func TestApplySeverityOnlyEscalates(t *testing.T) {
	s, _, _ := newStore(t)
	mustApply(t, s, sig(fp(1), false, t0), disp) // medium
	hi := sig(fp(1), false, t0)
	hi.Severity = result.High
	if r := mustApply(t, s, hi, disp); r.Incident.Severity != result.High {
		t.Fatalf("severity = %s", r.Incident.Severity)
	}
	lo := sig(fp(1), false, t0)
	lo.Severity = result.Low
	if r := mustApply(t, s, lo, disp); r.Incident.Severity != result.High {
		t.Fatalf("severity lowered to %s", r.Incident.Severity)
	}
}

func TestApplyReopensClosed(t *testing.T) {
	cases := []struct {
		name         string
		first, again bool
		wantNotify   bool
	}{
		{"both notify", true, true, true},
		{"signal does not notify", true, false, false},
		{"only the reopening signal notifies", false, true, true},
		{"neither notifies", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := newStore(t)
			id := mustApply(t, s, sig(fp(1), c.first, t0), disp).Incident.ID
			setState(t, s, id, StateClosed)
			t1 := t0.Add(time.Hour)
			r := mustApply(t, s, sig(fp(1), c.again, t1), disp)
			if r.Outcome != Reopened || r.Notify != c.wantNotify {
				t.Fatalf("outcome %v notify %v", r.Outcome, r.Notify)
			}
			in := r.Incident
			if in.State != StateOpen || in.ReopenCount != 1 || in.Count != 2 || !in.LastSeen.Equal(t1) ||
				in.ID != id || in.Notify != c.again {
				t.Fatalf("incident = %+v", in)
			}
			// A second round counts again.
			setState(t, s, id, StateClosed)
			r = mustApply(t, s, sig(fp(1), c.again, t1.Add(time.Hour)), disp)
			if r.Outcome != Reopened || r.Incident.ReopenCount != 2 {
				t.Fatalf("second reopen: %v %+v", r.Outcome, r.Incident)
			}
		})
	}
}

func TestNotifyOnlyForOpenedAndReopened(t *testing.T) {
	s, _, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), true, t0), disp).Incident.ID
	for i := 0; i < 3; i++ {
		if r := mustApply(t, s, sig(fp(1), true, t0), disp); r.Notify {
			t.Fatalf("update %d notified", i)
		}
	}
	setState(t, s, id, StateAcked)
	if r := mustApply(t, s, sig(fp(1), true, t0), disp); r.Notify {
		t.Fatal("update of an acked incident notified")
	}
	setState(t, s, id, StateClosed)
	if r := mustApply(t, s, sig(fp(1), true, t0), disp); !r.Notify || r.Outcome != Reopened {
		t.Fatalf("reopen: %+v", r)
	}
}

func TestApplyCutsDisplayAtRuneBoundary(t *testing.T) {
	s, _, _ := newStore(t)
	title := strings.Repeat("ä", MaxTitleRunes+5)
	sum := strings.Repeat("ü", MaxSummaryRunes+5)
	r := mustApply(t, s, sig(fp(1), false, t0), Display{Title: title, Summary: sum})
	if got := []rune(r.Incident.Title); len(got) != MaxTitleRunes || string(got) != strings.Repeat("ä", MaxTitleRunes) {
		t.Fatalf("title has %d runes", len(got))
	}
	if got := []rune(r.Incident.Summary); len(got) != MaxSummaryRunes {
		t.Fatalf("summary has %d runes", len(got))
	}
	// Exactly at the limit stays whole.
	exact := strings.Repeat("ä", MaxTitleRunes)
	r = mustApply(t, s, sig(fp(2), false, t0), Display{Title: exact})
	if r.Incident.Title != exact {
		t.Fatal("title at the limit was cut")
	}
	// Ten bytes over the byte count but under the rune count is not cut.
	r = mustApply(t, s, sig(fp(3), false, t0), Display{Summary: strings.Repeat("ü", MaxSummaryRunes)})
	if len([]rune(r.Incident.Summary)) != MaxSummaryRunes {
		t.Fatal("summary of exactly the limit was cut")
	}
}

func TestApplyDoesNotReadSignalText(t *testing.T) {
	s, _, _ := newStore(t)
	sg := sig(fp(1), false, t0)
	sg.Subject, sg.Summary = "raw-subject-secret", "raw-summary-secret"
	r := mustApply(t, s, sg, disp)
	if strings.Contains(r.Incident.Title+r.Incident.Summary, "secret") {
		t.Fatalf("raw signal text leaked: %+v", r.Incident)
	}
}

func TestApplyRejectsBadFingerprint(t *testing.T) {
	s, _, _ := newStore(t)
	for _, f := range []event.Fingerprint{"", "ABCDEF12", "xyz", event.Fingerprint(strings.Repeat("a", 65)), "../etc", "1234-5678", "../.."} {
		if _, err := s.Apply(sig(f, false, t0), disp); !errors.Is(err, ErrInvalidSignal) {
			t.Fatalf("%q: err = %v", f, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("a bad signal created an incident")
	}
}

func TestTransitions(t *testing.T) {
	type tc struct {
		from State
		ack  bool // Ack allowed
		cls  bool // Close allowed
	}
	for _, c := range []tc{
		{StateOpen, true, true},
		{StateAcked, false, true},
		{StateClosed, false, false},
	} {
		for _, action := range []string{"ack", "close"} {
			s, _, _ := newStore(t)
			id := mustApply(t, s, sig(fp(1), false, t0), disp).Incident.ID
			setState(t, s, id, c.from)
			var in Incident
			var err error
			to := StateClosed
			allowed := c.cls
			if action == "ack" {
				in, err = s.Ack(id)
				to, allowed = StateAcked, c.ack
			} else {
				in, err = s.Close(id)
			}
			if allowed {
				if err != nil || in.State != to {
					t.Fatalf("%s from %s: %v %+v", action, c.from, err, in)
				}
				if got, _ := s.Get(id); got.State != to {
					t.Fatalf("%s from %s: stored state %s", action, c.from, got.State)
				}
				continue
			}
			var te *TransitionError
			if !errors.Is(err, ErrInvalidTransition) || !errors.As(err, &te) || te.ID != id || te.From != c.from || te.To != to {
				t.Fatalf("%s from %s: err = %v", action, c.from, err)
			}
			if got, _ := s.Get(id); got.State != c.from {
				t.Fatalf("%s from %s changed the state to %s", action, c.from, got.State)
			}
		}
	}
}

func TestTransitionUnknownID(t *testing.T) {
	s, _, _ := newStore(t)
	mustApply(t, s, sig(fp(1), false, t0), disp)
	for _, id := range []string{"nope", ""} {
		if _, err := s.Ack(id); !errors.Is(err, ErrUnknownIncident) {
			t.Fatalf("Ack(%q) = %v", id, err)
		}
		if _, err := s.Close(id); !errors.Is(err, ErrUnknownIncident) {
			t.Fatalf("Close(%q) = %v", id, err)
		}
	}
}

func TestPersistence(t *testing.T) {
	s, d, p := newStore(t)
	a := mustApply(t, s, sig(fp(1), true, t0), disp).Incident
	b := mustApply(t, s, sig(fp(2), false, t0.Add(time.Second)), Display{Title: "b", Summary: "bs"}).Incident
	if _, err := s.Ack(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Close(b.ID); err != nil {
		t.Fatal(err)
	}
	want := s.List()
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.List()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("reloaded = %+v, want %+v", got, want)
	}
	raw, err := os.ReadFile(filepath.Join(p, FileName))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || doc["schema_version"] != float64(SchemaVersion) {
		t.Fatalf("file = %s (%v)", raw, err)
	}
	fi, _ := os.Stat(filepath.Join(p, FileName))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	// The reloaded store keeps working: the fingerprint is recognised.
	if r := mustApply(t, s2, sig(fp(2), true, t0.Add(time.Hour)), disp); r.Outcome != Reopened {
		t.Fatalf("outcome after reload = %v", r.Outcome)
	}
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	s, _, p := newStore(t)
	if len(s.List()) != 0 {
		t.Fatal("not empty")
	}
	if _, err := os.Stat(filepath.Join(p, FileName)); !os.IsNotExist(err) {
		t.Fatalf("Open created the file: %v", err)
	}
}

func TestOpenNilDir(t *testing.T) {
	if _, err := Open(nil); err == nil {
		t.Fatal("no error")
	}
}

func item(id string, f event.Fingerprint, st State, last time.Time) wireItem {
	return wireItem{ID: id, Fingerprint: string(f), RuleID: "r", Severity: "medium", State: string(st),
		Title: "t", Summary: "s", Count: 1, FirstSeen: last, LastSeen: last}
}

func writeDoc(t *testing.T, p string, v int, items []wireItem) {
	t.Helper()
	b, err := json.Marshal(fileDoc{SchemaVersion: v, Incidents: items})
	if err != nil {
		t.Fatal(err)
	}
	writeRaw(t, p, b)
}

func writeRaw(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p, FileName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenReportsProblemsAndLeavesFileAlone(t *testing.T) {
	good := item("aaaaaaaa", fp(1), StateOpen, t0)
	many := make([]wireItem, MaxIncidents+1)
	for i := range many {
		many[i] = item(fmt.Sprintf("id%d", i), fp(i+1), StateClosed, t0)
	}
	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"not json", []byte("{garbage"), ErrCorrupt},
		{"empty file", []byte(""), ErrCorrupt},
		{"truncated", []byte(`{"schema_version":2,"incidents":[`), ErrCorrupt},
		{"no schema_version", []byte(`{"incidents":[]}`), ErrCorrupt},
		{"newer schema", mustJSON(fileDoc{SchemaVersion: SchemaVersion + 1, Incidents: []wireItem{good}}), ErrSchema},
		{"schema zero", mustJSON(fileDoc{SchemaVersion: 0}), ErrSchema},
		{"newer schema with other fields", []byte(`{"schema_version":3,"incidents":"nope","extra":1}`), ErrSchema},
		{"unknown field", []byte(`{"schema_version":2,"incidents":[],"x":1}`), ErrCorrupt},
		{"data after document", append(mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{good}}), []byte(" {}")...), ErrCorrupt},
		{"unknown state", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("a", fp(1), "weird", t0)}}), ErrCorrupt},
		{"empty id", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("", fp(1), StateOpen, t0)}}), ErrCorrupt},
		{"empty fingerprint", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("a", "", StateOpen, t0)}}), ErrCorrupt},
		{"duplicate id", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("a", fp(1), StateOpen, t0), item("a", fp(2), StateOpen, t0)}}), ErrCorrupt},
		{"duplicate fingerprint", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("a", fp(1), StateOpen, t0), item("b", fp(1), StateOpen, t0)}}), ErrCorrupt},
		{"over the cap", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: many}), ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p := openDir(t)
			writeRaw(t, p, c.raw)
			s, err := Open(d)
			if !errors.Is(err, c.want) || s != nil {
				t.Fatalf("Open = %v, %v; want %v", s, err, c.want)
			}
			if got, _ := os.ReadFile(filepath.Join(p, FileName)); string(got) != string(c.raw) {
				t.Fatal("the file was replaced")
			}
		})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestOpenSchemaErrorMentionsVersions(t *testing.T) {
	d, p := openDir(t)
	writeDoc(t, p, 7, nil)
	_, err := Open(d)
	if !errors.Is(err, ErrSchema) || !strings.Contains(err.Error(), "7") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenRefusesOversizedFile(t *testing.T) {
	d, p := openDir(t)
	writeRaw(t, p, []byte(`{"schema_version":2,"incidents":[],"pad":"`+strings.Repeat("x", MaxFileSize)+`"}`))
	if _, err := Open(d); !errors.Is(err, securefile.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenReportsUntrustedFile(t *testing.T) {
	d, p := openDir(t)
	writeRaw(t, p, mustJSON(fileDoc{SchemaVersion: SchemaVersion}))
	if err := os.Chmod(filepath.Join(p, FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(d); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("err = %v", err)
	}
}

func seed(t *testing.T, p string, n int, st func(i int) State, last func(i int) time.Time) []wireItem {
	t.Helper()
	items := make([]wireItem, n)
	for i := range items {
		items[i] = item(fmt.Sprintf("seed%03d", i), fp(i+1), st(i), last(i))
	}
	writeDoc(t, p, SchemaVersion, items)
	return items
}

func TestCapEvictsOldestClosedFirst(t *testing.T) {
	d, p := openDir(t)
	// Closed incidents with LastSeen decreasing by index: the last one is oldest.
	seed(t, p, MaxIncidents, func(int) State { return StateClosed },
		func(i int) time.Time { return t0.Add(-time.Duration(i) * time.Minute) })
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sig(fp(10000), true, t0), disp)
	oldest := fmt.Sprintf("seed%03d", MaxIncidents-1)
	if r.Outcome != Opened || len(r.Evicted) != 1 || r.Evicted[0].ID != oldest {
		t.Fatalf("result = %+v", r)
	}
	if _, ok := s.Get(oldest); ok {
		t.Fatal("oldest closed incident still there")
	}
	if len(s.List()) != MaxIncidents {
		t.Fatalf("size = %d", len(s.List()))
	}
	// The eviction is persisted.
	s2, err := Open(d)
	if err != nil || len(s2.List()) != MaxIncidents {
		t.Fatalf("reload: %v, %d", err, len(s2.List()))
	}
	if _, ok := s2.Get(oldest); ok {
		t.Fatal("evicted incident came back")
	}
}

func TestCapNeverEvictsOpenOrAcked(t *testing.T) {
	d, p := openDir(t)
	// Open and acked incidents are OLDER than the single closed one: the
	// closed one must go, not the oldest.
	seed(t, p, MaxIncidents, func(i int) State {
		switch {
		case i == 7:
			return StateClosed
		case i%2 == 0:
			return StateOpen
		}
		return StateAcked
	}, func(i int) time.Time {
		if i == 7 {
			return t0
		}
		return t0.Add(-time.Hour - time.Duration(i)*time.Minute)
	})
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sig(fp(10000), false, t0.Add(time.Minute)), disp)
	if len(r.Evicted) != 1 || r.Evicted[0].ID != "seed007" {
		t.Fatalf("evicted = %v", r.Evicted)
	}
	if len(s.List()) != MaxIncidents {
		t.Fatalf("size = %d", len(s.List()))
	}
}

func TestCapReopenNeedsNoEviction(t *testing.T) {
	d, p := openDir(t)
	seed(t, p, MaxIncidents, func(int) State { return StateClosed }, func(int) time.Time { return t0 })
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sig(fp(3), true, t0.Add(time.Minute)), disp)
	if r.Outcome != Reopened || len(r.Evicted) != 0 || len(s.List()) != MaxIncidents {
		t.Fatalf("result = %+v, size %d", r, len(s.List()))
	}
}

func TestCapBelowCapDoesNotEvict(t *testing.T) {
	d, p := openDir(t)
	seed(t, p, MaxIncidents-1, func(int) State { return StateClosed }, func(int) time.Time { return t0 })
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sig(fp(10000), false, t0), disp)
	if len(r.Evicted) != 0 || len(s.List()) != MaxIncidents {
		t.Fatalf("result = %+v, size %d", r, len(s.List()))
	}
}

func TestIDsAreDerivedFromFingerprint(t *testing.T) {
	s, _, _ := newStore(t)
	f := event.Fingerprint("0123456789abcdef" + strings.Repeat("0", 48))
	r := mustApply(t, s, sig(f, false, t0), disp)
	if r.Incident.ID != "01234567" {
		t.Fatalf("id = %q", r.Incident.ID)
	}
	// Same fingerprint in a fresh store: same id.
	s2, _, _ := newStore(t)
	if r2 := mustApply(t, s2, sig(f, false, t0), disp); r2.Incident.ID != r.Incident.ID {
		t.Fatalf("id not deterministic: %q vs %q", r2.Incident.ID, r.Incident.ID)
	}
	// Updates keep the id.
	if r3 := mustApply(t, s, sig(f, false, t0), disp); r3.Incident.ID != "01234567" {
		t.Fatalf("id changed to %q", r3.Incident.ID)
	}
}

func TestIDCollisionExtendsPrefix(t *testing.T) {
	s, _, _ := newStore(t)
	a := event.Fingerprint("abcdef12" + "34" + strings.Repeat("0", 54))
	b := event.Fingerprint("abcdef12" + "35" + strings.Repeat("0", 54))
	c := event.Fingerprint("abcdef12" + "34" + strings.Repeat("1", 54))
	ia := mustApply(t, s, sig(a, false, t0), disp).Incident.ID
	ib := mustApply(t, s, sig(b, false, t0), disp).Incident.ID
	ic := mustApply(t, s, sig(c, false, t0), disp).Incident.ID
	if ia != "abcdef12" || ib != "abcdef123" || ic != "abcdef1234" {
		t.Fatalf("ids = %q %q %q", ia, ib, ic)
	}
	seen := map[string]bool{}
	for _, in := range s.List() {
		if seen[in.ID] {
			t.Fatalf("duplicate id %q", in.ID)
		}
		seen[in.ID] = true
	}
}

func TestIDForShortFingerprint(t *testing.T) {
	s, _, _ := newStore(t)
	r := mustApply(t, s, sig("abc", false, t0), disp)
	if r.Incident.ID != "abc" {
		t.Fatalf("id = %q", r.Incident.ID)
	}
	// A longer fingerprint whose prefix equals an existing id stays unique.
	r = mustApply(t, s, sig("abcdef0123456789", false, t0), disp)
	if r.Incident.ID == "abc" || !strings.HasPrefix("abcdef0123456789", r.Incident.ID) {
		t.Fatalf("id = %q", r.Incident.ID)
	}
	// And the reverse: an id that is a full fingerprint already taken as a prefix.
	s2, _, _ := newStore(t)
	mustApply(t, s2, sig("abcdef01", false, t0), disp)
	r = mustApply(t, s2, sig("abcdef01", false, t0), disp)
	if r.Outcome != Updated {
		t.Fatalf("outcome = %v", r.Outcome)
	}
}

func TestIDStaysUniqueWhenFileIdEqualsFullFingerprint(t *testing.T) {
	d, p := openDir(t)
	f := event.Fingerprint("abcdef01")
	writeDoc(t, p, SchemaVersion, []wireItem{
		item("abcdef01", fp(1), StateOpen, t0),
		item("abcdef01-2", fp(2), StateOpen, t0),
	})
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sig(f, false, t0), disp)
	if r.Incident.ID != "abcdef01-3" {
		t.Fatalf("id = %q", r.Incident.ID)
	}
	// Only the first is taken: the plain full fingerprint is not suffixed.
	d2, p2 := openDir(t)
	writeDoc(t, p2, SchemaVersion, []wireItem{item("abcdef01", fp(1), StateOpen, t0)})
	s2, err := Open(d2)
	if err != nil {
		t.Fatal(err)
	}
	if r := mustApply(t, s2, sig(f, false, t0), disp); r.Incident.ID != "abcdef01-2" {
		t.Fatalf("id = %q", r.Incident.ID)
	}
}

func TestIDForSevenCharacterFingerprint(t *testing.T) {
	s, _, _ := newStore(t)
	if r := mustApply(t, s, sig("abcdef0", false, t0), disp); r.Incident.ID != "abcdef0" {
		t.Fatalf("id = %q", r.Incident.ID)
	}
}

func TestApplyCutsOneRuneOver(t *testing.T) {
	s, _, _ := newStore(t)
	r := mustApply(t, s, sig(fp(1), false, t0), Display{
		Title:   strings.Repeat("\u00e4", MaxTitleRunes+1),
		Summary: strings.Repeat("\u00fc", MaxSummaryRunes+1),
	})
	if len([]rune(r.Incident.Title)) != MaxTitleRunes || len([]rune(r.Incident.Summary)) != MaxSummaryRunes {
		t.Fatalf("title %d, summary %d runes", len([]rune(r.Incident.Title)), len([]rune(r.Incident.Summary)))
	}
}

func TestFailedSaveLeavesStoreUnchanged(t *testing.T) {
	s, d, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), false, t0), disp).Incident.ID
	before := s.List()
	d.Close() // every later write fails
	if _, err := s.Apply(sig(fp(2), false, t0), disp); err == nil {
		t.Fatal("Apply: no error")
	}
	if _, err := s.Apply(sig(fp(1), false, t0), disp); err == nil {
		t.Fatal("Apply update: no error")
	}
	if _, err := s.Ack(id); err == nil {
		t.Fatal("Ack: no error")
	}
	if _, err := s.Close(id); err == nil {
		t.Fatal("Close: no error")
	}
	after := s.List()
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("store changed: %+v", after)
	}
}

func TestListReturnsCopy(t *testing.T) {
	s, _, _ := newStore(t)
	mustApply(t, s, sig(fp(1), false, t0), disp)
	l := s.List()
	l[0].Title = "changed"
	if s.List()[0].Title != "title" {
		t.Fatal("List exposes the store's slice")
	}
}

func TestOutcomeString(t *testing.T) {
	for o, w := range map[Outcome]string{Opened: "opened", Updated: "updated", Reopened: "reopened", 0: "unknown"} {
		if o.String() != w {
			t.Fatalf("%d = %q", o, o.String())
		}
	}
}

// seedFn writes MaxIncidents incidents built by f.
func seedFn(t *testing.T, p string, f func(i int) wireItem) {
	t.Helper()
	items := make([]wireItem, MaxIncidents)
	for i := range items {
		items[i] = f(i)
	}
	writeDoc(t, p, SchemaVersion, items)
}

func sev(it wireItem, s result.Severity, st State, notify bool, last time.Time) wireItem {
	it.Severity, it.State, it.Notify, it.LastSeen = string(s), string(st), notify, last
	return it
}

func sigSev(f event.Fingerprint, s result.Severity, notify bool, at time.Time) event.Signal {
	sg := sig(f, notify, at)
	sg.Severity = s
	return sg
}

func TestCapFloodOfLowOpenThenCriticalOpens(t *testing.T) {
	d, p := openDir(t)
	seedFn(t, p, func(i int) wireItem {
		return sev(item(fmt.Sprintf("seed%03d", i), fp(i+1), StateOpen, t0), result.Low, StateOpen, true, t0.Add(time.Duration(i)*time.Second))
	})
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sigSev(fp(10000), result.Critical, true, t0.Add(time.Hour)), disp)
	if r.Outcome != Opened || !r.Notify || len(r.Evicted) != 1 {
		t.Fatalf("result = %+v", r)
	}
	ev := r.Evicted[0]
	if ev.ID != "seed000" || ev.Fingerprint != fp(1) || ev.State != StateOpen {
		t.Fatalf("evicted = %+v", ev)
	}
	if len(s.List()) != MaxIncidents {
		t.Fatalf("size = %d", len(s.List()))
	}
	// The evicted id is retired, and the eviction is persisted.
	s2, err := Open(d)
	if err != nil || len(s2.List()) != MaxIncidents || len(s2.retired) != 1 || s2.retired[0] != "seed000" {
		t.Fatalf("reload: %v %d %v", err, len(s2.List()), s2.retired)
	}
}

func TestCapFloodOfCriticalOpenRefusesLow(t *testing.T) {
	for _, st := range []State{StateOpen, StateAcked} {
		d, p := openDir(t)
		seedFn(t, p, func(i int) wireItem {
			return sev(item(fmt.Sprintf("seed%03d", i), fp(i+1), st, t0), result.Critical, st, true, t0)
		})
		s, err := Open(d)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(p, FileName))
		r, err := s.Apply(sigSev(fp(10000), result.Low, true, t0), disp)
		if !errors.Is(err, ErrFull) || r.Outcome != Refused || r.Notify || r.Incident.Fingerprint != fp(10000) ||
			r.Incident.Severity != result.Low || len(r.Evicted) != 0 {
			t.Fatalf("%s: %+v, %v", st, r, err)
		}
		after, _ := os.ReadFile(filepath.Join(p, FileName))
		if string(before) != string(after) || len(s.List()) != MaxIncidents || len(s.retired) != 0 {
			t.Fatalf("%s: the store changed", st)
		}
		// A known fingerprint still updates, and an equal severity evicts.
		if r := mustApply(t, s, sigSev(fp(1), result.Low, false, t0.Add(time.Minute)), disp); r.Outcome != Updated {
			t.Fatalf("%s: known fingerprint: %v", st, r.Outcome)
		}
		if r := mustApply(t, s, sigSev(fp(10000), result.Critical, false, t0.Add(time.Minute)), disp); r.Outcome != Opened || len(r.Evicted) != 1 {
			t.Fatalf("%s: equal severity: %+v", st, r)
		}
	}
}

func TestCapEvictionPriority(t *testing.T) {
	// Index: severity, state, notify, last-seen offset (minutes).
	type spec struct {
		sev    result.Severity
		st     State
		notify bool
		min    int
	}
	specs := map[int]spec{
		0: {result.Medium, StateOpen, false, 0}, // the baseline for the rest
		1: {result.Low, StateOpen, true, 50},    // lowest severity wins over notify and age
		2: {result.Low, StateAcked, true, 10},   // low + notify true + older
		3: {result.Low, StateOpen, false, 30},   // low + notify false: before 1 and 2 despite being newer than 2
		4: {result.Low, StateOpen, false, 20},   // low + notify false + older than 3: the victim
	}
	d, p := openDir(t)
	seedFn(t, p, func(i int) wireItem {
		sp, ok := specs[i]
		if !ok {
			sp = spec{result.High, StateOpen, false, 0}
		}
		return sev(item(fmt.Sprintf("seed%03d", i), fp(i+1), StateOpen, t0), sp.sev, sp.st, sp.notify, t0.Add(time.Duration(sp.min)*time.Minute))
	})
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	now := t0.Add(2 * time.Hour)
	steps := []string{"seed004", "seed003", "seed002", "seed001", "seed000"}
	for n, want := range steps {
		r := mustApply(t, s, sigSev(fp(20000+n), result.High, false, now), disp)
		if len(r.Evicted) != 1 || r.Evicted[0].ID != want {
			t.Fatalf("step %d: evicted %+v, want %s", n, r.Evicted, want)
		}
	}
	// A closed incident goes before any open one, even a newer, lower one.
	if _, err := s.Close("seed010"); err != nil {
		t.Fatal(err)
	}
	r := mustApply(t, s, sigSev(fp(30000), result.High, false, now), disp)
	if len(r.Evicted) != 1 || r.Evicted[0].ID != "seed010" || r.Evicted[0].State != StateClosed {
		t.Fatalf("closed first: %+v", r.Evicted)
	}
}

func TestIdleCloseOnApplyFreesRoom(t *testing.T) {
	d, p := openDir(t)
	seedFn(t, p, func(i int) wireItem {
		return sev(item(fmt.Sprintf("seed%03d", i), fp(i+1), StateOpen, t0), result.Critical, StateOpen, true, t0.Add(time.Duration(i)*time.Second))
	})
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	// Just before the period: nothing closes, a low signal is refused.
	if _, err := s.Apply(sigSev(fp(10000), result.Low, false, t0.Add(DefaultIdleClose)), disp); !errors.Is(err, ErrFull) {
		t.Fatalf("err = %v", err)
	}
	// After it, all 500 are closed, the oldest is evicted and the signal opens.
	r := mustApply(t, s, sigSev(fp(10000), result.Low, false, t0.Add(DefaultIdleClose+time.Hour)), disp)
	if r.Outcome != Opened || len(r.AutoClosed) != MaxIncidents || len(r.Evicted) != 1 || r.Evicted[0].State != StateClosed {
		t.Fatalf("outcome %v, auto-closed %d, evicted %+v", r.Outcome, len(r.AutoClosed), r.Evicted)
	}
	for _, in := range r.AutoClosed {
		if in.State != StateClosed {
			t.Fatalf("auto-closed incident in state %s", in.State)
		}
	}
	closed := 0
	for _, in := range s.List() {
		if in.State == StateClosed {
			closed++
		}
	}
	if closed != MaxIncidents-1 {
		t.Fatalf("closed = %d", closed)
	}
	s2, err := Open(d)
	if err != nil || len(s2.List()) != MaxIncidents {
		t.Fatalf("reload: %v", err)
	}
}

func TestIdleCloseBoundaryAndStates(t *testing.T) {
	s, _, _ := newStore(t)
	a := mustApply(t, s, sig(fp(1), false, t0), disp).Incident.ID // open
	b := mustApply(t, s, sig(fp(2), false, t0), disp).Incident.ID // acked
	c := mustApply(t, s, sig(fp(3), false, t0), disp).Incident.ID // closed already
	setState(t, s, b, StateAcked)
	setState(t, s, c, StateClosed)
	// Exactly the period: not idle longer than it.
	if got, err := s.Sweep(t0.Add(DefaultIdleClose)); err != nil || len(got) != 0 {
		t.Fatalf("at the boundary: %v %v", got, err)
	}
	got, err := s.Sweep(t0.Add(DefaultIdleClose + time.Second))
	if err != nil || len(got) != 2 || got[0].ID != a || got[1].ID != b {
		t.Fatalf("sweep = %+v %v", got, err)
	}
	for _, id := range []string{a, b, c} {
		if in, _ := s.Get(id); in.State != StateClosed {
			t.Fatalf("%s is %s", id, in.State)
		}
	}
	// A second sweep finds nothing and a zero time closes nothing.
	if got, err := s.Sweep(t0.Add(365 * 24 * time.Hour)); err != nil || len(got) != 0 {
		t.Fatalf("second sweep: %v %v", got, err)
	}
	s3, _, _ := newStore(t)
	mustApply(t, s3, sig(fp(1), false, t0), disp)
	if got, err := s3.Sweep(time.Time{}); err != nil || len(got) != 0 {
		t.Fatalf("zero now: %v %v", got, err)
	}
}

func TestSweepWithNothingToCloseWritesNothing(t *testing.T) {
	s, _, p := newStore(t)
	if got, err := s.Sweep(t0); err != nil || len(got) != 0 {
		t.Fatalf("sweep = %v %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(p, FileName)); !os.IsNotExist(err) {
		t.Fatalf("a sweep that closed nothing wrote the file: %v", err)
	}
}

func TestIdleCloseIsPersisted(t *testing.T) {
	s, d, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), false, t0), disp).Incident.ID
	if _, err := s.Sweep(t0.Add(DefaultIdleClose + time.Minute)); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if in, _ := s2.Get(id); in.State != StateClosed {
		t.Fatalf("state = %s", in.State)
	}
}

func TestWithIdleClose(t *testing.T) {
	cases := []struct {
		name    string
		opts    []Option
		after   time.Duration
		wantAut int
	}{
		{"default 7d, before", nil, 6 * 24 * time.Hour, 0},
		{"default 7d, after", nil, 8 * 24 * time.Hour, 1},
		{"1h, after", []Option{WithIdleClose(time.Hour)}, 2 * time.Hour, 1},
		{"1h, before", []Option{WithIdleClose(time.Hour)}, 30 * time.Minute, 0},
		{"zero disables", []Option{WithIdleClose(0)}, 1000 * 24 * time.Hour, 0},
		{"negative disables", []Option{WithIdleClose(-time.Hour)}, 1000 * 24 * time.Hour, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, _ := openDir(t)
			s, err := Open(d, c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			mustApply(t, s, sig(fp(1), false, t0), disp)
			got, err := s.Sweep(t0.Add(c.after))
			if err != nil || len(got) != c.wantAut {
				t.Fatalf("sweep = %d %v", len(got), err)
			}
		})
	}
}

func TestApplyIdleClosesBeforeLookupSoTheSameIncidentReopens(t *testing.T) {
	s, _, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), true, t0), disp).Incident.ID
	r := mustApply(t, s, sig(fp(1), true, t0.Add(DefaultIdleClose+time.Hour)), disp)
	if r.Outcome != Reopened || !r.Notify || len(r.AutoClosed) != 1 || r.AutoClosed[0].ID != id || r.Incident.ReopenCount != 1 {
		t.Fatalf("result = %+v", r)
	}
	// A signal inside the period does not close or reopen.
	r = mustApply(t, s, sig(fp(1), true, t0.Add(DefaultIdleClose+2*time.Hour)), disp)
	if r.Outcome != Updated || len(r.AutoClosed) != 0 {
		t.Fatalf("result = %+v", r)
	}
	// An old signal time (replay) closes nothing.
	r = mustApply(t, s, sig(fp(1), true, t0), disp)
	if len(r.AutoClosed) != 0 {
		t.Fatalf("old time auto-closed %d", len(r.AutoClosed))
	}
}

func TestPendingAfterLostResult(t *testing.T) {
	s, _, _ := newStore(t)
	r1 := mustApply(t, s, sig(fp(1), true, t0), disp)
	if r1.Outcome != Opened || !r1.Notify || r1.Pending {
		t.Fatalf("first = %+v", r1)
	}
	// The result is dropped; the same signal arrives again.
	r2 := mustApply(t, s, sig(fp(1), true, t0), disp)
	if r2.Outcome != Updated || r2.Notify || !r2.Pending {
		t.Fatalf("replay = %+v", r2)
	}
	// Marking it as notified ends the pending state, and it is persisted.
	at := t0.Add(time.Minute)
	in, err := s.MarkNotified(r1.Incident.ID, at)
	if err != nil || !in.NotifiedAt.Equal(at) {
		t.Fatalf("MarkNotified = %+v, %v", in, err)
	}
	if r3 := mustApply(t, s, sig(fp(1), true, t0), disp); r3.Pending || r3.Notify {
		t.Fatalf("after marking = %+v", r3)
	}
}

func TestPendingCases(t *testing.T) {
	cases := []struct {
		name   string
		notify bool
		state  State
		mark   bool
		want   bool
	}{
		{"wants, open, unmarked", true, StateOpen, false, true},
		{"wants, open, marked", true, StateOpen, true, false},
		{"does not want, open", false, StateOpen, false, false},
		{"wants, acked, unmarked", true, StateAcked, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := newStore(t)
			id := mustApply(t, s, sig(fp(1), c.notify, t0), disp).Incident.ID
			if c.mark {
				if _, err := s.MarkNotified(id, t0); err != nil {
					t.Fatal(err)
				}
			}
			setState(t, s, id, c.state)
			// The updating signal's own Notify does not matter: the incident's flag does.
			if r := mustApply(t, s, sig(fp(1), !c.notify, t0), disp); r.Pending != c.want {
				t.Fatalf("Pending = %v, want %v", r.Pending, c.want)
			}
		})
	}
}

func TestReopenClearsNotifiedAt(t *testing.T) {
	s, d, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), true, t0), disp).Incident.ID
	if _, err := s.MarkNotified(id, t0); err != nil {
		t.Fatal(err)
	}
	setState(t, s, id, StateClosed)
	r := mustApply(t, s, sig(fp(1), true, t0.Add(time.Hour)), disp)
	if r.Outcome != Reopened || !r.Incident.NotifiedAt.IsZero() {
		t.Fatalf("reopen = %+v", r)
	}
	// The reopen notification is lost too: the replay is pending.
	if r := mustApply(t, s, sig(fp(1), true, t0.Add(time.Hour)), disp); !r.Pending {
		t.Fatal("replay after reopen is not pending")
	}
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if in, _ := s2.Get(id); !in.NotifiedAt.IsZero() {
		t.Fatal("NotifiedAt persisted after reopen")
	}
}

func TestMarkNotifiedErrors(t *testing.T) {
	s, d, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), true, t0), disp).Incident.ID
	if _, err := s.MarkNotified("nope", t0); !errors.Is(err, ErrUnknownIncident) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := s.MarkNotified(id, time.Time{}); !errors.Is(err, ErrInvalidSignal) {
		t.Fatalf("zero time: %v", err)
	}
	if in, _ := s.Get(id); !in.NotifiedAt.IsZero() {
		t.Fatal("a refused mark changed the incident")
	}
	if _, err := s.MarkNotified(id, t0); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if in, _ := s2.Get(id); !in.NotifiedAt.Equal(t0) {
		t.Fatalf("not persisted: %+v", in)
	}
	d.Close()
	if _, err := s.MarkNotified(id, t0.Add(time.Hour)); err == nil {
		t.Fatal("no error on a failed save")
	}
	if in, _ := s.Get(id); !in.NotifiedAt.Equal(t0) {
		t.Fatal("failed save changed the store")
	}
}

func TestRetiredIDsAreNotReused(t *testing.T) {
	d, p := openDir(t)
	items := make([]wireItem, MaxIncidents-1)
	for i := range items {
		it := item(fmt.Sprintf("seed%03d", i), fp(i+1), StateClosed, t0.Add(time.Hour))
		items[i] = it
	}
	writeDoc(t, p, SchemaVersion, items)
	s, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	a := event.Fingerprint("deadbeef0" + strings.Repeat("0", 55))
	b := event.Fingerprint("deadbeef1" + strings.Repeat("0", 55))
	ra := mustApply(t, s, sig(a, false, t0), disp)
	if ra.Incident.ID != "deadbeef" {
		t.Fatalf("id = %q", ra.Incident.ID)
	}
	setState(t, s, ra.Incident.ID, StateClosed)
	// The store is full; a new fingerprint evicts the oldest closed one, which is a.
	rc := mustApply(t, s, sig(fp(50000), false, t0.Add(2*time.Hour)), disp)
	if len(rc.Evicted) != 1 || rc.Evicted[0].ID != "deadbeef" {
		t.Fatalf("evicted = %+v", rc.Evicted)
	}
	rb := mustApply(t, s, sig(b, false, t0.Add(3*time.Hour)), disp)
	if rb.Incident.ID != "deadbeef1" {
		t.Fatalf("id = %q (the retired id was reused or not derived)", rb.Incident.ID)
	}
	// Persisted: a reloaded store remembers the retired id.
	s2, err := Open(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.retired) == 0 || s2.retired[0] != "deadbeef" {
		t.Fatalf("retired = %v", s2.retired)
	}
}

func TestRetiredIDsAreBounded(t *testing.T) {
	r := []string{}
	for i := 0; i < MaxRetiredIDs+5; i++ {
		r = addRetired(r, fmt.Sprintf("id%d", i))
	}
	if len(r) != MaxRetiredIDs || r[0] != "id5" || r[len(r)-1] != fmt.Sprintf("id%d", MaxRetiredIDs+4) {
		t.Fatalf("len %d first %q last %q", len(r), r[0], r[len(r)-1])
	}
	// Exactly at the bound nothing is dropped.
	r = nil
	for i := 0; i < MaxRetiredIDs; i++ {
		r = addRetired(r, fmt.Sprintf("id%d", i))
	}
	if len(r) != MaxRetiredIDs || r[0] != "id0" {
		t.Fatalf("len %d first %q", len(r), r[0])
	}
}

func TestApplyRejectsUnknownSeverity(t *testing.T) {
	s, _, _ := newStore(t)
	for _, sv := range []result.Severity{"", "bogus", "HIGH"} {
		if _, err := s.Apply(sigSev(fp(1), sv, false, t0), disp); !errors.Is(err, ErrInvalidSignal) {
			t.Fatalf("%q: %v", sv, err)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("a bad signal created an incident")
	}
	for _, sv := range result.Severities {
		if _, err := s.Apply(sigSev(fp(2), sv, false, t0), disp); err != nil {
			t.Fatalf("%q: %v", sv, err)
		}
	}
}

func TestReopenTakesReopeningSeverityUpdateOnlyEscalates(t *testing.T) {
	s, _, _ := newStore(t)
	id := mustApply(t, s, sigSev(fp(1), result.Critical, false, t0), disp).Incident.ID
	setState(t, s, id, StateClosed)
	r := mustApply(t, s, sigSev(fp(1), result.Info, false, t0.Add(time.Hour)), disp)
	if r.Outcome != Reopened || r.Incident.Severity != result.Info {
		t.Fatalf("reopen = %+v", r)
	}
	r = mustApply(t, s, sigSev(fp(1), result.Low, false, t0.Add(time.Hour)), disp)
	if r.Incident.Severity != result.Low {
		t.Fatalf("escalation to low: %s", r.Incident.Severity)
	}
}

func TestApplyCutsRuleID(t *testing.T) {
	s, _, _ := newStore(t)
	sg := sig(fp(1), false, t0)
	sg.RuleID = strings.Repeat("r", MaxRuleIDRunes+10)
	r := mustApply(t, s, sg, disp)
	if len(r.Incident.RuleID) != MaxRuleIDRunes {
		t.Fatalf("rule id has %d bytes", len(r.Incident.RuleID))
	}
}

func TestOpenRefusesVersionOne(t *testing.T) {
	d, p := openDir(t)
	writeRaw(t, p, []byte(`{"schema_version":1,"incidents":[]}`))
	if _, err := Open(d); !errors.Is(err, ErrSchema) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenStrictValues(t *testing.T) {
	long := strings.Repeat("x", MaxIDLen+1)
	mod := func(f func(*wireItem)) []byte {
		it := item("aaaaaaaa", fp(1), StateOpen, t0)
		f(&it)
		return mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{it}, RetiredIDs: []string{}})
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"unknown severity", mod(func(w *wireItem) { w.Severity = "bogus" })},
		{"empty severity", mod(func(w *wireItem) { w.Severity = "" })},
		{"negative count", mod(func(w *wireItem) { w.Count = -5 })},
		{"negative reopen count", mod(func(w *wireItem) { w.ReopenCount = -1 })},
		{"non-hex fingerprint", mod(func(w *wireItem) { w.Fingerprint = "zz" })},
		{"upper-case fingerprint", mod(func(w *wireItem) { w.Fingerprint = "ABCD" })},
		{"long fingerprint", mod(func(w *wireItem) { w.Fingerprint = strings.Repeat("a", 65) })},
		{"long id", mod(func(w *wireItem) { w.ID = long })},
		{"long title", mod(func(w *wireItem) { w.Title = strings.Repeat("t", MaxTitleRunes+1) })},
		{"long summary", mod(func(w *wireItem) { w.Summary = strings.Repeat("s", MaxSummaryRunes+1) })},
		{"long rule id", mod(func(w *wireItem) { w.RuleID = strings.Repeat("r", MaxRuleIDRunes+1) })},
		{"retired id repeated", mustJSON(fileDoc{SchemaVersion: SchemaVersion, RetiredIDs: []string{"a", "a"}})},
		{"retired id in use", mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{item("aaaaaaaa", fp(1), StateOpen, t0)}, RetiredIDs: []string{"aaaaaaaa"}})},
		{"retired id empty", mustJSON(fileDoc{SchemaVersion: SchemaVersion, RetiredIDs: []string{""}})},
		{"retired id long", mustJSON(fileDoc{SchemaVersion: SchemaVersion, RetiredIDs: []string{long}})},
		{"too many retired ids", mustJSON(fileDoc{SchemaVersion: SchemaVersion, RetiredIDs: manyIDs(MaxRetiredIDs + 1)})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p := openDir(t)
			writeRaw(t, p, c.raw)
			if _, err := Open(d); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// Values at their bounds are accepted.
	d, p := openDir(t)
	it := item(strings.Repeat("i", MaxIDLen), fp(1), StateOpen, t0)
	it.Title, it.Summary, it.RuleID = strings.Repeat("t", MaxTitleRunes), strings.Repeat("s", MaxSummaryRunes), strings.Repeat("r", MaxRuleIDRunes)
	it.Count = 0
	writeRaw(t, p, mustJSON(fileDoc{SchemaVersion: SchemaVersion, Incidents: []wireItem{it}, RetiredIDs: []string{strings.Repeat("j", MaxIDLen)}}))
	if _, err := Open(d); err != nil {
		t.Fatalf("at the bounds: %v", err)
	}
}

func manyIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("r%d", i)
	}
	return out
}

func TestSweepFailedSaveLeavesStoreUnchanged(t *testing.T) {
	s, d, _ := newStore(t)
	id := mustApply(t, s, sig(fp(1), false, t0), disp).Incident.ID
	d.Close()
	if _, err := s.Sweep(t0.Add(DefaultIdleClose + time.Hour)); err == nil {
		t.Fatal("no error")
	}
	if in, _ := s.Get(id); in.State != StateOpen {
		t.Fatalf("state = %s", in.State)
	}
}
