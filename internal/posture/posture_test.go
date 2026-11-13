package posture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

func item(raw, shown string) state.Item {
	return state.Item{Key: result.SubjectKey(raw), Subject: shown}
}

func chk(id string, st result.Status, sev result.Severity, items ...state.Item) state.Check {
	return state.Check{ID: id, Kind: "k", Status: st, Severity: sev, Items: append([]state.Item{}, items...)}
}

func st(run time.Time, checks ...state.Check) *state.State {
	return &state.State{SchemaVersion: state.SchemaVersion, RunAt: run, Checks: checks}
}

// seq serves the given load results in order, then repeats the last.
func seq(rs ...state.LoadResult) *Source {
	i := 0
	return &Source{load: func() (state.LoadResult, error) {
		r := rs[i]
		if i < len(rs)-1 {
			i++
		}
		return r, nil
	}}
}

func ok(s *state.State) state.LoadResult { return state.LoadResult{State: s} }

func TestBaselineThenNewFailureAndFixed(t *testing.T) {
	a := st(t0,
		chk("ssh", result.Pass, result.High),
		chk("fw", result.Fail, result.Medium),
	)
	b := st(t0.Add(time.Hour),
		chk("ssh", result.Fail, result.High),
		chk("fw", result.Pass, result.Medium),
	)
	s := seq(ok(a), ok(b))
	now := t0.Add(2 * time.Hour)
	sigs, err := s.Poll(now)
	if err != nil || len(sigs) != 0 {
		t.Fatalf("baseline: %v %v", sigs, err)
	}
	sigs, err = s.Poll(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("want one signal (the fix is no alert), got %+v", sigs)
	}
	g := sigs[0]
	if g.RuleID != RuleID || g.Severity != result.High || !g.Time.Equal(now) {
		t.Errorf("signal %+v", g)
	}
	if g.Fingerprint != event.FingerprintOf(RuleID, "ssh", "new_failure", "") {
		t.Errorf("fingerprint %s", g.Fingerprint)
	}
}

func TestNotifyFalseForEverySignal(t *testing.T) {
	a := st(t0, chk("a", result.Pass, result.High), chk("b", result.Pass, result.Low))
	b := st(t0.Add(time.Hour), chk("a", result.Fail, result.High), chk("b", result.Fail, result.Low), chk("c", result.Fail, result.Medium))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	sigs, _ := s.Poll(t0)
	if len(sigs) != 3 {
		t.Fatalf("got %d signals", len(sigs))
	}
	for _, g := range sigs {
		if g.Notify {
			t.Errorf("Notify true: %+v", g)
		}
	}
}

func TestSameRunAtYieldsNothing(t *testing.T) {
	a := st(t0, chk("a", result.Pass, result.High))
	// Same RunAt, different content: must not be diffed.
	b := st(t0, chk("a", result.Fail, result.High))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	for i := 0; i < 2; i++ {
		if sigs, err := s.Poll(t0); err != nil || len(sigs) != 0 {
			t.Fatalf("poll %d: %v %v", i, sigs, err)
		}
	}
}

func TestChangeIsReportedOnceThenQuiet(t *testing.T) {
	a := st(t0, chk("a", result.Pass, result.High))
	b := st(t0.Add(time.Hour), chk("a", result.Fail, result.High))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	if sigs, _ := s.Poll(t0); len(sigs) != 1 {
		t.Fatalf("first: %v", sigs)
	}
	if sigs, _ := s.Poll(t0); len(sigs) != 0 {
		t.Fatalf("second: %v", sigs)
	}
}

func TestFingerprintUsesRawKeyNotDisplaySubject(t *testing.T) {
	// Two raw subjects that display the same text.
	x, y := "tok-AAA", "tok-BBB"
	shown := "[redacted]"
	a := st(t0, chk("c", result.Fail, result.High, item(x, shown)))
	b := st(t0.Add(time.Hour), chk("c", result.Fail, result.High, item(x, shown), item(y, shown)))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	sigs, _ := s.Poll(t0)
	if len(sigs) != 1 {
		t.Fatalf("got %+v", sigs)
	}
	// Display subject is not unique in the check: the fallback applies.
	want := event.FingerprintOf(RuleID, "c", "subject_new", "subject:"+shown)
	if sigs[0].Fingerprint != want {
		t.Errorf("ambiguous: %s", sigs[0].Fingerprint)
	}

	// Unique display subjects: the raw key is used, and two raw values give
	// two fingerprints even where the display text is what the diff shows.
	a = st(t0, chk("c", result.Fail, result.High))
	b = st(t0.Add(time.Hour), chk("c", result.Fail, result.High, item(x, "one")))
	b2 := st(t0.Add(time.Hour), chk("c", result.Fail, result.High, item(y, "one")))
	fp := func(next *state.State) event.Fingerprint {
		s := seq(ok(a), ok(next))
		_, _ = s.Poll(t0)
		g, _ := s.Poll(t0)
		if len(g) != 1 {
			t.Fatalf("got %+v", g)
		}
		return g[0].Fingerprint
	}
	f1, f2 := fp(b), fp(b2)
	if f1 != event.FingerprintOf(RuleID, "c", "subject_new", "key:"+result.SubjectKey(x)) {
		t.Errorf("raw key fingerprint %s", f1)
	}
	if f1 == f2 {
		t.Error("same display subject, different raw key: fingerprints collide")
	}
	if f1 == event.FingerprintOf(RuleID, "c", "subject_new", "one") || f1 == event.FingerprintOf(RuleID, "c", "subject_new", "subject:one") {
		t.Error("fingerprint built from the display subject")
	}
}

func TestMinSeverity(t *testing.T) {
	a := st(t0, chk("lo", result.Pass, result.Low), chk("hi", result.Pass, result.High))
	b := st(t0.Add(time.Hour), chk("lo", result.Fail, result.Low), chk("hi", result.Fail, result.High))
	mk := func(min result.Severity) int {
		s := seq(ok(a), ok(b))
		s.min = min
		_, _ = s.Poll(t0)
		g, _ := s.Poll(t0)
		return len(g)
	}
	if n := mk(""); n != 2 {
		t.Errorf("empty min: %d", n)
	}
	if n := mk(result.High); n != 1 {
		t.Errorf("high min: %d", n)
	}
}

func TestMissingIsNotAnError(t *testing.T) {
	s := seq(state.LoadResult{Missing: true})
	for i := 0; i < 2; i++ {
		if sigs, err := s.Poll(t0); err != nil || sigs != nil {
			t.Fatalf("%v %v", sigs, err)
		}
	}
	// The first state after a missing file is the baseline.
	a := st(t0, chk("a", result.Fail, result.High))
	s = seq(state.LoadResult{Missing: true}, ok(a))
	_, _ = s.Poll(t0)
	if sigs, err := s.Poll(t0); err != nil || len(sigs) != 0 {
		t.Fatalf("%v %v", sigs, err)
	}
}

func TestProblemAndErrorAreReturnedAndBaselineKept(t *testing.T) {
	a := st(t0, chk("a", result.Pass, result.High))
	b := st(t0.Add(time.Hour), chk("a", result.Fail, result.High))
	s := seq(ok(a), state.LoadResult{Problem: "schema version 9"}, ok(b))
	_, _ = s.Poll(t0)
	if sigs, err := s.Poll(t0); err == nil || sigs != nil {
		t.Fatalf("problem: %v %v", sigs, err)
	}
	if sigs, err := s.Poll(t0); err != nil || len(sigs) != 1 {
		t.Fatalf("after problem: %v %v", sigs, err)
	}

	boom := errors.New("untrusted dir")
	s = &Source{load: func() (state.LoadResult, error) { return state.LoadResult{}, boom }}
	if _, err := s.Poll(t0); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
}

func TestSignalSeverityFollowsChange(t *testing.T) {
	for _, sv := range []result.Severity{result.Low, result.Medium} {
		a := st(t0, chk("a", result.Pass, sv))
		b := st(t0.Add(time.Hour), chk("a", result.Fail, sv))
		s := seq(ok(a), ok(b))
		_, _ = s.Poll(t0)
		g, _ := s.Poll(t0)
		if len(g) != 1 || g[0].Severity != sv {
			t.Errorf("severity %s: %+v", sv, g)
		}
	}
}

func TestSubjectAndSummary(t *testing.T) {
	a := st(t0, chk("c1", result.Pass, result.High), chk("c2", result.Fail, result.High))
	b := st(t0.Add(time.Hour), chk("c1", result.Fail, result.High), chk("c2", result.Fail, result.High, item("x", "shown-x")))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	g, _ := s.Poll(t0)
	if len(g) != 2 {
		t.Fatalf("got %+v", g)
	}
	if g[0].Subject != "c1" || g[0].Summary != "c1: new_failure" {
		t.Errorf("check change: %q %q", g[0].Subject, g[0].Summary)
	}
	if g[1].Subject != "c2 shown-x" || g[1].Summary != "c2: subject_new shown-x" {
		t.Errorf("item change: %q %q", g[1].Subject, g[1].Summary)
	}
}

func TestRawKeyUniqueAcrossCurAndPrev(t *testing.T) {
	// cur lists l, prev lists x, both display "[r]": the change is for l,
	// but the text is shared across the two runs, so the fallback applies.
	a := st(t0, chk("c", result.Fail, result.High, item("raw-x", "[r]")))
	b := st(t0.Add(time.Hour), chk("c", result.Fail, result.High, item("raw-l", "[r]")))
	s := seq(ok(a), ok(b))
	_, _ = s.Poll(t0)
	g, _ := s.Poll(t0)
	if len(g) != 1 {
		t.Fatalf("got %+v", g)
	}
	if g[0].Fingerprint != event.FingerprintOf(RuleID, "c", "subject_new", "subject:[r]") {
		t.Errorf("fingerprint %s", g[0].Fingerprint)
	}
}

func TestRawKeyLookupFindsPrevOnly(t *testing.T) {
	// A subject_gone is not an alert, so use diff directly through rawKey.
	a := st(t0, chk("c", result.Fail, result.High, item("raw-x", "only-prev")))
	b := st(t0.Add(time.Hour), chk("c", result.Fail, result.High))
	ch := diffChange("c", "only-prev")
	if got := rawKey(ch, a, b); got != "key:"+result.SubjectKey("raw-x") {
		t.Errorf("prev-only key %q", got)
	}
	if got := rawKey(ch, b, a); got != "key:"+result.SubjectKey("raw-x") {
		t.Errorf("cur-only key %q", got)
	}
	if got := rawKey(ch, b, b); got != "subject:only-prev" {
		t.Errorf("none %q", got)
	}
}

func TestCappedExceptionChangeUsesFallback(t *testing.T) {
	kx, kl := result.SubjectKey("raw-x"), result.SubjectKey("raw-l")
	keys := []string{kx, kl}
	if keys[0] > keys[1] {
		keys[0], keys[1] = keys[1], keys[0]
	}
	p := state.Check{ID: "c", Kind: "k", Status: result.Fail, Severity: result.High,
		Items: []state.Item{{Key: kx, Subject: "[r]", Excepted: true}, {Key: kl, Subject: "other"}},
		Total: 2, Keys: keys, Digest: "d1"}
	c := state.Check{ID: "c", Kind: "k", Status: result.Fail, Severity: result.High,
		Items: []state.Item{{Key: kl, Subject: "[r]"}},
		Total: 2, Keys: keys, Digest: "d2"}
	s := seq(ok(st(t0, p)), ok(st(t0.Add(time.Hour), c)))
	_, _ = s.Poll(t0)
	g, _ := s.Poll(t0)
	if len(g) == 0 {
		t.Fatal("no signal")
	}
	for _, x := range g {
		if x.Fingerprint == event.FingerprintOf(RuleID, "c", "subject_new", "key:"+kl) {
			t.Errorf("signal carries the key of another item: %+v", x)
		}
	}
	if g[0].Fingerprint != event.FingerprintOf(RuleID, "c", "subject_new", "subject:[r]") {
		t.Errorf("fingerprint %s", g[0].Fingerprint)
	}
}

func TestNewReadsRealStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	// min High: the Low failure is filtered, the High one passes.
	s := New(store, result.High)
	if g, err := s.Poll(t0); err != nil || g != nil {
		t.Fatalf("missing: %v %v", g, err)
	}
	run1 := t0.Truncate(time.Second)
	if err := store.Save(st(run1, chk("lo", result.Pass, result.Low), chk("hi", result.Pass, result.High))); err != nil {
		t.Fatal(err)
	}
	if g, err := s.Poll(t0); err != nil || len(g) != 0 {
		t.Fatalf("baseline: %v %v", g, err)
	}
	if err := store.Save(st(run1.Add(time.Hour), chk("lo", result.Fail, result.Low), chk("hi", result.Fail, result.High))); err != nil {
		t.Fatal(err)
	}
	g, err := s.Poll(t0)
	if err != nil || len(g) != 1 || g[0].Subject != "hi" || g[0].Notify {
		t.Fatalf("second run: %+v %v", g, err)
	}
}

func TestTransientRaceIsRetriedOnce(t *testing.T) {
	a := st(t0, chk("a", result.Pass, result.High))
	b := st(t0.Add(time.Hour), chk("a", result.Fail, result.High))
	race := state.LoadResult{Problem: "/x/state.json changed while it was being opened"}

	s := seq(ok(a), race, ok(b))
	_, _ = s.Poll(t0)
	if g, err := s.Poll(t0); err != nil || len(g) != 1 {
		t.Fatalf("one race: %v %v", g, err)
	}

	calls := 0
	s = &Source{load: func() (state.LoadResult, error) { calls++; return race, nil }}
	if _, err := s.Poll(t0); err == nil {
		t.Fatal("persisting race must be an error")
	}
	if calls != 2 {
		t.Errorf("loads: %d, want 2", calls)
	}
}

func diffChange(check, subject string) diff.Change {
	return diff.Change{Kind: diff.SubjectNew, CheckID: check, Subject: subject}
}

// An exception removed between two runs lists the same item in both; the
// signal still carries the item's raw key, not the display fallback.
func TestExceptionRemovedKeepsRawKey(t *testing.T) {
	kx := result.SubjectKey("raw-x")
	ky := result.SubjectKey("raw-y")
	p := state.Check{ID: "c", Kind: "k", Status: result.Fail, Severity: result.High,
		Items: []state.Item{{Key: kx, Subject: "shown-x", Excepted: true}, {Key: ky, Subject: "shown-y"}}}
	c := state.Check{ID: "c", Kind: "k", Status: result.Fail, Severity: result.High,
		Items: []state.Item{{Key: kx, Subject: "shown-x"}, {Key: ky, Subject: "shown-y"}}}
	s := seq(ok(st(t0, p)), ok(st(t0.Add(time.Hour), c)))
	if _, err := s.Poll(t0); err != nil {
		t.Fatal(err)
	}
	g, err := s.Poll(t0)
	if err != nil {
		t.Fatal(err)
	}
	want := event.FingerprintOf(RuleID, "c", "subject_new", "key:"+kx)
	for _, x := range g {
		if x.Fingerprint == want {
			return
		}
	}
	t.Errorf("no signal with the raw key %s: %+v", want, g)
}

// The "disappeared" form of the load race is retried like the "changed" one.
func TestDisappearedRaceIsRetried(t *testing.T) {
	gone := state.LoadResult{Problem: "/x/state.json disappeared while it was being opened"}
	s := seq(gone, state.LoadResult{Missing: true})
	if g, err := s.Poll(t0); err != nil || g != nil {
		t.Fatalf("got %v, %v; want nil, nil after one retry", g, err)
	}
}
