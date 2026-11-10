package diff

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// chk builds a check snapshot. An item ending in "!" is excepted.
func chk(id string, st result.Status, items ...string) state.Check {
	c := state.Check{ID: id, Kind: "k", Status: st, Severity: result.High, Items: []state.Item{}}
	for _, name := range items {
		ex := strings.HasSuffix(name, "!")
		name = strings.TrimSuffix(name, "!")
		c.Items = append(c.Items, state.Item{Key: result.SubjectKey(name), Subject: name, Excepted: ex})
	}
	return c
}

func kind(c state.Check, k string) state.Check { c.Kind = k; return c }
func sev(c state.Check, s result.Severity) state.Check {
	c.Severity = s
	return c
}

// cutAt is the display cap of the probes: a list of more than this many items
// is cut to cutAt-1 and a marker.
const cutAt = 100

// listed returns the evidence list a probe returns for names, built the way
// the probes' limitEvidence does it: sorted by subject, and when there are
// more than cutAt items the first cutAt-1 and the marker that carries the set
// of all of them. A name ending in "!" is an item an exception covers, as the
// engine marks it: only among the items that are listed.
func listed(names ...string) ([]result.Evidence, *result.EvidenceSet) {
	type item struct {
		name string
		ex   bool
	}
	var all []item
	var raw []result.Evidence
	for _, n := range names {
		ex := strings.HasSuffix(n, "!")
		n = strings.TrimSuffix(n, "!")
		all = append(all, item{n, ex})
		raw = append(raw, result.Evidence{Subject: n})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })
	shown := all
	if len(all) > cutAt {
		shown = all[:cutAt-1]
	}
	var out []result.Evidence
	for _, it := range shown {
		out = append(out, result.Evidence{Subject: it.name, Excepted: it.ex})
	}
	if len(all) > cutAt {
		out = append(out, result.Evidence{Subject: fmt.Sprintf("(%d more not shown)", len(all)-(cutAt-1))})
		return out, result.NewEvidenceSet(raw)
	}
	return out, nil
}

// big builds a check as the state package builds it from a probe's result:
// capped when names has more than cutAt items. clean is the display cleaner
// (nil leaves subjects as they are).
func big(clean func(string) string, id string, st result.Status, names ...string) state.Check {
	ev, set := listed(names...)
	r := result.Result{CheckID: id, Kind: "k", Status: st, Severity: result.High, Evidence: ev, Set: set}
	return state.FromResults([]result.Result{r}, time.Unix(0, 0), clean).Checks[0]
}

// bigN is big for the generated names of many.
func bigN(id string, st result.Status, names ...string) state.Check {
	return big(nil, id, st, names...)
}

func run(cs ...state.Check) *state.State {
	return &state.State{SchemaVersion: state.SchemaVersion, RunAt: time.Unix(0, 0).UTC(), Checks: cs}
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}

func many(prefix string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s-%03d", prefix, i))
	}
	return out
}

// show renders a change on one line: kind, check, transition or subject,
// and "ALERT" when it is alert-worthy.
func show(c Change) string {
	s := string(c.Kind) + " " + c.CheckID
	switch c.Kind {
	case SubjectNew, SubjectGone:
		s += " " + c.Subject
	case HiddenNew:
		s += fmt.Sprintf(" %d", c.HiddenNew)
	case HiddenGone:
		s += fmt.Sprintf(" %d", c.HiddenGone)
	case SetChanged:
		s += fmt.Sprintf(" %d>%d", c.OldTotal, c.NewTotal)
	case SeverityChange:
		s += fmt.Sprintf(" %s>%s (%s)", c.FromSeverity, c.ToSeverity, c.To)
	case CheckAdded:
		s += " ->" + string(c.To)
	case CheckRemoved:
		s += " " + string(c.From) + "->"
	default:
		s += " " + string(c.From) + ">" + string(c.To)
	}
	if c.Alert {
		s += " ALERT"
	}
	return s
}

func TestCompute(t *testing.T) {
	ak := func(st result.Status, items ...string) state.Check {
		return kind(chk("keys", st, items...), AuthorizedKeysKind)
	}
	tests := []struct {
		name         string
		prev, cur    *state.State
		want         []string
		stillFailing []string
		stillWarning []string
	}{
		{name: "nothing changed", prev: run(chk("a", result.Pass), chk("b", result.Skipped)), cur: run(chk("a", result.Pass), chk("b", result.Skipped))},
		{name: "pass to fail", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Fail, "x")), want: []string{"new_failure a pass>fail ALERT"}},
		{name: "skipped to fail", prev: run(chk("a", result.Skipped)), cur: run(chk("a", result.Fail, "x")), want: []string{"new_failure a skipped>fail ALERT"}},
		{name: "excepted to fail", prev: run(chk("a", result.Excepted, "x!")), cur: run(chk("a", result.Fail, "x")), want: []string{"new_failure a excepted>fail ALERT"}},
		{name: "warn to fail", prev: run(chk("a", result.Warn, "x")), cur: run(chk("a", result.Fail, "x")), want: []string{"new_failure a warn>fail ALERT"}},
		{name: "error to fail", prev: run(chk("a", result.Error)), cur: run(chk("a", result.Fail, "x")), want: []string{"new_failure a error>fail ALERT"}},
		{name: "fail to pass", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Pass)), want: []string{"fixed a fail>pass"}},
		{name: "fail to excepted", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Excepted, "x!")), want: []string{"status_change a fail>excepted"}},
		{name: "fail to skipped", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Skipped)), want: []string{"status_change a fail>skipped"}},
		{name: "pass to skipped", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Skipped)), want: []string{"status_change a pass>skipped"}},
		{name: "excepted to pass", prev: run(chk("a", result.Excepted, "x!")), cur: run(chk("a", result.Pass)), want: []string{"status_change a excepted>pass"}},
		{name: "pass to excepted", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Excepted, "x!")), want: []string{"status_change a pass>excepted"}},

		{name: "pass to error", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Error)), want: []string{"status_change a pass>error ALERT"}},
		{name: "skipped to error", prev: run(chk("a", result.Skipped)), cur: run(chk("a", result.Error)), want: []string{"status_change a skipped>error ALERT"}},
		{name: "fail to error", prev: run(chk("a", result.Fail, "x", "y")), cur: run(chk("a", result.Error, "z")), want: []string{"status_change a fail>error ALERT"}},
		{name: "error to pass", prev: run(chk("a", result.Error)), cur: run(chk("a", result.Pass)), want: []string{"status_change a error>pass"}},
		{name: "error stays error with other partial evidence", prev: run(chk("a", result.Error, "x")), cur: run(chk("a", result.Error, "y", "z"))},
		{name: "error with partial evidence is not compared when it appears", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Error, "x", "y", "z")), want: []string{"status_change a pass>error ALERT"}},

		{name: "fail to warn, other kind", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Warn, "x")), want: []string{"status_change a fail>warn"}},
		{name: "pass to warn, other kind", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Warn, "w")), want: []string{"status_change a pass>warn"}},
		{name: "warn to pass", prev: run(chk("a", result.Warn, "w")), cur: run(chk("a", result.Pass)), want: []string{"status_change a warn>pass"}},
		{name: "pass to warn, authorized_keys", prev: run(ak(result.Pass)), cur: run(ak(result.Warn, "u:path")), want: []string{"status_change keys pass>warn ALERT"}},
		{name: "fail to warn, authorized_keys", prev: run(ak(result.Fail, "u:fp")), cur: run(ak(result.Warn, "u:path")), want: []string{"status_change keys fail>warn ALERT"}},
		{name: "warn to excepted, authorized_keys", prev: run(ak(result.Warn, "u")), cur: run(ak(result.Excepted, "u!")), want: []string{"status_change keys warn>excepted"}},
		{name: "authorized_keys error", prev: run(ak(result.Pass)), cur: run(ak(result.Error)), want: []string{"status_change keys pass>error ALERT"}},

		{name: "still failing, nothing else", prev: run(chk("a", result.Fail, "x", "y")), cur: run(chk("a", result.Fail, "y", "x")), stillFailing: []string{"a"}},
		{name: "still failing with no evidence", prev: run(chk("a", result.Fail)), cur: run(chk("a", result.Fail)), stillFailing: []string{"a"}},
		{name: "still warning", prev: run(chk("a", result.Warn, "w")), cur: run(chk("a", result.Warn, "w")), stillWarning: []string{"a"}},
		{name: "new subject", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Fail, "x", "y")), want: []string{"subject_new a y ALERT"}, stillFailing: []string{"a"}},
		{name: "gone subject", prev: run(chk("a", result.Fail, "x", "y")), cur: run(chk("a", result.Fail, "x")), want: []string{"subject_gone a y"}, stillFailing: []string{"a"}},
		{name: "subject swapped, sorted new first", prev: run(chk("a", result.Fail, "m", "z")), cur: run(chk("a", result.Fail, "b", "z", "a")),
			want: []string{"subject_new a a ALERT", "subject_new a b ALERT", "subject_gone a m"}, stillFailing: []string{"a"}},
		{name: "warn, other kind: new subject is reported, not alerted", prev: run(chk("a", result.Warn, "w")), cur: run(chk("a", result.Warn, "w", "v")), want: []string{"subject_new a v"}, stillWarning: []string{"a"}},
		{name: "warn, authorized_keys: new subject alerts", prev: run(ak(result.Warn, "u:1")), cur: run(ak(result.Warn, "u:1", "u:2")), want: []string{"subject_new keys u:2 ALERT"}, stillWarning: []string{"keys"}},
		{name: "warn, authorized_keys: changed subject", prev: run(ak(result.Warn, "u:1")), cur: run(ak(result.Warn, "u:2")), want: []string{"subject_new keys u:2 ALERT", "subject_gone keys u:1"}, stillWarning: []string{"keys"}},
		{name: "items of a passing check are ignored", prev: run(chk("a", result.Pass, "x")), cur: run(chk("a", result.Pass, "y"))},
		{name: "items of an excepted check are ignored", prev: run(chk("a", result.Excepted, "x!")), cur: run(chk("a", result.Excepted, "x!", "y!"))},

		{name: "a new excepted subject does not alert", prev: run(chk("a", result.Fail, "x")), cur: run(chk("a", result.Fail, "x", "y!")), stillFailing: []string{"a"}},
		{name: "an excepted subject that disappears is not reported", prev: run(chk("a", result.Fail, "x", "y!")), cur: run(chk("a", result.Fail, "x")), stillFailing: []string{"a"}},
		{name: "a subject that becomes excepted is gone", prev: run(chk("a", result.Fail, "x", "y")), cur: run(chk("a", result.Fail, "x", "y!")), want: []string{"subject_gone a y"}, stillFailing: []string{"a"}},
		{name: "a subject that stops being excepted is new", prev: run(chk("a", result.Fail, "x", "y!")), cur: run(chk("a", result.Fail, "x", "y")), want: []string{"subject_new a y ALERT"}, stillFailing: []string{"a"}},
		{name: "the same display text under another key is a new subject",
			prev: run(state.Check{ID: "a", Kind: "k", Status: result.Fail, Severity: result.High, Items: []state.Item{{Key: result.SubjectKey("web"), Subject: "web"}}}),
			cur: run(state.Check{ID: "a", Kind: "k", Status: result.Fail, Severity: result.High, Items: []state.Item{
				{Key: result.SubjectKey("web"), Subject: "web"}, {Key: result.SubjectKey("web\x01"), Subject: "web"}}}),
			want: []string{"subject_new a web ALERT"}, stillFailing: []string{"a"}},

		{name: "new in the catalog, failing", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), chk("b", result.Fail, "x")), want: []string{"check_added b ->fail ALERT"}},
		{name: "new in the catalog, error", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), chk("b", result.Error)), want: []string{"check_added b ->error ALERT"}},
		{name: "new in the catalog, passing", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), chk("b", result.Pass)), want: []string{"check_added b ->pass"}},
		{name: "new in the catalog, warn", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), chk("b", result.Warn, "w")), want: []string{"check_added b ->warn"}},
		{name: "new in the catalog, authorized_keys warn", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), ak(result.Warn, "w")), want: []string{"check_added keys ->warn ALERT"}},
		{name: "new in the catalog, skipped", prev: run(chk("a", result.Pass)), cur: run(chk("a", result.Pass), chk("b", result.Skipped)), want: []string{"check_added b ->skipped"}},
		{name: "removed from the catalog", prev: run(chk("a", result.Pass), chk("b", result.Fail, "x")), cur: run(chk("a", result.Pass)), want: []string{"check_removed b fail->"}},

		{name: "order: current run first, removed last",
			prev: run(chk("old1", result.Fail, "x"), chk("a", result.Pass), chk("b", result.Fail, "x"), chk("old2", result.Pass)),
			cur:  run(chk("b", result.Pass), chk("new", result.Fail, "x"), chk("a", result.Fail, "y")),
			want: []string{"fixed b fail>pass", "check_added new ->fail ALERT", "new_failure a pass>fail ALERT", "check_removed old1 fail->", "check_removed old2 pass->"}},

		// Evidence cap: the list is cut, the set is complete. The count of the
		// hidden items never makes a subject.
		{name: "capped, nothing changed", prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, many("s", 104)...)), stillFailing: []string{"a"}},
		{name: "capped, order of the input does not matter",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, reverse(many("s", 104))...)), stillFailing: []string{"a"}},
		{name: "capped, one new item above the cut",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, many("s", 105)...)),
			want: []string{"hidden_new a 1 ALERT"}, stillFailing: []string{"a"}},
		{name: "capped, items gone above the cut",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, many("s", 102)...)),
			want: []string{"hidden_gone a 2"}, stillFailing: []string{"a"}},
		{name: "capped, a new item sorts into the listed part: named, and pushes one out of the window",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, append([]string{"a-new"}, many("s", 104)...)...)),
			want: []string{"subject_new a a-new ALERT"}, stillFailing: []string{"a"}},
		{name: "capped, one in and one out, same total",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, append([]string{"a-new"}, many("s", 103)...)...)),
			want: []string{"subject_new a a-new ALERT", "hidden_gone a 1"}, stillFailing: []string{"a"}},
		{name: "capped, a listed item swapped for a hidden one, same total",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, append(many("s", 104)[1:], "zz-new")...)),
			want: []string{"subject_gone a s-000", "hidden_new a 1 ALERT"}, stillFailing: []string{"a"}},
		{name: "capped, a hidden item swapped for another hidden one, same total",
			prev: run(bigN("a", result.Fail, many("s", 104)...)), cur: run(bigN("a", result.Fail, append(many("s", 103), "zz-new")...)),
			want: []string{"hidden_new a 1 ALERT", "hidden_gone a 1"}, stillFailing: []string{"a"}},
		{name: "capped warn of other kind: a new hidden item is reported, not alerted",
			prev: run(bigN("a", result.Warn, many("s", 104)...)), cur: run(bigN("a", result.Warn, many("s", 109)...)),
			want: []string{"hidden_new a 5"}, stillWarning: []string{"a"}},
		{name: "capped authorized_keys warn: a new hidden item alerts",
			prev: run(kind(bigN("keys", result.Warn, many("s", 104)...), AuthorizedKeysKind)), cur: run(kind(bigN("keys", result.Warn, many("s", 109)...), AuthorizedKeysKind)),
			want: []string{"hidden_new keys 5 ALERT"}, stillWarning: []string{"keys"}},
		{name: "capped error: nothing per item", prev: run(bigN("a", result.Error, many("s", 150)...)), cur: run(bigN("a", result.Error, many("t", 150)...))},
		{name: "pass to capped fail", prev: run(chk("a", result.Pass)), cur: run(bigN("a", result.Fail, many("s", 150)...)), want: []string{"new_failure a pass>fail ALERT"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute(tc.prev, tc.cur)
			if rep.Baseline {
				t.Fatal("Baseline set with a previous run")
			}
			var got []string
			for _, c := range rep.Changes {
				got = append(got, show(c))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("changes:\n got %q\nwant %q", got, tc.want)
			}
			refs := func(rs []Ref) []string {
				var out []string
				for _, r := range rs {
					out = append(out, r.CheckID)
				}
				return out
			}
			if !reflect.DeepEqual(refs(rep.StillFailing), tc.stillFailing) {
				t.Errorf("still failing = %v, want %v", refs(rep.StillFailing), tc.stillFailing)
			}
			if !reflect.DeepEqual(refs(rep.StillWarning), tc.stillWarning) {
				t.Errorf("still warning = %v, want %v", refs(rep.StillWarning), tc.stillWarning)
			}
		})
	}
}

func TestBaselineHasNoChanges(t *testing.T) {
	rep := Compute(nil, run(chk("a", result.Fail, "x"), chk("b", result.Error)))
	if !rep.Baseline || len(rep.Changes) != 0 || len(rep.StillFailing) != 0 || len(rep.Alerts(result.Info)) != 0 {
		t.Errorf("baseline report %+v", rep)
	}
}

func TestChangeCarriesCheckDetails(t *testing.T) {
	rep := Compute(
		run(sev(kind(chk("a", result.Pass), "sshd_effective"), result.Critical)),
		run(sev(kind(chk("a", result.Fail, "x"), "sshd_effective"), result.Critical)),
	)
	if len(rep.Changes) != 1 {
		t.Fatalf("changes %+v", rep.Changes)
	}
	c := rep.Changes[0]
	if c.CheckID != "a" || c.CheckKind != "sshd_effective" || c.Severity != result.Critical || c.From != result.Pass || c.To != result.Fail {
		t.Errorf("change %+v", c)
	}
	// The severity of a removed check is the previous one.
	rep = Compute(run(sev(chk("gone", result.Fail, "x"), result.Low)), run(chk("other", result.Pass)))
	var removed Change
	for _, c := range rep.Changes {
		if c.Kind == CheckRemoved {
			removed = c
		}
	}
	if removed.Severity != result.Low || removed.From != result.Fail {
		t.Errorf("removed change %+v", removed)
	}
}

func TestAlertsFiltersBySeverity(t *testing.T) {
	prev := run(sev(chk("lo", result.Pass), result.Low), sev(chk("mid", result.Pass), result.Medium), sev(chk("hi", result.Pass), result.High),
		sev(chk("fixed", result.Fail, "x"), result.Critical))
	cur := run(sev(chk("lo", result.Fail, "x"), result.Low), sev(chk("mid", result.Fail, "x"), result.Medium), sev(chk("hi", result.Fail, "x"), result.High),
		sev(chk("fixed", result.Pass), result.Critical))
	rep := Compute(prev, cur)
	ids := func(min result.Severity) string {
		var out []string
		for _, c := range rep.Alerts(min) {
			out = append(out, c.CheckID)
		}
		return strings.Join(out, ",")
	}
	if got := ids(result.Info); got != "lo,mid,hi" {
		t.Errorf("Alerts(info) = %s (a fixed check is not an alert)", got)
	}
	if got := ids(result.Medium); got != "mid,hi" {
		t.Errorf("Alerts(medium) = %s", got)
	}
	if got := ids(result.High); got != "hi" {
		t.Errorf("Alerts(high) = %s", got)
	}
	if got := ids(result.Critical); got != "" {
		t.Errorf("Alerts(critical) = %s", got)
	}
}

func TestComputeDoesNotModifyItsInput(t *testing.T) {
	prev := run(chk("a", result.Fail, "x", "y"), chk("b", result.Pass))
	cur := run(chk("a", result.Fail, "y", "z"), chk("c", result.Fail, "q"))
	pb, _ := state.Marshal(prev)
	cb, _ := state.Marshal(cur)
	Compute(prev, cur)
	pa, _ := state.Marshal(prev)
	ca, _ := state.Marshal(cur)
	if string(pb) != string(pa) || string(cb) != string(ca) {
		t.Error("Compute changed its input")
	}
}

func TestCompareIsDeterministic(t *testing.T) {
	prev := run(chk("a", result.Fail, many("p", 30)...), chk("b", result.Pass))
	cur := run(chk("a", result.Fail, many("q", 30)...), chk("b", result.Fail, "x"))
	first := Compute(prev, cur)
	for i := 0; i < 20; i++ {
		if !reflect.DeepEqual(first, Compute(prev, cur)) {
			t.Fatal("Compute is not deterministic")
		}
	}
}
