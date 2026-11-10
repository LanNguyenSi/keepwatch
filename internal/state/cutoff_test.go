package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// scrub stands in for the redactor: it hides the word "secret" and escapes a
// newline, so a subject that holds either is not shown as it is.
func scrub(s string) string {
	return strings.NewReplacer("secret", "[REDACTED]", "\n", `\n`).Replace(s)
}

// capped appends the marker a probe adds to a list it cut: the limit it names
// is the length of the list with the marker.
func capped(ev ...result.Evidence) []result.Evidence { return append(ev, marker(7, len(ev)+1)) }

func subjects(ss ...string) []result.Evidence {
	var out []result.Evidence
	for _, s := range ss {
		out = append(out, result.Evidence{Subject: s})
	}
	return out
}

func TestCutoffIsTheLastListedRawSubject(t *testing.T) {
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: append(items(99), marker(7, 100))}}, t0, scrub)
	c := st.Checks[0]
	if c.Cutoff == nil || *c.Cutoff != "item-098" {
		t.Fatalf("Cutoff = %v, want item-098", c.Cutoff)
	}
	for _, it := range c.Items {
		if !it.Exact {
			t.Errorf("item %q is not marked exact", it.Subject)
		}
	}
}

func TestCutoffIsKeptOnlyWhenItIsSafeAndKnown(t *testing.T) {
	long := strings.Repeat("x", displayRunes+1)
	cases := []struct {
		name  string
		rs    []result.Result
		clean func(string) string
		want  string // "" means no cutoff
	}{
		{"plain subject", []result.Result{{Evidence: capped(subjects("a", "b")...)}}, scrub, "b"},
		{"no clean function", []result.Result{{Evidence: capped(subjects("a", "b")...)}}, nil, "b"},
		{"list is complete", []result.Result{{Evidence: subjects("a", "b")}}, scrub, ""},
		{"last subject holds a secret", []result.Result{{Evidence: capped(subjects("a", "b secret c")...)}}, scrub, ""},
		{"last subject is escaped", []result.Result{{Evidence: capped(subjects("a", "b\nc")...)}}, scrub, ""},
		{"last subject is cut for display", []result.Result{{Evidence: capped(subjects("a", long)...)}}, scrub, ""},
		{"last subject is not UTF-8", []result.Result{{Evidence: capped(subjects("a", "b\xff")...)}}, nil, ""},
		{"list is not sorted", []result.Result{{Evidence: capped(subjects("b", "a")...)}}, scrub, ""},
		{"equal subjects are sorted", []result.Result{{Evidence: capped(subjects("a", "a")...)}}, scrub, "a"},
		{"an earlier subject holds a secret", []result.Result{{Evidence: capped(subjects("a secret", "b")...)}}, scrub, "b"},
		{"capped, then merged with more items", []result.Result{{Evidence: capped(subjects("a", "b")...)}, {Evidence: subjects("c")}}, scrub, ""},
		{"more items, then merged with a capped list", []result.Result{{Evidence: subjects("c")}, {Evidence: capped(subjects("a", "b")...)}}, scrub, ""},
		{"empty capped list", []result.Result{{Evidence: capped()}}, scrub, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for i := range c.rs {
				c.rs[i].CheckID, c.rs[i].Status, c.rs[i].Severity = "a.b", result.Fail, result.Low
			}
			st := FromResults(c.rs, t0, c.clean)
			got := st.Checks[0].Cutoff
			switch {
			case c.want == "" && got != nil:
				t.Errorf("Cutoff = %q, want none", *got)
			case c.want != "" && (got == nil || *got != c.want):
				t.Errorf("Cutoff = %v, want %q", got, c.want)
			}
			if got != nil {
				b, err := Marshal(st)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parse(b); err != nil {
					t.Errorf("the state with a cutoff is rejected by parse: %v", err)
				}
			}
		})
	}
}

func TestItemIsExactOnlyWhenItsDisplayTextIsTheRawSubject(t *testing.T) {
	long := strings.Repeat("x", displayRunes+1)
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low,
		Evidence: subjects("plain", "has secret", "line\nbreak", long, "bad\xffutf8")}}, t0, scrub)
	want := []bool{true, false, false, false, false}
	for i, it := range st.Checks[0].Items {
		if it.Exact != want[i] {
			t.Errorf("item %d (%q): Exact = %v, want %v", i, it.Subject, it.Exact, want[i])
		}
	}
}

func TestCutoffAddsNoTextThatTheStateDoesNotHoldAlready(t *testing.T) {
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low,
		Evidence: capped(subjects("a", "tcp/0.0.0.0:22 secret")...)}}, t0, scrub)
	b, err := Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "secret") {
		t.Errorf("the state holds the raw subject:\n%s", b)
	}
	if st.Checks[0].Cutoff != nil {
		t.Errorf("Cutoff = %q, want none for a subject that was redacted", *st.Checks[0].Cutoff)
	}
}

func TestCutoffSurvivesSaveAndLoad(t *testing.T) {
	s, _ := newStore(t)
	st := FromResults([]result.Result{
		{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: append(items(99), marker(7, 100))},
		{CheckID: "c.d", Status: result.Fail, Severity: result.Low, Evidence: items(3)},
	}, t0, scrub)
	mustSave(t, s, st)
	lr, err := s.Load()
	if err != nil || lr.State == nil {
		t.Fatalf("Load: %+v, %v", lr, err)
	}
	a, b := lr.State.Checks[0], lr.State.Checks[1]
	if a.Cutoff == nil || *a.Cutoff != "item-098" || !a.Items[98].Exact {
		t.Errorf("cutoff or exact mark lost: %v %+v", a.Cutoff, a.Items[98])
	}
	if b.Cutoff != nil {
		t.Errorf("a complete list has a cutoff: %q", *b.Cutoff)
	}
}

// A state file of version 1 has no cutoff and no exact marks. It is read, and
// anything it claims about them is ignored, so a capped list in it is treated
// like one whose cutoff is unknown.
func TestStateFileOfVersion1IsReadWithoutCutoffs(t *testing.T) {
	key := SubjectKey("a")
	v1 := fmt.Sprintf(`{"schema_version": 1, "run_at": "2026-11-10T12:00:00Z", "checks": [
	  {"id": "a.b", "kind": "k", "status": "fail", "severity": "low", "hidden": 3, "cutoff": "a",
	   "items": [{"key": %q, "subject": "a", "exact": true}]}]}`, key)
	st, err := parse([]byte(v1))
	if err != nil {
		t.Fatalf("a version 1 file is rejected: %v", err)
	}
	c := st.Checks[0]
	if st.SchemaVersion != 1 || c.Hidden != 3 || c.Cutoff != nil || c.Items[0].Exact || c.Items[0].Subject != "a" {
		t.Errorf("version 1 state: schema %d, hidden %d, cutoff %v, item %+v", st.SchemaVersion, c.Hidden, c.Cutoff, c.Items[0])
	}

	v2 := strings.Replace(v1, `"schema_version": 1`, `"schema_version": 2`, 1)
	st, err = parse([]byte(v2))
	if err != nil {
		t.Fatalf("the same content as version 2 is rejected: %v", err)
	}
	if c := st.Checks[0]; c.Cutoff == nil || *c.Cutoff != "a" || !c.Items[0].Exact {
		t.Errorf("version 2 state lost its cutoff: %v %+v", c.Cutoff, c.Items[0])
	}
}

func TestStateFileOfAnotherVersionIsNotRead(t *testing.T) {
	good, err := Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []int{0, SchemaVersion + 1, -1} {
		b := strings.Replace(string(good), fmt.Sprintf(`"schema_version": %d`, SchemaVersion), fmt.Sprintf(`"schema_version": %d`, v), 1)
		if _, err := parse([]byte(b)); err == nil {
			t.Errorf("schema version %d is accepted", v)
		}
	}
}

// A stored cutoff is the subject of the last listed item, so it must equal the
// subject of one item of that check, stored exactly. Anything else is a
// corrupted or forged file: it is rejected, and the run starts a new baseline.
func TestCutoffMustBeTheSubjectOfAnExactItem(t *testing.T) {
	item := func(subject string, exact bool) string {
		return fmt.Sprintf(`{"key": %q, "subject": %q, "exact": %v}`, SubjectKey(subject), subject, exact)
	}
	file := func(cutoff string, hidden int, items ...string) string {
		return fmt.Sprintf(`{"schema_version": 2, "run_at": "2026-11-10T12:00:00Z", "checks": [
		  {"id": "a.b", "kind": "k", "status": "fail", "severity": "low", "hidden": %d, "cutoff": %s,
		   "items": [%s]}]}`, hidden, cutoff, strings.Join(items, ","))
	}
	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{"cutoff equals an exact item", file(`"b"`, 3, item("a", true), item("b", true)), true},
		{"cutoff equals the first exact item, not the last", file(`"a"`, 3, item("a", true), item("b", true)), true},
		{"cutoff names no item", file(`"zzz"`, 3, item("a", true), item("b", true)), false},
		{"cutoff equals an item that is not stored exactly", file(`"b"`, 3, item("a", true), item("b", false)), false},
		{"cutoff differs in case", file(`"B"`, 3, item("a", true), item("b", true)), false},
		{"cutoff of a check without items", file(`"b"`, 3), false},
		{"empty cutoff, no item with an empty subject", file(`""`, 3, item("a", true)), false},
		{"no cutoff is fine", file(`null`, 3, item("a", true)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte(tc.body))
			if (err == nil) != tc.ok {
				t.Errorf("parse error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// The invalid file leads to a problem and no state through Load (the caller
// warns and starts a new baseline), never to a diff against a cutoff that
// points nowhere.
func TestLoadTurnsABadCutoffIntoAProblem(t *testing.T) {
	body := fmt.Sprintf(`{"schema_version": 2, "run_at": "2026-11-10T12:00:00Z", "checks": [
	  {"id": "a.b", "kind": "k", "status": "fail", "severity": "low", "hidden": 3, "cutoff": "zzz",
	   "items": [{"key": %q, "subject": "a", "exact": true}]}]}`, SubjectKey("a"))
	s, dir := newStore(t)
	mustSave(t, s, sample())
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.State != nil || !strings.Contains(r.Problem, "cutoff") {
		t.Errorf("Load = %+v, want a problem about the cutoff and no state", r)
	}
}
