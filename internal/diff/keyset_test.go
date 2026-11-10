package diff

import (
	"reflect"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// tally sums up the item changes of a report.
type tally struct {
	named      map[Kind][]string // subjects of subject_new / subject_gone
	hiddenNew  int
	hiddenGone int
	setChanged []Change
	alert      bool
}

func tallyOf(rep Report) tally {
	t := tally{named: map[Kind][]string{}}
	for _, c := range rep.Changes {
		switch c.Kind {
		case SubjectNew, SubjectGone:
			t.named[c.Kind] = append(t.named[c.Kind], c.Subject)
		case HiddenNew:
			t.hiddenNew += c.HiddenNew
		case HiddenGone:
			t.hiddenGone += c.HiddenGone
		case SetChanged:
			t.setChanged = append(t.setChanged, c)
		}
		t.alert = t.alert || c.Alert
	}
	return t
}

func (t tally) news() int  { return len(t.named[SubjectNew]) + t.hiddenNew }
func (t tally) gones() int { return len(t.named[SubjectGone]) + t.hiddenGone }

func cleaner() func(string) string { return redact.Default().Clean }

// The three findings of the last review of the cutoff design, as table cases.
func TestFindingsOfTheCutoffDesign(t *testing.T) {
	clean := cleaner()
	base := many("s", 150)
	without := func(drop string, add ...string) []string {
		var out []string
		for _, n := range base {
			if n != drop {
				out = append(out, n)
			}
		}
		return append(out, add...)
	}
	tests := []struct {
		name      string
		prev, cur state.Check
		// wantNamed are the subject_new and subject_gone subjects, new first.
		wantNew, wantGone []string
		hiddenNew         int
		hiddenGone        int
		alert             bool
	}{
		// F-A: a new item whose subject is changed for display used to be
		// invisible when it replaced a hidden item.
		{name: "F-A escaped subject replaces a hidden item",
			prev: big(clean, "a", result.Fail, base...), cur: big(clean, "a", result.Fail, without("s-149", "zz\x1b[31mevil\nline")...),
			hiddenNew: 1, hiddenGone: 1, alert: true},
		{name: "F-A redacted subject replaces a hidden item",
			prev: big(clean, "a", result.Fail, base...), cur: big(clean, "a", result.Fail, without("s-149", "zz password=hunter2")...),
			hiddenNew: 1, hiddenGone: 1, alert: true},
		{name: "F-A a subject with a control character instead of a hidden lookalike",
			prev: big(clean, "a", result.Fail, append(without("s-149"), "zz\x01")...), cur: big(clean, "a", result.Fail, append(without("s-149"), "zz\x02")...),
			hiddenNew: 1, hiddenGone: 1, alert: true},
		{name: "F-A over-long subject replaces a hidden item",
			prev: big(clean, "a", result.Fail, base...), cur: big(clean, "a", result.Fail, without("s-149", "zz"+strings.Repeat("x", 500))...),
			hiddenNew: 1, hiddenGone: 1, alert: true},
		{name: "F-A the same replacement among the listed items is named with its display text",
			prev: big(clean, "a", result.Fail, base...), cur: big(clean, "a", result.Fail, without("s-149", "a\x01first")...),
			wantNew: []string{`a\x01first`}, hiddenGone: 1, alert: true},
		{name: "F-A not escaped and not hidden: the old case still works",
			prev: big(clean, "a", result.Fail, base...), cur: big(clean, "a", result.Fail, without("s-149", "zz-new")...),
			hiddenNew: 1, hiddenGone: 1, alert: true},

		// F-B: capped on one side and complete on the other.
		{name: "F-B capped to complete: the exact number of gone items",
			prev: bigN("a", result.Fail, base...), cur: bigN("a", result.Fail, many("s", 50)...),
			wantGone: many("s", 99)[50:], hiddenGone: 51},
		{name: "F-B complete to capped: the exact number of new items",
			prev: bigN("a", result.Fail, many("s", 50)...), cur: bigN("a", result.Fail, base...),
			wantNew: many("s", 99)[50:], hiddenNew: 51, alert: true},
		{name: "F-B capped to complete with a new item",
			prev: bigN("a", result.Fail, base...), cur: bigN("a", result.Fail, append(many("s", 50), "x-new")...),
			wantNew: []string{"x-new"}, wantGone: many("s", 99)[50:], hiddenGone: 51, alert: true},

		// F-C: an excepted item is not in the failing set and does not count.
		{name: "F-C a new excepted item adds nothing",
			prev: bigN("a", result.Fail, many("s", 104)...), cur: bigN("a", result.Fail, append(many("s", 104), "a-new!")...)},
		{name: "F-C a new excepted item next to a hidden new one counts only the hidden one",
			prev: bigN("a", result.Fail, many("s", 104)...), cur: bigN("a", result.Fail, append(many("s", 105), "a-new!")...),
			hiddenNew: 1, alert: true},
		{name: "F-C an excepted item that disappears is not gone",
			prev: bigN("a", result.Fail, append(many("s", 104), "a-old!")...), cur: bigN("a", result.Fail, many("s", 104)...)},
		{name: "F-C a listed item that becomes excepted is gone",
			prev: bigN("a", result.Fail, many("s", 104)...), cur: bigN("a", result.Fail, append(many("s", 104)[1:], "s-000!")...),
			wantGone: []string{"s-000"}},
		{name: "F-C an excepted item that stops being excepted is new",
			prev: bigN("a", result.Fail, append(many("s", 104)[1:], "s-000!")...), cur: bigN("a", result.Fail, many("s", 104)...),
			wantNew: []string{"s-000"}, alert: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute(run(tc.prev), run(tc.cur))
			got := tallyOf(rep)
			if !reflect.DeepEqual(got.named[SubjectNew], tc.wantNew) || !reflect.DeepEqual(got.named[SubjectGone], tc.wantGone) ||
				got.hiddenNew != tc.hiddenNew || got.hiddenGone != tc.hiddenGone || got.alert != tc.alert || len(got.setChanged) != 0 {
				t.Errorf("new %q gone %q hidden_new %d hidden_gone %d alert %v set_changed %d\nwant new %q gone %q hidden_new %d hidden_gone %d alert %v",
					got.named[SubjectNew], got.named[SubjectGone], got.hiddenNew, got.hiddenGone, got.alert, len(got.setChanged),
					tc.wantNew, tc.wantGone, tc.hiddenNew, tc.hiddenGone, tc.alert)
			}
		})
	}
}

// An item an exception covers is only marked when it is listed. One that
// sorts into the hidden part is a failing item again, whatever the exception
// says: the failing set follows what the engine reported.
func TestAnExceptedItemThatMovesOutOfTheListedPartFailsAgain(t *testing.T) {
	except := func(names []string, name string) []string {
		out := append([]string(nil), names...)
		for i, n := range out {
			if n == name {
				out[i] = n + "!"
			}
		}
		return out
	}
	prev := bigN("a", result.Fail, except(many("s", 104), "s-050")...) // listed (it sorts before the cut), excepted
	cur := bigN("a", result.Fail, except(append(many("s", 104), many("a", 60)...), "s-050")...)
	got := tallyOf(Compute(run(prev), run(cur)))
	// The sixty a-items are listed now and push s-050 out of the listed
	// part, where it is not marked: it is new in the failing set again, and
	// it is named because the previous run listed it.
	if len(got.named[SubjectNew]) != 61 || got.named[SubjectNew][60] != "s-050" || got.hiddenNew != 0 || !got.alert {
		t.Errorf("%+v", got)
	}
}

// Hash-equal but display-equal subjects stay two items.
func TestSubjectsThatLookTheSameAreTwoItems(t *testing.T) {
	clean := cleaner()
	prev := big(clean, "a", result.Fail, "web\x01")
	cur := big(clean, "a", result.Fail, "web\x01", "web\x02")
	got := tallyOf(Compute(run(prev), run(cur)))
	if len(got.named[SubjectNew]) != 1 || len(got.named[SubjectGone]) != 0 || !got.alert {
		t.Errorf("%+v", got)
	}
}

// bigSet makes n subjects with a prefix.
func bigSet(prefix string, n int) []string { return many(prefix, n) }

// Above result.MaxKeys the keys are not stored and the digests decide.
func TestSetsTooLongToListAreComparedByDigest(t *testing.T) {
	n := result.MaxKeys + 40
	base := bigSet("h", n)
	swapped := append(append([]string(nil), base[:n-1]...), "other")
	moved := append([]string(nil), base...)
	moved[0], moved[n-1] = base[n-1], base[0] // the same list in another order

	check := func(name string, prev, cur state.Check, wantChanged bool, wantTotals [2]int) {
		t.Helper()
		rep := Compute(run(prev), run(cur))
		got := tallyOf(rep)
		if wantChanged {
			if len(got.setChanged) != 1 || !got.alert || got.news()+got.gones() != 0 {
				t.Errorf("%s: %+v", name, got)
				return
			}
			c := got.setChanged[0]
			if c.OldTotal != wantTotals[0] || c.NewTotal != wantTotals[1] || c.CheckID != "a" {
				t.Errorf("%s: totals %d>%d, want %v", name, c.OldTotal, c.NewTotal, wantTotals)
			}
			return
		}
		if len(rep.Changes) != 0 {
			t.Errorf("%s: unexpected changes %+v", name, rep.Changes)
		}
	}
	p := bigN("a", result.Fail, base...)
	if p.Keys != nil || p.Total != n || len(p.Digest) != 64 {
		t.Fatalf("the fixture is not digest only: %d keys, total %d", len(p.Keys), p.Total)
	}
	check("equal sets", p, bigN("a", result.Fail, moved...), false, [2]int{})
	check("one swap", p, bigN("a", result.Fail, swapped...), true, [2]int{n, n})
	check("one more", p, bigN("a", result.Fail, append(append([]string(nil), base...), "extra")...), true, [2]int{n, n + 1})
	check("one fewer", p, bigN("a", result.Fail, base[1:]...), true, [2]int{n, n - 1})
	check("digest only to complete", p, bigN("a", result.Fail, base[:150]...), true, [2]int{n, 150})
	check("complete to digest only", bigN("a", result.Fail, base[:150]...), p, true, [2]int{150, n})
	check("complete, uncapped to digest only", bigN("a", result.Fail, base[:20]...), p, true, [2]int{20, n})
	check("exactly MaxKeys against one more", bigN("a", result.Fail, base[:result.MaxKeys]...), bigN("a", result.Fail, base[:result.MaxKeys+1]...), true, [2]int{result.MaxKeys, result.MaxKeys + 1})

	// Warn of a kind that does not alert: reported, not alerted.
	w := Compute(run(bigN("a", result.Warn, base...)), run(bigN("a", result.Warn, swapped...)))
	if tw := tallyOf(w); len(tw.setChanged) != 1 || tw.alert {
		t.Errorf("warn: %+v", tw)
	}
	// authorized_keys warns alert.
	w = Compute(run(kind(bigN("a", result.Warn, base...), AuthorizedKeysKind)), run(kind(bigN("a", result.Warn, swapped...), AuthorizedKeysKind)))
	if tw := tallyOf(w); len(tw.setChanged) != 1 || !tw.alert {
		t.Errorf("authorized_keys warn: %+v", tw)
	}
}

// Equal digests: the same list. Only an exception can differ, and the items
// it covers are listed, so they are named.
func TestEqualDigestsLeaveOnlyTheExceptions(t *testing.T) {
	base := bigSet("h", result.MaxKeys+40)
	with := func(ex ...string) []string {
		out := append([]string(nil), base...)
		for _, e := range ex {
			for i, n := range out {
				if n == e {
					out[i] = n + "!"
				}
			}
		}
		return out
	}
	rep := Compute(run(bigN("a", result.Fail, with()...)), run(bigN("a", result.Fail, with("h-003")...)))
	got := tallyOf(rep)
	if !reflect.DeepEqual(got.named[SubjectGone], []string{"h-003"}) || got.news() != 0 || got.hiddenGone != 0 || got.alert || len(got.setChanged) != 0 {
		t.Errorf("an item becomes excepted: %+v", got)
	}
	rep = Compute(run(bigN("a", result.Fail, with("h-003")...)), run(bigN("a", result.Fail, with()...)))
	got = tallyOf(rep)
	if !reflect.DeepEqual(got.named[SubjectNew], []string{"h-003"}) || got.gones() != 0 || !got.alert || len(got.setChanged) != 0 {
		t.Errorf("an item stops being excepted: %+v", got)
	}
}

// The numbers in a report equal the true differences.
func TestCountsAreExact(t *testing.T) {
	prev := bigN("a", result.Fail, many("s", 130)...)      // s-000..s-129
	cur := bigN("a", result.Fail, many("s", 400)[100:]...) // s-100..s-399
	got := tallyOf(Compute(run(prev), run(cur)))
	// gone: s-000..s-099 (100 items); new: s-130..s-399 (270 items).
	if got.gones() != 100 || got.news() != 270 || !got.alert {
		t.Errorf("gone %d new %d", got.gones(), got.news())
	}
	// The listed part of the previous run is s-000..s-098: all of those that
	// are gone are named, s-099 is not listed.
	if len(got.named[SubjectGone]) != 99 || got.hiddenGone != 1 {
		t.Errorf("named gone %d hidden gone %d", len(got.named[SubjectGone]), got.hiddenGone)
	}
	// The listed part of the current run is s-100..s-198.
	if len(got.named[SubjectNew]) != 69 || got.hiddenNew != 201 {
		// s-130..s-198 are listed and new: 69; the other 201 are not.
		t.Errorf("named new %d hidden new %d", len(got.named[SubjectNew]), got.hiddenNew)
	}
}

func TestEverySubjectOfAChangeIsAlsoACleanedSubject(t *testing.T) {
	clean := cleaner()
	prev := big(clean, "a", result.Fail)
	cur := big(clean, "a", result.Fail, "bad\x1b[2Jname", "pw password=hunter2")
	for _, c := range Compute(run(prev), run(cur)).Changes {
		if strings.ContainsAny(c.Subject, "\x1b\n") || strings.Contains(c.Subject, "hunter2") {
			t.Errorf("change subject %q", c.Subject)
		}
	}
}
