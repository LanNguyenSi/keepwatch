package diff

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// list builds a fail check of a probe that cut its list: the items are the
// listed prefix (in sorted order, all stored as they were), hidden is the
// number left out, and the cutoff is the last listed subject. An item ending
// in "!" is excepted; one ending in "~" is stored as not exact.
func list(hidden int, items ...string) state.Check {
	var plain []string
	for _, it := range items {
		plain = append(plain, strings.TrimSuffix(it, "~"))
	}
	c := chk("a", result.Fail, plain...)
	for i, it := range items {
		c.Items[i].Exact = !strings.HasSuffix(it, "~")
	}
	if hidden > 0 && len(c.Items) > 0 {
		cut := c.Items[len(c.Items)-1].Subject
		c.Cutoff = &cut
	}
	c.Hidden = hidden
	return c
}

// noCutoff is c as an older state file would hold it.
func noCutoff(c state.Check) state.Check {
	c.Cutoff = nil
	c.Items = append([]state.Item(nil), c.Items...)
	for i := range c.Items {
		c.Items[i].Exact = false
	}
	return c
}

func TestCappedListsAreComparedBelowTheCutoff(t *testing.T) {
	// The previous run listed b, d, f, h and left 5 out, all of them above h.
	prev := list(5, "b", "d", "f", "h")
	tests := []struct {
		name      string
		prev, cur state.Check
		want      []string
	}{
		{name: "swap below the cutoff, same total: the new item alerts",
			prev: prev, cur: list(5, "b", "c", "f", "h"),
			want: []string{"subject_new a c ALERT", "subject_gone a d"}},
		{name: "swap above the cutoff, same total: nothing",
			prev: prev, cur: list(5, "b", "d", "f", "h")},
		{name: "an item enters the window from above: it is not new, the one that left is gone",
			prev: prev, cur: list(4, "b", "f", "h", "i"),
			want: []string{"subject_gone a d", "count_change a 9>8"}},
		{name: "shrink, only above the cutoff",
			prev: prev, cur: list(2, "b", "d", "f", "h"),
			want: []string{"count_change a 9>6"}},
		{name: "shrink with an item gone below the cutoff",
			prev: prev, cur: list(1, "b", "f", "h", "i"),
			want: []string{"subject_gone a d", "count_change a 9>5"}},
		{name: "grow with a new item below the cutoff",
			prev: prev, cur: list(8, "b", "c", "d", "f"),
			want: []string{"subject_new a c ALERT", "count_change a 9>12 ALERT"}},
		{name: "grow above the cutoff only",
			prev: prev, cur: list(9, "b", "d", "f", "h"),
			want: []string{"count_change a 9>13 ALERT"}},
		{name: "a new item at the cutoff itself is the cutoff item, so not new",
			prev: prev, cur: list(5, "b", "d", "f", "h")},
		{name: "an item just above the cutoff may have been hidden: it is not new",
			prev: prev, cur: list(5, "b", "d", "f", "i"),
			want: []string{"subject_gone a h"}},
		{name: "an item just below the cutoff would have been listed: it is new, and h left the window",
			prev: prev, cur: list(5, "b", "d", "f", "g"),
			want: []string{"subject_new a g ALERT"}},
		{name: "a new item that is not stored exactly cannot be placed",
			prev: prev, cur: list(5, "b", "c~", "f", "h"),
			want: []string{"subject_gone a d"}},
		{name: "an item gone that is not stored exactly cannot be placed",
			prev: list(5, "b", "d~", "f", "h"), cur: list(5, "b", "c", "f", "h"),
			want: []string{"subject_new a c ALERT"}},
		{name: "the previous run is from an older state file (no cutoff, no exact marks): no item changes",
			prev: noCutoff(prev), cur: list(5, "b", "c", "f", "h")},
		{name: "an older state file and the totals differ: the total only",
			prev: noCutoff(prev), cur: list(6, "b", "c", "f", "h"),
			want: []string{"count_change a 9>10 ALERT"}},
		{name: "the previous run has marks but no cutoff: new cannot be placed, gone can",
			prev: func() state.Check { c := prev; c.Cutoff = nil; return c }(), cur: list(5, "b", "c", "f", "h"),
			want: []string{"subject_gone a d"}},
		{name: "the current run has marks but no cutoff: new can be placed, gone cannot",
			prev: prev, cur: func() state.Check { c := list(5, "b", "c", "f", "h"); c.Cutoff = nil; return c }(),
			want: []string{"subject_new a c ALERT"}},
		{name: "an item that was excepted and is not any more is new, even in a capped list",
			prev: list(5, "b", "d!", "f", "h"), cur: list(5, "b", "d", "f", "h"),
			want: []string{"subject_new a d ALERT"}},
		{name: "an item that is excepted now is gone, even in a capped list",
			prev: prev, cur: list(5, "b", "d!", "f", "h"),
			want: []string{"subject_gone a d"}},

		{name: "previous complete, now capped: an item missing below the cutoff is gone, one above is not",
			prev: list(0, "b", "d", "z"), cur: list(4, "b", "c", "z"),
			want: []string{"subject_new a c ALERT", "subject_gone a d", "count_change a 3>7 ALERT"}},
		{name: "previous complete, now capped: an item above the cutoff is not reported gone",
			prev: list(0, "b", "d", "z"), cur: list(4, "b", "c", "d"),
			want: []string{"subject_new a c ALERT", "count_change a 3>7 ALERT"}},
		{name: "previous capped, now complete: an item below the previous cutoff is new, one above is not",
			prev: prev, cur: list(0, "b", "c", "d", "f", "h", "k"),
			want: []string{"subject_new a c ALERT", "count_change a 9>6"}},
		{name: "previous capped, now complete: everything missing is gone",
			prev: prev, cur: list(0, "b"),
			want: []string{"subject_gone a d", "subject_gone a f", "subject_gone a h", "count_change a 9>1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range Compute(run(tc.prev), run(tc.cur)).Changes {
				got = append(got, show(c))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("changes:\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// With a real-sized list: 99 listed items, one of them swapped for a new one
// that sorts inside the listed part, the total unchanged. This is the case in
// which a new listener went unnoticed.
func TestSwapInsideTheListedPartOfACappedListIsReported(t *testing.T) {
	names := many("tcp/198.51.100.1:", 99)
	prev := list(51, names...)
	curNames := append([]string{"tcp/198.51.100.1:,new"}, names[:98]...)
	cur := list(51, curNames...)
	rep := Compute(run(prev), run(cur))
	var got []string
	for _, c := range rep.Changes {
		got = append(got, show(c))
	}
	// The last listed item of the previous run left the window: it sorts
	// after the new cutoff, so it is not reported gone.
	want := []string{"subject_new a tcp/198.51.100.1:,new ALERT"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes:\n got %q\nwant %q", got, want)
	}
	if len(rep.Alerts(result.Info)) != 1 {
		t.Errorf("alerts = %+v", rep.Alerts(result.Info))
	}
}

func TestSeverityChange(t *testing.T) {
	ak := func(st result.Status, s result.Severity, items ...string) state.Check {
		return sev(kind(chk("a", st, items...), AuthorizedKeysKind), s)
	}
	tests := []struct {
		name         string
		prev, cur    state.Check
		want         []string
		stillFailing bool
	}{
		{name: "fail, higher: alert", prev: sev(chk("a", result.Fail, "x"), result.Low), cur: sev(chk("a", result.Fail, "x"), result.Critical),
			want: []string{"severity_change a low>critical (fail) ALERT"}, stillFailing: true},
		{name: "fail, lower: no alert", prev: sev(chk("a", result.Fail, "x"), result.Critical), cur: sev(chk("a", result.Fail, "x"), result.Low),
			want: []string{"severity_change a critical>low (fail)"}, stillFailing: true},
		{name: "fail, one step", prev: sev(chk("a", result.Fail, "x"), result.Medium), cur: sev(chk("a", result.Fail, "x"), result.High),
			want: []string{"severity_change a medium>high (fail) ALERT"}, stillFailing: true},
		{name: "fail, unchanged", prev: sev(chk("a", result.Fail, "x"), result.High), cur: sev(chk("a", result.Fail, "x"), result.High), stillFailing: true},
		{name: "fail, higher, and a new item", prev: sev(chk("a", result.Fail, "x"), result.Low), cur: sev(chk("a", result.Fail, "x", "y"), result.High),
			want: []string{"severity_change a low>high (fail) ALERT", "subject_new a y ALERT"}, stillFailing: true},
		{name: "error, higher: alert", prev: sev(chk("a", result.Error), result.Low), cur: sev(chk("a", result.Error), result.High),
			want: []string{"severity_change a low>high (error) ALERT"}},
		{name: "error, lower: no alert", prev: sev(chk("a", result.Error), result.High), cur: sev(chk("a", result.Error), result.Low),
			want: []string{"severity_change a high>low (error)"}},
		{name: "warn of another kind, higher: reported, no alert", prev: sev(chk("a", result.Warn, "w"), result.Low), cur: sev(chk("a", result.Warn, "w"), result.High),
			want: []string{"severity_change a low>high (warn)"}},
		{name: "authorized_keys warn, higher: alert", prev: ak(result.Warn, result.Low, "w"), cur: ak(result.Warn, result.High, "w"),
			want: []string{"severity_change a low>high (warn) ALERT"}},
		{name: "pass: not reported", prev: sev(chk("a", result.Pass), result.Low), cur: sev(chk("a", result.Pass), result.High)},
		{name: "skipped: not reported", prev: sev(chk("a", result.Skipped), result.Low), cur: sev(chk("a", result.Skipped), result.High)},
		{name: "excepted: not reported", prev: sev(chk("a", result.Excepted, "x!"), result.Low), cur: sev(chk("a", result.Excepted, "x!"), result.High)},
		{name: "a changed status is one status change, not two", prev: sev(chk("a", result.Pass), result.Low), cur: sev(chk("a", result.Fail, "x"), result.High),
			want: []string{"new_failure a pass>fail ALERT"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := Compute(run(tc.prev), run(tc.cur))
			var got []string
			for _, c := range rep.Changes {
				got = append(got, show(c))
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("changes:\n got %q\nwant %q", got, tc.want)
			}
			if tc.stillFailing != (len(rep.StillFailing) == 1) {
				t.Errorf("still failing = %v", rep.StillFailing)
			}
		})
	}
}

func TestSeverityChangeIsAnAlertAtTheNewSeverity(t *testing.T) {
	rep := Compute(run(sev(chk("a", result.Fail, "x"), result.Low)), run(sev(chk("a", result.Fail, "x"), result.High)))
	if len(rep.Alerts(result.Medium)) != 1 {
		t.Errorf("a failure that rose from low to high should alert at medium: %+v", rep.Changes)
	}
	rep = Compute(run(sev(chk("a", result.Fail, "x"), result.High)), run(sev(chk("a", result.Fail, "x"), result.Low)))
	if len(rep.Alerts(result.Info)) != 0 {
		t.Errorf("a failure that fell in severity should not alert: %+v", rep.Alerts(result.Info))
	}
	c := rep.Changes[0]
	if c.Kind != SeverityChange || c.Severity != result.Low || c.FromSeverity != result.High || c.ToSeverity != result.Low {
		t.Errorf("change %+v", c)
	}
}

// probeList is what a probe returns for n sorted subjects when it cuts the
// list at 100 items: the first 99 and the marker.
func probeList(subjects []string) []result.Evidence {
	var ev []result.Evidence
	for _, s := range subjects {
		ev = append(ev, result.Evidence{Subject: s})
	}
	if len(ev) <= 100 {
		return ev
	}
	hidden := len(ev) - 99
	ev = append(ev[:99:99], result.Evidence{
		Subject: "(" + strconv.Itoa(hidden) + " more not shown)",
		Detail:  strconv.Itoa(hidden) + " further items are not listed, the limit is 100 items",
	})
	return ev
}

// The whole path from probe output to the diff: 150 listeners, one of them
// replaced by a new one that sorts inside the listed part.
func TestCappedSwapFromProbeOutputToDiff(t *testing.T) {
	build := func(subjects []string) *state.State {
		return state.FromResults([]result.Result{{CheckID: "net.listeners", Kind: "listeners", Status: result.Fail, Severity: result.High,
			Evidence: probeList(subjects)}}, run().RunAt, nil)
	}
	all := many("tcp/198.51.100.1:", 150)
	swapped := append([]string{}, all...)
	swapped[10] = "tcp/198.51.100.1:,new"
	// the probe sorts before it cuts
	sort.Strings(swapped)

	rep := Compute(build(all), build(swapped))
	var got []string
	for _, c := range rep.Changes {
		got = append(got, show(c))
	}
	if len(got) != 2 || got[0] != "subject_new net.listeners tcp/198.51.100.1:,new ALERT" || got[1] != "subject_gone net.listeners tcp/198.51.100.1:-010" {
		t.Errorf("changes: %q", got)
	}

	// A swap above the cutoff: the listed part is the same.
	above := append([]string{}, all...)
	above[140] = "tcp/198.51.100.1:~new"
	sort.Strings(above)
	if rep := Compute(build(all), build(above)); len(rep.Changes) != 0 {
		t.Errorf("a swap above the cutoff produced changes: %+v", rep.Changes)
	}
}
