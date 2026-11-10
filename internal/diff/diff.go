// Package diff compares two runs of keepwatch and says what changed.
//
// Compute is a pure function of two state snapshots. Per check id it reports:
//
//   - a status change, in one of three kinds: new_failure (the check now
//     fails), fixed (it failed and now passes) and status_change (every other
//     pair, such as pass to error, fail to warn or excepted to fail);
//   - a check that is new in the catalog (check_added) or gone from it
//     (check_removed);
//   - a severity change of a check whose status did not change and is fail,
//     warn or error (severity_change);
//   - for a check that is fail or warn in both runs: items that are new
//     (subject_new) or gone (subject_gone), and a change of the item count
//     when the probe capped its list (count_change);
//   - the checks that keep failing, or keep warning, unchanged
//     (Report.StillFailing, Report.StillWarning).
//
// An error result is a partial picture: the probe could not see everything,
// so the evidence it kept is not compared. A check that is or was in error
// yields its status change once and never a per-item change.
//
// A probe that has more items than its cap lists only the first ones, sorted
// by raw subject, and says how many it left out (state.Check.Hidden). The
// state also keeps where it cut the list (state.Check.Cutoff, the raw subject
// of the last listed item) and, per item, whether its stored subject is the
// raw one (state.Item.Exact). That is enough to tell, for part of the list:
//
//   - with a capped previous run, an item that is listed now and sorts before
//     the previous cutoff would have been listed before if it had existed, so
//     it is new (subject_new, an alert as usual); an item that sorts after
//     the cutoff may have been hidden before, so nothing is said about it;
//   - with a capped current run, an item of the previous run that is not
//     listed now and sorts before the current cutoff is gone (subject_gone);
//     one that sorts after it may only be hidden now.
//
// When the cutoff or the item is not known (an older state file, a subject
// that was escaped, redacted or cut for display) the item counts as above the
// cutoff: nothing is said about it. In every capped case the totals are
// compared too, and a larger total is reported as count_change. The hidden
// count itself never produces subject changes.
//
// Which changes are worth an alert is decided here (Change.Alert); the exit
// code of `keepwatch check` does not depend on the diff, only on the current
// results (see the cli package).
package diff

import (
	"sort"

	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// Kind is the kind of a change.
type Kind string

// The kinds of change.
const (
	NewFailure   Kind = "new_failure"
	Fixed        Kind = "fixed"
	StatusChange Kind = "status_change"
	CheckAdded   Kind = "check_added"
	CheckRemoved Kind = "check_removed"
	SubjectNew   Kind = "subject_new"
	SubjectGone  Kind = "subject_gone"
	CountChange  Kind = "count_change"
	// SeverityChange is a changed severity of a check whose status is the
	// same in both runs (and fail, warn or error).
	SeverityChange Kind = "severity_change"
)

// AuthorizedKeysKind is the probe kind whose warn results are alert-worthy:
// a warn of that check can stand for keys that were not checked.
const AuthorizedKeysKind = "authorized_keys"

// Change is one difference between two runs.
type Change struct {
	Kind    Kind
	CheckID string
	// CheckKind is the probe kind of the check.
	CheckKind string
	// Severity is the check's severity in the current run (in the previous
	// run for check_removed).
	Severity result.Severity
	// From and To are the statuses before and after; empty where they do
	// not apply (From for check_added, To for check_removed).
	From, To result.Status
	// Subject is the display subject of an item change.
	Subject string
	// OldTotal and NewTotal are the item totals of a count_change.
	OldTotal, NewTotal int
	// FromSeverity and ToSeverity are the severities of a severity_change.
	FromSeverity, ToSeverity result.Severity
	// Alert is true for a change worth waking someone for: a check that
	// started failing, started to be in error, or is new and failing; a new
	// failing item; a bigger item total of a failing check; a higher
	// severity of a check that is failing or in error; and, for an
	// authorized_keys check, a warn that is new or has new items.
	Alert bool
}

// Ref names a check that is in the same state in both runs.
type Ref struct {
	CheckID   string
	CheckKind string
	Severity  result.Severity
}

// Report is the result of comparing two runs.
type Report struct {
	// Baseline is true when there was no previous run to compare with. A
	// baseline report has no changes: it says nothing about what is new.
	Baseline bool
	Changes  []Change
	// StillFailing lists the checks that fail in both runs, StillWarning
	// those that warn in both, in the order of the current run.
	StillFailing []Ref
	StillWarning []Ref
}

// Alerts returns the alert-worthy changes whose severity is at least min.
func (r Report) Alerts(min result.Severity) []Change {
	var out []Change
	for _, c := range r.Changes {
		if c.Alert && rank(c.Severity) >= rank(min) {
			out = append(out, c)
		}
	}
	return out
}

func rank(s result.Severity) int {
	for i, v := range result.Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Compute compares the previous run with the current one. A nil prev is a
// baseline. Changes come in the order of the current run's checks (status
// change first, then item changes sorted by subject), followed by the checks
// that are gone, in the order of the previous run.
func Compute(prev, cur *state.State) Report {
	if prev == nil {
		return Report{Baseline: true}
	}
	var rep Report
	seen := map[string]bool{}
	for i := range cur.Checks {
		c := &cur.Checks[i]
		seen[c.ID] = true
		p := prev.Find(c.ID)
		if p == nil {
			rep.Changes = append(rep.Changes, Change{
				Kind: CheckAdded, CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, To: c.Status,
				Alert: alertWorthy(c.Kind, c.Status),
			})
			continue
		}
		if p.Status != c.Status {
			rep.Changes = append(rep.Changes, statusChange(p, c))
			continue
		}
		if p.Severity != c.Severity {
			if ch, ok := severityChange(p, c); ok {
				rep.Changes = append(rep.Changes, ch)
			}
		}
		ref := Ref{CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity}
		switch c.Status {
		case result.Fail:
			rep.StillFailing = append(rep.StillFailing, ref)
		case result.Warn:
			rep.StillWarning = append(rep.StillWarning, ref)
		default:
			continue
		}
		rep.Changes = append(rep.Changes, itemChanges(p, c)...)
	}
	for i := range prev.Checks {
		p := &prev.Checks[i]
		if !seen[p.ID] {
			rep.Changes = append(rep.Changes, Change{
				Kind: CheckRemoved, CheckID: p.ID, CheckKind: p.Kind, Severity: p.Severity, From: p.Status,
			})
		}
	}
	return rep
}

// alertWorthy reports whether a check that is in status s is worth an alert
// when it appears or turns into s.
func alertWorthy(kind string, s result.Status) bool {
	switch s {
	case result.Fail, result.Error:
		return true
	case result.Warn:
		return kind == AuthorizedKeysKind
	}
	return false
}

func statusChange(p, c *state.Check) Change {
	ch := Change{Kind: StatusChange, CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, From: p.Status, To: c.Status}
	switch {
	case c.Status == result.Fail:
		ch.Kind = NewFailure
		ch.Alert = true
	case p.Status == result.Fail && c.Status == result.Pass:
		ch.Kind = Fixed
	default:
		ch.Alert = alertWorthy(c.Kind, c.Status)
	}
	return ch
}

// severityChange reports a changed severity of a check that has the same
// status in both runs. It is reported for the statuses that stand for an open
// problem (fail, warn, error); for the others the severity is not shown to
// anyone. It is an alert when the severity went up and the status counts
// toward the exit code of `check` (fail and error; a warn only for the
// authorized_keys check): a failure that was below --fail-on can have
// crossed it.
func severityChange(p, c *state.Check) (Change, bool) {
	switch c.Status {
	case result.Fail, result.Warn, result.Error:
	default:
		return Change{}, false
	}
	return Change{
		Kind: SeverityChange, CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, From: p.Status, To: c.Status,
		FromSeverity: p.Severity, ToSeverity: c.Severity,
		Alert: rank(c.Severity) > rank(p.Severity) && alertWorthy(c.Kind, c.Status),
	}, true
}

// itemChanges compares the items of a check that has the same status, fail
// or warn, in both runs.
func itemChanges(p, c *state.Check) []Change {
	base := Change{CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, From: p.Status, To: c.Status}
	alert := alertWorthy(c.Kind, c.Status)
	// Excepted items do not fail: an item that becomes excepted is gone
	// from the failing set, one that stops being excepted is new in it.
	prevSet, prevAll := failing(p), keys(p)
	curSet, curAll := failing(c), keys(c)

	var out []Change
	for _, it := range c.Items {
		if it.Excepted || prevSet[it.Key] {
			continue
		}
		// An item the previous run did not list is new only if that run
		// would have listed it.
		if !prevAll[it.Key] && !wasVisible(p, it) {
			continue
		}
		ch := base
		ch.Kind, ch.Subject, ch.Alert = SubjectNew, it.Subject, alert
		out = append(out, ch)
	}
	for _, it := range p.Items {
		if it.Excepted || curSet[it.Key] {
			continue
		}
		// Likewise an item that is not listed now is gone only if this run
		// would have listed it.
		if !curAll[it.Key] && !wasVisible(c, it) {
			continue
		}
		ch := base
		ch.Kind, ch.Subject = SubjectGone, it.Subject
		out = append(out, ch)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind == SubjectNew
		}
		return out[i].Subject < out[j].Subject
	})
	if (p.Capped() || c.Capped()) && p.Total() != c.Total() {
		ch := base
		ch.Kind, ch.OldTotal, ch.NewTotal = CountChange, p.Total(), c.Total()
		ch.Alert = alert && c.Total() > p.Total()
		out = append(out, ch)
	}
	return out
}

// wasVisible reports whether run r, in which item it is not listed, would have
// listed it had it existed: the list of r is complete, or the item sorts at or
// before the cutoff of r (the cutoff is the last item listed, so everything up
// to it was). An item that cannot be placed (no cutoff, or a
// subject that is not stored as it was) is not known to be visible.
func wasVisible(r *state.Check, it state.Item) bool {
	if !r.Capped() {
		return true
	}
	return r.Cutoff != nil && it.Exact && it.Subject <= *r.Cutoff
}

// keys returns the keys of all items of c, excepted ones too.
func keys(c *state.Check) map[string]bool {
	m := make(map[string]bool, len(c.Items))
	for _, it := range c.Items {
		m[it.Key] = true
	}
	return m
}

// failing returns the keys of the items of c that are not excepted. Items of
// a warn check are never excepted (an exception removes failures only).
func failing(c *state.Check) map[string]bool {
	m := make(map[string]bool, len(c.Items))
	for _, it := range c.Items {
		if !it.Excepted {
			m[it.Key] = true
		}
	}
	return m
}
