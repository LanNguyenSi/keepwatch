// Package diff compares two runs of keepwatch and says what changed.
//
// Compute is a pure function of two state snapshots. Per check id it reports:
//
//   - a status change, in one of three kinds: new_failure (the check now
//     fails), fixed (it failed and now passes) and status_change (every other
//     pair, such as pass to error, fail to warn or excepted to fail);
//   - a check that is new in the catalog (check_added) or gone from it
//     (check_removed);
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
// A probe that has more items than its cap lists only the first ones, sorted,
// and says how many it left out (state.Check.Hidden). The list of such a check
// is not a full picture, so the direction that cannot be told is not
// reported: with a capped previous run an item that is listed now may have
// been hidden before, and with a capped current run an item that is no longer
// listed may only be hidden now. Instead the totals are compared, and a
// larger total is reported as count_change. The hidden count itself never
// produces subject changes.
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
	// Alert is true for a change worth waking someone for: a check that
	// started failing, started to be in error, or is new and failing; a new
	// failing item; a bigger item total of a failing check; and, for an
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

// itemChanges compares the items of a check that has the same status, fail
// or warn, in both runs.
func itemChanges(p, c *state.Check) []Change {
	base := Change{CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, From: p.Status, To: c.Status}
	alert := alertWorthy(c.Kind, c.Status)
	// Excepted items do not fail: an item that becomes excepted is gone
	// from the failing set, one that stops being excepted is new in it.
	prevSet := failing(p)
	curSet := failing(c)

	var out []Change
	if !p.Capped() {
		for _, it := range c.Items {
			if it.Excepted || prevSet[it.Key] {
				continue
			}
			ch := base
			ch.Kind, ch.Subject, ch.Alert = SubjectNew, it.Subject, alert
			out = append(out, ch)
		}
	}
	if !c.Capped() {
		for _, it := range p.Items {
			if it.Excepted || curSet[it.Key] {
				continue
			}
			ch := base
			ch.Kind, ch.Subject = SubjectGone, it.Subject
			out = append(out, ch)
		}
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
