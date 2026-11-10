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
//   - for a check that is fail or warn in both runs: the items that are new
//     (subject_new, hidden_new) or gone (subject_gone, hidden_gone), and, for
//     a list too long to compare item by item, set_changed;
//   - the checks that keep failing, or keep warning, unchanged
//     (Report.StillFailing, Report.StillWarning).
//
// An error result is a partial picture: the probe could not see everything,
// so the evidence it kept is not compared. A check that is or was in error
// yields its status change once and never a per-item change.
//
// Items are compared as sets, never through what happened to be listed. The
// failing set of a check is the set of the keys of all its items (the SHA-256
// of the raw subject) without the keys of the items an exception covers. A
// probe that has more items than it lists keeps the complete key set of its
// list (state.Check.Keys) next to the items it lists, and a list that was not
// cut is its own set, so a capped and a complete list compare like any other
// pair. Per check:
//
//   - both sets are complete (at most result.MaxKeys keys each): the
//     difference is exact. A key that is new in the failing set is reported
//     as subject_new when its subject is among the items listed (in the
//     current run, or in the previous one for an item an exception stopped
//     covering) and otherwise counted into one hidden_new with the exact
//     number; a key that left the failing set is reported as subject_gone
//     under the same rule, or counted into one hidden_gone;
//   - a set has more than result.MaxKeys keys, so its keys are not stored:
//     the digests of the complete key lists are compared. Equal digests mean
//     the same list, and only a changed exception shows (named as above).
//     Different digests are one set_changed change with both totals: that
//     something changed is certain, what is not. A change of an excepted
//     item cannot be told apart from any other there, so it is reported too.
//
// With these rules every change of the failing set shows up as change
// entries, and a failing set that gained a member (a key not in the previous
// failing set) is an alert, whatever the lists look like: the arithmetic does
// not depend on where a list was cut, on whether a subject was escaped or
// redacted for display, or on the totals before and after. The tests check
// this against a model on random sets. A set that only lost members is
// reported, without an alert, like any other fix; for a list too long to
// compare, where the direction is not known, set_changed is an alert. The
// hidden count of a list never produces changes by itself.
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
	// HiddenNew is a number of new failing items that keepwatch cannot name
	// because they are not among the items listed (see Change.HiddenNew).
	HiddenNew Kind = "hidden_new"
	// HiddenGone is the same for items that left the failing set.
	HiddenGone Kind = "hidden_gone"
	// SetChanged says that a list too long to compare item by item changed
	// (see Change.OldTotal).
	SetChanged Kind = "set_changed"
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
	// OldTotal and NewTotal are the item totals of a set_changed.
	OldTotal, NewTotal int
	// HiddenNew is the number of new items of a hidden_new change.
	HiddenNew int
	// HiddenGone is the number of gone items of a hidden_gone change.
	HiddenGone int
	// FromSeverity and ToSeverity are the severities of a severity_change.
	FromSeverity, ToSeverity result.Severity
	// Alert is true for a change worth waking someone for: a check that
	// started failing, started to be in error, or is new and failing; a new
	// failing item (named or counted) or a changed set too long to compare
	// item by item; a higher
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

// side is one run of a check, as the comparison of its items sees it.
type side struct {
	check *state.Check
	// keys is the sorted list of all item keys, nil when the list is too
	// long to be stored (complete is false then).
	keys     []string
	complete bool
	total    int
	// display maps the key of every listed item to the item; excepted holds
	// the keys of the listed items an exception covers. Both are small.
	display  map[string]state.Item
	excepted map[string]bool
}

func sideOf(c *state.Check) side {
	s := side{check: c, total: c.SetTotal(), display: make(map[string]state.Item, len(c.Items)), excepted: map[string]bool{}}
	s.keys, s.complete = c.SetKeys()
	for _, it := range c.Items {
		s.display[it.Key] = it
		if it.Excepted {
			s.excepted[it.Key] = true
		}
	}
	return s
}

// itemChanges compares the items of a check that has the same status, fail
// or warn, in both runs.
func itemChanges(p, c *state.Check) []Change {
	base := Change{CheckID: c.ID, CheckKind: c.Kind, Severity: c.Severity, From: p.Status, To: c.Status}
	alert := alertWorthy(c.Kind, c.Status)
	ps, cs := sideOf(p), sideOf(c)

	var named []Change
	hiddenNew, hiddenGone := 0, 0
	// consider decides what a key's presence in the two lists means. An
	// excepted item is in its list but not in the failing set: an item that
	// becomes excepted has left the failing set, one that stops being
	// excepted is new in it.
	consider := func(key string, inPrev, inCur bool) {
		failPrev := inPrev && !ps.excepted[key]
		failCur := inCur && !cs.excepted[key]
		switch {
		case failCur && !failPrev:
			ch := base
			ch.Kind, ch.Alert = SubjectNew, alert
			if it, ok := cs.display[key]; ok {
				ch.Subject = it.Subject
			} else if it, ok := ps.display[key]; ok {
				ch.Subject = it.Subject
			} else {
				hiddenNew++
				return
			}
			named = append(named, ch)
		case failPrev && !failCur:
			ch := base
			ch.Kind = SubjectGone
			if it, ok := ps.display[key]; ok {
				ch.Subject = it.Subject
			} else if it, ok := cs.display[key]; ok {
				ch.Subject = it.Subject
			} else {
				hiddenGone++
				return
			}
			named = append(named, ch)
		}
	}

	setChanged := false
	switch {
	case ps.complete && cs.complete:
		i, j := 0, 0
		for i < len(ps.keys) || j < len(cs.keys) {
			switch {
			case j == len(cs.keys) || (i < len(ps.keys) && ps.keys[i] < cs.keys[j]):
				consider(ps.keys[i], true, false)
				i++
			case i == len(ps.keys) || cs.keys[j] < ps.keys[i]:
				consider(cs.keys[j], false, true)
				j++
			default:
				consider(ps.keys[i], true, true)
				i++
				j++
			}
		}
	case ps.total == cs.total && p.SetDigest() == c.SetDigest():
		// The same list: only an exception can differ, and the items it
		// covers are listed.
		for _, k := range sortedKeys(ps.display, cs.display) {
			consider(k, true, true)
		}
	default:
		setChanged = true
	}

	sort.SliceStable(named, func(i, j int) bool {
		if named[i].Kind != named[j].Kind {
			return named[i].Kind == SubjectNew
		}
		return named[i].Subject < named[j].Subject
	})
	out := named
	if hiddenNew > 0 {
		ch := base
		ch.Kind, ch.HiddenNew, ch.Alert = HiddenNew, hiddenNew, alert
		out = append(out, ch)
	}
	if hiddenGone > 0 {
		ch := base
		ch.Kind, ch.HiddenGone = HiddenGone, hiddenGone
		out = append(out, ch)
	}
	if setChanged {
		ch := base
		ch.Kind, ch.OldTotal, ch.NewTotal, ch.Alert = SetChanged, ps.total, cs.total, alert
		out = append(out, ch)
	}
	return out
}

// sortedKeys returns the keys of both maps, sorted and without duplicates.
func sortedKeys(a, b map[string]state.Item) []string {
	set := make(map[string]bool, len(a)+len(b))
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
