// Package posture turns the state file of the timer runs into Signals.
//
// The daemon polls the state file. The first usable state it sees is the
// baseline and says nothing. A later state with another RunAt is compared with
// the one before it, and every alert-worthy change becomes one Signal. The
// Signals are flagged Notify=false: `check --notify` is the one path that
// notifies about posture, the daemon only records the deviation as an incident.
//
// The baseline lives in memory. A change made while the daemon is down is not
// seen by it (the first poll after the start is a new baseline);
// `check --notify` still reports it.
package posture

import (
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// RuleID is the rule id of every posture Signal.
const RuleID = "posture"

// Source polls a state file for new runs. It is not safe for concurrent use.
type Source struct {
	load func() (state.LoadResult, error)
	min  result.Severity
	prev *state.State
}

// New returns a Source that reads the state through store, read-only. Only
// changes whose severity is at least min become Signals; an empty min lets
// every alert through.
func New(store *state.Store, min result.Severity) *Source {
	return &Source{load: store.Load, min: min}
}

// Poll loads the state and returns the Signals of the changes since the last
// run it saw. A missing state file is not an error and yields nothing. A state
// directory that cannot be trusted, or a file that cannot be used (unreadable,
// foreign schema version), is returned as an error; the baseline is kept, so
// the next good load is compared with it.
func (s *Source) Poll(now time.Time) ([]event.Signal, error) {
	lr, err := s.load()
	if err != nil {
		return nil, fmt.Errorf("posture: %w", err)
	}
	if lr.Missing {
		return nil, nil
	}
	if lr.Problem != "" || lr.State == nil {
		return nil, fmt.Errorf("posture: state not usable: %s", lr.Problem)
	}
	cur := lr.State
	prev := s.prev
	if prev != nil && prev.RunAt.Equal(cur.RunAt) {
		return nil, nil
	}
	s.prev = cur
	if prev == nil {
		return nil, nil
	}
	var out []event.Signal
	for _, ch := range diff.Compute(prev, cur).Alerts(s.min) {
		out = append(out, signalOf(ch, prev, cur, now))
	}
	return out, nil
}

func signalOf(ch diff.Change, prev, cur *state.State, now time.Time) event.Signal {
	subject := ch.CheckID
	summary := fmt.Sprintf("%s: %s", ch.CheckID, ch.Kind)
	if ch.Subject != "" {
		subject = ch.CheckID + " " + ch.Subject
		summary += " " + ch.Subject
	}
	return event.Signal{
		RuleID:      RuleID,
		Fingerprint: event.FingerprintOf(RuleID, ch.CheckID, string(ch.Kind), rawKey(ch, prev, cur)),
		Severity:    ch.Severity,
		Time:        now,
		Notify:      false,
		Subject:     subject,
		Summary:     summary,
	}
}

// rawKey returns the raw subject key of an item change, read from the state
// item the display subject belongs to. diff.Change carries only the display
// subject, which is cleaned and may be the same text for two items. When the
// key is not reachable (a change of a whole check, or a display subject that
// is not unique in its check) the display subject stands in for it, so items
// that look alike share one fingerprint rather than none.
func rawKey(ch diff.Change, prev, cur *state.State) string {
	if ch.Subject == "" {
		return ""
	}
	var found string
	n := 0
	for _, st := range []*state.State{cur, prev} {
		c := st.Find(ch.CheckID)
		if c == nil {
			continue
		}
		for _, it := range c.Items {
			if it.Subject == ch.Subject && (n == 0 || it.Key != found) {
				found = it.Key
				n++
			}
		}
		if n > 0 {
			break
		}
	}
	if n == 1 {
		return "key:" + found
	}
	return "subject:" + ch.Subject
}
