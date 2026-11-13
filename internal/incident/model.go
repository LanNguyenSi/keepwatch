// Package incident defines the incident model.
package incident

import (
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// State is the lifecycle state of an incident.
type State string

const (
	StateOpen   State = "open"
	StateAcked  State = "acked"
	StateClosed State = "closed"
)

// Incident groups the signals of one fingerprint.
//
// Title and Summary hold CLEANED text only: they are produced with
// red.Clean from the raw signal fields before an Incident is built.
type Incident struct {
	ID          string
	Fingerprint event.Fingerprint
	RuleID      string
	Severity    result.Severity
	State       State
	// Title is cleaned text.
	Title string
	// Summary is cleaned text.
	Summary   string
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
	Notify    bool
	// Reopened is true when the incident was closed and came back.
	Reopened   bool
	NotifiedAt time.Time
}

// CanTransition reports whether an incident may move from one state to
// another. Staying in a state is not a transition. A closed incident never
// moves on: a recurrence opens a new incident or reopens by the store's
// own rule, not through this table.
func CanTransition(from, to State) bool {
	switch from {
	case StateOpen:
		return to == StateAcked || to == StateClosed
	case StateAcked:
		return to == StateOpen || to == StateClosed
	}
	return false
}
