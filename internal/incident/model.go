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
	// ReopenCount is the number of times the incident was reopened.
	ReopenCount int
	NotifiedAt  time.Time
}

// CanTransition reports whether a request action may move an incident from
// one state to another: open to acked, open to closed, acked to closed.
// Staying in a state is not a transition, and a closed incident never moves
// on through this table.
func CanTransition(from, to State) bool {
	switch from {
	case StateOpen:
		return to == StateAcked || to == StateClosed
	case StateAcked:
		return to == StateClosed
	}
	return false
}

// CanReopen reports whether an incident in state from may be reopened. It is
// the store-only reopen edge (closed to open) that request actions never
// reach.
func CanReopen(from State) bool { return from == StateClosed }
