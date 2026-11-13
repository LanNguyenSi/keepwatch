// Package event defines the data that flows from the journal and posture
// readers through the rules to the incident store.
//
// Every string field in this package is RAW: it comes from a log line or a
// host probe and may carry secrets, control bytes or attacker-chosen text.
// A raw string must not be shown, logged, stored or sent without passing
// through red.Clean (internal/redact) first. Fingerprints are the one
// exception: they are derived from raw values on purpose, so that cleaning
// can never merge or split incidents.
package event

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Kind tells which reader produced an Event.
type Kind string

const (
	// KindJournal is a normalised journal entry.
	KindJournal Kind = "journal"
	// KindPosture is a posture deviation found by a probe. It travels the
	// same path as a journal entry.
	KindPosture Kind = "posture"
)

// Event is one normalised entry. All string fields are RAW.
type Event struct {
	Kind Kind
	// Cursor is the journal cursor of the entry (raw, opaque).
	Cursor string
	Time   time.Time
	// Unit is the systemd unit (raw).
	Unit string
	// Identifier is the syslog identifier (raw).
	Identifier string
	PID        int
	// Priority is the syslog priority, 0 (emerg) to 7 (debug).
	Priority int
	// Transport is the journal transport (raw), for example "kernel".
	Transport string
	// Message is the log message (raw).
	Message string
	// Comm is the command name of the process involved (raw), used for
	// OOM kills.
	Comm string
	// UnitResult is the result of a unit stop (raw), for example
	// "exit-code" or "oom-kill".
	UnitResult string
	// ExitCode and ExitStatus are the unit's exit fields (raw).
	ExitCode   string
	ExitStatus string
}

// Signal is the output of a rule. Subject and Summary are RAW.
type Signal struct {
	RuleID      string
	Fingerprint Fingerprint
	Severity    result.Severity
	Time        time.Time
	// Notify tells whether the rule wants a notification.
	Notify bool
	// Subject is what the signal is about (raw).
	Subject string
	// Summary is a one-line description (raw).
	Summary string
	// Key holds the raw values the fingerprint was built from.
	Key map[string]string
}

// Fingerprint identifies a recurring problem: lowercase hex SHA-256.
type Fingerprint string

// FingerprintOf returns the fingerprint of ruleID and parts. The inputs are
// RAW values: it is never derived from cleaned text, so redaction changes
// cannot alter it. Each input is encoded with an 8-byte big-endian length
// prefix, so no two different splits of the same bytes collide.
func FingerprintOf(ruleID string, parts ...string) Fingerprint {
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write(ruleID)
	for _, p := range parts {
		write(p)
	}
	return Fingerprint(hex.EncodeToString(h.Sum(nil)))
}
