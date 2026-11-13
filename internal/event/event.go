// Package event defines the data that flows from the journal and posture
// readers through the rules to the incident store.
//
// Every string field in this package is RAW: it comes from a log line or a
// host probe and may carry secrets, control bytes or attacker-chosen text.
// A raw string must not be shown, logged, stored or sent without passing
// through red.Clean (internal/redact) first. Fingerprints are the one
// exception: they are derived from raw values on purpose, so that cleaning
// can never merge or split incidents.
//
// Trust: journald sets some fields itself (names starting with an
// underscore) and takes others from the sender, which any local user can
// forge. Rules must base trust decisions only on journald-set fields, and
// among those only UID, SystemdUnit, PID (as PID 1) and Transport carry
// identity: Comm is set by journald but its value is the name the process
// chose for itself. An absent UID is -1, never 0, so a missing field can
// never read as root.
//
// Posture-sourced Subject and Summary are stored display text; the daemon
// cleans them again before they are shown or stored.
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

// Event is one normalised entry. All string fields are RAW. Each field is
// marked either "set by journald (trusted)" or "set by the sender (untrusted,
// forgeable by any local user)", following systemd.journal-fields(7).
type Event struct {
	// Kind is set by keepwatch: which reader produced the event.
	Kind Kind
	// Cursor is the journal cursor of the entry. Set by journald (trusted).
	Cursor string
	// Time is the journal timestamp. Set by journald (trusted).
	Time time.Time
	// UID is the user id of the logging process (_UID). Set by journald
	// (trusted). Absent is -1.
	UID int
	// SystemdUnit is the unit the logging process runs in
	// (_SYSTEMD_UNIT). Set by journald (trusted). Empty when absent.
	SystemdUnit string
	// Unit is the UNIT field a sender names, for example systemd on behalf
	// of a unit. Set by the sender (untrusted, forgeable by any local
	// user). Never base a trust decision on it.
	Unit string
	// Identifier is SYSLOG_IDENTIFIER. Set by the sender (untrusted,
	// forgeable by any local user).
	Identifier string
	// PID is _PID. Set by journald (trusted). Absent is 0.
	PID int
	// Priority is PRIORITY, 0 (emerg) to 7 (debug). Set by the sender
	// (untrusted, forgeable by any local user). Absent is -1.
	Priority int
	// Transport is _TRANSPORT, for example "kernel". Set by journald
	// (trusted).
	Transport string
	// Message is MESSAGE. Set by the sender (untrusted, forgeable by any
	// local user). With Transport kernel it comes from the kernel ring
	// buffer, which only root can write to.
	Message string
	// Comm is _COMM, the command name of the logging process. Set by
	// journald from the name the process chose for itself (prctl, or the
	// name of a copied binary), so never base a trust decision on it. It
	// is not the OOM victim: a rule parses the victim name from Message.
	Comm string
	// UnitResult is the systemd UNIT_RESULT field, for example
	// "exit-code" or "oom-kill". Set by the sender (untrusted, forgeable
	// by any local user).
	UnitResult string
	// ExitCode is EXIT_CODE. Set by the sender (untrusted, forgeable by
	// any local user).
	ExitCode string
	// ExitStatus is EXIT_STATUS. Set by the sender (untrusted, forgeable
	// by any local user).
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
