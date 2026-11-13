// Package audit defines the audit record and the audit log: an append-only
// JSON Lines file in which every record carries the SHA-256 of its own
// canonical bytes and the hash of the record before it.
//
// File format. One record per line, UTF-8, each line ended by a single "\n".
// A line is the canonical JSON object of a Record with the fields seq, time,
// kind, incident_id, fingerprint, summary, prev, hash in this order, no
// spaces, time in UTC with nine fractional digits and a literal Z, and
// strings escaped only as \" \\ and \u00xx (lowercase) for the bytes below
// 0x20 and 0x7f. The encoder is written by hand because the hash needs a form
// that no library version may change. Seq counts from 1. Prev of the first
// record is Genesis. Hash is the lowercase hex SHA-256 over the bytes of the
// line from its first byte up to and including the prev field (everything but
// the hash field), so the hash covers the link to the previous record.
//
// Writer appends and Open finds the end of an existing log; Verify and Show
// read it. What the chain proves and what it does not (a cut-off end, an
// attacker who rewrites everything) is on Verify. Rotation does not exist:
// at the size limit the writer refuses with ErrFull.
//
// A full log. Ordinary records are refused at MaxSize minus ReserveBytes; the
// reserve keeps room for one terminal record (DaemonError or DaemonStop) and
// for the record Open appends after a torn tail, so the daemon can still say
// that it stopped because the log is full. Nothing in keepwatch shrinks,
// rotates or deletes the file. An operator who finds the daemon stopped for
// this reason stops it (if it is running), runs Verify over the log and keeps
// the result (Count and LastHash) with the file, moves the file out of the
// state directory (never truncates it in place), and starts the daemon: it
// begins a new log at Seq 1 from Genesis. The two files are separate chains
// and are verified separately; nothing links the new one to the old one.
package audit

import "time"

// Kind names an auditable step.
type Kind string

const (
	DaemonStart    Kind = "daemon_start"
	DaemonStop     Kind = "daemon_stop"
	IncidentOpen   Kind = "incident_open"
	IncidentUpdate Kind = "incident_update"
	IncidentReopen Kind = "incident_reopen"
	IncidentAck    Kind = "incident_ack"
	IncidentClose  Kind = "incident_close"
	NotifySent     Kind = "notify_sent"
	NotifyFailed   Kind = "notify_failed"
	NotifyDropped  Kind = "notify_dropped"
	// RequestRejected is used when a request file is refused, including an
	// invalid state transition it asks for.
	RequestRejected Kind = "request_rejected"
	CursorReset     Kind = "cursor_reset"
	PostureSeen     Kind = "posture_seen"
	// JournalLineInvalid is used when a journal line cannot be parsed.
	JournalLineInvalid Kind = "journal_line_invalid"
	// AuditRecovered is used after torn-tail recovery of the audit log. Only
	// the writer's Open appends it; Append refuses it from callers.
	AuditRecovered Kind = "audit_recovered"
	// InputError is used when the posture or baseline input fails to load.
	InputError Kind = "input_error"
	// DaemonError is used on a fatal internal stop.
	DaemonError Kind = "daemon_error"
)

// Record is one entry of the hash-chained audit log. Summary is CLEANED
// text only; no raw journal or probe text may be stored here. Prev is the
// Hash of the previous record.
type Record struct {
	Seq         uint64
	Time        time.Time
	Kind        Kind
	IncidentID  string
	Fingerprint string
	Summary     string
	Prev        string
	Hash        string
}
