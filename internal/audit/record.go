// Package audit defines the audit record.
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
	// AuditRecovered is used after torn-tail recovery of the audit log.
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
