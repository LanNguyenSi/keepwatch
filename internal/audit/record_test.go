package audit

import "testing"

func TestKindStrings(t *testing.T) {
	want := map[Kind]string{
		DaemonStart: "daemon_start", DaemonStop: "daemon_stop",
		IncidentOpen: "incident_open", IncidentUpdate: "incident_update",
		IncidentReopen: "incident_reopen", IncidentAck: "incident_ack",
		IncidentClose: "incident_close", NotifySent: "notify_sent",
		NotifyFailed: "notify_failed", NotifyDropped: "notify_dropped",
		RequestRejected: "request_rejected", CursorReset: "cursor_reset",
		PostureSeen: "posture_seen", JournalLineInvalid: "journal_line_invalid",
		AuditRecovered: "audit_recovered", InputError: "input_error",
		DaemonError: "daemon_error",
	}
	if len(want) != 17 {
		t.Fatalf("got %d kinds", len(want))
	}
	for k, s := range want {
		if string(k) != s {
			t.Errorf("kind %q, want %q", k, s)
		}
	}
}
