package audit

import "testing"

func TestKindValuesUnique(t *testing.T) {
	kinds := []Kind{DaemonStart, DaemonStop, IncidentOpen, IncidentUpdate, IncidentReopen,
		IncidentAck, IncidentClose, NotifySent, NotifyFailed, NotifyDropped,
		RequestRejected, CursorReset, PostureSeen}
	if len(kinds) != 13 {
		t.Fatalf("got %d kinds", len(kinds))
	}
	seen := map[Kind]bool{}
	for _, k := range kinds {
		if k == "" || seen[k] {
			t.Errorf("empty or duplicate kind %q", k)
		}
		seen[k] = true
	}
}
