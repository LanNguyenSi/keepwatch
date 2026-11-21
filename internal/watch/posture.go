package watch

import (
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/posture"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// PostureSource is what the housekeeping pass polls for posture signals;
// posture.Source implements it. A nil Deps.Posture switches posture off; the
// wiring passes a nil interface, not a nil *posture.Source.
type PostureSource interface {
	Poll(now time.Time) ([]event.Signal, error)
}

// PostureMinSeverity is the least severity of a posture change that becomes
// a signal (the min argument of posture.New). It is the one `check --notify`
// alerts at, so every change that notification can name is also recorded as
// an incident by the daemon.
const PostureMinSeverity = result.Info

const (
	// posturePerPass is how many posture signals one housekeeping pass
	// handles: the per-rule budget at its default, so the records of one
	// pass fit the rule's budget of an interval.
	posturePerPass = DefaultAuditBudget
	// postureQueueMax bounds the posture signals waiting for a later pass:
	// as many as the incident store can hold.
	postureQueueMax = incident.MaxIncidents
)

// posturePass polls the posture source and handles at most posturePerPass
// queued signals (see Posture in the package comment). A poll error is
// audited through the noise path and the queue is still worked on.
func (d *Daemon) posturePass() error {
	src := d.deps.Posture
	if src == nil {
		return nil
	}
	sigs, err := src.Poll(d.now())
	if err != nil {
		if err := d.noise("posture_poll", audit.InputError, "cannot read the posture state: "+d.safe(err.Error())); err != nil {
			return err
		}
	}
	room := postureQueueMax - len(d.postureQueue)
	if over := len(sigs) - room; over > 0 {
		sigs = sigs[:room]
		if err := d.noiseN("posture_overflow", over, audit.InputError, "a posture signal was dropped because the posture queue was full"); err != nil {
			return err
		}
	}
	d.postureQueue = append(d.postureQueue, sigs...)
	n := min(posturePerPass, len(d.postureQueue))
	batch := d.postureQueue[:n]
	d.postureQueue = append([]event.Signal(nil), d.postureQueue[n:]...)
	for _, sig := range batch {
		// The daemon does not rely on the source: whatever it returns is
		// budgeted as the posture rule and never notifies.
		sig.RuleID, sig.Notify = posture.RuleID, false
		if err := d.handleSignal(sig); err != nil {
			return err
		}
	}
	return nil
}
