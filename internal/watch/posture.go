package watch

import (
	"slices"
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
// a signal (the min argument of posture.New): alert-worthy changes of any
// severity, as check --notify alerts on them.
const PostureMinSeverity = result.Info

// postureQueueMax bounds the posture signals waiting for a later pass: as
// many as the incident store can hold.
const postureQueueMax = incident.MaxIncidents

// posturePerPass is how many posture signals one housekeeping pass handles:
// the rule's budget shared by the passes of one NoiseInterval
// (AuditBudget*HousekeepingInterval/NoiseInterval, 5 at the defaults), at
// least 1 and at most AuditBudget, so a backlog of signals that each write
// one record is written, not counted.
func (d *Daemon) posturePerPass() int {
	n := int(int64(d.opt.AuditBudget) * int64(d.opt.HousekeepingInterval) / int64(d.opt.NoiseInterval))
	return min(max(n, 1), max(d.opt.AuditBudget, 1))
}

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
	// The most severe signals of a poll go first, so a cut drops the least
	// severe ones.
	sigs = slices.Clone(sigs)
	slices.SortStableFunc(sigs, func(a, b event.Signal) int {
		return slices.Index(result.Severities, b.Severity) - slices.Index(result.Severities, a.Severity)
	})
	room := postureQueueMax - len(d.postureQueue)
	if over := len(sigs) - room; over > 0 {
		sigs = sigs[:room]
		if err := d.noiseN("posture_overflow", over, audit.InputError, "a posture signal was dropped because the posture queue was full"); err != nil {
			return err
		}
	}
	d.postureQueue = append(d.postureQueue, sigs...)
	n := min(d.posturePerPass(), len(d.postureQueue))
	batch := d.postureQueue[:n]
	d.postureQueue = append([]event.Signal(nil), d.postureQueue[n:]...)
	owner := map[event.Fingerprint]string{}
	for _, in := range d.deps.Incidents.List() {
		owner[in.Fingerprint] = in.RuleID
	}
	for _, sig := range batch {
		// The daemon does not rely on the source for the rule id and
		// Notify, and refuses a fingerprint that belongs to an incident of
		// another rule, whose Notify it would otherwise inherit.
		if rule, ok := owner[sig.Fingerprint]; ok && rule != posture.RuleID {
			if err := d.noise("signal_invalid", audit.InputError, "a posture signal named an incident of another rule and was refused"); err != nil {
				return err
			}
			continue
		}
		sig.RuleID, sig.Notify = posture.RuleID, false
		if err := d.handleSignal(sig); err != nil {
			return err
		}
	}
	return nil
}

// countQueuedAtStop counts the posture signals still queued when the daemon
// stops through the noise path; the queue lives in memory and is not
// drained.
func (d *Daemon) countQueuedAtStop() error {
	n := len(d.postureQueue)
	if n == 0 {
		return nil
	}
	d.postureQueue = nil
	if err := d.noiseN("posture_overflow", n, audit.InputError, "a posture signal was still queued when the daemon stopped and was not handled"); err != nil {
		return err
	}
	return d.flushNoise(true)
}
