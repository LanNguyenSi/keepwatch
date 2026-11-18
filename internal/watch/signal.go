package watch

import (
	"errors"
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
)

func (d *Daemon) now() time.Time { return d.deps.Clock() }

// handleSignal applies one signal to the incident store, audits the outcome
// through admit and hands the notification on.
func (d *Daemon) handleSignal(sig event.Signal) error {
	if now := d.now(); sig.Time.After(now.Add(d.opt.ClockSkew)) {
		if err := d.noise("clock_clamp", audit.InputError,
			fmt.Sprintf("a signal time was more than %s ahead of the daemon clock and was set to the daemon clock", d.opt.ClockSkew)); err != nil {
			return err
		}
		sig.Time = now
	}
	res, err := d.deps.Incidents.Apply(sig, d.display(sig))
	switch {
	case errors.Is(err, incident.ErrFull):
		if err := d.noise("incident_full", audit.InputError, "the incident store is full of more severe incidents; a signal was refused"); err != nil {
			return err
		}
		if res.Incident.Notify && d.due(string(res.Incident.Fingerprint)) {
			inc := res.Incident
			inc.ID = "refused"
			_, err := d.notifyIncident(inc, true)
			return err
		}
		return nil
	case errors.Is(err, incident.ErrInvalidSignal):
		return d.noise("signal_invalid", audit.InputError, "the incident store refused a signal as invalid")
	case err != nil:
		return fmt.Errorf("watch: incident store: %w", err)
	}
	for _, in := range res.AutoClosed {
		if err := d.admit(sigRecord{rule: sig.RuleID, kind: audit.IncidentClose, in: in, summary: "closed automatically after being idle"}, nil); err != nil {
			return err
		}
	}
	for _, ev := range res.Evicted {
		in := incident.Incident{ID: ev.ID, Fingerprint: ev.Fingerprint}
		if err := d.admit(sigRecord{rule: sig.RuleID, kind: audit.IncidentClose, in: in, summary: fmt.Sprintf("evicted to make room, it was %s", ev.State)}, nil); err != nil {
			return err
		}
	}
	kind := audit.IncidentUpdate
	switch res.Outcome {
	case incident.Opened:
		kind = audit.IncidentOpen
	case incident.Reopened:
		kind = audit.IncidentReopen
	}
	in := res.Incident
	var send func() (bool, error)
	if res.Notify || (res.Pending && d.due(string(in.Fingerprint))) {
		send = func() (bool, error) { return d.notifyIncident(in, false) }
	}
	return d.admit(sigRecord{rule: sig.RuleID, kind: kind, in: in, summary: fmt.Sprintf("[%s] %s: %s", in.Severity, in.Title, in.Summary)}, send)
}
