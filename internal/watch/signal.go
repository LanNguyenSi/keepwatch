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
// and hands the notification on.
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
			return d.notifyIncident(inc, true)
		}
		return nil
	case errors.Is(err, incident.ErrInvalidSignal):
		return d.noise("signal_invalid", audit.InputError, "the incident store refused a signal as invalid")
	case err != nil:
		return fmt.Errorf("watch: incident store: %w", err)
	}
	for _, in := range res.AutoClosed {
		if err := d.record(audit.IncidentClose, in.ID, string(in.Fingerprint), "closed automatically after being idle"); err != nil {
			return err
		}
	}
	for _, ev := range res.Evicted {
		if err := d.recordLimited("incident_evicted", audit.IncidentClose, ev.ID, string(ev.Fingerprint),
			fmt.Sprintf("evicted to make room, it was %s", ev.State), "incidents were evicted to make room, not audited one by one"); err != nil {
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
	text := fmt.Sprintf("[%s] %s: %s", in.Severity, in.Title, in.Summary)
	if kind == audit.IncidentOpen {
		err = d.recordLimited("incident_open", kind, in.ID, string(in.Fingerprint), text, "incidents were opened for new fingerprints, not audited one by one")
	} else {
		err = d.record(kind, in.ID, string(in.Fingerprint), text)
	}
	if err != nil {
		return err
	}
	d.markLogged(in.ID)
	if res.Notify || (res.Pending && d.due(string(in.Fingerprint))) {
		return d.notifyIncident(in, false)
	}
	return nil
}

// markLogged remembers that the audit log mentions the incident, so the
// housekeeping retry does not have to say so (see reconcileNotifications).
func (d *Daemon) markLogged(id string) {
	if len(d.logged) >= maxLogged {
		clear(d.logged)
	}
	d.logged[id] = true
}

// maxLogged bounds the set of logged incident ids; at the bound the set starts
// over, which costs at most one extra record per incident.
const maxLogged = 4096
