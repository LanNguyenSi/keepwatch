package watch

import (
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
)

// sigRecord is an audit record about an incident: what a signal did to the
// store (open, update, reopen, the closes and evictions it caused), an idle
// close, and the housekeeping takeover of an incident the log does not
// mention. Whoever can make the host log lines can cause these at will, so
// they all go through admit.
type sigRecord struct {
	// rule is the budget key: the rule of the signal (or of the incident)
	// the record is about. Rules are a small fixed set.
	rule    string
	kind    audit.Kind
	in      incident.Incident
	summary string
}

// admit is the one way a sigRecord reaches the audit log. Per rule and
// NoiseInterval at most AuditBudget records are written, and at most one
// incident_update per incident; the rest of a rule's window is counted into
// one record when the window ends. send, when not nil, hands the incident's
// notification on and reports whether the worker accepted it: a record that
// is over the budget is still written when its notification was accepted,
// so no notification goes out for an incident the log does not mention.
// Those records are bounded by the daemon's notification limit
// (GlobalPerMinute), not by the budget.
func (d *Daemon) admit(r sigRecord, send func() (bool, error)) error {
	ok, err := d.allow(r)
	if err != nil {
		return err
	}
	if ok {
		if err := d.writeSig(r); err != nil {
			return err
		}
	}
	accepted := false
	if send != nil {
		if accepted, err = send(); err != nil {
			return err
		}
	}
	switch {
	case ok:
		return nil
	case accepted:
		return d.writeSig(r)
	}
	d.noisy[budgetKey(r.rule)].extra++
	return nil
}

func budgetKey(rule string) string { return "rule:" + rule }

// allow decides whether r fits: an incident_update of an incident that had
// one in the last NoiseInterval does not, otherwise the rule's budget
// decides. Either way the rule's window exists afterwards, so a record that
// does not fit is counted there.
func (d *Daemon) allow(r sigRecord) (bool, error) {
	key := budgetKey(r.rule)
	if last, ok := d.updated[r.in.ID]; ok && r.kind == audit.IncidentUpdate && d.now().Sub(last) < d.opt.NoiseInterval {
		_, _, err := d.take(key, 0, audit.IncidentUpdate, d.aggText(r.rule))
		return false, err
	}
	_, ok, err := d.take(key, d.opt.AuditBudget, audit.IncidentUpdate, d.aggText(r.rule))
	return ok, err
}

// aggText is the text of a rule's count record. A rule id is not host text:
// it comes from the rules, and the store keeps the one of the signal.
func (d *Daemon) aggText(rule string) string {
	return fmt.Sprintf("incident records of rule %s (opens, updates, reopens, closes) were counted, not written one by one", rule)
}

// writeSig writes r and remembers what the takeover and the update limit
// need: that the log mentions the incident, and when its last update was.
func (d *Daemon) writeSig(r sigRecord) error {
	if err := d.record(r.kind, r.in.ID, string(r.in.Fingerprint), r.summary); err != nil {
		return err
	}
	switch r.kind {
	case audit.IncidentUpdate:
		d.updated[r.in.ID] = d.now()
		d.markLogged(r.in.ID)
	case audit.IncidentOpen, audit.IncidentReopen:
		d.markLogged(r.in.ID)
	}
	return nil
}

// pruneUpdated forgets the update times that no longer limit anything.
func (d *Daemon) pruneUpdated(now time.Time) {
	for id, at := range d.updated {
		if now.Sub(at) >= d.opt.NoiseInterval {
			delete(d.updated, id)
		}
	}
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
