package watch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/requests"
)

// RequestOps are the operations on the request spool the housekeeping pass
// uses; StateRequests binds them to a state directory, tests replace them.
type RequestOps struct {
	Pending   func() (requests.Batch, error)
	Remove    func(name string) error
	SweepTemp func(olderThan time.Duration) (int, error)
}

// StateRequests returns the operations on the spool below stateDir.
func StateRequests(stateDir string) *RequestOps {
	return &RequestOps{
		Pending:   func() (requests.Batch, error) { return requests.Pending(stateDir) },
		Remove:    func(name string) error { return requests.Remove(stateDir, name) },
		SweepTemp: func(older time.Duration) (int, error) { return requests.SweepTemp(stateDir, older) },
	}
}

func (d *Daemon) housekeepLoop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	tick := d.opt.HousekeepingTick
	if tick == nil {
		t := time.NewTicker(d.opt.HousekeepingInterval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-tick:
			if !ok {
				// A closed tick source ends the housekeeping, instead of a
				// pass after every receive from the closed channel.
				return
			}
			d.mu.Lock()
			err := d.housekeep()
			d.mu.Unlock()
			if err != nil {
				d.fail(err)
				return
			}
		}
	}
}

// housekeep is the periodic pass: save the cursor, write the counts of ended
// noise windows, close idle incidents, look after the request spool and
// retry notifications.
func (d *Daemon) housekeep() error {
	if err := d.flushCursor(); err != nil {
		return err
	}
	if err := d.flushNoise(false); err != nil {
		return err
	}
	closed, err := d.deps.Incidents.Sweep(d.now())
	switch {
	case errors.Is(err, incident.ErrInvalidSignal):
	case err != nil:
		return fmt.Errorf("watch: incident store: %w", err)
	}
	for _, in := range closed {
		if err := d.admit(sigRecord{rule: in.RuleID, kind: audit.IncidentClose, in: in, summary: "closed automatically after being idle"}, nil); err != nil {
			return err
		}
	}
	// Requests go before the notification retry, so an ack or close of this
	// pass stops a retry that would be due in it.
	if err := d.requestsPass(); err != nil {
		return err
	}
	return d.reconcileNotifications()
}

// requestsPass handles what is wrong in the spool: a rejected entry is
// audited once per name and removed (a name that is still listed on the next
// pass, because Remove failed, is not audited again; a name that has left the
// listing is forgotten); a directory with more entries than one
// listing examines is audited and notified once per episode; stale temporary
// files are swept now and then. Accepted requests are applied, audited and
// removed (applyRequests).
func (d *Daemon) requestsPass() error {
	ops := d.deps.Requests
	if ops == nil {
		return nil
	}
	b, err := ops.Pending()
	if err != nil {
		return d.noise("requests_pending", audit.InputError, "cannot list the request spool: "+d.safe(err.Error()))
	}
	seen := map[string]bool{}
	if err := d.applyRequests(b.Items, seen); err != nil {
		return err
	}
	for _, it := range append(append([]requests.Item(nil), b.Items...), b.Stray...) {
		if it.Accepted() {
			continue
		}
		seen[it.Name] = true
		if !d.rejAudited[it.Name] {
			d.rejAudited[it.Name] = true
			if err := d.record(audit.RequestRejected, "", "", fmt.Sprintf("request %s rejected (%s): %s", d.safe(it.Name), it.Rejection.Reason, d.safe(it.Rejection.Detail))); err != nil {
				return err
			}
		}
		// A failed Remove is tried again on the next pass, without a new record.
		_ = ops.Remove(it.Name)
	}
	for name := range d.rejAudited {
		if !seen[name] {
			delete(d.rejAudited, name)
		}
	}
	switch {
	case b.Overfull && !d.overfull:
		d.overfull = true
		msg := fmt.Sprintf("the request spool holds more than %d entries; the rest is not looked at until it is cleared", requests.MaxExamined)
		if err := d.record(audit.RequestRejected, "", "", msg); err != nil {
			return err
		}
		d.alertEvent("requests_overfull", "keepwatch: request spool is full", msg)
	case !b.Overfull:
		d.overfull = false
	}
	if now := d.now(); now.Sub(d.lastTempSweep) >= d.opt.TempSweepInterval {
		d.lastTempSweep = now
		if _, err := ops.SweepTemp(d.opt.TempAge); err != nil {
			return d.noise("requests_sweep", audit.InputError, "cannot sweep stale request files: "+d.safe(err.Error()))
		}
	}
	return nil
}
