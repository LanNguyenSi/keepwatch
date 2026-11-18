package watch

import (
	"errors"
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// maxTries bounds the retry bookkeeping; expired entries go first.
const maxTries = 4096

// tryState is the pacing of notification attempts of one fingerprint.
type tryState struct {
	failures  int
	notBefore time.Time
}

// alreadyClean formats the incident's own fields, which were cleaned when
// the incident was built; nothing is transformed a second time.
func alreadyClean(s string) string { return s }

// onResult is the worker's OnResult. It may run on the worker's goroutine or
// on the caller of Enqueue (which holds d.mu), so it only queues the result.
func (d *Daemon) onResult(r alert.Result) {
	d.resMu.RLock()
	defer d.resMu.RUnlock()
	if !d.resClosed {
		select {
		case d.results <- r:
			return
		default:
		}
	}
	d.lost.Add(1)
}

func (d *Daemon) closeResults() {
	d.resMu.Lock()
	d.resClosed = true
	close(d.results)
	d.resMu.Unlock()
}

// resultLoop audits every outcome of the worker until the queue is closed.
func (d *Daemon) resultLoop(done chan<- struct{}) {
	defer close(done)
	for r := range d.results {
		d.mu.Lock()
		err := d.handleResult(r)
		d.mu.Unlock()
		if err != nil {
			d.fail(err)
		}
	}
}

func (d *Daemon) handleResult(r alert.Result) error {
	fp, id := r.Job.Fingerprint, r.Job.IncidentID
	switch r.Status {
	case alert.Sent:
		d.release(fp)
		delete(d.tries, fp)
		if err := d.record(audit.NotifySent, id, fp, "notification sent"); err != nil {
			return err
		}
		if id != "" {
			return d.markNotified(id, r.At)
		}
	case alert.Failed:
		d.release(fp)
		st := d.tries[fp]
		st.failures++
		st.notBefore = r.At.Add(d.gap(st.failures))
		d.tries[fp] = st
		return d.record(audit.NotifyFailed, id, fp, fmt.Sprintf("notification failed (%s): %s", r.Class, d.safe(r.Detail)))
	case alert.Dropped:
		if r.Reason == alert.DropShutdown {
			d.release(fp)
		}
		return d.noise("notify_dropped:"+string(r.Reason), audit.NotifyDropped, "notification dropped: "+string(r.Reason))
	}
	return nil
}

// release gives back an in-flight job of fp.
func (d *Daemon) release(fp string) {
	if d.inflight[fp] > 0 {
		d.inflight[fp]--
		d.inflightTotal--
		if d.inflight[fp] == 0 {
			delete(d.inflight, fp)
		}
	}
}

// gap is the least wait before the next attempt after the given number of
// failures: max(PerIncidentInterval/4, the longest Retry-After the ntfy
// client waits for), doubled per failure, up to PerIncidentInterval.
func (d *Daemon) gap(failures int) time.Duration {
	base := max(d.opt.PerIncidentInterval/4, notify.MaxRetryAfter)
	limit := max(d.opt.PerIncidentInterval, base)
	g := base
	for i := 1; i < failures && g < limit; i++ {
		g *= 2
	}
	return min(g, limit)
}

// due reports whether another attempt for fp is allowed now.
func (d *Daemon) due(fp string) bool {
	st, ok := d.tries[fp]
	return d.inflight[fp] == 0 && (!ok || !d.now().Before(st.notBefore))
}

func (d *Daemon) enqueue(j alert.Job) alert.DropReason {
	reason := d.deps.Worker.Enqueue(j)
	if reason == alert.NotDropped {
		d.inflight[j.Fingerprint]++
		d.inflightTotal++
	}
	return reason
}

func (d *Daemon) markNotified(id string, at time.Time) error {
	_, err := d.deps.Incidents.MarkNotified(id, at)
	if err == nil || errors.Is(err, incident.ErrUnknownIncident) || errors.Is(err, incident.ErrInvalidSignal) {
		return nil
	}
	return fmt.Errorf("watch: incident store: %w", err)
}

// notifyIncident hands the notification of in to the worker. A refused
// signal (no stored incident) is sent under the per-fingerprint limit but
// never marked. Without a notifier, and when a rate limit drops the send, the
// incident counts as notified: the limit already decided there will be no
// message for it now.
func (d *Daemon) notifyIncident(in incident.Incident, refused bool) error {
	now := d.now()
	fp := string(in.Fingerprint)
	if d.deps.Worker == nil {
		if refused {
			return nil
		}
		return d.markNotified(in.ID, now)
	}
	id := in.ID
	if refused {
		id = ""
	}
	if len(d.tries) >= maxTries {
		for k, st := range d.tries {
			if now.After(st.notBefore) && d.inflight[k] == 0 {
				delete(d.tries, k)
			}
		}
	}
	st := d.tries[fp]
	st.notBefore = now.Add(d.gap(st.failures))
	d.tries[fp] = st
	switch d.enqueue(alert.Job{IncidentID: id, Fingerprint: fp, Msg: alert.BuildMessage(in, alreadyClean)}) {
	case alert.DropIncident, alert.DropGlobal:
		if !refused {
			return d.markNotified(in.ID, now)
		}
	}
	return nil
}

// alertEvent notifies a security-relevant event of the daemon itself (not an
// incident) with the worker's limits; the text is cleaned like any other.
func (d *Daemon) alertEvent(key, title, body string) {
	if d.deps.Worker == nil {
		return
	}
	d.enqueue(alert.Job{
		Fingerprint: string(event.FingerprintOf("daemon", key)),
		Msg: notify.Message{
			Title: d.safe(title), Body: d.safe(body),
			Priority: notify.PriorityOf(result.High), Tags: []string{"keepwatch", string(result.High)},
		},
	})
}

// reconcileNotifications retries the incidents that want a notification and
// have none recorded: a failed or dropped send, or a crash before the
// enqueue. Attempts are paced by gap.
func (d *Daemon) reconcileNotifications() error {
	for _, in := range d.deps.Incidents.List() {
		if in.State == incident.StateOpen && in.Notify && in.NotifiedAt.IsZero() && d.due(string(in.Fingerprint)) {
			if err := d.notifyIncident(in, false); err != nil {
				return err
			}
		}
	}
	return nil
}
