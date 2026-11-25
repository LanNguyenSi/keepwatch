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
		// The failure is recorded before the lock is released, so the drain at
		// shutdown, which waits for this result under the lock, cannot go on
		// without seeing it.
		if err := d.handleResult(r); err != nil {
			d.fail(err)
		}
		d.mu.Unlock()
	}
}

func (d *Daemon) handleResult(r alert.Result) error {
	fp, id := r.Job.Fingerprint, r.Job.IncidentID
	switch r.Status {
	case alert.Sent:
		d.release(fp)
		delete(d.tries, fp)
		d.noticeSent(fp)
		if err := d.record(audit.NotifySent, id, fp, "notification sent"); err != nil {
			return err
		}
		if id != "" {
			return d.markNotified(id, r.Job.ReopenCount, r.At)
		}
	case alert.Failed:
		d.release(fp)
		st := d.tries[fp]
		st.failures++
		st.notBefore = r.At.Add(d.retryGap(st.failures, r.RetryAfter))
		d.setTry(fp, st)
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
	limit := d.gapLimit()
	g := base
	for i := 1; i < failures && g < limit; i++ {
		g *= 2
	}
	return min(g, limit)
}

// gapLimit is the upper bound of gap: max(PerIncidentInterval, base).
func (d *Daemon) gapLimit() time.Duration {
	return max(d.opt.PerIncidentInterval, max(d.opt.PerIncidentInterval/4, notify.MaxRetryAfter))
}

// retryGap is the wait before the next attempt after a failed send: gap,
// raised to the Retry-After the server asked for (Result.RetryAfter, 0 when
// it asked for nothing usable) but never past gapLimit, so a hostile or
// buggy server cannot silence alerts indefinitely.
func (d *Daemon) retryGap(failures int, retryAfter time.Duration) time.Duration {
	return max(d.gap(failures), min(retryAfter, d.gapLimit()))
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

// attemptsLastMinute is how many incident notifications the worker accepted
// in the last minute. The worker gives the slot of its global limit back when
// a send fails, so its limit does not bound attempts against a notifier that
// keeps failing; this count does. Daemon notices are not counted: they are
// sent again on every pass until one was sent, and would otherwise use up
// the limit of the incidents. Only notifyIncident adds to the list, after it
// dropped the expired entries and found fewer than GlobalPerMinute, so the
// list never holds more than GlobalPerMinute entries.
func (d *Daemon) attemptsLastMinute() int {
	cut := d.now().Add(-time.Minute)
	kept := d.attempts[:0]
	for _, t := range d.attempts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	d.attempts = kept
	return len(kept)
}

// noticeWaiting reports whether a daemon notice waits to be sent. Notices go
// first: while one waits, no incident notification is handed to the worker,
// so incidents cannot take the place in the queue it needs.
func (d *Daemon) noticeWaiting() bool {
	for fp := range d.notices {
		if d.inflight[fp] == 0 {
			return true
		}
	}
	return false
}

func (d *Daemon) markNotified(id string, reopenCount int, at time.Time) error {
	_, err := d.deps.Incidents.MarkNotified(id, reopenCount, at)
	if err == nil || errors.Is(err, incident.ErrUnknownIncident) || errors.Is(err, incident.ErrInvalidSignal) ||
		errors.Is(err, incident.ErrStaleMark) {
		return nil
	}
	return fmt.Errorf("watch: incident store: %w", err)
}

// notifyIncident hands the notification of in to the worker and reports
// whether the worker accepted it. A refused signal (no stored incident) is
// sent under the per-fingerprint limit but never marked. Without a notifier,
// and when a rate limit drops the send, the incident counts as notified: the
// limit already decided there will be no message for it now. While a daemon
// notice waits, nothing is handed on and the incident stays unnotified for
// the housekeeping retry. The job carries the incident's reopen count, so a
// late result marks only the generation it was built for.
func (d *Daemon) notifyIncident(in incident.Incident, refused bool) (bool, error) {
	now := d.now()
	fp := string(in.Fingerprint)
	if d.deps.Worker == nil {
		if refused {
			return false, nil
		}
		return false, d.markNotified(in.ID, in.ReopenCount, now)
	}
	if d.noticeWaiting() {
		return false, nil
	}
	id := in.ID
	if refused {
		id = ""
	}
	reason := alert.DropGlobal
	if d.attemptsLastMinute() < d.opt.GlobalPerMinute {
		st := d.tries[fp]
		st.notBefore = now.Add(d.gap(st.failures))
		d.setTry(fp, st)
		if reason = d.enqueue(alert.Job{IncidentID: id, Fingerprint: fp, ReopenCount: in.ReopenCount, Msg: alert.BuildMessage(in, alreadyClean)}); reason == alert.NotDropped {
			d.attempts = append(d.attempts, now)
		}
	} else if err := d.noise("notify_dropped:"+string(alert.DropGlobal), audit.NotifyDropped, "notification dropped: "+string(alert.DropGlobal)); err != nil {
		return false, err
	}
	switch reason {
	case alert.NotDropped:
		return true, nil
	case alert.DropIncident, alert.DropGlobal:
		if !refused {
			// The limit decided there is no message now: the incident counts as
			// notified and its pacing entry goes.
			delete(d.tries, fp)
			return false, d.markNotified(in.ID, in.ReopenCount, now)
		}
	}
	return false, nil
}

// setTry stores the pacing of fp. At maxTries entries it first drops the
// expired ones that are not in flight, and then the one with the oldest
// notBefore, so the map never grows past the bound.
func (d *Daemon) setTry(fp string, st tryState) {
	if _, ok := d.tries[fp]; !ok && len(d.tries) >= maxTries {
		now := d.now()
		oldest, oldestAt := "", time.Time{}
		for k, t := range d.tries {
			if now.After(t.notBefore) && d.inflight[k] == 0 {
				delete(d.tries, k)
			} else if oldest == "" || t.notBefore.Before(oldestAt) {
				oldest, oldestAt = k, t.notBefore
			}
		}
		if len(d.tries) >= maxTries {
			delete(d.tries, oldest)
		}
	}
	d.tries[fp] = st
}

// notice is the text of a daemon notice that has not been sent yet. It is
// cleaned when it is stored.
type notice struct {
	title, body string
	// again is set when the event happened once more while the notice was in
	// flight: the next send is still due after this one succeeded.
	again bool
}

// noticeSent ends a notice whose send succeeded, unless the event came again
// meanwhile.
func (d *Daemon) noticeSent(fp string) {
	n, ok := d.notices[fp]
	switch {
	case !ok:
	case n.again:
		n.again = false
		d.notices[fp] = n
	default:
		delete(d.notices, fp)
	}
}

// maxNotices bounds the pending daemon notices; their keys are a small fixed
// set (an audit recovery, the fill and the full audit log, a full spool, a
// login baseline reset), so
// the bound is never reached in practice.
const maxNotices = 8

// noticeFingerprint is the fingerprint of the daemon notice of key.
func noticeFingerprint(key string) string {
	return string(event.FingerprintOf("daemon", key))
}

// alertEvent notifies a security-relevant event of the daemon itself (not an
// incident), at high priority. The notice stays pending until it was sent:
// every housekeeping pass sends it again while it is not in flight, so a
// failed send, the global limit and a full queue do not lose it. Only the
// worker's per-incident limit ends it unsent: the same notice went out within
// that interval.
func (d *Daemon) alertEvent(key, title, body string) {
	if d.deps.Worker == nil {
		return
	}
	fp := noticeFingerprint(key)
	if _, ok := d.notices[fp]; !ok && len(d.notices) >= maxNotices {
		return
	}
	n := notice{title: d.safe(title), body: d.safe(body), again: d.inflight[fp] > 0}
	d.notices[fp] = n
	if !n.again {
		d.sendNotice(fp)
	}
}

// sendNotice hands the pending notice of fp to the worker and reports whether
// the worker accepted it.
func (d *Daemon) sendNotice(fp string) bool {
	n := d.notices[fp]
	reason := d.enqueue(alert.Job{Fingerprint: fp, Msg: notify.Message{
		Title: n.title, Body: n.body,
		Priority: notify.PriorityOf(result.High), Tags: []string{"keepwatch", string(result.High)},
	}})
	if reason == alert.DropIncident {
		delete(d.notices, fp)
	}
	return reason == alert.NotDropped
}

// reconcileNotifications sends the daemon notices that are not in flight,
// and then retries the incidents that want a notification and have none
// recorded: a failed or dropped send, a notice that went first, or a crash
// before the enqueue. Incident attempts are paced by gap.
func (d *Daemon) reconcileNotifications() error {
	for fp := range d.notices {
		if d.inflight[fp] == 0 {
			d.sendNotice(fp)
		}
	}
	for _, in := range d.deps.Incidents.List() {
		if in.State == incident.StateOpen && in.Notify && in.NotifiedAt.IsZero() && d.due(string(in.Fingerprint)) {
			if err := d.takeOver(in); err != nil {
				return err
			}
		}
	}
	return nil
}

// takeOver notifies an incident from the housekeeping pass. An incident the
// log does not mention (its record was lost in a crash, a replayed line gave
// no signal, or its record was over the budget) is mentioned with its
// notification, through admit.
func (d *Daemon) takeOver(in incident.Incident) error {
	send := func() (bool, error) { return d.notifyIncident(in, false) }
	if d.logged[in.ID] {
		_, err := send()
		return err
	}
	return d.admit(sigRecord{rule: in.RuleID, kind: audit.IncidentUpdate, in: in,
		summary: fmt.Sprintf("found without a recorded notification: [%s] %s: %s", in.Severity, in.Title, in.Summary)}, send)
}
