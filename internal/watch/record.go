package watch

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
)

// refusal is an audit append that the log refused because of the record
// itself (hostile or oversized input), as opposed to a failing log.
type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

// maxRecordSummary is the longest summary of an ordinary record; it bounds a
// record line (see the audit volume in the package comment).
const maxRecordSummary = 512

// appendRecord writes one audit record. Summary is cut to maxRecordSummary;
// it must already be cleaned. A full log is ErrAuditFull (finish then writes
// the one terminal record into the reserve); a record the log refuses is a
// refusal; any other failure is fatal.
func (d *Daemon) appendRecord(kind audit.Kind, incidentID, fingerprint, summary string) error {
	_, err := d.deps.Audit.Append(audit.Record{
		Time: d.now(), Kind: kind, IncidentID: incidentID, Fingerprint: fingerprint,
		Summary: cutBytes(summary, maxRecordSummary),
	})
	switch {
	case err == nil:
		d.checkFill()
		return nil
	case errors.Is(err, audit.ErrFull):
		return fmt.Errorf("%w: %v", ErrAuditFull, err)
	case errors.Is(err, audit.ErrInvalidRecord), errors.Is(err, audit.ErrSummaryTooLong), errors.Is(err, audit.ErrFieldTooLong):
		return refusal{err}
	}
	return fmt.Errorf("watch: audit write failed: %w", err)
}

// record is appendRecord for a step whose record the log may refuse: a
// refusal is counted and audited as input_error and auditing goes on.
func (d *Daemon) record(kind audit.Kind, incidentID, fingerprint, summary string) error {
	err := d.appendRecord(kind, incidentID, fingerprint, summary)
	var r refusal
	if errors.As(err, &r) {
		return d.noise("audit_refused", audit.InputError, fmt.Sprintf("the audit log refused a %s record as invalid: %s", kind, d.safe(r.Error())))
	}
	return err
}

type noiseState struct {
	start   time.Time
	written int
	extra   int
	kind    audit.Kind
	agg     string
}

// noise writes a repeating kind of record at most once per NoiseInterval:
// the first one of a window at once, the rest as one record with their
// count when the window ends (flushNoise, or the next event of the key after
// the end). key names the kind of event and is always one of a small fixed
// set, never host text.
func (d *Daemon) noise(key string, kind audit.Kind, summary string) error {
	return d.noiseN(key, 1, kind, summary)
}

func (d *Daemon) noiseN(key string, n int, kind audit.Kind, summary string) error {
	st, ok, err := d.take(key, 1, kind, summary)
	if err != nil {
		return err
	}
	if !ok {
		st.extra += n
		return nil
	}
	st.extra += n - 1
	return d.recordNoise(kind, summary)
}

// take returns the current window of key, after writing the count of a
// window that ended, and takes one of its budget records when one is left
// (ok). The window is stored before the caller writes, so a write that
// reports a refusal through the limiter finds it open.
func (d *Daemon) take(key string, budget int, kind audit.Kind, agg string) (st *noiseState, ok bool, err error) {
	now := d.now()
	st = d.noisy[key]
	if st != nil && now.Sub(st.start) >= d.opt.NoiseInterval {
		if err := d.flushOne(key, st); err != nil {
			return nil, false, err
		}
		st = nil
	}
	if st == nil {
		st = &noiseState{start: now, kind: kind, agg: agg}
		d.noisy[key] = st
	}
	if st.written >= budget {
		return st, false, nil
	}
	st.written++
	return st, true, nil
}

// recordNoise writes a noise record; a refusal is dropped (the record is
// ours, and refusing the report of a refusal must not loop).
func (d *Daemon) recordNoise(kind audit.Kind, summary string) error {
	err := d.appendRecord(kind, "", "", summary)
	var r refusal
	if errors.As(err, &r) {
		return nil
	}
	return err
}

func (d *Daemon) flushOne(key string, st *noiseState) error {
	delete(d.noisy, key)
	if st.extra == 0 {
		return nil
	}
	return d.recordNoise(st.kind, fmt.Sprintf("%d more within %s: %s", st.extra, d.opt.NoiseInterval, st.agg))
}

// flushNoise writes the counts of the windows that ended (all of them when
// all is set, at shutdown) and forgets update times that limit nothing.
func (d *Daemon) flushNoise(all bool) error {
	d.pruneUpdated(d.now())
	if n := d.lost.Swap(0); n > 0 {
		if err := d.noiseN("results_lost", int(n), audit.NotifyDropped, "notification results were lost because the result queue was full"); err != nil {
			return err
		}
	}
	now := d.now()
	for key, st := range d.noisy {
		if all || now.Sub(st.start) >= d.opt.NoiseInterval {
			if err := d.flushOne(key, st); err != nil {
				return err
			}
		}
	}
	return nil
}

// finish writes the last audit record and returns what Run returns: the
// first fatal error (after a terminal daemon_error), or nil after daemon_stop.
// stopErr is what flushAtStop and the last flush returned; a failure recorded
// after them (by the result loop while draining) also counts.
func (d *Daemon) finish(stopErr error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ferr := stopErr
	if ferr == nil {
		ferr = d.failure()
	}
	if ferr != nil {
		// The terminal record may use the audit log's reserve, so it can say
		// that the log is full. A log that cannot write at all cannot say it.
		_, _ = d.deps.Audit.Append(audit.Record{Time: d.now(), Kind: audit.DaemonError, Summary: cutBytes("stopped: "+d.safe(ferr.Error()), audit.MaxSummary)})
		return ferr
	}
	return d.appendRecord(audit.DaemonStop, "", "", "daemon stopped on request")
}

// fillNoticeNumerator and fillNoticeDenominator are the share of the audit
// log's size limit (80 %) at which the daemon sends its one fill notice.
const (
	fillNoticeNumerator   = 4
	fillNoticeDenominator = 5
)

// checkFill sends one notice per process when the audit log passes 80 % of its
// size limit, so there is time to move it aside before the daemon stops.
func (d *Daemon) checkFill() {
	if d.fillNoticed {
		return
	}
	size, limit := d.deps.Audit.Size(), d.deps.Audit.MaxSize()
	if size*fillNoticeDenominator < limit*fillNoticeNumerator {
		return
	}
	d.fillNoticed = true
	d.alertEvent("audit_fill", "keepwatch: audit log is 80% full",
		fmt.Sprintf("The audit log holds %d of at most %d bytes. At the limit the watch daemon stops, because it does not run without auditing. Move the log aside as described in the audit documentation before that.", size, limit))
}

// cutBytes cuts s to at most n bytes at a character boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
