package watch

import (
	"errors"
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
)

// refusal is an audit append that the log refused because of the record
// itself (hostile or oversized input), as opposed to a failing log.
type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

// appendRecord writes one audit record. Summary is cut to the audit limit;
// it must already be cleaned. A full log is ErrAuditFull (finish then writes
// the one terminal record into the reserve); a record the log refuses is a
// refusal; any other failure is fatal.
func (d *Daemon) appendRecord(kind audit.Kind, incidentID, fingerprint, summary string) error {
	_, err := d.deps.Audit.Append(audit.Record{
		Time: d.now(), Kind: kind, IncidentID: incidentID, Fingerprint: fingerprint,
		Summary: cutBytes(summary, audit.MaxSummary),
	})
	switch {
	case err == nil:
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
	extra   int
	kind    audit.Kind
	summary string
}

// noise writes a repeating kind of record at most once per NoiseInterval:
// the first one of a window at once, the rest as one record with their
// count when the window ends (flushNoise). key names the kind of event and
// is always one of a small fixed set, never host text.
func (d *Daemon) noise(key string, kind audit.Kind, summary string) error {
	return d.noiseN(key, 1, kind, summary)
}

func (d *Daemon) noiseN(key string, n int, kind audit.Kind, summary string) error {
	now := d.now()
	if st := d.noisy[key]; st != nil {
		if now.Sub(st.start) < d.opt.NoiseInterval {
			st.extra += n
			return nil
		}
		if err := d.flushOne(key, st); err != nil {
			return err
		}
	}
	d.noisy[key] = &noiseState{start: now, kind: kind, summary: summary, extra: n - 1}
	return d.recordNoise(kind, summary)
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
	return d.recordNoise(st.kind, fmt.Sprintf("%d more within %s: %s", st.extra, d.opt.NoiseInterval, st.summary))
}

// flushNoise writes the counts of the windows that ended (all of them when
// all is set, at shutdown).
func (d *Daemon) flushNoise(all bool) error {
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
func (d *Daemon) finish(loopErr error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	ferr := d.failure()
	if ferr == nil {
		ferr = loopErr
	}
	cerr := d.flushCursor()
	if ferr == nil && cerr != nil {
		ferr = cerr
	}
	if ferr == nil {
		ferr = d.flushNoise(true)
	}
	if ferr != nil {
		// The terminal record may use the audit log's reserve, so it can say
		// that the log is full. A log that cannot write at all cannot say it.
		_, _ = d.deps.Audit.Append(audit.Record{Time: d.now(), Kind: audit.DaemonError, Summary: cutBytes("stopped: "+d.safe(ferr.Error()), audit.MaxSummary)})
		return ferr
	}
	return d.appendRecord(audit.DaemonStop, "", "", "daemon stopped on request")
}
