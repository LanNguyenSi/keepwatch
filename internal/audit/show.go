package audit

import (
	"io"
	"time"
)

// Filter selects records for Show. All set fields must match; the zero
// Filter matches every record.
type Filter struct {
	// Kinds, when not empty, keeps records of one of these kinds.
	Kinds []Kind
	// IncidentID, when not empty, keeps records of that incident.
	IncidentID string
	// Since keeps records at or after this time, Until records before it. A
	// zero value leaves that side open.
	Since time.Time
	Until time.Time
}

// Match reports whether r passes the filter.
func (f Filter) Match(r Record) bool {
	if len(f.Kinds) > 0 {
		found := false
		for _, k := range f.Kinds {
			if r.Kind == k {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.IncidentID != "" && r.IncidentID != f.IncidentID {
		return false
	}
	if !f.Since.IsZero() && r.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !r.Time.Before(f.Until) {
		return false
	}
	return true
}

// Show streams the records of the log that pass the filter to fn, in log
// order, one at a time. It checks the chain on the way exactly as Verify
// does and hands fn only records that passed, so what it shows is
// consistent from the first record up to that point. At the first break it
// stops and returns the *BreakError (records before the break have been
// delivered); an error from fn stops it and is returned as it is. The
// limits of Verify apply: Show does not notice a log that was cut off at the
// end.
func Show(r io.Reader, f Filter, fn func(Record) error) error {
	_, err := walk(r, func(rec Record) error {
		if !f.Match(rec) {
			return nil
		}
		return fn(rec)
	})
	return err
}
