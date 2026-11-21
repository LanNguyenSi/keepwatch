package watch

import (
	"errors"
	"fmt"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/journal"
)

// safe is the only call of Deps.Clean in the package: every string that
// started as host text goes through it once before it is stored, audited or
// sent. A test pins that there is exactly one call site.
func (d *Daemon) safe(raw string) string { return d.deps.Clean(raw) }

// display builds the stored text of a signal: the incident title (rule and
// subject) and summary. Subject and Summary are raw; this is where they are
// cleaned.
func (d *Daemon) display(sig event.Signal) incident.Display {
	return incident.Display{
		Title:   d.safe(sig.RuleID + ": " + sig.Subject),
		Summary: d.safe(sig.Summary),
	}
}

// onLine is the stream callback: one journal line, handled completely
// before the next one is read.
func (d *Daemon) onLine(line []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.delivered++
	if err := d.handleLine(line); err != nil {
		d.fail(err)
		return err
	}
	return nil
}

func (d *Daemon) handleLine(line []byte) error {
	ev, err := journal.Decode(line)
	if err != nil {
		var le *journal.LineError
		cursor := ""
		if errors.As(err, &le) && validCursor(le.Cursor) {
			cursor = le.Cursor
		}
		return d.badLine(err, cursor)
	}
	// A cursor the store would refuse must not reach the save: the line is a
	// bad line and the cursor stays where it is.
	if !validCursor(ev.Cursor) {
		return d.badLine(errors.New("the line has a cursor the daemon cannot save"), "")
	}
	if err := d.checkGap(ev.Cursor); err != nil {
		return err
	}
	if ev.Time.IsZero() {
		return d.badLine(errors.New("the line has no __REALTIME_TIMESTAMP"), ev.Cursor)
	}
	// Every event goes to the rules, in journal order, unfiltered: the OOM
	// rule needs the kernel lines in between to end a group kill episode.
	sigs := d.deps.Engine.Evaluate(ev, ev.Time)
	for _, sig := range sigs {
		if err := d.handleSignal(sig); err != nil {
			return err
		}
	}
	if err := d.saveBaseline(sigs); err != nil {
		return err
	}
	return d.handled(ev.Cursor, len(sigs) > 0)
}

// badLine audits a line that cannot be used (rate limited) and moves the
// cursor past it when it named one. A bad line with a usable cursor is as
// good a first line for the gap check as any other: without the check here,
// the line after it would be compared and one entry reported missing.
func (d *Daemon) badLine(err error, cursor string) error {
	if cursor != "" {
		if err := d.checkGap(cursor); err != nil {
			return err
		}
	} else {
		// The check stays pending for the next line, which can no longer
		// count what is missing (see checkGap).
		d.gapSkipped = true
	}
	if err := d.noise("journal_line_invalid", audit.JournalLineInvalid, "journal line skipped: "+d.safe(err.Error())); err != nil {
		return err
	}
	return d.handled(cursor, false)
}

// handled records that a line is done and saves the cursor when due. A line
// that produced a signal saves at once.
func (d *Daemon) handled(cursor string, force bool) error {
	if cursor == "" {
		return nil
	}
	d.cur = cursor
	if cursor == d.saved {
		return nil
	}
	if force || d.opt.CursorInterval < 0 || d.now().Sub(d.lastSave) >= d.opt.CursorInterval {
		return d.flushCursor()
	}
	return nil
}

// flushCursor saves the cursor of the last handled line when it is not on
// disk yet.
func (d *Daemon) flushCursor() error {
	if d.cur == d.saved {
		return nil
	}
	if err := d.deps.Cursor.Save(d.cur); err != nil {
		return fmt.Errorf("watch: cannot save the cursor: %w", err)
	}
	d.saved, d.lastSave = d.cur, d.now()
	return nil
}
