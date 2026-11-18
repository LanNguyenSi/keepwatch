package watch

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/journal"
)

// KindJournalGap is the audit kind of a gap found between the saved cursor
// and the first line after a restart. The audit package has no constant for
// it; the kind is a plain string there.
const KindJournalGap audit.Kind = "journal_gap"

// streamLoop runs journalctl until the context ends or the loop gives up.
func (d *Daemon) streamLoop(ctx context.Context) error {
	backoff, fails := d.opt.BackoffMin, 0
	for {
		if ctx.Err() != nil {
			return d.failure()
		}
		d.mu.Lock()
		cur := d.cur
		d.delivered = 0
		d.mu.Unlock()
		args, err := journal.Args(cur)
		if err != nil {
			return fmt.Errorf("watch: %w", err)
		}
		d.mu.Lock()
		d.gapFrom = cur
		d.mu.Unlock()
		res, serr := d.deps.Streamer.Stream(ctx, append([]string{d.opt.Program}, args...), execx.StreamOpts{}, d.onLine)
		if f := d.failure(); f != nil {
			return f
		}
		d.mu.Lock()
		err = d.countDropped(res)
		d.mu.Unlock()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(serr, execx.ErrNotAllowed) || errors.Is(serr, execx.ErrNotFound) {
			return fmt.Errorf("%w: %s cannot be started: %v", ErrStreamEnded, d.opt.Program, serr)
		}
		d.mu.Lock()
		reset, progress, err := d.streamEnded(res, serr, cur)
		d.mu.Unlock()
		if err != nil {
			return err
		}
		if reset {
			continue
		}
		if progress || res.Duration >= d.opt.StableAfter {
			backoff, fails = d.opt.BackoffMin, 0
		}
		fails++
		if fails > d.opt.MaxRestarts {
			return fmt.Errorf("%w: %d restarts without progress, last exit %d", ErrStreamEnded, fails-1, res.ExitCode)
		}
		if err := d.opt.Sleep(ctx, backoff); err != nil {
			if ctx.Err() != nil {
				return d.failure()
			}
			return fmt.Errorf("watch: waiting to restart journalctl: %w", err)
		}
		backoff = min(backoff*2, d.opt.BackoffMax)
	}
}

// countDropped audits the over-long lines a stream dropped; it runs for every
// stream end, also the one at shutdown.
func (d *Daemon) countDropped(res execx.StreamResult) error {
	if res.DroppedLines == 0 {
		return nil
	}
	return d.noiseN("line_too_long", res.DroppedLines, audit.JournalLineInvalid, "journal lines over the size limit were dropped")
}

// streamEnded handles the end of one journalctl run: it saves the cursor and
// decides whether journalctl refused the saved cursor as invalid (reset) or
// the run is an ordinary failure to retry.
func (d *Daemon) streamEnded(res execx.StreamResult, serr error, cur string) (reset, progress bool, err error) {
	progress = d.delivered > 0
	if err := d.flushCursor(); err != nil {
		return false, progress, err
	}
	if cur != "" && !progress && cursorRejected(res.Stderr) {
		d.cur, d.saved = "", ""
		if err := d.deps.Cursor.Save(""); err != nil {
			return false, progress, fmt.Errorf("watch: cannot reset the cursor: %w", err)
		}
		return true, progress, d.record(audit.CursorReset, "", "", "journalctl refused the saved cursor as invalid; starting at now")
	}
	why := fmt.Sprintf("exit %d", res.ExitCode)
	if serr != nil {
		why += ", " + d.safe(serr.Error())
	}
	// The stderr is cleaned whole and cut afterwards, so a secret that
	// straddles the cut is redacted before anything is cut off.
	return false, progress, d.noise("stream_restart", audit.InputError,
		fmt.Sprintf("journalctl ended (%s); restarting from the saved cursor. stderr: %s", why, cutBytes(d.safe(string(res.Stderr)), 300)))
}

// cursorRejected reports whether journalctl's stderr says it could not use
// the cursor. journalctl refuses only a malformed cursor, with "Failed to
// seek to cursor: Invalid argument" and exit 1; a cursor whose entry is gone
// is not an error. The check is the word, as no exit code separates this
// failure from others.
func cursorRejected(stderr []byte) bool {
	return strings.Contains(strings.ToLower(string(stderr)), "cursor")
}

// seqFields returns the seqnum id (s=) and the seqnum (i=, hex) of a cursor.
func seqFields(cursor string) (id string, seq uint64, ok bool) {
	for _, f := range strings.Split(cursor, ";") {
		switch {
		case strings.HasPrefix(f, "s="):
			id = f[2:]
		case strings.HasPrefix(f, "i="):
			n, err := strconv.ParseUint(f[2:], 16, 64)
			if err != nil {
				return "", 0, false
			}
			seq, ok = n, true
		}
	}
	return id, seq, ok && id != ""
}

// journalGap compares the saved cursor with the cursor of the first line
// delivered after a restart. Entries written while the daemon was down are
// delivered, and journald numbers the entries of all its files from one
// counter, so the seqnum (i=) of the first line is the saved one plus one.
// The seqnum id (s=) may differ even then: each journal file (the system
// file, each user's file) has its own. So only a seqnum that does not follow
// is reported. The record claims a loss only for the same seqnum id with a
// seqnum further ahead: the entries in between are missing (vacuumed or
// deleted). In every other case it says only what is known, that the seqnum
// does not follow: journald of systemd 249 starts its files with a new
// seqnum id and a seqnum of 1 after it was killed, with no entry lost, and a
// replaced journal looks the same. It returns "" when the seqnum follows or
// a cursor does not parse.
func journalGap(saved, first string) string {
	sid, sseq, ok1 := seqFields(saved)
	fid, fseq, ok2 := seqFields(first)
	switch {
	case !ok1 || !ok2:
		return ""
	case fseq == sseq+1:
		return ""
	case sid == fid && fseq > sseq+1:
		return fmt.Sprintf("%d journal entries between the saved cursor and the first line after the restart are missing", fseq-sseq-1)
	}
	return gapUnknown
}

// gapUnknown is the text of a gap record that cannot say what happened.
const gapUnknown = "the journal's seqnum does not follow the saved cursor; entries may be missing or the journal files were replaced"

// checkGap compares the cursor of the first line of a stream that resumed
// from a saved cursor with that cursor, once per stream. The line may be one
// that cannot be decoded, as long as it names a usable cursor (see badLine).
func (d *Daemon) checkGap(first string) error {
	saved := d.gapFrom
	d.gapFrom = ""
	if saved == "" {
		return nil
	}
	if msg := journalGap(saved, first); msg != "" {
		return d.noise("journal_gap", KindJournalGap, "journal gap: "+msg)
	}
	return nil
}
