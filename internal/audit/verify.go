package audit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// Result is what Verify returns for a log whose chain is intact.
type Result struct {
	// Count is the number of records, which is also the Seq of the last one.
	Count uint64
	// LastHash is the Hash of the last record, Genesis for an empty log. It
	// is the value to keep elsewhere if the end of the log is to be
	// protected (see Verify).
	LastHash string
	// TornLines is the number of torn regions the log carries, each of them
	// accounted for by the audit_recovered record that follows it. A region
	// is all the bytes between two records that are not records, however
	// many lines they make.
	TornLines int
}

// BreakError says where the chain first breaks. It is the error Verify and
// Show return for a log that is not intact; any other error is a failure of
// the reader.
type BreakError struct {
	// Seq is the Seq the chain expected at the broken place: one more than
	// the last good record (1 at the start). It is the Seq of the first
	// record that cannot be trusted. A record with a different Seq than the
	// expected one is named in Detail.
	Seq uint64
	// Line is the 1-based line number, Offset the byte offset of its start.
	Line   int
	Offset int64
	Reason Reason
	Detail string
}

func (e *BreakError) Error() string {
	return fmt.Sprintf("audit log broken at seq %d (line %d, offset %d): %s: %s", e.Seq, e.Line, e.Offset, e.Reason, e.Detail)
}

// Verify reads a log from its first byte and checks every line: it must be a
// record in canonical form with a correct hash, Seq must count 1, 2, 3 and
// so on, and each Prev must be the Hash of the record before (Genesis for
// the first). It returns the first break as a *BreakError, or the count and
// the last hash.
//
// Bytes that are not records are tolerated only as one torn region: every
// consecutive line that is not a record, taken together with their
// newlines, must be followed by an audit_recovered record that names the
// region by offset, length, whether it ended with a newline, and SHA-256
// (the torn tail the writer found when it reopened the log; see Open). A
// region longer than MaxTornBytes, a recovery record that names it wrongly,
// any other record after it and a region at the end of the log are breaks.
// A line that looks like a record but has a wrong hash is a break, never
// part of a region.
//
// What Verify proves: the file is a consistent chain from its first record,
// in order, and no byte was changed, inserted, removed or reordered inside
// it without the hashes being recomputed. What it does not prove, on purpose
// and as a documented limit:
//
//   - Truncation at the end. The log without its last records is again a
//     valid chain, so cutting the tail at a record boundary passes. The
//     protection against that is a copy of Result.LastHash and Count kept
//     off the host, which is not part of this code.
//   - Authenticity. The hashes are unkeyed. Whoever can write the file can
//     rewrite all of it with a consistent chain; Verify cannot tell.
//   - What a torn region was. It is named and hashed, not judged: a crash
//     artefact and bytes that someone put there look alike, and the record
//     that was in the region (if any) is gone from the chain.
//
// The reader is consumed in lines; a line over MaxLineBytes is not a record
// whatever the buffer of the reader, and Verify holds at most MaxTornBytes+1
// bytes of any line.
func Verify(r io.Reader) (Result, error) {
	return walk(r, nil)
}

// region is a run of lines that are not records, waiting for the record that
// accounts for it.
type region struct {
	seq    uint64
	line   int
	offset int64
	detail string
	// buf holds the bytes of the region, each line with its newline, up to
	// MaxTornBytes+1 bytes; n counts all of them.
	buf []byte
	n   int64
}

// add appends one line to the region.
func (g *region) add(l rawLine) {
	g.n += l.length
	if l.terminated {
		g.n++
	}
	if room := MaxTornBytes + 1 - len(g.buf); room > 0 {
		g.buf = append(g.buf, l.data[:min(room, len(l.data))]...)
		if l.terminated && len(g.buf) < MaxTornBytes+1 {
			g.buf = append(g.buf, '\n')
		}
	}
}

// tooLong: the region cannot be what Open accounts for.
func (g *region) tooLong() bool { return g.n > MaxTornBytes+1 }

// accounts reports whether rec is the record that Open writes for exactly
// this region. A region Open found without a final newline is followed by a
// newline Open added, which is not part of what the record names.
func (g *region) accounts(rec Record) bool {
	if rec.Kind != AuditRecovered || g.tooLong() {
		return false
	}
	// Not too long: buf holds every byte of the region.
	n := len(g.buf)
	if n <= MaxTornBytes && rec.Summary == tornSummary(g.offset, int64(n), true, sumHex(g.buf)) {
		return true
	}
	if n >= 2 && n-1 <= MaxTornBytes && g.buf[n-1] == '\n' {
		return rec.Summary == tornSummary(g.offset, int64(n-1), false, sumHex(g.buf[:n-1]))
	}
	return false
}

func (g *region) breakError() *BreakError {
	detail := g.detail + " (not followed by a matching audit_recovered record)"
	if g.tooLong() {
		detail = fmt.Sprintf("%s (the lines that are not records add up to more than %d bytes)", g.detail, MaxTornBytes)
	}
	return &BreakError{Seq: g.seq, Line: g.line, Offset: g.offset, Reason: ReasonMalformed, Detail: detail}
}

// rawLine is one line as read from the log.
type rawLine struct {
	// data is the line without its newline, cut at MaxTornBytes+1 bytes; it
	// is valid until the next call of lineReader.next.
	data       []byte
	length     int64 // all bytes of the line, without the newline
	over       bool  // length > MaxLineBytes: not a record
	terminated bool
}

// lineReader splits a reader into lines. The cap on a line is applied to
// the bytes read, not to the size of the buffer, so it does not depend on
// the reader it is given (bufio.NewReaderSize returns a *bufio.Reader it is
// handed when that one is large enough).
type lineReader struct {
	br  *bufio.Reader
	buf []byte
}

// next reads the next line. At the end of the input it returns io.EOF.
func (lr *lineReader) next() (rawLine, error) {
	lr.buf = lr.buf[:0]
	var l rawLine
	for {
		chunk, err := lr.br.ReadSlice('\n')
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) && !errors.Is(err, io.EOF) {
			return rawLine{}, err
		}
		terminated := err == nil
		if terminated {
			chunk = chunk[:len(chunk)-1]
		}
		l.length += int64(len(chunk))
		if room := MaxTornBytes + 1 - len(lr.buf); room > 0 {
			lr.buf = append(lr.buf, chunk[:min(room, len(chunk))]...)
		}
		if terminated || errors.Is(err, io.EOF) {
			l.terminated = terminated
			break
		}
	}
	if l.length == 0 && !l.terminated {
		return rawLine{}, io.EOF
	}
	l.data = lr.buf
	l.over = l.length > MaxLineBytes
	return l, nil
}

// walk is the one reader behind Verify and Show. It calls emit (when not
// nil) for every record after the record has passed all checks.
func walk(r io.Reader, emit func(Record) error) (Result, error) {
	lr := &lineReader{br: bufio.NewReaderSize(r, MaxLineBytes+1)}
	res := Result{LastHash: Genesis}
	expect := uint64(1)
	var offset int64
	var pending *region
	lineNo := 0
	for {
		raw, err := lr.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, err
		}
		lineNo++
		start := offset
		offset += raw.length
		if raw.terminated {
			offset++
		}

		var rec Record
		var lerr *lineError
		switch {
		case raw.over:
			lerr = malformed("longer than %d bytes", MaxLineBytes)
		case !raw.terminated:
			lerr = malformed("no trailing newline")
		default:
			rec, lerr = decodeLine(raw.data)
		}

		if lerr != nil {
			if lerr.reason != ReasonMalformed {
				// A record with a wrong hash is never part of a torn
				// region; an earlier region is the first break.
				if pending != nil {
					return res, pending.breakError()
				}
				return res, &BreakError{Seq: expect, Line: lineNo, Offset: start, Reason: lerr.reason, Detail: lerr.detail}
			}
			if pending == nil {
				pending = &region{seq: expect, line: lineNo, offset: start, detail: lerr.detail}
			}
			pending.add(raw)
			if pending.tooLong() {
				return res, pending.breakError()
			}
			continue
		}

		if pending != nil {
			if !pending.accounts(rec) {
				return res, pending.breakError()
			}
			pending = nil
			res.TornLines++
		}
		if rec.Seq != expect {
			return res, &BreakError{Seq: expect, Line: lineNo, Offset: start, Reason: ReasonSeq,
				Detail: fmt.Sprintf("record has seq %d", rec.Seq)}
		}
		if rec.Prev != res.LastHash {
			return res, &BreakError{Seq: expect, Line: lineNo, Offset: start, Reason: ReasonPrev,
				Detail: "prev is not the hash of the previous record"}
		}
		res.Count = rec.Seq
		res.LastHash = rec.Hash
		expect++
		if emit != nil {
			if err := emit(rec); err != nil {
				return res, err
			}
		}
	}
	if pending != nil {
		return res, pending.breakError()
	}
	return res, nil
}
