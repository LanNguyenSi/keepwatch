package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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
	// TornLines is the number of torn lines the log carries, each of them
	// accounted for by the audit_recovered record that follows it.
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
// A line that is not a record is tolerated only when the very next line is
// an audit_recovered record that names it by offset, length and SHA-256 (the
// torn tail the writer found when it reopened the log). Any other malformed
// line, and a malformed line at the end of the log, is a break.
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
//
// The reader is consumed in lines of at most MaxLineBytes; longer lines are
// counted and hashed without being held in memory.
func Verify(r io.Reader) (Result, error) {
	return walk(r, nil)
}

// tornLine is a malformed line waiting for the record that accounts for it.
type tornLine struct {
	seq    uint64
	line   int
	offset int64
	length int64
	sum    string
	detail string
}

// rawLine is one line as read from the log.
type rawLine struct {
	data       []byte // nil when over
	length     int64  // without the newline
	sum        string // hex SHA-256 of the line, set only when over
	over       bool
	terminated bool
}

// readLine reads the next line. At the end of the input it returns io.EOF
// with an empty rawLine. data is valid until the next call.
func readLine(br *bufio.Reader) (rawLine, error) {
	chunk, err := br.ReadSlice('\n')
	switch {
	case err == nil:
		return rawLine{data: chunk[:len(chunk)-1], length: int64(len(chunk) - 1), terminated: true}, nil
	case errors.Is(err, io.EOF):
		if len(chunk) == 0 {
			return rawLine{}, io.EOF
		}
		return rawLine{data: chunk, length: int64(len(chunk))}, nil
	case errors.Is(err, bufio.ErrBufferFull):
		h := sha256.New()
		l := rawLine{over: true}
		for {
			terminated := err == nil
			if terminated {
				chunk = chunk[:len(chunk)-1]
			}
			h.Write(chunk)
			l.length += int64(len(chunk))
			if terminated || errors.Is(err, io.EOF) {
				l.terminated = terminated
				l.sum = hex.EncodeToString(h.Sum(nil))
				return l, nil
			}
			if !errors.Is(err, bufio.ErrBufferFull) {
				return rawLine{}, err
			}
			chunk, err = br.ReadSlice('\n')
		}
	default:
		return rawLine{}, err
	}
}

// walk is the one reader behind Verify and Show. It calls emit (when not
// nil) for every record after the record has passed all checks.
func walk(r io.Reader, emit func(Record) error) (Result, error) {
	br := bufio.NewReaderSize(r, MaxLineBytes+1)
	res := Result{LastHash: Genesis}
	expect := uint64(1)
	var offset int64
	var pending *tornLine
	lineNo := 0
	for {
		raw, err := readLine(br)
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
			// The earlier malformed line, if any, is the first break.
			if pending != nil {
				return res, pending.breakError()
			}
			if lerr.reason != ReasonMalformed {
				return res, &BreakError{Seq: expect, Line: lineNo, Offset: start, Reason: lerr.reason, Detail: lerr.detail}
			}
			sum := raw.sum
			if !raw.over {
				s := sha256.Sum256(raw.data)
				sum = hex.EncodeToString(s[:])
			}
			pending = &tornLine{seq: expect, line: lineNo, offset: start, length: raw.length, sum: sum, detail: lerr.detail}
			continue
		}

		if pending != nil {
			if rec.Kind != AuditRecovered || rec.Summary != tornSummary(pending.offset, pending.length, pending.sum) {
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

func (p *tornLine) breakError() *BreakError {
	return &BreakError{Seq: p.seq, Line: p.line, Offset: p.offset, Reason: ReasonMalformed,
		Detail: p.detail + " (not followed by a matching audit_recovered record)"}
}
