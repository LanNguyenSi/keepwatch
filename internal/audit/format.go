package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"
)

// FileName is the name of the audit log inside the state directory.
const FileName = "audit.jsonl"

// Genesis is the Prev of the first record: 64 ASCII zeros, the width of a
// hex SHA-256.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Limits on what Append accepts. A value over its limit is refused, never
// cut. All lengths count bytes of the string as handed in.
const (
	// MaxSummary is the longest Summary.
	MaxSummary = 2048
	// MaxKind is the longest Kind.
	MaxKind = 64
	// MaxIncidentID is the longest IncidentID.
	MaxIncidentID = 128
	// MaxFingerprint is the longest Fingerprint (a hex SHA-256 is 64).
	MaxFingerprint = 128
	// MaxLineBytes is the longest record line, without its newline. The
	// worst case (every byte of every string escaped to six bytes, plus
	// the fixed parts) stays below it; a test pins that. Verify and Show
	// read a longer line as a malformed one without holding it in memory.
	MaxLineBytes = 16384
	// DefaultMaxSize is the size at which the writer refuses to append:
	// 256 MiB.
	DefaultMaxSize = 256 << 20
)

// timeLayout is the one time format of a record: UTC, nanoseconds always
// printed (nine digits), a literal Z.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

// wire is the decoded form of a line. Field order here is irrelevant; the
// canonical order lives in encodeBody.
type wire struct {
	Seq         uint64 `json:"seq"`
	Time        string `json:"time"`
	Kind        string `json:"kind"`
	IncidentID  string `json:"incident_id"`
	Fingerprint string `json:"fingerprint"`
	Summary     string `json:"summary"`
	Prev        string `json:"prev"`
	Hash        string `json:"hash"`
}

// appendString appends s as a JSON string in the canonical form: the only
// escapes are \" and \\ and \u00xx (lowercase hex) for bytes below 0x20 and
// 0x7f; every other byte, including multi-byte UTF-8, stays as it is. s must
// be valid UTF-8 (Append checks), so the encoding is reversible and
// injective. encoding/json is not used to write: its escaping of <, >, & and
// of invalid UTF-8 is not a stable contract for a hash.
func appendString(dst []byte, s string) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			dst = append(dst, '\\', '"')
		case c == '\\':
			dst = append(dst, '\\', '\\')
		case c < 0x20 || c == 0x7f:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return append(dst, '"')
}

// encodeBody is the canonical bytes of r without its Hash field: a JSON
// object, fixed field order, no spaces, not yet closed. Prev is its last
// field, so the hash covers the link to the previous record.
func encodeBody(r Record) []byte {
	b := make([]byte, 0, 256+len(r.Summary))
	b = append(b, `{"seq":`...)
	b = strconv.AppendUint(b, r.Seq, 10)
	b = append(b, `,"time":`...)
	b = appendString(b, r.Time.UTC().Format(timeLayout))
	b = append(b, `,"kind":`...)
	b = appendString(b, string(r.Kind))
	b = append(b, `,"incident_id":`...)
	b = appendString(b, r.IncidentID)
	b = append(b, `,"fingerprint":`...)
	b = appendString(b, r.Fingerprint)
	b = append(b, `,"summary":`...)
	b = appendString(b, r.Summary)
	b = append(b, `,"prev":`...)
	b = appendString(b, r.Prev)
	return b
}

// hashOf is the hex SHA-256 of the canonical body of r (its Hash field is
// not an input).
func hashOf(r Record) string {
	sum := sha256.Sum256(encodeBody(r))
	return hex.EncodeToString(sum[:])
}

// encodeLine is the canonical line of r without the newline.
func encodeLine(r Record) []byte {
	b := encodeBody(r)
	b = append(b, `,"hash":`...)
	b = appendString(b, r.Hash)
	return append(b, '}')
}

// Reason says why a line or a link of the chain is not accepted.
type Reason string

// The reasons Verify and Show report.
const (
	// ReasonMalformed: the line is not a record in canonical form (not JSON,
	// a field missing or in the wrong place, a non-canonical byte, no
	// trailing newline, longer than MaxLineBytes).
	ReasonMalformed Reason = "malformed line"
	// ReasonHash: the stored hash is not the hash of the record.
	ReasonHash Reason = "hash mismatch"
	// ReasonPrev: Prev is not the hash of the previous record.
	ReasonPrev Reason = "prev mismatch"
	// ReasonSeq: Seq is not the previous Seq plus one (a gap, a repeat or a
	// reorder), or the first record does not have Seq 1.
	ReasonSeq Reason = "seq gap or reorder"
)

// lineError describes why decodeLine refused a line.
type lineError struct {
	reason Reason
	detail string
}

func (e *lineError) Error() string { return string(e.reason) + ": " + e.detail }

func malformed(format string, args ...any) *lineError {
	return &lineError{reason: ReasonMalformed, detail: fmt.Sprintf(format, args...)}
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// decodeLine parses one line (without its newline). It accepts exactly the
// bytes encodeLine would produce for the record it returns: the line is
// decoded, encoded again and compared byte for byte, so every byte of an
// accepted line is significant. A line that is a record but whose Hash is
// not the hash of its content gets ReasonHash; every other refusal is
// ReasonMalformed. The chain (Seq, Prev) is not looked at here.
func decodeLine(line []byte) (Record, *lineError) {
	var w wire
	if err := json.Unmarshal(line, &w); err != nil {
		return Record{}, malformed("%v", err)
	}
	t, err := time.Parse(timeLayout, w.Time)
	if err != nil {
		return Record{}, malformed("time: %v", err)
	}
	if !isHex64(w.Prev) {
		return Record{}, malformed("prev is not 64 lowercase hex digits")
	}
	if !isHex64(w.Hash) {
		return Record{}, malformed("hash is not 64 lowercase hex digits")
	}
	r := Record{
		Seq: w.Seq, Time: t, Kind: Kind(w.Kind), IncidentID: w.IncidentID,
		Fingerprint: w.Fingerprint, Summary: w.Summary, Prev: w.Prev, Hash: w.Hash,
	}
	if got := encodeLine(r); string(got) != string(line) {
		return Record{}, malformed("not in canonical form")
	}
	if hashOf(r) != r.Hash {
		return Record{}, &lineError{reason: ReasonHash, detail: "stored hash is not the hash of the record"}
	}
	return r, nil
}

// Errors returned by Append and Open.
var (
	// ErrInvalidRecord is returned for a record that cannot be stored: an
	// empty Kind, a zero Time or a year outside 1..9999, a string that is
	// not valid UTF-8.
	ErrInvalidRecord = errors.New("invalid audit record")
	// ErrSummaryTooLong is returned for a Summary over MaxSummary bytes. It
	// is never cut; the caller shortens it.
	ErrSummaryTooLong = errors.New("audit summary too long")
	// ErrFieldTooLong is returned for a Kind, IncidentID or Fingerprint over
	// its limit.
	ErrFieldTooLong = errors.New("audit field too long")
)

// validate checks the fields the caller supplies.
func validate(r Record) error {
	if len(r.Summary) > MaxSummary {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrSummaryTooLong, len(r.Summary), MaxSummary)
	}
	for _, f := range []struct {
		name  string
		value string
		max   int
	}{
		{"kind", string(r.Kind), MaxKind},
		{"incident id", r.IncidentID, MaxIncidentID},
		{"fingerprint", r.Fingerprint, MaxFingerprint},
	} {
		if len(f.value) > f.max {
			return fmt.Errorf("%w: %s is %d bytes, limit %d", ErrFieldTooLong, f.name, len(f.value), f.max)
		}
	}
	if r.Kind == "" {
		return fmt.Errorf("%w: empty kind", ErrInvalidRecord)
	}
	if r.Time.IsZero() {
		return fmt.Errorf("%w: zero time", ErrInvalidRecord)
	}
	if y := r.Time.UTC().Year(); y < 1 || y > 9999 {
		return fmt.Errorf("%w: year %d outside 1..9999", ErrInvalidRecord, y)
	}
	for _, s := range []string{string(r.Kind), r.IncidentID, r.Fingerprint, r.Summary} {
		if !utf8.ValidString(s) {
			return fmt.Errorf("%w: a string is not valid UTF-8", ErrInvalidRecord)
		}
	}
	return nil
}

// tornSummary is the Summary of the record that follows a torn line: where
// the line starts, how long it is (without a newline) and the SHA-256 of its
// bytes, so Verify can tell this line from any other garbage.
func tornSummary(offset, length int64, sum string) string {
	return fmt.Sprintf("torn tail: offset=%d length=%d sha256=%s", offset, length, sum)
}

// completedSummary is the Summary of the record noting that the last record,
// found without its newline, was whole and was completed.
func completedSummary(offset int64, seq uint64) string {
	return fmt.Sprintf("unterminated last record completed: offset=%d seq=%d", offset, seq)
}
