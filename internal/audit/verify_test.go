package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// sample returns n records for a log, with a mix of kinds, incidents and
// strings that need escaping.
func sample(n int) []Record {
	kinds := []Kind{DaemonStart, IncidentOpen, NotifySent, IncidentAck, IncidentClose, PostureSeen}
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{
			Time:        t0.Add(time.Duration(i) * time.Minute),
			Kind:        kinds[i%len(kinds)],
			IncidentID:  fmt.Sprintf("inc-%d", i%3),
			Fingerprint: strings.Repeat(fmt.Sprintf("%x", i%16), 64),
			Summary:     fmt.Sprintf("step %d \"quoted\" \\ é <&>", i),
		}
	}
	return recs
}

// chainLines links recs into canonical lines (without newlines), starting
// from Genesis and Seq 1, ignoring any Seq/Prev/Hash they carry.
func chainLines(recs []Record) ([]Record, [][]byte) {
	out := make([]Record, len(recs))
	lines := make([][]byte, len(recs))
	prev := Genesis
	for i, r := range recs {
		r.Seq = uint64(i + 1)
		r.Prev = prev
		r.Hash = hashOf(r)
		prev = r.Hash
		out[i] = r
		lines[i] = encodeLine(r)
	}
	return out, lines
}

func join(lines [][]byte) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// rechain rebuilds lines for recs in the given order with Prev and Hash
// recomputed but Seq left as it is, which is what an attacker without a
// consistency check on Seq would produce.
func rechainKeepSeq(recs []Record) [][]byte {
	lines := make([][]byte, len(recs))
	prev := Genesis
	for i, r := range recs {
		r.Prev = prev
		r.Hash = hashOf(r)
		prev = r.Hash
		lines[i] = encodeLine(r)
	}
	return lines
}

func mustBreak(t *testing.T, name string, log []byte) *BreakError {
	t.Helper()
	_, err := Verify(bytes.NewReader(log))
	var be *BreakError
	if !errors.As(err, &be) {
		t.Fatalf("%s: Verify = %v, want a *BreakError", name, err)
	}
	return be
}

func mustVerify(t *testing.T, name string, log []byte) Result {
	t.Helper()
	res, err := Verify(bytes.NewReader(log))
	if err != nil {
		t.Fatalf("%s: Verify = %v", name, err)
	}
	return res
}

func TestVerifyEmptyLog(t *testing.T) {
	res := mustVerify(t, "empty", nil)
	if res.Count != 0 || res.LastHash != Genesis || res.TornLines != 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestVerifyIntactChain(t *testing.T) {
	recs, lines := chainLines(sample(10))
	res := mustVerify(t, "intact", join(lines))
	if res.Count != 10 || res.LastHash != recs[9].Hash || res.TornLines != 0 {
		t.Fatalf("got %+v, last hash %s", res, recs[9].Hash)
	}
	one := mustVerify(t, "one", join(lines[:1]))
	if one.Count != 1 || one.LastHash != recs[0].Hash {
		t.Fatalf("got %+v", one)
	}
}

func TestVerifyBreakReasons(t *testing.T) {
	recs, lines := chainLines(sample(6))
	cases := []struct {
		name   string
		log    []byte
		reason Reason
		seq    uint64 // expected Seq of the break
		line   int
	}{
		{"garbage line", join([][]byte{lines[0], lines[1], []byte("garbage"), lines[2]}), ReasonMalformed, 3, 3},
		{"empty line", join([][]byte{lines[0], {}, lines[1]}), ReasonMalformed, 2, 2},
		{"no trailing newline", bytes.TrimSuffix(join(lines[:3]), []byte("\n")), ReasonMalformed, 3, 3},
		{"stored hash changed", func() []byte {
			ls := append([][]byte(nil), lines...)
			ls[2] = bytes.Replace(ls[2], []byte(recs[2].Hash), []byte(strings.Repeat("a", 64)), 1)
			return join(ls)
		}(), ReasonHash, 3, 3},
		{"content changed, hash kept", func() []byte {
			ls := append([][]byte(nil), lines...)
			ls[3] = bytes.Replace(ls[3], []byte("step 3"), []byte("step 9"), 1)
			return join(ls)
		}(), ReasonHash, 4, 4},
		{"wrong prev, hash recomputed", func() []byte {
			r := recs[2]
			r.Prev = recs[0].Hash
			r.Hash = hashOf(r)
			ls := append([][]byte(nil), lines...)
			ls[2] = encodeLine(r)
			return join(ls[:3])
		}(), ReasonPrev, 3, 3},
		{"first prev is not genesis", func() []byte {
			r := recs[0]
			r.Prev = strings.Repeat("1", 64)
			r.Hash = hashOf(r)
			return join([][]byte{encodeLine(r)})
		}(), ReasonPrev, 1, 1},
		{"first record is not seq 1", func() []byte {
			r := recs[0]
			r.Seq = 2
			r.Hash = hashOf(r)
			return join([][]byte{encodeLine(r)})
		}(), ReasonSeq, 1, 1},
		{"first record seq 0", func() []byte {
			r := recs[0]
			r.Seq = 0
			r.Hash = hashOf(r)
			return join([][]byte{encodeLine(r)})
		}(), ReasonSeq, 1, 1},
		{"gap with valid links", func() []byte {
			sr := append([]Record(nil), recs[:4]...)
			sr[3].Seq = 5
			return join(rechainKeepSeq(sr))
		}(), ReasonSeq, 4, 4},
		{"repeated seq with valid links", func() []byte {
			sr := append([]Record(nil), recs[:4]...)
			sr[3].Seq = 3
			return join(rechainKeepSeq(sr))
		}(), ReasonSeq, 4, 4},
		{"deleted middle record, relinked", func() []byte {
			sr := append(append([]Record(nil), recs[:2]...), recs[3:]...)
			return join(rechainKeepSeq(sr))
		}(), ReasonSeq, 3, 3},
		{"swapped records, relinked", func() []byte {
			sr := append([]Record(nil), recs...)
			sr[2], sr[3] = sr[3], sr[2]
			return join(rechainKeepSeq(sr))
		}(), ReasonSeq, 3, 3},
		{"deleted first record, relinked", join(rechainKeepSeq(recs[1:])), ReasonSeq, 1, 1},
	}
	for _, c := range cases {
		be := mustBreak(t, c.name, c.log)
		if be.Reason != c.reason || be.Seq != c.seq || be.Line != c.line {
			t.Errorf("%s: got %+v, want reason %q seq %d line %d", c.name, be, c.reason, c.seq, c.line)
		}
	}
}

func TestBreakErrorText(t *testing.T) {
	be := &BreakError{Seq: 5, Line: 6, Offset: 700, Reason: ReasonPrev, Detail: "d"}
	if got := be.Error(); got != "audit log broken at seq 5 (line 6, offset 700): prev mismatch: d" {
		t.Fatalf("got %q", got)
	}
}

func TestBreakOffsetCountsBytes(t *testing.T) {
	_, lines := chainLines(sample(3))
	log := join([][]byte{lines[0], lines[1], []byte("junk")})
	be := mustBreak(t, "junk", log)
	if want := int64(len(lines[0]) + 1 + len(lines[1]) + 1); be.Offset != want {
		t.Fatalf("offset %d, want %d", be.Offset, want)
	}
}

// First broken Seq: a later break is not reported when an earlier one exists.
func TestVerifyReportsTheFirstBreak(t *testing.T) {
	recs, lines := chainLines(sample(6))
	ls := append([][]byte(nil), lines...)
	ls[1] = bytes.Replace(ls[1], []byte(recs[1].Hash), []byte(strings.Repeat("b", 64)), 1)
	ls[4] = []byte("junk")
	be := mustBreak(t, "two breaks", join(ls))
	if be.Seq != 2 || be.Reason != ReasonHash {
		t.Fatalf("got %+v", be)
	}
}

func TestVerifyTruncatedTail(t *testing.T) {
	recs, lines := chainLines(sample(8))
	full := join(lines)
	// Documented limit: cutting the log at a record boundary leaves a valid
	// chain. Verify cannot see that records are missing.
	boundary := 0
	for k := 0; k <= len(lines); k++ {
		res := mustVerify(t, fmt.Sprintf("cut after %d records", k), full[:boundary])
		wantHash := Genesis
		if k > 0 {
			wantHash = recs[k-1].Hash
		}
		if res.Count != uint64(k) || res.LastHash != wantHash {
			t.Errorf("cut after %d: %+v", k, res)
		}
		if k < len(lines) {
			boundary += len(lines[k]) + 1
		}
	}
	// Cutting inside a record is not at a boundary and breaks.
	boundary = 0
	for k := range lines {
		for cut := boundary + 1; cut < boundary+len(lines[k])+1; cut++ {
			be := mustBreak(t, fmt.Sprintf("cut at %d", cut), full[:cut])
			if be.Reason != ReasonMalformed || be.Seq != uint64(k+1) {
				t.Errorf("cut at %d: %+v", cut, be)
			}
		}
		boundary += len(lines[k]) + 1
	}
}

// Every single byte of the log is significant: replacing any one byte by
// another value breaks the chain.
func TestPropertyAnySingleByteChangeIsDetected(t *testing.T) {
	_, lines := chainLines(sample(6))
	full := join(lines)
	// A log that went through a torn tail recovery is covered as well.
	torn := join(lines[:4])
	torn = append(torn, []byte(`{"seq":5,"tim`)...)
	sum := sha256.Sum256([]byte(`{"seq":5,"tim`))
	tr := Record{Seq: 5, Time: t0, Kind: AuditRecovered,
		Summary: tornSummary(int64(len(join(lines[:4]))), 13, hex.EncodeToString(sum[:])),
		Prev:    func() string { r, _ := decodeLine(lines[3]); return r.Hash }()}
	tr.Hash = hashOf(tr)
	torn = append(torn, '\n')
	torn = append(torn, encodeLine(tr)...)
	torn = append(torn, '\n')
	mustVerify(t, "recovered log", torn)

	for name, log := range map[string][]byte{"plain": full, "recovered": torn} {
		n := 0
		for i := range log {
			orig := log[i]
			for _, v := range []byte{orig ^ 0x01, orig ^ 0x20, orig ^ 0x80, '\n', 0, 'x'} {
				if v == orig {
					continue
				}
				mut := append([]byte(nil), log...)
				mut[i] = v
				n++
				if _, err := Verify(bytes.NewReader(mut)); err == nil {
					t.Fatalf("%s: byte %d changed from %q to %q and Verify passed", name, i, orig, v)
				}
			}
		}
		if n < 5*len(log)/2 {
			t.Fatalf("%s: only %d mutations over %d bytes", name, n, len(log))
		}
	}
}

func TestPropertyInsertedByteIsDetected(t *testing.T) {
	_, lines := chainLines(sample(6))
	full := join(lines)
	for i := 0; i <= len(full); i++ {
		for _, v := range []byte{' ', 'x', '\n', 0} {
			mut := append(append(append([]byte(nil), full[:i]...), v), full[i:]...)
			if _, err := Verify(bytes.NewReader(mut)); err == nil {
				t.Fatalf("byte %q inserted at %d and Verify passed", v, i)
			}
		}
	}
}

func TestPropertyDeletedByteIsDetected(t *testing.T) {
	_, lines := chainLines(sample(6))
	full := join(lines)
	for i := 0; i < len(full); i++ {
		mut := append(append([]byte(nil), full[:i]...), full[i+1:]...)
		if _, err := Verify(bytes.NewReader(mut)); err == nil {
			t.Fatalf("byte %d deleted and Verify passed", i)
		}
	}
}

func TestPropertyRecordSwapIsDetected(t *testing.T) {
	_, lines := chainLines(sample(8))
	for i := range lines {
		for j := i + 1; j < len(lines); j++ {
			ls := append([][]byte(nil), lines...)
			ls[i], ls[j] = ls[j], ls[i]
			if _, err := Verify(bytes.NewReader(join(ls))); err == nil {
				t.Fatalf("records %d and %d swapped and Verify passed", i, j)
			}
		}
	}
}

func TestPropertyDeletionInTheMiddleIsDetected(t *testing.T) {
	recs, lines := chainLines(sample(8))
	for i := 0; i < len(lines)-1; i++ {
		ls := append(append([][]byte(nil), lines[:i]...), lines[i+1:]...)
		if _, err := Verify(bytes.NewReader(join(ls))); err == nil {
			t.Fatalf("record %d deleted and Verify passed", i)
		}
		// Same with the links and hashes recomputed, so that only the
		// continuity of Seq is left to notice.
		sr := append(append([]Record(nil), recs[:i]...), recs[i+1:]...)
		be := mustBreak(t, fmt.Sprintf("relinked deletion of %d", i), join(rechainKeepSeq(sr)))
		if be.Reason != ReasonSeq || be.Seq != uint64(i+1) {
			t.Errorf("relinked deletion of %d: %+v", i, be)
		}
	}
	// Deleting the last record is a truncation at a boundary: it passes, by
	// the documented limit.
	mustVerify(t, "last record deleted", join(lines[:len(lines)-1]))
}

func TestPropertyInsertedLineIsDetected(t *testing.T) {
	recs, lines := chainLines(sample(6))
	extras := map[string][]byte{
		"copy of a record":  lines[1],
		"garbage":           []byte("not json"),
		"empty line":        {},
		"blank":             []byte(" "),
		"forged self-hash":  forged(recs[2], 3, recs[1].Hash),
		"forged wrong prev": forged(recs[2], 3, Genesis),
		"forged wrong seq":  forged(recs[2], 9, recs[1].Hash),
	}
	for name, extra := range extras {
		for at := 0; at <= len(lines); at++ {
			ls := append(append(append([][]byte(nil), lines[:at]...), extra), lines[at:]...)
			if _, err := Verify(bytes.NewReader(join(ls))); err == nil {
				// Appending a record that really continues the chain is not
				// an insertion: it is an append.
				if name == "forged self-hash" && at == 2 {
					continue
				}
				t.Fatalf("%s inserted before line %d and Verify passed", name, at)
			}
		}
	}
}

// forged builds a record with a correct own hash but the given Seq and Prev.
func forged(base Record, seq uint64, prev string) []byte {
	base.Seq = seq
	base.Prev = prev
	base.Hash = hashOf(base)
	return encodeLine(base)
}

func TestVerifyLineCap(t *testing.T) {
	_, lines := chainLines(sample(2))
	atCap := bytes.Repeat([]byte("x"), MaxLineBytes)
	over := bytes.Repeat([]byte("x"), MaxLineBytes+1)
	huge := bytes.Repeat([]byte("x"), 5*MaxLineBytes+17)
	for _, c := range []struct {
		name   string
		line   []byte
		detail string
	}{
		{"at cap", atCap, "invalid character"},
		{"one over", over, "longer than"},
		{"several buffers", huge, "longer than"},
	} {
		be := mustBreak(t, c.name, join([][]byte{lines[0], c.line, lines[1]}))
		if be.Reason != ReasonMalformed || be.Seq != 2 || be.Line != 2 || !strings.Contains(be.Detail, c.detail) {
			t.Errorf("%s: %+v", c.name, be)
		}
		// The same line as the last line, with and without a newline.
		be = mustBreak(t, c.name+" last", join([][]byte{lines[0], c.line}))
		if be.Reason != ReasonMalformed || be.Seq != 2 || be.Line != 2 {
			t.Errorf("%s last: %+v", c.name, be)
		}
		be = mustBreak(t, c.name+" unterminated", append(join(lines[:1]), c.line...))
		if be.Reason != ReasonMalformed || be.Seq != 2 || be.Line != 2 {
			t.Errorf("%s unterminated: %+v", c.name, be)
		}
	}
}

// recoveredLog builds lines[:keep], a torn line, and the matching recovery
// record, then the remaining lines relinked after it.
func recoveredLog(t *testing.T, keep int, tornBytes []byte) ([]byte, int64) {
	t.Helper()
	recs, lines := chainLines(sample(keep))
	log := join(lines)
	off := int64(len(log))
	log = append(log, tornBytes...)
	log = append(log, '\n')
	sum := sha256.Sum256(tornBytes)
	prev := Genesis
	if keep > 0 {
		prev = recs[keep-1].Hash
	}
	r := Record{Seq: uint64(keep + 1), Time: t0, Kind: AuditRecovered, Prev: prev,
		Summary: tornSummary(off, int64(len(tornBytes)), hex.EncodeToString(sum[:]))}
	r.Hash = hashOf(r)
	log = append(log, encodeLine(r)...)
	log = append(log, '\n')
	return log, off
}

func TestVerifyAcceptsAccountedTornLine(t *testing.T) {
	for _, torn := range [][]byte{
		[]byte(`{"seq":4,"time":"2026`),
		[]byte("\x00\x00\x00\x00"),
		[]byte{},
		bytes.Repeat([]byte("z"), 3*MaxLineBytes+5),
	} {
		for _, keep := range []int{0, 3} {
			log, _ := recoveredLog(t, keep, torn)
			res := mustVerify(t, fmt.Sprintf("torn %d bytes after %d records", len(torn), keep), log)
			if res.TornLines != 1 || res.Count != uint64(keep+1) {
				t.Errorf("torn %d bytes after %d records: %+v", len(torn), keep, res)
			}
		}
	}
}

func TestVerifyTornLineNeedsItsRecoveryRecord(t *testing.T) {
	log, off := recoveredLog(t, 3, []byte(`{"seq":4,"tim`))
	good := mustVerify(t, "accounted", log)
	if good.TornLines != 1 {
		t.Fatalf("%+v", good)
	}
	lines := bytes.Split(bytes.TrimSuffix(log, []byte("\n")), []byte("\n"))
	if len(lines) != 5 {
		t.Fatalf("test bug: %d lines", len(lines))
	}
	tornAt := func(extra ...string) []byte {
		return join(append(append([][]byte(nil), lines[:3]...), toBytes(extra)...))
	}
	recovery, _ := decodeLine(lines[4])
	sum := sha256.Sum256([]byte(`{"seq":4,"tim`))
	hexSum := hex.EncodeToString(sum[:])
	mk := func(kind Kind, summary string) string {
		r := recovery
		r.Kind = kind
		r.Summary = summary
		r.Hash = hashOf(r)
		return string(encodeLine(r))
	}
	cases := map[string][]byte{
		"torn line only":         tornAt(`{"seq":4,"tim`),
		"torn then ordinary":     tornAt(`{"seq":4,"tim`, mk(NotifySent, recovery.Summary)),
		"wrong offset":           tornAt(`{"seq":4,"tim`, mk(AuditRecovered, tornSummary(off+1, 13, hexSum))),
		"wrong length":           tornAt(`{"seq":4,"tim`, mk(AuditRecovered, tornSummary(off, 14, hexSum))),
		"wrong sum":              tornAt(`{"seq":4,"tim`, mk(AuditRecovered, tornSummary(off, 13, strings.Repeat("0", 64)))),
		"other torn bytes":       tornAt(`{"seq":4,"tiM`, string(lines[4])),
		"free text summary":      tornAt(`{"seq":4,"tim`, mk(AuditRecovered, "recovered")),
		"two torn lines":         tornAt(`{"seq":4,"tim`, `{"seq":4,"tim`, string(lines[4])),
		"torn then bad hash rec": tornAt(`{"seq":4,"tim`, strings.Replace(string(lines[4]), recovery.Hash, strings.Repeat("a", 64), 1)),
	}
	for name, l := range cases {
		be := mustBreak(t, name, l)
		if be.Reason != ReasonMalformed || be.Seq != 4 || be.Line != 4 || be.Offset != off {
			t.Errorf("%s: %+v", name, be)
		}
	}
	// A recovery record that is not preceded by a torn line is fine, it is
	// an ordinary record.
	recs, ls := chainLines(sample(2))
	r := Record{Seq: 3, Time: t0, Kind: AuditRecovered, Prev: recs[1].Hash, Summary: "anything"}
	r.Hash = hashOf(r)
	if res := mustVerify(t, "lone recovery", join(append(ls, encodeLine(r)))); res.TornLines != 0 || res.Count != 3 {
		t.Errorf("%+v", res)
	}
}

func toBytes(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = []byte(s)
	}
	return out
}

type failingReader struct{ n int }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n == 0 {
		return 0, errors.New("disk on fire")
	}
	f.n--
	return copy(p, "x"), nil
}

func TestVerifyReaderErrorIsNotABreak(t *testing.T) {
	_, err := Verify(&failingReader{n: 3})
	var be *BreakError
	if err == nil || errors.As(err, &be) || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("got %v", err)
	}
	// The same while skipping an over-long line.
	long := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("x"), 2*MaxLineBytes)), &failingReader{})
	_, err = Verify(long)
	if err == nil || errors.As(err, &be) || !strings.Contains(err.Error(), "disk on fire") {
		t.Fatalf("over-long line: got %v", err)
	}
}
