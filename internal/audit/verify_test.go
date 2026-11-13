package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
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
	// A log that went through a torn tail recovery is covered as well, with a
	// region of two lines.
	region := []byte("{\"seq\":5,\"tim\njunk")
	torn := join(lines[:4])
	tornAt := int64(len(torn))
	torn = append(torn, region...)
	tr := Record{Seq: 5, Time: t0, Kind: AuditRecovered,
		Summary: regionSummary(tornAt, region),
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

// regionSummary is the Summary Open writes for the bytes after the last
// intact record as it found them (a newline Open adds is not among them).
func regionSummary(offset int64, region []byte) string {
	terminated := len(region) > 0 && region[len(region)-1] == '\n'
	return tornSummary(offset, int64(len(region)), terminated, sumHex(region))
}

// recoveredLog builds the first keep records, the torn region as given
// (ended by a newline if it lacks one, as Open does), and the matching
// recovery record.
func recoveredLog(t *testing.T, keep int, region []byte) ([]byte, int64) {
	t.Helper()
	recs, lines := chainLines(sample(keep))
	log := join(lines)
	off := int64(len(log))
	log = append(log, region...)
	if len(region) == 0 || region[len(region)-1] != '\n' {
		log = append(log, '\n')
	}
	prev := Genesis
	if keep > 0 {
		prev = recs[keep-1].Hash
	}
	r := Record{Seq: uint64(keep + 1), Time: t0, Kind: AuditRecovered, Prev: prev, Summary: regionSummary(off, region)}
	r.Hash = hashOf(r)
	log = append(log, encodeLine(r)...)
	log = append(log, '\n')
	return log, off
}

func TestVerifyAcceptsAccountedTornRegion(t *testing.T) {
	for name, region := range map[string][]byte{
		"fragment":                 []byte(`{"seq":4,"time":"2026`),
		"zeros":                    []byte("\x00\x00\x00\x00"),
		"blank line":               []byte("\n"),
		"fragment with newline":    []byte("{\"seq\":4,\n"),
		"two lines":                []byte("frag one\nfrag two"),
		"two lines, newline end":   []byte("frag one\nfrag two\n"),
		"blank line inside":        []byte("a\n\nb"),
		"newline first":            []byte("\nb"),
		"three buffers":            bytes.Repeat([]byte("z"), 3*MaxLineBytes+5),
		"exactly the bound":        bytes.Repeat([]byte("z"), MaxTornBytes),
		"the bound, newline end":   append(bytes.Repeat([]byte("z"), MaxTornBytes-1), '\n'),
		"over-long lines in a row": append(append(bytes.Repeat([]byte("y"), MaxLineBytes+5), '\n'), bytes.Repeat([]byte("x"), MaxLineBytes+9)...),
	} {
		for _, keep := range []int{0, 3} {
			log, _ := recoveredLog(t, keep, region)
			res := mustVerify(t, fmt.Sprintf("%s after %d records", name, keep), log)
			if res.TornLines != 1 || res.Count != uint64(keep+1) {
				t.Errorf("%s after %d records: %+v", name, keep, res)
			}
		}
	}
}

func TestVerifyTornRegionBound(t *testing.T) {
	// One byte over the bound cannot be accounted for, in any of its forms.
	for name, region := range map[string][]byte{
		"one line":                 bytes.Repeat([]byte("z"), MaxTornBytes+1),
		"one line, newline end":    append(bytes.Repeat([]byte("z"), MaxTornBytes), '\n'),
		"several lines":            append(append(bytes.Repeat([]byte("z"), MaxTornBytes/2), '\n'), bytes.Repeat([]byte("z"), MaxTornBytes/2+1)...),
		"far over the bound":       bytes.Repeat([]byte("z"), 10*MaxTornBytes),
		"short lines add up":       bytes.Repeat([]byte("z\n"), MaxTornBytes/2+1),
		"short lines, exact bound": bytes.Repeat([]byte("z\n"), MaxTornBytes/2),
	} {
		log, off := recoveredLog(t, 2, region)
		wantBreak := int64(len(region)) > MaxTornBytes
		_, err := Verify(bytes.NewReader(log))
		var be *BreakError
		if !wantBreak {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		// The region Open would have to account for, with the newline it
		// adds, is one byte longer than the bytes of the region.
		withNL := len(region)
		if region[len(region)-1] != '\n' {
			withNL++
		}
		wantDetail := "not followed by a matching"
		if withNL > MaxTornBytes+1 {
			wantDetail = fmt.Sprintf("more than %d bytes", MaxTornBytes)
		}
		if !errors.As(err, &be) || be.Reason != ReasonMalformed || be.Seq != 3 || be.Line != 3 || be.Offset != off ||
			!strings.Contains(be.Detail, wantDetail) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// The break is reported at once: bytes behind it are not read, so a
	// failing reader after the region is not what Verify returns.
	long := bytes.Repeat([]byte("z\n"), MaxTornBytes/2+2)
	logLong, _ := recoveredLog(t, 2, long)
	cut := bytes.Index(logLong, long) + len(long)
	_, err := Verify(io.MultiReader(bytes.NewReader(logLong[:cut]), &failingReader{}))
	var be *BreakError
	if !errors.As(err, &be) {
		t.Errorf("with a failing reader behind the region: %v", err)
	}
	// A region that does not add up to the bound has the plain detail.
	log, _ := recoveredLog(t, 2, []byte("junk"))
	_, err = Verify(bytes.NewReader(log[:len(log)-5]))
	if !errors.As(err, &be) || !strings.Contains(be.Detail, "not followed by a matching") {
		t.Errorf("plain detail: %v", err)
	}
}

func TestVerifyTornLineNeedsItsRecoveryRecord(t *testing.T) {
	frag := `{"seq":4,"tim`
	log, off := recoveredLog(t, 3, []byte(frag))
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
	hexSum := sumHex([]byte(frag))
	mk := func(kind Kind, summary string) string {
		r := recovery
		r.Kind = kind
		r.Summary = summary
		r.Hash = hashOf(r)
		return string(encodeLine(r))
	}
	cases := map[string][]byte{
		"torn line only":         tornAt(frag),
		"torn then ordinary":     tornAt(frag, mk(NotifySent, recovery.Summary)),
		"wrong offset":           tornAt(frag, mk(AuditRecovered, tornSummary(off+1, 13, false, hexSum))),
		"wrong length":           tornAt(frag, mk(AuditRecovered, tornSummary(off, 14, false, hexSum))),
		"wrong sum":              tornAt(frag, mk(AuditRecovered, tornSummary(off, 13, false, strings.Repeat("0", 64)))),
		"wrong terminated flag":  tornAt(frag, mk(AuditRecovered, tornSummary(off, 13, true, hexSum))),
		"flag and length lie":    tornAt(frag, mk(AuditRecovered, tornSummary(off, 12, false, sumHex([]byte(frag[:12]))))),
		"other torn bytes":       tornAt(`{"seq":4,"tiM`, string(lines[4])),
		"free text summary":      tornAt(frag, mk(AuditRecovered, "recovered")),
		"two torn lines":         tornAt(frag, frag, string(lines[4])),
		"torn then bad hash rec": tornAt(frag, strings.Replace(string(lines[4]), recovery.Hash, strings.Repeat("a", 64), 1)),
	}
	for name, l := range cases {
		be := mustBreak(t, name, l)
		if be.Reason != ReasonMalformed || be.Seq != 4 || be.Line != 4 || be.Offset != off {
			t.Errorf("%s: %+v", name, be)
		}
	}
	// The newline that ends the fragment is either one Open added or one the
	// region had; the bytes are the same, so a record that names the region
	// with it (terminated) is as good as one that names it without.
	withNL := recovery
	withNL.Summary = tornSummary(off, int64(len(frag)+1), true, sumHex([]byte(frag+"\n")))
	withNL.Hash = hashOf(withNL)
	if res := mustVerify(t, "region named with its newline", tornAt(frag, string(encodeLine(withNL)))); res.TornLines != 1 {
		t.Errorf("%+v", res)
	}
	// A blank line is a region of one byte; a record that claims an empty
	// region without a newline for it does not account for it.
	blank := recovery
	blank.Summary = tornSummary(off, 0, false, sumHex(nil))
	blank.Hash = hashOf(blank)
	be0 := mustBreak(t, "empty region claimed over a blank line", tornAt("", string(encodeLine(blank))))
	if be0.Seq != 4 || be0.Line != 4 || be0.Offset != off {
		t.Errorf("empty region claimed: %+v", be0)
	}
	// Both lines of a two-line region are accounted for by one record that
	// names both.
	two := frag + "\n" + frag
	r2 := recovery
	r2.Summary = regionSummary(off, []byte(two))
	r2.Hash = hashOf(r2)
	if res := mustVerify(t, "two lines, one record", tornAt(frag, frag, string(encodeLine(r2)))); res.TornLines != 1 || res.Count != 4 {
		t.Errorf("%+v", res)
	}
	// A record with a wrong hash inside a region is a break at the region's
	// start, not part of the region.
	_, ls := chainLines(sample(4))
	badRec := bytes.Replace(ls[3], []byte(`"hash":"`), []byte(`"hash":"0`), 1)
	be := mustBreak(t, "record-shaped line in a region", join(append(append([][]byte(nil), lines[:3]...), []byte(frag), badRec)))
	if be.Seq != 4 || be.Line != 4 || be.Offset != off {
		t.Errorf("record-shaped line in a region: %+v", be)
	}
	// A recovery record that is not preceded by a torn line is fine, it is
	// an ordinary record.
	recs, ls2 := chainLines(sample(2))
	r := Record{Seq: 3, Time: t0, Kind: AuditRecovered, Prev: recs[1].Hash, Summary: "anything"}
	r.Hash = hashOf(r)
	if res := mustVerify(t, "lone recovery", join(append(ls2, encodeLine(r)))); res.TornLines != 0 || res.Count != 3 {
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

// The cap on a line does not depend on the reader: a bufio.Reader with a
// large buffer is used as it is by bufio.NewReaderSize, and the line must
// still be refused.
func TestVerifyLineCapDoesNotDependOnTheReader(t *testing.T) {
	_, lines := chainLines(sample(2))
	readers := map[string]func([]byte) io.Reader{
		"bytes.Reader":       func(b []byte) io.Reader { return bytes.NewReader(b) },
		"bufio 1 MiB":        func(b []byte) io.Reader { return bufio.NewReaderSize(bytes.NewReader(b), 1<<20) },
		"bufio 64 KiB":       func(b []byte) io.Reader { return bufio.NewReaderSize(bytes.NewReader(b), 64<<10) },
		"bufio tiny":         func(b []byte) io.Reader { return bufio.NewReaderSize(bytes.NewReader(b), 16) },
		"one byte at a time": func(b []byte) io.Reader { return iotest.OneByteReader(bytes.NewReader(b)) },
	}
	for _, size := range []int{MaxLineBytes + 1, 3 * MaxLineBytes, MaxTornBytes, MaxTornBytes + 5} {
		line := bytes.Repeat([]byte("x"), size)
		for _, form := range []struct {
			name string
			log  []byte
			line int
		}{
			{"middle", join([][]byte{lines[0], line, lines[1]}), 2},
			{"last, with newline", join([][]byte{lines[0], line}), 2},
			{"last, unterminated", append(join(lines[:1]), line...), 2},
		} {
			for rname, mk := range readers {
				_, err := Verify(mk(form.log))
				var be *BreakError
				if !errors.As(err, &be) || be.Reason != ReasonMalformed || be.Seq != 2 || be.Line != form.line || be.Offset != int64(len(lines[0])+1) ||
					!strings.Contains(be.Detail, fmt.Sprintf("longer than %d bytes", MaxLineBytes)) {
					t.Errorf("%d bytes, %s, %s: %v", size, form.name, rname, err)
				}
			}
		}
	}
	// A record that fills the cap as far as a record can, in a large buffer,
	// is still a record.
	worst := worstRecord()
	worst.Seq, worst.Prev = 1, Genesis
	worst.Hash = hashOf(worst)
	line := encodeLine(worst)
	if len(line) <= MaxLineBytes/2 || len(line) > MaxLineBytes {
		t.Fatalf("test bug: %d bytes", len(line))
	}
	for rname, mk := range readers {
		if res, err := Verify(mk(join([][]byte{line}))); err != nil || res.Count != 1 {
			t.Errorf("worst-case record, %s: %+v %v", rname, res, err)
		}
	}
}
