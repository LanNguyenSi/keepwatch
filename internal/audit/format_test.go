package audit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// goldenRecord is a fixed record whose canonical bytes and hash are pinned.
// The hash was checked against an independent SHA-256 of the body.
func goldenRecord() Record {
	return Record{
		Seq:         7,
		Time:        time.Date(2026, 11, 13, 10, 11, 12, 123456789, time.UTC),
		Kind:        IncidentOpen,
		IncidentID:  "inc-1",
		Fingerprint: "ab" + strings.Repeat("0", 62),
		Summary:     "a\"b\\c<d>&\u00e9\n\x7f\u2028",
		Prev:        Genesis,
	}
}

const goldenBody = `{"seq":7,"time":"2026-11-13T10:11:12.123456789Z","kind":"incident_open","incident_id":"inc-1",` +
	`"fingerprint":"ab00000000000000000000000000000000000000000000000000000000000000",` +
	"\"summary\":\"a\\\"b\\\\c<d>&\u00e9\\u000a\\u007f\u2028\"," +
	`"prev":"0000000000000000000000000000000000000000000000000000000000000000"`

const goldenHash = "16974f5b51ea853f3074c970b6784d014894bab805e6649661bb85b5f906e4ba"

func TestGoldenCanonicalBytesAndHash(t *testing.T) {
	r := goldenRecord()
	if got := string(encodeBody(r)); got != goldenBody {
		t.Fatalf("body\n got %s\nwant %s", got, goldenBody)
	}
	if got := hashOf(r); got != goldenHash {
		t.Fatalf("hash = %s, want %s", got, goldenHash)
	}
	r.Hash = goldenHash
	want := goldenBody + `,"hash":"` + goldenHash + `"}`
	if got := string(encodeLine(r)); got != want {
		t.Fatalf("line\n got %s\nwant %s", got, want)
	}
	back, lerr := decodeLine([]byte(want))
	if lerr != nil {
		t.Fatalf("decode golden: %v", lerr)
	}
	if back.Seq != r.Seq || !back.Time.Equal(r.Time) || back.Kind != r.Kind || back.IncidentID != r.IncidentID ||
		back.Fingerprint != r.Fingerprint || back.Summary != r.Summary || back.Prev != r.Prev || back.Hash != r.Hash {
		t.Fatalf("round trip changed the record: %+v", back)
	}
}

func TestGenesisIsDocumentedConstant(t *testing.T) {
	if Genesis != strings.Repeat("0", 64) {
		t.Fatalf("Genesis = %q", Genesis)
	}
}

func TestHashDependsOnEveryField(t *testing.T) {
	base := goldenRecord()
	want := hashOf(base)
	variants := map[string]func(*Record){
		"seq":         func(r *Record) { r.Seq++ },
		"time":        func(r *Record) { r.Time = r.Time.Add(time.Nanosecond) },
		"kind":        func(r *Record) { r.Kind = IncidentClose },
		"incident id": func(r *Record) { r.IncidentID += "x" },
		"fingerprint": func(r *Record) { r.Fingerprint = "cd" + r.Fingerprint[2:] },
		"summary":     func(r *Record) { r.Summary += "x" },
		"prev":        func(r *Record) { r.Prev = strings.Repeat("1", 64) },
	}
	for name, mut := range variants {
		r := base
		mut(&r)
		if hashOf(r) == want {
			t.Errorf("changing %s does not change the hash", name)
		}
	}
	r := base
	r.Hash = strings.Repeat("f", 64)
	if hashOf(r) != want {
		t.Error("the Hash field is an input of the hash")
	}
}

func TestTimeIsNormalisedToUTC(t *testing.T) {
	loc := time.FixedZone("x", 5*3600+1800)
	a := goldenRecord()
	b := a
	b.Time = a.Time.In(loc)
	if !bytes.Equal(encodeBody(a), encodeBody(b)) {
		t.Fatalf("same instant in another zone encodes differently:\n%s\n%s", encodeBody(a), encodeBody(b))
	}
	c := a
	c.Time = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !strings.Contains(string(encodeBody(c)), `"time":"2026-01-02T03:04:05.000000000Z"`) {
		t.Fatalf("nanoseconds are not always printed: %s", encodeBody(c))
	}
}

func TestStringEscapingRoundTrips(t *testing.T) {
	var all strings.Builder
	for c := 0; c < 0x80; c++ {
		all.WriteByte(byte(c))
	}
	cases := []string{
		"", "plain", `"quoted"`, `back\slash`, "<script>&amp;</script>", all.String(),
		"tab\tnl\ncr\r", "\u00e9\u4e16\u754c", "\U0001F600", "\u2028\u2029", "\ufffd", "\u007f",
		"\\u0041", "\\\"", "\x00\x1f",
	}
	for _, s := range cases {
		r := goldenRecord()
		r.Summary = s
		r.Hash = hashOf(r)
		line := encodeLine(r)
		if bytes.IndexByte(line, '\n') >= 0 {
			t.Errorf("%q: encoded line has a raw newline", s)
		}
		back, lerr := decodeLine(line)
		if lerr != nil {
			t.Errorf("%q: %v", s, lerr)
			continue
		}
		if back.Summary != s {
			t.Errorf("summary %q came back as %q", s, back.Summary)
		}
	}
}

func TestEscapeForms(t *testing.T) {
	got := string(appendString(nil, "\x00\x1f\x7f\"\\<>&\u00e9"))
	want := "\"\\u0000\\u001f\\u007f\\\"\\\\<>&\u00e9\""
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// A line is accepted only in the one form the encoder writes.
func TestDecodeRefusesNonCanonicalForms(t *testing.T) {
	r := goldenRecord()
	r.Hash = hashOf(r)
	good := string(encodeLine(r))
	if _, lerr := decodeLine([]byte(good)); lerr != nil {
		t.Fatalf("baseline: %v", lerr)
	}
	rep := func(old, new string) string {
		if !strings.Contains(good, old) {
			t.Fatalf("test bug: %q not in line", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	bad := map[string]string{
		"leading space":     " " + good,
		"trailing space":    good + " ",
		"trailing data":     good + "{}",
		"space after colon": rep(`"seq":7`, `"seq": 7`),
		"leading zero seq":  rep(`"seq":7`, `"seq":07`),
		"exponent seq":      rep(`"seq":7`, `"seq":7e0`),
		"negative seq":      rep(`"seq":7`, `"seq":-7`),
		"upper case key":    rep(`"seq"`, `"SEQ"`),
		"unknown field":     strings.TrimSuffix(good, "}") + `,"extra":1}`,
		"missing field":     rep(`"incident_id":"inc-1",`, ``),
		"swapped fields":    rep(`"kind":"incident_open","incident_id":"inc-1"`, `"incident_id":"inc-1","kind":"incident_open"`),
		"duplicate key":     rep(`"seq":7,`, `"seq":7,"seq":7,`),
		"alt escape":        rep(`inc-1`, `inc\u002d1`),
		"escaped slash":     rep(`inc-1`, `inc\/1`),
		"short time":        rep(`.123456789Z`, `.123Z`),
		"offset time":       rep(`.123456789Z`, `.123456789+00:00`),
		"upper hex hash":    strings.Replace(good, goldenHash, strings.ToUpper(goldenHash), 1),
		"short prev":        rep(strings.Repeat("0", 64), strings.Repeat("0", 63)),
		"non hex hash":      strings.Replace(good, goldenHash, strings.Repeat("g", 64), 1),
		"raw control char":  rep(`inc-1`, "inc\x01"),
		"raw invalid utf8":  rep(`inc-1`, "inc\xff"),
		"raw del":           rep(`inc-1`, "inc\x7f"),
		"empty":             "",
		"not an object":     `[]`,
		"string seq":        rep(`"seq":7`, `"seq":"7"`),
		"null summary":      rep(`"summary":"`, `"summary":null,"x":"`),
		"truncated":         good[:len(good)-1],
		"month 13":          rep(`2026-11-13`, `2026-13-13`),
		"time with t lower": rep(`T10`, `t10`),
		"mid line newline":  rep(`inc-1`, "inc\n1"),
	}
	for name, line := range bad {
		if _, lerr := decodeLine([]byte(line)); lerr == nil {
			t.Errorf("%s: accepted", name)
		} else if lerr.reason != ReasonMalformed {
			t.Errorf("%s: reason %q, want malformed", name, lerr.reason)
		}
	}
	// A well formed record with the wrong hash is a hash mismatch, not a
	// malformed line.
	wrong := strings.Replace(good, goldenHash, strings.Repeat("a", 64), 1)
	if _, lerr := decodeLine([]byte(wrong)); lerr == nil || lerr.reason != ReasonHash {
		t.Errorf("wrong hash: %v", lerr)
	}
	changed := rep(`inc-1`, `inc-2`)
	if _, lerr := decodeLine([]byte(changed)); lerr == nil || lerr.reason != ReasonHash {
		t.Errorf("changed content: %v", lerr)
	}
}

func TestIsHex64(t *testing.T) {
	for s, want := range map[string]bool{
		strings.Repeat("a", 64): true, strings.Repeat("0", 64): true, "0123456789abcdef" + strings.Repeat("9", 48): true,
		strings.Repeat("a", 63): false, strings.Repeat("a", 65): false, strings.Repeat("A", 64): false,
		strings.Repeat("g", 64): false, strings.Repeat("/", 64): false, strings.Repeat(":", 64): false,
		strings.Repeat("`", 64): false, strings.Repeat("{", 64): false, "": false,
	} {
		if got := isHex64(s); got != want {
			t.Errorf("isHex64(%.12q...) = %v", s, got)
		}
	}
}

type validateCase struct {
	name string
	mut  func(*Record)
	want error
}

func validateCases() []validateCase {
	return []validateCase{
		{"summary at cap", func(r *Record) { r.Summary = strings.Repeat("x", MaxSummary) }, nil},
		{"summary over cap", func(r *Record) { r.Summary = strings.Repeat("x", MaxSummary+1) }, ErrSummaryTooLong},
		{"kind at cap", func(r *Record) { r.Kind = Kind(strings.Repeat("k", MaxKind)) }, nil},
		{"kind over cap", func(r *Record) { r.Kind = Kind(strings.Repeat("k", MaxKind+1)) }, ErrFieldTooLong},
		{"kind far over cap", func(r *Record) { r.Kind = Kind(strings.Repeat("k", 200)) }, ErrFieldTooLong},
		{"incident id at cap", func(r *Record) { r.IncidentID = strings.Repeat("i", MaxIncidentID) }, nil},
		{"incident id over cap", func(r *Record) { r.IncidentID = strings.Repeat("i", MaxIncidentID+1) }, ErrFieldTooLong},
		{"fingerprint at cap", func(r *Record) { r.Fingerprint = strings.Repeat("f", MaxFingerprint) }, nil},
		{"fingerprint over cap", func(r *Record) { r.Fingerprint = strings.Repeat("f", MaxFingerprint+1) }, ErrFieldTooLong},
		{"empty kind", func(r *Record) { r.Kind = "" }, ErrInvalidRecord},
		{"an unknown kind is stored as given", func(r *Record) { r.Kind = "not_one_of_ours" }, nil},
		{"zero time", func(r *Record) { r.Time = time.Time{} }, ErrInvalidRecord},
		{"year 1", func(r *Record) { r.Time = time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC) }, nil},
		{"year 9999", func(r *Record) { r.Time = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC) }, nil},
		{"year 10000", func(r *Record) { r.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }, ErrInvalidRecord},
		{"year 0", func(r *Record) { r.Time = time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC) }, ErrInvalidRecord},
		{"year 9999 in a zone that is 10000 in UTC", func(r *Record) {
			r.Time = time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("x", -2*3600))
		}, ErrInvalidRecord},
		{"invalid utf8 summary", func(r *Record) { r.Summary = "a\xffb" }, ErrInvalidRecord},
		{"invalid utf8 kind", func(r *Record) { r.Kind = "k\xff" }, ErrInvalidRecord},
		{"invalid utf8 incident id", func(r *Record) { r.IncidentID = "\xc3" }, ErrInvalidRecord},
		{"invalid utf8 fingerprint", func(r *Record) { r.Fingerprint = "\xe2\x82" }, ErrInvalidRecord},
		{"encoded surrogate", func(r *Record) { r.Summary = "\xed\xa0\x80" }, ErrInvalidRecord},
	}
}

func TestValidate(t *testing.T) {
	ok := goldenRecord()
	if err := validate(ok); err != nil {
		t.Fatalf("golden record: %v", err)
	}
	for _, c := range validateCases() {
		r := ok
		c.mut(&r)
		err := validate(r)
		if c.want == nil && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if errors.Is(validate(func() Record { r := ok; r.Summary = strings.Repeat("x", MaxSummary+1); return r }()), ErrFieldTooLong) {
		t.Error("a long summary is ErrSummaryTooLong, not ErrFieldTooLong")
	}
}

// What the writer cannot store is not read as a record: for every case a
// line that is otherwise a perfect record (canonical, with its own correct
// hash) is accepted by decodeLine exactly when validate accepts the record,
// and a refusal is a malformed line, not a hash mismatch.
func TestDecodeAppliesTheWritersValidation(t *testing.T) {
	for _, c := range validateCases() {
		r := goldenRecord()
		c.mut(&r)
		r.Hash = hashOf(r)
		got, lerr := decodeLine(encodeLine(r))
		if c.want == nil {
			if lerr != nil {
				t.Errorf("%s: a record Append stores was refused: %v", c.name, lerr)
			} else if got.Kind != r.Kind || got.Summary != r.Summary || !got.Time.Equal(r.Time) {
				t.Errorf("%s: decoded %+v", c.name, got)
			}
			continue
		}
		if lerr == nil || lerr.reason != ReasonMalformed {
			t.Errorf("%s: a record Append refuses was accepted or not malformed: %v", c.name, lerr)
		}
	}
}

// The same through Verify and Show: such a line is not a record, so it is a
// break unless a recovery record accounts for it.
func TestVerifyAndShowRefuseWhatAppendRefuses(t *testing.T) {
	recs, lines := chainLines(sample(2))
	for _, c := range validateCases() {
		if c.want == nil {
			continue
		}
		bad := Record{Seq: 3, Time: t0, Kind: IncidentOpen, Prev: recs[1].Hash}
		c.mut(&bad)
		bad.Hash = hashOf(bad)
		log := join(append(append([][]byte(nil), lines...), encodeLine(bad)))
		be := mustBreak(t, c.name, log)
		if be.Reason != ReasonMalformed || be.Seq != 3 || be.Line != 3 {
			t.Errorf("%s: %+v", c.name, be)
		}
		n := 0
		err := Show(bytes.NewReader(log), Filter{}, func(Record) error { n++; return nil })
		if err == nil || n != 2 {
			t.Errorf("%s: Show delivered %d records, err %v", c.name, n, err)
		}
	}
	// Year 0000 written the way an attacker would, by hand.
	zero := `"time":"0000-01-01T00:00:00.000000000Z"`
	r := Record{Seq: 3, Time: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Kind: IncidentOpen, Prev: recs[1].Hash}
	r.Hash = hashOf(r)
	line := strings.Replace(string(encodeLine(r)), `"time":"2026-01-01T00:00:00.000000000Z"`, zero, 1)
	if line == string(encodeLine(r)) {
		t.Fatal("test bug")
	}
	if _, lerr := decodeLine([]byte(line)); lerr == nil {
		t.Error("year 0000 accepted")
	}
}

// The longest record that Append can accept still fits MaxLineBytes, so a
// valid line is never read as an over-long one.
func TestWorstCaseLineFitsTheLineCap(t *testing.T) {
	r := Record{
		Seq: ^uint64(0), Time: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		Kind: Kind(strings.Repeat("\x01", MaxKind)), IncidentID: strings.Repeat("\x02", MaxIncidentID),
		Fingerprint: strings.Repeat("\x03", MaxFingerprint), Summary: strings.Repeat("\x04", MaxSummary),
		Prev: Genesis,
	}
	if err := validate(r); err != nil {
		t.Fatal(err)
	}
	r.Hash = hashOf(r)
	line := encodeLine(r)
	if len(line) > MaxLineBytes {
		t.Fatalf("worst case line is %d bytes, cap %d", len(line), MaxLineBytes)
	}
	if len(line) < MaxLineBytes/2 {
		t.Fatalf("worst case line is only %d bytes: the test no longer covers the worst case", len(line))
	}
	if _, lerr := decodeLine(line); lerr != nil {
		t.Fatalf("worst case does not decode: %v", lerr)
	}
}

func TestTornSummaryFormat(t *testing.T) {
	got := tornSummary(12, 34, true, "abc")
	if got != "torn tail: offset=12 length=34 terminated=true sha256=abc" {
		t.Fatalf("got %q", got)
	}
	got = tornSummary(12, 34, false, "abc")
	if got != "torn tail: offset=12 length=34 terminated=false sha256=abc" {
		t.Fatalf("got %q", got)
	}
}

// Prev is hashed as part of the record: a line whose Prev was changed, with
// every other byte and the stored hash kept, is a hash mismatch.
func TestDecodeDetectsChangedPrev(t *testing.T) {
	r := goldenRecord()
	r.Hash = hashOf(r)
	line := strings.Replace(string(encodeLine(r)), `"prev":"`+Genesis, `"prev":"`+strings.Repeat("1", 64), 1)
	if _, lerr := decodeLine([]byte(line)); lerr == nil || lerr.reason != ReasonHash {
		t.Fatalf("got %v", lerr)
	}
}
