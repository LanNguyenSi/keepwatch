package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

func newDir(t *testing.T) (*securefile.Dir, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	d, err := securefile.OpenDir(p, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, p
}

func logPath(p string) string { return filepath.Join(p, FileName) }

func readLog(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(logPath(p))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func appendRaw(t *testing.T, p string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(logPath(p), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

func openW(t *testing.T, d *securefile.Dir, o Options) (*Writer, *Recovery) {
	t.Helper()
	if o.Now == nil {
		o.Now = func() time.Time { return t0.Add(time.Hour) }
	}
	w, rec, err := Open(d, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w, rec
}

func put(t *testing.T, w *Writer, n int) []Record {
	t.Helper()
	var out []Record
	for _, r := range sample(n) {
		got, err := w.Append(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got)
	}
	return out
}

func TestOpenCreatesLogAndAppendChains(t *testing.T) {
	d, p := newDir(t)
	w, rec := openW(t, d, Options{})
	if rec != nil {
		t.Fatalf("fresh log reported a recovery: %+v", rec)
	}
	recs := put(t, w, 3)
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("record %d has seq %d", i, r.Seq)
		}
		if i == 0 && r.Prev != Genesis {
			t.Errorf("first prev %s", r.Prev)
		}
		if i > 0 && r.Prev != recs[i-1].Hash {
			t.Errorf("record %d prev %s, want %s", i, r.Prev, recs[i-1].Hash)
		}
		if r.Hash != hashOf(r) {
			t.Errorf("record %d: returned hash is not the hash of the record", i)
		}
	}
	b := readLog(t, p)
	res := mustVerify(t, "written", b)
	if res.Count != 3 || res.LastHash != recs[2].Hash {
		t.Fatalf("%+v", res)
	}
	if want := int64(len(b)); w.Size() != want {
		t.Errorf("Size() = %d, file has %d", w.Size(), want)
	}
	fi, err := os.Stat(logPath(p))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, err %v", fi.Mode(), err)
	}
}

func TestAppendIgnoresCallerChainFields(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	r := sample(1)[0]
	r.Seq, r.Prev, r.Hash = 99, strings.Repeat("e", 64), strings.Repeat("d", 64)
	got, err := w.Append(r)
	if err != nil {
		t.Fatal(err)
	}
	if got.Seq != 1 || got.Prev != Genesis || got.Hash == r.Hash {
		t.Fatalf("%+v", got)
	}
	mustVerify(t, "ignored fields", readLog(t, p))
}

func TestAppendStoresStringsAsGiven(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	r := sample(1)[0]
	r.Summary = strings.Repeat("a\"\\\né ", 100)
	r.IncidentID = "weird id \t"
	if _, err := w.Append(r); err != nil {
		t.Fatal(err)
	}
	var got []Record
	if err := Show(bytes.NewReader(readLog(t, p)), Filter{}, func(x Record) error { got = append(got, x); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Summary != r.Summary || got[0].IncidentID != r.IncidentID {
		t.Fatalf("got %+v", got)
	}
}

func TestAppendRefusesWithoutWriting(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 2)
	before := readLog(t, p)
	long := sample(1)[0]
	long.Summary = strings.Repeat("x", MaxSummary+1)
	if _, err := w.Append(long); !errors.Is(err, ErrSummaryTooLong) {
		t.Fatalf("got %v", err)
	}
	bad := sample(1)[0]
	bad.Summary = "\xff"
	if _, err := w.Append(bad); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(before, readLog(t, p)) {
		t.Fatal("a refused record changed the file")
	}
	// The writer is still usable and the sequence has no hole.
	r, err := w.Append(sample(1)[0])
	if err != nil || r.Seq != 3 {
		t.Fatalf("%+v %v", r, err)
	}
	mustVerify(t, "after refusals", readLog(t, p))
	// A summary at the cap is stored whole.
	atCap := sample(1)[0]
	atCap.Summary = strings.Repeat("y", MaxSummary)
	if _, err := w.Append(atCap); err != nil {
		t.Fatal(err)
	}
	var last Record
	_ = Show(bytes.NewReader(readLog(t, p)), Filter{}, func(x Record) error { last = x; return nil })
	if last.Summary != atCap.Summary {
		t.Fatalf("summary at the cap was changed: %d bytes", len(last.Summary))
	}
}

// Only Open writes the kind that accounts for a torn region; a caller that
// could write it would be able to plant a record Verify takes as proof of a
// region.
func TestAppendRefusesTheRecoveryKind(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 2)
	before := readLog(t, p)
	for _, summary := range []string{"", "x", tornSummary(0, 4, false, sumHex([]byte("torn"))), completedSummary(0, 1)} {
		r := sample(1)[0]
		r.Kind = AuditRecovered
		r.Summary = summary
		if _, err := w.Append(r); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("summary %q: got %v", summary, err)
		}
	}
	if !bytes.Equal(before, readLog(t, p)) {
		t.Fatal("a refused record was written")
	}
	// The writer is not hurt by the refusals and Open still writes the kind.
	if _, err := w.Append(sample(1)[0]); err != nil {
		t.Fatal(err)
	}
	w.Close()
	appendRaw(t, p, []byte("torn"))
	w2, rec := openW(t, d, Options{})
	defer w2.Close()
	if rec == nil || rec.Seq != 4 {
		t.Fatalf("%+v", rec)
	}
	var last Record
	_ = Show(bytes.NewReader(readLog(t, p)), Filter{}, func(r Record) error { last = r; return nil })
	if last.Kind != AuditRecovered {
		t.Fatalf("%+v", last)
	}
}

func TestReopenContinuesSeqAndPrev(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	recs := put(t, w, 3)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w2, rec := openW(t, d, Options{})
	if rec != nil {
		t.Fatalf("clean reopen reported a recovery: %+v", rec)
	}
	next, err := w2.Append(sample(1)[0])
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq != 4 || next.Prev != recs[2].Hash {
		t.Fatalf("got seq %d prev %s, want 4 and %s", next.Seq, next.Prev, recs[2].Hash)
	}
	res := mustVerify(t, "reopened", readLog(t, p))
	if res.Count != 4 || res.LastHash != next.Hash {
		t.Fatalf("%+v", res)
	}
}

func TestReopenOfEmptyFileStartsAtGenesis(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	w.Close()
	w2, rec := openW(t, d, Options{})
	if rec != nil {
		t.Fatal("recovery on an empty file")
	}
	r, err := w2.Append(sample(1)[0])
	if err != nil || r.Seq != 1 || r.Prev != Genesis {
		t.Fatalf("%+v %v", r, err)
	}
	mustVerify(t, "empty reopen", readLog(t, p))
}

func TestTornTail(t *testing.T) {
	_, lines := chainLines(sample(3))
	good := join(lines)
	two := join(lines[:2])
	partial := lines[2][:len(lines[2])/2] // half of a record, as a crash leaves it
	cases := []struct {
		name       string
		content    []byte
		tornAt     int    // offset of the torn region
		region     []byte // the bytes after the last intact record
		wantSeq    uint64 // seq of the recovery record
		terminated bool   // the region already ends with a newline
	}{
		{"unterminated fragment", append(append([]byte(nil), two...), partial...), len(two), partial, 3, false},
		{"invalid line with newline", append(append([]byte(nil), two...), append(append([]byte(nil), partial...), '\n')...), len(two), append(append([]byte(nil), partial...), '\n'), 3, true},
		{"zero filled tail", append(append([]byte(nil), two...), make([]byte, 40)...), len(two), make([]byte, 40), 3, false},
		{"empty line at the end", append(append([]byte(nil), good...), '\n'), len(good), []byte("\n"), 4, true},
		{"fragment only", partial, 0, partial, 1, false},
		{"invalid line only", append(append([]byte(nil), partial...), '\n'), 0, append(append([]byte(nil), partial...), '\n'), 1, true},
		{"non canonical last line", append(append([]byte(nil), two...), append([]byte(" "+string(lines[2])), '\n')...), len(two), append([]byte(" "+string(lines[2])), '\n'), 3, true},
		{"two lines, the last without newline", append(append([]byte(nil), two...), []byte("junk\nmore junk")...), len(two), []byte("junk\nmore junk"), 3, false},
		{"two lines with newlines", append(append([]byte(nil), two...), []byte("junk\nmore junk\n")...), len(two), []byte("junk\nmore junk\n"), 3, true},
		{"garbage then a fragment", append(append([]byte(nil), lines[0]...), append([]byte("\njunk\n"), lines[2][:20]...)...), len(lines[0]) + 1, append([]byte("junk\n"), lines[2][:20]...), 2, false},
		{"empty line then a fragment", append(append([]byte(nil), join(lines[:1])...), append([]byte("\n"), lines[2][:20]...)...), len(lines[0]) + 1, append([]byte("\n"), lines[2][:20]...), 2, false},
		{"garbage then an invalid line", append(append([]byte(nil), join(lines[:1])...), []byte("junk\nmore junk\n")...), len(lines[0]) + 1, []byte("junk\nmore junk\n"), 2, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, p := newDir(t)
			appendRaw(t, p, c.content)
			now := t0.Add(48 * time.Hour)
			w, rec, err := Open(d, Options{Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if rec == nil {
				t.Fatal("torn tail not reported")
			}
			want := Recovery{Offset: int64(c.tornAt), Length: int64(len(c.region)), Hash: sumHex(c.region), Terminated: c.terminated, Seq: c.wantSeq}
			if *rec != want {
				t.Fatalf("recovery %+v, want %+v", *rec, want)
			}
			after := readLog(t, p)
			if !bytes.HasPrefix(after, c.content) {
				t.Fatal("earlier bytes were changed")
			}
			added := after[len(c.content):]
			if c.terminated == (len(added) > 0 && added[0] == '\n') {
				t.Errorf("newline handling: added %q", added)
			}
			res := mustVerify(t, "recovered", after)
			if res.TornLines != 1 || res.Count != c.wantSeq {
				t.Fatalf("%+v", res)
			}
			var last Record
			_ = Show(bytes.NewReader(after), Filter{}, func(r Record) error { last = r; return nil })
			if last.Kind != AuditRecovered || last.Seq != c.wantSeq || !last.Time.Equal(now) ||
				last.Summary != tornSummary(want.Offset, want.Length, want.Terminated, want.Hash) || last.IncidentID != "" || last.Fingerprint != "" {
				t.Errorf("recovery record %+v", last)
			}
			// The writer continues after the recovery record.
			next, err := w.Append(sample(1)[0])
			if err != nil || next.Seq != c.wantSeq+1 || next.Prev != last.Hash {
				t.Fatalf("%+v %v", next, err)
			}
			mustVerify(t, "continued", readLog(t, p))
			// A reopen finds an intact end and reports nothing.
			w.Close()
			w2, rec2 := openW(t, d, Options{})
			if rec2 != nil {
				t.Errorf("second open reported %+v", rec2)
			}
			n2, err := w2.Append(sample(1)[0])
			if err != nil || n2.Seq != c.wantSeq+2 {
				t.Fatalf("%+v %v", n2, err)
			}
		})
	}
}

func TestTornRegionBoundAtOpen(t *testing.T) {
	for _, withRecords := range []int{0, 2} {
		for name, size := range map[string]int{"at the bound": MaxTornBytes, "past the bound": MaxTornBytes + 1} {
			t.Run(fmt.Sprintf("%s after %d records", name, withRecords), func(t *testing.T) {
				d, p := newDir(t)
				w, _ := openW(t, d, Options{})
				put(t, w, withRecords)
				w.Close()
				junk := bytes.Repeat([]byte("j"), size)
				appendRaw(t, p, junk)
				before := readLog(t, p)
				w2, rec, err := Open(d, Options{Now: func() time.Time { return t0 }})
				if size > MaxTornBytes {
					if !errors.Is(err, ErrCorrupt) || w2 != nil {
						t.Fatalf("got %v %v", w2, err)
					}
					if !bytes.Equal(readLog(t, p), before) {
						t.Fatal("the file was changed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer w2.Close()
				if rec == nil || rec.Length != int64(len(junk)) || rec.Hash != sumHex(junk) || rec.Terminated {
					t.Fatalf("%+v", rec)
				}
				res := mustVerify(t, "large torn", readLog(t, p))
				if res.TornLines != 1 || res.Count != uint64(withRecords+1) {
					t.Fatalf("%+v", res)
				}
			})
		}
	}
}

func TestOpenRefusesDamageThatIsNotATornWrite(t *testing.T) {
	recs, lines := chainLines(sample(3))
	badHash := func(l []byte, r Record) []byte {
		return bytes.Replace(l, []byte(r.Hash), []byte(strings.Repeat("a", 64)), 1)
	}
	cases := map[string][]byte{
		"last record with a wrong hash":                  join([][]byte{lines[0], lines[1], badHash(lines[2], recs[2])}),
		"only record with a wrong hash":                  join([][]byte{badHash(lines[0], recs[0])}),
		"bad record before a torn fragment":              append(join([][]byte{lines[0], badHash(lines[1], recs[1])}), lines[2][:20]...),
		"bad record after a torn fragment":               join([][]byte{lines[0], lines[1][:20], badHash(lines[2], recs[2])}),
		"bad record, then garbage, then an unterminated": append(join([][]byte{lines[0], badHash(lines[1], recs[1]), []byte("junk")}), "tail"...),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			d, p := newDir(t)
			appendRaw(t, p, content)
			w, rec, err := Open(d, Options{})
			if !errors.Is(err, ErrCorrupt) || w != nil || rec != nil {
				t.Fatalf("got %v %v %v", w, rec, err)
			}
			if !bytes.Equal(readLog(t, p), content) {
				t.Fatal("the file was changed")
			}
		})
	}
}

func TestOpenRefusesChangedFile(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 2)
	// A writer that believes the file has another size than it has: bigger
	// and smaller.
	for _, believed := range []int64{5, w.Size() + 7} {
		x := &Writer{f: w.f, size: believed, max: DefaultMaxSize}
		if _, err := x.resume(); !errors.Is(err, securefile.ErrChanged) {
			t.Fatalf("believed %d: got %v", believed, err)
		}
	}
	// A file that cannot be examined at all is an error, not a size.
	gone, err := os.Open(logPath(p))
	if err != nil {
		t.Fatal(err)
	}
	gone.Close()
	if _, err := (&Writer{f: gone, size: w.Size(), max: DefaultMaxSize}).resume(); err == nil || errors.Is(err, securefile.ErrChanged) {
		t.Fatalf("closed file: got %v", err)
	}
	// A file that shrank before the check, and one that shrank between the
	// check and the read.
	size := w.Size()
	ran := false
	x := &Writer{f: w.f, size: size, max: DefaultMaxSize, afterStat: func() {
		ran = true
		if err := os.Truncate(logPath(p), size-3); err != nil {
			t.Error(err)
		}
	}}
	if _, err := x.resume(); !errors.Is(err, securefile.ErrChanged) || !ran {
		t.Fatalf("shrunk after the check (hook ran: %v): got %v", ran, err)
	}
	if _, err := (&Writer{f: w.f, size: size, max: DefaultMaxSize}).resume(); !errors.Is(err, securefile.ErrChanged) {
		t.Fatalf("shrunk before the check: got %v", err)
	}
}

func TestOpenReadsTheFileItAppendsTo(t *testing.T) {
	// The log is replaced by another file (same name, other content) after
	// the writer opened it: the writer keeps working on the descriptor it
	// holds and never mixes in the file that the name now points to.
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	recs := put(t, w, 2)
	w.Close()
	_, other := chainLines(sample(9))
	ran := false
	w2, _, err := Open(d, Options{afterOpen: func() {
		ran = true
		// Between the open and the read, swap the file by name.
		if err := os.WriteFile(logPath(p)+".new", join(other), 0o600); err != nil {
			t.Error(err)
		}
		if err := os.Rename(logPath(p)+".new", logPath(p)); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if !ran {
		t.Fatal("test bug: the file was not swapped")
	}
	r, err := w2.Append(sample(1)[0])
	if err != nil || r.Seq != 3 || r.Prev != recs[1].Hash {
		t.Fatalf("resumed from the swapped file: %+v %v", r, err)
	}
}

// sizedFor is a MaxSize that lets ordinary records reach ordinary bytes.
func sizedFor(ordinary int64) int64 { return ordinary + ReserveBytes }

func lineLenOf(t *testing.T, r Record) int64 {
	t.Helper()
	_, probe := chainLines([]Record{r})
	return int64(len(probe[0]) + 1)
}

func TestSizeLimit(t *testing.T) {
	_, lines := chainLines(sample(3))
	lineLen := int64(len(lines[0]) + 1)
	t.Run("ordinary records stop at the limit minus the reserve and leave the file alone", func(t *testing.T) {
		d, p := newDir(t)
		// room for exactly two records of this size
		w, _ := openW(t, d, Options{MaxSize: sizedFor(2*lineLen + 20)})
		for i := 0; i < 2; i++ {
			if _, err := w.Append(sample(3)[i]); err != nil {
				t.Fatal(err)
			}
		}
		before := readLog(t, p)
		_, err := w.Append(sample(3)[2])
		if !errors.Is(err, ErrFull) {
			t.Fatalf("got %v", err)
		}
		if !bytes.Equal(before, readLog(t, p)) {
			t.Fatal("the refused record was written")
		}
		// Not a failure of the writer: the refusal stays the same and the
		// chain has no hole.
		if _, err := w.Append(sample(3)[2]); !errors.Is(err, ErrFull) {
			t.Fatalf("second try: %v", err)
		}
		mustVerify(t, "at limit", readLog(t, p))
	})
	t.Run("a record that fits exactly is written, one byte less room is not", func(t *testing.T) {
		d, p := newDir(t)
		r := sample(1)[0]
		exact := lineLenOf(t, r)
		w, _ := openW(t, d, Options{MaxSize: sizedFor(exact - 1)})
		if _, err := w.Append(r); !errors.Is(err, ErrFull) {
			t.Fatalf("one byte short: %v", err)
		}
		w.Close()
		os.Remove(logPath(p))
		w2, _ := openW(t, d, Options{MaxSize: sizedFor(exact)})
		if _, err := w2.Append(r); err != nil {
			t.Fatalf("exact fit: %v", err)
		}
		if w2.Size() != exact {
			t.Fatalf("size %d", w2.Size())
		}
		if _, err := w2.Append(r); !errors.Is(err, ErrFull) {
			t.Fatalf("after the exact fit: %v", err)
		}
	})
	t.Run("open of a log past the limit", func(t *testing.T) {
		d, p := newDir(t)
		// More than the reserve, so that the limit under test is a valid one.
		writeChain(t, logPath(p), 20, bigRecord)
		before := readLog(t, p)
		if len(before) <= ReserveBytes+1 {
			t.Fatal("test bug: the log is not above the reserve")
		}
		_, _, err := Open(d, Options{MaxSize: int64(len(before)) - 1})
		if !errors.Is(err, ErrFull) || !errors.Is(err, securefile.ErrTooLarge) {
			t.Fatalf("got %v", err)
		}
		// At the limit exactly, open works and no record is accepted, not
		// even a terminal one.
		w2, _, err := Open(d, Options{MaxSize: int64(len(before))})
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		for _, k := range []Kind{IncidentOpen, DaemonStop, DaemonError} {
			r := sample(1)[0]
			r.Kind = k
			if _, err := w2.Append(r); !errors.Is(err, ErrFull) {
				t.Fatalf("%s: got %v", k, err)
			}
		}
	})
	t.Run("the recovery record uses the reserve and needs room there", func(t *testing.T) {
		d, p := newDir(t)
		w, _ := openW(t, d, Options{})
		put(t, w, 2)
		w.Close()
		// A torn region bigger than the reserve, so that the recovery record
		// starts beyond the ordinary limit.
		appendRaw(t, p, bytes.Repeat([]byte("t"), ReserveBytes+500))
		before := readLog(t, p)
		// Find the size after a recovery with room to spare.
		probe := t.TempDir()
		pd, err := securefile.OpenDir(filepath.Join(probe, "s"), true, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer pd.Close()
		if err := os.WriteFile(filepath.Join(probe, "s", FileName), before, 0o600); err != nil {
			t.Fatal(err)
		}
		pw, _, err := Open(pd, Options{Now: func() time.Time { return t0 }})
		if err != nil {
			t.Fatal(err)
		}
		final := pw.Size()
		pw.Close()
		if final-ReserveBytes >= int64(len(before)) {
			t.Fatal("test bug: the recovery record does not need the reserve")
		}

		_, _, err = Open(d, Options{MaxSize: final - 1, Now: func() time.Time { return t0 }})
		if !errors.Is(err, ErrFull) {
			t.Fatalf("one byte short: %v", err)
		}
		if !bytes.Equal(before, readLog(t, p)) {
			t.Fatal("the file was changed")
		}
		w2, rec, err := Open(d, Options{MaxSize: final, Now: func() time.Time { return t0 }})
		if err != nil || rec == nil {
			t.Fatalf("exact fit: %v %v", rec, err)
		}
		defer w2.Close()
		if w2.Size() != final {
			t.Fatalf("size %d, want %d", w2.Size(), final)
		}
	})
	t.Run("a log in the reserve opens; only a terminal record is taken", func(t *testing.T) {
		d, _ := newDir(t)
		w, _ := openW(t, d, Options{MaxSize: sizedFor(2*lineLen + 20)})
		for i := 0; i < 2; i++ {
			if _, err := w.Append(sample(3)[i]); err != nil {
				t.Fatal(err)
			}
		}
		stop := sample(1)[0]
		stop.Kind = DaemonStop
		if _, err := w.Append(stop); err != nil {
			t.Fatalf("terminal record in the reserve: %v", err)
		}
		w.Close()
		w2, rec := openW(t, d, Options{MaxSize: sizedFor(2*lineLen + 20)})
		if rec != nil {
			t.Fatalf("%+v", rec)
		}
		if w2.Size() <= w2.MaxSize()-ReserveBytes {
			t.Fatal("test bug: the log is not in the reserve")
		}
		if _, err := w2.Append(sample(1)[0]); !errors.Is(err, ErrFull) {
			t.Fatalf("ordinary record: %v", err)
		}
		// A terminal record of the new run may use the reserve again.
		stop.Kind = DaemonError
		if _, err := w2.Append(stop); err != nil {
			t.Fatalf("terminal record after reopen: %v", err)
		}
	})
}

func TestTerminalRecordUsesTheReserveOnce(t *testing.T) {
	r := sample(1)[0]
	for _, kind := range []Kind{DaemonStop, DaemonError} {
		t.Run(string(kind), func(t *testing.T) {
			d, p := newDir(t)
			lineLen := lineLenOf(t, r)
			w, _ := openW(t, d, Options{MaxSize: sizedFor(lineLen)})
			if _, err := w.Append(r); err != nil {
				t.Fatal(err)
			}
			if _, err := w.Append(r); !errors.Is(err, ErrFull) {
				t.Fatalf("ordinary record at the limit: %v", err)
			}
			term := r
			term.Kind = kind
			if _, err := w.Append(term); err != nil {
				t.Fatalf("terminal record: %v", err)
			}
			if w.Size() <= w.MaxSize()-ReserveBytes {
				t.Fatal("test bug: the terminal record did not use the reserve")
			}
			// Only one: a second terminal record, of either kind, and any
			// other record are refused.
			for _, k := range []Kind{DaemonStop, DaemonError, IncidentClose} {
				x := r
				x.Kind = k
				if _, err := w.Append(x); !errors.Is(err, ErrFull) {
					t.Errorf("%s after the terminal record: %v", k, err)
				}
			}
			mustVerify(t, "terminal", readLog(t, p))
		})
	}
}

func TestOnlyTerminalKindsUseTheReserve(t *testing.T) {
	r := sample(1)[0]
	for _, kind := range []Kind{IncidentOpen, DaemonStart, NotifyDropped, Kind("daemon_stop2")} {
		d, _ := newDir(t)
		w, _ := openW(t, d, Options{MaxSize: sizedFor(10)})
		x := r
		x.Kind = kind
		if _, err := w.Append(x); !errors.Is(err, ErrFull) {
			t.Errorf("%s: got %v", kind, err)
		}
	}
}

// prefilled returns a state directory whose log holds twenty long records,
// more than the reserve, and the size of that log.
func prefilled(t *testing.T) (*securefile.Dir, string, int64) {
	t.Helper()
	d, p := newDir(t)
	_, _, size := writeChain(t, logPath(p), 20, bigRecord)
	if size <= ReserveBytes+1 {
		t.Fatal("test bug: the log is not above the reserve")
	}
	return d, p, size
}

// appendedSize is how many bytes r takes at the end of the prefilled log.
func appendedSize(t *testing.T, r Record) int64 {
	t.Helper()
	d, _, size := prefilled(t)
	w, _ := openW(t, d, Options{})
	defer w.Close()
	if _, err := w.Append(r); err != nil {
		t.Fatal(err)
	}
	return w.Size() - size
}

func TestTerminalRecordUpperBoundAndRetry(t *testing.T) {
	r := sample(1)[0]
	r.Kind = DaemonError
	exact := appendedSize(t, r)
	// The log is past its ordinary limit: a terminal record fits up to
	// MaxSize exactly.
	d, p, size := prefilled(t)
	w, _ := openW(t, d, Options{MaxSize: size + exact - 1})
	before := readLog(t, p)
	if _, err := w.Append(r); !errors.Is(err, ErrFull) {
		t.Fatalf("one byte over MaxSize: %v", err)
	}
	if !bytes.Equal(before, readLog(t, p)) {
		t.Fatal("the refused record was written")
	}
	w.Close()
	w2, _ := openW(t, d, Options{MaxSize: size + exact})
	if _, err := w2.Append(r); err != nil {
		t.Fatalf("exactly MaxSize: %v", err)
	}
	if w2.Size() != w2.MaxSize() {
		t.Fatalf("size %d, want %d", w2.Size(), w2.MaxSize())
	}
	w2.Close()
	// A refused terminal record does not use up the allowance.
	small := r
	small.Summary = ""
	smallLen := appendedSize(t, small)
	if smallLen >= exact {
		t.Fatal("test bug: the small record is not smaller")
	}
	d3, _, size3 := prefilled(t)
	w3, _ := openW(t, d3, Options{MaxSize: size3 + smallLen})
	if _, err := w3.Append(r); !errors.Is(err, ErrFull) {
		t.Fatalf("too big: %v", err)
	}
	if _, err := w3.Append(small); err != nil {
		t.Fatalf("smaller terminal record after a refused one: %v", err)
	}
}

// The terminal allowance belongs to the first terminal record that needs the
// reserve. A terminal-kind record that still fits below the ordinary limit
// has not used it, however early it came, and neither has one that ends
// exactly on the limit.
func TestTerminalAllowanceIsUsedUpByTheReserveOnly(t *testing.T) {
	r := sample(1)[0]
	lineLen := lineLenOf(t, r)
	term := r
	term.Kind = DaemonError
	for _, c := range []struct {
		name string
		// ordinary is the ordinary limit in lines; extra is added to it in
		// bytes.
		ordinary int64
		extra    int64
		// before is how many ordinary records precede the first terminal
		// one.
		before int
		// wantFirstUsesReserve: the first terminal record ends above the
		// ordinary limit, so a second one is refused at the full log.
		wantFirstUsesReserve bool
	}{
		{"far below the limit", 3, 10, 0, false},
		{"ends one byte below the limit", 3, 1, 2, false},
		{"ends exactly on the limit", 3, 0, 2, false},
		{"ends one byte above the limit", 3, -1, 2, true},
		{"ends well above the limit", 2, 0, 2, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, _ := newDir(t)
			w, _ := openW(t, d, Options{MaxSize: sizedFor(c.ordinary*lineLen + c.extra)})
			for i := 0; i < c.before; i++ {
				if _, err := w.Append(r); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := w.Append(term); err != nil {
				t.Fatalf("first terminal record: %v", err)
			}
			// Fill the log up to its ordinary limit.
			for {
				if _, err := w.Append(r); err != nil {
					if !errors.Is(err, ErrFull) {
						t.Fatal(err)
					}
					break
				}
			}
			inReserve := w.Size() > w.MaxSize()-ReserveBytes
			if inReserve != c.wantFirstUsesReserve {
				t.Fatalf("test bug: log in the reserve is %t, want %t", inReserve, c.wantFirstUsesReserve)
			}
			_, err := w.Append(term)
			if c.wantFirstUsesReserve {
				if !errors.Is(err, ErrFull) {
					t.Fatalf("second terminal record after one that used the reserve: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("terminal record at the full log: %v", err)
			}
			if _, err := w.Append(term); !errors.Is(err, ErrFull) {
				t.Fatalf("third terminal record: %v", err)
			}
		})
	}
}

func TestMaxSizeOption(t *testing.T) {
	d, _ := newDir(t)
	w, _ := openW(t, d, Options{})
	if w.MaxSize() != DefaultMaxSize || DefaultMaxSize != 256<<20 {
		t.Fatalf("zero MaxSize: %d", w.MaxSize())
	}
	w.Close()
	w2, _ := openW(t, d, Options{MaxSize: 123456})
	if w2.MaxSize() != 123456 {
		t.Fatalf("explicit MaxSize: %d", w2.MaxSize())
	}
	w2.Close()
}

// A MaxSize that is set must leave room for ordinary records above the
// reserve: zero is the default, ReserveBytes+1 is the smallest valid value,
// everything at or below ReserveBytes (a negative one too) is refused, and a
// refusal leaves nothing behind.
func TestMaxSizeMustBeAboveTheReserve(t *testing.T) {
	for _, c := range []struct {
		name string
		max  int64
		ok   bool
	}{
		{"negative", -1, false},
		{"one", 1, false},
		{"one below the reserve", ReserveBytes - 1, false},
		{"the reserve", ReserveBytes, false},
		{"one above the reserve", ReserveBytes + 1, true},
		{"default", 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, p := newDir(t)
			w, _, err := Open(d, Options{MaxSize: c.max})
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				w.Close()
				return
			}
			if !errors.Is(err, ErrInvalidSize) || w != nil {
				t.Fatalf("got %v", err)
			}
			if _, serr := os.Stat(logPath(p)); !os.IsNotExist(serr) {
				t.Fatalf("the refused Open left the log behind: %v", serr)
			}
		})
	}
	// The refusal also holds for a log that exists.
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 2)
	w.Close()
	before := readLog(t, p)
	if _, _, err := Open(d, Options{MaxSize: ReserveBytes}); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("existing log: %v", err)
	}
	if !bytes.Equal(before, readLog(t, p)) {
		t.Fatal("the log changed")
	}
}

func TestClockOption(t *testing.T) {
	// The clock is used for the recovery record only; unset means time.Now.
	d, p := newDir(t)
	appendRaw(t, p, []byte("torn"))
	before := time.Now()
	w, rec, err := Open(d, Options{})
	if err != nil || rec == nil {
		t.Fatalf("%v %v", rec, err)
	}
	w.Close()
	var last Record
	_ = Show(bytes.NewReader(readLog(t, p)), Filter{}, func(r Record) error { last = r; return nil })
	if last.Time.Before(before.Add(-time.Second)) || last.Time.After(time.Now().Add(time.Second)) {
		t.Fatalf("recovery time %v, now %v", last.Time, time.Now())
	}
}

func TestFsyncAfterEveryAppend(t *testing.T) {
	d, _ := newDir(t)
	var calls atomic.Int32
	o := Options{syncFile: func(f *os.File) error { calls.Add(1); return f.Sync() }}
	w, _ := openW(t, d, o)
	for i := 1; i <= 4; i++ {
		if _, err := w.Append(sample(1)[0]); err != nil {
			t.Fatal(err)
		}
		if int(calls.Load()) != i {
			t.Fatalf("after %d appends the file was synced %d times", i, calls.Load())
		}
	}
	// A refused append does not sync.
	bad := sample(1)[0]
	bad.Kind = ""
	_, _ = w.Append(bad)
	if calls.Load() != 4 {
		t.Fatalf("a refused append synced: %d", calls.Load())
	}
	// The default sync is File.Sync: no hook, still works.
	d2, _ := newDir(t)
	w2, _ := openW(t, d2, Options{})
	if _, err := w2.Append(sample(1)[0]); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRecordIsSynced(t *testing.T) {
	d, p := newDir(t)
	appendRaw(t, p, []byte("torn"))
	var calls atomic.Int32
	w, rec, err := Open(d, Options{syncFile: func(f *os.File) error { calls.Add(1); return f.Sync() }})
	if err != nil || rec == nil {
		t.Fatalf("%v %v", rec, err)
	}
	defer w.Close()
	if calls.Load() != 1 {
		t.Fatalf("synced %d times", calls.Load())
	}
}

func TestWriteAndSyncFailuresAreSticky(t *testing.T) {
	t.Run("sync", func(t *testing.T) {
		d, p := newDir(t)
		boom := errors.New("sync boom")
		fail := false
		w, _ := openW(t, d, Options{syncFile: func(f *os.File) error {
			if fail {
				return boom
			}
			return f.Sync()
		}})
		put(t, w, 1)
		fail = true
		if _, err := w.Append(sample(1)[0]); !errors.Is(err, boom) {
			t.Fatalf("got %v", err)
		}
		fail = false
		if _, err := w.Append(sample(1)[0]); !errors.Is(err, boom) {
			t.Fatalf("writer recovered by itself: %v", err)
		}
		// The failed record may be in the file; a reopen is consistent.
		w.Close()
		mustVerify(t, "after sync failure", readLog(t, p))
	})
	t.Run("write", func(t *testing.T) {
		d, _ := newDir(t)
		w, _ := openW(t, d, Options{})
		put(t, w, 1)
		w.f.Close() // the next write fails
		_, err := w.Append(sample(1)[0])
		if err == nil || errors.Is(err, ErrClosed) {
			t.Fatalf("got %v", err)
		}
		_, err2 := w.Append(sample(1)[0])
		if err2 == nil || err2.Error() != err.Error() {
			t.Fatalf("second error %v, first %v", err2, err)
		}
	})
}

func TestAppendAfterClose(t *testing.T) {
	d, _ := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 1)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := w.Append(sample(1)[0]); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestConcurrentAppends(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	var wg sync.WaitGroup
	seen := make([]Record, 0, 200)
	var mu sync.Mutex
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				r, err := w.Append(sample(1)[0])
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				seen = append(seen, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	res := mustVerify(t, "concurrent", readLog(t, p))
	if res.Count != 200 || len(seen) != 200 {
		t.Fatalf("%+v, %d", res, len(seen))
	}
}

func TestOpenRefusesLinkedLog(t *testing.T) {
	d, p := newDir(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, logPath(p)); err != nil {
		t.Skip(err)
	}
	if _, _, err := Open(d, Options{}); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("got %v", err)
	}
}

// A last record that only lacks its newline is part of the chain: Open ends
// the line and notes it, and the record keeps its place.
func TestWholeRecordWithoutNewlineIsCompleted(t *testing.T) {
	for _, n := range []int{1, 3} {
		d, p := newDir(t)
		recs, lines := chainLines(sample(n))
		content := bytes.TrimSuffix(join(lines), []byte("\n"))
		appendRaw(t, p, content)
		w, rec, err := Open(d, Options{Now: func() time.Time { return t0.Add(time.Hour) }})
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		off := int64(len(content) - len(lines[n-1]))
		if rec == nil || !rec.Completed || rec.Terminated || rec.Seq != uint64(n+1) || rec.Offset != off ||
			rec.Length != int64(len(lines[n-1])) || rec.Hash != sumHex(lines[n-1]) {
			t.Fatalf("n=%d: %+v", n, rec)
		}
		after := readLog(t, p)
		if !bytes.HasPrefix(after, content) {
			t.Fatal("earlier bytes were changed")
		}
		res := mustVerify(t, "completed", after)
		if res.Count != uint64(n+1) || res.TornLines != 0 {
			t.Fatalf("%+v", res)
		}
		var got []Record
		_ = Show(bytes.NewReader(after), Filter{}, func(r Record) error { got = append(got, r); return nil })
		last := got[len(got)-1]
		if got[n-1].Hash != recs[n-1].Hash || last.Kind != AuditRecovered || last.Prev != recs[n-1].Hash ||
			last.Summary != completedSummary(off, uint64(n)) {
			t.Fatalf("n=%d: %+v", n, got)
		}
	}
}

func TestWholeRecordWithoutNewlineAndWrongHashIsCorrupt(t *testing.T) {
	d, p := newDir(t)
	recs, lines := chainLines(sample(2))
	bad := bytes.Replace(lines[1], []byte(recs[1].Hash), []byte(strings.Repeat("c", 64)), 1)
	content := append(join(lines[:1]), bad...)
	appendRaw(t, p, content)
	if _, _, err := Open(d, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v", err)
	}
	if !bytes.Equal(readLog(t, p), content) {
		t.Fatal("the file was changed")
	}
}

// openFDs counts the descriptors of this process, or skips the test where the
// platform has no listing.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skip("no /dev/fd listing: ", err)
	}
	return len(ents)
}

func TestFailedOpenReleasesTheFile(t *testing.T) {
	recs, lines := chainLines(sample(2))
	badHash := bytes.Replace(lines[1], []byte(recs[1].Hash), []byte(strings.Repeat("a", 64)), 1)
	t.Run("corrupt log", func(t *testing.T) {
		d, p := newDir(t)
		appendRaw(t, p, join([][]byte{lines[0], badHash}))
		before := openFDs(t)
		if _, _, err := Open(d, Options{}); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("got %v", err)
		}
		if after := openFDs(t); after != before {
			t.Fatalf("%d descriptors before, %d after a failed Open", before, after)
		}
	})
	t.Run("no room for the recovery record", func(t *testing.T) {
		d, p := newDir(t)
		// A log above the reserve with a torn tail and 5 bytes of room.
		writeChain(t, logPath(p), 20, bigRecord)
		appendRaw(t, p, []byte("torn"))
		before := openFDs(t)
		size := int64(len(readLog(t, p)))
		if _, _, err := Open(d, Options{MaxSize: size + 5}); !errors.Is(err, ErrFull) {
			t.Fatalf("got %v", err)
		}
		if after := openFDs(t); after != before {
			t.Fatalf("%d descriptors before, %d after a failed Open", before, after)
		}
	})
}

func TestCloseReleasesTheFile(t *testing.T) {
	d, _ := newDir(t)
	w, _, err := Open(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	put(t, w, 1)
	open := openFDs(t)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after != open-1 {
		t.Fatalf("%d descriptors before Close, %d after", open, after)
	}
	// A second Close is a no-op and does not close anything else.
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if again := openFDs(t); again != open-1 {
		t.Fatalf("%d descriptors after the second Close", again)
	}
}

func TestCloseReportsTheCloseError(t *testing.T) {
	d, _ := newDir(t)
	w, _, err := Open(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w.f.Close() // the descriptor is gone: closing it again fails
	if err := w.Close(); err == nil {
		t.Fatal("Close hid the error of the file")
	}
}

// Open looks at the end only. A record with a wrong hash in the middle of the
// log is for Verify to find; it must not stop the writer from resuming at the
// intact record behind it.
func TestOpenIgnoresDamageBeforeTheLastIntactRecord(t *testing.T) {
	recs, lines := chainLines(sample(4))
	bad := bytes.Replace(lines[1], []byte(recs[1].Hash), []byte(strings.Repeat("a", 64)), 1)
	d, p := newDir(t)
	appendRaw(t, p, join([][]byte{lines[0], bad, lines[2], lines[3]}))
	w, rec := openW(t, d, Options{})
	if rec != nil || w.seq != 4 || w.prev != recs[3].Hash {
		t.Fatalf("%+v seq %d", rec, w.seq)
	}
	be := mustBreak(t, "damaged middle", readLog(t, p))
	if be.Seq != 2 || be.Reason != ReasonHash {
		t.Fatalf("%+v", be)
	}
}
