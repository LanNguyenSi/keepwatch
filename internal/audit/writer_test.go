package audit

import (
	"bytes"
	"errors"
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
	partial := lines[2][:len(lines[2])/2] // half of a record, as a crash leaves it
	cases := []struct {
		name       string
		content    []byte
		tornAt     int // offset of the torn line
		tornBytes  []byte
		wantSeq    uint64 // seq of the recovery record
		addNewline bool
	}{
		{"unterminated fragment", append(join(lines[:2]), partial...), len(join(lines[:2])), partial, 3, true},
		{"invalid line with newline", append(join(lines[:2]), append(append([]byte(nil), partial...), '\n')...), len(join(lines[:2])), partial, 3, false},
		{"zero filled tail", append(join(lines[:2]), make([]byte, 40)...), len(join(lines[:2])), make([]byte, 40), 3, true},
		{"empty line at the end", append(append([]byte(nil), good...), '\n'), len(good), nil, 4, false},
		{"fragment only", partial, 0, partial, 1, true},
		{"invalid line only", append(append([]byte(nil), partial...), '\n'), 0, partial, 1, false},
		{"non canonical last line", append(join(lines[:2]), append([]byte(" "+string(lines[2])), '\n')...), len(join(lines[:2])), []byte(" " + string(lines[2])), 3, false},
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
			want := Recovery{Offset: int64(c.tornAt), Length: int64(len(c.tornBytes)), Hash: sumHex(c.tornBytes), Seq: c.wantSeq}
			if *rec != want {
				t.Fatalf("recovery %+v, want %+v", *rec, want)
			}
			after := readLog(t, p)
			if !bytes.HasPrefix(after, c.content) {
				t.Fatal("earlier bytes were changed")
			}
			added := after[len(c.content):]
			if c.addNewline != (len(added) > 0 && added[0] == '\n' && bytes.Count(added, []byte("\n")) == 2) {
				t.Errorf("newline handling: added %q", added)
			}
			res := mustVerify(t, "recovered", after)
			if res.TornLines != 1 || res.Count != c.wantSeq {
				t.Fatalf("%+v", res)
			}
			var last Record
			_ = Show(bytes.NewReader(after), Filter{}, func(r Record) error { last = r; return nil })
			if last.Kind != AuditRecovered || last.Seq != c.wantSeq || !last.Time.Equal(now) ||
				last.Summary != tornSummary(want.Offset, want.Length, want.Hash) || last.IncidentID != "" || last.Fingerprint != "" {
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

func TestTornTailLargerThanLineCap(t *testing.T) {
	d, p := newDir(t)
	w, _ := openW(t, d, Options{})
	put(t, w, 2)
	w.Close()
	junk := bytes.Repeat([]byte("j"), 4*MaxLineBytes+3)
	appendRaw(t, p, junk)
	_, rec := openW(t, d, Options{})
	if rec == nil || rec.Length != int64(len(junk)) || rec.Hash != sumHex(junk) {
		t.Fatalf("%+v", rec)
	}
	res := mustVerify(t, "large torn", readLog(t, p))
	if res.TornLines != 1 || res.Count != 3 {
		t.Fatalf("%+v", res)
	}
}

func TestOpenRefusesDamageThatIsNotATornWrite(t *testing.T) {
	recs, lines := chainLines(sample(3))
	badHash := func(l []byte, r Record) []byte {
		return bytes.Replace(l, []byte(r.Hash), []byte(strings.Repeat("a", 64)), 1)
	}
	cases := map[string][]byte{
		"last record with a wrong hash":     join([][]byte{lines[0], lines[1], badHash(lines[2], recs[2])}),
		"only record with a wrong hash":     join([][]byte{badHash(lines[0], recs[0])}),
		"bad record before a torn fragment": append(join([][]byte{lines[0], badHash(lines[1], recs[1])}), lines[2][:20]...),
		"garbage before a torn fragment":    append(join([][]byte{lines[0], []byte("junk")}), lines[2][:20]...),
		"garbage before an invalid line":    join([][]byte{lines[0], []byte("junk"), []byte("more junk")}),
		"empty line before a torn fragment": append(join([][]byte{lines[0], {}}), lines[2][:20]...),
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
	// A writer that believes the file has another size than it has.
	x := &Writer{size: 5, max: DefaultMaxSize}
	if _, err := x.resume(d); !errors.Is(err, securefile.ErrChanged) {
		t.Fatalf("got %v", err)
	}
	_ = p
}

func TestSizeLimit(t *testing.T) {
	_, lines := chainLines(sample(3))
	lineLen := int64(len(lines[0]) + 1)
	t.Run("refuses at the limit and leaves the file alone", func(t *testing.T) {
		d, p := newDir(t)
		// room for exactly two records of this size
		w, _ := openW(t, d, Options{MaxSize: 2*lineLen + 20})
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
		// Not a failure of the writer: the refusal stays the same, a smaller
		// record that fits is accepted, and the chain has no hole.
		if _, err := w.Append(sample(3)[2]); !errors.Is(err, ErrFull) {
			t.Fatalf("second try: %v", err)
		}
		mustVerify(t, "at limit", readLog(t, p))
	})
	t.Run("a record that fits exactly is written, one byte less room is not", func(t *testing.T) {
		d, p := newDir(t)
		r := sample(1)[0]
		_, probe := chainLines([]Record{r})
		exact := int64(len(probe[0]) + 1)
		w, _ := openW(t, d, Options{MaxSize: exact - 1})
		if _, err := w.Append(r); !errors.Is(err, ErrFull) {
			t.Fatalf("one byte short: %v", err)
		}
		w.Close()
		os.Remove(logPath(p))
		w2, _ := openW(t, d, Options{MaxSize: exact})
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
		w, _ := openW(t, d, Options{})
		put(t, w, 3)
		w.Close()
		before := readLog(t, p)
		_, _, err := Open(d, Options{MaxSize: int64(len(before)) - 1})
		if !errors.Is(err, ErrFull) || !errors.Is(err, securefile.ErrTooLarge) {
			t.Fatalf("got %v", err)
		}
		// At the limit exactly, open works and the next append is refused.
		w2, _, err := Open(d, Options{MaxSize: int64(len(before))})
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		if _, err := w2.Append(sample(1)[0]); !errors.Is(err, ErrFull) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("the recovery record needs room too", func(t *testing.T) {
		d, p := newDir(t)
		w, _ := openW(t, d, Options{})
		put(t, w, 2)
		w.Close()
		appendRaw(t, p, []byte(`{"seq":3,`))
		before := readLog(t, p)
		_, _, err := Open(d, Options{MaxSize: int64(len(before)) + 10})
		if !errors.Is(err, ErrFull) {
			t.Fatalf("got %v", err)
		}
		if !bytes.Equal(before, readLog(t, p)) {
			t.Fatal("the file was changed")
		}
	})
}

func TestMaxSizeOption(t *testing.T) {
	d, _ := newDir(t)
	w, _ := openW(t, d, Options{})
	if w.MaxSize() != DefaultMaxSize || DefaultMaxSize != 256<<20 {
		t.Fatalf("zero MaxSize: %d", w.MaxSize())
	}
	w.Close()
	w2, _ := openW(t, d, Options{MaxSize: 12345})
	if w2.MaxSize() != 12345 {
		t.Fatalf("explicit MaxSize: %d", w2.MaxSize())
	}
	w2.Close()
	if _, _, err := Open(d, Options{MaxSize: -1}); !errors.Is(err, securefile.ErrInvalidSize) {
		t.Fatalf("negative MaxSize: %v", err)
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
		if rec == nil || !rec.Completed || rec.Seq != uint64(n+1) || rec.Offset != off ||
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
		appendRaw(t, p, append(join(lines[:1]), "torn"...))
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
