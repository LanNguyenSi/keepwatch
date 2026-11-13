package audit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

var quiet = Options{
	Now:      func() time.Time { return t0.Add(time.Hour) },
	syncFile: func(*os.File) error { return nil },
}

// bigRecord is a record with a long Summary, so a large log needs few
// records.
func bigRecord(i int) Record {
	r := sample(1)[0]
	r.Time = t0.Add(time.Duration(i) * time.Second)
	r.Summary = strings.Repeat(fmt.Sprintf("%d ", i%10), MaxSummary/2)
	return r
}

// writeChain writes n records from gen to the log file with constant memory
// and returns the Seq and Hash of the last one and the size of the file.
func writeChain(t *testing.T, path string, n int, gen func(int) Record) (uint64, string, int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	prev := Genesis
	var size int64
	var seq uint64
	for i := 0; i < n; i++ {
		r := gen(i)
		seq++
		r.Seq = seq
		r.Prev = prev
		r.Hash = hashOf(r)
		prev = r.Hash
		line := append(encodeLine(r), '\n')
		if _, err := bw.Write(line); err != nil {
			t.Fatal(err)
		}
		size += int64(len(line))
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	return seq, prev, size
}

// The log is not read whole: Open of a log of tens of MiB allocates a few
// MiB at most and resumes at the right record.
func TestOpenOfALargeLogReadsOnlyItsEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a 72 MiB log; the normal run (CI) does not skip it")
	}
	const logBytes = 72 << 20
	for _, tail := range []string{"clean", "torn fragment"} {
		t.Run(tail, func(t *testing.T) {
			d, p := newDir(t)
			_, probe := chainLines([]Record{bigRecord(0)})
			n := logBytes/(len(probe[0])+1) + 1
			seq, last, size := writeChain(t, logPath(p), n, bigRecord)
			if size < 64<<20 {
				t.Fatalf("test bug: only %d bytes", size)
			}
			if tail == "torn fragment" {
				appendRaw(t, p, []byte(`{"seq":99,"time":"2026-01`))
			}

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			w, rec, err := Open(d, quiet)
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
				t.Fatalf("Open of a %d MiB log allocated %d KiB", size>>20, alloc>>10)
			}
			if tail == "clean" {
				if rec != nil || w.seq != seq || w.prev != last {
					t.Fatalf("%+v seq %d prev %s, want seq %d prev %s", rec, w.seq, w.prev, seq, last)
				}
			} else {
				if rec == nil || rec.Offset != size || rec.Seq != seq+1 || rec.Terminated {
					t.Fatalf("%+v", rec)
				}
				if w.seq != seq+1 {
					t.Fatalf("seq %d", w.seq)
				}
			}
			next, err := w.Append(sample(1)[0])
			if err != nil || next.Seq != w.seq {
				t.Fatalf("%+v %v", next, err)
			}
			if tail == "clean" && (next.Seq != seq+1 || next.Prev != last) {
				t.Fatalf("%+v", next)
			}
		})
	}
}

// worstLine is the longest line a record can have (see
// TestWorstCaseLineFitsTheLineCap).
func worstRecord() Record {
	return Record{
		Time: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		Kind: Kind(strings.Repeat("\x01", MaxKind)), IncidentID: strings.Repeat("\x02", MaxIncidentID),
		Fingerprint: strings.Repeat("\x03", MaxFingerprint), Summary: strings.Repeat("\x04", MaxSummary),
	}
}

// The window Open reads reaches back far enough: the longest intact line,
// followed by the longest region Open accepts, with the log longer than the
// window so that the window starts in the middle of a line.
func TestWindowFindsTheLongestLineBeforeTheLongestRegion(t *testing.T) {
	for _, filler := range []int{0, 3, 40, 41, 42} {
		for _, regionLen := range []int{0, 1, MaxLineBytes, MaxTornBytes - 1, MaxTornBytes} {
			t.Run(fmt.Sprintf("%d fillers, %d torn bytes", filler, regionLen), func(t *testing.T) {
				d, p := newDir(t)
				seq, last, _ := writeChain(t, logPath(p), filler+1, func(i int) Record {
					if i == filler {
						return worstRecord()
					}
					return bigRecord(i)
				})
				region := bytes.Repeat([]byte("j"), regionLen)
				appendRaw(t, p, region)
				w, rec, err := Open(d, quiet)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				if regionLen == 0 {
					if rec != nil || w.seq != seq || w.prev != last {
						t.Fatalf("%+v seq %d, want %d", rec, w.seq, seq)
					}
					return
				}
				if rec == nil || rec.Length != int64(regionLen) || w.seq != seq+1 {
					t.Fatalf("%+v seq %d", rec, w.seq)
				}
				res := mustVerify(t, "after open", readLog(t, p))
				if res.Count != seq+1 || res.TornLines != 1 {
					t.Fatalf("%+v", res)
				}
			})
		}
	}
}

func TestRegionBeyondTheBoundIsCorruptWhereverTheLogStarts(t *testing.T) {
	for _, filler := range []int{0, 1, 60} {
		d, p := newDir(t)
		writeChain(t, logPath(p), filler, bigRecord)
		appendRaw(t, p, bytes.Repeat([]byte("j"), MaxTornBytes+1))
		before := readLog(t, p)
		if w, _, err := Open(d, quiet); !errors.Is(err, ErrCorrupt) || w != nil {
			t.Fatalf("%d fillers: %v", filler, err)
		}
		if !bytes.Equal(before, readLog(t, p)) {
			t.Fatal("the file was changed")
		}
	}
}

// A log longer than the window whose end has no intact record (and no line
// break) is refused, not resumed from nothing.
func TestOpenRefusesALongLogWithoutAnIntactEnd(t *testing.T) {
	d, p := newDir(t)
	writeChain(t, logPath(p), 60, bigRecord)
	appendRaw(t, p, bytes.Repeat([]byte("j"), tailWindow+10))
	if w, _, err := Open(d, quiet); !errors.Is(err, ErrCorrupt) || w != nil {
		t.Fatalf("no line break in the window: %v", err)
	}
	// Line breaks, but no intact record: junk lines for the whole window.
	d2, p2 := newDir(t)
	writeChain(t, logPath(p2), 60, bigRecord)
	appendRaw(t, p2, bytes.Repeat([]byte("junk\n"), tailWindow/5+10))
	if w, _, err := Open(d2, quiet); !errors.Is(err, ErrCorrupt) || w != nil {
		t.Fatalf("junk lines: %v", err)
	}
}

// Whatever the tail, Open and Verify agree: the file after Open verifies, the
// writer continues the chain, and nothing before the tail changed.
func TestOpenAgreesWithVerifyOnRandomTails(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	d, p := newDir(t)
	for i := 0; i < 80; i++ {
		os.Remove(logPath(p))
		filler := rng.Intn(60)
		seq, _, _ := writeChain(t, logPath(p), filler, func(i int) Record {
			r := bigRecord(i)
			r.Summary = r.Summary[:rng.Intn(len(r.Summary))]
			return r
		})
		var tail []byte
		switch rng.Intn(4) {
		case 0:
		case 1:
			tail = bytes.Repeat([]byte{byte('a' + rng.Intn(26))}, 1+rng.Intn(MaxTornBytes))
		case 2:
			for l := 0; l < 1+rng.Intn(8); l++ {
				tail = append(tail, bytes.Repeat([]byte("q"), rng.Intn(3000))...)
				tail = append(tail, '\n')
			}
		case 3:
			_, ls := chainLines(sample(1))
			tail = ls[0][:1+rng.Intn(len(ls[0])-1)]
		}
		appendRaw(t, p, tail)
		before := readLog(t, p)
		w, rec, err := Open(d, quiet)
		if err != nil {
			t.Fatalf("round %d (%d fillers, %d tail bytes): %v", i, filler, len(tail), err)
		}
		want := seq
		if len(tail) > 0 {
			want = seq + 1
		}
		if (rec != nil) != (len(tail) > 0) || w.seq != want {
			t.Fatalf("round %d: %+v seq %d, want %d", i, rec, w.seq, want)
		}
		w.Close()
		after := readLog(t, p)
		if !bytes.HasPrefix(after, before) {
			t.Fatalf("round %d: earlier bytes were changed", i)
		}
		if res := mustVerify(t, fmt.Sprintf("round %d", i), after); res.Count != want {
			t.Fatalf("round %d: %+v", i, res)
		}
	}
}

// A crash in the middle of the recovery write leaves the first k bytes of
// the newline and the recovery record after the torn fragment. Whatever k is,
// the next Open recovers and the log verifies.
func TestInterruptedRecoveryIsRecoverable(t *testing.T) {
	_, lines := chainLines(sample(3))
	base := join(lines[:2])
	d, p := newDir(t)

	write := func(b ...[]byte) {
		t.Helper()
		if err := os.WriteFile(logPath(p), bytes.Join(b, nil), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// recoverFrom opens the log as it is, closes it again and returns what
	// Open appended.
	recoverFrom := func(content []byte) ([]byte, *Recovery) {
		t.Helper()
		write(content)
		w, rec, err := Open(d, quiet)
		if err != nil {
			t.Fatalf("%d bytes: %v", len(content), err)
		}
		w.Close()
		after := readLog(t, p)
		if !bytes.HasPrefix(after, content) {
			t.Fatal("earlier bytes were changed")
		}
		return after[len(content):], rec
	}

	fragments := map[string][]byte{
		"fragment":                   lines[2][:len(lines[2])/2],
		"fragment with newline":      append(append([]byte(nil), lines[2][:len(lines[2])/2]...), '\n'),
		"two fragments":              append(append([]byte(nil), lines[2][:40]...), append([]byte("\n"), lines[2][:50]...)...),
		"bytes that are not a start": []byte("\x00\x00\x00"),
	}
	for name, frag := range fragments {
		t.Run(name, func(t *testing.T) {
			content := append(append([]byte(nil), base...), frag...)
			recovery, first := recoverFrom(content)
			if first == nil || first.Offset != int64(len(base)) || first.Length != int64(len(frag)) {
				t.Fatalf("%+v", first)
			}
			for k := 0; k <= len(recovery); k++ {
				cut := append(append([]byte(nil), content...), recovery[:k]...)
				added, rec := recoverFrom(cut)
				switch k {
				case len(recovery):
					// The write was complete: nothing to recover.
					if rec != nil || len(added) != 0 {
						t.Fatalf("k=%d: %+v %q", k, rec, added)
					}
				case len(recovery) - 1:
					// The record is whole, only its newline is missing.
					if rec == nil || !rec.Completed || rec.Terminated {
						t.Fatalf("k=%d: %+v", k, rec)
					}
				default:
					region := cut[len(base):]
					if rec == nil || rec.Completed || rec.Offset != int64(len(base)) || rec.Length != int64(len(region)) ||
						rec.Hash != sumHex(region) || rec.Terminated != bytes.HasSuffix(region, []byte("\n")) {
						t.Fatalf("k=%d: %+v", k, rec)
					}
				}
				res := mustVerify(t, fmt.Sprintf("k=%d", k), readLog(t, p))
				if res.Count < 3 {
					t.Fatalf("k=%d: %+v", k, res)
				}
				// The log goes on and a reopen finds nothing to do.
				w, rec2, err := Open(d, quiet)
				if err != nil || rec2 != nil {
					t.Fatalf("k=%d: reopen %+v %v", k, rec2, err)
				}
				if _, err := w.Append(sample(1)[0]); err != nil {
					t.Fatal(err)
				}
				w.Close()
				mustVerify(t, fmt.Sprintf("k=%d continued", k), readLog(t, p))
			}

			// The recovery of the recovery can be interrupted as well.
			for _, k1 := range []int{1, 2, len(recovery) / 2, len(recovery) - 2} {
				cut1 := append(append([]byte(nil), content...), recovery[:k1]...)
				second, _ := recoverFrom(cut1)
				for _, k2 := range []int{0, 1, 2, len(second) / 2, len(second) - 1, len(second)} {
					cut2 := append(append([]byte(nil), cut1...), second[:k2]...)
					recoverFrom(cut2)
					mustVerify(t, fmt.Sprintf("k1=%d k2=%d", k1, k2), readLog(t, p))
				}
			}
		})
	}
}

// Open with the recovery interrupted, in the way a real crash does it: the
// writer's own write is cut short.
func TestRecoveryWriteCutShortByAFailingFile(t *testing.T) {
	_, lines := chainLines(sample(2))
	d, p := newDir(t)
	if err := os.WriteFile(logPath(p), append(join(lines[:1]), lines[1][:30]...), 0o600); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("sync boom")
	_, _, err := Open(d, Options{Now: quiet.Now, syncFile: func(*os.File) error { return boom }})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	// The record was written, only the sync failed: it is in the file, and
	// the next Open finds an intact end.
	w, rec, err := Open(d, quiet)
	if err != nil || rec != nil {
		t.Fatalf("%+v %v", rec, err)
	}
	defer w.Close()
	if res := mustVerify(t, "after failed sync", readLog(t, p)); res.Count != 2 || res.TornLines != 1 {
		t.Fatalf("%+v", res)
	}
}

// In a log longer than the window, a last record that only lacks its newline
// is completed and located by its offset in the file, not in the window.
func TestCompletedRecordInALongLog(t *testing.T) {
	d, p := newDir(t)
	seq, last, size := writeChain(t, logPath(p), 60, bigRecord)
	if size < tailWindow+2*MaxLineBytes {
		t.Fatalf("test bug: %d bytes", size)
	}
	if err := os.Truncate(logPath(p), size-1); err != nil {
		t.Fatal(err)
	}
	w, rec, err := Open(d, quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if rec == nil || !rec.Completed || rec.Terminated || rec.Offset >= size || rec.Offset < size-int64(MaxLineBytes+1) ||
		rec.Offset+rec.Length != size-1 || rec.Seq != seq+1 {
		t.Fatalf("%+v (size %d)", rec, size)
	}
	if w.prev == last {
		t.Fatal("the recovery record was not chained")
	}
	res := mustVerify(t, "completed", readLog(t, p))
	if res.Count != seq+1 {
		t.Fatalf("%+v", res)
	}
}
