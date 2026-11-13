package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// showLog has 12 records: kinds cycle over six, incident ids over three,
// times one minute apart from t0.
func showLog() ([]Record, []byte) {
	recs, lines := chainLines(sample(12))
	return recs, join(lines)
}

func seqs(t *testing.T, log []byte, f Filter) []uint64 {
	t.Helper()
	var out []uint64
	if err := Show(bytes.NewReader(log), f, func(r Record) error { out = append(out, r.Seq); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

func eq(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestShowFilters(t *testing.T) {
	recs, log := showLog()
	// Kinds cycle DaemonStart, IncidentOpen, NotifySent, IncidentAck,
	// IncidentClose, PostureSeen; incident ids inc-0, inc-1, inc-2 repeat.
	at := func(i int) time.Time { return recs[i].Time }
	cases := []struct {
		name string
		f    Filter
		want []uint64
	}{
		{"no filter", Filter{}, []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}},
		{"one kind", Filter{Kinds: []Kind{IncidentOpen}}, []uint64{2, 8}},
		{"two kinds", Filter{Kinds: []Kind{IncidentOpen, PostureSeen}}, []uint64{2, 6, 8, 12}},
		{"kind that never occurs", Filter{Kinds: []Kind{DaemonError}}, nil},
		{"one incident", Filter{IncidentID: "inc-1"}, []uint64{2, 5, 8, 11}},
		{"incident that never occurs", Filter{IncidentID: "inc-9"}, nil},
		{"since only, inclusive", Filter{Since: at(9)}, []uint64{10, 11, 12}},
		{"since between records", Filter{Since: at(9).Add(time.Second)}, []uint64{11, 12}},
		{"until only, exclusive", Filter{Until: at(3)}, []uint64{1, 2, 3}},
		{"until between records", Filter{Until: at(3).Add(time.Second)}, []uint64{1, 2, 3, 4}},
		{"range", Filter{Since: at(2), Until: at(5)}, []uint64{3, 4, 5}},
		{"empty range", Filter{Since: at(5), Until: at(5)}, nil},
		{"kind and incident", Filter{Kinds: []Kind{IncidentOpen, NotifySent}, IncidentID: "inc-1"}, []uint64{2, 8}},
		{"kind and range", Filter{Kinds: []Kind{IncidentOpen}, Since: at(3)}, []uint64{8}},
		{"incident and range", Filter{IncidentID: "inc-1", Until: at(6)}, []uint64{2, 5}},
		{"all three", Filter{Kinds: []Kind{IncidentOpen}, IncidentID: "inc-1", Since: at(1), Until: at(7)}, []uint64{2}},
		{"kind matches, incident does not", Filter{Kinds: []Kind{IncidentOpen}, IncidentID: "inc-0"}, nil},
		{"incident matches, range does not", Filter{IncidentID: "inc-1", Since: at(11).Add(time.Hour)}, nil},
	}
	for _, c := range cases {
		if got := seqs(t, log, c.f); !eq(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestShowDeliversWholeRecordsInOrder(t *testing.T) {
	recs, log := showLog()
	var got []Record
	if err := Show(bytes.NewReader(log), Filter{}, func(r Record) error { got = append(got, r); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(recs) {
		t.Fatalf("%d records", len(got))
	}
	for i := range recs {
		g, w := got[i], recs[i]
		if g.Seq != w.Seq || !g.Time.Equal(w.Time) || g.Kind != w.Kind || g.IncidentID != w.IncidentID ||
			g.Fingerprint != w.Fingerprint || g.Summary != w.Summary || g.Prev != w.Prev || g.Hash != w.Hash {
			t.Fatalf("record %d: got %+v want %+v", i, g, w)
		}
	}
}

func TestShowStopsAtTheFirstBreak(t *testing.T) {
	recs, lines := chainLines(sample(8))
	lines[4] = bytes.Replace(lines[4], []byte(recs[4].Hash), []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), 1)
	var delivered []uint64
	err := Show(bytes.NewReader(join(lines)), Filter{}, func(r Record) error { delivered = append(delivered, r.Seq); return nil })
	var be *BreakError
	if !errors.As(err, &be) || be.Seq != 5 || be.Reason != ReasonHash {
		t.Fatalf("got %v", err)
	}
	if !eq(delivered, []uint64{1, 2, 3, 4}) {
		t.Fatalf("delivered %v", delivered)
	}
	// Records after the break are not shown even if they would match.
	delivered = nil
	_ = Show(bytes.NewReader(join(lines)), Filter{Since: recs[6].Time}, func(r Record) error { delivered = append(delivered, r.Seq); return nil })
	if len(delivered) != 0 {
		t.Fatalf("delivered %v after a break", delivered)
	}
}

func TestShowReturnsCallbackError(t *testing.T) {
	_, log := showLog()
	stop := errors.New("enough")
	n := 0
	err := Show(bytes.NewReader(log), Filter{}, func(r Record) error {
		n++
		if n == 3 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 3 {
		t.Fatalf("err %v after %d records", err, n)
	}
	// The callback is not called for records the filter drops, so its error
	// can only come from a match.
	n = 0
	err = Show(bytes.NewReader(log), Filter{IncidentID: "none"}, func(Record) error { n++; return stop })
	if err != nil || n != 0 {
		t.Fatalf("err %v, %d calls", err, n)
	}
}

func TestShowAcceptsAnAccountedTornRegion(t *testing.T) {
	log, _ := recoveredLog(t, 3, []byte("torn\nlines"))
	var kinds []Kind
	if err := Show(bytes.NewReader(log), Filter{}, func(r Record) error { kinds = append(kinds, r.Kind); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 4 || kinds[3] != AuditRecovered {
		t.Fatalf("%v", kinds)
	}
}

func TestFilterMatchEmptyKindsListMeansAll(t *testing.T) {
	r := goldenRecord()
	for _, f := range []Filter{{}, {Kinds: []Kind{}}, {Kinds: []Kind{r.Kind}}} {
		if !f.Match(r) {
			t.Errorf("%+v does not match", f)
		}
	}
	if (Filter{Kinds: []Kind{DaemonStop}}).Match(r) {
		t.Error("other kind matched")
	}
}

// The zero Filter matches every record, whatever its time, and an open side
// of the time range leaves that side open.
func TestFilterMatchOpenTimeRange(t *testing.T) {
	early := goldenRecord()
	early.Time = time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC)
	late := goldenRecord()
	late.Time = time.Date(10000, 6, 1, 0, 0, 0, 0, time.UTC)
	for _, r := range []Record{early, late, {}} {
		if !(Filter{}).Match(r) {
			t.Errorf("zero filter does not match time %v", r.Time)
		}
		if !(Filter{Since: t0}).Match(late) || !(Filter{Until: t0.Add(time.Hour)}).Match(early) {
			t.Error("one open side")
		}
	}
	if (Filter{Since: t0}).Match(early) || (Filter{Until: t0}).Match(late) {
		t.Error("closed side ignored")
	}
}
