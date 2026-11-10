package state

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func TestCheckConsistencyRejectsEachInconsistency(t *testing.T) {
	// Every case starts from a valid capped state of 106 items (99 listed) and
	// breaks one thing.
	cases := []struct {
		name string
		mut  func(c *Check)
		want string
	}{
		{"a listed item that is not in the set", func(c *Check) {
			c.Items[0].Key = result.SubjectKey("not in the set")
		}, "the item is not in the key set"},
		{"more items listed than the total", func(c *Check) {
			// all in the set, but listed more often than the set holds
			c.Total, c.Keys = 1, c.Keys[:1]
			c.Digest = result.DigestOfKeys(c.Keys)
			c.Items = []Item{{Key: c.Keys[0]}, {Key: c.Keys[0]}}
		}, "2 items listed for a total of 1"},
		{"a digest that does not match the keys", func(c *Check) {
			c.Digest = result.DigestOfKeys([]string{result.SubjectKey("other")})
		}, "the digest does not match the keys"},
		{"a digest that is not hash-sized", func(c *Check) { c.Digest = "abc" }, "invalid digest"},
		{"unsorted keys", func(c *Check) {
			c.Keys[3], c.Keys[4] = c.Keys[4], c.Keys[3]
		}, "keys are not sorted and unique"},
		{"duplicate keys", func(c *Check) {
			c.Keys[4] = c.Keys[3]
		}, "keys are not sorted and unique"},
		{"a key that is not hex", func(c *Check) { c.Keys[0] = "xyz" }, "invalid key"},
		{"fewer keys than the total", func(c *Check) { c.Keys = c.Keys[:50] }, "keys for a total of"},
		{"a total of zero with a digest", func(c *Check) { c.Total = 0 }, "invalid total"},
		{"keys listed above the limit", func(c *Check) { c.Total = result.MaxKeys + 1 }, "more than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := cappedState(106)
			if err := CheckConsistency(st); err != nil {
				t.Fatalf("the starting state is not consistent: %v", err)
			}
			tc.mut(&st.Checks[0])
			err := CheckConsistency(st)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), `check "a.b"`) {
				t.Errorf("error %q does not name the check", err)
			}
			for _, it := range st.Checks[0].Items {
				if it.Subject != "" && strings.Contains(err.Error(), it.Subject) {
					t.Errorf("error %q names a subject", err)
				}
			}
		})
	}
}

// Every check of the state is examined, not only the first: the broken one is
// second of two, last of three, and in the middle.
func TestCheckConsistencyExaminesEveryCheck(t *testing.T) {
	build := func(n int) *State {
		var rs []result.Result
		for i := 0; i < n; i++ {
			r := capped(106 + i)
			r.CheckID = fmt.Sprintf("c%d", i)
			rs = append(rs, r)
		}
		return FromResults(rs, t0, nil)
	}
	for _, tc := range []struct{ n, broken int }{{2, 1}, {3, 2}, {3, 1}} {
		st := build(tc.n)
		if err := CheckConsistency(st); err != nil {
			t.Fatalf("n=%d: the starting state is not consistent: %v", tc.n, err)
		}
		st.Checks[tc.broken].Items[0].Key = result.SubjectKey("not in the set")
		err := CheckConsistency(st)
		want := fmt.Sprintf("check %q", fmt.Sprintf("c%d", tc.broken))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("n=%d broken=%d: error = %v, want one naming %s", tc.n, tc.broken, err, want)
		}
	}
	// the items-vs-total rule too, on a later check
	st := build(2)
	c := &st.Checks[1]
	c.Total, c.Keys = 1, c.Keys[:1]
	c.Digest = result.DigestOfKeys(c.Keys)
	c.Items = []Item{{Key: c.Keys[0]}, {Key: c.Keys[0]}}
	if err := CheckConsistency(st); err == nil || !strings.Contains(err.Error(), "items listed for a total of") {
		t.Errorf("second check listing more items than its total: %v", err)
	}
}

// A state that is fine for a run but that the checks for a foreign file would
// refuse is not an inconsistency of the run.
func TestCheckConsistencyDoesNotApplyTheLimitsOfAFile(t *testing.T) {
	if err := CheckConsistency(&State{SchemaVersion: SchemaVersion}); err != nil {
		t.Errorf("a state without checks: %v", err)
	}
	long := strings.Repeat("i", maxIDLen+1)
	st := FromResults([]result.Result{{CheckID: long, Kind: long, Status: result.Pass, Severity: result.Low}}, t0, nil)
	if err := CheckConsistency(st); err != nil {
		t.Errorf("a long id: %v", err)
	}
	if validate(st) == nil {
		t.Error("the file check accepts a long id, the premise of this test is gone")
	}
	var ev []result.Evidence
	for i := 0; i < maxItems+50; i++ {
		ev = append(ev, result.Evidence{Subject: fmt.Sprintf("s-%d", i)})
	}
	st = FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: ev}}, t0, nil)
	if err := CheckConsistency(st); err != nil {
		t.Errorf("an uncut list above the file limit: %v", err)
	}
}

// A state without a set (an uncut list) has nothing to contradict.
func TestCheckConsistencyAcceptsUncappedChecks(t *testing.T) {
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: items(5)}}, t0, nil)
	if err := CheckConsistency(st); err != nil {
		t.Error(err)
	}
	// A total or keys without a digest do not make a set.
	st.Checks[0].Total = 3
	if err := CheckConsistency(st); err == nil {
		t.Error("a total without a digest was accepted")
	}
}

// Whatever FromResults builds from results of any shape passes the check: it
// can never fire on correct input. The shapes follow the set-model property
// test of the probes: lists below, at and above the cut, unsorted, with
// repeated subjects, results that share a check id (capped with capped, capped
// with uncut), sets too large to list and lists that are cut here.
func TestFromResultsOutputAlwaysPassesTheConsistencyCheck(t *testing.T) {
	seeds := 150
	if testing.Short() {
		seeds = 30
	}
	if s := os.Getenv("KEEPWATCH_SEED"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		runConsistencyProperty(t, int64(v))
		return
	}
	for seed := 1; seed <= seeds; seed++ {
		runConsistencyProperty(t, int64(seed))
	}
}

func runConsistencyProperty(t *testing.T, seed int64) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	subjects := func(n int) []result.Evidence {
		ev := make([]result.Evidence, n)
		for i := range ev {
			// a small alphabet makes repeated subjects likely
			ev[i] = result.Evidence{Subject: fmt.Sprintf("s%04d", rng.Intn(n+n/3+1)), Excepted: rng.Intn(4) == 0}
		}
		return ev
	}
	// cut lists the way limitEvidence does: sorted, 99 items and a marker.
	cut := func(ev []result.Evidence) result.Result {
		r := result.Result{Status: result.Fail, Severity: result.Low}
		if len(ev) <= 100 {
			r.Evidence = ev
			return r
		}
		sort.SliceStable(ev, func(i, j int) bool { return ev[i].Subject < ev[j].Subject })
		r.Set = result.NewEvidenceSet(ev)
		r.Evidence = append(append([]result.Evidence(nil), ev[:99]...), result.Evidence{Subject: "(more not shown)"})
		return r
	}
	sizes := []int{0, 1, 5, 99, 100, 101, 250, 1200, result.MaxKeys - 1, result.MaxKeys, result.MaxKeys + 1, result.MaxKeys + 400}
	var rs []result.Result
	for n := 1 + rng.Intn(4); n > 0; n-- {
		size := sizes[rng.Intn(len(sizes))]
		if size > 1500 && seed%10 != 0 {
			size = 1200 // the sets too large to list are slow under the race detector: one seed in ten
		}
		r := cut(subjects(size))
		r.CheckID = fmt.Sprintf("c%d", rng.Intn(3)) // ids repeat: results merge
		r.Kind = "k"
		rs = append(rs, r)
	}
	st := FromResults(rs, t0, nil)
	if err := CheckConsistency(st); err != nil {
		t.Fatalf("seed %d (replay with KEEPWATCH_SEED=%d): %v", seed, seed, err)
	}
}

// A state file with data after the JSON document is not used. The schema
// version is read first, and that read already refuses trailing data, so the
// document is never decoded a second time.
func TestParseRefusesDataAfterTheDocument(t *testing.T) {
	good, err := Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(good); err != nil {
		t.Fatalf("the starting file is not valid: %v", err)
	}
	for name, tail := range map[string]string{"an object": "{}", "text": " x", "a second document": string(good)} {
		_, err := parse(append(append([]byte(nil), good...), tail...))
		if err == nil || !strings.Contains(err.Error(), "not a valid state file") {
			t.Errorf("%s after the document: error = %v", name, err)
		}
	}
}
