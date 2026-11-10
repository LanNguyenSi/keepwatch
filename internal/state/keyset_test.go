package state

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// roundTrip marshals st and parses it back, as a Save and a Load would.
func roundTrip(t *testing.T, st *State) (*State, error) {
	t.Helper()
	b, err := Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return parse(b)
}

func writeStateFile(t *testing.T, s *Store, dir, content string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cappedState(total int) *State {
	return FromResults([]result.Result{{CheckID: "a.b", Kind: "k", Status: result.Fail, Severity: result.Low, Evidence: capped(total)}}, t0, nil)
}

func TestACappedCheckSurvivesSaveAndLoad(t *testing.T) {
	for _, total := range []int{100, 106, 5000, result.MaxKeys, result.MaxKeys + 1, result.MaxKeys + 500} {
		st := cappedState(total)
		got, err := roundTrip(t, st)
		if err != nil {
			t.Fatalf("total %d: %v", total, err)
		}
		a, b := st.Checks[0], got.Checks[0]
		if a.Total != b.Total || a.Digest != b.Digest || !slices.Equal(a.Keys, b.Keys) || len(a.Items) != len(b.Items) {
			t.Errorf("total %d: the check changed in the round trip", total)
		}
		if (total <= result.MaxKeys) != (len(b.Keys) == total) || (total > result.MaxKeys && b.Keys != nil) {
			t.Errorf("total %d: %d keys kept", total, len(b.Keys))
		}
	}
}

func TestKeySetValidation(t *testing.T) {
	valid := func() *State { return cappedState(130) }
	digestOnly := func() *State { return cappedState(result.MaxKeys + 3) }
	swap := func(keys []string, i, j int) { keys[i], keys[j] = keys[j], keys[i] }
	cases := []struct {
		name string
		base func() *State
		mut  func(c *Check)
		ok   bool
	}{
		{"valid, keys listed", valid, func(c *Check) {}, true},
		{"valid, digest only", digestOnly, func(c *Check) {}, true},
		{"total zero with keys", valid, func(c *Check) { c.Total = 0 }, false},
		{"negative total", valid, func(c *Check) { c.Total = -1 }, false},
		{"total absurd", digestOnly, func(c *Check) { c.Total = maxTotal + 1 }, false},
		{"fewer keys than the total", valid, func(c *Check) { c.Keys = c.Keys[:len(c.Keys)-1] }, false},
		{"more keys than the total", valid, func(c *Check) { c.Total-- }, false},
		{"no keys though the total is small", valid, func(c *Check) { c.Keys = nil }, false},
		{"keys not sorted", valid, func(c *Check) { swap(c.Keys, 3, 4) }, false},
		{"duplicate key", valid, func(c *Check) { c.Keys[5] = c.Keys[4] }, false},
		{"upper-case key", valid, func(c *Check) { c.Keys[5] = strings.ToUpper(c.Keys[5]) }, false},
		{"short key", valid, func(c *Check) { c.Keys[5] = c.Keys[5][:63] }, false},
		{"digest missing", valid, func(c *Check) { c.Digest = "" }, false},
		{"digest not hex", valid, func(c *Check) { c.Digest = strings.Repeat("z", 64) }, false},
		{"digest of other keys", valid, func(c *Check) { c.Digest = result.SubjectKey("other") }, false},
		{"item missing from the set", valid, func(c *Check) { c.Items[0].Key = result.SubjectKey("not in the set") }, false},
		{"keys listed above the maximum", digestOnly, func(c *Check) { c.Keys = []string{result.SubjectKey("a")} }, false},
		{"digest only with a bad digest", digestOnly, func(c *Check) { c.Digest = "x" }, false},
		{"keys without total and digest", func() *State {
			st := valid()
			st.Checks[0].Total, st.Checks[0].Digest = 0, ""
			return st
		}, func(c *Check) {}, false},
		{"digest without total", func() *State {
			st := valid()
			st.Checks[0].Total, st.Checks[0].Keys = 0, nil
			return st
		}, func(c *Check) {}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := c.base()
			st.Checks[0].Keys = slices.Clone(st.Checks[0].Keys)
			c.mut(&st.Checks[0])
			_, err := roundTrip(t, st)
			if (err == nil) != c.ok {
				t.Fatalf("parse error = %v, want ok=%v", err, c.ok)
			}
			if err != nil {
				if _, isProblem := err.(*problem); !isProblem {
					t.Errorf("error is %T, want a problem (a baseline with a warning)", err)
				}
			}
		})
	}
}

// The boundary is exact: MaxKeys keys are listed, one more is not.
func TestKeySetBoundary(t *testing.T) {
	at, over := cappedState(result.MaxKeys), cappedState(result.MaxKeys+1)
	if len(at.Checks[0].Keys) != result.MaxKeys || over.Checks[0].Keys != nil {
		t.Fatalf("keys at the boundary: %d, above: %v", len(at.Checks[0].Keys), over.Checks[0].Keys != nil)
	}
	over.Checks[0].Keys = at.Checks[0].Keys
	if _, err := roundTrip(t, over); err == nil {
		t.Error("a check with more than MaxKeys members and listed keys was accepted")
	}
}

// Files of the older schemas are not read: a baseline with a warning, never a
// comparison that guesses.
func TestOlderSchemasAreABaselineWithAWarning(t *testing.T) {
	v2 := `{"schema_version": 2, "run_at": "2026-11-10T12:00:00Z", "checks": [{"id": "a.b", "kind": "k", "status": "fail", "severity": "low",
 "items": [{"key": "` + result.SubjectKey("a") + `", "subject": "a", "exact": true}], "hidden": 5, "cutoff": "a"}]}`
	v1 := `{"schema_version": 1, "run_at": "2026-11-10T12:00:00Z", "checks": [{"id": "a.b", "kind": "k", "status": "pass", "severity": "low", "items": []}]}`
	for name, doc := range map[string]string{"v1": v1, "v2": v2} {
		s, dir := newStore(t)
		writeStateFile(t, s, dir, doc)
		lr, err := s.Load()
		if err != nil || lr.State != nil || lr.Missing || !strings.Contains(lr.Problem, "this keepwatch reads version 3 only") {
			t.Errorf("%s: Load = %+v, %v", name, lr, err)
		}
	}
}

// MaxFileSize must hold the largest state keepwatch can write: every check of
// the base catalog capped and full, with the longest display subjects. The
// numbers in the MaxFileSize comment come from here.
func TestMaxFileSizeHoldsTheWorstCaseState(t *testing.T) {
	cat, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	longSubject := strings.Repeat("<", displayRunes) // json escapes each as <: 6 bytes
	st := &State{SchemaVersion: SchemaVersion, RunAt: t0}
	for _, e := range cat.Entries() {
		c := Check{ID: e.ID, Kind: e.Kind, Status: result.Fail, Severity: result.High, Items: []Item{}}
		all := make([]result.Evidence, result.MaxKeys)
		for i := range all {
			all[i] = result.Evidence{Subject: fmt.Sprintf("%s/%d", e.ID, i)}
		}
		set := result.NewEvidenceSet(all)
		c.Total, c.Keys, c.Digest = set.Total, set.Keys, set.Digest
		for i := 0; i < displayItems; i++ {
			c.Items = append(c.Items, Item{Key: set.Keys[i], Subject: longSubject, Excepted: true})
		}
		st.Checks = append(st.Checks, c)
	}
	b, err := Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("worst case: %d checks, %d bytes (limit %d)", len(st.Checks), len(b), MaxFileSize)
	if len(b) >= MaxFileSize {
		t.Fatalf("%d bytes do not fit in MaxFileSize %d", len(b), MaxFileSize)
	}
	// The comment on MaxFileSize says a key costs 72 bytes in the file.
	size := func(n int) int {
		set := cappedState(n).Checks[0]
		b, _ := Marshal(&State{SchemaVersion: SchemaVersion, RunAt: t0, Checks: []Check{set}})
		return len(b)
	}
	if per := (size(1100) - size(1000)) / 100; per != 72 {
		t.Errorf("a key costs %d bytes in the file, the MaxFileSize comment says 72", per)
	}
	if _, err := parse(b); err != nil {
		t.Fatalf("the worst case state does not load: %v", err)
	}
}
