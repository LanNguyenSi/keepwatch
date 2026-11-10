package probes_test

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// The tests in this file run the whole chain that decides what an operator is
// told about a list that was cut: the probes' limitEvidence, the exception
// marks of the engine, state.FromResults with the real redactor, and
// diff.Compute. They are checked against a model that knows nothing but sets
// of raw subjects.

// seedsToRun returns the seeds of a property test: KEEPWATCH_SEED when set (to
// replay a failure), else 1..n (fewer under -short).
func seedsToRun(t *testing.T, n int) []int64 {
	t.Helper()
	switch {
	case raceEnabled:
		return seedsOf(t, n/10) // the race detector makes these 20 times slower
	case testing.Short():
		return seedsOf(t, n/5)
	}
	return seedsOf(t, n)
}

// seedsOf returns KEEPWATCH_SEED when it is set, else the seeds 1..n.
func seedsOf(t *testing.T, n int) []int64 {
	t.Helper()
	if s := os.Getenv("KEEPWATCH_SEED"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("KEEPWATCH_SEED: %v", err)
		}
		return []int64{v}
	}
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(i + 1)
	}
	return out
}

// pool builds subjects of every shape the cleaner changes: plain, with escape
// sequences and control characters, secrets that are redacted, newlines, lines
// longer than the display limit and look-alikes. A random first letter spreads
// them over the sort order.
func pool(rng *rand.Rand, n int) []string {
	out := make([]string, n)
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		var body string
		switch i % 6 {
		case 0:
			body = fmt.Sprintf("tcp/0.0.0.0:%05d", i)
		case 1:
			body = fmt.Sprintf("x%04d\x1b[3%dm", i, i%8)
		case 2:
			body = fmt.Sprintf("pw%04d password=s3cr3t%d", i, i)
		case 3:
			body = fmt.Sprintf("n%04d\nsecond line", i)
		case 4:
			body = fmt.Sprintf("L%04d", i) + strings.Repeat("y", 250)
		case 5:
			body = fmt.Sprintf("dup%04d%c", i/2, rune(1+i%2)) // two raw subjects, one display text
		}
		s := string(rune('a'+rng.Intn(26))) + body
		for seen[s] {
			s += "."
		}
		seen[s] = true
		out[i] = s
	}
	return out
}

func subset(rng *rand.Rand, from []string, n int) []string {
	idx := rng.Perm(len(from))[:n]
	out := make([]string, n)
	for i, j := range idx {
		out[i] = from[j]
	}
	return out
}

func minus(a, b []string) []string {
	drop := map[string]bool{}
	for _, s := range b {
		drop[s] = true
	}
	var out []string
	for _, s := range a {
		if !drop[s] {
			out = append(out, s)
		}
	}
	return out
}

// side is one run: the raw subjects of a check's list and the subjects an
// exception covers.
type side struct {
	subjects []string
	covered  map[string]bool
}

// runOf builds the check as the engine and state would: limitEvidence, the
// exception marks (only on listed items, as applyExceptions does), FromResults.
func runOf(t *testing.T, rng *rand.Rand, sd side, clean func(string) string, st result.Status) (state.Check, map[string]bool) {
	t.Helper()
	ev := make([]result.Evidence, len(sd.subjects))
	for i, s := range sd.subjects {
		ev[i] = result.Evidence{Subject: s, Detail: "d"}
	}
	rng.Shuffle(len(ev), func(i, j int) { ev[i], ev[j] = ev[j], ev[i] })
	shown, _, set := probes.LimitEvidence(ev)
	exceptedRaw := map[string]bool{}
	for i := range shown {
		if (set == nil || i < len(shown)-1) && sd.covered[shown[i].Subject] {
			shown[i].Excepted = true
			exceptedRaw[shown[i].Subject] = true
		}
	}
	r := result.Result{CheckID: "c", Kind: "k", Status: st, Severity: result.High, Evidence: shown, Set: set}
	return state.FromResults([]result.Result{r}, time.Unix(0, 0), clean).Checks[0], exceptedRaw
}

func displayOf(clean func(string) string, raw string) string {
	s := clean(raw)
	if utf8.RuneCountInString(s) <= 200 {
		return s
	}
	return string([]rune(s)[:200]) + "..."
}

func toSet(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func TestDiffMatchesASetModel(t *testing.T) {
	clean := redact.Default().Clean
	seeds := seedsToRun(t, 1000)
	// The classes of scenario seen, to make sure the run is not vacuous.
	seen := map[string]int{}
	for _, seed := range seeds {
		rng := rand.New(rand.NewSource(seed))
		fail := func(format string, a ...any) {
			t.Helper()
			t.Fatalf("seed %d (replay with KEEPWATCH_SEED=%d): %s", seed, seed, fmt.Sprintf(format, a...))
		}
		all := pool(rng, 420)
		size := func() int {
			if rng.Intn(4) == 0 {
				return rng.Intn(101) // up to the cap
			}
			return 100 + rng.Intn(201) // up to 3x the cap
		}
		A := subset(rng, all, size())
		var B []string
		mode := rng.Intn(7)
		switch mode {
		case 0: // independent
			B = subset(rng, all, size())
		case 1: // k swaps, same total
			k := 1 + rng.Intn(5)
			rest := minus(all, A)
			if len(A) < k || len(rest) < k {
				k = 0
			}
			keep := subset(rng, A, len(A)-k)
			B = append(keep, subset(rng, rest, k)...)
		case 2: // additions only
			rest := minus(all, A)
			B = append(append([]string(nil), A...), subset(rng, rest, rng.Intn(min(len(rest), 4)+1))...)
		case 3: // removals only
			B = subset(rng, A, len(A)-rng.Intn(min(len(A), 4)+1))
		case 4: // the same list
			B = append([]string(nil), A...)
		case 5: // swap across the cut: smallest in, largest out and the other way round
			sorted := append([]string(nil), A...)
			sort.Strings(sorted)
			rest := minus(all, A)
			sort.Strings(rest)
			if len(sorted) > 0 && len(rest) > 0 {
				B = append(append([]string(nil), sorted[1:]...), rest[len(rest)-1])
			} else {
				B = append([]string(nil), A...)
			}
		case 6: // a lookalike or escaped subject replaces the last of the sorted list
			sorted := append([]string(nil), A...)
			sort.Strings(sorted)
			rest := minus(all, A)
			if len(sorted) > 0 && len(rest) > 0 {
				B = append(append([]string(nil), sorted[:len(sorted)-1]...), rest[rng.Intn(len(rest))])
			} else {
				B = append([]string(nil), A...)
			}
		}
		cover := func() map[string]bool {
			switch rng.Intn(3) {
			case 0:
				return map[string]bool{}
			case 1:
				return toSet(subset(rng, all, 1+rng.Intn(20)))
			}
			return toSet(subset(rng, all, 100+rng.Intn(150)))
		}
		coverA := cover()
		coverB := coverA
		if rng.Intn(2) == 0 {
			coverB = cover()
		}
		status := result.Fail
		if rng.Intn(5) == 0 {
			status = result.Warn // warns have no exceptions in the engine
			coverA, coverB = map[string]bool{}, map[string]bool{}
		}

		prev, exA := runOf(t, rng, side{A, coverA}, clean, status)
		cur, exB := runOf(t, rng, side{B, coverB}, clean, status)

		// The model: failing set = list minus the listed items an exception covers.
		failA, failB := toSet(minus(A, keysOf(exA))), toSet(minus(B, keysOf(exB)))
		var gained, lost []string
		for s := range failB {
			if !failA[s] {
				gained = append(gained, s)
			}
		}
		for s := range failA {
			if !failB[s] {
				lost = append(lost, s)
			}
		}
		// listed: the items of a run that are named; a gained item is named
		// from the current list, or from the previous one if it was a listed
		// excepted item there.
		rawOf := map[string]string{}
		for _, s := range all {
			rawOf[result.SubjectKey(s)] = s
		}
		listedCur, listedPrev := listedOf(cur, rawOf), listedOf(prev, rawOf)
		var wantNew, wantGone []string
		wantHiddenNew, wantHiddenGone := 0, 0
		for _, s := range gained {
			if listedCur[s] || (listedPrev[s] && exA[s]) {
				wantNew = append(wantNew, displayOf(clean, s))
			} else {
				wantHiddenNew++
			}
		}
		for _, s := range lost {
			if listedPrev[s] || (listedCur[s] && exB[s]) {
				wantGone = append(wantGone, displayOf(clean, s))
			} else {
				wantHiddenGone++
			}
		}

		rep := diff.Compute(&state.State{Checks: []state.Check{prev}}, &state.State{Checks: []state.Check{cur}})
		var gotNew, gotGone []string
		gotHiddenNew, gotHiddenGone := 0, 0
		alert := false
		for _, c := range rep.Changes {
			alert = alert || c.Alert
			switch c.Kind {
			case diff.SubjectNew:
				gotNew = append(gotNew, c.Subject)
			case diff.SubjectGone:
				gotGone = append(gotGone, c.Subject)
			case diff.HiddenNew:
				gotHiddenNew += c.HiddenNew
			case diff.HiddenGone:
				gotHiddenGone += c.HiddenGone
			default:
				fail("mode %d: unexpected change %+v", mode, c)
			}
		}
		sort.Strings(gotNew)
		sort.Strings(gotGone)
		sort.Strings(wantNew)
		sort.Strings(wantGone)
		if !equalStrings(gotNew, wantNew) || !equalStrings(gotGone, wantGone) || gotHiddenNew != wantHiddenNew || gotHiddenGone != wantHiddenGone {
			fail("mode %d, |A|=%d |B|=%d, failing %d>%d: named new %d (want %d), named gone %d (want %d), hidden new %d (want %d), hidden gone %d (want %d)",
				mode, len(A), len(B), len(failA), len(failB), len(gotNew), len(wantNew), len(gotGone), len(wantGone),
				gotHiddenNew, wantHiddenNew, gotHiddenGone, wantHiddenGone)
		}
		// The invariant: the failing set gained a member exactly when there is
		// an alert (every kind alerts for a fail; a warn of kind "k" does not,
		// so for those only the counts above are checked).
		if status == result.Fail && alert != (len(gained) > 0) {
			fail("mode %d: alert=%v but %d members gained, %d lost", mode, alert, len(gained), len(lost))
		}
		for class, hit := range map[string]bool{
			"hidden new":              wantHiddenNew > 0,
			"hidden gone":             wantHiddenGone > 0,
			"named new":               len(wantNew) > 0,
			"named gone":              len(wantGone) > 0,
			"equal failing sets":      len(gained)+len(lost) == 0,
			"capped to complete":      len(A) > 100 && len(B) <= 100,
			"complete to capped":      len(A) <= 100 && len(B) > 100,
			"both capped":             len(A) > 100 && len(B) > 100,
			"swap, equal totals":      len(A) == len(B) && len(gained) > 0 && len(gained) == len(lost),
			"listed prev-excepted":    len(prev.Items) > 0 && len(exA) > 0 && len(gained) > 0,
			"alert without named new": alert && len(wantNew) == 0,
			"display differs from raw": func() bool {
				for _, s := range gained {
					if displayOf(clean, s) != s {
						return true
					}
				}
				return false
			}(),
		} {
			if hit {
				seen[class]++
			}
		}
		if len(gained)+len(lost) == 0 && len(rep.Changes) != 0 {
			fail("mode %d: the failing sets are equal and the report is not empty: %+v", mode, rep.Changes)
		}
	}
	if len(seeds) > 1 {
		for _, class := range []string{"hidden new", "hidden gone", "named new", "named gone", "equal failing sets", "capped to complete",
			"complete to capped", "both capped", "swap, equal totals", "alert without named new", "display differs from raw"} {
			want := 20
			if len(seeds) < 1000 {
				want = 1 // a shortened run (-short, -race) only has to see each class
			}
			if seen[class] < want {
				t.Errorf("only %d scenarios of the class %q in %d seeds: the generator is too narrow", seen[class], class, len(seeds))
			}
		}
		t.Logf("scenario classes over %d seeds: %v", len(seeds), seen)
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// listedOf returns the raw subjects of the items a check lists, found by key.
func listedOf(c state.Check, rawOf map[string]string) map[string]bool {
	m := map[string]bool{}
	for _, it := range c.Items {
		m[rawOf[it.Key]] = true
	}
	return m
}

func equalStrings(a, b []string) bool {
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
