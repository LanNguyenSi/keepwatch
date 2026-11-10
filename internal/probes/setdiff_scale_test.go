package probes_test

import (
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// Sets above result.MaxKeys keep no keys, only a digest: the comparison must
// still follow the model (equal sets, no change; any other difference, one
// set_changed with both totals).
func TestDigestModeMatchesASetModel(t *testing.T) {
	seeds := seedsOf(t, 40)
	if raceEnabled || testing.Short() {
		seeds = seedsOf(t, 12)
	}
	changedSeen, equalSeen := 0, 0
	for _, seed := range seeds {
		rng := rand.New(rand.NewSource(seed))
		fail := func(format string, a ...any) {
			t.Helper()
			t.Fatalf("seed %d (replay with KEEPWATCH_SEED=%d): %s", seed, seed, fmt.Sprintf(format, a...))
		}
		all := make([]string, result.MaxKeys+400)
		for i := range all {
			all[i] = fmt.Sprintf("d%05d", i)
		}
		// Sizes around the boundary: uncapped, capped and complete, exactly
		// MaxKeys, and above it.
		sizes := []int{20, 150, result.MaxKeys - 1, result.MaxKeys, result.MaxKeys + 1, result.MaxKeys + 1 + rng.Intn(300)}
		A := subset(rng, all, sizes[rng.Intn(len(sizes))])
		var B []string
		switch rng.Intn(6) {
		case 0: // the same list, in another order
			B = append([]string(nil), A...)
		case 1: // one swap
			rest := minus(all, A)
			B = append(append([]string(nil), A[1:]...), rest[rng.Intn(len(rest))])
		case 2: // one more
			rest := minus(all, A)
			B = append(append([]string(nil), A...), rest[rng.Intn(len(rest))])
		case 3: // one fewer
			B = append([]string(nil), A[1:]...)
		case 4: // another size entirely
			B = subset(rng, all, sizes[rng.Intn(len(sizes))])
		case 5: // a handful of swaps
			rest := minus(all, A)
			k := 1 + rng.Intn(8)
			B = append(append([]string(nil), A[k:]...), subset(rng, rest, k)...)
		}
		prev, _ := runOf(t, rng, side{A, nil}, nil, result.Fail)
		cur, _ := runOf(t, rng, side{B, nil}, nil, result.Fail)
		rep := diff.Compute(&state.State{Checks: []state.Check{prev}}, &state.State{Checks: []state.Check{cur}})

		inA, inB := toSet(A), toSet(B)
		gained, lost := 0, 0
		for s := range inB {
			if !inA[s] {
				gained++
			}
		}
		for s := range inA {
			if !inB[s] {
				lost++
			}
		}
		long := len(A) > result.MaxKeys || len(B) > result.MaxKeys
		var gotNew, gotGone, gotSet int
		alert := false
		for _, c := range rep.Changes {
			alert = alert || c.Alert
			switch c.Kind {
			case diff.SubjectNew:
				gotNew++
			case diff.SubjectGone:
				gotGone++
			case diff.HiddenNew:
				gotNew += c.HiddenNew
			case diff.HiddenGone:
				gotGone += c.HiddenGone
			case diff.SetChanged:
				gotSet++
				if c.OldTotal != len(A) || c.NewTotal != len(B) {
					fail("set_changed totals %d>%d, want %d>%d", c.OldTotal, c.NewTotal, len(A), len(B))
				}
			default:
				fail("unexpected change %+v", c)
			}
		}
		switch {
		case gained+lost == 0:
			equalSeen++
			if len(rep.Changes) != 0 {
				fail("equal sets of %d items: changes %+v", len(A), rep.Changes)
			}
		case long:
			changedSeen++
			if gotSet != 1 || gotNew+gotGone != 0 || !alert {
				fail("|A|=%d |B|=%d: set_changed %d, named %d/%d, alert %v", len(A), len(B), gotSet, gotNew, gotGone, alert)
			}
		default:
			if gotSet != 0 || gotNew != gained || gotGone != lost || alert != (gained > 0) {
				fail("|A|=%d |B|=%d: new %d (want %d), gone %d (want %d), alert %v", len(A), len(B), gotNew, gained, gotGone, lost, alert)
			}
		}
	}
	if len(seeds) == 40 && (changedSeen < 5 || equalSeen < 3) || len(seeds) > 1 && (changedSeen < 1 || equalSeen < 1) {
		t.Errorf("the generator is too narrow: %d changed and %d equal scenarios above the key limit", changedSeen, equalSeen)
	}
}

// peak samples the heap in use while a function runs.
func peak(fn func()) (maxHeap uint64) {
	var mu sync.Mutex
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			mu.Lock()
			if ms.HeapInuse > maxHeap {
				maxHeap = ms.HeapInuse
			}
			mu.Unlock()
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	fn()
	close(done)
	wg.Wait()
	return maxHeap
}

// pipeline runs n synthetic subjects through limitEvidence, FromResults and
// Compute, twice (the second list has one listed item swapped for a hidden one)
// and returns the time of the whole run and a check of the result.
func pipeline(t *testing.T, n int) (time.Duration, uint64) {
	t.Helper()
	runtime.GC()
	var d time.Duration
	heap := peak(func() {
		start := time.Now()
		build := func(swap bool) state.Check {
			ev := make([]result.Evidence, n)
			for i := range ev {
				ev[i] = result.Evidence{Subject: fmt.Sprintf("tcp/10.%d.%d.%d:%d", i>>16&255, i>>8&255, i&255, 1024+i%60000), Detail: "p"}
			}
			if swap {
				ev[0].Subject = "zz-hidden-new" // sorts after everything
			}
			// Probes list items in the order of the host, not sorted.
			rng := rand.New(rand.NewSource(1))
			rng.Shuffle(len(ev), func(i, j int) { ev[i], ev[j] = ev[j], ev[i] })
			shown, _, set := probes.LimitEvidence(ev)
			r := result.Result{CheckID: "c", Kind: "k", Status: result.Fail, Severity: result.High, Evidence: shown, Set: set}
			return state.FromResults([]result.Result{r}, time.Unix(0, 0), nil).Checks[0]
		}
		prev := build(false)
		cur := build(true)
		rep := diff.Compute(&state.State{Checks: []state.Check{prev}}, &state.State{Checks: []state.Check{cur}})
		d = time.Since(start)
		var sc, hn, hg int
		for _, c := range rep.Changes {
			switch c.Kind {
			case diff.SetChanged:
				sc++
			case diff.HiddenNew:
				hn += c.HiddenNew
			case diff.SubjectGone, diff.HiddenGone, diff.SubjectNew:
				hg++
			}
		}
		// n > MaxKeys: the keys are not kept and the digests tell the lists apart.
		if prev.Keys != nil || prev.Total != n || sc != 1 || hn != 0 {
			t.Errorf("n=%d: total %d, %d keys kept, %d set_changed, %d other", n, prev.Total, len(prev.Keys), sc, hg)
		}
	})
	return d, heap
}

// A million items go through the whole chain in linear-ish time and bounded
// memory: the work is a sort and a hash per item, nothing quadratic. The
// numbers are logged so that the figures can be quoted.
func TestAMillionItemsThroughLimitEvidenceAndDiff(t *testing.T) {
	if testing.Short() {
		t.Skip("a million items take a few seconds")
	}
	nSmall, nBig := 250_000, 1_000_000
	if raceEnabled {
		nSmall, nBig = 25_000, 100_000 // the race detector slows this down by a factor of 20 or more
	}
	small, smallHeap := pipeline(t, nSmall)
	big, bigHeap := pipeline(t, nBig)
	t.Logf("%d items: %v, peak heap in use %d MiB; %d items: %v, peak heap in use %d MiB", nSmall, small.Round(time.Millisecond), smallHeap>>20, nBig, big.Round(time.Millisecond), bigHeap>>20)
	if big > 90*time.Second {
		t.Errorf("%d items took %v", nBig, big)
	}
	// 4x the items: n log n is about 4.4x, quadratic would be 16x.
	if big > 10*small+time.Second {
		t.Errorf("%d items took %v against %v for %d: not linear", nBig, big, small, nSmall)
	}
	if bigHeap > 2<<30 {
		t.Errorf("peak heap in use %d MiB", bigHeap>>20)
	}
}
