package probes_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func evidenceN(n int) []result.Evidence {
	ev := make([]result.Evidence, n)
	for i := range ev {
		ev[i] = result.Evidence{Subject: fmt.Sprintf("s%05d", n-i), Detail: "d"}
	}
	return ev
}

func TestLimitEvidence(t *testing.T) {
	t.Run("a list at the cap is untouched and has no set", func(t *testing.T) {
		ev, hidden := probes.LimitEvidence(evidenceN(probes.MaxEvidence))
		if len(ev) != probes.MaxEvidence || hidden != 0 {
			t.Fatalf("%d items, %d hidden", len(ev), hidden)
		}
		for _, e := range ev {
			if e.IsMarker() {
				t.Fatalf("marker in an uncapped list: %+v", e)
			}
		}
	})
	t.Run("one over the cap is cut and the set covers the whole list", func(t *testing.T) {
		in := evidenceN(probes.MaxEvidence + 1)
		var all []string
		for _, e := range in {
			all = append(all, e.Subject)
		}
		sort.Strings(all)
		ev, hidden := probes.LimitEvidence(in)
		if len(ev) != probes.MaxEvidence || hidden != 2 || ev[probes.MaxEvidence-1].Subject != "(2 more not shown)" {
			t.Fatalf("%d items, %d hidden, last %+v", len(ev), hidden, ev[len(ev)-1])
		}
		wantCapped(t, ev, probes.MaxEvidence+1)
		member := map[string]bool{}
		for _, k := range ev[len(ev)-1].Set.Keys {
			member[k] = true
		}
		// The two items that were cut are in the set.
		for _, s := range all[probes.MaxEvidence-1:] {
			if !member[result.SubjectKey(s)] {
				t.Fatalf("cut subject %q is not in the set", s)
			}
		}
	})
	t.Run("duplicate subjects count once in the set", func(t *testing.T) {
		in := evidenceN(probes.MaxEvidence + 50)
		in = append(in, in[:20]...)
		ev, _ := probes.LimitEvidence(in)
		wantCapped(t, ev, probes.MaxEvidence+50)
	})
	t.Run("a very long list keeps only the total and the digest", func(t *testing.T) {
		ev, _ := probes.LimitEvidence(evidenceN(result.MaxKeys + 1))
		set := ev[len(ev)-1].Set
		if set == nil || set.Total != result.MaxKeys+1 || set.Keys != nil || len(set.Digest) != 64 {
			t.Fatalf("%+v", set)
		}
	})
}
