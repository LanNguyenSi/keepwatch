package probes

import (
	"fmt"
	"sort"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// maxEvidence bounds the evidence items of one outcome. Some of what a probe
// lists is shaped by local users (listening sockets, lines of a key file), and
// an outcome with a million items would blow up memory, the state file and
// the notification. The limit includes the marker item described at
// limitEvidence.
const maxEvidence = 100

// limitEvidence sorts items by subject and, when there are more than
// maxEvidence, keeps the first maxEvidence-1 and appends one marker item that
// says how many are not shown. It returns the items and the number hidden.
//
// The marker is an item on purpose. An exception removes a failing check only
// when every evidence item is covered; a list that silently dropped the tail
// would let an exception for the visible items hide the rest. The marker's
// subject changes with the count, so no exception matches it by accident, and
// the check stays failed.
//
// The marker also carries the complete set of the list (result.EvidenceSet),
// computed over all items before the cut. Without it the items that were left
// out are gone, and two runs of a capped check could not be compared (see the
// diff package). Every probe that can list more than maxEvidence items must
// go through this function; nothing else may cut a list.
func limitEvidence(items []result.Evidence) ([]result.Evidence, int) {
	sort.SliceStable(items, func(i, j int) bool { return items[i].Subject < items[j].Subject })
	if len(items) <= maxEvidence {
		return items, 0
	}
	hidden := len(items) - (maxEvidence - 1)
	set := result.NewEvidenceSet(items)
	out := append([]result.Evidence(nil), items[:maxEvidence-1]...)
	out = append(out, result.Evidence{
		Subject: fmt.Sprintf("(%d more not shown)", hidden),
		Detail:  fmt.Sprintf("%d further items are not listed, the limit is %d items", hidden, maxEvidence),
		Set:     set,
	})
	return out, hidden
}

// moreNote renders the "and M more" part of a summary, or "" when nothing is
// hidden.
func moreNote(hidden int) string {
	if hidden == 0 {
		return ""
	}
	return fmt.Sprintf("; showing %d, and %d more", maxEvidence-1, hidden)
}
