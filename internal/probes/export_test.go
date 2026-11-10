package probes

import "github.com/LanNguyenSi/keepwatch/internal/result"

// AptPolicyShape is the shape classifyAptPolicyLine gives a line of
// "apt-cache policy" output, "" for a line it does not know.
func AptPolicyShape(line string) string { return classifyAptPolicyLine(line).shape }

// LimitEvidence exposes limitEvidence to the external tests.
func LimitEvidence(items []result.Evidence) ([]result.Evidence, int, *result.EvidenceSet) {
	return limitEvidence(items)
}

// MaxEvidence is the display cap of a list.
const MaxEvidence = maxEvidence
