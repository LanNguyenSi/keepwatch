package result

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
)

// MaxKeys is the most keys an EvidenceSet lists. A set with more distinct
// members keeps only its total and its digest.
const MaxKeys = 10000

// EvidenceSet describes the complete evidence list of a result whose
// evidence was capped: the list shown is a prefix of it, and this is the part
// that lets two runs be compared without the items that were left out.
//
// A member is identified by its key (SubjectKey): the lowercase hex SHA-256
// of the subject as the check produced it, before the redaction and escaping
// of the report. (A few checks clean a path or a name before it becomes the
// subject; for those the key follows the cleaned text.) A subject is never
// stored, so the set holds nothing a secret could hide in.
//
//   - Total is the number of distinct keys of the complete list.
//   - Keys is the sorted, deduplicated list of all keys, when Total is at
//     most MaxKeys. When Total is larger Keys is nil: the list would be too
//     large to store.
//   - Digest is the SHA-256 (lowercase hex) of the complete sorted,
//     deduplicated key list, whatever its length: each key as its 64 hex
//     characters followed by one newline byte. Keys have a fixed length, so
//     the framing is unambiguous, and two lists have the same digest only if
//     they are the same list. See DigestOfKeys.
type EvidenceSet struct {
	Total  int
	Keys   []string
	Digest string
}

// Complete reports whether the set lists its keys.
func (s *EvidenceSet) Complete() bool { return s.Total <= MaxKeys }

// SubjectKey returns the key of a raw subject: the lowercase hex SHA-256 of
// it. It is the one definition probes, state and diff share.
func SubjectKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

// keyBytes is the length of a key before hex encoding.
const keyBytes = sha256.Size

// NewEvidenceSet builds the set of the subjects of items. It takes the whole
// list, so it has to be called before a list is cut. Time is O(n log n) and
// memory is 32 bytes per item plus the keys that are kept (at most MaxKeys).
func NewEvidenceSet(items []Evidence) *EvidenceSet {
	sums := make([][keyBytes]byte, len(items))
	h := sha256.New()
	for i := range items {
		h.Reset()
		_, _ = io.WriteString(h, items[i].Subject)
		h.Sum(sums[i][:0])
	}
	return setOfSums(sums)
}

// SetOfKeys builds the set of a list of keys, which may be unsorted and hold
// duplicates. Every key must be 64 lowercase hex characters; ok is false if
// one is not.
func SetOfKeys(keys []string) (set *EvidenceSet, ok bool) {
	sums := make([][keyBytes]byte, len(keys))
	for i, k := range keys {
		if len(k) != 2*keyBytes || !isLowerHex(k) {
			return nil, false
		}
		_, _ = hex.Decode(sums[i][:], []byte(k))
	}
	return setOfSums(sums), true
}

// setOfSums sorts and deduplicates sums (in place) and builds the set.
func setOfSums(sums [][keyBytes]byte) *EvidenceSet {
	slices.SortFunc(sums, func(a, b [keyBytes]byte) int { return bytes.Compare(a[:], b[:]) })
	sums = slices.Compact(sums)
	set := &EvidenceSet{Total: len(sums)}
	h := sha256.New()
	var line [2*keyBytes + 1]byte
	line[2*keyBytes] = '\n'
	for i := range sums {
		hex.Encode(line[:2*keyBytes], sums[i][:])
		_, _ = h.Write(line[:])
		// Lowercase hex sorts like the bytes it encodes, so the key list
		// is in the order of the sums.
		if len(sums) <= MaxKeys {
			set.Keys = append(set.Keys, string(line[:2*keyBytes]))
		}
	}
	set.Digest = hex.EncodeToString(h.Sum(nil))
	return set
}

// DigestOfKeys returns the digest (see EvidenceSet) of a key list, which must
// be sorted and free of duplicates.
func DigestOfKeys(keys []string) string {
	h := sha256.New()
	for _, k := range keys {
		_, _ = io.WriteString(h, k)
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
