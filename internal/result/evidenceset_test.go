package result

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"
)

func items(subjects ...string) []Evidence {
	out := make([]Evidence, len(subjects))
	for i, s := range subjects {
		out[i] = Evidence{Subject: s}
	}
	return out
}

func subjectsN(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%06d", prefix, i)
	}
	return out
}

// reference builds the set the slow way, from the definition: hash every
// subject, sort and deduplicate the hex strings, join them with newlines.
func reference(subjects []string) (total int, keys []string, digest string) {
	for _, s := range subjects {
		sum := sha256.Sum256([]byte(s))
		keys = append(keys, hex.EncodeToString(sum[:]))
	}
	sort.Strings(keys)
	keys = slices.Compact(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\n")
	}
	d := sha256.Sum256([]byte(b.String()))
	return len(keys), keys, hex.EncodeToString(d[:])
}

func TestSubjectKey(t *testing.T) {
	// sha256("a") and sha256("")
	if got := SubjectKey("a"); got != "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" {
		t.Errorf("SubjectKey(a) = %s", got)
	}
	if got := SubjectKey(""); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("SubjectKey(empty) = %s", got)
	}
	// The raw subject is hashed: a control character changes the key.
	if SubjectKey("web") == SubjectKey("web\x01") {
		t.Error("subjects that differ in a control character share a key")
	}
}

func TestNewEvidenceSetMatchesTheDefinition(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for _, n := range []int{0, 1, 2, 99, 100, 101, 1000, MaxKeys - 1, MaxKeys, MaxKeys + 1, 25000} {
		subjects := subjectsN("host/", n)
		// Duplicates and a shuffled order must not matter.
		subjects = append(subjects, subjects[:n/3]...)
		rng.Shuffle(len(subjects), func(i, j int) { subjects[i], subjects[j] = subjects[j], subjects[i] })
		total, keys, digest := reference(subjects)

		got := NewEvidenceSet(items(subjects...))
		if got.Total != total || got.Digest != digest {
			t.Fatalf("n=%d: total %d digest %s, want %d %s", n, got.Total, got.Digest, total, digest)
		}
		if total <= MaxKeys {
			if !slices.Equal(got.Keys, keys) || !got.Complete() {
				t.Fatalf("n=%d: keys differ from the sorted, deduplicated reference", n)
			}
		} else if got.Keys != nil || got.Complete() {
			t.Fatalf("n=%d: %d keys kept above MaxKeys", n, len(got.Keys))
		}
		if total <= MaxKeys && DigestOfKeys(got.Keys) != digest {
			t.Fatalf("n=%d: DigestOfKeys disagrees", n)
		}
	}
}

func TestEvidenceSetDigest(t *testing.T) {
	base := subjectsN("p", MaxKeys+5)
	a := NewEvidenceSet(items(base...))
	if b := NewEvidenceSet(items(slices.Concat(base[3:], base[:3])...)); a.Digest != b.Digest {
		t.Error("the digest depends on the order of the input")
	}
	swapped := slices.Clone(base)
	swapped[len(swapped)-1] = "other"
	if b := NewEvidenceSet(items(swapped...)); a.Digest == b.Digest || a.Total != b.Total {
		t.Errorf("one swapped member: digest %s vs %s, totals %d %d", a.Digest, b.Digest, a.Total, b.Total)
	}
	if b := NewEvidenceSet(items(base[1:]...)); a.Digest == b.Digest {
		t.Error("a missing member leaves the digest unchanged")
	}
	// Framing: the key list "x\ny" cannot be mistaken for another split.
	if DigestOfKeys([]string{"ab", "c"}) == DigestOfKeys([]string{"a", "bc"}) {
		t.Error("the framing is ambiguous")
	}
}

func TestSetOfKeys(t *testing.T) {
	subjects := subjectsN("k", 300)
	want := NewEvidenceSet(items(subjects...))
	var keys []string
	for _, s := range subjects {
		keys = append(keys, SubjectKey(s))
	}
	keys = append(keys, keys[:10]...)
	slices.Reverse(keys)
	got, ok := SetOfKeys(keys)
	if !ok || got.Total != want.Total || got.Digest != want.Digest || !slices.Equal(got.Keys, want.Keys) {
		t.Fatalf("ok=%v got %+v", ok, got)
	}
	for _, bad := range []string{"", "ab", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if _, ok := SetOfKeys([]string{keys[0], bad}); ok {
			t.Errorf("SetOfKeys accepted %q", bad)
		}
	}
	if s, ok := SetOfKeys(nil); !ok || s.Total != 0 || s.Digest != DigestOfKeys(nil) {
		t.Errorf("empty: %+v %v", s, ok)
	}
}
