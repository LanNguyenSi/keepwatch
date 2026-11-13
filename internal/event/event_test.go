package event

import "testing"

func TestFingerprintOfSplitsDiffer(t *testing.T) {
	a := FingerprintOf("r", "ab", "c")
	b := FingerprintOf("r", "a", "bc")
	c := FingerprintOf("r", "abc")
	d := FingerprintOf("r", "abc", "")
	e := FingerprintOf("r", "", "abc")
	all := []Fingerprint{a, b, c, d, e}
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			if all[i] == all[j] {
				t.Errorf("collision between %d and %d", i, j)
			}
		}
	}
	if FingerprintOf("ra", "b") == FingerprintOf("r", "ab") {
		t.Error("rule id and parts collide")
	}
}

func TestFingerprintOfStable(t *testing.T) {
	x, y := FingerprintOf("r", "x"), FingerprintOf("r", "x")
	if x != y {
		t.Error("not deterministic")
	}
	const want = "dae82531a0a43d9ece0a17f89d93d36f544f9f68c18fc0290b41c0928ede232a"
	got := FingerprintOf("oom", "nginx", "1234")
	if string(got) != want {
		t.Errorf("golden: got %s", got)
	}
}
