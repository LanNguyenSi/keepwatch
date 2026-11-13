package incident

import "testing"

func TestCanTransition(t *testing.T) {
	states := []State{StateOpen, StateAcked, StateClosed}
	want := map[[2]State]bool{
		{StateOpen, StateAcked}:   true,
		{StateOpen, StateClosed}:  true,
		{StateAcked, StateClosed}: true,
	}
	for _, from := range states {
		for _, to := range states {
			if got := CanTransition(from, to); got != want[[2]State{from, to}] {
				t.Errorf("%s -> %s: got %v", from, to, got)
			}
		}
	}
	if CanTransition("bogus", StateOpen) || CanTransition(StateOpen, "bogus") {
		t.Error("unknown state may transition")
	}
}

func TestCanReopen(t *testing.T) {
	want := map[State]bool{StateOpen: false, StateAcked: false, StateClosed: true, "bogus": false}
	for s, w := range want {
		if got := CanReopen(s); got != w {
			t.Errorf("CanReopen(%s) = %v", s, got)
		}
	}
}
