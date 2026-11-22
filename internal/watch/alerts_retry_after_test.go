package watch

import (
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// After a failed send the next attempt waits for max(gap, min(RetryAfter,
// the upper bound of gap)): a missing header keeps today's gap, a wait below
// the gap does not shorten it, a wait between the gap and the bound is
// honoured, and a wait above the bound is capped at it. The harness interval
// is 40m: the gap for one failure is 10m and the bound is 40m.
func TestFailedResultPacingUsesRetryAfter(t *testing.T) {
	cases := []struct {
		name       string
		retryAfter time.Duration
		want       time.Duration
	}{
		{"missing header keeps the gap", 0, 10 * time.Minute},
		{"below the gap the gap wins", 5 * time.Minute, 10 * time.Minute},
		{"between the gap and the bound the answer wins", 20 * time.Minute, 20 * time.Minute},
		{"above the bound the bound wins", time.Hour, 40 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.d.mu.Lock()
			defer h.d.mu.Unlock()
			res := alert.Result{
				Job:        alert.Job{Fingerprint: "fp"},
				Status:     alert.Failed,
				Class:      notify.Transient,
				Detail:     "ntfy: HTTP 429",
				At:         t0,
				RetryAfter: c.retryAfter,
			}
			if err := h.d.handleResult(res); err != nil {
				t.Fatal(err)
			}
			if got := h.d.tries["fp"].notBefore; !got.Equal(t0.Add(c.want)) {
				t.Fatalf("notBefore = %v, want %v", got, t0.Add(c.want))
			}
		})
	}
}

// The whole chain: an ntfy 429 with a Retry-After between the gap and the
// bound travels through the worker into the pacing, and the housekeeping
// pass retries neither before nor long after it.
func TestFailedSendWithRetryAfterPacesTheRetry(t *testing.T) {
	h := newHarness(t, hopts{})
	h.notif.fail = func(int) error {
		return &notify.Error{Class: notify.Transient, Status: 429, Msg: "slow down", RetryAfter: 20 * time.Minute}
	}
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	r := h.start()
	waitFor(t, "failed send audited", func() bool { return h.count(audit.NotifyFailed) == 1 })
	fp := string(h.store.List()[0].Fingerprint)
	h.d.mu.Lock()
	st := h.d.tries[fp]
	h.d.mu.Unlock()
	if !st.notBefore.Equal(t0.Add(20 * time.Minute)) {
		t.Fatalf("notBefore = %v, want %v: the asked-for wait beats the 10m gap", st.notBefore, t0.Add(20*time.Minute))
	}
	step := func(d time.Duration) int {
		h.clk.add(d)
		housekeepOnce(t, h)
		time.Sleep(60 * time.Millisecond)
		return len(h.notif.sent())
	}
	// The gap alone would already be over after 15m; the asked-for wait is not.
	if n := step(15 * time.Minute); n != 1 {
		t.Fatalf("sends = %d after 15m, want 1 (the Retry-After is not over)", n)
	}
	if n := step(6 * time.Minute); n != 2 {
		t.Fatalf("sends = %d after 21m, want the retry (2)", n)
	}
	waitFor(t, "second failure audited", func() bool { return h.count(audit.NotifyFailed) == 2 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
}
