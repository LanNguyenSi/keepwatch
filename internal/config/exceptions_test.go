package config

import (
	"fmt"
	"testing"
	"time"
)

func TestExpiryBoundary(t *testing.T) {
	// The injected clock decides: an exception is active through its
	// expiry date and expired from the day after. Each row states the
	// expiry date, the injected "now", and which list the exception
	// lands in.
	now := time.Date(2035, 6, 15, 13, 45, 0, 0, time.Local)
	tests := []struct {
		name      string
		expires   string
		wantAct   bool
		wantExpir bool
	}{
		{"expires today is still active", "2035-06-15", true, false},
		{"expires tomorrow is active", "2035-06-16", true, false},
		{"expires yesterday is expired", "2035-06-14", false, true},
		{"expires far future is active", "2099-12-31", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf("exceptions:\n  - check: c\n    reason: r\n    expires: %s\n", tc.expires)
			_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.ActiveExceptions(now); len(got) != boolInt(tc.wantAct) {
				t.Errorf("ActiveExceptions len = %d, want active=%v", len(got), tc.wantAct)
			}
			if got := cfg.ExpiredExceptions(now); len(got) != boolInt(tc.wantExpir) {
				t.Errorf("ExpiredExceptions len = %d, want expired=%v", len(got), tc.wantExpir)
			}
			want, err := parseDate(tc.expires)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Exceptions[0].Expires.Equal(want) {
				t.Errorf("parsed Expires = %v, want %v", cfg.Exceptions[0].Expires, want)
			}
		})
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestExpiryUsesLocalDayBoundaries(t *testing.T) {
	// The exception is active on its expiry date no matter the time of
	// day, and expired from midnight of the next day.
	expires := time.Date(2035, 6, 15, 0, 0, 0, 0, time.Local)
	e := Exception{Expires: expires}
	c := &Config{Exceptions: []Exception{e}}
	evening := time.Date(2035, 6, 15, 23, 59, 59, 0, time.Local)
	if len(c.ActiveExceptions(evening)) != 1 {
		t.Error("active late on the expiry date: want 1")
	}
	justAfter := time.Date(2035, 6, 16, 0, 0, 1, 0, time.Local)
	if len(c.ActiveExceptions(justAfter)) != 0 || len(c.ExpiredExceptions(justAfter)) != 1 {
		t.Error("one second after local midnight past the expiry: want expired")
	}
}

func TestPackageHasNoClockDependencyInLogic(t *testing.T) {
	// ActiveExceptions and ExpiredExceptions are pure functions of the
	// injected now: same input, same result.
	c := &Config{Exceptions: []Exception{
		{Check: "a", Expires: time.Date(2035, 6, 14, 0, 0, 0, 0, time.Local)},
		{Check: "b", Expires: time.Date(2035, 6, 15, 0, 0, 0, 0, time.Local)},
		{Check: "c", Expires: time.Date(2035, 6, 16, 0, 0, 0, 0, time.Local)},
	}}
	now := time.Date(2035, 6, 15, 1, 2, 3, 0, time.Local)
	got := ""
	for _, e := range c.ActiveExceptions(now) {
		got += e.Check
	}
	if got != "bc" {
		t.Errorf("active = %q, want %q", got, "bc")
	}
	got = ""
	for _, e := range c.ExpiredExceptions(now) {
		got += e.Check
	}
	if got != "a" {
		t.Errorf("expired = %q, want %q", got, "a")
	}
}
