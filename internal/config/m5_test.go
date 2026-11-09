package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestURLNegativeEmptyHost(t *testing.T) {
	// https:///x and http:///x parse but have no host; ":443" has a
	// Host but an empty host part; "host:" has an empty port: none of
	// them is a valid absolute URL.
	for _, u := range []string{"https:///x", "http:///x", "https://:443/x", "https://host:/x"} {
		t.Run(u, func(t *testing.T) {
			yaml := "notify:\n  ntfy:\n    url: " + u + "\n    topic: t\n"
			_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
			loadErrs(t, main, "is not a valid absolute URL")
		})
	}
}

func TestErrorsFromTwoFilesSortedByFileThenLine(t *testing.T) {
	// Pin the order: errors are sorted by file name, then by line.
	// conf.d/a.yaml sorts before keepwatch.yaml ('c' < 'k'), so all
	// conf.d errors come first regardless of load order.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_di: /a\nstate_dj: /b\n",
		"conf.d/a.yaml":  "unknown_x: 1\nlisteners:\n  allow:\n    - port: 0\n      proto: tcp\n",
	})
	confd := filepath.Join(dir, "conf.d", "a.yaml")
	got := errsOf(t, main)
	want := []string{
		confd + ":1: unknown key \"unknown_x\"",
		confd + ":4: listeners.allow[0].port: must be between 1 and 65535, got 0",
		main + ":1: unknown key \"state_di\"",
		main + ":2: unknown key \"state_dj\"",
	}
	if len(got) != len(want) {
		t.Fatalf("errors = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("error[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExpiryLocalDayAcrossZones(t *testing.T) {
	// The documented rule is the local day: expiry compares against
	// midnight of time.Local, never the injected now's own zone and
	// never UTC. time.Local is temporarily a fixed UTC-10 zone and the
	// injected now sits in a fixed UTC+13 zone (UTC+14 would have the
	// same day boundaries as UTC-10, which would make the comparison
	// vacuous). Non-parallel: it mutates time.Local via defer.
	if testing.Short() {
		t.Skip("mutates time.Local")
	}
	defer func(orig *time.Location) { time.Local = orig }(time.Local)
	time.Local = time.FixedZone("testutcminus10", -10*3600)

	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "exceptions:\n  - check: c\n    reason: r\n    expires: 2035-06-14\n",
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	plus13 := time.FixedZone("testutcplus13", 13*3600)

	// 2035-06-15 19:00+13 = 06:00 UTC = 2035-06-14 20:00 in UTC-10.
	// The local (UTC-10) day is June 14, so the exception expiring on
	// June 14 is still active. In the injected zone or in UTC the day
	// is June 15, which would make it expired.
	now := time.Date(2035, 6, 15, 19, 0, 0, 0, plus13)
	if len(cfg.ActiveExceptions(now)) != 1 || len(cfg.ExpiredExceptions(now)) != 0 {
		t.Errorf("at %v (local day June 14): want active, got active=%d expired=%d",
			now, len(cfg.ActiveExceptions(now)), len(cfg.ExpiredExceptions(now)))
	}

	// 2035-06-15 08:00+13 = 2035-06-14 19:00 UTC = 2035-06-14 09:00 in
	// UTC-10: still local day June 14, still active.
	now = time.Date(2035, 6, 15, 8, 0, 0, 0, plus13)
	if len(cfg.ActiveExceptions(now)) != 1 {
		t.Errorf("at %v (local day June 14): want active", now)
	}

	// 2035-06-14 08:00+13 = 2035-06-13 19:00 UTC = 2035-06-13 09:00 in
	// UTC-10: local day June 13, before the expiry date: active.
	now = time.Date(2035, 6, 14, 8, 0, 0, 0, plus13)
	if len(cfg.ActiveExceptions(now)) != 1 {
		t.Errorf("at %v (local day June 13, before expiry): want active", now)
	}

	// 2035-06-16 08:00+13 = 2035-06-15 19:00 UTC = 2035-06-15 09:00 in
	// UTC-10: local day June 15, the day after the expiry date:
	// expired.
	now = time.Date(2035, 6, 16, 8, 0, 0, 0, plus13)
	if len(cfg.ActiveExceptions(now)) != 0 || len(cfg.ExpiredExceptions(now)) != 1 {
		t.Errorf("at %v (local day June 15, past expiry): want expired", now)
	}
}
