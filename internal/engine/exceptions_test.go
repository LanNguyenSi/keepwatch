package engine_test

import (
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// until returns an exception that is active through the day of d.
func exc(check, match, reason string, d time.Time) config.Exception {
	return config.Exception{Check: check, Match: match, Reason: reason,
		Expires: time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, time.Local)}
}

func withExceptions(es ...config.Exception) *config.Config { return &config.Config{Exceptions: es} }

func TestWholeCheckException(t *testing.T) {
	cfg := withExceptions(exc("t.listeners", "", "known service", day))
	got := byID(t, run(t, cfg, host(), day), "t.listeners")
	if got.Status != result.Excepted {
		t.Fatalf("status %s", got.Status)
	}
	if len(got.ExceptionReasons) != 1 || got.ExceptionReasons[0] != "known service" || !strings.Contains(got.Summary, "excepted: known service") {
		t.Fatalf("result %+v", got)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("evidence lost: %+v", got.Evidence)
	}
	for _, e := range got.Evidence {
		if !e.Excepted || e.ExceptionReason != "known service" {
			t.Fatalf("evidence not marked: %+v", e)
		}
	}
	// other checks are untouched
	if s := byID(t, run(t, cfg, host(), day), "t.sshd"); s.Status != result.Fail || len(s.ExceptionReasons) != 0 {
		t.Fatalf("exception leaked to another check: %+v", s)
	}
}

func TestMatchExceptionCoveringEverySubject(t *testing.T) {
	cfg := withExceptions(
		exc("t.listeners", "tcp/0.0.0.0:8080", "v4", day),
		exc("t.listeners", "tcp/[::]:8080", "v6", day),
	)
	got := byID(t, run(t, cfg, host(), day), "t.listeners")
	if got.Status != result.Excepted {
		t.Fatalf("status %s: %+v", got.Status, got)
	}
	if strings.Join(got.ExceptionReasons, "|") != "v4|v6" {
		t.Fatalf("reasons %v", got.ExceptionReasons)
	}
	for _, e := range got.Evidence {
		if !e.Excepted || e.ExceptionReason == "" {
			t.Fatalf("evidence not marked: %+v", e)
		}
	}
}

func TestPartialException(t *testing.T) {
	cfg := withExceptions(exc("t.listeners", "tcp/0.0.0.0:8080", "v4 only", day))
	got := byID(t, run(t, cfg, host(), day), "t.listeners")
	if got.Status != result.Fail {
		t.Fatalf("status %s", got.Status)
	}
	if len(got.Evidence) != 2 {
		t.Fatalf("evidence %+v", got.Evidence)
	}
	for _, e := range got.Evidence {
		switch e.Subject {
		case "tcp/0.0.0.0:8080":
			if !e.Excepted || e.ExceptionReason != "v4 only" {
				t.Fatalf("matched item: %+v", e)
			}
		default:
			if e.Excepted || e.ExceptionReason != "" {
				t.Fatalf("unmatched item marked: %+v", e)
			}
		}
	}
	if strings.Contains(got.Summary, "excepted") {
		t.Fatalf("a failing check must not say it is excepted: %q", got.Summary)
	}
}

func TestMatchIsAnExactComparison(t *testing.T) {
	for _, m := range []string{"tcp/0.0.0.0:808", "0.0.0.0:8080", "TCP/0.0.0.0:8080", "tcp/0.0.0.0:8080 ", " tcp/0.0.0.0:8080", "tcp/0.0.0.0", "tcp", "*"} {
		cfg := withExceptions(exc("t.listeners", m, "r", day))
		got := byID(t, run(t, cfg, host(), day), "t.listeners")
		if got.Status != result.Fail {
			t.Errorf("match %q changed the status to %s", m, got.Status)
		}
		for _, e := range got.Evidence {
			if e.Excepted {
				t.Errorf("match %q marked %+v", m, e)
			}
		}
	}
}

func TestExceptionForAnotherCheckDoesNotApply(t *testing.T) {
	cfg := withExceptions(exc("t.service", "", "r", day))
	if got := byID(t, run(t, cfg, host(), day), "t.listeners"); got.Status != result.Fail {
		t.Fatalf("status %s", got.Status)
	}
	// same match text, different check
	cfg = withExceptions(exc("t.service", "tcp/0.0.0.0:8080", "r", day))
	if got := byID(t, run(t, cfg, host(), day), "t.listeners"); got.Status != result.Fail || got.Evidence[0].Excepted {
		t.Fatalf("result %+v", got)
	}
}

func TestWholeAndMatchExceptionsTogether(t *testing.T) {
	cfg := withExceptions(
		exc("t.listeners", "tcp/0.0.0.0:8080", "item reason", day),
		exc("t.listeners", "", "whole reason", day),
		exc("t.listeners", "", "whole reason", day), // duplicate reasons are listed once
	)
	got := byID(t, run(t, cfg, host(), day), "t.listeners")
	if got.Status != result.Excepted {
		t.Fatalf("status %s", got.Status)
	}
	if strings.Join(got.ExceptionReasons, "|") != "whole reason|item reason" {
		t.Fatalf("reasons %v", got.ExceptionReasons)
	}
	for _, e := range got.Evidence {
		if !e.Excepted {
			t.Fatalf("not marked: %+v", e)
		}
		if e.Subject == "tcp/0.0.0.0:8080" && e.ExceptionReason != "whole reason; item reason" {
			t.Fatalf("item reason %q", e.ExceptionReason)
		}
	}
}

func TestExceptionsNeverChangeNonFailures(t *testing.T) {
	// error: sshd -T fails; pass: the service is up; skipped: disabled.
	r := fake.New(nil).
		AddResult(svcArgv, res("active\n", 0)).
		AddResult(sshdArgv, execx.Result{ExitCode: 255, Stderr: []byte("Missing privilege separation directory: /run/sshd\n")}).
		AddResult(ssTCP, res(ssOneListener, 0)).AddResult(ssUDP, res("", 0))
	cfg := withExceptions(
		exc("t.service", "", "r", day),
		exc("t.sshd", "", "r", day),
		exc("t.listeners", "", "r", day),
	)
	cfg.Checks = map[string]config.Check{"t.listeners": {Enabled: false}}
	rs := run(t, cfg, r, day)
	for id, want := range map[string]result.Status{"t.service": result.Pass, "t.sshd": result.Error, "t.listeners": result.Skipped} {
		got := byID(t, rs, id)
		if got.Status != want || len(got.ExceptionReasons) != 0 || strings.Contains(got.Summary, "excepted") {
			t.Errorf("%s: %+v, want %s untouched", id, got, want)
		}
	}
	// an error with match exceptions has no evidence to match and stays error
	cfg = withExceptions(exc("t.sshd", "passwordauthentication", "r", day))
	if got := byID(t, run(t, cfg, r, day), "t.sshd"); got.Status != result.Error {
		t.Fatalf("status %s", got.Status)
	}
}

func TestExpiredExceptionDoesNotApplyAndIsReported(t *testing.T) {
	yesterday := day.AddDate(0, 0, -1)
	cfg := withExceptions(exc("t.listeners", "", "old reason", yesterday))
	rs := run(t, cfg, host(), day)
	if got := byID(t, rs, "t.listeners"); got.Status != result.Fail || len(got.ExceptionReasons) != 0 {
		t.Fatalf("an expired exception was applied: %+v", got)
	}
	if len(rs) != 4 {
		t.Fatalf("%d results: %+v", len(rs), rs)
	}
	exp := rs[3]
	if exp.CheckID != engine.ExpiredID || exp.Status != result.Fail || exp.Severity != result.Low || exp.Kind == "" {
		t.Fatalf("expired result %+v", exp)
	}
	if !strings.Contains(exp.Summary, "2026-11-08") || !strings.Contains(exp.Summary, "t.listeners") {
		t.Fatalf("summary %q", exp.Summary)
	}
	if len(exp.Evidence) != 1 || exp.Evidence[0].Subject != "t.listeners" || !strings.Contains(exp.Evidence[0].Detail, "old reason") || !strings.Contains(exp.Evidence[0].Detail, "2026-11-08") {
		t.Fatalf("evidence %+v", exp.Evidence)
	}
}

func TestExpiredResultSubjectIncludesMatch(t *testing.T) {
	long := day.AddDate(0, -2, 0)
	cfg := withExceptions(
		exc("t.listeners", "tcp/0.0.0.0:8080", "first", long),
		exc("t.sshd", "", "second", long.AddDate(0, 0, 3)),
		exc("t.service", "", "still active", day),
	)
	rs := run(t, cfg, host(), day)
	if len(rs) != 5 {
		t.Fatalf("%d results", len(rs))
	}
	if rs[3].Evidence[0].Subject != "t.listeners tcp/0.0.0.0:8080" || rs[4].Evidence[0].Subject != "t.sshd" {
		t.Fatalf("subjects %q, %q (config order expected)", rs[3].Evidence[0].Subject, rs[4].Evidence[0].Subject)
	}
	if rs[3].CheckID != engine.ExpiredID || rs[4].CheckID != engine.ExpiredID {
		t.Fatalf("ids %s %s", rs[3].CheckID, rs[4].CheckID)
	}
	if !strings.Contains(rs[3].Summary, "2026-09-09") {
		t.Fatalf("summary %q", rs[3].Summary)
	}
}

func TestExpiryBoundaryUsesTheInjectedClock(t *testing.T) {
	expires := time.Date(2026, 11, 9, 0, 0, 0, 0, time.Local)
	cfg := withExceptions(config.Exception{Check: "t.listeners", Reason: "r", Expires: expires})
	cases := []struct {
		name    string
		now     time.Time
		active  bool
		results int
	}{
		{"morning of the expiry date", time.Date(2026, 11, 9, 0, 0, 0, 0, time.Local), true, 3},
		{"last instant of the expiry date", time.Date(2026, 11, 9, 23, 59, 59, 999999999, time.Local), true, 3},
		{"first instant of the next day", time.Date(2026, 11, 10, 0, 0, 0, 0, time.Local), false, 4},
		{"the day before", time.Date(2026, 11, 8, 23, 59, 59, 0, time.Local), true, 3},
		{"long after", time.Date(2027, 11, 9, 12, 0, 0, 0, time.Local), false, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := run(t, cfg, host(), c.now)
			if len(rs) != c.results {
				t.Fatalf("%d results, want %d", len(rs), c.results)
			}
			st := byID(t, rs, "t.listeners").Status
			if c.active && st != result.Excepted {
				t.Fatalf("status %s, want excepted", st)
			}
			if !c.active && st != result.Fail {
				t.Fatalf("status %s, want fail", st)
			}
		})
	}
}

func TestExceptionForTheExpiredCheckItself(t *testing.T) {
	yesterday := day.AddDate(0, 0, -1)
	cfg := withExceptions(
		exc("t.listeners", "", "old", yesterday),
		exc(engine.ExpiredID, "t.listeners", "we know", day),
	)
	rs := run(t, cfg, host(), day)
	exp := rs[len(rs)-1]
	if exp.CheckID != engine.ExpiredID || exp.Status != result.Excepted || !exp.Evidence[0].Excepted {
		t.Fatalf("result %+v", exp)
	}
	// a match that names another subject does not except it
	cfg = withExceptions(
		exc("t.listeners", "", "old", yesterday),
		exc(engine.ExpiredID, "t.sshd", "other", day),
	)
	rs = run(t, cfg, host(), day)
	if exp = rs[len(rs)-1]; exp.Status != result.Fail {
		t.Fatalf("result %+v", exp)
	}
	// a whole-check exception for the synthetic id covers every expiry
	cfg = withExceptions(exc("t.listeners", "", "old", yesterday), exc("t.sshd", "", "old", yesterday), exc(engine.ExpiredID, "", "migration", day))
	for _, x := range run(t, cfg, host(), day)[3:] {
		if x.Status != result.Excepted {
			t.Fatalf("result %+v", x)
		}
	}
}
