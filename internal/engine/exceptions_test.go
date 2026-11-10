package engine_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
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

// An error that keeps the failing items it confirmed is still an error:
// neither a whole-check exception nor one that matches a kept item changes
// it, and the kept items are not marked as excepted.
func TestExceptionsDoNotTouchAPartialError(t *testing.T) {
	r := host().AddResult(ssUDP, res("", 1)) // udp cannot be read, the tcp listeners are confirmed
	for name, cfg := range map[string]*config.Config{
		"whole check": withExceptions(exc("t.listeners", "", "known", day)),
		"one item":    withExceptions(exc("t.listeners", "tcp/0.0.0.0:8080", "known", day)),
		"every item": withExceptions(exc("t.listeners", "tcp/0.0.0.0:8080", "a", day),
			exc("t.listeners", "tcp/[::]:8080", "b", day)),
	} {
		t.Run(name, func(t *testing.T) {
			got := byID(t, run(t, cfg, r, day), "t.listeners")
			if got.Status != result.Error || len(got.ExceptionReasons) != 0 || strings.Contains(got.Summary, "(excepted") {
				t.Fatalf("result %+v", got)
			}
			if len(got.Evidence) != 2 || !strings.Contains(got.Summary, "partial") {
				t.Fatalf("the confirmed items were lost: %+v", got)
			}
			for _, e := range got.Evidence {
				if e.Excepted || e.ExceptionReason != "" {
					t.Fatalf("item marked excepted: %+v", e)
				}
			}
		})
	}
}

// A flood of listening sockets is cut to 100 evidence items. An exception for
// every item that is shown must not hide the ones that are not.
func TestExceptionsDoNotHideEvidenceBeyondTheLimit(t *testing.T) {
	var sb strings.Builder
	for port := 9000; port < 9150; port++ {
		fmt.Fprintf(&sb, "LISTEN 0 5 0.0.0.0:%d 0.0.0.0:*\n", port)
	}
	r := fake.New(nil).
		AddResult(svcArgv, res("active\n", 0)).
		AddResult(sshdArgv, res("passwordauthentication no\n", 0)).
		AddResult(ssTCP, res(sb.String(), 0)).AddResult(ssUDP, res("", 0)).
		AddResult(ssTCPp, res("", 0)).AddResult(ssUDPp, res("", 0))
	base := byID(t, run(t, &config.Config{}, r, day), "t.listeners")
	if base.Status != result.Fail || len(base.Evidence) != 100 {
		t.Fatalf("status %s, %d items", base.Status, len(base.Evidence))
	}
	var es []config.Exception
	for _, e := range base.Evidence[:99] {
		es = append(es, exc("t.listeners", e.Subject, "shown", day))
	}
	got := byID(t, run(t, withExceptions(es...), r, day), "t.listeners")
	if got.Status != result.Fail {
		t.Fatalf("the hidden sockets were excepted along with the shown ones: %s", got.Status)
	}
	last := got.Evidence[99]
	if last.Excepted || !strings.Contains(last.Subject, "more not shown") {
		t.Fatalf("marker %+v", last)
	}
	// a whole-check exception still covers everything
	if got := byID(t, run(t, withExceptions(exc("t.listeners", "", "all", day)), r, day), "t.listeners"); got.Status != result.Excepted {
		t.Fatalf("status %s", got.Status)
	}
}

// keysHost is a host with the authorized_keys check: alice holds the keys of
// the given files, and the configuration expects the given fingerprints.
func keysRun(t *testing.T, aliceKeys string, expected []string, es ...config.Exception) result.Result {
	t.Helper()
	cat, err := catalog.Parse([]byte(`
checks:
  - id: t.keys
    title: Keys
    kind: authorized_keys
    severity: high
    rationale: r
    fix_hint: f
`))
	if err != nil {
		t.Fatal(err)
	}
	passwd, err := os.ReadFile("../probes/testdata/ubuntu2404/etc_passwd.stdout")
	if err != nil {
		t.Fatal(err)
	}
	fsys := probestest.FakeFS{
		Files: map[string]string{"/etc/passwd": string(passwd)},
		Homes: map[string]string{probestest.HomeKey("/home/alice", ".ssh/authorized_keys"): aliceKeys},
	}
	r := fake.New(os.DirFS("../probes/testdata")).Add(sshdArgv, "ubuntu2404/sshd_T_default")
	cfg := &config.Config{Exceptions: es}
	cfg.AuthorizedKeys.Expected = map[string][]string{"alice": expected}
	rs, err := engine.Run(context.Background(), cat, cfg, deps2(r, fsys))
	if err != nil {
		t.Fatal(err)
	}
	return byID(t, rs, "t.keys")
}

func deps2(r execx.Runner, fsys probes.FS) engine.Deps {
	return engine.Deps{Runner: r, FS: fsys, Now: func() time.Time { return day }}
}

func keyLine(t *testing.T, name string) (line, fp string) {
	t.Helper()
	b, err := os.ReadFile("../probes/testdata/ubuntu2404/sshkey_" + name + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.ReadFile("../probes/testdata/ubuntu2404/sshkey_" + name + "_fp.stdout")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b)), strings.Fields(string(f))[1]
}

// An exception removes failures, never warnings: when every failing item is
// excepted and warnings remain, the check is a warn that carries the warnings.
func TestExceptedFailuresLeaveTheWarnings(t *testing.T) {
	ed, edFP := keyLine(t, "ed25519")
	ec, ecFP := keyLine(t, "ecdsa")
	_, rsaFP := keyLine(t, "rsa")
	// ecdsa is unexpected (fail), the expected rsa key is missing (warn)
	files := ed + "\n" + ec + "\n"
	expected := []string{edFP, rsaFP}
	failing := "alice:" + ecFP
	warning := "alice:" + rsaFP

	t.Run("without an exception: fail, the warning is not evidence", func(t *testing.T) {
		got := keysRun(t, files, expected)
		if got.Status != result.Fail || len(got.Evidence) != 1 || got.Evidence[0].Subject != failing {
			t.Fatalf("result %+v", got)
		}
	})
	t.Run("every failing item excepted, a warning remains: warn", func(t *testing.T) {
		got := keysRun(t, files, expected, exc("t.keys", failing, "known key", day))
		if got.Status != result.Warn {
			t.Fatalf("status %s: %+v", got.Status, got)
		}
		if len(got.Evidence) != 1 || got.Evidence[0].Subject != warning || got.Evidence[0].Excepted {
			t.Fatalf("evidence %+v", got.Evidence)
		}
		for _, want := range []string{"failing items excepted: known key", "1 warning(s) remain"} {
			if !strings.Contains(got.Summary, want) {
				t.Fatalf("summary %q lacks %q", got.Summary, want)
			}
		}
		if len(got.ExceptionReasons) != 1 || got.ExceptionReasons[0] != "known key" {
			t.Fatalf("reasons %v", got.ExceptionReasons)
		}
	})
	t.Run("a whole-check exception leaves the warning too", func(t *testing.T) {
		got := keysRun(t, files, expected, exc("t.keys", "", "accepted", day))
		if got.Status != result.Warn || len(got.Evidence) != 1 || got.Evidence[0].Subject != warning {
			t.Fatalf("result %+v", got)
		}
	})
	t.Run("no warning remains: excepted, as before", func(t *testing.T) {
		got := keysRun(t, files, []string{edFP}, exc("t.keys", failing, "known key", day))
		if got.Status != result.Excepted || !strings.Contains(got.Summary, "excepted: known key") {
			t.Fatalf("result %+v", got)
		}
		if len(got.Evidence) != 1 || !got.Evidence[0].Excepted {
			t.Fatalf("evidence %+v", got.Evidence)
		}
	})
	t.Run("only some failing items excepted: still fail, the warning stays out", func(t *testing.T) {
		rsa, _ := keyLine(t, "rsa")
		two := ed + "\n" + ec + "\n" + rsa + "\n"
		got := keysRun(t, two, []string{edFP, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, exc("t.keys", failing, "known key", day))
		if got.Status != result.Fail || len(got.Evidence) != 2 {
			t.Fatalf("result %+v", got)
		}
		excepted := 0
		for _, e := range got.Evidence {
			if e.Excepted {
				excepted++
			}
			if strings.Contains(e.Detail, "expected key not found") {
				t.Fatalf("a warning became evidence of the failure: %+v", e)
			}
		}
		if excepted != 1 {
			t.Fatalf("evidence %+v", got.Evidence)
		}
	})
	t.Run("an unreadable key file is a warning that an exception does not hide", func(t *testing.T) {
		got := keysRun(t, ec+"\nthis is not a key\n", []string{edFP}, exc("t.keys", "alice:"+ecFP, "known key", day))
		if got.Status != result.Warn || len(got.Evidence) != 2 {
			t.Fatalf("result %+v", got)
		}
	})
}
