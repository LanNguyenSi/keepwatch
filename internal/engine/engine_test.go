package engine_test

import (
	"context"
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

// miniCatalog has one check per interesting shape.
const miniCatalog = `
checks:
  - id: t.service
    title: Service
    kind: service_active
    params: {service: ssh.service}
    severity: medium
    rationale: r
    fix_hint: f
  - id: t.sshd
    title: Option
    kind: sshd_effective
    params: {option: passwordauthentication, allow: [no]}
    severity: high
    rationale: r
    fix_hint: f
  - id: t.listeners
    title: Listeners
    kind: listeners
    params: {allow_loopback: true}
    severity: low
    rationale: r
    fix_hint: f
`

func mini(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Parse([]byte(miniCatalog))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var (
	svcArgv  = []string{"systemctl", "is-active", "--", "ssh.service"}
	sshdArgv = []string{"sshd", "-T"}
	ssTCP    = []string{"ss", "-Hltn"}
	ssUDP    = []string{"ss", "-Hlun"}
	ssTCPp   = []string{"ss", "-Hltnp"}
	ssUDPp   = []string{"ss", "-Hlunp"}
)

const (
	ssTwoListeners  = "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 5 [::]:8080 [::]:*\n"
	ssOneListener   = "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n"
	ssTwoListenersP = "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:* users:((\"web\",pid=1,fd=3))\nLISTEN 0 5 [::]:8080 [::]:* users:((\"web\",pid=1,fd=4))\n"
)

func res(stdout string, exit int) execx.Result {
	return execx.Result{Stdout: []byte(stdout), ExitCode: exit}
}

// host returns a runner for a host where the service is down, password
// login is on and two sockets listen on 8080.
func host() *fake.FakeRunner {
	return fake.New(nil).
		AddResult(svcArgv, res("inactive\n", 3)).
		AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)).
		AddResult(ssTCP, res(ssTwoListeners, 0)).
		AddResult(ssUDP, res("", 0)).
		AddResult(ssTCPp, res(ssTwoListenersP, 0)).
		AddResult(ssUDPp, res("", 0))
}

var day = time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local)

func deps(r execx.Runner, now time.Time) engine.Deps {
	return engine.Deps{Runner: r, FS: probestest.MemFS{}, Now: func() time.Time { return now }}
}

func byID(t *testing.T, rs []result.Result, id string) result.Result {
	t.Helper()
	for _, r := range rs {
		if r.CheckID == id {
			return r
		}
	}
	t.Fatalf("no result for %s in %+v", id, rs)
	return result.Result{}
}

func run(t *testing.T, cfg *config.Config, r execx.Runner, now time.Time) []result.Result {
	t.Helper()
	rs, err := engine.Run(context.Background(), mini(t), cfg, deps(r, now))
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestResultsInCatalogOrderWithDefaults(t *testing.T) {
	rs := run(t, &config.Config{}, host(), day)
	var ids []string
	for _, r := range rs {
		ids = append(ids, r.CheckID)
	}
	if strings.Join(ids, ",") != "t.service,t.sshd,t.listeners" {
		t.Fatalf("ids = %v", ids)
	}
	for _, r := range rs {
		if r.Status != result.Fail || r.Evidence == nil || len(r.Evidence) == 0 || r.Summary == "" {
			t.Fatalf("result %+v", r)
		}
	}
	svc := byID(t, rs, "t.service")
	if svc.Kind != "service_active" || svc.Severity != result.Medium {
		t.Fatalf("service result %+v", svc)
	}
	if got := byID(t, rs, "t.sshd").Severity; got != result.High {
		t.Fatalf("catalog severity not used: %s", got)
	}
}

func TestPassResultHasEmptyEvidenceList(t *testing.T) {
	r := host().AddResult(svcArgv, res("active\n", 0))
	got := byID(t, run(t, &config.Config{}, r, day), "t.service")
	if got.Status != result.Pass || got.Evidence == nil || len(got.Evidence) != 0 {
		t.Fatalf("result %+v", got)
	}
}

func TestDisabledCheckIsSkippedAndNotRun(t *testing.T) {
	r := host()
	cfg := &config.Config{Checks: map[string]config.Check{"t.sshd": {Enabled: false}, "t.service": {Enabled: true}}}
	rs := run(t, cfg, r, day)
	got := byID(t, rs, "t.sshd")
	if got.Status != result.Skipped || !strings.Contains(got.Summary, "disabled") || len(got.Evidence) != 0 {
		t.Fatalf("result %+v", got)
	}
	for _, c := range r.Calls() {
		if c.Argv[0] == "sshd" {
			t.Fatalf("a disabled check ran: %v", c.Argv)
		}
	}
	if byID(t, rs, "t.service").Status != result.Fail {
		t.Fatalf("enabled check did not run")
	}
}

func TestSeverityOverride(t *testing.T) {
	cfg := &config.Config{Checks: map[string]config.Check{
		"t.service": {Enabled: true, Severity: "critical"},
		"t.sshd":    {Enabled: true}, // no override: the catalog severity stays
	}}
	rs := run(t, cfg, host(), day)
	if got := byID(t, rs, "t.service").Severity; got != result.Critical {
		t.Fatalf("override not applied: %s", got)
	}
	if got := byID(t, rs, "t.sshd").Severity; got != result.High {
		t.Fatalf("catalog severity lost: %s", got)
	}
	// a disabled check keeps the effective severity too
	cfg.Checks["t.listeners"] = config.Check{Enabled: false, Severity: "info"}
	if got := byID(t, run(t, cfg, host(), day), "t.listeners").Severity; got != result.Info {
		t.Fatalf("severity of a disabled check: %s", got)
	}
}

func TestParamsMergeReplacesLists(t *testing.T) {
	// The catalog allows "no". The configuration lists "yes": the list is
	// replaced, so "yes" now passes and "no" is no longer in the set.
	cfg := &config.Config{Checks: map[string]config.Check{"t.sshd": {Enabled: true, Params: map[string]any{"allow": []any{"yes"}}}}}
	if got := byID(t, run(t, cfg, host(), day), "t.sshd"); got.Status != result.Pass {
		t.Fatalf("replacing list: %+v", got)
	}
	r := host().AddResult(sshdArgv, res("passwordauthentication no\n", 0))
	if got := byID(t, run(t, cfg, r, day), "t.sshd"); got.Status != result.Fail {
		t.Fatalf("the catalog's list leaked into the merged one: %+v", got)
	}
	// keys the configuration does not set keep the catalog value
	cfg = &config.Config{Checks: map[string]config.Check{"t.sshd": {Enabled: true, Params: map[string]any{"allow": []any{"yes"}}}}}
	if got := byID(t, run(t, cfg, host(), day), "t.sshd"); got.Evidence != nil && got.Status == result.Error {
		t.Fatalf("option lost in merge: %+v", got)
	}
	// a bool replaces a bool; the catalog default is allow_loopback: true
	loop := "LISTEN 0 5 127.0.0.1:5432 0.0.0.0:*\n"
	r = host().AddResult(ssTCP, res(loop, 0))
	if got := byID(t, run(t, &config.Config{}, r, day), "t.listeners"); got.Status != result.Pass {
		t.Fatalf("loopback by default: %+v", got)
	}
	cfg = &config.Config{Checks: map[string]config.Check{"t.listeners": {Enabled: true, Params: map[string]any{"allow_loopback": false}}}}
	if got := byID(t, run(t, cfg, r, day), "t.listeners"); got.Status != result.Fail {
		t.Fatalf("allow_loopback override: %+v", got)
	}
}

func TestMergeDoesNotModifyTheCatalog(t *testing.T) {
	cat := mini(t)
	cfg := &config.Config{Checks: map[string]config.Check{"t.sshd": {Enabled: true, Params: map[string]any{"allow": []any{"yes"}}}}}
	if _, err := engine.Run(context.Background(), cat, cfg, deps(host(), day)); err != nil {
		t.Fatal(err)
	}
	e, _ := cat.Get("t.sshd")
	if l := e.Params["allow"].([]any); len(l) != 1 || l[0] != "no" {
		t.Fatalf("catalog params changed: %v", e.Params)
	}
}

func TestConfigErrorsStopBeforeAnyProbe(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want []string
	}{
		{"unknown check id", &config.Config{Checks: map[string]config.Check{"t.nope": {Enabled: true}}}, []string{"checks.t.nope", "unknown check id"}},
		{"unknown exception id", &config.Config{Exceptions: []config.Exception{{Check: "t.nope", Reason: "r", Expires: day}}}, []string{"exceptions[0].check", "t.nope"}},
		{"unknown id in an expired exception", &config.Config{Exceptions: []config.Exception{{Check: "t.nope", Reason: "r", Expires: day.AddDate(-1, 0, 0)}}}, []string{"t.nope"}},
		{"synthetic id under checks", &config.Config{Checks: map[string]config.Check{engine.ExpiredID: {Enabled: false}}}, []string{"checks.exception_expired", "cannot be configured"}},
		{"bad param type", &config.Config{Checks: map[string]config.Check{"t.service": {Enabled: true, Params: map[string]any{"service": 3}}}}, []string{"checks.t.service.params", "service"}},
		{"bad param value", &config.Config{Checks: map[string]config.Check{"t.service": {Enabled: true, Params: map[string]any{"service": "-x"}}}}, []string{"checks.t.service.params", "must not start with"}},
		{"unknown param", &config.Config{Checks: map[string]config.Check{"t.listeners": {Enabled: true, Params: map[string]any{"ports": []any{1}}}}}, []string{"checks.t.listeners.params", `unknown parameter "ports"`}},
		{"bad param in a disabled check", &config.Config{Checks: map[string]config.Check{"t.service": {Enabled: false, Params: map[string]any{"service": "a b"}}}}, []string{"checks.t.service.params"}},
		{"bad severity", &config.Config{Checks: map[string]config.Check{"t.service": {Enabled: true, Severity: "loud"}}}, []string{"checks.t.service.severity"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := host()
			rs, err := engine.Run(context.Background(), mini(t), c.cfg, deps(r, day))
			if err == nil {
				t.Fatalf("no error; results %+v", rs)
			}
			if rs != nil {
				t.Fatalf("results returned with an error: %+v", rs)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
			if n := len(r.Calls()); n != 0 {
				t.Fatalf("%d probes ran before the error", n)
			}
		})
	}
}

func TestConfigErrorsAreReportedTogether(t *testing.T) {
	cfg := &config.Config{
		Checks:     map[string]config.Check{"t.a": {Enabled: true}, "t.b": {Enabled: true}},
		Exceptions: []config.Exception{{Check: "t.c", Reason: "r", Expires: day}},
	}
	_, err := engine.Run(context.Background(), mini(t), cfg, deps(host(), day))
	if err == nil {
		t.Fatal("no error")
	}
	for _, w := range []string{"checks.t.a", "checks.t.b", "t.c"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q lacks %q", err, w)
		}
	}
}

func TestExceptionMayNameTheSyntheticCheck(t *testing.T) {
	cfg := &config.Config{Exceptions: []config.Exception{{Check: engine.ExpiredID, Match: "t.service", Reason: "r", Expires: day}}}
	if _, err := engine.Run(context.Background(), mini(t), cfg, deps(host(), day)); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareNeedsItsDependencies(t *testing.T) {
	cat, cfg := mini(t), &config.Config{}
	good := deps(host(), day)
	for name, d := range map[string]engine.Deps{
		"runner": {FS: good.FS, Now: good.Now},
		"fs":     {Runner: good.Runner, Now: good.Now},
		"clock":  {Runner: good.Runner, FS: good.FS},
	} {
		if _, err := engine.Prepare(cat, cfg, d); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
	if _, err := engine.Prepare(nil, cfg, good); err == nil {
		t.Error("nil catalog accepted")
	}
	if _, err := engine.Prepare(cat, nil, good); err == nil {
		t.Error("nil config accepted")
	}
}

func TestOneCommandRunsOncePerRun(t *testing.T) {
	cat, err := catalog.Parse([]byte(strings.Replace(miniCatalog, "  - id: t.listeners", `  - id: t.sshd2
    title: Second option
    kind: sshd_effective
    params: {option: port, allow: ["22"]}
    severity: low
    rationale: r
    fix_hint: f
  - id: t.listeners`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	r := host()
	rs, err := engine.Run(context.Background(), cat, &config.Config{}, deps(r, day))
	if err != nil {
		t.Fatal(err)
	}
	if byID(t, rs, "t.sshd").Status != result.Fail || byID(t, rs, "t.sshd2").Status != result.Pass {
		t.Fatalf("results %+v", rs)
	}
	n := 0
	for _, c := range r.Calls() {
		if c.Argv[0] == "sshd" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sshd -T ran %d times for two checks", n)
	}
	// a second run starts with a fresh snapshot
	plan, err := engine.Prepare(cat, &config.Config{}, deps(r, day))
	if err != nil {
		t.Fatal(err)
	}
	plan.Run(context.Background())
	plan.Run(context.Background())
	n = 0
	for _, c := range r.Calls() {
		if c.Argv[0] == "sshd" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("sshd -T ran %d times over three runs", n)
	}
}

func TestErrorsAreCachedTooWithinOneRun(t *testing.T) {
	r := fake.New(nil).AddError(sshdArgv, execx.ErrNotFound).
		AddResult(svcArgv, res("active\n", 0)).AddResult(ssTCP, res(ssOneListener, 0)).AddResult(ssUDP, res("", 0))
	rs := run(t, &config.Config{}, r, day)
	if got := byID(t, rs, "t.sshd"); got.Status != result.Skipped || !strings.Contains(got.Summary, "sshd") {
		t.Fatalf("missing program: %+v", got)
	}
}

func TestCancelledContextRunsNothing(t *testing.T) {
	r := host()
	plan, err := engine.Prepare(mini(t), &config.Config{}, deps(r, day))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs := plan.Run(ctx)
	if len(rs) != 3 || len(r.Calls()) != 0 {
		t.Fatalf("results %d, calls %d", len(rs), len(r.Calls()))
	}
	for _, x := range rs {
		if x.Status != result.Error || !strings.Contains(x.Summary, "not run") {
			t.Fatalf("result %+v", x)
		}
	}
}

func TestProgramsIsTheUnionOverTheCatalog(t *testing.T) {
	if got := strings.Join(engine.Programs(mini(t)), ","); got != "ss,sshd,systemctl" {
		t.Fatalf("Programs = %s", got)
	}
	base, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	want := "dpkg-query,fail2ban-client,needrestart,ss,sshd,systemctl"
	if got := strings.Join(engine.Programs(base), ","); got != want {
		t.Fatalf("Programs = %s, want %s", got, want)
	}
}

func TestListenerAllowlistReachesTheProbe(t *testing.T) {
	cfg := &config.Config{Listeners: config.Listeners{Allow: []config.Listener{
		{Port: 8080, Proto: "tcp", Bind: "0.0.0.0"},
	}}}
	got := byID(t, run(t, cfg, host(), day), "t.listeners")
	if got.Status != result.Fail || len(got.Evidence) != 1 || got.Evidence[0].Subject != "tcp/[::]:8080" {
		t.Fatalf("result %+v", got)
	}
	cfg.Listeners.Allow = append(cfg.Listeners.Allow, config.Listener{Port: 8080, Proto: "tcp", Bind: "::"})
	if got := byID(t, run(t, cfg, host(), day), "t.listeners"); got.Status != result.Pass {
		t.Fatalf("result %+v", got)
	}
}

// The base catalog against real captured outputs: a host with a drop-in that
// re-enables password login.
func TestBaseCatalogAgainstCapturedHost(t *testing.T) {
	base, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"ubuntu2204", "ubuntu2404"} {
		t.Run(v, func(t *testing.T) {
			fx := os.DirFS("../probes/testdata")
			r := fake.New(fx).
				Add([]string{"systemctl", "is-active", "--", "fail2ban.service"}, v+"/systemctl_active").
				Add([]string{"systemctl", "is-active", "--", "unattended-upgrades.service"}, v+"/systemctl_unattended").
				Add([]string{"dpkg-query", "-W", "-f=${Status}\t${Version}\n", "--", "fail2ban"}, v+"/dpkg_installed").
				Add([]string{"dpkg-query", "-W", "-f=${Status}\t${Version}\n", "--", "unattended-upgrades"}, v+"/dpkg_installed").
				AddResult([]string{"dpkg-query", "-W", "-f=${Status}\t${Version}\n", "--", "needrestart"},
					execx.Result{ExitCode: 1, Stderr: []byte("dpkg-query: no packages found matching needrestart\n")}).
				Add(sshdArgv, v+"/sshd_T_dropin_open").
				Add([]string{"fail2ban-client", "--", "status", "sshd"}, v+"/fail2ban_status_sshd").
				Add(ssTCP, v+"/ss_tcp_sshd_only").
				Add(ssUDP, v+"/ss_udp_sshd_only").
				Add([]string{"needrestart", "-b", "-k", "-r", "l"}, v+"/needrestart_kernel")
			cfg := &config.Config{Listeners: config.Listeners{Allow: []config.Listener{{Port: 22, Proto: "tcp", Bind: "*"}}}}
			rs, err := engine.Run(context.Background(), base, cfg, deps(r, day))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]result.Status{
				"services.fail2ban_active":                result.Pass,
				"services.unattended_upgrades_active":     result.Pass,
				"packages.fail2ban_installed":             result.Pass,
				"packages.unattended_upgrades_installed":  result.Pass,
				"packages.needrestart_installed":          result.Fail,
				"ssh.password_authentication":             result.Fail,
				"ssh.permit_root_login":                   result.Fail,
				"ssh.keyboard_interactive_authentication": result.Fail,
				"ssh.x11_forwarding":                      result.Fail,
				"fail2ban.sshd_jail":                      result.Pass,
				"network.listeners":                       result.Pass,
				"system.reboot_required":                  result.Pass,
			}
			if len(rs) != len(want) {
				t.Fatalf("%d results, want %d", len(rs), len(want))
			}
			for _, x := range rs {
				if x.Status != want[x.CheckID] {
					t.Errorf("%s: %s (%s), want %s", x.CheckID, x.Status, x.Summary, want[x.CheckID])
				}
			}
			n := 0
			allowed := map[string]bool{}
			for _, p := range engine.Programs(base) {
				allowed[p] = true
			}
			for _, c := range r.Calls() {
				if c.Argv[0] == "sshd" {
					n++
				}
				if !allowed[c.Argv[0]] {
					t.Errorf("%s runs a program outside engine.Programs: %v", c.Argv[0], c.Argv)
				}
			}
			if n != 1 {
				t.Errorf("sshd -T ran %d times", n)
			}
		})
	}
}

// Every command a probe issues starts with a program that its kind declares,
// and engine.Programs (the allowlist production hands to execx.NewReal) holds
// all of them as bare base names, which is how execx matches. The test
// records the commands through the fake runner and runs nothing on the host.
func TestProbeCommandsAreCoveredByTheAllowlist(t *testing.T) {
	base, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	allowlist := map[string]bool{}
	for _, p := range engine.Programs(base) {
		if strings.ContainsRune(p, '/') {
			t.Errorf("allowlist entry %q is not a bare base name", p)
		}
		allowlist[p] = true
	}
	fx := os.DirFS("../probes/testdata")
	used := map[string]bool{}
	for _, e := range base.Entries() {
		kind, ok := probes.Lookup(e.Kind)
		if !ok {
			t.Fatalf("%s: unknown kind %q", e.ID, e.Kind)
		}
		declared := map[string]bool{}
		for _, p := range kind.Programs() {
			declared[p] = true
		}
		probe, err := kind.Prepare(e.Params)
		if err != nil {
			t.Fatalf("%s: %v", e.ID, err)
		}
		// ss answers from captured output with an unallowed listener and
		// the process names, so the listeners probe runs all its commands;
		// every other command finds no program.
		r := fake.New(fx).
			Add(ssTCP, "ubuntu2404/ss_tcp_mixed").Add(ssUDP, "ubuntu2404/ss_udp_mixed").
			Add(ssTCPp, "ubuntu2404/ssp_tcp_mixed").Add(ssUDPp, "ubuntu2404/ssp_udp_mixed")
		probe.Run(context.Background(), &probes.Env{Runner: r, FS: probestest.MemFS{}})
		if len(r.Calls()) == 0 {
			t.Errorf("%s: the probe ran no command", e.ID)
		}
		for _, c := range r.Calls() {
			prog := c.Argv[0]
			used[prog] = true
			if !declared[prog] {
				t.Errorf("%s runs %q, which kind %s does not declare", e.ID, prog, e.Kind)
			}
			if !allowlist[prog] {
				t.Errorf("%s runs %q, which is not on the allowlist engine.Programs returns", e.ID, prog)
			}
		}
	}
	for prog := range allowlist {
		if !used[prog] {
			t.Errorf("%q is on the allowlist but no probe ever runs it", prog)
		}
	}
}
