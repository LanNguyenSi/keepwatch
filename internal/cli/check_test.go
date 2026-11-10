package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// miniCatalog has a service check (medium), an sshd option check (high) and
// a listeners check (low).
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

var (
	svcArgv  = []string{"systemctl", "is-active", "--", "ssh.service"}
	sshdArgv = []string{"sshd", "-T"}
	ssTCP    = []string{"ss", "-Hltn"}
	ssUDP    = []string{"ss", "-Hlun"}
	ssTCPp   = []string{"ss", "-Hltnp"}
	ssUDPp   = []string{"ss", "-Hlunp"}
)

func res(stdout string, exit int) execx.Result {
	return execx.Result{Stdout: []byte(stdout), ExitCode: exit}
}

// badHost: service down, password login on, one stray listener on 8080.
func badHost() *fake.FakeRunner {
	return fake.New(nil).
		AddResult(svcArgv, res("inactive\n", 3)).
		AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)).
		AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n", 0)).
		AddResult(ssUDP, res("", 0)).
		AddResult(ssTCPp, res("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:* users:((\"web\",pid=1,fd=3))\n", 0)).
		AddResult(ssUDPp, res("", 0))
}

// goodHost: everything as expected.
func goodHost() *fake.FakeRunner {
	return badHost().
		AddResult(svcArgv, res("active\n", 0)).
		AddResult(sshdArgv, res("port 22\npasswordauthentication no\n", 0)).
		AddResult(ssTCP, res(loopback, 0)).
		AddResult(ssTCPp, res(loopback+"", 0))
}

// loopback is a database that listens on the loopback interface only, which
// the mini catalog allows.
const loopback = "LISTEN 0 5 127.0.0.1:5432 0.0.0.0:*\n"

type fixture struct {
	t        *testing.T
	dir      string
	cfgPath  string
	stateDir string
	env      env
	clock    time.Time
}

func newFixture(t *testing.T, runner execx.Runner, extraConfig string) *fixture {
	t.Helper()
	cat, err := catalog.Parse([]byte(miniCatalog))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: t.TempDir(), clock: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	f.stateDir = filepath.Join(f.dir, "state")
	f.cfgPath = filepath.Join(f.dir, "keepwatch.yaml")
	f.writeConfig(extraConfig)
	f.env = env{
		ctx:      context.Background(),
		catalog:  cat,
		runner:   runner,
		fs:       probestest.MemFS{},
		now:      func() time.Time { return f.clock },
		hostname: func() (string, error) { return "testhost", nil },
	}
	return f
}

func (f *fixture) writeConfig(extra string) {
	f.t.Helper()
	body := "state_dir: " + strconv.Quote(f.stateDir) + "\n" + extra
	if err := os.WriteFile(f.cfgPath, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) check(args ...string) (int, string, string) {
	f.t.Helper()
	var out, errb bytes.Buffer
	code := dispatch(f.env, append([]string{"check", "--config", f.cfgPath}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func (f *fixture) statePath() string { return filepath.Join(f.stateDir, state.FileName) }

func (f *fixture) loadState() *state.State {
	f.t.Helper()
	s, err := state.Open(f.stateDir)
	if err != nil {
		f.t.Fatal(err)
	}
	lr, err := s.Load()
	if err != nil || lr.State == nil {
		f.t.Fatalf("state: %+v, %v", lr, err)
	}
	return lr.State
}

func TestCheckFirstRunIsABaseline(t *testing.T) {
	f := newFixture(t, badHost(), "")
	code, out, errb := f.check()
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (the host fails above medium)", code)
	}
	for _, want := range []string{"host testhost", "3 checks: 0 pass, 3 fail", "baseline run, no changes are reported: no previous state (first run)", "[FAIL] t.sshd (high)", "- passwordauthentication:", "- tcp/0.0.0.0:8080:"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "changes (") {
		t.Errorf("a baseline run lists changes:\n%s", out)
	}
	if errb != "" {
		t.Errorf("stderr = %q", errb)
	}
	fi, err := os.Stat(f.statePath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if st := f.loadState(); len(st.Checks) != 3 || st.Find("t.sshd").Status != "fail" {
		t.Errorf("saved state %+v", st)
	}
}

func TestCheckSecondRunWithoutChanges(t *testing.T) {
	f := newFixture(t, badHost(), "")
	f.check()
	f.clock = f.clock.Add(6 * time.Hour)
	code, out, _ := f.check()
	if code != 1 {
		t.Fatalf("exit = %d: the host still fails, the exit code does not depend on the diff", code)
	}
	for _, want := range []string{"changes since the previous run at 2026-11-10T12:00:00Z", "changes (0):", "none", "still failing (3):"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if !f.loadState().RunAt.Equal(f.clock) {
		t.Error("the state was not updated")
	}
}

func TestCheckShowsWhatChanged(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	if code, out, _ := f.check(); code != 0 || !strings.Contains(out, "no findings") {
		t.Fatalf("clean host: exit %d\n%s", code, out)
	}
	// Now the service goes down and a stray listener appears.
	f.env.runner = goodHost().
		AddResult(svcArgv, res("inactive\n", 3)).
		AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\n", 0)).
		AddResult(ssTCPp, res("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"nc\",pid=7,fd=3))\n", 0))
	f.clock = f.clock.Add(time.Hour)
	code, out, _ := f.check()
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"! t.service (medium): now failing (was pass)", "! t.listeners (low): now failing (was pass)", "baseline"} {
		if want == "baseline" {
			if strings.Contains(out, want) {
				t.Errorf("a second run reports a baseline:\n%s", out)
			}
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	// The listener check keeps failing, a second stray listener is a new item.
	f.env.runner = goodHost().
		AddResult(svcArgv, res("inactive\n", 3)).
		AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\nLISTEN 0 5 0.0.0.0:9001 0.0.0.0:*\n", 0)).
		AddResult(ssTCPp, res("", 0))
	f.clock = f.clock.Add(time.Hour)
	_, out, _ = f.check()
	if !strings.Contains(out, "! t.listeners (low): new item: tcp/0.0.0.0:9001") {
		t.Errorf("a new listener is not reported:\n%s", out)
	}
	// Fixing everything is reported as fixed.
	f.env.runner = goodHost()
	f.clock = f.clock.Add(time.Hour)
	code, out, _ = f.check()
	if code != 0 || !strings.Contains(out, "t.service (medium): fixed (was failing)") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestCheckFormats(t *testing.T) {
	f := newFixture(t, badHost(), "")
	_, js, _ := f.check("--format", "json", "--no-state")
	var v struct {
		SchemaVersion int `json:"schema_version"`
		ExitCode      int `json:"exit_code"`
		Host          string
		Counts        struct{ Fail, Total int }
		State         struct{ Used bool }
		Results       []struct {
			CheckID  string `json:"check_id"`
			Evidence []struct{ Subject string }
		}
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, js)
	}
	if v.SchemaVersion != 1 || v.ExitCode != 1 || v.Host != "testhost" || v.Counts.Fail != 3 || v.Counts.Total != 3 || v.State.Used || len(v.Results) != 3 {
		t.Errorf("json report %+v", v)
	}
	_, md, _ := f.check("--format", "markdown", "--no-state")
	for _, want := range []string{"# keepwatch check", "## Findings", "### FAIL ` t.sshd ` (` high `)", "| ` t.sshd ` | ` fail ` | ` high ` |"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
	_, tx, _ := f.check("--format", "text", "--no-state")
	if !strings.HasPrefix(tx, "keepwatch check: host testhost") {
		t.Errorf("text report:\n%s", tx)
	}
}

func TestCheckNoStateNeitherReadsNorWrites(t *testing.T) {
	f := newFixture(t, badHost(), "")
	if code, out, _ := f.check("--no-state"); code != 1 || !strings.Contains(out, "state not used (--no-state)") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(f.stateDir); err == nil {
		t.Error("--no-state created the state directory")
	}
	// An existing state is not read (a corrupt one raises no warning) and
	// not touched.
	f.check()
	if err := os.WriteFile(f.statePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := f.check("--no-state")
	if code != 1 || errb != "" || strings.Contains(out, "warnings") {
		t.Errorf("exit %d stderr %q\n%s", code, errb, out)
	}
	if b, _ := os.ReadFile(f.statePath()); string(b) != "{not json" {
		t.Errorf("--no-state wrote the state: %q", b)
	}
}

func TestCheckWithABrokenStateWarnsAndStartsANewBaseline(t *testing.T) {
	corrupt := map[string]string{
		"garbage":     "\x00\x01 not json",
		"truncated":   `{"schema_version": 1, "run_at": "2026-11-10T1`,
		"empty":       "",
		"wrong shema": `{"schema_version": 99, "run_at": "2026-11-10T12:00:00Z", "checks": []}`,
		"no checks":   `{"schema_version": 1, "run_at": "2026-11-10T12:00:00Z", "checks": []}`,
	}
	for name, content := range corrupt {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, badHost(), "")
			if err := os.MkdirAll(f.stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.statePath(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errb := f.check()
			if code != 1 {
				t.Errorf("exit = %d: a broken state is a warning, the findings decide", code)
			}
			if !strings.Contains(errb, "warning: previous state not used, this run is a new baseline") {
				t.Errorf("stderr = %q", errb)
			}
			for _, want := range []string{"baseline run, no changes are reported: the previous state was not usable (see warnings)", "warnings:", "previous state not used, this run is a new baseline"} {
				if !strings.Contains(out, want) {
					t.Errorf("stdout lacks %q:\n%s", want, out)
				}
			}
			// The next run has a good state again.
			if st := f.loadState(); len(st.Checks) != 3 {
				t.Errorf("state not rewritten: %+v", st)
			}
			_, out, _ = f.check()
			if strings.Contains(out, "baseline") || !strings.Contains(out, "changes (0)") {
				t.Errorf("the run after the recovery:\n%s", out)
			}
		})
	}
}

func TestCheckRefusesToTrustAForeignStateFile(t *testing.T) {
	f := newFixture(t, badHost(), "")
	f.check()
	// The file looks as if somebody else owns it.
	f.env.ownerOf = func(fi fs.FileInfo) (int, error) {
		if fi.IsDir() {
			return os.Getuid(), nil
		}
		return os.Getuid() + 4242, nil
	}
	code, out, _ := f.check()
	if code != 1 || !strings.Contains(out, "baseline run") || !strings.Contains(out, "owned by uid") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestCheckWithAnUnsafeStateDirectoryExits3ButStillReports(t *testing.T) {
	setups := map[string]func(f *fixture){
		"group writable": func(f *fixture) {
			if err := os.MkdirAll(f.stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(f.stateDir, 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(f *fixture) {
			real := filepath.Join(f.dir, "real")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, f.stateDir); err != nil {
				t.Fatal(err)
			}
		},
		"a file": func(f *fixture) {
			if err := os.WriteFile(f.stateDir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, badHost(), "")
			setup(f)
			code, out, errb := f.check()
			if code != 3 {
				t.Errorf("exit = %d, want 3", code)
			}
			if !strings.Contains(errb, "state is neither read nor written") {
				t.Errorf("stderr = %q", errb)
			}
			// The operator still gets the findings.
			if !strings.Contains(out, "[FAIL] t.sshd") || !strings.Contains(out, "exit code 3") {
				t.Errorf("stdout:\n%s", out)
			}
			entries, _ := os.ReadDir(f.stateDir)
			for _, e := range entries {
				if e.Name() == state.FileName {
					t.Error("a state file was written into an untrusted directory")
				}
			}
			// No attempt to save was made, so nothing about saving is reported.
			if strings.Contains(out, "could not be saved") || strings.Contains(errb, "could not be saved") {
				t.Errorf("a save was attempted in an untrusted directory:\n%s\n%s", out, errb)
			}
		})
	}
}

func TestCheckStateThatCannotBeSavedExits3(t *testing.T) {
	f := newFixture(t, badHost(), "")
	if err := os.MkdirAll(filepath.Join(f.statePath(), "inner"), 0o700); err != nil { // a non-empty directory where the file belongs
		t.Fatal(err)
	}
	code, out, errb := f.check()
	if code != 3 {
		t.Errorf("exit = %d, want 3", code)
	}
	if !strings.Contains(errb, "the state could not be saved") || !strings.Contains(out, "the state could not be saved") {
		t.Errorf("stderr = %q\nstdout:\n%s", errb, out)
	}
	if !strings.Contains(out, "[FAIL] t.sshd") {
		t.Errorf("the report is missing:\n%s", out)
	}
	entries, _ := os.ReadDir(f.stateDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".state.json.tmp-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestCheckUsageErrorsExit2(t *testing.T) {
	f := newFixture(t, badHost(), "")
	for _, args := range [][]string{
		{"--format", "xml"}, {"--format", ""}, {"--format", "JSON"},
		{"--fail-on", "urgent"}, {"--fail-on", ""}, {"--fail-on", "MEDIUM"},
		{"--nope"}, {"extra"}, {"--no-state=maybe"},
	} {
		code, out, errb := f.check(args...)
		if code != 2 || errb == "" || out != "" {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, code, out, errb)
		}
	}
	if _, err := os.Stat(f.stateDir); err == nil {
		t.Error("a usage error touched the state")
	}
	var out, errb bytes.Buffer
	if code := dispatch(f.env, []string{"check", "-h"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "-fail-on") || !strings.Contains(out.String(), "-no-state") {
		t.Errorf("check -h: exit %d\n%s", code, out.String())
	}
}

func TestCheckFailOn(t *testing.T) {
	// The bad host fails at medium (service), high (sshd) and low (listeners).
	cases := []struct {
		failOn string
		want   int
	}{{"info", 1}, {"low", 1}, {"medium", 1}, {"high", 1}, {"critical", 0}}
	for _, c := range cases {
		f := newFixture(t, badHost(), "")
		if code, _, _ := f.check("--no-state", "--fail-on", c.failOn); code != c.want {
			t.Errorf("--fail-on %s: exit %d, want %d", c.failOn, code, c.want)
		}
	}
	// Only the low listener check fails: medium is green, low is red.
	only := goodHost().AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n", 0))
	f := newFixture(t, only, "")
	if code, _, _ := f.check("--no-state"); code != 0 {
		t.Errorf("default --fail-on with only a low failure: exit %d", code)
	}
	if code, _, _ := f.check("--no-state", "--fail-on", "low"); code != 1 {
		t.Errorf("--fail-on low with a low failure: exit %d", code)
	}
}

func TestCheckErrorResultCountsAndWarnDoesNot(t *testing.T) {
	// sshd -T cannot be run: the check is an error, not green.
	r := goodHost().AddError(sshdArgv, execx.ErrTimeout)
	f := newFixture(t, r, "")
	code, out, _ := f.check("--no-state")
	if code != 1 || !strings.Contains(out, "[ERROR] t.sshd (high)") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if code, _, _ := f.check("--no-state", "--fail-on", "critical"); code != 0 {
		t.Errorf("error below --fail-on: exit %d", code)
	}
}

func TestCheckInvalidConfigurationExits3(t *testing.T) {
	f := newFixture(t, badHost(), "")
	if err := os.WriteFile(f.cfgPath, []byte("state_dir: relative\nbogus: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := f.check()
	if code != 3 || out != "" || !strings.Contains(errb, "keepwatch.yaml:1: state_dir: must be an absolute path") || !strings.Contains(errb, `unknown key "bogus"`) {
		t.Errorf("exit %d stdout %q stderr %q", code, out, errb)
	}
	// A check id the catalog does not have is caught before any probe runs.
	f.writeConfig("checks:\n  no.such_check:\n    enabled: false\n")
	r := badHost()
	f.env.runner = r
	code, _, errb = f.check()
	if code != 3 || !strings.Contains(errb, "no.such_check: unknown check id") || len(r.Calls()) != 0 {
		t.Errorf("exit %d stderr %q, %d probe calls", code, errb, len(r.Calls()))
	}
	// A missing configuration file.
	var o, e bytes.Buffer
	if code := dispatch(f.env, []string{"check", "--config", filepath.Join(f.dir, "missing.yaml")}, &o, &e); code != 3 || e.Len() == 0 {
		t.Errorf("missing config: exit %d stderr %q", code, e.String())
	}
}

func TestCheckInterruptedRunReportsNothingAndKeepsTheState(t *testing.T) {
	f := newFixture(t, badHost(), "")
	f.check()
	before, _ := os.ReadFile(f.statePath())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.env.ctx = ctx
	f.clock = f.clock.Add(time.Hour)
	code, out, errb := f.check()
	if code != 3 || out != "" || !strings.Contains(errb, "interrupted") {
		t.Errorf("exit %d stdout %q stderr %q", code, out, errb)
	}
	if after, _ := os.ReadFile(f.statePath()); string(after) != string(before) {
		t.Error("an interrupted run changed the state")
	}
}

func TestCheckRedactsAndEscapesEveryFormat(t *testing.T) {
	// An exception reason from the configuration carries a terminal escape
	// and a secret, and a configured pattern hides a host name.
	cfg := "exceptions:\n  - check: t.listeners\n    match: tcp/0.0.0.0:8080\n    reason: \"jump \\e[2J\\e]0;owned\\a password=hunter2 secret-host-7\"\n    expires: 2099-12-31\n" +
		"redact:\n  patterns:\n    - 'secret-host-[0-9]+'\n"
	for _, format := range []string{"text", "json", "markdown"} {
		t.Run(format, func(t *testing.T) {
			f := newFixture(t, badHost(), cfg)
			_, out, errb := f.check("--format", format)
			for _, bad := range []string{"\x1b", "\x07", "hunter2", "secret-host-7"} {
				if strings.Contains(out, bad) || strings.Contains(errb, bad) {
					t.Errorf("%q in the output:\n%s\n%s", bad, out, errb)
				}
			}
			if !strings.Contains(out, "jump") || !strings.Contains(out, "[REDACTED]") || !strings.Contains(out, `\x1b`) {
				t.Errorf("the reason is missing or not escaped:\n%s", out)
			}
			// The state holds no text from the exception reason.
			b, _ := os.ReadFile(f.statePath())
			for _, bad := range []string{"hunter2", "secret-host-7", "jump"} {
				if strings.Contains(string(b), bad) {
					t.Errorf("%q in the state file", bad)
				}
			}
		})
	}
}

func TestCheckStateKeysComeFromTheRawSubject(t *testing.T) {
	f := newFixture(t, goodHost().
		AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n", 0)).
		AddResult(ssTCPp, res("", 0)), "")
	f.check()
	st := f.loadState()
	c := st.Find("t.listeners")
	if len(c.Items) != 1 || c.Items[0].Key != state.SubjectKey("tcp/0.0.0.0:8080") {
		t.Fatalf("state %+v", c)
	}
}

func TestCheckNilRunnerBuildsTheRealOne(t *testing.T) {
	// With no injected runner `check` builds the real allowlisted runner.
	// Every program of the mini catalog is absent or fails on a test host in
	// some way, so only the plumbing is asserted: it runs and reports.
	f := newFixture(t, nil, "")
	f.env.runner = nil
	var out, errb bytes.Buffer
	code := dispatch(f.env, []string{"check", "--config", f.cfgPath, "--no-state", "--format", "json"}, &out, &errb)
	if code != 0 && code != 1 {
		t.Fatalf("exit %d stderr %s", code, errb.String())
	}
	var v struct{ Counts struct{ Total int } }
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Counts.Total != 3 {
		t.Errorf("report %v: %s", err, out.String())
	}
}

func TestCheckBrokenOutputExits3(t *testing.T) {
	f := newFixture(t, badHost(), "")
	var errb bytes.Buffer
	code := dispatch(f.env, []string{"check", "--config", f.cfgPath, "--no-state"}, failingWriter{}, &errb)
	if code != 3 || !strings.Contains(errb.String(), "cannot write the report") {
		t.Errorf("exit %d stderr %q", code, errb.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestCheckStateSubjectsAreRedacted(t *testing.T) {
	// The subject of an expired exception is built from its configured
	// match, so it can hold anything. The state keeps the cleaned text.
	cfg := "exceptions:\n  - check: t.listeners\n    match: \"password=hunter2 \\e[2J\"\n    reason: old\n    expires: 2020-01-01\n"
	f := newFixture(t, badHost(), cfg)
	_, out, _ := f.check()
	b, err := os.ReadFile(f.statePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"hunter2", "\x1b"} {
		if strings.Contains(string(b), bad) || strings.Contains(out, bad) {
			t.Errorf("%q in the state or the report", bad)
		}
	}
	if !strings.Contains(string(b), "t.listeners password=[REDACTED] ") {
		t.Errorf("state holds:\n%s", b)
	}
	c := f.loadState().Find("exception_expired")
	if c == nil || len(c.Items) != 1 || c.Status != "fail" {
		t.Errorf("exception_expired in the state: %+v", c)
	}
}

func TestCheckUnknownHostname(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	f.env.hostname = func() (string, error) { return "", os.ErrNotExist }
	if _, out, _ := f.check("--no-state"); !strings.Contains(out, "host unknown,") {
		t.Errorf("stdout:\n%s", out)
	}
}

func TestCheckConfigErrorsArePrintedOnePerLine(t *testing.T) {
	f := newFixture(t, badHost(), "")
	if err := os.WriteFile(f.cfgPath, []byte("state_dir: relative\nbogus: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, errb := f.check()
	lines := strings.Split(strings.TrimRight(errb, "\n"), "\n")
	if len(lines) != 2 || strings.Contains(errb, `\n`) {
		t.Errorf("stderr should hold one error per line:\n%q", errb)
	}
}

func TestCheckUsesTheBaseCatalogByDefault(t *testing.T) {
	f := newFixture(t, fake.New(nil), "")
	f.env.catalog = nil
	base, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	dispatch(f.env, []string{"check", "--config", f.cfgPath, "--no-state", "--format", "json"}, &out, &errb)
	var v struct{ Counts struct{ Total int } }
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Counts.Total != len(base.Entries()) || v.Counts.Total < 12 {
		t.Errorf("total = %d, base catalog has %d (%v): %s", v.Counts.Total, len(base.Entries()), err, errb.String())
	}
}

func TestCheckStateDirectoryThatCannotBeOpenedExits3(t *testing.T) {
	f := newFixture(t, badHost(), "")
	if err := os.WriteFile(f.cfgPath, []byte("state_dir: /\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errb := f.check()
	if code != 3 || !strings.Contains(errb, "state is neither read nor written") || !strings.Contains(out, "[FAIL] t.sshd") {
		t.Errorf("exit %d stderr %q\n%s", code, errb, out)
	}
}

// cancelRunner cancels the run's context when the first program is run.
type cancelRunner struct {
	inner  execx.Runner
	cancel context.CancelFunc
	calls  int
}

func (c *cancelRunner) Run(ctx context.Context, argv []string, o execx.Opts) (execx.Result, error) {
	c.calls++
	if c.cancel != nil {
		c.cancel()
	}
	return c.inner.Run(ctx, argv, o)
}

func TestCheckStopsRunningProbesWhenInterrupted(t *testing.T) {
	full := &cancelRunner{inner: badHost()}
	f := newFixture(t, full, "")
	f.check("--no-state")
	ctx, cancel := context.WithCancel(context.Background())
	cut := &cancelRunner{inner: badHost(), cancel: cancel}
	f = newFixture(t, cut, "")
	f.env.ctx = ctx
	code, _, _ := f.check("--no-state")
	if code != 3 || cut.calls == 0 || cut.calls >= full.calls {
		t.Errorf("exit %d, %d probe calls after the interrupt, %d for a full run", code, cut.calls, full.calls)
	}
}

func TestCheckMessagesAreCleaned(t *testing.T) {
	esc := "\x1b[2J"
	t.Run("warning about the state", func(t *testing.T) {
		f := newFixture(t, badHost(), "")
		f.stateDir = filepath.Join(f.dir, "ev"+esc+"il", "state")
		f.writeConfig("")
		if err := os.MkdirAll(f.stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(f.dir, "elsewhere"), f.statePath()); err != nil {
			t.Fatal(err)
		}
		code, out, errb := f.check()
		if code != 1 || !strings.Contains(errb, "is a symlink") {
			t.Fatalf("exit %d stderr %q", code, errb)
		}
		if strings.Contains(errb, "\x1b") || strings.Contains(out, "\x1b") || !strings.Contains(errb, `ev\x1b[2Jil`) {
			t.Errorf("stderr %q\nstdout:\n%s", errb, out)
		}
	})
	t.Run("error of the engine", func(t *testing.T) {
		f := newFixture(t, badHost(), "checks:\n  \"no\\e[2Jsuch.id\":\n    enabled: false\n")
		code, _, errb := f.check()
		if code != 3 || strings.Contains(errb, "\x1b") || !strings.Contains(errb, `no\x1b[2Jsuch.id: unknown check id`) {
			t.Errorf("exit %d stderr %q", code, errb)
		}
	})
	t.Run("error of the configuration", func(t *testing.T) {
		f := newFixture(t, badHost(), "")
		dir := filepath.Join(f.dir, "ev"+esc+"il")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := filepath.Join(dir, "keepwatch.yaml")
		if err := os.WriteFile(cfg, []byte("bogus: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		code := dispatch(f.env, []string{"check", "--config", cfg}, &out, &errb)
		if code != 3 || strings.Contains(errb.String(), "\x1b") || !strings.Contains(errb.String(), `ev\x1b[2Jil`) {
			t.Errorf("exit %d stderr %q", code, errb.String())
		}
	})
}
