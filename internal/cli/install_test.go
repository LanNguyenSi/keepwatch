package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// hostRig is a fake host for the commands that act on it. Tests never touch
// the real host: opsFor is replaced for the length of the test.
type hostRig struct {
	fs       *installtest.MemFS
	sd       *installtest.Systemd
	uid      int
	exe      string
	cfg      *config.Config
	cfgErr   error
	resolver map[string]error
	state    doctor.StateStatus
}

type missingResolver map[string]error

func (m missingResolver) Resolve(n string) (string, error) {
	if err, ok := m[n]; ok {
		return "", err
	}
	return "/usr/bin/" + n, nil
}

func newHost(t *testing.T) *hostRig {
	t.Helper()
	h := &hostRig{fs: installtest.NewMemFS(), sd: installtest.NewSystemd(), exe: "/usr/local/bin/keepwatch", resolver: map[string]error{}}
	h.cfg = &config.Config{Sources: config.Sources{Main: "/etc/keepwatch/keepwatch.yaml"}, StateDir: "/var/lib/keepwatch", Checks: map[string]config.Check{}}
	h.state = doctor.StateStatus{Exists: true}
	h.fs.AddDir("/run/sshd", 0o755, 0)
	old := opsFor
	opsFor = func(env) hostOps {
		return hostOps{
			fs: h.fs, runner: h.sd.Runner, geteuid: func() int { return h.uid }, exe: func() (string, error) { return h.exe, nil },
			loadConfig: func(string) (*config.Config, error) { return h.cfg, h.cfgErr },
			state:      func(string) doctor.StateStatus { return h.state }, resolver: missingResolver(h.resolver),
		}
	}
	t.Cleanup(func() { opsFor = old })
	return h
}

func (h *hostRig) withConfigFile() { h.fs.AddFile("/etc/keepwatch/keepwatch.yaml", 0o644, 0, "{}\n") }

func runCmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	e := env{ctx: context.Background()}
	return dispatch(e, args, &out, &errb), out.String(), errb.String()
}

func TestInstallFlagValidation(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"interval too short", []string{"--interval", "1m"}, "--interval"},
		{"interval with a newline", []string{"--interval", "6h\nExecStartPre=/bin/sh"}, "--interval"},
		{"interval with a percent", []string{"--interval", "6%h"}, "--interval"},
		{"interval compound", []string{"--interval", "1h30m"}, "--interval"},
		{"interval empty", []string{"--interval", ""}, "--interval"},
		{"weekly with a newline", []string{"--weekly-report", "Mon 08:00\nExecStart=/bin/sh"}, "--weekly-report"},
		{"weekly lower case", []string{"--weekly-report", "mon 08:00"}, "--weekly-report"},
		{"weekly unquoted: the time is an extra argument", []string{"--weekly-report", "Mon", "08:00"}, `unexpected argument "08:00"`},
		{"weekly out of range", []string{"--weekly-report", "Mon 25:00"}, "--weekly-report"},
		{"unknown flag", []string{"--bogus"}, "bogus"},
		{"extra argument", []string{"now"}, "unexpected argument"},
	}
	for _, c := range cases {
		for _, extra := range [][]string{nil, {"--print"}, {"--dry-run"}} {
			h := newHost(t)
			code, stdout, stderr := runCmd(append([]string{"install"}, append(append([]string{}, c.args...), extra...)...)...)
			if code != ExitUsage || !strings.Contains(stderr, c.want) {
				t.Errorf("%s %v: exit = %d stderr = %q, want 2 mentioning %q", c.name, extra, code, stderr, c.want)
			}
			if stdout != "" || len(h.fs.Log) != 0 || len(h.sd.Runner.Calls) != 0 {
				t.Errorf("%s: a rejected command did something: stdout %q log %v calls %v", c.name, stdout, h.fs.Log, h.sd.Runner.Calls)
			}
		}
	}
}

func TestInstallPrint(t *testing.T) {
	h := newHost(t)
	h.uid = 1000 // printing needs no privileges
	h.withConfigFile()
	h.cfg.StateDir = "/srv/kw/state"
	code, stdout, stderr := runCmd("install", "--print", "--interval", "30m", "--weekly-report", "Sun 23:59")
	if code != ExitOK || stderr != "" {
		t.Fatalf("exit = %d stderr = %q", code, stderr)
	}
	for _, want := range []string{
		"# ===== keepwatch-check.service =====", "# ===== keepwatch-report.timer =====",
		"ExecStart=/usr/local/bin/keepwatch check --config /etc/keepwatch/keepwatch.yaml",
		"ExecStart=/usr/local/bin/keepwatch report --weekly --config /etc/keepwatch/keepwatch.yaml",
		"ReadWritePaths=/srv/kw/state", "OnUnitActiveSec=30min", "OnCalendar=Sun *-*-* 23:59:00",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("--print output lacks %q:\n%s", want, stdout)
		}
	}
	if len(h.fs.Log) != 0 || len(h.sd.Runner.Calls) != 0 {
		t.Errorf("--print changed or ran something: %v %v", h.fs.Log, h.sd.Runner.Calls)
	}
}

func TestInstallPrintRefusesAnUnsafeBinaryPath(t *testing.T) {
	h := newHost(t)
	for _, exe := range []string{"/tmp/keepwatch", "/home/me/my tools/keepwatch", "/opt/kw%n/keepwatch"} {
		h.exe = exe
		if code, stdout, stderr := runCmd("install", "--print"); code != ExitUsage || stdout != "" || stderr == "" {
			t.Errorf("%s: exit = %d stdout %q stderr %q", exe, code, stdout, stderr)
		}
	}
}

func TestInstallUsesThePathOfTheConfigurationFile(t *testing.T) {
	h := newHost(t)
	code, stdout, _ := runCmd("install", "--print", "--config", "/srv/kw/../kw/main.yaml")
	if code != ExitOK || !strings.Contains(stdout, "--config /srv/kw/main.yaml\n") {
		t.Errorf("exit = %d\n%s", code, stdout)
	}
	_ = h
	if code, _, stderr := runCmd("install", "--print", "--config", "/srv/my config.yaml"); code != ExitUsage || !strings.Contains(stderr, "configuration file") {
		t.Errorf("exit = %d stderr = %q", code, stderr)
	}
}

func TestInstallEndToEndOnTheFakeHost(t *testing.T) {
	h := newHost(t)
	h.withConfigFile()
	code, stdout, stderr := runCmd("install")
	if code != ExitOK {
		t.Fatalf("exit = %d stderr = %q\n%s", code, stderr, stdout)
	}
	if !h.sd.Enabled[install.CheckTimer] || !h.sd.Enabled[install.ReportTimer] {
		t.Error("the timers are not enabled")
	}
	code, stdout, _ = runCmd("install")
	if code != ExitOK || !strings.Contains(stdout, "already installed, nothing to change") {
		t.Errorf("second run: exit = %d\n%s", code, stdout)
	}
	code, stdout, _ = runCmd("uninstall")
	if code != ExitOK || h.fs.Exists("/etc/systemd/system/"+install.CheckTimer) {
		t.Errorf("uninstall: exit = %d\n%s", code, stdout)
	}
}

func TestInstallExitCodes(t *testing.T) {
	t.Run("not root is 2", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.uid = 1000
		if code, _, stderr := runCmd("install"); code != ExitUsage || !strings.Contains(stderr, "root") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
	})
	t.Run("a file without the marker is 2 and nothing is written", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.fs.AddFile("/etc/systemd/system/"+install.CheckService, 0o644, 0, "[Unit]\n")
		code, _, stderr := runCmd("install")
		if code != ExitUsage || !strings.Contains(stderr, install.CheckService) || !strings.Contains(stderr, "not written by keepwatch") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
		if len(h.fs.Log) != 0 {
			t.Errorf("wrote %v", h.fs.Log)
		}
	})
	t.Run("a binary a user can change is 2 and nothing is written", func(t *testing.T) {
		h := newHost(t)
		h.fs.AddFile("/usr/local/bin/keepwatch", 0o755, 1000, "")
		code, _, stderr := runCmd("install")
		if code != ExitUsage || !strings.Contains(stderr, "cannot be trusted to run as root") || !strings.Contains(stderr, "install -o root -g root") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
		if len(h.fs.Log) != 0 {
			t.Errorf("wrote %v", h.fs.Log)
		}
	})
	t.Run("a configuration file or state_dir the sandbox hides is 2 and nothing is written", func(t *testing.T) {
		h := newHost(t)
		h.fs.AddDir("/tmp", 0o1777, 0)
		h.fs.AddDir("/tmp/kwc", 0o755, 0)
		h.fs.AddFile("/tmp/kwc/keepwatch.yaml", 0o644, 0, "{}\n")
		code, _, stderr := runCmd("install", "--config", "/tmp/kwc/keepwatch.yaml")
		if code != ExitUsage || !strings.Contains(stderr, "under /tmp") || !strings.Contains(stderr, "put it elsewhere") {
			t.Errorf("config under /tmp: exit = %d stderr = %q", code, stderr)
		}
		h.cfg.StateDir = "/tmp/kwstate"
		h.withConfigFile()
		code, _, stderr = runCmd("install")
		if code != ExitUsage || !strings.Contains(stderr, "state_dir") || !strings.Contains(stderr, "under /tmp") {
			t.Errorf("state_dir under /tmp: exit = %d stderr = %q", code, stderr)
		}
		if len(h.fs.Log) != 0 || len(h.sd.Runner.Calls) != 0 {
			t.Errorf("a refused install did something: %v %v", h.fs.Log, h.sd.Runner.Calls)
		}
	})
	t.Run("a failing systemctl is 1", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.sd.Fail["enable"] = execx.Result{ExitCode: 1, Stderr: []byte("denied")}
		if code, _, stderr := runCmd("install"); code != ExitError || !strings.Contains(stderr, "denied") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
	})
	t.Run("an invalid configuration is 2 and listed", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.cfgErr = config.Errors{{File: "/etc/keepwatch/keepwatch.yaml", Line: 4, Msg: "unknown key"}}
		code, _, stderr := runCmd("install")
		if code != ExitUsage || !strings.Contains(stderr, "keepwatch.yaml:4") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
		if len(h.fs.Log) != 0 {
			t.Errorf("wrote %v", h.fs.Log)
		}
	})
	t.Run("a missing configuration is refused with exit 2 and the hint, also as a dry run", func(t *testing.T) {
		h := newHost(t)
		for _, args := range [][]string{{"install"}, {"install", "--dry-run"}} {
			code, stdout, stderr := runCmd(args...)
			if code != ExitUsage || !strings.Contains(stderr, "keepwatch init") || !strings.Contains(stderr, "does not exist") || stdout != "" {
				t.Errorf("%v: exit = %d stderr = %q stdout = %q", args, code, stderr, stdout)
			}
		}
		if len(h.fs.Log) != 0 || len(h.sd.Runner.Calls) != 0 {
			t.Errorf("a refused install did something: %v %v", h.fs.Log, h.sd.Runner.Calls)
		}
	})
	t.Run("dry run lists and changes nothing", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.uid = 1000
		code, stdout, _ := runCmd("install", "--dry-run")
		if code != ExitOK || !strings.Contains(stdout, "would create") || len(h.fs.Log) != 0 {
			t.Errorf("exit = %d log %v\n%s", code, h.fs.Log, stdout)
		}
	})
}

func TestUninstallCommand(t *testing.T) {
	t.Run("flags", func(t *testing.T) {
		newHost(t)
		for _, args := range [][]string{{"uninstall", "--bogus"}, {"uninstall", "now"}, {"uninstall", "--purge=maybe"}} {
			if code, _, _ := runCmd(args...); code != ExitUsage {
				t.Errorf("%v: exit = %d, want 2", args, code)
			}
		}
	})
	t.Run("purge uses the state_dir of the configuration", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.cfg.StateDir = "/srv/state"
		h.fs.AddDir("/srv", 0o755, 0)
		h.fs.AddDir("/srv/state", 0o700, 0)
		h.fs.AddFile("/srv/state/state.json", 0o600, 0, "{}")
		h.fs.AddDir("/var/lib/keepwatch", 0o700, 0)
		h.fs.AddFile("/var/lib/keepwatch/state.json", 0o600, 0, "{}")
		if code, stdout, stderr := runCmd("uninstall", "--purge"); code != ExitOK {
			t.Fatalf("exit = %d stderr = %q\n%s", code, stderr, stdout)
		}
		if h.fs.Exists("/srv/state/state.json") || !h.fs.Exists("/var/lib/keepwatch/state.json") {
			t.Error("--purge did not follow state_dir")
		}
	})
	t.Run("purge with an unreadable configuration falls back to the default and says so", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		h.cfgErr = config.Errors{{File: "/etc/keepwatch/keepwatch.yaml", Line: 1, Msg: "bad"}}
		h.fs.AddDir("/var/lib/keepwatch", 0o700, 0)
		h.fs.AddFile("/var/lib/keepwatch/state.json", 0o600, 0, "{}")
		code, stdout, _ := runCmd("uninstall", "--purge")
		if code != ExitOK || !strings.Contains(stdout, "warning") || h.fs.Exists("/var/lib/keepwatch/state.json") {
			t.Errorf("exit = %d stdout = %q", code, stdout)
		}
	})
	t.Run("purge of a configuration that is not keepwatch's is refused with exit 2 and leaves it", func(t *testing.T) {
		h := newHost(t)
		h.fs.AddDir("/etc/otherapp", 0o755, 0)
		h.fs.AddFile("/etc/otherapp/otherapp.yaml", 0o644, 0, "a: 1\n")
		h.fs.AddFile("/etc/otherapp/empty.yaml", 0o644, 0, "")
		for _, f := range []string{"otherapp.yaml", "empty.yaml"} {
			code, stdout, stderr := runCmd("uninstall", "--purge", "--config", "/etc/otherapp/"+f)
			if code != ExitUsage || !strings.Contains(stderr, "by hand") || !strings.Contains(stdout, "left /etc/otherapp/"+f) {
				t.Errorf("%s: exit = %d stderr = %q stdout = %q", f, code, stderr, stdout)
			}
			if !h.fs.Exists("/etc/otherapp/"+f) || !h.fs.Exists("/etc/otherapp") {
				t.Errorf("%s was removed", f)
			}
		}
	})
	t.Run("purge follows the --config recorded in the units, and an explicit other --config is refused", func(t *testing.T) {
		h := newHost(t)
		h.fs.AddDir("/srv", 0o755, 0)
		h.fs.AddDir("/srv/kw", 0o755, 0)
		h.fs.AddFile("/srv/kw/main.yaml", 0o644, 0, "{}\n")
		h.fs.AddFile("/srv/kw/other.yaml", 0o644, 0, "{}\n")
		h.cfg.StateDir = "/srv/kw/state"
		if code, _, stderr := runCmd("install", "--config", "/srv/kw/main.yaml"); code != ExitOK {
			t.Fatalf("install: %d %q", code, stderr)
		}
		if code, _, stderr := runCmd("uninstall", "--purge", "--config", "/srv/kw/other.yaml"); code != ExitUsage || !strings.Contains(stderr, "by hand") {
			t.Errorf("another --config: exit = %d stderr = %q", code, stderr)
		}
		if !h.fs.Exists("/srv/kw/other.yaml") || h.fs.Exists("/srv/kw/state/state.json") || h.fs.Exists("/etc/systemd/system/"+install.CheckTimer) {
			t.Error("the refusal did not leave the foreign file or did not do the provable work")
		}
		// The units are gone now; the recorded path is no longer known.
		if code, _, _ := runCmd("uninstall", "--purge", "--config", "/srv/kw/main.yaml"); code != ExitUsage || !h.fs.Exists("/srv/kw/main.yaml") {
			t.Errorf("after the units are gone a custom --config is not proven: exit = %d", code)
		}
	})
	t.Run("purge without --config uses the recorded one", func(t *testing.T) {
		h := newHost(t)
		h.fs.AddDir("/srv", 0o755, 0)
		h.fs.AddDir("/srv/kw", 0o755, 0)
		h.fs.AddFile("/srv/kw/main.yaml", 0o644, 0, "{}\n")
		h.cfg.StateDir = "/srv/kw/state"
		if code, _, stderr := runCmd("install", "--config", "/srv/kw/main.yaml"); code != ExitOK {
			t.Fatalf("install: %d %q", code, stderr)
		}
		if code, stdout, stderr := runCmd("uninstall", "--purge"); code != ExitOK || h.fs.Exists("/srv/kw/main.yaml") {
			t.Errorf("exit = %d stderr = %q\n%s", code, stderr, stdout)
		}
	})
	t.Run("not root is 2", func(t *testing.T) {
		h := newHost(t)
		h.uid = 1000
		if code, _, _ := runCmd("uninstall"); code != ExitUsage {
			t.Errorf("exit = %d", code)
		}
	})
}

func TestDoctorCommand(t *testing.T) {
	healthy := func(t *testing.T) *hostRig {
		h := newHost(t)
		h.withConfigFile()
		h.cfg.Notify.Ntfy = &config.Ntfy{URL: "https://ntfy.example.org", Topic: "x"}
		if code, _, stderr := runCmd("install"); code != ExitOK {
			t.Fatalf("install: %d %q", code, stderr)
		}
		return h
	}
	t.Run("healthy is 0", func(t *testing.T) {
		healthy(t)
		code, stdout, stderr := runCmd("doctor")
		if code != ExitOK || !strings.Contains(stdout, "doctor: all ok") {
			t.Errorf("exit = %d stderr = %q\n%s", code, stderr, stdout)
		}
	})
	t.Run("a problem is 1", func(t *testing.T) {
		h := healthy(t)
		h.fs.Remove("/run/sshd")
		code, stdout, _ := runCmd("doctor")
		if code != ExitError || !strings.Contains(stdout, "/run/sshd does not exist") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
	t.Run("warnings alone are 0", func(t *testing.T) {
		h := healthy(t)
		h.resolver["fail2ban-client"] = execx.ErrNotFound
		code, stdout, _ := runCmd("doctor")
		if code != ExitOK || !strings.Contains(stdout, "will be skipped") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
	t.Run("the check ids of a missing program are named", func(t *testing.T) {
		h := healthy(t)
		h.resolver["ss"] = execx.ErrNotFound
		_, stdout, _ := runCmd("doctor")
		if !strings.Contains(stdout, "network.listeners: ss not found") {
			t.Errorf("\n%s", stdout)
		}
	})
	t.Run("flags", func(t *testing.T) {
		newHost(t)
		for _, args := range [][]string{{"doctor", "--bogus"}, {"doctor", "extra"}} {
			if code, _, _ := runCmd(args...); code != ExitUsage {
				t.Errorf("%v: exit = %d, want 2", args, code)
			}
		}
	})
}

// withNtfy configures notify.ntfy on the fake host and returns the fake server.
func withNtfy(t *testing.T, h *hostRig) *fakeNtfy {
	t.Helper()
	n := newFakeNtfy(t)
	h.cfg.Notify.Ntfy = &config.Ntfy{URL: n.srv.URL, Topic: "kw-test"}
	return n
}

// installedNtfyHost is a host with notify.ntfy configured and the units
// installed, so that doctor has nothing else to say.
func installedNtfyHost(t *testing.T) (*hostRig, *fakeNtfy) {
	t.Helper()
	h := newHost(t)
	n := withNtfy(t, h)
	h.withConfigFile()
	if code, _, stderr := runCmd("install"); code != ExitOK {
		t.Fatalf("install: %d %q", code, stderr)
	}
	return h, n
}

func runDoctorEnv(h *hostRig, e env, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	if e.ctx == nil {
		e.ctx = context.Background()
	}
	return dispatch(e, append([]string{"doctor"}, args...), &out, &errb), out.String(), errb.String()
}

type failingNotifier struct{ err error }

func (f failingNotifier) Send(context.Context, notify.Message) error { return f.err }

func TestDoctorSendTest(t *testing.T) {
	quick := []notify.Option{notify.WithBackoff(0)}
	t.Run("delivers one short test message and exits 0", func(t *testing.T) {
		h, n := installedNtfyHost(t)
		logs := len(h.fs.Log)
		code, stdout, stderr := runDoctorEnv(h, env{notifyOpts: quick}, "--send-test")
		if code != ExitOK || !strings.Contains(stdout, "send-test: the test message was delivered") {
			t.Fatalf("exit = %d stderr = %q\n%s", code, stderr, stdout)
		}
		if n.count() != 1 {
			t.Fatalf("%d requests, want 1", n.count())
		}
		r := n.last()
		if r.Method != "POST" || r.Path != "/kw-test" || !strings.Contains(r.Body, "doctor --send-test") || len(r.Body) > 300 {
			t.Errorf("request = %+v", r)
		}
		if got := r.Header.Get("Title"); got != "keepwatch test message" {
			t.Errorf("title = %q", got)
		}
		if p := r.Header.Get("Priority"); p != "2" || r.Header.Get("Tags") != "keepwatch" {
			t.Errorf("priority %q tags %q", p, r.Header.Get("Tags"))
		}
		if len(h.fs.Log) != logs {
			t.Errorf("--send-test wrote: %v", h.fs.Log[logs:])
		}
	})
	t.Run("without --send-test nothing is sent", func(t *testing.T) {
		h, n := installedNtfyHost(t)
		runDoctorEnv(h, env{notifyOpts: quick})
		if n.count() != 0 {
			t.Errorf("%d requests without --send-test", n.count())
		}
	})
	t.Run("a refused delivery is a problem with the reason, exit 1, no secret", func(t *testing.T) {
		h, n := installedNtfyHost(t)
		n.answer(401)
		code, stdout, _ := runDoctorEnv(h, env{notifyOpts: quick}, "--send-test")
		if code != ExitError || !strings.Contains(stdout, "PROBLEM send-test: the test message was not delivered: ntfy:") || strings.Count(stdout, "PROBLEM") != 1 {
			t.Fatalf("exit = %d\n%s", code, stdout)
		}
		line := stdout[strings.Index(stdout, "PROBLEM send-test"):]
		if strings.Contains(line, n.srv.URL) || strings.Contains(line, "kw-test") {
			t.Errorf("the server address or the topic is in the finding:\n%s", line)
		}
	})
	t.Run("a server that is down is a problem", func(t *testing.T) {
		h, n := installedNtfyHost(t)
		n.srv.Close()
		code, stdout, _ := runDoctorEnv(h, env{notifyOpts: append(quick, notify.WithTimeout(time.Second))}, "--send-test")
		if code != ExitError || !strings.Contains(stdout, "PROBLEM send-test: the test message was not delivered") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
	t.Run("without notify.ntfy there is nothing to send to", func(t *testing.T) {
		h := newHost(t)
		code, stdout, _ := runDoctorEnv(h, env{}, "--send-test")
		if code != ExitError || !strings.Contains(stdout, "PROBLEM send-test: no test message sent: notify.ntfy is not configured") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
	t.Run("an invalid configuration sends nothing", func(t *testing.T) {
		h := newHost(t)
		n := withNtfy(t, h)
		h.cfgErr = config.Errors{{File: "/etc/keepwatch/keepwatch.yaml", Line: 2, Msg: "bad"}}
		code, stdout, _ := runDoctorEnv(h, env{notifyOpts: quick}, "--send-test")
		if code != ExitError || n.count() != 0 || !strings.Contains(stdout, "PROBLEM send-test: no test message sent: the configuration is not valid") {
			t.Errorf("exit = %d requests = %d\n%s", code, n.count(), stdout)
		}
	})
	t.Run("the redactor runs over the error", func(t *testing.T) {
		h, _ := installedNtfyHost(t)
		h.cfg.Redact.Patterns = []string{"secret-[0-9]+"}
		code, stdout, _ := runDoctorEnv(h, env{notifier: failingNotifier{errors.New("boom secret-12345")}}, "--send-test")
		if code != ExitError || strings.Contains(stdout, "secret-12345") || !strings.Contains(stdout, "not delivered: boom [REDACTED]") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
	t.Run("the redactor runs over the message", func(t *testing.T) {
		h := newHost(t)
		n := withNtfy(t, h)
		h.cfg.Redact.Patterns = []string{"doctor"}
		runDoctorEnv(h, env{notifyOpts: quick}, "--send-test")
		if strings.Contains(n.last().Body, "doctor") {
			t.Errorf("body = %q", n.last().Body)
		}
	})
}

// The scheduled runs notify exactly when notify.ntfy is configured in the
// configuration install validated.
func TestInstallAddsNotifyOnlyWhenConfigured(t *testing.T) {
	unitText := func(h *hostRig, name string) string {
		s, _ := h.fs.Content("/etc/systemd/system/" + name)
		return s
	}
	t.Run("configured", func(t *testing.T) {
		h := newHost(t)
		withNtfy(t, h)
		h.withConfigFile()
		code, stdout, stderr := runCmd("install")
		if code != ExitOK {
			t.Fatalf("exit = %d %q", code, stderr)
		}
		if !strings.Contains(unitText(h, install.CheckService), " check --notify --config ") || !strings.Contains(unitText(h, install.ReportService), " report --weekly --notify --config ") {
			t.Errorf("the services do not notify:\n%s", unitText(h, install.CheckService))
		}
		if !strings.Contains(stdout, "the scheduled runs notify") {
			t.Errorf("no word about notifying:\n%s", stdout)
		}
		if code, stdout, _ := runCmd("doctor"); code != ExitOK || strings.Contains(stdout, "warn    units") {
			t.Errorf("doctor after install: exit = %d\n%s", code, stdout)
		}
	})
	t.Run("not configured", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		code, stdout, _ := runCmd("install")
		if code != ExitOK {
			t.Fatalf("exit = %d", code)
		}
		for _, n := range []string{install.CheckService, install.ReportService} {
			if strings.Contains(unitText(h, n), "--notify") {
				t.Errorf("%s notifies although notify.ntfy is not configured", n)
			}
		}
		if !strings.Contains(stdout, "the scheduled runs do not notify: notify.ntfy is not configured") {
			t.Errorf("no word about not notifying:\n%s", stdout)
		}
	})
	t.Run("ntfy added later: install again updates the services, and doctor warned before", func(t *testing.T) {
		h := newHost(t)
		h.withConfigFile()
		if code, _, _ := runCmd("install"); code != ExitOK {
			t.Fatal("install failed")
		}
		withNtfy(t, h)
		code, stdout, _ := runCmd("doctor")
		if code != ExitError || !strings.Contains(stdout, "PROBLEM units: notify.ntfy is configured, but /etc/systemd/system/keepwatch-check.service runs without --notify") {
			t.Fatalf("doctor: exit = %d\n%s", code, stdout)
		}
		h.sd.Runner.Calls = nil
		code, stdout, _ = runCmd("install")
		if code != ExitOK || !strings.Contains(stdout, "update /etc/systemd/system/"+install.CheckService) || !strings.Contains(unitText(h, install.CheckService), "--notify") {
			t.Fatalf("install: exit = %d\n%s", code, stdout)
		}
		for _, l := range h.sd.Mutations() {
			if strings.Contains(l, "restart") {
				t.Errorf("a timer was restarted for a service change: %s", l)
			}
		}
		if code, stdout, _ := runCmd("doctor"); code != ExitOK || strings.Contains(stdout, "warn    units") {
			t.Errorf("doctor after: exit = %d\n%s", code, stdout)
		}
	})
	t.Run("ntfy removed later: doctor says every run exits 3", func(t *testing.T) {
		h := newHost(t)
		withNtfy(t, h)
		h.withConfigFile()
		if code, _, _ := runCmd("install"); code != ExitOK {
			t.Fatal("install failed")
		}
		h.cfg.Notify.Ntfy = nil
		code, stdout, _ := runCmd("doctor")
		if code != ExitError || !strings.Contains(stdout, "PROBLEM units") || !strings.Contains(stdout, "runs with --notify, but notify.ntfy is not configured") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
	})
}

// The default host access must be the real one: opsFor is only replaced by
// tests, and a command run in a test that forgot to replace it would act on
// the machine. This pins what the default builds.
func TestDefaultHostAccessIsTheRealOne(t *testing.T) {
	h := hostOps{}.withDefaults(env{}, nil)
	if _, ok := h.fs.(install.OSFS); !ok {
		t.Errorf("fs = %T", h.fs)
	}
	if _, ok := h.runner.(*execx.Real); !ok {
		t.Errorf("runner = %T", h.runner)
	}
	if h.geteuid == nil || h.exe == nil || h.loadConfig == nil || h.state == nil {
		t.Error("a default is missing")
	}
	if h.geteuid() != os.Geteuid() {
		t.Errorf("geteuid = %d", h.geteuid())
	}
}

// A configuration whose notify.ntfy cannot be turned into a notifier is refused
// where it is written down: config check, install and doctor all go through the
// real loader, which applies the rule of notify.NewNtfy. Before, such a
// configuration passed all three and then every scheduled run exited 3.
func TestABadNtfyConfigurationIsRefusedEverywhere(t *testing.T) {
	cases := []struct {
		name, url, topic, want string
	}{
		{"topic with a dot", "https://ntfy.example.org", "kw.alerts", "notify.ntfy.topic must be 1 to 64 characters"},
		{"topic too long", "https://ntfy.example.org", strings.Repeat("a", 65), "notify.ntfy.topic must be 1 to 64 characters"},
		{"credentials and a query", "http://kwuser:kwSECRETpass@127.0.0.1:80/?auth=QXV0aFNlY3JldA", "alerts", "must not hold credentials"},
		{"query only", "https://ntfy.example.org/?auth=kwSECRETq", "alerts", "query or a fragment"},
		{"fragment", "https://ntfy.example.org/#kwSECRETf", "alerts", "query or a fragment"},
		{"http to a remote host", "http://ntfy.example.org", "alerts", "http is only allowed for loopback hosts"},
		{"port out of range", "https://ntfy.example.org:99999", "alerts", "port must be between 1 and 65535"},
		{"not https", "ftp://ntfy.example.org", "alerts", "the scheme must be https"},
	}
	for _, c := range cases {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		real := dir + "/keepwatch.yaml"
		doc := "notify:\n  ntfy:\n    url: " + strconv.Quote(c.url) + "\n    topic: " + strconv.Quote(c.topic) + "\n"
		if err := os.WriteFile(real, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		h := newHost(t)
		h.withConfigFile()
		old := opsFor
		opsFor = func(e env) hostOps {
			o := old(e)
			o.loadConfig = func(string) (*config.Config, error) { return config.Load(real) }
			return o
		}
		t.Cleanup(func() { opsFor = old })
		noSecret := func(what, text string) {
			t.Helper()
			for _, secret := range []string{"kwSECRET", "kwuser", "QXV0aFNlY3JldA"} {
				if strings.Contains(text, secret) {
					t.Errorf("%s %s: the output holds %q:\n%s", c.name, what, secret, text)
				}
			}
		}

		code, stdout, stderr := runCmd("config", "check", "--config", real)
		if code != ExitError || !strings.Contains(stderr, "keepwatch.yaml:") || !strings.Contains(stderr, c.want) || stdout != "" {
			t.Errorf("%s: config check: exit = %d stderr = %q", c.name, code, stderr)
		}
		noSecret("config check", stderr)

		code, stdout, stderr = runCmd("install")
		if code != ExitUsage || !strings.Contains(stderr, c.want) || stdout != "" {
			t.Errorf("%s: install: exit = %d stderr = %q", c.name, code, stderr)
		}
		noSecret("install", stderr)
		if len(h.fs.Log) != 0 || len(h.sd.Runner.Calls) != 0 {
			t.Errorf("%s: a refused install did something: %v %v", c.name, h.fs.Log, h.sd.Runner.Calls)
		}

		for _, args := range [][]string{{"doctor"}, {"doctor", "--send-test"}} {
			code, stdout, _ = runCmd(args...)
			if code != ExitError || !strings.Contains(stdout, "PROBLEM config:") || !strings.Contains(stdout, c.want) {
				t.Errorf("%s: %v: exit = %d\n%s", c.name, args, code, stdout)
			}
			noSecret(strings.Join(args, " "), stdout)
		}
	}
}
