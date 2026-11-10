package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
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
		h.uid = 1000
		if code, _, stderr := runCmd("install"); code != ExitUsage || !strings.Contains(stderr, "root") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
	})
	t.Run("a file without the marker is 2 and nothing is written", func(t *testing.T) {
		h := newHost(t)
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
	t.Run("a missing configuration is a warning, not an error", func(t *testing.T) {
		h := newHost(t)
		code, stdout, _ := runCmd("install")
		if code != ExitOK || !strings.Contains(stdout, "keepwatch init") {
			t.Errorf("exit = %d\n%s", code, stdout)
		}
		_ = h
	})
	t.Run("dry run lists and changes nothing", func(t *testing.T) {
		h := newHost(t)
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

func TestDoctorSendTest(t *testing.T) {
	t.Run("is not available yet: exit 2, clear message, no diagnosis", func(t *testing.T) {
		h := newHost(t)
		code, stdout, stderr := runCmd("doctor", "--send-test")
		if code != ExitUsage || !strings.Contains(stderr, "--send-test is not available yet") {
			t.Errorf("exit = %d stderr = %q", code, stderr)
		}
		if stdout != "" || len(h.sd.Runner.Calls) != 0 {
			t.Errorf("the diagnosis ran: %q %v", stdout, h.sd.Runner.Calls)
		}
	})
	t.Run("the seam can be filled", func(t *testing.T) {
		newHost(t)
		old := sendTest
		defer func() { sendTest = old }()
		called := false
		sendTest = func(env, *config.Config) error { called = true; return nil }
		runCmd("doctor", "--send-test")
		if !called {
			t.Error("the seam was not called")
		}
	})
	t.Run("without the flag the seam is not used", func(t *testing.T) {
		newHost(t)
		old := sendTest
		defer func() { sendTest = old }()
		sendTest = func(env, *config.Config) error { t.Error("called"); return errors.New("x") }
		runCmd("doctor")
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
