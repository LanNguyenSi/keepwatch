package doctor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
)

const (
	cfgPath  = "/etc/keepwatch/keepwatch.yaml"
	stateDir = "/var/lib/keepwatch"
)

type resolver map[string]error

func (r resolver) Resolve(name string) (string, error) {
	if err, ok := r[name]; ok {
		return "", err
	}
	return "/usr/bin/" + name, nil
}

type rig struct {
	fs      *installtest.MemFS
	sd      *installtest.Systemd
	uid     int
	cfg     *config.Config
	cfgErr  error
	missing resolver
	state   doctor.StateStatus
	// configPath is the --config given to doctor; empty means none, as when
	// the command is run without the flag.
	configPath string
	// cfgs are the configurations by path; a path that is not in it loads
	// cfg (or fails with cfgErr).
	cfgs    map[string]*config.Config
	cfgErrs map[string]error
	// loaded records the paths doctor asked for.
	loaded []string
}

// newRig is a healthy host: root, a valid configuration, every program, the
// units installed and the timers running.
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{fs: installtest.NewMemFS(), sd: installtest.NewSystemd(), missing: resolver{}, cfgs: map[string]*config.Config{}, cfgErrs: map[string]error{}}
	r.fs.AddDir("/run/sshd", 0o755, 0)
	r.fs.AddDir("/etc/keepwatch", 0o750, 0)
	r.fs.AddFile(cfgPath, 0o640, 0, "{}\n")
	r.cfg = &config.Config{
		Sources:  config.Sources{Main: cfgPath, ConfD: []string{"/etc/keepwatch/conf.d/a.yaml"}},
		StateDir: stateDir, Checks: map[string]config.Check{},
		Notify: config.Notify{Ntfy: &config.Ntfy{URL: "https://ntfy.example.org", Topic: "t"}},
	}
	r.state = doctor.StateStatus{Exists: true}
	iv, _ := install.ParseInterval("6h")
	wk, _ := install.ParseWeekly("Mon 08:00")
	deps := install.Deps{FS: r.fs, Runner: r.sd.Runner, Geteuid: func() int { return 0 }, Out: &bytes.Buffer{}}
	err := install.Install(context.Background(), deps, install.InstallOptions{
		Spec: install.Spec{Binary: "/usr/local/bin/keepwatch", ConfigPath: cfgPath, StateDir: stateDir, Notify: true, Interval: iv, Weekly: wk}, ConfigFound: true})
	if err != nil {
		t.Fatal(err)
	}
	r.sd.Loaded[install.CheckService], r.sd.Loaded[install.ReportService] = true, true
	return r
}

// load is the configuration loader of the rig.
func (r *rig) load(p string) (*config.Config, error) {
	r.loaded = append(r.loaded, p)
	if err, ok := r.cfgErrs[p]; ok {
		return nil, err
	}
	if c, ok := r.cfgs[p]; ok {
		return c, nil
	}
	if r.cfgErr != nil {
		return nil, r.cfgErr
	}
	return r.cfg, nil
}

func (r *rig) run() doctor.Report {
	r.loaded = nil
	return doctor.Run(context.Background(), doctor.Deps{
		ConfigPath: r.configPath,
		LoadConfig: r.load,
		Resolver:   r.missing,
		Runner:     r.sd.Runner,
		FS:         r.fs,
		Geteuid:    func() int { return r.uid },
		State:      func(string) doctor.StateStatus { return r.state },
	})
}

// has reports whether the report has a finding of the level in the area whose
// message contains all of the parts.
func has(rep doctor.Report, l doctor.Level, area string, parts ...string) bool {
	for _, f := range rep.Findings {
		if f.Level != l || f.Area != area {
			continue
		}
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(f.Message, p)
		}
		if ok {
			return true
		}
	}
	return false
}

func dump(rep doctor.Report) string {
	var b bytes.Buffer
	rep.Write(&b)
	return b.String()
}

func TestHealthyHostIsAllOK(t *testing.T) {
	r := newRig(t)
	rep := r.run()
	if rep.Problems() != 0 || rep.Warnings() != 0 {
		t.Fatalf("a healthy host:\n%s", dump(rep))
	}
	out := dump(rep)
	for _, want := range []string{"ok      user: running as root", "config: " + cfgPath + " is valid (+1 conf.d files)", "catalog: 18 checks",
		"programs: every program", "ssh: /run/sshd exists", "notify: ntfy is configured", "state: state_dir " + stateDir + " is writable",
		"units: the four unit files", "timers: keepwatch-check.timer is enabled and active", "doctor: all ok"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestNotRoot(t *testing.T) {
	r := newRig(t)
	r.uid = 1000
	if rep := r.run(); !has(rep, doctor.Problem, "user", "not running as root") || rep.Problems() != 1 {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestInvalidConfiguration(t *testing.T) {
	r := newRig(t)
	r.cfgErr = config.Errors{{File: cfgPath, Line: 3, Msg: "state_dir: must be an absolute path"}, {File: cfgPath, Line: 9, Msg: "unknown key"}}
	rep := r.run()
	if !has(rep, doctor.Problem, "config", cfgPath+":3", "state_dir") || !has(rep, doctor.Problem, "config", ":9") {
		t.Errorf("\n%s", dump(rep))
	}
	// One finding per error, each on its own line.
	if has(rep, doctor.Problem, "config", ":3", ":9") || rep.Problems() != 2 {
		t.Errorf("want the two errors as two findings:\n%s", dump(rep))
	}
	// Without a configuration nothing that depends on it is claimed as ok.
	for _, f := range rep.Findings {
		if f.Level == doctor.OK && (f.Area == "programs" || f.Area == "state" || f.Area == "ssh") {
			t.Errorf("%s reported ok without a configuration: %+v", f.Area, f)
		}
	}
	if !strings.Contains(dump(rep), "problem(s)") {
		t.Errorf("no summary:\n%s", dump(rep))
	}
	r.cfgErr = errors.New("open /etc/keepwatch/keepwatch.yaml: no such file or directory")
	if rep := r.run(); !has(rep, doctor.Problem, "config", "no such file") {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestConfigNamesAnUnknownCheck(t *testing.T) {
	r := newRig(t)
	r.cfg.Checks["no.such_check"] = config.Check{Enabled: true}
	if rep := r.run(); !has(rep, doctor.Problem, "config", "no.such_check", "unknown check id") {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestMissingPrograms(t *testing.T) {
	notFound := fmt.Errorf("%w: x", execx.ErrNotFound)
	cases := []struct {
		name    string
		missing resolver
		disable []string
		level   doctor.Level
		area    string
		parts   []string
		nothing bool // no programs finding other than ok
	}{
		{name: "fail2ban-client missing skips the jail check", missing: resolver{"fail2ban-client": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"fail2ban.sshd_jail", "fail2ban-client not found", "skipped"}},
		{name: "the same program for two checks is reported for each", missing: resolver{"sshd": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"ssh.x11_forwarding", "sshd not found", "skipped"}},
		{name: "apt-cache missing skips security updates", missing: resolver{"apt-cache": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"updates.security_pending", "apt-cache"}},
		{name: "refused by the execution layer is a problem", missing: resolver{"ss": fmt.Errorf("%w: ss resolves outside", execx.ErrNotAllowed)},
			level: doctor.Problem, area: "programs", parts: []string{"network.listeners", "refuses", "would be an error"}},
		{name: "needrestart missing is partial", missing: resolver{"needrestart": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"system.reboot_required", "kernel status stays unknown"}},
		{name: "docker missing", missing: resolver{"docker": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"docker.exposure", "unless a Docker daemon"}},
		{name: "no firewall tool", missing: resolver{"nft": notFound, "iptables": notFound, "ip6tables": notFound},
			level: doctor.Warn, area: "programs", parts: []string{"network.firewall_default", "none of nft, iptables and ip6tables"}},
		{name: "iptables without ip6tables and without nft leaves a family unreadable", missing: resolver{"nft": notFound, "ip6tables": notFound},
			level: doctor.Problem, area: "programs", parts: []string{"network.firewall_default", "one address family"}},
		{name: "nft alone is enough", missing: resolver{"iptables": notFound, "ip6tables": notFound, "ufw": notFound}, nothing: true},
		{name: "ufw is only a note", missing: resolver{"ufw": notFound}, nothing: true},
		{name: "a disabled check needs nothing", missing: resolver{"fail2ban-client": notFound}, disable: []string{"fail2ban.sshd_jail"}, nothing: true},
	}
	for _, c := range cases {
		r := newRig(t)
		r.missing = c.missing
		for _, id := range c.disable {
			r.cfg.Checks[id] = config.Check{Enabled: false}
		}
		rep := r.run()
		if c.nothing {
			for _, f := range rep.Findings {
				if f.Area == "programs" && f.Level != doctor.OK {
					t.Errorf("%s: unexpected finding %+v", c.name, f)
				}
			}
			continue
		}
		if !has(rep, c.level, c.area, c.parts...) {
			t.Errorf("%s: no %v finding with %v:\n%s", c.name, c.level, c.parts, dump(rep))
		}
		for _, f := range rep.Findings {
			if f.Area == "programs" && f.Level == doctor.OK {
				t.Errorf("%s: programs reported ok next to a finding: %+v", c.name, f)
			}
		}
	}
}

func TestMissingProgramsAreWarningsNotProblems(t *testing.T) {
	r := newRig(t)
	r.missing = resolver{"fail2ban-client": execx.ErrNotFound}
	if rep := r.run(); rep.Problems() != 0 || rep.Warnings() == 0 || !strings.Contains(dump(rep), "no problems, 1 warning(s)") {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestRunSSHDirectory(t *testing.T) {
	t.Run("missing names the cause", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/sshd")
		rep := r.run()
		if !has(rep, doctor.Problem, "ssh", "/run/sshd does not exist", "ssh.password_authentication", "ssh.authorized_keys", "ssh.socket", "systemctl start ssh") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("not a directory", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/sshd")
		r.fs.AddFile("/run/sshd", 0o644, 0, "")
		if rep := r.run(); !has(rep, doctor.Problem, "ssh", "not a directory") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("sshd not installed: the checks are skipped, no ssh finding", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/sshd")
		r.missing = resolver{"sshd": execx.ErrNotFound}
		for _, f := range r.run().Findings {
			if f.Area == "ssh" {
				t.Errorf("unexpected ssh finding %+v", f)
			}
		}
	})
	t.Run("ssh checks disabled", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/sshd")
		for _, id := range []string{"ssh.password_authentication", "ssh.permit_root_login", "ssh.keyboard_interactive_authentication", "ssh.x11_forwarding", "ssh.authorized_keys"} {
			r.cfg.Checks[id] = config.Check{Enabled: false}
		}
		for _, f := range r.run().Findings {
			if f.Area == "ssh" {
				t.Errorf("unexpected ssh finding %+v", f)
			}
		}
	})
	t.Run("only one ssh check enabled is still named", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/sshd")
		for _, id := range []string{"ssh.password_authentication", "ssh.permit_root_login", "ssh.keyboard_interactive_authentication", "ssh.x11_forwarding"} {
			r.cfg.Checks[id] = config.Check{Enabled: false}
		}
		if rep := r.run(); !has(rep, doctor.Problem, "ssh", "ssh.authorized_keys") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

func TestStateDirectory(t *testing.T) {
	cases := []struct {
		name  string
		st    doctor.StateStatus
		level doctor.Level
		parts []string
	}{
		{"untrusted", doctor.StateStatus{Exists: true, Err: errors.New("is a symlink")}, doctor.Problem, []string{"not usable", "exit 3", "is a symlink"}},
		{"not writable", doctor.StateStatus{Exists: true, Err: errors.New("not writable: permission denied")}, doctor.Problem, []string{"not writable"}},
		{"missing, the units are not installed", doctor.StateStatus{}, doctor.Warn, []string{"does not exist yet", "keepwatch install\" creates it", "keepwatch check"}},
		{"bad state file", doctor.StateStatus{Exists: true, FileProblem: "state.json is a symlink, it is not followed"}, doctor.Warn, []string{"new baseline", "symlink"}},
		{"fine", doctor.StateStatus{Exists: true}, doctor.OK, []string{"is writable"}},
	}
	for _, c := range cases {
		r := newRig(t)
		if c.name == "missing, the units are not installed" {
			for _, n := range install.UnitNames {
				r.fs.Remove(install.DefaultUnitDir + "/" + n)
			}
		}
		r.state = c.st
		if rep := r.run(); !has(rep, c.level, "state", c.parts...) {
			t.Errorf("%s:\n%s", c.name, dump(rep))
		}
	}
}

// The state directory is gone while the units are installed: the services fail
// with 226/NAMESPACE, whatever the first run would do.
func TestStateDirectoryMissingWithInstalledUnitsIsAProblem(t *testing.T) {
	r := newRig(t)
	r.state = doctor.StateStatus{}
	rep := r.run()
	if !has(rep, doctor.Problem, "state", "does not exist, but the units are installed", "226/NAMESPACE", "keepwatch install\" again") {
		t.Errorf("\n%s", dump(rep))
	}
	if strings.Contains(dump(rep), "first run creates it") {
		t.Errorf("the false remedy is still there:\n%s", dump(rep))
	}
	if rep.Problems() != 1 {
		t.Errorf("want exactly the one problem:\n%s", dump(rep))
	}
}

// Files of the unit names that keepwatch did not write do not make the units
// "installed" for this finding.
func TestStateDirectoryMissingWithForeignUnitFilesIsOnlyAWarning(t *testing.T) {
	r := newRig(t)
	for _, n := range install.UnitNames {
		r.fs.AddFile(install.DefaultUnitDir+"/"+n, 0o644, 0, "[Unit]\n")
	}
	r.state = doctor.StateStatus{}
	if rep := r.run(); !has(rep, doctor.Warn, "state", "does not exist yet") || has(rep, doctor.Problem, "state") {
		t.Errorf("\n%s", dump(rep))
	}
}

// state_dir in a place the sandbox hides or that is empty after a reboot.
func TestStateDirectoryTheSandboxHides(t *testing.T) {
	for _, dir := range []string{"/tmp/kwstate", "/var/tmp/kw", "/dev/shm/kw", "/dev/kw", "/run/kw", "/var/run/kw", "/tmp"} {
		r := newRig(t)
		r.cfg.StateDir = dir
		rep := r.run()
		if !has(rep, doctor.Problem, "state", dir, "scheduled run fails to start", "keepwatch install") {
			t.Errorf("%s:\n%s", dir, dump(rep))
		}
	}
	// Close names that must stay allowed.
	for _, dir := range []string{"/var/lib/keepwatch", "/srv/tmpfiles", "/var/tmpx/kw", "/home/x/runner", "/runner"} {
		r := newRig(t)
		r.cfg.StateDir = dir
		for _, f := range r.run().Findings {
			if f.Area == "state" && f.Level == doctor.Problem && strings.Contains(f.Message, "under") {
				t.Errorf("%s refused: %+v", dir, f)
			}
		}
	}
}

// The configuration file the installed unit passes.
func TestUnitConfigurationFile(t *testing.T) {
	setConfig := func(r *rig, path string) {
		for _, n := range []string{install.CheckService, install.ReportService} {
			p := install.DefaultUnitDir + "/" + n
			c, _ := r.fs.Content(p)
			r.fs.AddFile(p, 0o644, 0, strings.ReplaceAll(c, "--config "+cfgPath, "--config "+path))
		}
	}
	// Without --config doctor examines the file of the units, so its
	// placement is a finding about the configuration, said once.
	t.Run("under /tmp: the service does not see it", func(t *testing.T) {
		r := newRig(t)
		setConfig(r, "/tmp/kwc/keepwatch.yaml")
		rep := r.run()
		if !has(rep, doctor.Problem, "config", "the configuration directory /tmp/kwc", "under /tmp", "exits 3") || rep.Problems() != 1 {
			t.Errorf("\n%s", dump(rep))
		}
		if rep.ConfigPath != "/tmp/kwc/keepwatch.yaml" {
			t.Errorf("examined %q", rep.ConfigPath)
		}
	})
	t.Run("missing", func(t *testing.T) {
		r := newRig(t)
		r.fs.AddDir("/srv", 0o755, 0)
		setConfig(r, "/srv/gone.yaml")
		if rep := r.run(); !has(rep, doctor.Problem, "config", "the configuration file /srv/gone.yaml does not exist", "exits 3") || rep.Problems() != 1 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("the file of the unit is deleted", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove(cfgPath)
		if rep := r.run(); !has(rep, doctor.Problem, "config", "the configuration file "+cfgPath+" does not exist") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("no --config in the unit", func(t *testing.T) {
		r := newRig(t)
		p := install.DefaultUnitDir + "/" + install.CheckService
		c, _ := r.fs.Content(p)
		r.fs.AddFile(p, 0o644, 0, strings.ReplaceAll(c, " --config "+cfgPath, ""))
		if rep := r.run(); !has(rep, doctor.Problem, "units", install.CheckService, "no --config") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

// The sandbox only shows when the service runs: a check service that never ran
// proves nothing, and the warning says how to try it.
func TestCheckServiceNeverRan(t *testing.T) {
	r := newRig(t)
	r.sd.Props[install.CheckService] = map[string]string{"ExecMainStartTimestamp": ""}
	rep := r.run()
	if !has(rep, doctor.Warn, "last run", install.CheckService, "has not run since the host booted", "systemctl start keepwatch-check.service") || rep.Problems() != 0 {
		t.Errorf("\n%s", dump(rep))
	}
	// The weekly report is not expected to have run.
	r = newRig(t)
	r.sd.Props[install.ReportService] = map[string]string{"ExecMainStartTimestamp": ""}
	if rep := r.run(); rep.Warnings() != 0 || rep.Problems() != 0 {
		t.Errorf("the report service not having run is reported:\n%s", dump(rep))
	}
	// A failed run is the problem, not a warning about a missing run.
	r = newRig(t)
	r.sd.Props[install.CheckService] = map[string]string{"ExecMainStartTimestamp": "", "Result": "exit-code", "ExecMainStatus": "226", "ActiveState": "failed"}
	rep = r.run()
	if !has(rep, doctor.Problem, "last run", "226") || has(rep, doctor.Warn, "last run", "has not run") {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestNotifyNotConfigured(t *testing.T) {
	r := newRig(t)
	r.cfg.Notify.Ntfy = nil
	for _, n := range []string{install.CheckService, install.ReportService} { // installed without --notify
		p := install.DefaultUnitDir + "/" + n
		c, _ := r.fs.Content(p)
		r.fs.AddFile(p, 0o644, 0, strings.ReplaceAll(c, " --notify", ""))
	}
	if rep := r.run(); !has(rep, doctor.Warn, "notify", "no notification channel") || rep.Problems() != 0 {
		t.Errorf("\n%s", dump(rep))
	}
}

func TestUnits(t *testing.T) {
	unit := func(name string) string { return install.DefaultUnitDir + "/" + name }
	t.Run("not installed", func(t *testing.T) {
		r := newRig(t)
		for _, n := range install.UnitNames {
			r.fs.Remove(unit(n))
		}
		r.sd.Loaded = map[string]bool{}
		rep := r.run()
		for _, n := range install.UnitNames {
			if !has(rep, doctor.Problem, "units", n, "not installed") {
				t.Errorf("%s not reported:\n%s", n, dump(rep))
			}
		}
		if !has(rep, doctor.Problem, "timers", "keepwatch-check.timer", "not loaded") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a file without the marker", func(t *testing.T) {
		r := newRig(t)
		r.fs.AddFile(unit(install.CheckTimer), 0o644, 0, "[Timer]\n")
		if rep := r.run(); !has(rep, doctor.Problem, "units", install.CheckTimer, "not written by keepwatch") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("state_dir changed since the install", func(t *testing.T) {
		r := newRig(t)
		r.cfg.StateDir = "/srv/other-state"
		rep := r.run()
		if !has(rep, doctor.Problem, "units", install.CheckService, "/var/lib/keepwatch", "/srv/other-state", "keepwatch install") {
			t.Errorf("\n%s", dump(rep))
		}
		if !has(rep, doctor.Problem, "units", install.ReportService, "/srv/other-state") {
			t.Errorf("the report service is not checked:\n%s", dump(rep))
		}
	})
	t.Run("another configuration file", func(t *testing.T) {
		r := newRig(t)
		r.fs.AddDir("/srv", 0o755, 0)
		r.fs.AddFile("/srv/kw.yaml", 0o640, 0, "{}\n")
		r.configPath = "/srv/kw.yaml"
		rep := r.run()
		for _, svc := range []string{install.CheckService, install.ReportService} {
			if !has(rep, doctor.Problem, "units", svc, "runs with --config "+cfgPath, "examined /srv/kw.yaml (given with --config)", "without --config") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
		if rep.Problems() != 2 || rep.ConfigPath != "/srv/kw.yaml" {
			t.Errorf("want exactly the two problems about /srv/kw.yaml:\n%s", dump(rep))
		}
	})
	timers := map[string]struct {
		set   func(r *rig)
		parts []string
	}{
		"disabled":     {func(r *rig) { r.sd.Enabled[install.ReportTimer] = false }, []string{install.ReportTimer, "disabled", "not enabled"}},
		"inactive":     {func(r *rig) { r.sd.Active[install.CheckTimer] = false }, []string{install.CheckTimer, "inactive", "not active"}},
		"not loaded":   {func(r *rig) { r.sd.Loaded[install.CheckTimer] = false }, []string{install.CheckTimer, "not loaded"}},
		"failed state": {func(r *rig) { r.sd.Props[install.CheckTimer] = map[string]string{"ActiveState": "failed"} }, []string{install.CheckTimer, "failed", "not active"}},
	}
	for name, c := range timers {
		t.Run("timer "+name, func(t *testing.T) {
			r := newRig(t)
			c.set(r)
			if rep := r.run(); !has(rep, doctor.Problem, "timers", c.parts...) {
				t.Errorf("\n%s", dump(rep))
			}
		})
	}
	t.Run("the last run failed", func(t *testing.T) {
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"Result": "exit-code", "ExecMainStatus": "3", "ActiveState": "failed"}
		if rep := r.run(); !has(rep, doctor.Problem, "last run", install.CheckService, "exit-code", "status 3", "journalctl") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("systemd is not running", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/systemd/system")
		before := len(r.sd.Runner.Calls)
		rep := r.run()
		if !has(rep, doctor.Problem, "systemd", "not running") {
			t.Errorf("\n%s", dump(rep))
		}
		for _, l := range r.sd.Runner.Lines()[before:] {
			t.Errorf("systemctl was asked although systemd is not running: %q", l)
		}
	})
	t.Run("systemctl is missing", func(t *testing.T) {
		r := newRig(t)
		r.sd.Runner.Handler = func([]string) (execx.Result, error) { return execx.Result{}, execx.ErrNotFound }
		if rep := r.run(); !has(rep, doctor.Problem, "timers", "cannot ask systemd") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("only read-only queries", func(t *testing.T) {
		r := newRig(t)
		before := len(r.sd.Runner.Calls)
		logs := len(r.fs.Log)
		r.run()
		for _, l := range r.sd.Runner.Lines()[before:] {
			if !strings.HasPrefix(l, "systemctl show ") {
				t.Errorf("doctor ran %q", l)
			}
		}
		if len(r.fs.Log) != logs {
			t.Errorf("doctor wrote: %v", r.fs.Log[logs:])
		}
	})
	t.Run("the binary of the unit", func(t *testing.T) {
		cases := map[string]struct {
			set   func(r *rig)
			level doctor.Level
			parts []string
		}{
			"missing": {func(r *rig) { r.fs.Remove("/usr/local/bin/keepwatch") }, doctor.Problem, []string{"/usr/local/bin/keepwatch", "does not exist"}},
			"owned by a user": {func(r *rig) { r.fs.AddFile("/usr/local/bin/keepwatch", 0o755, 1000, "") }, doctor.Problem,
				[]string{"cannot be trusted", "uid 1000", "install -o root -g root -m 0755"}},
			"group writable":     {func(r *rig) { r.fs.AddFile("/usr/local/bin/keepwatch", 0o775, 0, "") }, doctor.Problem, []string{"writable by group or other"}},
			"directory writable": {func(r *rig) { r.fs.AddDir("/usr/local/bin", 0o777, 0) }, doctor.Problem, []string{"/usr/local/bin has permissions 0777"}},
			"ancestor is a link": {func(r *rig) { r.fs.Remove("/usr/local"); r.fs.AddSymlink("/usr/local", "/srv") }, doctor.Problem, []string{"symbolic link"}},
		}
		for name, c := range cases {
			r := newRig(t)
			c.set(r)
			rep := r.run()
			for _, svc := range []string{install.CheckService, install.ReportService} {
				if !has(rep, c.level, "units", append([]string{svc}, c.parts...)...) {
					t.Errorf("%s: %s not reported:\n%s", name, svc, dump(rep))
				}
			}
			if name == "missing" && strings.Contains(dump(rep), "cannot be trusted") {
				t.Errorf("a missing binary is reported as untrusted:\n%s", dump(rep))
			}
		}
		r := newRig(t)
		r.fs.AddFile(unit(install.CheckService), 0o644, 0, "# keepwatch-managed-unit: x\n[Service]\nType=oneshot\n")
		if rep := r.run(); !has(rep, doctor.Problem, "units", install.CheckService, "no ExecStart program") {
			t.Errorf("a unit without ExecStart:\n%s", dump(rep))
		}
	})
	t.Run("unit directory is a symlink", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove(install.DefaultUnitDir)
		r.fs.AddSymlink(install.DefaultUnitDir, "/srv")
		if rep := r.run(); !has(rep, doctor.Problem, "units", "symlink") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

func TestReportWriteFormat(t *testing.T) {
	rep := doctor.Report{Findings: []doctor.Finding{{Level: doctor.OK, Area: "a", Message: "fine"}, {Level: doctor.Warn, Area: "b", Message: "hm"}, {Level: doctor.Problem, Area: "c", Message: "bad"}}}
	want := "ok      a: fine\nwarn    b: hm\nPROBLEM c: bad\ndoctor: 1 problem(s), 1 warning(s)\n"
	if got := dump(rep); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestOSStateProber(t *testing.T) {
	newDir := func(t *testing.T, mode os.FileMode) string {
		d := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		return d
	}
	leftovers := func(t *testing.T, d string) {
		t.Helper()
		ents, _ := os.ReadDir(d)
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".keepwatch-") {
				t.Errorf("probe file %s left behind", e.Name())
			}
		}
	}
	t.Run("writable", func(t *testing.T) {
		d := newDir(t, 0o700)
		st := doctor.OSStateProber(d)
		if !st.Exists || st.Err != nil || st.FileProblem != "" {
			t.Errorf("%+v", st)
		}
		leftovers(t, d)
	})
	t.Run("missing is not created", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "nope")
		st := doctor.OSStateProber(d)
		if st.Exists || st.Err != nil {
			t.Errorf("%+v", st)
		}
		if _, err := os.Lstat(d); err == nil {
			t.Error("the probe created the directory")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		real := newDir(t, 0o700)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		st := doctor.OSStateProber(link)
		if st.Err == nil || !strings.Contains(st.Err.Error(), "symlink") {
			t.Errorf("%+v", st)
		}
		leftovers(t, real)
	})
	t.Run("group writable", func(t *testing.T) {
		st := doctor.OSStateProber(newDir(t, 0o770))
		if st.Err == nil {
			t.Errorf("%+v", st)
		}
	})
	t.Run("relative path", func(t *testing.T) {
		if st := doctor.OSStateProber("relative/dir"); st.Err == nil {
			t.Errorf("%+v", st)
		}
	})
	t.Run("not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can write anywhere")
		}
		d := newDir(t, 0o500)
		st := doctor.OSStateProber(d)
		if st.Err == nil || !strings.Contains(st.Err.Error(), "not writable") {
			t.Errorf("%+v", st)
		}
		os.Chmod(d, 0o700)
	})
	t.Run("a state file that will not be used", func(t *testing.T) {
		d := newDir(t, 0o700)
		if err := os.Symlink("/etc/hostname", filepath.Join(d, "state.json")); err != nil {
			t.Fatal(err)
		}
		st := doctor.OSStateProber(d)
		if st.Err != nil || st.FileProblem == "" || !strings.Contains(st.FileProblem, "symlink") {
			t.Errorf("%+v", st)
		}
		leftovers(t, d)
	})
	t.Run("the probe file never goes outside", func(t *testing.T) {
		d := newDir(t, 0o700)
		outside := filepath.Dir(d)
		before, _ := os.ReadDir(outside)
		doctor.OSStateProber(d)
		after, _ := os.ReadDir(outside)
		if len(before) != len(after) {
			t.Errorf("entries next to the state directory changed: %d -> %d", len(before), len(after))
		}
	})
	_ = syscall.Getuid
}

// The services notify exactly when notify.ntfy is configured.
func TestUnitsNotifyMatchTheConfiguration(t *testing.T) {
	reinstall := func(r *rig, notify bool) {
		for _, n := range install.UnitNames {
			r.fs.Remove(install.DefaultUnitDir + "/" + n)
		}
		iv, _ := install.ParseInterval("6h")
		wk, _ := install.ParseWeekly("Mon 08:00")
		deps := install.Deps{FS: r.fs, Runner: r.sd.Runner, Geteuid: func() int { return 0 }, Out: &bytes.Buffer{}}
		if err := install.Install(context.Background(), deps, install.InstallOptions{
			Spec: install.Spec{Binary: "/usr/local/bin/keepwatch", ConfigPath: cfgPath, StateDir: stateDir, Notify: notify, Interval: iv, Weekly: wk}, ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("configured and notifying: nothing to say", func(t *testing.T) {
		r := newRig(t)
		if rep := r.run(); rep.Warnings() != 0 || rep.Problems() != 0 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("not configured and not notifying: nothing to say about it", func(t *testing.T) {
		r := newRig(t)
		reinstall(r, false)
		r.cfg.Notify.Ntfy = nil
		for _, f := range r.run().Findings {
			if f.Area == "units" && f.Level != doctor.OK {
				t.Errorf("%+v", f)
			}
		}
	})
	t.Run("configured, unit without --notify: a problem for each service (alerts are lost)", func(t *testing.T) {
		r := newRig(t)
		reinstall(r, false)
		rep := r.run()
		for _, svc := range []string{install.CheckService, install.ReportService} {
			if !has(rep, doctor.Problem, "units", "notify.ntfy is configured", svc, "without --notify", "consumes the alerts", "a loss", "keepwatch install\" again") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
		if rep.Problems() != 2 || rep.Warnings() != 0 {
			t.Errorf("want exactly the two problems, one per service:\n%s", dump(rep))
		}
	})
	t.Run("not configured, unit with --notify: every run exits 3, a problem", func(t *testing.T) {
		r := newRig(t)
		r.cfg.Notify.Ntfy = nil
		rep := r.run()
		for _, svc := range []string{install.CheckService, install.ReportService} {
			if !has(rep, doctor.Problem, "units", svc, "runs with --notify", "notify.ntfy is not configured", "exits 3") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
	})
	t.Run("the configuration did not load: no claim about --notify", func(t *testing.T) {
		r := newRig(t)
		r.cfgErr = errors.New("broken")
		for _, f := range r.run().Findings {
			if f.Area == "units" && strings.Contains(f.Message, "--notify") {
				t.Errorf("%+v", f)
			}
		}
	})
}

func TestLastRunFailureNamesTheExitStatus(t *testing.T) {
	for status, want := range map[string]string{
		"4": "the notification could not be delivered", "3": "keepwatch could not do its job", "226": "ReadWritePaths names a missing directory",
	} {
		for _, svc := range []string{install.CheckService, install.ReportService} {
			r := newRig(t)
			r.sd.Props[svc] = map[string]string{"Result": "exit-code", "ExecMainStatus": status, "ActiveState": "failed"}
			if rep := r.run(); !has(rep, doctor.Problem, "last run", svc, "exit status "+status, want) {
				t.Errorf("%s %s:\n%s", svc, status, dump(rep))
			}
		}
	}
	r := newRig(t)
	r.sd.Props[install.ReportService] = map[string]string{"Result": "exit-code", "ExecMainStatus": "77", "ActiveState": "failed"}
	if rep := r.run(); !has(rep, doctor.Problem, "last run", "exit status 77)") {
		t.Errorf("an unknown status:\n%s", dump(rep))
	}
}

// doctor's output does not go through the redactor: of the ntfy URL it prints
// scheme://host[:port] and nothing else.
func TestNotifyFindingPrintsOnlyTheOrigin(t *testing.T) {
	cases := map[string]string{
		"http://kwuser:kwSECRETpass@127.0.0.1:80/kw-topic?auth=QXV0aFNlY3JldA#frag": "http://127.0.0.1:80",
		"https://ntfy.example.org/ntfy/kw-topic":                                    "https://ntfy.example.org",
		"https://[2001:db8::1]:8443/x":                                              "https://[2001:db8::1]:8443",
		"https://kwuser:kwSECRETpass@ntfy.example.org":                              "https://ntfy.example.org",
	}
	for raw, want := range cases {
		r := newRig(t)
		r.cfg.Notify.Ntfy = &config.Ntfy{URL: raw, Topic: "kw-topic"}
		out := dump(r.run())
		if !has(r.run(), doctor.OK, "notify", "ntfy is configured ("+want+")") {
			t.Errorf("%s:\n%s", raw, out)
		}
		for _, secret := range []string{"kwSECRET", "kwuser", "QXV0aFNlY3JldA", "kw-topic", "frag"} {
			if strings.Contains(out, secret) {
				t.Errorf("%s: the output holds %q:\n%s", raw, secret, out)
			}
		}
	}
	r := newRig(t)
	r.cfg.Notify.Ntfy = &config.Ntfy{URL: "::not a url::kwSECRET", Topic: "t"}
	out := dump(r.run())
	if !strings.Contains(out, "ntfy is configured (address not shown)") || strings.Contains(out, "kwSECRET") {
		t.Errorf("an unparsable URL:\n%s", out)
	}
	// parseable, but without a scheme or a host
	for _, raw := range []string{"relative/kwSECRET", "//ntfy.example.org/kwSECRET", "https:///kwSECRET"} {
		r := newRig(t)
		r.cfg.Notify.Ntfy = &config.Ntfy{URL: raw, Topic: "t"}
		out := dump(r.run())
		if !strings.Contains(out, "ntfy is configured (address not shown)") || strings.Contains(out, "kwSECRET") {
			t.Errorf("%s:\n%s", raw, out)
		}
	}
}

// A service whose last run ended with a failure result is a problem even when
// systemd no longer calls it failed (a later stop leaves it inactive).
func TestLastRunResultWithoutAFailedActiveState(t *testing.T) {
	for _, svc := range []string{install.CheckService, install.ReportService} {
		r := newRig(t)
		r.sd.Props[svc] = map[string]string{"Result": "exit-code", "ExecMainStatus": "3", "ActiveState": "inactive"}
		if rep := r.run(); !has(rep, doctor.Problem, "last run", svc, "result exit-code") {
			t.Errorf("%s:\n%s", svc, dump(rep))
		}
	}
	r := newRig(t)
	r.sd.Props[install.CheckService] = map[string]string{"Result": "success", "ExecMainStatus": "1", "ActiveState": "inactive"}
	if rep := r.run(); rep.Problems() != 0 {
		t.Errorf("a successful run with findings is not a problem:\n%s", dump(rep))
	}
}
