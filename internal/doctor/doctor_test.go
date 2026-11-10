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
}

// newRig is a healthy host: root, a valid configuration, every program, the
// units installed and the timers running.
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{fs: installtest.NewMemFS(), sd: installtest.NewSystemd(), missing: resolver{}}
	r.fs.AddDir("/run/sshd", 0o755, 0)
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
		Spec: install.Spec{Binary: "/usr/local/bin/keepwatch", ConfigPath: cfgPath, StateDir: stateDir, Interval: iv, Weekly: wk}, ConfigFound: true})
	if err != nil {
		t.Fatal(err)
	}
	r.sd.Loaded[install.CheckService], r.sd.Loaded[install.ReportService] = true, true
	return r
}

func (r *rig) run() doctor.Report {
	d := doctor.Deps{
		ConfigPath: cfgPath,
		LoadConfig: func(string) (*config.Config, error) { return r.cfg, r.cfgErr },
		Resolver:   r.missing,
		Runner:     r.sd.Runner,
		FS:         r.fs,
		Geteuid:    func() int { return r.uid },
		State:      func(string) doctor.StateStatus { return r.state },
	}
	if r.cfgErr != nil {
		d.LoadConfig = func(string) (*config.Config, error) { return nil, r.cfgErr }
	}
	return doctor.Run(context.Background(), d)
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
		{"missing", doctor.StateStatus{}, doctor.Warn, []string{"does not exist yet"}},
		{"bad state file", doctor.StateStatus{Exists: true, FileProblem: "state.json is a symlink, it is not followed"}, doctor.Warn, []string{"new baseline", "symlink"}},
		{"fine", doctor.StateStatus{Exists: true}, doctor.OK, []string{"is writable"}},
	}
	for _, c := range cases {
		r := newRig(t)
		r.state = c.st
		if rep := r.run(); !has(rep, c.level, "state", c.parts...) {
			t.Errorf("%s:\n%s", c.name, dump(rep))
		}
	}
}

func TestNotifyNotConfigured(t *testing.T) {
	r := newRig(t)
	r.cfg.Notify.Ntfy = nil
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
		d := doctor.Deps{ConfigPath: "/srv/kw.yaml", LoadConfig: func(string) (*config.Config, error) { return r.cfg, nil }, Resolver: r.missing, Runner: r.sd.Runner,
			FS: r.fs, Geteuid: func() int { return 0 }, State: func(string) doctor.StateStatus { return r.state }}
		if rep := doctor.Run(context.Background(), d); !has(rep, doctor.Warn, "units", "--config "+cfgPath, "/srv/kw.yaml") {
			t.Errorf("\n%s", dump(rep))
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
