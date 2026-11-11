package install_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
)

const (
	unitDir  = "/etc/systemd/system"
	cfgPath  = "/etc/keepwatch/keepwatch.yaml"
	stateDir = "/var/lib/keepwatch"
)

type rig struct {
	fs   *installtest.MemFS
	sd   *installtest.Systemd
	out  *bytes.Buffer
	deps install.Deps
	uid  int
	// noConfig: the configuration file does not exist.
	noConfig bool
}

// newRig is a host where install has everything it needs: the binary of
// NewMemFS and a root-owned configuration directory with the main file.
func newRig() *rig {
	r := &rig{fs: installtest.NewMemFS(), sd: installtest.NewSystemd(), out: &bytes.Buffer{}}
	r.fs.AddDir("/etc/keepwatch", 0o750, 0)
	r.fs.AddFile(cfgPath, 0o640, 0, "{}\n")
	r.deps = install.Deps{FS: r.fs, Runner: r.sd.Runner, Geteuid: func() int { return r.uid }, Out: r.out}
	return r
}

func spec(t testing.TB) install.Spec {
	t.Helper()
	iv, err := install.ParseInterval("6h")
	if err != nil {
		t.Fatal(err)
	}
	wk, err := install.ParseWeekly("Mon 08:00")
	if err != nil {
		t.Fatal(err)
	}
	return install.Spec{Binary: "/usr/local/bin/keepwatch", ConfigPath: cfgPath, StateDir: stateDir, Interval: iv, Weekly: wk}
}

func (r *rig) install(t testing.TB, o install.InstallOptions) error {
	t.Helper()
	if o.Spec.Binary == "" {
		o.Spec = spec(t)
	}
	r.out.Reset()
	o.ConfigFound = !r.noConfig
	return install.Install(context.Background(), r.deps, o)
}

func (r *rig) uninstall(o install.UninstallOptions) error {
	r.out.Reset()
	if o.ConfigPath == "" {
		o.ConfigPath = cfgPath
	}
	if o.DefaultConfigPath == "" {
		o.DefaultConfigPath = cfgPath
	}
	if o.DefaultStateDir == "" {
		o.DefaultStateDir = stateDir
	}
	if o.StateDirOf == nil {
		o.StateDirOf = func(string) (string, bool, error) { return stateDir, true, nil }
	}
	return install.Uninstall(context.Background(), r.deps, o)
}

func wantLines(t *testing.T, what string, got, want []string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s:\n got:\n  %s\nwant:\n  %s", what, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func unitPath(name string) string { return unitDir + "/" + name }

// writes is the log without the entries of install's write probe (one file in
// state_dir, created and removed under a random name).
func writes(log []string) []string {
	var out []string
	for _, l := range log {
		if !strings.Contains(l, "/"+install.ProbePrefix) {
			out = append(out, l)
		}
	}
	return out
}

// probes counts the probe files the log shows created and removed.
func probes(log []string) (created, removed int) {
	for _, l := range log {
		switch {
		case strings.HasPrefix(l, "write ") && strings.Contains(l, "/"+install.ProbePrefix):
			created++
		case strings.HasPrefix(l, "remove ") && strings.Contains(l, "/"+install.ProbePrefix):
			removed++
		}
	}
	return
}

func TestFirstInstall(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatalf("Install: %v\n%s", err, r.out)
	}
	wantLines(t, "writes", writes(r.fs.Log), []string{
		"mkdir /var/lib/keepwatch",
		"write " + unitPath(install.CheckService), "write " + unitPath(install.ReportService),
		"write " + unitPath(install.CheckTimer), "write " + unitPath(install.ReportTimer),
	})
	wantLines(t, "systemctl", r.sd.Mutations(), []string{
		"systemctl daemon-reload",
		"systemctl enable --now keepwatch-check.timer keepwatch-report.timer",
	})
	if m := r.fs.Mode(stateDir); m != fs.ModeDir|0o700 {
		t.Errorf("state dir mode = %v, want 0700", m)
	}
	files, _ := install.Render(spec(t))
	for _, f := range files {
		got, ok := r.fs.Content(unitPath(f.Name))
		if !ok || got != string(f.Content) {
			t.Errorf("%s was not written as rendered", f.Name)
		}
		if m := r.fs.Mode(unitPath(f.Name)); m != 0o644 {
			t.Errorf("%s mode = %v, want 0644", f.Name, m)
		}
	}
	if !strings.Contains(r.out.String(), "installed:") {
		t.Errorf("output does not say it installed:\n%s", r.out)
	}
}

func TestSecondInstallChangesNothingAndSaysSo(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	logs, calls := len(writes(r.fs.Log)), len(r.sd.Runner.Calls)
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if got := writes(r.fs.Log); len(got) != logs {
		t.Errorf("second run wrote: %v", got[logs:])
	}
	for _, l := range r.sd.Runner.Lines()[calls:] {
		if !strings.HasPrefix(l, "systemctl show ") {
			t.Errorf("second run ran %q, want only read-only queries", l)
		}
	}
	if !strings.Contains(r.out.String(), "already installed, nothing to change") {
		t.Errorf("second run does not say that nothing changed:\n%s", r.out)
	}
}

func TestInstallUpdatesAChangedScheduleAndRestartsTheTimer(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	r.fs.Log = nil
	r.sd.Runner.Calls = nil
	s := spec(t)
	s.Interval, _ = install.ParseInterval("1h")
	if err := r.install(t, install.InstallOptions{Spec: s, ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	wantLines(t, "writes", writes(r.fs.Log), []string{"write " + unitPath(install.CheckTimer)})
	wantLines(t, "systemctl", r.sd.Mutations(), []string{
		"systemctl daemon-reload",
		"systemctl enable --now keepwatch-check.timer keepwatch-report.timer",
		"systemctl restart keepwatch-check.timer",
	})
	if got, _ := r.fs.Content(unitPath(install.CheckTimer)); !strings.Contains(got, "OnUnitActiveSec=1h\n") {
		t.Errorf("timer does not carry the new interval:\n%s", got)
	}
	if !strings.Contains(r.out.String(), "unchanged "+unitPath(install.CheckService)) {
		t.Errorf("an unchanged file is not reported as such:\n%s", r.out)
	}
}

func TestInstallEnablesTimersThatWereTurnedOff(t *testing.T) {
	cases := map[string]func(r *rig){
		"disabled but running": func(r *rig) { r.sd.Enabled[install.ReportTimer] = false },
		"enabled but stopped":  func(r *rig) { r.sd.Active[install.CheckTimer] = false },
		"query fails":          func(r *rig) { r.sd.Fail["show"] = execx.Result{ExitCode: 1, Stderr: []byte("no bus")} },
	}
	for name, off := range cases {
		r := newRig()
		if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
		r.fs.Log = nil
		r.sd.Runner.Calls = nil
		off(r)
		if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(writes(r.fs.Log)) != 0 {
			t.Errorf("%s: wrote %v", name, r.fs.Log)
		}
		wantLines(t, name+": systemctl", r.sd.Mutations(), []string{"systemctl enable --now keepwatch-check.timer keepwatch-report.timer"})
		if strings.Contains(r.out.String(), "already installed") {
			t.Errorf("%s: says it is already installed:\n%s", name, r.out)
		}
	}
}

func TestInstallDryRunChangesNothing(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{DryRun: true, ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("dry run wrote: %v", r.fs.Log)
	}
	if m := r.sd.Mutations(); len(m) != 0 {
		t.Errorf("dry run ran: %v", m)
	}
	for _, want := range []string{
		"would create directory /var/lib/keepwatch (mode 0700)",
		"would create " + unitPath(install.CheckService), "would create " + unitPath(install.ReportTimer),
		"would run systemctl daemon-reload", "would run systemctl enable --now keepwatch-check.timer keepwatch-report.timer",
	} {
		if !strings.Contains(r.out.String(), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, r.out)
		}
	}
	// Installed for real, a dry run is a no-op report.
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	r.fs.Log = nil
	if err := r.install(t, install.InstallOptions{DryRun: true, ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	if len(r.fs.Log) != 0 || !strings.Contains(r.out.String(), "already installed") {
		t.Errorf("dry run after install: log %v\n%s", r.fs.Log, r.out)
	}
}

func TestInstallDryRunNeedsNoRoot(t *testing.T) {
	r := newRig()
	r.uid = 1000
	if err := r.install(t, install.InstallOptions{DryRun: true}); err != nil {
		t.Fatalf("dry run as a normal user: %v", err)
	}
	err := r.install(t, install.InstallOptions{})
	if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "as root") {
		t.Errorf("real install as a normal user: err = %v, want a refusal that says root", err)
	}
	if len(r.fs.Log) != 0 || len(r.sd.Mutations()) != 0 {
		t.Errorf("a refused install changed something: %v %v", r.fs.Log, r.sd.Mutations())
	}
}

// Without the configuration file every scheduled run would exit 3: install
// refuses, also as a dry run, and writes nothing.
func TestInstallRefusesWhenTheConfigurationIsMissing(t *testing.T) {
	for _, dry := range []bool{false, true} {
		r := newRig()
		r.noConfig = true
		err := r.install(t, install.InstallOptions{DryRun: dry})
		if !errors.Is(err, install.ErrRefused) {
			t.Fatalf("dry=%v: err = %v, want ErrRefused", dry, err)
		}
		for _, want := range []string{cfgPath, "does not exist", "keepwatch init", "install again"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("dry=%v: the message lacks %q: %v", dry, want, err)
			}
		}
		if len(r.fs.Log) != 0 || len(r.sd.Runner.Calls) != 0 {
			t.Errorf("dry=%v: a refused install did something: %v %v", dry, r.fs.Log, r.sd.Runner.Calls)
		}
	}
}

func TestInstallRefusesWhenSystemdIsNotRunning(t *testing.T) {
	r := newRig()
	r.fs.Remove("/run/systemd/system")
	err := r.install(t, install.InstallOptions{})
	if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "systemd is not running") {
		t.Fatalf("err = %v", err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("wrote %v", r.fs.Log)
	}
	if err := r.install(t, install.InstallOptions{DryRun: true}); err != nil {
		t.Errorf("a dry run should still list the plan: %v", err)
	}
	if !strings.Contains(r.out.String(), "systemd is not running") {
		t.Errorf("dry run does not mention it:\n%s", r.out)
	}
}

// A file in the way that keepwatch did not write is never overwritten, and the
// refusal comes before the first write: the other files are not created either.
func TestInstallDoesNotOverwriteAFileWithoutTheMarker(t *testing.T) {
	r := newRig()
	const foreign = "[Unit]\nDescription=somebody else's\n"
	r.fs.AddFile(unitPath(install.ReportService), 0o644, 0, foreign)
	err := r.install(t, install.InstallOptions{ConfigFound: true})
	if !errors.Is(err, install.ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	for _, want := range []string{unitPath(install.ReportService), "not written by keepwatch", "refusing to overwrite"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %v", want, err)
		}
	}
	if got, _ := r.fs.Content(unitPath(install.ReportService)); got != foreign {
		t.Errorf("the foreign file was changed: %q", got)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("a refused install wrote %v", r.fs.Log)
	}
	if len(r.sd.Mutations()) != 0 {
		t.Errorf("a refused install ran %v", r.sd.Mutations())
	}
}

func TestInstallRefusesASymlinkedTarget(t *testing.T) {
	r := newRig()
	const victim = "/etc/important.conf"
	r.fs.AddFile(victim, 0o644, 0, "keep me")
	r.fs.AddSymlink(unitPath(install.CheckTimer), victim)
	err := r.install(t, install.InstallOptions{ConfigFound: true})
	if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want a refusal that names the symlink", err)
	}
	if got, _ := r.fs.Content(victim); got != "keep me" {
		t.Errorf("the link target was written: %q", got)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("wrote %v", r.fs.Log)
	}
	// A dangling link is refused as well.
	r.fs.AddSymlink(unitPath(install.CheckTimer), "/nonexistent/target")
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); !errors.Is(err, install.ErrRefused) {
		t.Errorf("dangling link: err = %v", err)
	}
}

func TestInstallRefusesWhatIsNotARegularFile(t *testing.T) {
	r := newRig()
	r.fs.AddDir(unitPath(install.CheckService), 0o755, 0)
	err := r.install(t, install.InstallOptions{})
	if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "exists and is not a regular file, refusing to replace it") {
		t.Fatalf("err = %v", err)
	}
}

func TestInstallRefusesAnUntrustedUnitDirectory(t *testing.T) {
	cases := map[string]func(r *rig){
		"symlink": func(r *rig) {
			r.fs.Remove(unitDir)
			r.fs.AddSymlink(unitDir, "/tmp/elsewhere")
		},
		"group writable": func(r *rig) { r.fs.AddDir(unitDir, 0o775, 0) },
		"foreign owner":  func(r *rig) { r.fs.AddDir(unitDir, 0o755, 1000) },
		"missing":        func(r *rig) { r.fs.Remove(unitDir) },
	}
	for name, mutate := range cases {
		r := newRig()
		mutate(r)
		err := r.install(t, install.InstallOptions{})
		if !errors.Is(err, install.ErrRefused) {
			t.Errorf("%s: err = %v, want ErrRefused", name, err)
		}
		if len(r.fs.Log) != 0 {
			t.Errorf("%s: wrote %v", name, r.fs.Log)
		}
	}
}

// While state_dir is missing only its parent can be checked. The directory
// install has just created is checked itself before anything depends on it:
// whatever is at the name then (here, what somebody put there in between) must
// pass the placement check, or the install stops before a unit is written.
func TestInstallChecksTheDirectoriesItCreated(t *testing.T) {
	swaps := map[string]struct {
		swap func(r *rig, p string)
		want string
	}{
		"owned by a user":   {func(r *rig, p string) { r.fs.AddDir(p, 0o700, 1000) }, "owned by uid 1000"},
		"writable by group": {func(r *rig, p string) { r.fs.AddDir(p, 0o770, 0) }, "writable by group or other"},
		"a symbolic link":   {func(r *rig, p string) { r.fs.AddSymlink(p, "/etc") }, "symbolic link"},
	}
	for name, c := range swaps {
		r := newRig()
		r.fs.AfterMkdir = func(p string) { c.swap(r, p) }
		err := r.install(t, install.InstallOptions{ConfigFound: true})
		if !errors.Is(err, install.ErrFailed) || !strings.Contains(err.Error(), "after creating "+stateDir) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want ErrFailed naming %q", name, err, c.want)
		}
		if len(r.sd.Mutations()) != 0 {
			t.Errorf("%s: systemctl ran after the failure: %v", name, r.sd.Mutations())
		}
		for _, n := range install.UnitNames {
			if r.fs.Exists(unitPath(n)) {
				t.Errorf("%s: %s was written although the directory it needs cannot be trusted", name, n)
			}
		}
	}
	// The directory as install makes it passes, and is created exactly once.
	r := newRig()
	made := 0
	r.fs.AfterMkdir = func(string) { made++ }
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil || made != 1 {
		t.Errorf("err = %v, %d directories created, want none and 1", err, made)
	}
}

func TestInstallChecksTheDirectoriesItDoesNotCreate(t *testing.T) {
	cases := map[string]func(r *rig){
		"config dir is a symlink": func(r *rig) { r.fs.AddSymlink("/etc/keepwatch", "/tmp/x") },
		"config dir writable":     func(r *rig) { r.fs.AddDir("/etc/keepwatch", 0o777, 0) },
		"state dir is a symlink":  func(r *rig) { r.fs.AddSymlink(stateDir, "/etc") },
		"state dir group writable": func(r *rig) {
			r.fs.AddDir(stateDir, 0o770, 0)
		},
		"state dir foreign owner": func(r *rig) { r.fs.AddDir(stateDir, 0o700, 1000) },
		"state dir parent missing": func(r *rig) {
			r.fs.Remove("/var/lib")
		},
	}
	for name, mutate := range cases {
		r := newRig()
		mutate(r)
		err := r.install(t, install.InstallOptions{ConfigFound: true})
		if !errors.Is(err, install.ErrRefused) {
			t.Errorf("%s: err = %v, want ErrRefused", name, err)
		}
		if len(r.fs.Log) != 0 || len(r.sd.Mutations()) != 0 {
			t.Errorf("%s: a refused install changed something: %v %v", name, r.fs.Log, r.sd.Mutations())
		}
	}
	// Existing, trusted directories are left as they are.
	r := newRig()
	r.fs.AddDir("/etc/keepwatch", 0o755, 0)
	r.fs.AddDir(stateDir, 0o755, 0)
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	if r.fs.Mode("/etc/keepwatch") != fs.ModeDir|0o755 || r.fs.Mode(stateDir) != fs.ModeDir|0o755 {
		t.Error("an existing directory was changed")
	}
}

func TestInstallRefusesAnInvalidSpecWithoutTouchingAnything(t *testing.T) {
	r := newRig()
	s := spec(t)
	s.StateDir = "/var/lib/kw\nReadWritePaths=/"
	err := r.install(t, install.InstallOptions{Spec: s})
	if !errors.Is(err, install.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	if len(r.fs.Log) != 0 || len(r.sd.Runner.Calls) != 0 {
		t.Errorf("touched the host: %v %v", r.fs.Log, r.sd.Runner.Calls)
	}
}

func TestInstallReportsSystemctlFailures(t *testing.T) {
	for _, sub := range []string{"daemon-reload", "enable"} {
		r := newRig()
		r.sd.Fail[sub] = execx.Result{ExitCode: 1, Stderr: []byte("Failed to connect to bus\nsecond line")}
		err := r.install(t, install.InstallOptions{ConfigFound: true})
		if !errors.Is(err, install.ErrFailed) || !strings.Contains(err.Error(), "Failed to connect to bus") || strings.Contains(err.Error(), "second line") {
			t.Errorf("%s: err = %v", sub, err)
		}
	}
	r := newRig()
	r.sd.Runner.Handler = func([]string) (execx.Result, error) { return execx.Result{}, execx.ErrNotFound }
	if err := r.install(t, install.InstallOptions{}); !errors.Is(err, install.ErrFailed) {
		t.Errorf("systemctl missing: err = %v", err)
	}
}

func TestInstallReportsAFailedWriteAndLeavesTheRestToTheNextRun(t *testing.T) {
	r := newRig()
	r.fs.FailWrite[unitPath(install.CheckTimer)] = errors.New("disk full")
	err := r.install(t, install.InstallOptions{ConfigFound: true})
	if !errors.Is(err, install.ErrFailed) || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
	if len(r.sd.Mutations()) != 0 {
		t.Errorf("systemctl ran after a failed write: %v", r.sd.Mutations())
	}
	delete(r.fs.FailWrite, unitPath(install.CheckTimer))
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatalf("the next run: %v", err)
	}
	if !r.sd.Enabled[install.CheckTimer] {
		t.Error("the next run did not finish the install")
	}
}

func TestInstallOverwritesItsOwnOlderFile(t *testing.T) {
	r := newRig()
	r.fs.AddFile(unitPath(install.CheckService), 0o644, 0, "# keepwatch-managed-unit: an older version\n[Service]\nExecStart=/old\n")
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.fs.Content(unitPath(install.CheckService)); strings.Contains(got, "/old") {
		t.Errorf("the older file was kept:\n%s", got)
	}
	if !strings.Contains(r.out.String(), "update "+unitPath(install.CheckService)) {
		t.Errorf("output does not say update:\n%s", r.out)
	}
}

func TestUninstallRemovesOnlyItsOwnFiles(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	const foreignName = "other.service"
	r.fs.AddFile(unitPath(foreignName), 0o644, 0, "[Unit]\n")
	r.fs.Log, r.sd.Runner.Calls = nil, nil
	if err := r.uninstall(install.UninstallOptions{}); err != nil {
		t.Fatalf("Uninstall: %v\n%s", err, r.out)
	}
	wantLines(t, "systemctl", r.sd.Mutations(), []string{
		"systemctl disable --now keepwatch-check.timer", "systemctl disable --now keepwatch-report.timer",
		"systemctl stop keepwatch-check.service", "systemctl stop keepwatch-report.service",
		"systemctl daemon-reload",
	})
	for _, n := range install.UnitNames {
		if r.fs.Exists(unitPath(n)) {
			t.Errorf("%s is still there", n)
		}
	}
	if !r.fs.Exists(unitPath(foreignName)) {
		t.Error("a file that is not keepwatch's was removed")
	}
	for _, p := range []string{"/etc/keepwatch", stateDir} {
		if !r.fs.Exists(p) {
			t.Errorf("%s was removed without --purge", p)
		}
	}
	if !strings.Contains(r.out.String(), "kept") {
		t.Errorf("no word about config and state:\n%s", r.out)
	}
}

func TestUninstallLeavesFilesThatAreNotKeepwatchs(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	// Somebody replaced the check service and made the report timer a link.
	const foreign = "[Service]\nExecStart=/bin/true\n"
	r.fs.AddFile(unitPath(install.CheckService), 0o644, 0, foreign)
	r.fs.AddFile("/etc/other-target", 0o644, 0, "target")
	r.fs.AddSymlink(unitPath(install.ReportTimer), "/etc/other-target")
	r.fs.Log, r.sd.Runner.Calls = nil, nil
	if err := r.uninstall(install.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.fs.Content(unitPath(install.CheckService)); !ok || got != foreign {
		t.Error("the foreign service file was changed or removed")
	}
	if !r.fs.Exists(unitPath(install.ReportTimer)) {
		t.Error("the symlink was removed")
	}
	if got, _ := r.fs.Content("/etc/other-target"); got != "target" {
		t.Error("the symlink target was touched")
	}
	for _, n := range []string{install.CheckTimer, install.ReportService} {
		if r.fs.Exists(unitPath(n)) {
			t.Errorf("%s (keepwatch's) should be gone", n)
		}
	}
	for _, l := range r.sd.Mutations() {
		if strings.Contains(l, install.ReportTimer) || strings.Contains(l, install.CheckService) {
			t.Errorf("systemctl was run for a unit that is not keepwatch's: %q", l)
		}
	}
	for _, want := range []string{"left " + unitPath(install.CheckService) + ": not written by keepwatch", "left " + unitPath(install.ReportTimer) + ": it is a symlink"} {
		if !strings.Contains(r.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, r.out)
		}
	}
}

func TestUninstallWhenNothingIsInstalled(t *testing.T) {
	r := newRig()
	if err := r.uninstall(install.UninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(r.sd.Runner.Calls) != 0 || len(r.fs.Log) != 0 {
		t.Errorf("did something: %v %v", r.sd.Runner.Calls, r.fs.Log)
	}
	if !strings.Contains(r.out.String(), "nothing to remove") {
		t.Errorf("output:\n%s", r.out)
	}
}

func TestUninstallDryRun(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	r.fs.Log, r.sd.Runner.Calls = nil, nil
	if err := r.uninstall(install.UninstallOptions{DryRun: true, Purge: true}); err != nil {
		t.Fatal(err)
	}
	if len(r.fs.Log) != 0 || len(r.sd.Runner.Calls) != 0 {
		t.Errorf("dry run changed or ran something: %v %v", r.fs.Log, r.sd.Runner.Calls)
	}
	if !strings.Contains(r.out.String(), "would remove "+unitPath(install.CheckService)) {
		t.Errorf("output:\n%s", r.out)
	}
}

func TestUninstallStopsWhenDisableFails(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	r.fs.Log = nil
	r.sd.Fail["disable"] = execx.Result{ExitCode: 1, Stderr: []byte("boom")}
	err := r.uninstall(install.UninstallOptions{})
	if !errors.Is(err, install.ErrFailed) {
		t.Fatalf("err = %v", err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("files were removed although the timer is still enabled: %v", r.fs.Log)
	}
}

func TestUninstallNeedsRoot(t *testing.T) {
	r := newRig()
	r.uid = 1000
	if err := r.uninstall(install.UninstallOptions{}); !errors.Is(err, install.ErrRefused) {
		t.Errorf("err = %v", err)
	}
	if err := r.uninstall(install.UninstallOptions{DryRun: true}); err != nil {
		t.Errorf("dry run: %v", err)
	}
}

func TestPurge(t *testing.T) {
	setup := func() *rig {
		r := newRig()
		if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
		r.fs.AddFile(cfgPath, 0o644, 0, "state_dir: "+stateDir+"\n")
		r.fs.AddDir("/etc/keepwatch/conf.d", 0o755, 0)
		r.fs.AddFile("/etc/keepwatch/conf.d/10-site.yaml", 0o644, 0, "{}\n")
		r.fs.AddFile(stateDir+"/state.json", 0o600, 0, "{}")
		r.fs.AddFile(stateDir+"/.state.json.tmp-0123456789abcdef", 0o600, 0, "x")
		return r
	}
	t.Run("removes keepwatch's own files and the directories that are then empty", func(t *testing.T) {
		r := setup()
		// Outside the two directories: untouched.
		r.fs.AddDir("/var/lib/other", 0o755, 0)
		r.fs.AddFile("/var/lib/other/state.json", 0o600, 0, "{}")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		for _, p := range []string{cfgPath, "/etc/keepwatch/conf.d/10-site.yaml", "/etc/keepwatch/conf.d", "/etc/keepwatch", stateDir + "/state.json", stateDir} {
			if r.fs.Exists(p) {
				t.Errorf("%s is still there", p)
			}
		}
		if !r.fs.Exists("/var/lib/other/state.json") || !r.fs.Exists("/etc") {
			t.Error("purge went outside keepwatch's directories")
		}
	})
	t.Run("keeps what is not keepwatch's and the directory that holds it", func(t *testing.T) {
		r := setup()
		r.fs.AddFile("/etc/keepwatch/ntfy.token", 0o600, 0, "secret")
		r.fs.AddFile("/etc/keepwatch/conf.d/notes.txt", 0o644, 0, "mine")
		r.fs.AddFile(stateDir+"/backup.tar", 0o600, 0, "mine")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		for _, p := range []string{"/etc/keepwatch/ntfy.token", "/etc/keepwatch/conf.d/notes.txt", stateDir + "/backup.tar", "/etc/keepwatch", "/etc/keepwatch/conf.d", stateDir} {
			if !r.fs.Exists(p) {
				t.Errorf("%s was removed", p)
			}
		}
		for _, p := range []string{cfgPath, "/etc/keepwatch/conf.d/10-site.yaml", stateDir + "/state.json", stateDir + "/.state.json.tmp-0123456789abcdef"} {
			if r.fs.Exists(p) {
				t.Errorf("%s is still there", p)
			}
		}
		if !strings.Contains(r.out.String(), "left /etc/keepwatch:") {
			t.Errorf("no word about what was left:\n%s", r.out)
		}
	})
	t.Run("never follows a link", func(t *testing.T) {
		r := setup()
		r.fs.AddFile("/etc/secret-target", 0o600, 0, "keep")
		r.fs.Remove(stateDir + "/state.json")
		r.fs.AddSymlink(stateDir+"/state.json", "/etc/secret-target")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if got, _ := r.fs.Content("/etc/secret-target"); got != "keep" {
			t.Error("the link target was removed")
		}
		if !r.fs.Exists(stateDir + "/state.json") {
			t.Error("a symlink named state.json was removed as if it were keepwatch's file")
		}
	})
	t.Run("refuses a state directory that is a symlink", func(t *testing.T) {
		r := setup()
		r.fs.Remove(stateDir + "/state.json")
		r.fs.Remove(stateDir + "/.state.json.tmp-0123456789abcdef")
		r.fs.Remove(stateDir)
		r.fs.AddDir("/srv", 0o755, 0)
		r.fs.AddDir("/srv/real", 0o755, 0)
		r.fs.AddFile("/srv/real/state.json", 0o600, 0, "{}")
		r.fs.AddSymlink(stateDir, "/srv/real")
		err := r.uninstall(install.UninstallOptions{Purge: true})
		if !errors.Is(err, install.ErrFailed) {
			t.Fatalf("err = %v", err)
		}
		if !r.fs.Exists("/srv/real/state.json") {
			t.Error("the file behind the link was removed")
		}
	})
	t.Run("without --purge nothing of it is touched", func(t *testing.T) {
		r := setup()
		if err := r.uninstall(install.UninstallOptions{}); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{cfgPath, "/etc/keepwatch/conf.d/10-site.yaml", stateDir + "/state.json"} {
			if !r.fs.Exists(p) {
				t.Errorf("%s was removed without --purge", p)
			}
		}
	})
	t.Run("history.json and its temporary files are keepwatch's own", func(t *testing.T) {
		r := setup()
		r.fs.AddFile(stateDir+"/history.json", 0o600, 0, "{}")
		r.fs.AddFile(stateDir+"/.history.json.tmp-0123456789abcdef", 0o600, 0, "x")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if r.fs.Exists(stateDir) {
			t.Errorf("the state directory stays because of the history:\n%s", r.out)
		}
	})
	t.Run("a probe file or temporary file left by a crash is keepwatch's own", func(t *testing.T) {
		r := setup()
		r.fs.AddFile(stateDir+"/"+install.ProbePrefix+"0123456789abcdef", 0o600, 0, "x")
		r.fs.AddFile(stateDir+"/.keepwatch-tmp-0123456789abcdef", 0o600, 0, "x")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if r.fs.Exists(stateDir) {
			t.Errorf("the state directory stays because of its own leftovers:\n%s", r.out)
		}
	})
}

// The configuration side of --purge is for a path that is provably keepwatch's:
// the default path, or the --config recorded in an installed unit. That a file
// loads as a keepwatch configuration proves nothing (an empty YAML file does).
func TestPurgeLeavesAConfigurationThatIsNotProvablyKeepwatchs(t *testing.T) {
	foreignFiles := func(r *rig) {
		r.fs.AddDir("/etc/otherapp", 0o755, 0)
		r.fs.AddFile("/etc/otherapp/otherapp.yaml", 0o644, 0, "a: 1\n")
		r.fs.AddFile("/etc/otherapp/empty.yaml", 0o644, 0, "")
		r.fs.AddFile("/etc/otherapp/daemon.json", 0o644, 0, "{}")
		r.fs.AddDir("/etc/otherapp/conf.d", 0o755, 0)
		r.fs.AddFile("/etc/otherapp/conf.d/10-site.yaml", 0o644, 0, "b: 2\n")
		r.fs.AddFile("/etc/otherapp/notes.txt", 0o644, 0, "mine")
	}
	untouched := func(t *testing.T, r *rig) {
		t.Helper()
		for _, p := range []string{"/etc/otherapp/otherapp.yaml", "/etc/otherapp/empty.yaml", "/etc/otherapp/daemon.json", "/etc/otherapp/conf.d", "/etc/otherapp/conf.d/10-site.yaml", "/etc/otherapp/notes.txt", "/etc/otherapp"} {
			if !r.fs.Exists(p) {
				t.Errorf("%s was removed", p)
			}
		}
	}
	noLoad := func(t *testing.T) func(string) (string, bool, error) {
		return func(p string) (string, bool, error) {
			t.Errorf("the configuration %s was consulted although it is not keepwatch's", p)
			return "/etc/otherapp", true, nil
		}
	}
	for _, foreign := range []string{"/etc/otherapp/otherapp.yaml", "/etc/otherapp/empty.yaml", "/etc/otherapp/daemon.json"} {
		t.Run("foreign "+foreign, func(t *testing.T) {
			r := newRig()
			if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
				t.Fatal(err)
			}
			foreignFiles(r)
			r.fs.AddFile(stateDir+"/state.json", 0o600, 0, "{}")
			err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: foreign, ConfigExplicit: true, StateDirOf: noLoad(t)})
			if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "remove it and its conf.d by hand") {
				t.Fatalf("err = %v, want a refusal that says to remove it by hand", err)
			}
			untouched(t, r)
			if !strings.Contains(r.out.String(), "left "+foreign) {
				t.Errorf("the output does not list the file left:\n%s", r.out)
			}
			// What can be proven is still done: the units, and the state directory
			// the units recorded.
			for _, n := range install.UnitNames {
				if r.fs.Exists(unitPath(n)) {
					t.Errorf("%s was not removed", n)
				}
			}
			if r.fs.Exists(stateDir + "/state.json") {
				t.Errorf("the recorded state was not purged:\n%s", r.out)
			}
		})
	}
	t.Run("without an installed unit nothing is known: remove by hand", func(t *testing.T) {
		r := newRig()
		foreignFiles(r)
		err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: "/etc/otherapp/otherapp.yaml", ConfigExplicit: true, StateDirOf: noLoad(t)})
		if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "by hand") {
			t.Fatalf("err = %v", err)
		}
		untouched(t, r)
		if !strings.Contains(r.out.String(), "no installed unit records a state directory") {
			t.Errorf("no word about the state directory:\n%s", r.out)
		}
	})
	t.Run("after a plain uninstall a custom --config is refused, the default path still purges", func(t *testing.T) {
		r := newRig()
		if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
		foreignFiles(r)
		r.fs.AddFile(cfgPath, 0o644, 0, "{}\n")
		if err := r.uninstall(install.UninstallOptions{}); err != nil {
			t.Fatal(err)
		}
		err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: "/etc/otherapp/otherapp.yaml", ConfigExplicit: true, StateDirOf: noLoad(t)})
		if !errors.Is(err, install.ErrRefused) {
			t.Fatalf("err = %v", err)
		}
		untouched(t, r)
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("purge of the default path: %v\n%s", err, r.out)
		}
		if r.fs.Exists(cfgPath) || r.fs.Exists("/etc/keepwatch") {
			t.Errorf("the default configuration is still there:\n%s", r.out)
		}
	})
	t.Run("a unit file without the marker records nothing", func(t *testing.T) {
		r := newRig()
		foreignFiles(r)
		r.fs.AddFile(unitPath(install.CheckService), 0o644, 0, "[Service]\nExecStart=/usr/bin/x check --config /etc/otherapp/otherapp.yaml\nReadWritePaths=/etc/otherapp\n")
		err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: "/etc/otherapp/otherapp.yaml", ConfigExplicit: true, StateDirOf: noLoad(t)})
		if !errors.Is(err, install.ErrRefused) {
			t.Fatalf("err = %v", err)
		}
		untouched(t, r)
		if !r.fs.Exists(unitPath(install.CheckService)) {
			t.Error("the foreign unit file was removed")
		}
	})
	t.Run("conf.d that is a regular file is left alone", func(t *testing.T) {
		r := newRig()
		r.fs.AddDir("/etc/keepwatch", 0o750, 0)
		r.fs.AddFile(cfgPath, 0o644, 0, "{}\n")
		r.fs.AddFile("/etc/keepwatch/conf.d", 0o644, 0, "not a directory")
		if err := r.uninstall(install.UninstallOptions{Purge: true}); err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if got, ok := r.fs.Content("/etc/keepwatch/conf.d"); !ok || got != "not a directory" {
			t.Error("the file named conf.d was removed or changed")
		}
		if !strings.Contains(r.out.String(), "left /etc/keepwatch/conf.d: not a directory") || r.fs.Exists(cfgPath) {
			t.Errorf("\n%s", r.out)
		}
		if !r.fs.Exists("/etc/keepwatch") {
			t.Error("the configuration directory was removed with a foreign entry in it")
		}
	})
	t.Run("an empty configuration path is never trusted", func(t *testing.T) {
		r := newRig()
		r.fs.AddFile(unitPath(install.CheckService), 0o644, 0, "# keepwatch-managed-unit: x\n[Service]\nExecStart=/usr/local/bin/keepwatch check\n")
		err := install.Uninstall(context.Background(), r.deps, install.UninstallOptions{Purge: true, ConfigPath: "", ConfigExplicit: true,
			DefaultConfigPath: cfgPath, DefaultStateDir: stateDir, StateDirOf: noLoad(t)})
		if !errors.Is(err, install.ErrRefused) {
			t.Errorf("a unit without --config and an empty path: err = %v", err)
		}
	})
	t.Run("dry run refuses the same and removes nothing", func(t *testing.T) {
		r := newRig()
		if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
		foreignFiles(r)
		r.fs.Log = nil
		err := r.uninstall(install.UninstallOptions{DryRun: true, Purge: true, ConfigPath: "/etc/otherapp/otherapp.yaml", ConfigExplicit: true, StateDirOf: noLoad(t)})
		if !errors.Is(err, install.ErrRefused) || len(r.fs.Log) != 0 {
			t.Errorf("err = %v, log = %v", err, r.fs.Log)
		}
	})
}

func TestPurgeFollowsTheConfigurationRecordedInTheUnits(t *testing.T) {
	setup := func() *rig {
		r := newRig()
		r.fs.AddDir("/srv", 0o755, 0)
		r.fs.AddDir("/srv/kw", 0o755, 0)
		r.fs.AddFile("/srv/kw/main.yaml", 0o644, 0, "{}\n")
		s := spec(t)
		s.ConfigPath, s.StateDir = "/srv/kw/main.yaml", "/srv/kw/state"
		if err := r.install(t, install.InstallOptions{Spec: s, ConfigFound: true}); err != nil {
			t.Fatal(err)
		}
		r.fs.AddDir("/srv/kw/conf.d", 0o755, 0)
		r.fs.AddFile("/srv/kw/conf.d/10-site.yaml", 0o644, 0, "{}\n")
		r.fs.AddFile("/srv/kw/state/state.json", 0o600, 0, "{}")
		r.fs.AddFile("/srv/kw/other.yaml", 0o644, 0, "{}")
		// Another configuration, at the default path, is not what the units use.
		r.fs.AddDir("/etc/keepwatch", 0o750, 0)
		r.fs.AddFile(cfgPath, 0o644, 0, "{}\n")
		return r
	}
	read := func(t *testing.T) func(string) (string, bool, error) {
		return func(p string) (string, bool, error) {
			if p != "/srv/kw/main.yaml" {
				t.Errorf("the configuration %s was consulted", p)
			}
			return "/srv/kw/state", true, nil
		}
	}
	for name, explicit := range map[string]bool{"without --config": false, "with the recorded --config": true} {
		t.Run(name, func(t *testing.T) {
			r := setup()
			o := install.UninstallOptions{Purge: true, StateDirOf: read(t)}
			if explicit {
				o.ConfigPath, o.ConfigExplicit = "/srv/kw/main.yaml", true
			}
			if err := r.uninstall(o); err != nil {
				t.Fatalf("%v\n%s", err, r.out)
			}
			for _, p := range []string{"/srv/kw/main.yaml", "/srv/kw/conf.d", "/srv/kw/conf.d/10-site.yaml", "/srv/kw/state/state.json", "/srv/kw/state"} {
				if r.fs.Exists(p) {
					t.Errorf("%s is still there", p)
				}
			}
			for _, p := range []string{"/srv/kw/other.yaml", "/srv/kw", cfgPath, "/etc/keepwatch"} {
				if !r.fs.Exists(p) {
					t.Errorf("%s was removed", p)
				}
			}
		})
	}
	t.Run("the default path is trusted too, next to a recorded one", func(t *testing.T) {
		r := setup()
		err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: cfgPath, ConfigExplicit: true,
			StateDirOf: func(string) (string, bool, error) { return stateDir, true, nil }})
		if err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if r.fs.Exists(cfgPath) || !r.fs.Exists("/srv/kw/main.yaml") {
			t.Error("purge went to the wrong configuration")
		}
	})
	t.Run("an unreadable configuration falls back to what the unit recorded", func(t *testing.T) {
		r := setup()
		err := r.uninstall(install.UninstallOptions{Purge: true,
			StateDirOf: func(string) (string, bool, error) { return "", true, errors.New("bad yaml") }})
		if err != nil {
			t.Fatalf("%v\n%s", err, r.out)
		}
		if r.fs.Exists("/srv/kw/state/state.json") || !strings.Contains(r.out.String(), "warning: the configuration /srv/kw/main.yaml cannot be read") {
			t.Errorf("\n%s", r.out)
		}
	})
	t.Run("no configuration, no unit: the default state directory", func(t *testing.T) {
		r := newRig()
		r.fs.AddDir(stateDir, 0o700, 0)
		r.fs.AddFile(stateDir+"/state.json", 0o600, 0, "{}")
		err := r.uninstall(install.UninstallOptions{Purge: true,
			StateDirOf: func(string) (string, bool, error) { return "", false, nil }})
		if err != nil || r.fs.Exists(stateDir) || !strings.Contains(r.out.String(), "purging the default") {
			t.Errorf("err = %v\n%s", err, r.out)
		}
	})
}
