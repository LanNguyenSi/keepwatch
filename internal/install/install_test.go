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
}

func newRig() *rig {
	r := &rig{fs: installtest.NewMemFS(), sd: installtest.NewSystemd(), out: &bytes.Buffer{}}
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
	return install.Install(context.Background(), r.deps, o)
}

func (r *rig) uninstall(o install.UninstallOptions) error {
	r.out.Reset()
	if o.ConfigPath == "" {
		o.ConfigPath = cfgPath
	}
	if o.StateDir == "" {
		o.StateDir = stateDir
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

func TestFirstInstall(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatalf("Install: %v\n%s", err, r.out)
	}
	wantLines(t, "writes", r.fs.Log, []string{
		"mkdir /etc/keepwatch", "mkdir /var/lib/keepwatch",
		"write " + unitPath(install.CheckService), "write " + unitPath(install.ReportService),
		"write " + unitPath(install.CheckTimer), "write " + unitPath(install.ReportTimer),
	})
	wantLines(t, "systemctl", r.sd.Mutations(), []string{
		"systemctl daemon-reload",
		"systemctl enable --now keepwatch-check.timer keepwatch-report.timer",
	})
	if m := r.fs.Mode("/etc/keepwatch"); m != fs.ModeDir|0o750 {
		t.Errorf("config dir mode = %v, want 0750", m)
	}
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
	logs, calls := len(r.fs.Log), len(r.sd.Runner.Calls)
	if err := r.install(t, install.InstallOptions{ConfigFound: true}); err != nil {
		t.Fatalf("second Install: %v", err)
	}
	if len(r.fs.Log) != logs {
		t.Errorf("second run wrote: %v", r.fs.Log[logs:])
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
	wantLines(t, "writes", r.fs.Log, []string{"write " + unitPath(install.CheckTimer)})
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
		if len(r.fs.Log) != 0 {
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
		"would create directory /etc/keepwatch (mode 0750)", "would create directory /var/lib/keepwatch (mode 0700)",
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

func TestInstallWarnsWhenTheConfigurationIsMissing(t *testing.T) {
	r := newRig()
	if err := r.install(t, install.InstallOptions{ConfigFound: false}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.out.String(), "keepwatch init") {
		t.Errorf("no hint to run init:\n%s", r.out)
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
	t.Run("a custom configuration path purges its own directory only", func(t *testing.T) {
		r := newRig()
		r.fs.AddDir("/srv", 0o755, 0)
		r.fs.AddDir("/srv/kw", 0o755, 0)
		r.fs.AddFile("/srv/kw/main.yaml", 0o644, 0, "{}")
		r.fs.AddFile("/srv/kw/other.yaml", 0o644, 0, "{}")
		if err := r.uninstall(install.UninstallOptions{Purge: true, ConfigPath: "/srv/kw/main.yaml"}); err != nil {
			t.Fatal(err)
		}
		if r.fs.Exists("/srv/kw/main.yaml") || !r.fs.Exists("/srv/kw/other.yaml") || !r.fs.Exists("/srv/kw") {
			t.Error("purge removed the wrong files")
		}
	})
}
