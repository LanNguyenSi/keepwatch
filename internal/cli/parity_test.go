package cli

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
)

// The parity matrix. install, doctor and the scheduled run each decide in
// their own code whether the run will work: install before it writes the
// units, doctor when it is asked, the run when it starts. The three must not
// drift apart, in this direction: what install accepts, doctor has no problem
// with, and what doctor has no problem with starts. The matrix puts one host
// after the other in front of all three and compares the answers.
//
// The host is a directory tree on the real file system, seen through a jail:
// the path "/etc/keepwatch" of a fixture is the directory etc/keepwatch below
// a temporary directory. install and doctor run as commands against the jail;
// the run is the command line of the ExecStart of the unit file in the jail,
// executed in this process with the real loaders.
//
// What a test process cannot do is modelled, and only that:
//
//   - The owner. Everything in the jail belongs to the user running the test,
//     who stands for root (uid 0); a fixture names the paths that belong to
//     "another user" (uid 1000). A test that runs as root and changes the owner
//     for real is TestPlacementOnTheRealFileSystemAsRoot in package install.
//   - The sandbox. The process has no mount namespace, so a run finds a file
//     below /tmp of the jail that a service would not find. Before the run the
//     model asks, for the binary, the configuration, the token file and
//     ReadWritePaths of the unit, where the kernel ends up (symbolic links
//     resolved, which only this model does and the product never) and whether
//     the sandbox table hides that place. That makes the model as good as the
//     table and no better: a place the real sandbox hides and the table does
//     not know passes here. The table itself is held to a sandbox that was
//     measured under systemd (test/systemd, and the test of the measured
//     files in package install).
type jail struct {
	t    *testing.T
	base string
	sd   *installtest.Systemd
	// other lists the paths (as the fixture names them) that another user
	// owns.
	other map[string]int
	// binary and cfgPath are what the units are given.
	binary, cfgPath string
	ntfy            *fakeNtfy
}

const (
	jailBinary = "/usr/local/bin/keepwatch"
	jailConfig = "/etc/keepwatch/keepwatch.yaml"
	jailState  = "/var/lib/keepwatch"
	otherUID   = 1000
)

// real is the place of a path of the jail on the real file system.
func (j *jail) real(p string) string { return filepath.Join(j.base, filepath.FromSlash(p)) }

// inside turns a real path back into a path of the jail.
func (j *jail) inside(real string) string {
	j.t.Helper()
	if real == j.base {
		return "/"
	}
	if !strings.HasPrefix(real, j.base+"/") {
		j.t.Fatalf("%s is outside the jail %s", real, j.base)
	}
	return strings.TrimPrefix(real, j.base)
}

// jailFS is install.FS for the jail. Lstat shows the user of the test as
// root and the paths of j.other as owned by another user.
type jailFS struct{ j *jail }

func (f jailFS) Lstat(p string) (install.Info, error) {
	i, err := install.OSFS{}.Lstat(f.j.real(p))
	if err != nil {
		return i, err
	}
	if uid, ok := f.j.other[p]; ok {
		i.UID = uid
	} else if i.UID == os.Getuid() {
		i.UID = 0
	}
	return i, nil
}
func (f jailFS) Mkdir(p string, perm fs.FileMode) error {
	return install.OSFS{}.Mkdir(f.j.real(p), perm)
}
func (f jailFS) Rmdir(p string) error                  { return install.OSFS{}.Rmdir(f.j.real(p)) }
func (f jailFS) OpenDir(p string) (install.Dir, error) { return install.OSFS{}.OpenDir(f.j.real(p)) }

// load is the configuration loader of install and doctor in the jail: the
// real loader on the real file, with the paths it returns turned back into
// paths of the jail.
func (j *jail) load(p string) (*config.Config, error) {
	cfg, err := config.Load(j.real(p))
	if err != nil {
		return nil, err
	}
	cfg.StateDir = j.inside(cfg.StateDir)
	if n := cfg.Notify.Ntfy; n != nil && n.TokenFile != "" {
		n.TokenFile = j.inside(n.TokenFile)
	}
	cfg.Sources.Main = j.inside(cfg.Sources.Main)
	return cfg, nil
}

func (j *jail) mkdir(p string, perm fs.FileMode) {
	j.t.Helper()
	if err := os.MkdirAll(j.real(p), 0o755); err != nil {
		j.t.Fatal(err)
	}
	if err := os.Chmod(j.real(p), perm); err != nil {
		j.t.Fatal(err)
	}
}

func (j *jail) write(p string, perm fs.FileMode, data string) {
	j.t.Helper()
	if err := os.WriteFile(j.real(p), []byte(data), perm); err != nil {
		j.t.Fatal(err)
	}
	if err := os.Chmod(j.real(p), perm); err != nil {
		j.t.Fatal(err)
	}
}

// link makes the path of the jail a symbolic link to another path of the jail.
func (j *jail) link(p, target string) {
	j.t.Helper()
	if err := os.Symlink(j.real(target), j.real(p)); err != nil {
		j.t.Fatal(err)
	}
}

// writeConfig writes a configuration file. stateDir and token are paths of the
// jail; token is empty for a configuration without notify.ntfy.
func (j *jail) writeConfig(p, stateDir, token string) {
	j.t.Helper()
	body := "state_dir: " + j.real(stateDir) + "\n"
	if token != "" {
		body += "notify:\n  ntfy:\n    url: " + j.ntfy.srv.URL + "\n    topic: alerts\n    token_file: " + j.real(token) + "\n"
	}
	j.write(p, 0o640, body)
}

// newJail is a host as "keepwatch init" and a first install leave it: the
// binary, the default configuration and the state directory, all root's.
func newJail(t *testing.T) *jail {
	t.Helper()
	j := &jail{t: t, base: t.TempDir(), sd: installtest.NewSystemd(), other: map[string]int{}, binary: jailBinary, cfgPath: jailConfig, ntfy: newFakeNtfy(t)}
	for _, d := range []string{"/etc/systemd/system", "/run/systemd/system", "/run/sshd", "/var/lib", "/usr/local/bin", "/usr/bin", "/dev", "/home", "/srv"} {
		j.mkdir(d, 0o755)
	}
	j.mkdir("/tmp", 0o777|fs.ModeSticky)
	j.mkdir("/etc/keepwatch", 0o750)
	j.mkdir(jailState, 0o700)
	j.write(jailBinary, 0o755, "the binary")
	j.writeConfig(jailConfig, jailState, "")
	old := opsFor
	opsFor = func(env) hostOps {
		return hostOps{
			fs: jailFS{j}, runner: j.sd.Runner, geteuid: func() int { return 0 }, exe: func() (string, error) { return j.binary, nil },
			loadConfig: j.load,
			state:      func(dir string) doctor.StateStatus { return doctor.OSStateProber(j.real(dir)) },
			resolver:   missingResolver{},
		}
	}
	t.Cleanup(func() { opsFor = old })
	return j
}

// placeUnits puts the unit files there as they are rendered for what the host
// says, without asking install: the units of a host that was installed before
// it became what it is now, or that somebody copied from a listing. The
// timers count as enabled and running.
func (j *jail) placeUnits() {
	j.t.Helper()
	iv, _ := install.ParseInterval(install.DefaultInterval)
	wk, _ := install.ParseWeekly(install.DefaultWeeklyReport)
	spec := install.Spec{Binary: j.binary, ConfigPath: j.cfgPath, StateDir: jailState, Interval: iv, Weekly: wk}
	if cfg, err := j.load(j.cfgPath); err == nil {
		spec.StateDir, spec.Notify = cfg.StateDir, cfg.Notify.Ntfy != nil
	}
	files, err := install.Render(spec)
	if err != nil {
		j.t.Fatal(err)
	}
	for _, f := range files {
		j.write(install.DefaultUnitDir+"/"+f.Name, 0o644, string(f.Content))
		j.sd.Loaded[f.Name] = true
	}
	for _, tm := range install.Timers {
		j.sd.Enabled[tm], j.sd.Active[tm] = true, true
	}
}

// resolved is where the kernel ends up for a path of the jail, as a path of
// the jail; ok is false when the path does not exist. This is the model of the
// kernel, and the only place that resolves symbolic links.
func (j *jail) resolved(p string) (string, bool) {
	j.t.Helper()
	real, err := filepath.EvalSymlinks(j.real(p))
	if err != nil {
		return "", false
	}
	base, err := filepath.EvalSymlinks(j.base)
	if err != nil {
		j.t.Fatal(err)
	}
	if real == base {
		return "/", true
	}
	if !strings.HasPrefix(real, base+"/") {
		j.t.Fatalf("%s leaves the jail", p)
	}
	return strings.TrimPrefix(real, base), true
}

// How a scheduled run fails in the matrix. The first three are the model of
// the sandbox, the last is the exit code of the command line itself.
const (
	failsHidden    = "hidden"        // a path is where the sandbox hides it or a reboot empties it
	failsNoBinary  = "203/EXEC"      // systemd finds no program
	failsNamespace = "226/NAMESPACE" // ReadWritePaths names a missing directory
	failsExit3     = "exit 3"        // keepwatch itself refuses at startup
)

// startup says whether the service of the unit file would start and do its
// job: fails is "" when it would, else one of the constants above, and why is
// the detail. First the model of the sandbox, then the command line of
// ExecStart for real.
func (j *jail) startup(unit string) (fails, why string) {
	j.t.Helper()
	content, err := os.ReadFile(j.real(install.DefaultUnitDir + "/" + unit))
	if err != nil {
		j.t.Fatal(err)
	}
	in := install.Inspect(content)
	var argv []string
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			argv = strings.Fields(strings.TrimPrefix(line, "ExecStart="))
		}
	}
	if len(argv) < 2 || argv[0] != in.Binary {
		j.t.Fatalf("%s: ExecStart = %q", unit, argv)
	}
	type dep struct {
		what, path string
		role       install.Role
		missing    string // what systemd does when the path is not there; "" lets the run find out
	}
	deps := []dep{
		{"the binary", in.Binary, install.RoleBinary, failsNoBinary},
		{"the configuration", in.ConfigPath, install.RoleConfig, ""},
		{"ReadWritePaths", in.ReadWritePaths, install.RoleState, failsNamespace},
	}
	if cfg, err := j.load(in.ConfigPath); err == nil && cfg.Notify.Ntfy != nil && cfg.Notify.Ntfy.TokenFile != "" {
		deps = append(deps, dep{"the token file", cfg.Notify.Ntfy.TokenFile, install.RoleConfig, ""})
	}
	for _, d := range deps {
		at, ok := j.resolved(d.path)
		if !ok {
			if d.missing != "" {
				return d.missing, fmt.Sprintf("%s %s is missing", d.what, d.path)
			}
			continue
		}
		if h, hidden := install.HiddenBy(at, d.role); hidden {
			return failsHidden, fmt.Sprintf("%s %s is at %s, below %s", d.what, d.path, at, h.Path)
		}
	}
	args := append([]string(nil), argv[1:]...)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--config" {
			args[i+1] = j.real(args[i+1])
		}
	}
	cat, err := catalog.Parse([]byte(miniCatalog))
	if err != nil {
		j.t.Fatal(err)
	}
	e := env{
		ctx: context.Background(), catalog: cat, runner: goodHost(), fs: probestest.MemFS{},
		now:        func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) },
		hostname:   func() (string, error) { return "testhost", nil },
		notifyOpts: []notify.Option{notify.WithBackoff(0)},
	}
	var out, errb bytes.Buffer
	switch code := dispatch(e, args, &out, &errb); code {
	case ExitOK, ExitError:
		return "", ""
	case ExitInternal:
		return failsExit3, strings.TrimSpace(errb.String())
	default:
		j.t.Fatalf("%s: %v: exit = %d: %s", unit, args, code, errb.String())
		return "", ""
	}
}

func TestParityOfInstallDoctorAndTheScheduledRun(t *testing.T) {
	home := func(j *jail) {
		j.mkdir("/home/tester", 0o750)
		j.other["/home/tester"] = otherUID
	}
	cases := []struct {
		name  string
		build func(j *jail)
		// fails: how the scheduled run fails; empty when it starts and does
		// its job.
		fails string
		// accepted: install accepts the host and doctor has no problem.
		accepted bool
		// msg is in the refusal of install and in the report of doctor.
		msg string
		// absent is a path that must not exist after the three have run: the
		// refusal has to come before anything is created.
		absent string
	}{
		{name: "valid: the default host", build: func(j *jail) {}, accepted: true},
		{name: "valid: own paths, conf.d, token file and notifications", build: func(j *jail) {
			j.mkdir("/srv/kw", 0o750)
			j.mkdir("/srv/kw/conf.d", 0o750)
			j.mkdir("/srv/kw/secrets", 0o700)
			j.mkdir("/srv/kw/state", 0o700)
			j.write("/srv/kw/secrets/ntfy.token", 0o600, testToken+"\n")
			j.write("/srv/kw/conf.d/10-site.yaml", 0o640, "host:\n  profile: web\n")
			j.cfgPath = "/srv/kw/main.yaml"
			j.writeConfig(j.cfgPath, "/srv/kw/state", "/srv/kw/secrets/ntfy.token")
		}, accepted: true},

		// What a reboot empties: /run for every role, not for state_dir alone.
		{name: "volatile: configuration and token file below /run", build: func(j *jail) {
			j.mkdir("/run/kw", 0o750)
			j.write("/run/kw/ntfy.token", 0o600, testToken+"\n")
			j.cfgPath = "/run/kw/keepwatch.yaml"
			j.writeConfig(j.cfgPath, jailState, "/run/kw/ntfy.token")
		}, fails: failsHidden, msg: "the configuration directory /run/kw is under /run"},
		{name: "volatile: token file below /run", build: func(j *jail) {
			j.mkdir("/run/kw", 0o700)
			j.write("/run/kw/ntfy.token", 0o600, testToken+"\n")
			j.writeConfig(j.cfgPath, jailState, "/run/kw/ntfy.token")
		}, fails: failsHidden, msg: "the directory of notify.ntfy.token_file /run/kw is under /run"},
		{name: "volatile: binary below /run", build: func(j *jail) {
			j.mkdir("/run/kwbin", 0o755)
			j.write("/run/kwbin/keepwatch", 0o755, "the binary")
			j.binary = "/run/kwbin/keepwatch"
		}, fails: failsHidden, msg: "the keepwatch binary /run/kwbin/keepwatch is under /run"},

		// What the sandbox hides although no option of the unit names it.
		{name: "hidden: token file below /run/credentials", build: func(j *jail) {
			j.mkdir("/run/credentials/kw", 0o700)
			j.write("/run/credentials/kw/ntfy.token", 0o600, testToken+"\n")
			j.writeConfig(j.cfgPath, jailState, "/run/credentials/kw/ntfy.token")
		}, fails: failsHidden, msg: "the directory of notify.ntfy.token_file /run/credentials/kw is under /run/credentials"},
		{name: "hidden: configuration below /run/credentials", build: func(j *jail) {
			j.mkdir("/run/credentials/kw", 0o750)
			j.cfgPath = "/run/credentials/kw/keepwatch.yaml"
			j.writeConfig(j.cfgPath, jailState, "")
		}, fails: failsHidden, msg: "the configuration directory /run/credentials/kw is under /run/credentials"},

		// A file system of the kernel: a mkdir there would make a control
		// group, so install must refuse before it creates anything.
		{name: "kernel: state_dir in the control group file system", build: func(j *jail) {
			j.mkdir("/sys/fs/cgroup", 0o755)
			j.writeConfig(j.cfgPath, "/sys/fs/cgroup/kwstate", "")
		}, fails: failsNamespace, msg: "state_dir /sys/fs/cgroup/kwstate is under /sys", absent: "/sys/fs/cgroup/kwstate"},

		// What the sandbox hides, or a reboot empties.
		{name: "hidden: configuration through a link into a directory below /tmp", build: func(j *jail) {
			j.mkdir("/tmp/kwreal/cfg", 0o750)
			j.link("/srv/kwlink", "/tmp/kwreal")
			j.cfgPath = "/srv/kwlink/cfg/keepwatch.yaml"
			j.writeConfig(j.cfgPath, jailState, "")
		}, fails: failsHidden, msg: "the configuration directory /srv/kwlink/cfg cannot be trusted: /srv/kwlink is a symbolic link"},
		{name: "hidden: token file below /tmp", build: func(j *jail) {
			j.mkdir("/tmp/kwtok", 0o700)
			j.write("/tmp/kwtok/ntfy.token", 0o600, testToken+"\n")
			j.writeConfig(j.cfgPath, jailState, "/tmp/kwtok/ntfy.token")
		}, fails: failsHidden, msg: "the directory of notify.ntfy.token_file /tmp/kwtok is under /tmp"},
		{name: "hidden: binary below /dev in the unit", build: func(j *jail) {
			j.mkdir("/dev/kw", 0o755)
			j.write("/dev/kw/keepwatch", 0o755, "the binary")
			j.binary = "/dev/kw/keepwatch"
		}, fails: failsHidden, msg: "the keepwatch binary /dev/kw/keepwatch is under /dev"},
		{name: "hidden: configuration below /tmp", build: func(j *jail) {
			j.mkdir("/tmp/kwc", 0o750)
			j.cfgPath = "/tmp/kwc/keepwatch.yaml"
			j.writeConfig(j.cfgPath, jailState, "")
		}, fails: failsHidden, msg: "the configuration directory /tmp/kwc is under /tmp"},
		{name: "hidden: state_dir below /run", build: func(j *jail) {
			j.mkdir("/run/kwstate", 0o700)
			j.writeConfig(j.cfgPath, "/run/kwstate", "")
		}, fails: failsHidden, msg: "state_dir /run/kwstate is under /run"},
		{name: "hidden: state_dir below the link /var/run", build: func(j *jail) {
			j.mkdir("/run/kwstate", 0o700)
			j.link("/var/run", "/run")
			j.writeConfig(j.cfgPath, "/var/run/kwstate", "")
		}, fails: failsHidden, msg: "state_dir /var/run/kwstate is under /var/run"},
		{name: "the binary is gone", build: func(j *jail) {
			if err := os.Remove(j.real(jailBinary)); err != nil {
				j.t.Fatal(err)
			}
		}, fails: failsNoBinary, msg: "the keepwatch binary /usr/local/bin/keepwatch does not exist"},

		// What another user can rename or replace. The run
		// starts on such a host (until that user acts), so the first column is
		// not what install and doctor go by here: they refuse because of who
		// can change the path.
		{name: "other user: configuration directory below the home of a user", build: func(j *jail) {
			home(j)
			j.mkdir("/home/tester/kwc", 0o750)
			j.cfgPath = "/home/tester/kwc/keepwatch.yaml"
			j.writeConfig(j.cfgPath, jailState, "")
		}, msg: "the configuration directory /home/tester/kwc cannot be trusted: /home/tester is owned by uid 1000"},
		{name: "other user: conf.d of a user", build: func(j *jail) {
			j.mkdir("/etc/keepwatch/conf.d", 0o755)
			j.other["/etc/keepwatch/conf.d"] = otherUID
		}, msg: "the conf.d directory /etc/keepwatch/conf.d cannot be trusted: /etc/keepwatch/conf.d is owned by uid 1000"},
		{name: "other user: token file below the home of a user", build: func(j *jail) {
			home(j)
			j.mkdir("/home/tester/secrets", 0o700)
			j.write("/home/tester/secrets/ntfy.token", 0o600, testToken+"\n")
			j.writeConfig(j.cfgPath, jailState, "/home/tester/secrets/ntfy.token")
		}, msg: "the directory of notify.ntfy.token_file /home/tester/secrets cannot be trusted: /home/tester is owned by uid 1000"},
		{name: "other user: state_dir below the home of a user", build: func(j *jail) {
			home(j)
			j.mkdir("/home/tester/kwstate", 0o700)
			j.writeConfig(j.cfgPath, "/home/tester/kwstate", "")
		}, msg: "state_dir /home/tester/kwstate cannot be trusted: /home/tester is owned by uid 1000"},
		{name: "other user: missing state_dir below the home of a user", build: func(j *jail) {
			home(j)
			j.writeConfig(j.cfgPath, "/home/tester/kwstate", "")
		}, fails: failsNamespace, msg: "state_dir /home/tester/kwstate cannot be created in a trusted place: /home/tester is owned by uid 1000"},
		{name: "link: the binary through a link (as /bin is one on a merged /usr)", build: func(j *jail) {
			j.write("/usr/bin/keepwatch", 0o755, "the binary")
			j.link("/bin", "/usr/bin")
			j.binary = "/bin/keepwatch"
		}, msg: "the keepwatch binary /bin/keepwatch cannot be trusted to run as root: /bin is a symbolic link"},

		// What the run itself refuses.
		{name: "run refuses: an invalid configuration behind the --config of the unit", build: func(j *jail) {
			j.mkdir("/srv/kw", 0o750)
			j.cfgPath = "/srv/kw/main.yaml"
			j.write(j.cfgPath, 0o640, "state_dir: "+j.real(jailState)+"\nnonsense: 1\n")
		}, fails: failsExit3, msg: "nonsense"},
		{name: "run refuses: a state_dir that group can write", build: func(j *jail) {
			j.mkdir("/srv/kwstate", 0o770)
			j.writeConfig(j.cfgPath, "/srv/kwstate", "")
		}, fails: failsExit3, msg: "state_dir /srv/kwstate cannot be trusted: /srv/kwstate has permissions 0770"},
	}
	var table strings.Builder
	fmt.Fprintf(&table, "%-72s | %-13s | %-8s | %s\n", "fixture", "ExecStart", "install", "doctor")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := newJail(t)
			c.build(j)
			j.placeUnits()
			before := j.unitFiles()

			// doctor, without --config: it has to find out what the units use.
			doctorCode, doctorOut, _ := runCmd("doctor")
			doctorOK := doctorCode == ExitOK
			if !doctorOK && doctorCode != ExitError {
				t.Fatalf("doctor: exit = %d\n%s", doctorCode, doctorOut)
			}

			// The scheduled runs: the command lines of the two unit files.
			fails, why := j.startup(install.CheckService)
			if fails == "" {
				fails, why = j.startup(install.ReportService)
			}
			starts := fails == ""

			// install, with the configuration and from the binary of the units.
			installCode, _, installErr := runCmd("install", "--config", j.cfgPath)
			installOK := installCode == ExitOK
			if !installOK && installCode != ExitUsage {
				t.Fatalf("install: exit = %d stderr = %q", installCode, installErr)
			}

			cell := func(ok bool, yes, no string) string {
				if ok {
					return yes
				}
				return no
			}
			fmt.Fprintf(&table, "%-72s | %-13s | %-8s | %s\n", c.name, cell(starts, "starts", fails), cell(installOK, "accepts", "refuses"), cell(doctorOK, "no problem", "PROBLEM"))

			// install and doctor agree, in both directions.
			if installOK != doctorOK {
				t.Errorf("install accepts = %v, but doctor has no problem = %v\ninstall: %s\ndoctor:\n%s", installOK, doctorOK, installErr, doctorOut)
			}
			// What they accept starts.
			if installOK && !starts {
				t.Errorf("install accepts a host on which the scheduled run does not work: %s", why)
			}
			if doctorOK && !starts {
				t.Errorf("doctor has no problem with a host on which the scheduled run does not work: %s\n%s", why, doctorOut)
			}
			// And each cell is what this fixture is known to be.
			if fails != c.fails {
				t.Errorf("the scheduled run fails with %q (%s), want %q", fails, why, c.fails)
			}
			if installOK != c.accepted {
				t.Errorf("install accepts = %v, want %v: %s", installOK, c.accepted, installErr)
			}
			if doctorOK != c.accepted {
				t.Errorf("doctor has no problem = %v, want %v:\n%s", doctorOK, c.accepted, doctorOut)
			}
			if c.msg != "" {
				if !strings.Contains(installErr, c.msg) {
					t.Errorf("the refusal of install lacks %q: %s", c.msg, installErr)
				}
				if !strings.Contains(doctorOut, "PROBLEM") || !strings.Contains(doctorOut, c.msg) {
					t.Errorf("the report of doctor lacks %q:\n%s", c.msg, doctorOut)
				}
			}
			if !installOK && j.unitFiles() != before {
				t.Error("a refused install changed the unit files")
			}
			if c.absent != "" {
				if _, err := os.Lstat(j.real(c.absent)); !os.IsNotExist(err) {
					t.Errorf("%s exists after the refusal (%v)", c.absent, err)
				}
			}
			if len(j.sd.Mutations()) != 0 && !installOK {
				t.Errorf("a refused install ran %v", j.sd.Mutations())
			}
		})
	}
	t.Logf("parity matrix:\n%s", table.String())
}

// unitFiles is the content of the unit directory of the jail.
func (j *jail) unitFiles() string {
	j.t.Helper()
	var b strings.Builder
	for _, n := range install.UnitNames {
		c, err := os.ReadFile(j.real(install.DefaultUnitDir + "/" + n))
		if err != nil {
			j.t.Fatal(err)
		}
		b.WriteString(n + "\n" + string(c))
	}
	return b.String()
}
