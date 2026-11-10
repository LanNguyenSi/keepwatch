package install_test

import (
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
)

const tokenPath = "/etc/keepwatch/ntfy.token"

// fullPaths are the inputs of a manifest with every entry.
func fullPaths() install.Paths {
	return install.Paths{Binary: "/usr/local/bin/keepwatch", ConfigPath: cfgPath, StateDir: stateDir, TokenFile: tokenPath}
}

// placedFS is a host on which every entry of fullPaths passes: the
// configuration directory with the file, conf.d and the token file, and the
// state directory.
func placedFS() *installtest.MemFS {
	m := installtest.NewMemFS()
	m.AddDir("/etc/keepwatch", 0o750, 0)
	m.AddFile(cfgPath, 0o640, 0, "{}\n")
	m.AddDir("/etc/keepwatch/conf.d", 0o750, 0)
	m.AddFile(tokenPath, 0o600, 0, "t\n")
	m.AddDir(stateDir, 0o700, 0)
	return m
}

func TestManifest(t *testing.T) {
	type row struct {
		name, path string
		role       install.Role
		kind       install.PathKind
		absent     install.Absence
	}
	rows := func(m []install.PathEntry) []row {
		var out []row
		for _, e := range m {
			out = append(out, row{e.Name, e.Path, e.Role, e.Kind, e.Absent})
		}
		return out
	}
	p := fullPaths()
	p.TokenFile = "/srv/secrets/ntfy.token"
	want := []row{
		{"the keepwatch binary", "/usr/local/bin/keepwatch", install.RoleBinary, install.KindFile, install.MustExist},
		{"the configuration directory", "/etc/keepwatch", install.RoleConfig, install.KindDir, install.MustExist},
		{"the configuration file", cfgPath, install.RoleConfig, install.KindFile, install.MustExist},
		{"the conf.d directory", "/etc/keepwatch/conf.d", install.RoleConfig, install.KindDir, install.MayBeAbsent},
		{"the directory of notify.ntfy.token_file", "/srv/secrets", install.RoleConfig, install.KindDir, install.MustExist},
		{"notify.ntfy.token_file", "/srv/secrets/ntfy.token", install.RoleConfig, install.KindFile, install.MustExist},
		{"state_dir", stateDir, install.RoleState, install.KindDir, install.MayBeAbsent},
	}
	if got := rows(install.Manifest(p)); !reflect.DeepEqual(got, want) {
		t.Errorf("Manifest:\n got %+v\nwant %+v", got, want)
	}
	// An empty input adds no entry.
	if got := install.Manifest(install.Paths{}); len(got) != 0 {
		t.Errorf("empty: %+v", got)
	}
	for name, c := range map[string]struct {
		p    install.Paths
		want []string
	}{
		"binary only":   {install.Paths{Binary: "/b"}, []string{"/b"}},
		"config only":   {install.Paths{ConfigPath: "/c/k.yaml"}, []string{"/c", "/c/k.yaml", "/c/conf.d"}},
		"token only":    {install.Paths{TokenFile: "/t/tok"}, []string{"/t", "/t/tok"}},
		"state only":    {install.Paths{StateDir: "/s"}, []string{"/s"}},
		"no token file": {install.Paths{Binary: "/b", ConfigPath: "/c/k.yaml", StateDir: "/s"}, []string{"/b", "/c", "/c/k.yaml", "/c/conf.d", "/s"}},
	} {
		var got []string
		for _, e := range install.Manifest(c.p) {
			got = append(got, e.Path)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: paths = %v, want %v", name, got, c.want)
		}
	}
}

// problemsOf runs the placement check and returns the messages.
func problemsOf(m *installtest.MemFS, p install.Paths) []string {
	var out []string
	for _, pr := range install.CheckPlacement(m, install.Manifest(p)) {
		out = append(out, pr.Error())
	}
	return out
}

func TestCheckPlacementAcceptsAGoodHost(t *testing.T) {
	if got := problemsOf(placedFS(), fullPaths()); len(got) != 0 {
		t.Errorf("a good host: %q", got)
	}
	// conf.d is optional, and so is a token file.
	m := placedFS()
	m.Remove("/etc/keepwatch/conf.d")
	m.Remove(tokenPath)
	p := fullPaths()
	p.TokenFile = ""
	if got := problemsOf(m, p); len(got) != 0 {
		t.Errorf("without conf.d and token file: %q", got)
	}
	// state_dir may be missing as long as its parent passes.
	m = placedFS()
	m.Remove(stateDir)
	if got := problemsOf(m, fullPaths()); len(got) != 0 {
		t.Errorf("without state_dir: %q", got)
	}
	if len(m.Log) != 0 {
		t.Errorf("the check changed something: %v", m.Log)
	}
}

// Every entry is walked from "/": an ancestor or the entry itself that is not
// root's, that group or other can write, or that is a symbolic link, is a
// problem that names the entry and the component.
func TestCheckPlacementRefusesWhatAnotherUserCanChange(t *testing.T) {
	const others = "must be owned by root and not writable by group or other"
	cases := []struct {
		name  string
		setup func(m *installtest.MemFS, p *install.Paths)
		parts []string
	}{
		{"binary owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddFile(p.Binary, 0o755, 1000, "") },
			[]string{"the keepwatch binary /usr/local/bin/keepwatch cannot be trusted to run as root", "uid 1000", "install -o root -g root -m 0755 keepwatch /usr/local/bin/ && /usr/local/bin/keepwatch install"}},
		{"binary is a symbolic link", func(m *installtest.MemFS, p *install.Paths) { m.AddSymlink(p.Binary, "/usr/lib/kw") },
			[]string{"the keepwatch binary", "is a symbolic link", "install -o root -g root"}},
		{"binary missing", func(m *installtest.MemFS, p *install.Paths) { m.Remove(p.Binary) },
			[]string{"the keepwatch binary /usr/local/bin/keepwatch does not exist", "the scheduled run cannot start", "install the binary there"}},
		{"config directory owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddDir("/etc/keepwatch", 0o750, 1000) },
			[]string{"the configuration directory /etc/keepwatch cannot be trusted: /etc/keepwatch is owned by uid 1000", others, "rename or replace"}},
		{"ancestor of the config directory owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddDir("/etc", 0o755, 1000) },
			[]string{"the configuration directory /etc/keepwatch cannot be trusted: /etc is owned by uid 1000", others}},
		{"config directory writable by group", func(m *installtest.MemFS, p *install.Paths) { m.AddDir("/etc/keepwatch", 0o770, 0) },
			[]string{"the configuration directory /etc/keepwatch cannot be trusted", "permissions 0770"}},
		{"config directory is a symbolic link", func(m *installtest.MemFS, p *install.Paths) { m.AddSymlink("/etc/keepwatch", "/tmp/kwreal") },
			[]string{"the configuration directory /etc/keepwatch cannot be trusted: /etc/keepwatch is a symbolic link", `"realpath /etc/keepwatch" prints it`, "/run for /var/run"}},
		{"config directory missing", func(m *installtest.MemFS, p *install.Paths) { m.Remove("/etc/keepwatch") },
			[]string{"the configuration directory /etc/keepwatch does not exist", "the scheduled run exits 3"}},
		{"config file owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddFile(cfgPath, 0o640, 1000, "") },
			[]string{"the configuration file " + cfgPath + " cannot be trusted: " + cfgPath + " is owned by uid 1000", others}},
		{"config file writable by other", func(m *installtest.MemFS, p *install.Paths) { m.AddFile(cfgPath, 0o646, 0, "") },
			[]string{"the configuration file " + cfgPath + " cannot be trusted", "permissions 0646"}},
		{"config file is a symbolic link", func(m *installtest.MemFS, p *install.Paths) { m.AddSymlink(cfgPath, "/srv/kw.yaml") },
			[]string{"the configuration file " + cfgPath + " cannot be trusted", "is a symbolic link", "realpath"}},
		{"config file is a directory", func(m *installtest.MemFS, p *install.Paths) { m.AddDir(cfgPath, 0o755, 0) },
			[]string{"the configuration file " + cfgPath + " cannot be trusted", "not a regular file"}},
		{"config file missing", func(m *installtest.MemFS, p *install.Paths) { m.Remove(cfgPath) },
			[]string{"the configuration file " + cfgPath + " does not exist", "the scheduled run exits 3"}},
		{"conf.d owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddDir("/etc/keepwatch/conf.d", 0o750, 1000) },
			[]string{"the conf.d directory /etc/keepwatch/conf.d cannot be trusted", "uid 1000"}},
		{"conf.d is a dangling symbolic link", func(m *installtest.MemFS, p *install.Paths) { m.AddSymlink("/etc/keepwatch/conf.d", "/nowhere") },
			[]string{"the conf.d directory /etc/keepwatch/conf.d cannot be trusted", "is a symbolic link"}},
		{"conf.d is a file", func(m *installtest.MemFS, p *install.Paths) { m.AddFile("/etc/keepwatch/conf.d", 0o644, 0, "") },
			[]string{"the conf.d directory /etc/keepwatch/conf.d cannot be trusted", "not a directory"}},
		{"token directory owned by a user", func(m *installtest.MemFS, p *install.Paths) {
			m.AddDir("/home", 0o755, 0)
			m.AddDir("/home/tester", 0o750, 1000)
			m.AddDir("/home/tester/secrets", 0o700, 0)
			m.AddFile("/home/tester/secrets/ntfy.token", 0o600, 0, "t\n")
			p.TokenFile = "/home/tester/secrets/ntfy.token"
		}, []string{"the directory of notify.ntfy.token_file /home/tester/secrets cannot be trusted: /home/tester is owned by uid 1000", others}},
		{"token file owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddFile(tokenPath, 0o600, 1000, "t\n") },
			[]string{"notify.ntfy.token_file " + tokenPath + " cannot be trusted", "uid 1000"}},
		{"token file missing", func(m *installtest.MemFS, p *install.Paths) { m.Remove(tokenPath) },
			[]string{"notify.ntfy.token_file " + tokenPath + " does not exist", "the scheduled run exits 3"}},
		{"state_dir owned by a user", func(m *installtest.MemFS, p *install.Paths) { m.AddDir(stateDir, 0o700, 1000) },
			[]string{"state_dir " + stateDir + " cannot be trusted: " + stateDir + " is owned by uid 1000", others}},
		{"state_dir writable by group", func(m *installtest.MemFS, p *install.Paths) { m.AddDir(stateDir, 0o770, 0) },
			[]string{"state_dir " + stateDir + " cannot be trusted", "permissions 0770"}},
		{"state_dir is a symbolic link", func(m *installtest.MemFS, p *install.Paths) { m.AddSymlink(stateDir, "/etc") },
			[]string{"state_dir " + stateDir + " cannot be trusted", "is a symbolic link", "realpath"}},
		{"state_dir is a file", func(m *installtest.MemFS, p *install.Paths) { m.AddFile(stateDir, 0o600, 0, "") },
			[]string{"state_dir " + stateDir + " cannot be trusted", "not a directory"}},
		{"ancestor of state_dir owned by a user", func(m *installtest.MemFS, p *install.Paths) {
			m.AddDir("/home", 0o755, 0)
			m.AddDir("/home/tester", 0o750, 1000)
			m.AddDir("/home/tester/kwstate", 0o700, 0)
			p.StateDir = "/home/tester/kwstate"
		}, []string{"state_dir /home/tester/kwstate cannot be trusted: /home/tester is owned by uid 1000", others}},
		{"state_dir missing, its parent owned by a user", func(m *installtest.MemFS, p *install.Paths) {
			m.AddDir("/home", 0o755, 0)
			m.AddDir("/home/tester", 0o750, 1000)
			p.StateDir = "/home/tester/kwstate"
		}, []string{"state_dir /home/tester/kwstate cannot be created in a trusted place: /home/tester is owned by uid 1000", others}},
		{"state_dir missing, its parent a symbolic link", func(m *installtest.MemFS, p *install.Paths) {
			m.AddSymlink("/var/kwlink", "/var/lib")
			p.StateDir = "/var/kwlink/kw"
		}, []string{"state_dir /var/kwlink/kw cannot be created in a trusted place: /var/kwlink is a symbolic link", "realpath /var/kwlink/kw"}},
		{"state_dir missing, its parent a file", func(m *installtest.MemFS, p *install.Paths) {
			m.AddFile("/var/afile", 0o644, 0, "")
			p.StateDir = "/var/afile/kw"
		}, []string{"state_dir /var/afile/kw", "/var/afile is not a directory"}},
		{"state_dir and its parent missing", func(m *installtest.MemFS, p *install.Paths) { p.StateDir = "/srv/kw/state" },
			[]string{"state_dir /srv/kw/state does not exist and cannot be created, because its parent directory is missing too", "create the parent directory first"}},
		{"a path that is not clean", func(m *installtest.MemFS, p *install.Paths) { p.StateDir = "/var/lib/../lib/keepwatch" },
			[]string{"state_dir /var/lib/../lib/keepwatch cannot be trusted", "not a clean absolute path"}},
	}
	for _, c := range cases {
		m, p := placedFS(), fullPaths()
		c.setup(m, &p)
		got := problemsOf(m, p)
		if len(got) != 1 {
			t.Errorf("%s: %d problems, want 1: %q", c.name, len(got), got)
			continue
		}
		for _, part := range c.parts {
			if !strings.Contains(got[0], part) {
				t.Errorf("%s: the message lacks %q:\n%s", c.name, part, got[0])
			}
		}
		if len(m.Log) != 0 {
			t.Errorf("%s: the check changed something: %v", c.name, m.Log)
		}
	}
}

// The sandbox table decides by role, and it comes before the walk: a path
// below /var/run is refused for what /run is, not for the link at /var/run.
func TestCheckPlacementRefusesWhatTheSandboxHides(t *testing.T) {
	cases := []struct {
		name  string
		setup func(m *installtest.MemFS, p *install.Paths)
		parts []string
	}{
		{"binary under /tmp", func(m *installtest.MemFS, p *install.Paths) { p.Binary = "/tmp/keepwatch" },
			[]string{"the keepwatch binary /tmp/keepwatch is under /tmp:", "PrivateTmp=yes", "the scheduled run cannot start", "put it elsewhere"}},
		{"binary under /dev", func(m *installtest.MemFS, p *install.Paths) { p.Binary = "/dev/shm/keepwatch" },
			[]string{"the keepwatch binary /dev/shm/keepwatch is under /dev:", "PrivateDevices=yes"}},
		{"binary under the kernel modules", func(m *installtest.MemFS, p *install.Paths) { p.Binary = "/usr/lib/modules/keepwatch" },
			[]string{"is under /usr/lib/modules:", "ProtectKernelModules=yes"}},
		{"config under /tmp", func(m *installtest.MemFS, p *install.Paths) { p.ConfigPath = "/tmp/kwc/keepwatch.yaml" },
			[]string{"the configuration directory /tmp/kwc is under /tmp:", "the scheduled run exits 3", `put it elsewhere and run "keepwatch install" again`}},
		{"config under /var/tmp", func(m *installtest.MemFS, p *install.Paths) { p.ConfigPath = "/var/tmp/keepwatch.yaml" },
			[]string{"the configuration directory /var/tmp is under /var/tmp:"}},
		{"token file under /tmp", func(m *installtest.MemFS, p *install.Paths) { p.TokenFile = "/tmp/kwtok/ntfy.token" },
			[]string{"the directory of notify.ntfy.token_file /tmp/kwtok is under /tmp:", "PrivateTmp=yes", "the scheduled run exits 3"}},
		{"token file under /dev", func(m *installtest.MemFS, p *install.Paths) { p.TokenFile = "/dev/shm/ntfy.token" },
			[]string{"the directory of notify.ntfy.token_file /dev/shm is under /dev:"}},
		{"state_dir under /tmp", func(m *installtest.MemFS, p *install.Paths) { p.StateDir = "/tmp/kwstate" },
			[]string{"state_dir /tmp/kwstate is under /tmp:", "the scheduled run fails to start"}},
		{"state_dir under /run", func(m *installtest.MemFS, p *install.Paths) { p.StateDir = "/run/keepwatch" },
			[]string{"state_dir /run/keepwatch is under /run:", "empty after a reboot"}},
		{"state_dir under the link /var/run", func(m *installtest.MemFS, p *install.Paths) {
			m.AddSymlink("/var/run", "/run")
			p.StateDir = "/var/run/keepwatch"
		}, []string{"state_dir /var/run/keepwatch is under /var/run:", "empty after a reboot"}},
		{"state_dir under the link /var/lock", func(m *installtest.MemFS, p *install.Paths) {
			m.AddSymlink("/var/lock", "/run/lock")
			p.StateDir = "/var/lock/keepwatch"
		}, []string{"state_dir /var/lock/keepwatch is under /var/lock:", "empty after a reboot"}},
	}
	for _, c := range cases {
		m, p := placedFS(), fullPaths()
		c.setup(m, &p)
		got := problemsOf(m, p)
		if len(got) != 1 {
			t.Errorf("%s: %d problems, want 1: %q", c.name, len(got), got)
			continue
		}
		for _, part := range c.parts {
			if !strings.Contains(got[0], part) {
				t.Errorf("%s: the message lacks %q:\n%s", c.name, part, got[0])
			}
		}
		if strings.Contains(got[0], "symbolic link") {
			t.Errorf("%s: the link is named, not what the sandbox does:\n%s", c.name, got[0])
		}
	}
	// A configuration file and a token file may lie below /run: it is only
	// state_dir that must survive a reboot.
	m, p := placedFS(), fullPaths()
	m.AddDir("/run/kw", 0o750, 0)
	m.AddFile("/run/kw/keepwatch.yaml", 0o640, 0, "{}\n")
	m.AddFile("/run/kw/ntfy.token", 0o600, 0, "t\n")
	p.ConfigPath, p.TokenFile = "/run/kw/keepwatch.yaml", "/run/kw/ntfy.token"
	if got := problemsOf(m, p); len(got) != 0 {
		t.Errorf("configuration below /run: %q", got)
	}
	// An absent conf.d is not looked at, wherever it would lie; a present one
	// under a hidden path is covered by the directory above it.
	if got := problemsOf(placedFS(), install.Paths{ConfigPath: cfgPath}); len(got) != 0 {
		t.Errorf("config entries alone: %q", got)
	}
}

// One message per cause: what lies under a path that already has a problem is
// not reported again, and what lies elsewhere is.
func TestCheckPlacementReportsEachCauseOnce(t *testing.T) {
	m, p := placedFS(), fullPaths()
	m.AddDir("/etc/keepwatch", 0o777, 0)
	got := install.CheckPlacement(m, install.Manifest(p))
	if len(got) != 1 || got[0].Entry.Path != "/etc/keepwatch" {
		t.Fatalf("a writable configuration directory holding the file, conf.d and the token: %+v", got)
	}
	if !install.Blocks(got, cfgPath) || !install.Blocks(got, tokenPath) || !install.Blocks(got, "/etc/keepwatch") {
		t.Error("the problem of the directory does not block what is in it")
	}
	if install.Blocks(got, stateDir) || install.Blocks(got, "/etc/keepwatch2") || install.Blocks(got, "/etc") {
		t.Error("the problem blocks a path that is not under it")
	}
	if install.Blocks(nil, cfgPath) {
		t.Error("no problem blocks nothing")
	}
	// Independent causes are all reported, in the order of the manifest.
	m, p = placedFS(), fullPaths()
	m.AddFile(p.Binary, 0o777, 0, "")
	m.AddFile(cfgPath, 0o640, 1000, "")
	m.AddDir("/etc/keepwatch/conf.d", 0o777, 0)
	p.StateDir = "/tmp/kwstate"
	got = install.CheckPlacement(m, install.Manifest(p))
	var paths []string
	for _, pr := range got {
		paths = append(paths, pr.Entry.Path)
	}
	if want := []string{p.Binary, cfgPath, "/etc/keepwatch/conf.d", "/tmp/kwstate"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("problems for %v, want %v", paths, want)
	}
	if lines := strings.Split(install.PlacementError(got), "\n"); len(lines) != 4 || lines[0] != got[0].Error() || lines[3] != got[3].Error() {
		t.Errorf("PlacementError:\n%s", install.PlacementError(got))
	}
	// Hidden and Err are never both set, and Checked names what was walked.
	for _, pr := range got {
		if (pr.Hidden != nil) == (pr.Err != nil) {
			t.Errorf("%s: Hidden %v and Err %v", pr.Entry.Path, pr.Hidden, pr.Err)
		}
		if pr.Err != nil && pr.Checked != pr.Entry.Path {
			t.Errorf("%s: Checked = %q", pr.Entry.Path, pr.Checked)
		}
	}
}

// Install refuses every placement problem with exit kind "refused" before it
// changes anything, as a dry run too; the message is the one of the problem.
func TestInstallRefusesAPlacementProblem(t *testing.T) {
	type fixture struct {
		setup func(r *rig, o *install.InstallOptions)
		want  string
	}
	cases := map[string]fixture{
		"config through a link into /tmp (the link hides where it really is)": {func(r *rig, o *install.InstallOptions) {
			r.fs.AddDir("/srv", 0o755, 0)
			r.fs.AddSymlink("/srv/kwlink", "/tmp/kwreal")
			r.fs.AddDir("/srv/kwlink/cfg", 0o750, 0)
			r.fs.AddFile("/srv/kwlink/cfg/keepwatch.yaml", 0o640, 0, "{}\n")
			o.Spec.ConfigPath = "/srv/kwlink/cfg/keepwatch.yaml"
		}, "the configuration directory /srv/kwlink/cfg cannot be trusted: /srv/kwlink is a symbolic link"},
		"token file under /tmp": {func(r *rig, o *install.InstallOptions) { o.TokenFile = "/tmp/kwtok/ntfy.token" },
			"the directory of notify.ntfy.token_file /tmp/kwtok is under /tmp"},
		"token file in a directory of a user": {func(r *rig, o *install.InstallOptions) {
			r.fs.AddDir("/home", 0o755, 0)
			r.fs.AddDir("/home/tester", 0o750, 1000)
			r.fs.AddFile("/home/tester/ntfy.token", 0o600, 0, "t\n")
			o.TokenFile = "/home/tester/ntfy.token"
		}, "the directory of notify.ntfy.token_file /home/tester cannot be trusted: /home/tester is owned by uid 1000"},
		"configuration directory below the home of a user": {func(r *rig, o *install.InstallOptions) {
			r.fs.AddDir("/home", 0o755, 0)
			r.fs.AddDir("/home/tester", 0o750, 1000)
			r.fs.AddDir("/home/tester/kwc", 0o750, 0)
			r.fs.AddFile("/home/tester/kwc/keepwatch.yaml", 0o640, 0, "{}\n")
			o.Spec.ConfigPath = "/home/tester/kwc/keepwatch.yaml"
		}, "the configuration directory /home/tester/kwc cannot be trusted: /home/tester is owned by uid 1000"},
		"conf.d of a user": {func(r *rig, o *install.InstallOptions) { r.fs.AddDir("/etc/keepwatch/conf.d", 0o755, 1000) },
			"the conf.d directory /etc/keepwatch/conf.d cannot be trusted"},
		"missing state_dir below the home of a user": {func(r *rig, o *install.InstallOptions) {
			r.fs.AddDir("/home", 0o755, 0)
			r.fs.AddDir("/home/tester", 0o750, 1000)
			o.Spec.StateDir = "/home/tester/kwstate"
		}, "state_dir /home/tester/kwstate cannot be created in a trusted place: /home/tester is owned by uid 1000"},
		"state_dir under /run": {func(r *rig, o *install.InstallOptions) { o.Spec.StateDir = "/run/keepwatch" },
			"state_dir /run/keepwatch is under /run"},
		"binary under /dev": {func(r *rig, o *install.InstallOptions) { o.Spec.Binary = "/dev/shm/keepwatch" },
			"the keepwatch binary /dev/shm/keepwatch is under /dev"},
	}
	for name, c := range cases {
		for _, dry := range []bool{false, true} {
			r := newRig()
			o := install.InstallOptions{Spec: spec(t), DryRun: dry}
			c.setup(r, &o)
			err := r.install(t, o)
			if !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s dry=%v: err = %v, want ErrRefused with %q", name, dry, err, c.want)
			}
			if len(r.fs.Log) != 0 || len(r.sd.Runner.Calls) != 0 {
				t.Errorf("%s dry=%v: a refused install did something: %v %v", name, dry, r.fs.Log, r.sd.Runner.Calls)
			}
			// What install refuses, Preflight (the --print path) refuses with the
			// same words.
			o.ConfigFound = true
			if _, perr := install.Preflight(r.fs, o); perr == nil || perr.Error() != err.Error() {
				t.Errorf("%s: Preflight says %v, Install says %v", name, perr, err)
			}
		}
	}
}

// A good host with a token file and conf.d installs, and Preflight returns the
// files that Install writes.
func TestInstallWithATokenFileAndConfD(t *testing.T) {
	r := newRig()
	r.fs.AddDir("/etc/keepwatch/conf.d", 0o750, 0)
	r.fs.AddFile(tokenPath, 0o600, 0, "t\n")
	o := install.InstallOptions{Spec: spec(t), TokenFile: tokenPath, ConfigFound: true}
	files, err := install.Preflight(r.fs, o)
	if err != nil || len(files) != 4 {
		t.Fatalf("Preflight: %d files, %v", len(files), err)
	}
	if len(r.fs.Log) != 0 {
		t.Errorf("Preflight changed something: %v", r.fs.Log)
	}
	if err := r.install(t, o); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if got, _ := r.fs.Content(unitPath(f.Name)); got != string(f.Content) {
			t.Errorf("%s was not written as Preflight returned it", f.Name)
		}
	}
	// Preflight refuses what Render refuses and a missing configuration.
	bad := o
	bad.Spec.StateDir = "/var/lib/kw\nReadWritePaths=/"
	if _, err := install.Preflight(r.fs, bad); !errors.Is(err, install.ErrRefused) {
		t.Errorf("an invalid spec: %v", err)
	}
	o.ConfigFound = false
	if _, err := install.Preflight(r.fs, o); !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "keepwatch init") {
		t.Errorf("a missing configuration: %v", err)
	}
}

// A missing state_dir is created by a real install only: a dry run names it
// and creates nothing, and neither does Preflight.
func TestOnlyARealInstallCreatesTheStateDirectory(t *testing.T) {
	r := newRig()
	if _, err := install.Preflight(r.fs, install.InstallOptions{Spec: spec(t), ConfigFound: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.install(t, install.InstallOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if r.fs.Exists(stateDir) || len(r.fs.Log) != 0 {
		t.Fatalf("a dry run or Preflight created something: %v", r.fs.Log)
	}
	if !strings.Contains(r.out.String(), "would create directory "+stateDir+" (mode 0700)") {
		t.Errorf("the dry run does not name the directory:\n%s", r.out)
	}
	if err := r.install(t, install.InstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if r.fs.Mode(stateDir).Perm() != 0o700 || r.fs.Log[0] != "mkdir "+stateDir {
		t.Errorf("state_dir after the install: mode %v, log %v", r.fs.Mode(stateDir), r.fs.Log)
	}
	// An existing state_dir is neither created nor reported as created.
	if err := r.install(t, install.InstallOptions{DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.out.String(), "create directory") {
		t.Errorf("an existing directory is reported as created:\n%s", r.out)
	}
	// A failing mkdir stops the install before a unit is written.
	r = newRig()
	r.fs.FailMkdir[stateDir] = errors.New("read-only file system")
	err := r.install(t, install.InstallOptions{})
	if !errors.Is(err, install.ErrFailed) || !strings.Contains(err.Error(), "create "+stateDir+": read-only file system") {
		t.Errorf("a failing mkdir: %v", err)
	}
	if len(r.fs.Log) != 0 || len(r.sd.Mutations()) != 0 {
		t.Errorf("the install went on after the failure: %v %v", r.fs.Log, r.sd.Mutations())
	}
}

// errFS is a file system on which looking at some paths fails.
type errFS struct {
	install.FS
	fail map[string]error
}

func (f errFS) Lstat(p string) (install.Info, error) {
	if err, ok := f.fail[p]; ok {
		return install.Info{}, err
	}
	return f.FS.Lstat(p)
}

// Only "it is not there" counts as absent. A path that cannot be looked at
// (no permission, an I/O error) is not accepted as a missing conf.d, and not
// replaced by its parent as a missing state_dir: it is a problem.
func TestCheckPlacementDoesNotTakeAnErrorForAbsence(t *testing.T) {
	for _, p := range []string{"/etc/keepwatch/conf.d", stateDir} {
		m := placedFS()
		m.Remove("/etc/keepwatch/conf.d")
		m.Remove(stateDir)
		if got := install.CheckPlacement(m, install.Manifest(fullPaths())); len(got) != 0 {
			t.Fatalf("both absent: %+v", got)
		}
		got := install.CheckPlacement(errFS{m, map[string]error{p: fs.ErrPermission}}, install.Manifest(fullPaths()))
		if len(got) != 1 || got[0].Entry.Path != p || got[0].Checked != p || !errors.Is(got[0].Err, fs.ErrPermission) {
			t.Errorf("%s cannot be looked at: %+v", p, got)
		}
	}
}
