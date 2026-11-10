package install_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
)

// The placement check on the real file system, with nothing modelled: the walk
// starts at "/", the owners are changed with chown and the links are links.
// That needs root, and a place that is root's from "/" down, so the tree is
// made directly below "/" (the temporary directory is below /tmp, which others
// can write and which the sandbox table refuses). The Linux container run of
// the test suite runs this.
func TestPlacementOnTheRealFileSystemAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the walk starts at / and another owner is made with chown")
	}
	base, err := os.MkdirTemp("/", "kwplacement")
	if err != nil {
		t.Skipf("cannot create a directory below /: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(rel string, perm os.FileMode) string {
		t.Helper()
		p := filepath.Join(base, rel)
		must(os.MkdirAll(p, 0o755))
		must(os.Chmod(p, perm))
		return p
	}
	write := func(rel string, perm os.FileMode) string {
		t.Helper()
		p := filepath.Join(base, rel)
		must(os.WriteFile(p, []byte("x\n"), perm))
		must(os.Chmod(p, perm))
		return p
	}
	must(os.Chmod(base, 0o755))
	if err := install.TrustedPath(install.OSFS{}, base, install.KindDir); err != nil {
		t.Skipf("the root directory of this host is not root's alone: %v", err)
	}
	mkdir("bin", 0o755)
	mkdir("etc", 0o750)
	mkdir("etc/conf.d", 0o750)
	mkdir("var", 0o755)
	good := install.Paths{
		Binary:     write("bin/keepwatch", 0o755),
		ConfigPath: write("etc/keepwatch.yaml", 0o640),
		TokenFile:  write("etc/ntfy.token", 0o600),
		StateDir:   filepath.Join(base, "var/state"), // missing: its parent is checked
	}
	check := func(p install.Paths) string {
		return install.PlacementError(install.CheckPlacement(install.OSFS{}, install.Manifest(p)))
	}
	if msg := check(good); msg != "" {
		t.Fatalf("a tree that is root's alone:\n%s", msg)
	}

	// Another user owns a directory above each kind of path.
	mkdir("home/tester", 0o750)
	must(os.Chown(filepath.Join(base, "home/tester"), 12345, 12345))
	mkdir("home/tester/kwc", 0o750)
	mkdir("home/tester/kwc/conf.d", 0o750)
	mkdir("home/tester/kwstate", 0o700)
	for name, c := range map[string]struct {
		change func(p *install.Paths)
		want   string
	}{
		"binary":            {func(p *install.Paths) { p.Binary = write("home/tester/keepwatch", 0o755) }, "the keepwatch binary"},
		"configuration":     {func(p *install.Paths) { p.ConfigPath = write("home/tester/kwc/keepwatch.yaml", 0o640) }, "the configuration directory"},
		"token file":        {func(p *install.Paths) { p.TokenFile = write("home/tester/kwc/ntfy.token", 0o600) }, "the directory of notify.ntfy.token_file"},
		"state_dir":         {func(p *install.Paths) { p.StateDir = filepath.Join(base, "home/tester/kwstate") }, "state_dir"},
		"missing state_dir": {func(p *install.Paths) { p.StateDir = filepath.Join(base, "home/tester/absent") }, "cannot be created in a trusted place"},
	} {
		p := good
		c.change(&p)
		msg := check(p)
		if !strings.Contains(msg, c.want) || !strings.Contains(msg, filepath.Join(base, "home/tester")+" is owned by uid 12345, not by root") || strings.Count(msg, "\n") != 0 {
			t.Errorf("%s below a directory of another user:\n%s", name, msg)
		}
	}
	// conf.d itself belongs to another user.
	must(os.Chown(filepath.Join(base, "etc/conf.d"), 12345, 0))
	if msg := check(good); !strings.Contains(msg, "the conf.d directory "+filepath.Join(base, "etc/conf.d")+" cannot be trusted") {
		t.Errorf("conf.d of another user:\n%s", msg)
	}
	must(os.Chown(filepath.Join(base, "etc/conf.d"), 0, 0))

	// A link in the path, here into the real /tmp: where the file really is,
	// the sandbox hides it, and the text of the path does not show that.
	hidden, err := os.MkdirTemp("", "kwreal")
	must(err)
	t.Cleanup(func() { os.RemoveAll(hidden) })
	must(os.WriteFile(filepath.Join(hidden, "keepwatch.yaml"), []byte("{}\n"), 0o640))
	must(os.Symlink(hidden, filepath.Join(base, "kwlink")))
	p := good
	p.ConfigPath = filepath.Join(base, "kwlink", "keepwatch.yaml")
	if msg := check(p); !strings.Contains(msg, filepath.Join(base, "kwlink")+" is a symbolic link") || !strings.Contains(msg, "realpath") {
		t.Errorf("configuration through a link:\n%s", msg)
	}
	// And named by its real path, the table refuses it (when the temporary
	// directory is below /tmp, as it is unless TMPDIR says otherwise).
	p.ConfigPath = filepath.Join(hidden, "keepwatch.yaml")
	if strings.HasPrefix(hidden, "/tmp/") {
		if msg := check(p); !strings.Contains(msg, "is under /tmp") {
			t.Errorf("configuration below /tmp:\n%s", msg)
		}
	}

	// Install on the real file system: it creates the missing state directory
	// and what it created passes the check.
	units, run := mkdir("units", 0o755), mkdir("run", 0o755)
	iv, _ := install.ParseInterval(install.DefaultInterval)
	wk, _ := install.ParseWeekly(install.DefaultWeeklyReport)
	sd := installtest.NewSystemd()
	deps := install.Deps{FS: install.OSFS{}, Runner: sd.Runner, Geteuid: os.Geteuid, UnitDir: units, SystemdRunDir: run, Out: &bytes.Buffer{}}
	opts := install.InstallOptions{Spec: install.Spec{Binary: good.Binary, ConfigPath: good.ConfigPath, StateDir: good.StateDir, Interval: iv, Weekly: wk},
		ConfigFound: true, TokenFile: good.TokenFile}
	opts.DryRun = true
	must(install.Install(context.Background(), deps, opts))
	if _, err := os.Lstat(good.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dry run created state_dir: %v", err)
	}
	opts.DryRun = false
	must(install.Install(context.Background(), deps, opts))
	if fi, err := os.Lstat(good.StateDir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("state_dir after the install: %v %v", fi, err)
	}
	if msg := check(good); msg != "" {
		t.Errorf("after the install:\n%s", msg)
	}
	// Somebody gives the state directory away: the next install refuses.
	must(os.Chown(good.StateDir, 12345, 0))
	if err := install.Install(context.Background(), deps, opts); !errors.Is(err, install.ErrRefused) || !strings.Contains(err.Error(), "is owned by uid 12345") {
		t.Errorf("state_dir of another user: %v", err)
	}
}
