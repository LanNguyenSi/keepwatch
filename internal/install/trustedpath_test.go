package install_test

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/install/installtest"
)

func TestTrustedPathOnTheFakeHost(t *testing.T) {
	const bin = "/usr/local/bin/keepwatch"
	cases := []struct {
		name  string
		setup func(m *installtest.MemFS)
		path  string
		kind  install.PathKind
		want  string // substring of the error; empty means trusted
	}{
		{name: "root-owned binary below root-owned directories", path: bin},
		{name: "a root-owned directory", path: "/usr/local/bin", kind: install.KindDir},
		{name: "the root directory", path: "/", kind: install.KindDir},
		{name: "binary owned by a user", setup: func(m *installtest.MemFS) { m.AddFile(bin, 0o755, 1000, "") }, path: bin, want: "uid 1000"},
		{name: "binary writable by group", setup: func(m *installtest.MemFS) { m.AddFile(bin, 0o775, 0, "") }, path: bin, want: "writable by group or other"},
		{name: "binary writable by other", setup: func(m *installtest.MemFS) { m.AddFile(bin, 0o757, 0, "") }, path: bin, want: "writable by group or other"},
		{name: "binary is a symlink to a trusted file", setup: func(m *installtest.MemFS) {
			m.AddFile("/usr/lib-keepwatch", 0o755, 0, "")
			m.AddSymlink(bin, "/usr/lib-keepwatch")
		}, path: bin, want: "symbolic link"},
		{name: "binary is a dangling symlink", setup: func(m *installtest.MemFS) { m.AddSymlink(bin, "/nowhere") }, path: bin, want: "symbolic link"},
		{name: "binary is a directory", setup: func(m *installtest.MemFS) { m.AddDir(bin, 0o755, 0) }, path: bin, want: "not a regular file"},
		{name: "a directory path that is a file", setup: func(m *installtest.MemFS) {}, path: bin, kind: install.KindDir, want: "not a directory"},
		{name: "missing", path: "/usr/local/bin/nothing", want: "does not exist"},
		{name: "a component is a symlink", setup: func(m *installtest.MemFS) {
			m.Remove("/usr/local")
			m.AddSymlink("/usr/local", "/srv")
		}, path: bin, want: "/usr/local is a symbolic link"},
		{name: "a component is a file", setup: func(m *installtest.MemFS) { m.AddFile("/usr/local", 0o755, 0, "") }, path: bin, want: "/usr/local is not a directory"},
		{name: "a directory owned by a user", setup: func(m *installtest.MemFS) { m.AddDir("/usr/local/bin", 0o755, 1000) }, path: bin, want: "/usr/local/bin is owned by uid 1000"},
		{name: "a directory writable by group", setup: func(m *installtest.MemFS) { m.AddDir("/usr/local", 0o775, 0) }, path: bin, want: "/usr/local has permissions 0775"},
		{name: "a sticky world-writable directory", setup: func(m *installtest.MemFS) { m.AddDir("/usr", 0o1777, 0) }, path: bin, want: "/usr has permissions"},
		{name: "the root directory writable by other", setup: func(m *installtest.MemFS) { m.AddDir("/", 0o757, 0) }, path: bin, want: "/ has permissions"},
		{name: "the root directory owned by a user", setup: func(m *installtest.MemFS) { m.AddDir("/", 0o755, 1000) }, path: bin, want: "/ is owned by uid 1000"},
		{name: "home directory of a user", setup: func(m *installtest.MemFS) {
			m.AddDir("/home", 0o755, 0)
			m.AddDir("/home/tester", 0o755, 1000)
			m.AddDir("/home/tester/bin", 0o755, 1000)
			m.AddFile("/home/tester/bin/keepwatch", 0o755, 1000, "")
		}, path: "/home/tester/bin/keepwatch", want: "owned by uid 1000"},
		{name: "relative", path: "keepwatch", want: "clean absolute"},
		{name: "not clean", path: "/usr/local/../local/bin/keepwatch", want: "clean absolute"},
		{name: "empty", path: "", want: "clean absolute"},
	}
	for _, c := range cases {
		m := installtest.NewMemFS()
		if c.setup != nil {
			c.setup(m)
		}
		err := install.TrustedPath(m, c.path, c.kind)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: err = %v, want it to contain %q", c.name, err, c.want)
		}
	}
	if err := install.TrustedPath(installtest.NewMemFS(), "/usr/local/bin/nothing", install.KindFile); !install.IsMissing(err) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file is not reported as missing: %v", err)
	}
	if err := install.TrustedPath(installtest.NewMemFS(), bin, install.KindFile); install.IsMissing(err) {
		t.Errorf("IsMissing(nil) = true")
	}
}

// Install refuses a binary that a non-root user can change, before it writes
// anything, and says how to fix it.
func TestInstallRefusesAnUntrustedBinary(t *testing.T) {
	setups := map[string]func(r *rig){
		"owned by a user": func(r *rig) {
			r.fs.AddDir("/home", 0o755, 0)
			r.fs.AddDir("/home/tester", 0o755, 1000)
			r.fs.AddFile("/home/tester/keepwatch", 0o755, 1000, "")
		},
		"writable by group":         func(r *rig) { r.fs.AddFile("/usr/local/bin/keepwatch", 0o775, 0, "") },
		"directory owned by a user": func(r *rig) { r.fs.AddDir("/usr/local/bin", 0o755, 1000) },
		"symlink": func(r *rig) {
			r.fs.Remove("/usr/local/bin/keepwatch")
			r.fs.AddSymlink("/usr/local/bin/keepwatch", "/etc/hostname")
		},
		"missing": func(r *rig) { r.fs.Remove("/usr/local/bin/keepwatch") },
	}
	for name, mutate := range setups {
		for _, dry := range []bool{false, true} {
			r := newRig()
			mutate(r)
			s := spec(t)
			if name == "owned by a user" {
				s.Binary = "/home/tester/keepwatch"
			}
			err := r.install(t, install.InstallOptions{Spec: s, DryRun: dry, ConfigFound: true})
			if !errors.Is(err, install.ErrRefused) {
				t.Errorf("%s dry=%v: err = %v, want ErrRefused", name, dry, err)
				continue
			}
			wants := []string{s.Binary, "cannot be trusted to run as root", "install -o root -g root -m 0755 keepwatch /usr/local/bin/"}
			if name == "missing" {
				// A binary that is not there is not called untrusted.
				wants = []string{s.Binary, "does not exist", "the scheduled run cannot start"}
				if strings.Contains(err.Error(), "cannot be trusted") {
					t.Errorf("a missing binary is called untrusted: %v", err)
				}
			}
			for _, want := range wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the message lacks %q: %v", name, want, err)
				}
			}
			if len(r.fs.Log) != 0 || len(r.sd.Mutations()) != 0 {
				t.Errorf("%s: a refused install changed something: %v %v", name, r.fs.Log, r.sd.Mutations())
			}
		}
	}
}
