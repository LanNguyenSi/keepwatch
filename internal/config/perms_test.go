package config

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPathPermissions(t *testing.T) {
	// D-020: keepwatch runs as root, so every loaded path must be a
	// real file/directory owned by root or the running user and not
	// writable by group or other. Group-readable is fine.
	t.Run("group-writable main file is rejected", func(t *testing.T) {
		_, main := setup(t, nil)
		writeMode(t, main, []byte("state_dir: /srv/kw\n"), 0o664)
		loadErrs(t, main, main+":", "allow group or other writes")
	})
	t.Run("other-writable conf.d dir is rejected", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		confd := filepath.Join(dir, "conf.d")
		if err := os.Chmod(confd, 0o757); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, confd+":", "allow group or other writes")
	})
	t.Run("symlinked conf.d file is rejected", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
		})
		real := filepath.Join(dir, "elsewhere.yaml")
		writeMode(t, real, []byte("host:\n  profile: x\n"), 0o644)
		if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "conf.d", "a.yaml")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, link+":", "it is a symlink")
	})
	t.Run("symlinked main file is rejected", func(t *testing.T) {
		dir, main := setup(t, nil)
		real := filepath.Join(dir, "real.yaml")
		writeMode(t, real, []byte("state_dir: /srv/kw\n"), 0o644)
		if err := os.Symlink(real, main); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, main+":", "it is a symlink")
	})
	t.Run("symlinked conf.d dir is rejected", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
		})
		real := filepath.Join(dir, "elsewhere-conf.d")
		if err := os.MkdirAll(real, 0o755); err != nil {
			t.Fatal(err)
		}
		writeMode(t, filepath.Join(real, "a.yaml"), []byte("host:\n  profile: x\n"), 0o644)
		if err := os.Symlink(real, filepath.Join(dir, "conf.d")); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, filepath.Join(dir, "conf.d")+":", "must not be a symlink")
	})
	t.Run("foreign owner via injection is rejected", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
		_, err := Load(main, WithOwnerOf(func(fs.FileInfo) (int, error) { return 60001, nil }))
		if err == nil {
			t.Fatal("want foreign-owner error, got nil")
		}
		want := "owned by uid 60001, want uid 0 or"
		if !containsSub([]string{err.Error()}, want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	})
	t.Run("oversized config file is rejected", func(t *testing.T) {
		_, main := setup(t, nil)
		writeMode(t, main, bytes.Repeat([]byte("# pad\n"), maxConfigSize/6+1), 0o644)
		loadErrs(t, main, "larger than the limit")
	})
	t.Run("group-readable main file is accepted", func(t *testing.T) {
		_, main := setup(t, nil)
		writeMode(t, main, []byte("state_dir: /srv/kw\n"), 0o640)
		if _, err := Load(main); err != nil {
			t.Fatalf("Load with mode 0640: %v", err)
		}
	})
	t.Run("conf.d dir foreign owner via injection is rejected", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		confd := filepath.Join(dir, "conf.d")
		_, err := Load(main, WithOwnerOf(func(fi fs.FileInfo) (int, error) {
			if fi.Name() == "conf.d" {
				return 60001, nil
			}
			return ownerOf(fi)
		}))
		if err == nil {
			t.Fatal("want foreign-owner error for conf.d, got nil")
		}
		if !containsSub([]string{err.Error()}, confd+": owned by uid 60001, want uid 0 or") {
			t.Errorf("error %q lacks the conf.d owner error", err)
		}
	})
	t.Run("conf.d file group-writable is rejected", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		a := filepath.Join(dir, "conf.d", "a.yaml")
		if err := os.Chmod(a, 0o664); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, a+":", "allow group or other writes")
	})
}

func TestErrorsNameThePathOnce(t *testing.T) {
	// An Error is printed as "<file>: <msg>", so a message produced
	// with that same path already in it must not repeat the path:
	// never "<dir>/conf.d: <dir>/conf.d: permissions ..." and never
	// "<file>: cannot read: <file>: must be a regular file".
	t.Run("conf.d dir permissions", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		confd := filepath.Join(dir, "conf.d")
		if err := os.Chmod(confd, 0o757); err != nil {
			t.Fatal(err)
		}
		errs := errsOf(t, main)
		want := confd + ": permissions 0757 allow group or other writes"
		if !containsSub(errs, want) {
			t.Fatalf("errors %q lack %q", errs, want)
		}
		for _, e := range errs {
			if strings.Contains(e, confd+": "+confd+":") {
				t.Errorf("error repeats the path: %q", e)
			}
		}
	})
	t.Run("cannot read wraps the plain reason", func(t *testing.T) {
		_, main := setup(t, nil)
		if err := os.Mkdir(main, 0o755); err != nil {
			t.Fatal(err)
		}
		errs := errsOf(t, main)
		want := main + ": cannot read: must be a regular file, found " + os.ModeDir.String()
		if !containsSub(errs, want) {
			t.Fatalf("errors %q lack %q", errs, want)
		}
		for _, e := range errs {
			if strings.Contains(e, main+": cannot read: "+main) {
				t.Errorf("error repeats the path: %q", e)
			}
		}
	})
}

func TestOwnerRootAcceptedViaInjection(t *testing.T) {
	// A root-owned main file, conf.d file and conf.d directory are
	// accepted while the running uid is not 0: configPolicy accepts
	// uid 0 or the running uid, and checkConfigDir must not reject a
	// root-owned directory for a non-root caller.
	if os.Getuid() == 0 {
		t.Skip("running as root: an injected uid 0 cannot be told from the real owner")
	}
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /srv/kw\n",
		"conf.d/a.yaml":  "host:\n  profile: a\n",
	})
	rootOwned := map[string]bool{"keepwatch.yaml": true, "a.yaml": true, "conf.d": true}
	cfg, err := Load(main, WithOwnerOf(func(fi fs.FileInfo) (int, error) {
		if rootOwned[fi.Name()] {
			return 0, nil
		}
		return ownerOf(fi)
	}))
	if err != nil {
		t.Fatalf("Load with root-owned files and dir: %v", err)
	}
	if cfg.Host.Profile != "a" {
		t.Errorf("Host.Profile = %q, want a (conf.d applied)", cfg.Host.Profile)
	}
}

func TestOwnerForeignRejectedPerConfigPath(t *testing.T) {
	// A foreign non-zero uid on each of the main file, a conf.d file
	// and the conf.d directory is rejected.
	tests := []struct {
		name   string
		inject string // file name whose injected owner is foreign
	}{
		{name: "main file", inject: "keepwatch.yaml"},
		{name: "conf.d file", inject: "a.yaml"},
		{name: "conf.d dir", inject: "conf.d"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, main := setup(t, map[string]string{
				"keepwatch.yaml": "state_dir: /srv/kw\n",
				"conf.d/a.yaml":  "host:\n  profile: a\n",
			})
			path := map[string]string{
				"keepwatch.yaml": main,
				"a.yaml":         filepath.Join(dir, "conf.d", "a.yaml"),
				"conf.d":         filepath.Join(dir, "conf.d"),
			}[tc.inject]
			_, err := Load(main, WithOwnerOf(func(fi fs.FileInfo) (int, error) {
				if fi.Name() == tc.inject {
					return 60001, nil
				}
				return ownerOf(fi)
			}))
			if err == nil {
				t.Fatalf("Load with foreign owner on %s: want error, got nil", tc.inject)
			}
			if !containsSub([]string{err.Error()}, path) ||
				!containsSub([]string{err.Error()}, "owned by uid 60001, want uid 0 or") {
				t.Errorf("error %q lacks the foreign-owner error for %s", err, path)
			}
		})
	}
}
