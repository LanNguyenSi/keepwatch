package config

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
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
