package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestConfigReadCapReachedThroughProcfs(t *testing.T) {
	// procfs files report st_size 0, so the size check in openSecureIn
	// passes and only the cap on the bytes actually read stops them.
	// /proc/kallsyms is several MiB on a normal kernel.
	if runtime.GOOS != "linux" {
		t.Skip("procfs is Linux only")
	}
	const p = "/proc/kallsyms"
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("%s not readable: %v", p, err)
	}
	if len(b) <= maxConfigSize {
		t.Skipf("%s has %d bytes, not over the %d byte cap", p, len(b), maxConfigSize)
	}
	t.Run("parseFile", func(t *testing.T) {
		dir, err := os.OpenRoot("/proc")
		if err != nil {
			t.Fatal(err)
		}
		defer dir.Close()
		_, _, errs := parseFile(dir, "kallsyms", p, configPolicy(ownerOf))
		if len(errs) == 0 || !strings.Contains(errs.Error(), "larger than 1048576 bytes") {
			t.Fatalf("parseFile(%s) errors = %v, want the read cap error", p, errs)
		}
	})
	t.Run("Load", func(t *testing.T) {
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), "larger than 1048576 bytes") {
			t.Fatalf("Load(%s) err = %v, want the read cap error", p, err)
		}
	})
}

func TestTokenReadCapReachedThroughProcfs(t *testing.T) {
	// The token file path is /proc/<pid>/environ of the test process
	// itself, re-executed with an environment over the 4096 byte cap.
	// Its st_size is 0, so only the read cap can refuse it. The
	// absolute pid path is used because /proc/self is a symlink.
	if runtime.GOOS != "linux" {
		t.Skip("procfs is Linux only")
	}
	if os.Getenv("KEEPWATCH_TEST_PROC_CHILD") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestTokenReadCapReachedThroughProcfs$", "-test.count=1")
		cmd.Env = append(os.Environ(), "KEEPWATCH_TEST_PROC_CHILD=1", "KEEPWATCH_TEST_BIG="+strings.Repeat("x", 6000))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		return
	}
	p := "/proc/" + strconv.Itoa(os.Getpid()) + "/environ"
	if fi, err := os.Stat(p); err != nil || fi.Size() != 0 {
		t.Skipf("%s: stat = %v, %v; want a size-0 file", p, fi, err)
	}
	cfg := &Config{Notify: Notify{Ntfy: &Ntfy{TokenFile: p}}}
	b, err := cfg.ReadToken()
	if err == nil || !strings.Contains(err.Error(), "larger than 4096") {
		t.Fatalf("ReadToken(%s) = %d bytes, err %v; want the read cap error", p, len(b), err)
	}
}

func TestReadTokenRechecksTokenDirectory(t *testing.T) {
	// The directory holding the token is checked at Load and again by
	// ReadToken: one made group- or other-writable afterwards is
	// refused before the token is opened.
	for _, mode := range []os.FileMode{0o775, 0o757} {
		dir, main := setup(t, nil)
		secrets := filepath.Join(dir, "secrets")
		if err := os.Mkdir(secrets, 0o755); err != nil {
			t.Fatal(err)
		}
		token := filepath.Join(secrets, "token")
		writeMode(t, token, []byte("s3cr3t\n"), 0o600)
		cfg := loadTokenCfg(t, main, token)
		if b, err := cfg.ReadToken(); err != nil || string(b) != "s3cr3t" {
			t.Fatalf("ReadToken before the change = %q, %v; want the token", b, err)
		}
		if err := os.Chmod(secrets, mode); err != nil {
			t.Fatal(err)
		}
		b, err := cfg.ReadToken()
		if err == nil || !strings.Contains(err.Error(), secrets+":") || !strings.Contains(err.Error(), "allow group or other writes") {
			t.Fatalf("ReadToken after chmod %04o = %q, %v; want the directory permissions error", mode, b, err)
		}
		if len(b) != 0 {
			t.Errorf("ReadToken returned %q along with the error", b)
		}
	}
}

func TestConfDIgnoresHiddenEntries(t *testing.T) {
	// A shell glob ignores names starting with a dot, so do we: a
	// hidden file, an editor lock symlink (dangling, as Emacs makes
	// them), a hidden directory and a hidden wrong-case or .yml name
	// neither load nor produce an error.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml":        "state_dir: /srv/kw\n",
		"conf.d/10-real.yaml":   "host:\n  profile: real\n",
		"conf.d/.hidden.yaml":   "bogus_key: 1\n",
		"conf.d/.old.yml":       "bogus_key: 1\n",
		"conf.d/.UPPER.YAML":    "bogus_key: 1\n",
		"conf.d/.hiddendir/x.y": "x\n",
	})
	if err := os.Symlink("user@host.4242", filepath.Join(dir, "conf.d", ".#10-real.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("10-real.yaml", filepath.Join(dir, "conf.d", ".#alias.yaml")); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load with hidden conf.d entries: %v", err)
	}
	if cfg.Host.Profile != "real" {
		t.Errorf("Host.Profile = %q, want real", cfg.Host.Profile)
	}
	if want := []string{filepath.Join(dir, "conf.d", "10-real.yaml")}; len(cfg.Sources.ConfD) != 1 || cfg.Sources.ConfD[0] != want[0] {
		t.Errorf("Sources.ConfD = %v, want %v", cfg.Sources.ConfD, want)
	}
}

func TestConfDHiddenRuleDoesNotHideVisibleNames(t *testing.T) {
	// Only a leading dot hides an entry: a name with a dot elsewhere
	// is still loaded and still judged.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml":          "state_dir: /srv/kw\n",
		"conf.d/a.b.yaml":         "bogus_key: 1\n",
		"conf.d/.ignored.yaml":    "bogus_key: 1\n",
		"conf.d/dotted.name.yaml": "host:\n  profile: dotted\n",
	})
	loadErrs(t, main, "a.b.yaml:1:", `unknown key "bogus_key"`)
}

func TestPathErrorNamesThePathOnce(t *testing.T) {
	// An fs.PathError reads "open <path>: <reason>", and an Error
	// already prefixes its File: the path must appear once.
	if os.Getuid() == 0 {
		t.Skip("running as root: mode 0000 does not deny root")
	}
	t.Run("main file permission denied", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
		if err := os.Chmod(main, 0o000); err != nil {
			t.Fatal(err)
		}
		errs := errsOf(t, main)
		if len(errs) != 1 {
			t.Fatalf("errors = %q, want exactly one", errs)
		}
		if n := strings.Count(errs[0], main); n != 1 {
			t.Errorf("error %q names the path %d times, want once", errs[0], n)
		}
		if !strings.Contains(errs[0], "permission denied") {
			t.Errorf("error %q lacks the reason", errs[0])
		}
	})
	t.Run("conf.d file permission denied", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		a := filepath.Join(dir, "conf.d", "a.yaml")
		if err := os.Chmod(a, 0o000); err != nil {
			t.Fatal(err)
		}
		errs := errsOf(t, main)
		if len(errs) != 1 || strings.Count(errs[0], a) != 1 || !strings.Contains(errs[0], "permission denied") {
			t.Errorf("errors = %q, want one error naming %s once with the reason", errs, a)
		}
	})
	t.Run("conf.d directory unreadable", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /srv/kw\n",
			"conf.d/a.yaml":  "host:\n  profile: a\n",
		})
		confd := filepath.Join(dir, "conf.d")
		if err := os.Chmod(confd, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(confd, 0o755) })
		errs := errsOf(t, main)
		if len(errs) != 1 || strings.Count(errs[0], confd) != 1 || !strings.Contains(errs[0], "permission denied") {
			t.Errorf("errors = %q, want one error naming %s once with the reason", errs, confd)
		}
	})
}
