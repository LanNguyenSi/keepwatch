package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/config"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfigCheckExitCodes(t *testing.T) {
	t.Run("valid config exits 0 with summary", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeFile(t, main, "state_dir: /srv/kw\n")
		writeFile(t, filepath.Join(dir, "conf.d", "a.yaml"), "host:\n  profile: a\n")
		writeFile(t, filepath.Join(dir, "conf.d", "b.yaml"), "host:\n  profile: b\n")
		code, stdout, stderr := run("config", "check", "--config", main)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
		}
		want := "config ok: " + main + " (+2 conf.d files)\n"
		if stdout != want {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	})

	t.Run("zero conf.d files", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeFile(t, main, "state_dir: /srv/kw\n")
		code, stdout, _ := run("config", "check", "--config", main)
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if want := "config ok: " + main + " (+0 conf.d files)\n"; stdout != want {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	})

	t.Run("invalid config exits 1 with file:line messages", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeFile(t, main, "state_dir: relative\nbadkey: 1\n")
		code, stdout, stderr := run("config", "check", "--config", main)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		for _, want := range []string{
			main + ":1: state_dir: must be an absolute path",
			main + ":2: unknown key \"badkey\"",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr %q lacks %q", stderr, want)
			}
		}
		if lines := strings.Split(strings.TrimSpace(stderr), "\n"); len(lines) != 2 {
			t.Errorf("want 2 error lines, got %d: %q", len(lines), stderr)
		}
	})

	t.Run("missing main file exits 1", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.yaml")
		code, _, stderr := run("config", "check", "--config", missing)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, missing) {
			t.Errorf("stderr %q lacks %s", stderr, missing)
		}
	})

	t.Run("usage errors exit 2", func(t *testing.T) {
		for _, args := range [][]string{
			{"config", "check", "--nope"},
			{"config", "check", "extra"},
		} {
			code, _, stderr := run(args...)
			if code != 2 || stderr == "" {
				t.Errorf("%v: exit = %d stderr = %q, want 2 with message", args, code, stderr)
			}
		}
	})
}

func TestInit(t *testing.T) {
	t.Run("fresh writes example with modes, dir 0750, file 0640", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "sub", "keepwatch.yaml")
		code, stdout, stderr := run("init", "--config", main)
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
		}
		if !strings.Contains(stdout, main) {
			t.Errorf("stdout %q lacks %s", stdout, main)
		}
		di, err := os.Stat(filepath.Dir(main))
		if err != nil {
			t.Fatal(err)
		}
		if di.Mode().Perm() != 0o750 {
			t.Errorf("dir mode = 0%o, want 0750", di.Mode().Perm())
		}
		fi, err := os.Stat(main)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("file mode = 0%o, want 0640", fi.Mode().Perm())
		}
		if _, err := config.Load(main); err != nil {
			t.Errorf("written example fails check: %v", err)
		}
	})

	t.Run("refuses to overwrite without force (exit 1)", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeFile(t, main, "keepme\n")
		code, _, stderr := run("init", "--config", main)
		if code != 1 {
			t.Fatalf("exit = %d, want 1", code)
		}
		if !strings.Contains(stderr, "--force") {
			t.Errorf("stderr %q lacks --force guidance", stderr)
		}
		b, _ := os.ReadFile(main)
		if string(b) != "keepme\n" {
			t.Errorf("file was modified: %q", b)
		}
	})

	t.Run("force overwrites (exit 0)", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeFile(t, main, "keepme\n")
		code, _, stderr := run("init", "--config", main, "--force")
		if code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr %q)", code, stderr)
		}
		if _, err := config.Load(main); err != nil {
			t.Errorf("--force did not write a valid example: %v", err)
		}
	})

	t.Run("usage errors exit 2", func(t *testing.T) {
		if code, _, _ := run("init", "--nope"); code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
	})
}

func TestInitAndConfigCheckTogether(t *testing.T) {
	// init then config check must succeed end to end.
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	if code, _, errb := run("init", "--config", main); code != 0 {
		t.Fatalf("init: %d %s", code, errb)
	}
	var out, errb bytes.Buffer
	if code := Run([]string{"config", "check", "--config", main}, &out, &errb); code != 0 {
		t.Fatalf("config check: %d %s", code, errb.String())
	}
}
