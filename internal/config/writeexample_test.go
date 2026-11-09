package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteExampleSymlinks(t *testing.T) {
	t.Run("dangling symlink without force is refused and its target is not created", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		target := filepath.Join(dir, "elsewhere.yaml")
		if err := os.Symlink(target, main); err != nil {
			t.Fatal(err)
		}
		err := WriteExample(main, false)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("WriteExample on a dangling symlink: err = %v, want a refusal", err)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Errorf("the refusal must not create the symlink target %s", target)
		}
	})
	t.Run("symlink to a file with force is refused and the target is untouched", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		target := filepath.Join(dir, "elsewhere.yaml")
		writeMode(t, target, []byte("do not touch\n"), 0o600)
		if err := os.Symlink(target, main); err != nil {
			t.Fatal(err)
		}
		err := WriteExample(main, true)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("WriteExample --force on a symlink: err = %v, want a refusal", err)
		}
		if b, _ := os.ReadFile(target); !bytes.Equal(b, []byte("do not touch\n")) {
			t.Errorf("the symlink target was modified: %q", b)
		}
	})
	t.Run("symlinked directory is refused", func(t *testing.T) {
		dir := t.TempDir()
		real := filepath.Join(dir, "realdir")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "confdir")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := WriteExample(filepath.Join(link, "keepwatch.yaml"), false); err == nil ||
			!strings.Contains(err.Error(), "is a symlink") {
			t.Fatalf("WriteExample into a symlinked dir: err = %v, want a symlink refusal", err)
		}
		if _, err := os.Lstat(filepath.Join(real, "keepwatch.yaml")); !os.IsNotExist(err) {
			t.Error("nothing must be written into the symlinked-to directory")
		}
	})
	t.Run("directory that is a plain file is refused", func(t *testing.T) {
		dir := t.TempDir()
		notadir := filepath.Join(dir, "notadir")
		writeMode(t, notadir, []byte("x\n"), 0o644)
		if err := WriteExample(filepath.Join(notadir, "keepwatch.yaml"), false); err == nil ||
			!strings.Contains(err.Error(), "not a directory") {
			t.Fatalf("WriteExample through a file: err = %v, want a not-a-directory error", err)
		}
	})
	t.Run("regular file with force is replaced", func(t *testing.T) {
		dir := t.TempDir()
		main := filepath.Join(dir, "keepwatch.yaml")
		writeMode(t, main, []byte("old content\n"), 0o644)
		if err := WriteExample(main, true); err != nil {
			t.Fatalf("WriteExample --force: %v", err)
		}
		b, err := os.ReadFile(main)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, Example()) {
			t.Error("--force must replace the regular file with the example")
		}
	})
}

func TestWriteExampleModeIndependentOfUmask(t *testing.T) {
	// The file must end up 0640 (and a created directory 0750) no
	// matter the process umask: the temp file is chmodded explicitly
	// before the rename.
	if testing.Short() {
		t.Skip("umask is process-wide")
	}
	defer syscall.Umask(syscall.Umask(0o077))
	dir := t.TempDir()
	main := filepath.Join(dir, "sub", "keepwatch.yaml")
	if err := WriteExample(main, false); err != nil {
		t.Fatalf("WriteExample under umask 077: %v", err)
	}
	fi, err := os.Stat(main)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode = 0%o, want 0640", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(main))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o750 {
		t.Errorf("created dir mode = 0%o, want 0750", di.Mode().Perm())
	}
}

func TestWriteExampleNoTempLeftovers(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	if err := WriteExample(main, false); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".keepwatch-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}
