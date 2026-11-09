package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExamplePassesConfigCheck(t *testing.T) {
	// The embedded example is valid: Load applies no errors to it.
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	if err := os.WriteFile(main, Example(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("the example config must pass check: %v", err)
	}
	if cfg.StateDir != DefaultStateDir {
		t.Errorf("example StateDir = %q", cfg.StateDir)
	}
	if len(cfg.Exceptions) != 1 {
		t.Errorf("example Exceptions = %+v", cfg.Exceptions)
	}
}

func TestWriteExample(t *testing.T) {
	root := t.TempDir()
	main := filepath.Join(root, "sub", "keepwatch.yaml")

	// Fresh: creates the missing directory with 0750 and the file with
	// 0640, and the result passes Load.
	if err := WriteExample(main, false); err != nil {
		t.Fatalf("WriteExample fresh: %v", err)
	}
	dirInfo, err := os.Stat(filepath.Dir(main))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o750 {
		t.Errorf("directory mode = 0%o, want 0750", dirInfo.Mode().Perm())
	}
	info, err := os.Stat(main)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("file mode = 0%o, want 0640", info.Mode().Perm())
	}
	if !bytes.Equal(mustRead(t, main), Example()) {
		t.Error("written file differs from Example()")
	}
	if _, err := Load(main); err != nil {
		t.Errorf("written example fails Load: %v", err)
	}

	// Refuse: an existing file is not touched without --force.
	sentinel := []byte("do not touch\n")
	if err := os.WriteFile(main, sentinel, 0o644); err != nil {
		t.Fatal(err)
	}
	err = WriteExample(main, false)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("WriteExample without --force: err = %v, want a refusal mentioning --force", err)
	}
	if !bytes.Equal(mustRead(t, main), sentinel) {
		t.Error("refusal must not modify the existing file")
	}

	// Force: overwrites.
	if err := WriteExample(main, true); err != nil {
		t.Fatalf("WriteExample --force: %v", err)
	}
	if !bytes.Equal(mustRead(t, main), Example()) {
		t.Error("--force must overwrite with the example")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
