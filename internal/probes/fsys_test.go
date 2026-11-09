//go:build unix

package probes_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOSFSRegularFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), "hello\n")
	got, err := probes.OSFS{}.ReadFile(filepath.Join(dir, "f"), 100)
	if err != nil || string(got) != "hello\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	writeFile(t, filepath.Join(dir, "empty"), "")
	if got, err := (probes.OSFS{}).ReadFile(filepath.Join(dir, "empty"), 100); err != nil || len(got) != 0 {
		t.Fatalf("empty file: %q, %v", got, err)
	}
}

func TestOSFSMissingFile(t *testing.T) {
	_, err := probes.OSFS{}.ReadFile(filepath.Join(t.TempDir(), "nope"), 100)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want not-exist", err)
	}
}

func TestOSFSSizeCap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "f"), strings.Repeat("x", 11))
	if _, err := (probes.OSFS{}).ReadFile(filepath.Join(dir, "f"), 10); !errors.Is(err, probes.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if got, err := (probes.OSFS{}).ReadFile(filepath.Join(dir, "f"), 11); err != nil || len(got) != 11 {
		t.Fatalf("exactly at the cap: %d, %v", len(got), err)
	}
}

// A symbolic link in the last component is refused, whatever it points to:
// the file may sit in a directory other users write to.
func TestOSFSRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "target"), "secret\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	got, err := probes.OSFS{}.ReadFile(link, 100)
	if err == nil {
		t.Fatalf("symlink was followed: %q", got)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a symlink must not look like a missing file: %v", err)
	}
	// a dangling link is refused the same way, not reported as missing
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink("nowhere", dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := (probes.OSFS{}).ReadFile(dangling, 100); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("dangling link: err = %v", err)
	}
}

// Directories on the way may be links (/var/run is one on Ubuntu): only the
// last component is not followed.
func TestOSFSFollowsDirectorySymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "run"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "run", "reboot-required"), "x\n")
	if err := os.Symlink("run", filepath.Join(dir, "var-run")); err != nil {
		t.Fatal(err)
	}
	got, err := probes.OSFS{}.ReadFile(filepath.Join(dir, "var-run", "reboot-required"), 100)
	if err != nil || string(got) != "x\n" {
		t.Fatalf("got %q, %v", got, err)
	}
}

// A FIFO without a writer must neither block the open nor be read.
func TestOSFSRefusesFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := probes.OSFS{}.ReadFile(path, 100)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want a refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile blocked on a FIFO")
	}
}

func TestOSFSRefusesDirectory(t *testing.T) {
	if _, err := (probes.OSFS{}).ReadFile(t.TempDir(), 100); err == nil {
		t.Fatal("a directory was read")
	}
}
