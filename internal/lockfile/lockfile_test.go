//go:build linux || darwin

package lockfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// childDirEnv makes the test binary, re-executed with this environment set
// to the state directory, hold the lock until its stdin is closed.
const childDirEnv = "KEEPWATCH_LOCKFILE_TEST_DIR"

func lockPath(dir string) string { return filepath.Join(dir, lockFileName) }

func TestAcquireBlocksSecondAcquireUntilRelease(t *testing.T) {
	dir := t.TempDir()
	l1, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := l1.Path(); got != lockPath(dir) {
		t.Fatalf("Path() = %q, want %q", got, lockPath(dir))
	}
	fi, err := os.Stat(l1.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode %v, want regular 0600", fi.Mode())
	}
	if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire: got %v, want ErrLocked", err)
	} else if !strings.Contains(err.Error(), l1.Path()) {
		t.Fatalf("second Acquire error %q does not name the lock file", err)
	}
	if err := l1.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	l2, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	if err := l2.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func TestReleaseKeepsTheLockFile(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(l.Path())
	if err != nil {
		t.Fatalf("lock file after Release: %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode %v after Release, want regular 0600", fi.Mode())
	}
	data, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("lock file holds %q, want empty", data)
	}
}

func TestReleaseClosesTheFile(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	fd := int(l.f.Fd())
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("flock on the released fd %d: got %v, want EBADF (the file stayed open)", fd, err)
	}
}

func TestAcquireRefusesSymlinkedLockFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("do not open"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := lockPath(dir)
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is %v, want it to stay a symlink", link, fi.Mode())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not open" {
		t.Fatalf("target was modified: %q", data)
	}
}

func TestAcquireRefusesGroupWritableLockFile(t *testing.T) {
	dir := t.TempDir()
	p := lockPath(dir)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestAcquireMissingStateDir(t *testing.T) {
	if _, err := Acquire(filepath.Join(t.TempDir(), "state")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want ErrNotExist", err)
	}
}

// childHold locks dir, reports ready on stdout, and releases when the
// parent closes stdin. It runs inside a re-executed copy of this test
// binary.
func childHold(dir string) {
	l, err := Acquire(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: Acquire: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "child: stdin: %v\n", err)
		l.Release()
		os.Exit(1)
	}
	if err := l.Release(); err != nil {
		fmt.Fprintf(os.Stderr, "child: Release: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("released")
	os.Exit(0)
}

func TestCrossProcessExclusion(t *testing.T) {
	if dir := os.Getenv(childDirEnv); dir != "" {
		childHold(dir)
		return
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCrossProcessExclusion$")
	cmd.Env = append(os.Environ(), childDirEnv+"="+dir)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 8)
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			lines <- s.Text()
		}
		close(lines)
	}()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	await := func(want string) {
		t.Helper()
		select {
		case ln, ok := <-lines:
			if !ok {
				t.Fatalf("child exited before reporting %q", want)
			}
			if ln != want {
				t.Fatalf("child reported %q, want %q", ln, want)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("timed out waiting for the child to report %q", want)
		}
	}
	await("ready")
	if l, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		if l != nil {
			l.Release()
		}
		t.Fatalf("Acquire while the child holds the lock: got %v, want ErrLocked", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	await("released")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("child: %v", err)
	}
	l, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after the child exited: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
}
