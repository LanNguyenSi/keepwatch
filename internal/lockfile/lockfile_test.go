//go:build linux || darwin

package lockfile

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
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

// stateDir returns a fresh state directory whose mode is exactly 0700.
// t.TempDir applies the process umask, so under a permissive umask such as
// 002 its directory is group-writable and securefile refuses the directory
// itself, which would fail the other tests and make the refusal tests pass
// for the wrong reason. Mkdir plus an explicit Chmod is umask-independent
// (Chmod is not masked), and the child of the re-exec test inherits the
// directory built here.
func stateDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAcquireBlocksSecondAcquireUntilRelease(t *testing.T) {
	dir := stateDir(t)
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
	dir := stateDir(t)
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
	dir := stateDir(t)
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

func TestNoDescriptorLeak(t *testing.T) {
	dir := stateDir(t)
	// A leaked *os.File is closed by its finalizer, which would hide the
	// leak from the count: keep the GC off while measuring.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	before := openFDCount(t)
	for range 50 {
		l, err := Acquire(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
			l.Release()
			t.Fatalf("second Acquire: got %v, want ErrLocked", err)
		}
		if err := l.Release(); err != nil {
			t.Fatal(err)
		}
	}
	if after := openFDCount(t); after > before+2 {
		t.Fatalf("descriptors leaked: %d open before 50 acquire/refused/release cycles, %d after", before, after)
	}
}

// openFDCount counts the entries of /dev/fd, the process's own open file
// descriptors (on linux a symlink to /proc/self/fd). The counting open
// appears in both samples and cancels out.
func openFDCount(t *testing.T) int {
	t.Helper()
	des, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(des)
}

func TestAcquireRefusesSymlinkedLockFile(t *testing.T) {
	dir := stateDir(t)
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
	} else if !strings.Contains(err.Error(), lockPath(dir)) {
		t.Fatalf("error %q does not name the lock file %s: the directory may have been refused instead", err, lockPath(dir))
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
	dir := stateDir(t)
	p := lockPath(dir)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	} else if !strings.Contains(err.Error(), lockPath(dir)) {
		t.Fatalf("error %q does not name the lock file %s: the directory may have been refused instead", err, lockPath(dir))
	}
}

func TestAcquireRefusesOversizedLockFile(t *testing.T) {
	dir := stateDir(t)
	if err := os.WriteFile(lockPath(dir), make([]byte, maxLockSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, securefile.ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	} else if !strings.Contains(err.Error(), "not keepwatch's own lock file") {
		t.Fatalf("error %q does not say the lock file is not keepwatch's own", err)
	}
}

func TestAcquireMissingStateDir(t *testing.T) {
	if _, err := Acquire(filepath.Join(stateDir(t), "missing")); !errors.Is(err, fs.ErrNotExist) {
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
	dir := stateDir(t)
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
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
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
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	t.Cleanup(func() {
		stop()
		if t.Failed() && stderr.Len() > 0 {
			t.Logf("child stderr:\n%s", stderr.String())
		}
	})
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
		t.Fatalf("child: %v\nstderr:\n%s", err, stderr.String())
	}
	stopped = true
	l, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after the child exited: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
}
