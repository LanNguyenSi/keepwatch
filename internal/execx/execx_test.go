package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var bg = context.Background()

func realRunner(t *testing.T, allow ...string) *Real {
	t.Helper()
	return NewReal(allow)
}

func TestAllowlistedBareName(t *testing.T) {
	res, err := realRunner(t, "echo").Run(bg, []string{"echo", "hello"}, Opts{})
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "hello\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestAllowlistedAbsolutePath(t *testing.T) {
	path, err := NewReal(nil).lookup("echo")
	if err != nil {
		t.Skip("no echo")
	}
	res, err := realRunner(t, "echo").Run(bg, []string{path, "x"}, Opts{})
	if err != nil || string(res.Stdout) != "x\n" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestNotAllowedBareNameRefused(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	_, err := realRunner(t, "echo").Run(bg, []string{"touch", marker}, Opts{})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("program was executed")
	}
}

func TestNotAllowedAbsolutePathRefused(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	touch, err := NewReal(nil).lookup("touch")
	if err != nil {
		t.Skip("no touch")
	}
	_, err = realRunner(t, "echo").Run(bg, []string{touch, marker}, Opts{})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("program was executed")
	}
}

func TestRelativePathRefused(t *testing.T) {
	_, err := realRunner(t, "echo").Run(bg, []string{"./echo"}, Opts{})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
}

// Symlink rule: the target's base name allowing it is enough; the given name
// allowing it counts only when the target sits in a trusted directory.
func TestSymlinkRule(t *testing.T) {
	trusted := t.TempDir()
	outside := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	write := func(dir, name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	r := NewReal([]string{"ss", "sshd", "tool"}, WithSearchDirs(trusted))

	// 1. allowed name -> non-allowed target outside trusted dirs: refused.
	evil := write(outside, "evil")
	link1 := filepath.Join(trusted, "ss")
	if err := os.Symlink(evil, link1); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(bg, []string{"ss"}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("outside target: err = %v, want ErrNotAllowed", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("executed")
	}

	// 2. allowed name -> non-allowed multi-call target inside trusted dir: allowed.
	multi := write(trusted, "busybox")
	link2 := filepath.Join(trusted, "sshd")
	if err := os.Symlink(multi, link2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(bg, []string{"sshd"}, Opts{}); err != nil {
		t.Fatalf("busybox-style: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("expected execution")
	}

	// 3. non-allowed name -> non-allowed target: refused (absolute path too).
	link3 := filepath.Join(trusted, "other")
	if err := os.Symlink(multi, link3); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(bg, []string{link3}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}

	// 4. non-allowed name -> allowed target, target in a trusted dir: allowed.
	real := write(trusted, "tool")
	link4 := filepath.Join(trusted, "alias")
	if err := os.Symlink(real, link4); err != nil {
		t.Fatal(err)
	}
	os.Remove(marker)
	if _, err := r.Run(bg, []string{link4}, Opts{}); err != nil {
		t.Fatalf("allowed target: %v", err)
	}
}

func TestInheritedPathIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mytool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, err := realRunner(t, "mytool").Run(bg, []string{"mytool"}, Opts{})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestTimeoutKills(t *testing.T) {
	start := time.Now()
	res, err := realRunner(t, "sleep").Run(bg, []string{"sleep", "30"}, Opts{Timeout: 200 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %s", el)
	}
	if res.Duration <= 0 {
		t.Error("duration not set")
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	// The shell's grandchild holds the output pipes; the run must still end promptly.
	start := time.Now()
	_, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "sleep 30 & sleep 30"}, Opts{Timeout: 200 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("took %s, grandchild kept pipes open", el)
	}
}

func TestParentCancelIsNotTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	_, err := realRunner(t, "sleep").Run(ctx, []string{"sleep", "30"}, Opts{})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestOutputTruncation(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "yes | head -c 5000; yes | head -c 5000 >&2"}, Opts{MaxOutput: 100})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Stdout) != 100 || len(res.Stderr) != 100 {
		t.Fatalf("truncated=%v out=%d err=%d", res.Truncated, len(res.Stdout), len(res.Stderr))
	}
	res, err = realRunner(t, "echo").Run(bg, []string{"echo", "short"}, Opts{MaxOutput: 100})
	if err != nil || res.Truncated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDefaultMaxOutputIsOneMiB(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "yes | head -c 2000000"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || int64(len(res.Stdout)) != DefaultMaxOutput {
		t.Fatalf("truncated=%v len=%d", res.Truncated, len(res.Stdout))
	}
}

func TestNonZeroExitIsNotError(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "echo out; echo err >&2; exit 7"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 7 || string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" {
		t.Fatalf("%+v", res)
	}
}

func TestMissingBinary(t *testing.T) {
	r := realRunner(t, "keepwatch-no-such-tool")
	if _, err := r.Run(bg, []string{"keepwatch-no-such-tool"}, Opts{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bare: %v", err)
	}
	if _, err := r.Run(bg, []string{"/nonexistent/keepwatch-no-such-tool"}, Opts{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("abs: %v", err)
	}
}

func TestEmptyArgv(t *testing.T) {
	r := realRunner(t, "echo")
	if _, err := r.Run(bg, nil, Opts{}); !errors.Is(err, ErrEmptyArgv) {
		t.Fatalf("nil: %v", err)
	}
	if _, err := r.Run(bg, []string{""}, Opts{}); !errors.Is(err, ErrEmptyArgv) {
		t.Fatalf("empty string: %v", err)
	}
}

func TestMinimalEnv(t *testing.T) {
	t.Setenv("KEEPWATCH_SECRET", "leak")
	res, err := realRunner(t, "env").Run(bg, []string{"env"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	want := map[string]bool{"PATH=" + SearchPath: true, "LANG=C.UTF-8": true, "LC_ALL=C": true}
	for _, l := range got {
		if !want[l] {
			t.Errorf("unexpected env line %q", l)
		}
		delete(want, l)
	}
	if len(want) != 0 {
		t.Errorf("missing env: %v", want)
	}
}

func TestEnvOverride(t *testing.T) {
	res, err := realRunner(t, "env").Run(bg, []string{"env"}, Opts{Env: []string{"FOO=bar"}})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "FOO=bar" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestDir(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	res, err := realRunner(t, "pwd").Run(bg, []string{"pwd"}, Opts{Dir: dir})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != dir {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func notExecuted(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("program was executed")
	}
}

// A regular file named like an allowlisted program, outside the trusted
// directories, must not run when given by absolute path.
func TestAbsolutePathOutsideTrustedDirRefused(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	p := writeScript(t, dir, "sshd", "touch "+marker)
	_, err := NewReal([]string{"sshd"}).Run(bg, []string{p}, Opts{})
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
	notExecuted(t, marker)
}

// A planted link named like an allowlisted program that points at a system
// binary which is not allowlisted must be refused.
func TestPlantedLinkToSystemBinaryRefused(t *testing.T) {
	dir := t.TempDir()
	sh, err := NewReal([]string{"sh"}).lookup("sh")
	if err != nil {
		t.Skip("no sh")
	}
	link := filepath.Join(dir, "ss")
	if err := os.Symlink(sh, link); err != nil {
		t.Fatal(err)
	}
	r := NewReal([]string{"ss"})
	if _, err := r.Run(bg, []string{link, "-c", "echo hi"}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
}

func TestExtraPrograms(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	p := writeScript(t, dir, "probe", "touch "+marker)
	other := writeScript(t, dir, "other", "touch "+marker)
	r := NewReal(nil, WithExtraPrograms(p, "relative/ignored"))
	if _, err := r.Run(bg, []string{other}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("unlisted: %v", err)
	}
	notExecuted(t, marker)
	if _, err := r.Run(bg, []string{"probe"}, Opts{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bare name must not find extra program: %v", err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(p, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(bg, []string{alias}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("alias of listed program: %v", err)
	}
	notExecuted(t, marker)
	if _, err := r.Run(bg, []string{p}, Opts{}); err != nil {
		t.Fatalf("listed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("expected execution")
	}
}

// TestHelperArgv0 is not a test: re-executed as a child, it prints argv[0].
func TestHelperArgv0(t *testing.T) {
	if os.Getenv("KEEPWATCH_HELPER") != "1" {
		t.Skip("helper process")
	}
	os.Stdout.WriteString(os.Args[0])
}

// The name as given must reach the child as argv[0] (multi-call binaries).
func TestArgv0IsGivenName(t *testing.T) {
	trusted := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Skip(err)
	}
	if err := os.WriteFile(filepath.Join(trusted, "multicall"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(trusted, "multicall"), filepath.Join(trusted, "alias")); err != nil {
		t.Fatal(err)
	}
	r := NewReal([]string{"alias"}, WithSearchDirs(trusted))
	res, err := r.Run(bg, []string{"alias", "-test.run=^TestHelperArgv0$"}, Opts{Env: []string{"KEEPWATCH_HELPER=1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Stdout); !strings.HasPrefix(got, "alias") {
		t.Fatalf("argv[0] = %q (stdout %q), want alias", got, res.Stdout)
	}
}

func TestOutputExactlyAtLimitNotTruncated(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "head -c 100 /dev/zero"}, Opts{MaxOutput: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Truncated || len(res.Stdout) != 100 {
		t.Fatalf("truncated=%v len=%d", res.Truncated, len(res.Stdout))
	}
	res, err = realRunner(t, "sh").Run(bg, []string{"sh", "-c", "head -c 101 /dev/zero"}, Opts{MaxOutput: 100})
	if err != nil || !res.Truncated || len(res.Stdout) != 100 {
		t.Fatalf("101 bytes: %+v %v", res, err)
	}
}

func pidAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitGone(pid int) bool {
	for i := 0; i < 50; i++ {
		if !pidAlive(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// The child exits 0 while a background grandchild holds stdout: Run must
// return within the wait delay with ErrIOTimeout and kill the grandchild.
func TestGrandchildHoldingPipeBoundedAndKilled(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })

	start := time.Now()
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "sleep 30 & echo $!; exit 0"}, Opts{})
	if !errors.Is(err, ErrIOTimeout) {
		t.Fatalf("err = %v, want ErrIOTimeout", err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("Run took %s", el)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if perr != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, perr)
	}
	if !waitGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("grandchild outlived Run")
	}
}

// A background grandchild that does not hold the pipes must also be gone
// after a normal, successful Run.
func TestBackgroundGrandchildKilledAfterNormalExit(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	pid, perr := strconv.Atoi(strings.TrimSpace(string(res.Stdout)))
	if perr != nil {
		t.Fatalf("stdout %q: %v", res.Stdout, perr)
	}
	if !waitGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("grandchild outlived Run")
	}
}

func TestSignalExit(t *testing.T) {
	res, err := realRunner(t, "sh").Run(bg, []string{"sh", "-c", "kill -9 $$"}, Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != -1 || !res.Signaled {
		t.Fatalf("%+v", res)
	}
	res, err = realRunner(t, "sh").Run(bg, []string{"sh", "-c", "exit 3"}, Opts{})
	if err != nil || res.Signaled || res.ExitCode != 3 {
		t.Fatalf("%+v %v", res, err)
	}
}

// A parent deadline shorter than Opts.Timeout surfaces as the context error,
// not ErrTimeout.
func TestParentDeadlineIsNotErrTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(bg, 150*time.Millisecond)
	defer cancel()
	_, err := realRunner(t, "sleep").Run(ctx, []string{"sleep", "30"}, Opts{Timeout: 30 * time.Second})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v", err)
	}
}
