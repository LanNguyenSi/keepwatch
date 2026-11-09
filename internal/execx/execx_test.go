package execx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	r := NewReal([]string{"ss", "sshd"}, WithSearchDirs(trusted))

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

	// 4. non-allowed name -> allowed target: allowed.
	real := write(outside, "ss")
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
