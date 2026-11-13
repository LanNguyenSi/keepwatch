package execx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type streamOut struct {
	res   StreamResult
	err   error
	lines []string
}

// within runs f and fails the test with a named message when it has not
// finished after d, so a hang is reported in seconds instead of as the go test
// timeout. A hung f is left behind.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %s", what, d)
	}
}

// callStream is a bounded r.Stream for tests that need no line collection.
func callStream(t *testing.T, r *Real, ctx context.Context, argv []string, opts StreamOpts, onLine func([]byte) error) (StreamResult, error) {
	t.Helper()
	var res StreamResult
	var err error
	within(t, 15*time.Second, "Stream "+strings.Join(argv, " "), func() { res, err = r.Stream(ctx, argv, opts, onLine) })
	return res, err
}

// streamBounded runs Stream and fails the test with a named message if it has
// not returned after streamDeadline, instead of letting a hang surface as a
// go test timeout.
func streamBounded(t *testing.T, ctx context.Context, r *Real, argv []string, opts StreamOpts, onLine func([]byte) error) streamOut {
	t.Helper()
	const streamDeadline = 10 * time.Second
	ch := make(chan streamOut, 1)
	go func() {
		var out streamOut
		out.res, out.err = r.Stream(ctx, argv, opts, func(l []byte) error {
			out.lines = append(out.lines, string(l))
			if onLine != nil {
				return onLine(l)
			}
			return nil
		})
		ch <- out
	}()
	select {
	case o := <-ch:
		return o
	case <-time.After(streamDeadline):
		t.Fatalf("Stream did not return within %s", streamDeadline)
		return streamOut{}
	}
}

func TestStreamDeliversLinesInOrder(t *testing.T) {
	o := streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "echo one; echo; echo three"}, StreamOpts{}, nil)
	if o.err != nil || o.res.ExitCode != 0 || o.res.Signaled || o.res.DroppedLines != 0 || o.res.IOIncomplete {
		t.Fatalf("res=%+v err=%v", o.res, o.err)
	}
	if got := strings.Join(o.lines, "|"); got != "one||three" {
		t.Fatalf("lines = %q", got)
	}
	if o.res.Duration <= 0 {
		t.Error("duration not set")
	}
}

func TestStreamUnterminatedLastLineDelivered(t *testing.T) {
	o := streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "printf 'a\\nb'"}, StreamOpts{}, nil)
	if o.err != nil || strings.Join(o.lines, "|") != "a|b" {
		t.Fatalf("lines = %q err=%v", o.lines, o.err)
	}
}

func TestStreamNoOutput(t *testing.T) {
	o := streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "exit 0"}, StreamOpts{}, nil)
	if o.err != nil || len(o.lines) != 0 {
		t.Fatalf("lines=%q err=%v", o.lines, o.err)
	}
}

func TestStreamNonZeroExitIsNotError(t *testing.T) {
	o := streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "echo out; echo err >&2; exit 7"}, StreamOpts{}, nil)
	if o.err != nil || o.res.ExitCode != 7 || string(o.res.Stderr) != "err\n" || strings.Join(o.lines, "|") != "out" {
		t.Fatalf("res=%+v lines=%q err=%v", o.res, o.lines, o.err)
	}
}

func TestStreamSignalExit(t *testing.T) {
	o := streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "kill -9 $$"}, StreamOpts{}, nil)
	if o.err != nil || o.res.ExitCode != -1 || !o.res.Signaled {
		t.Fatalf("res=%+v err=%v", o.res, o.err)
	}
}

// Same allowlist and resolve path as Run.
func TestStreamAllowlist(t *testing.T) {
	r := realRunner(t, "echo")
	marker := t.TempDir() + "/ran"
	noLine := func([]byte) error { t.Error("onLine called"); return nil }
	if _, err := callStream(t, r, bg, nil, StreamOpts{}, noLine); !errors.Is(err, ErrEmptyArgv) {
		t.Errorf("nil argv: %v", err)
	}
	if _, err := callStream(t, r, bg, []string{""}, StreamOpts{}, noLine); !errors.Is(err, ErrEmptyArgv) {
		t.Errorf("empty argv: %v", err)
	}
	if _, err := callStream(t, r, bg, []string{"touch", marker}, StreamOpts{}, noLine); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("not allowed: %v", err)
	}
	notExecuted(t, marker)
	if _, err := callStream(t, r, bg, []string{"./echo"}, StreamOpts{}, noLine); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("relative: %v", err)
	}
	if _, err := callStream(t, realRunner(t, "keepwatch-no-such-tool"), bg, []string{"keepwatch-no-such-tool"}, StreamOpts{}, noLine); !errors.Is(err, ErrNotFound) {
		t.Errorf("not found: %v", err)
	}
	var got []string
	if _, err := callStream(t, r, bg, []string{"echo", "hi"}, StreamOpts{}, func(l []byte) error { got = append(got, string(l)); return nil }); err != nil || len(got) != 1 || got[0] != "hi" {
		t.Errorf("allowed: %q %v", got, err)
	}
}

func TestStreamMinimalEnv(t *testing.T) {
	t.Setenv("KEEPWATCH_SECRET", "leak")
	o := streamBounded(t, bg, realRunner(t, "env"), []string{"env"}, StreamOpts{}, nil)
	want := map[string]bool{"PATH=" + SearchPath: true, "LANG=C.UTF-8": true, "LC_ALL=C": true}
	for _, l := range o.lines {
		if !want[l] {
			t.Errorf("unexpected env line %q", l)
		}
		delete(want, l)
	}
	if len(want) != 0 {
		t.Errorf("missing env: %v", want)
	}
	o = streamBounded(t, bg, realRunner(t, "env"), []string{"env"}, StreamOpts{Env: []string{"FOO=bar"}}, nil)
	if strings.Join(o.lines, "|") != "FOO=bar" {
		t.Errorf("env override: %q", o.lines)
	}
}

func TestStreamDir(t *testing.T) {
	dir := t.TempDir()
	o := streamBounded(t, bg, realRunner(t, "pwd"), []string{"pwd"}, StreamOpts{Dir: dir}, nil)
	if len(o.lines) != 1 || !strings.HasSuffix(o.lines[0], strings.TrimPrefix(dir, "/private")) {
		t.Fatalf("lines = %q, want %q", o.lines, dir)
	}
}

// An over-long line is dropped, counted, and the stream goes on. The
// boundary: MaxLine bytes pass, MaxLine+1 do not.
func TestStreamLongLineDropped(t *testing.T) {
	script := "head -c 10 /dev/zero | tr '\\0' a; echo; " + // exactly MaxLine
		"head -c 11 /dev/zero | tr '\\0' b; echo; " + // one over
		"head -c 50000 /dev/zero | tr '\\0' c; echo; " + // far over, longer than the read buffer
		"echo after; head -c 11 /dev/zero | tr '\\0' d" // over-long and unterminated
	o := streamBounded(t, bg, realRunner(t, "sh", "head", "tr"), []string{"sh", "-c", script}, StreamOpts{MaxLine: 10}, nil)
	if o.err != nil {
		t.Fatal(o.err)
	}
	if got := strings.Join(o.lines, "|"); got != "aaaaaaaaaa|after" {
		t.Fatalf("lines = %q", got)
	}
	if o.res.DroppedLines != 3 {
		t.Fatalf("dropped = %d, want 3", o.res.DroppedLines)
	}
}

// Documented default: DefaultMaxLine bytes pass, one more is dropped.
func TestStreamDefaultMaxLine(t *testing.T) {
	if DefaultMaxLine != 64<<10 {
		t.Fatalf("DefaultMaxLine = %d, want 64 KiB", DefaultMaxLine)
	}
	script := "head -c " + strconv.Itoa(DefaultMaxLine) + " /dev/zero | tr '\\0' a; echo; " +
		"head -c " + strconv.Itoa(DefaultMaxLine+1) + " /dev/zero | tr '\\0' b; echo; echo end"
	o := streamBounded(t, bg, realRunner(t, "sh", "head", "tr"), []string{"sh", "-c", script}, StreamOpts{}, nil)
	if o.err != nil || len(o.lines) != 2 || len(o.lines[0]) != DefaultMaxLine || o.lines[1] != "end" || o.res.DroppedLines != 1 {
		t.Fatalf("n=%d dropped=%d err=%v", len(o.lines), o.res.DroppedLines, o.err)
	}
}

// Each input of the defaults on its own: zero and negative select the
// default; an explicit value wins; no timeout is ever defaulted.
func TestStreamOptsDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   StreamOpts
		want StreamOpts
	}{
		{"zero", StreamOpts{}, StreamOpts{MaxLine: DefaultMaxLine, MaxStderr: DefaultMaxOutput}},
		{"negative", StreamOpts{MaxLine: -1, MaxStderr: -1, Timeout: -1, IdleTimeout: -1}, StreamOpts{MaxLine: DefaultMaxLine, MaxStderr: DefaultMaxOutput}},
		{"explicit", StreamOpts{MaxLine: 5, MaxStderr: 6, Timeout: time.Second, IdleTimeout: 2 * time.Second}, StreamOpts{MaxLine: 5, MaxStderr: 6, Timeout: time.Second, IdleTimeout: 2 * time.Second}},
		{"timeout alone", StreamOpts{Timeout: time.Second}, StreamOpts{MaxLine: DefaultMaxLine, MaxStderr: DefaultMaxOutput, Timeout: time.Second}},
		{"idle alone", StreamOpts{IdleTimeout: time.Second}, StreamOpts{MaxLine: DefaultMaxLine, MaxStderr: DefaultMaxOutput, IdleTimeout: time.Second}},
	}
	for _, c := range cases {
		got := c.in.withDefaults()
		got.Env = nil
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
	if got := (StreamOpts{}).withDefaults(); len(got.Env) != len(DefaultEnv) {
		t.Errorf("default env = %v", got.Env)
	}
	if got := (StreamOpts{Env: []string{"A=b"}}).withDefaults(); len(got.Env) != 1 || got.Env[0] != "A=b" {
		t.Errorf("explicit env = %v", got.Env)
	}
}

// A chatty child must not block on a full stderr pipe: it writes far more than
// a pipe holds to stderr before its first stdout line.
func TestStreamChattyStderrDoesNotBlock(t *testing.T) {
	script := "head -c 1000000 /dev/zero >&2; echo done"
	o := streamBounded(t, bg, realRunner(t, "sh", "head"), []string{"sh", "-c", script}, StreamOpts{MaxStderr: 1000}, nil)
	if o.err != nil || strings.Join(o.lines, "|") != "done" {
		t.Fatalf("lines=%q err=%v", o.lines, o.err)
	}
	if len(o.res.Stderr) != 1000 || !o.res.StderrTruncated {
		t.Fatalf("stderr len=%d truncated=%v, want 1000 and true", len(o.res.Stderr), o.res.StderrTruncated)
	}
	o = streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "echo e >&2"}, StreamOpts{MaxStderr: 1000}, nil)
	if o.res.StderrTruncated || string(o.res.Stderr) != "e\n" {
		t.Fatalf("short stderr: %+v", o.res)
	}
}

// followChild starts a followed child that prints the pid of a long-lived
// grandchild as its first line. It calls action with the pid once the line
// arrived and returns what Stream returned.
func followChild(t *testing.T, ctx context.Context, opts StreamOpts, action func(pid int) error) (streamOut, int) {
	t.Helper()
	pid := 0
	o := streamBounded(t, ctx, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 & echo $!; wait"}, opts, func(l []byte) error {
		if pid != 0 {
			return nil
		}
		n, err := strconv.Atoi(string(l))
		if err != nil {
			t.Errorf("first line %q: %v", l, err)
			return nil
		}
		pid = n
		return action(n)
	})
	if pid == 0 {
		t.Fatalf("no pid line: %+v", o)
	}
	return o, pid
}

func mustBeGone(t *testing.T, pid int) {
	t.Helper()
	if !waitGone(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("process outlived Stream")
	}
}

func TestStreamCancelKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	o, pid := followChild(t, ctx, StreamOpts{}, func(int) error { cancel(); return nil })
	if !errors.Is(o.err, context.Canceled) || errors.Is(o.err, ErrTimeout) {
		t.Fatalf("err = %v, want context.Canceled", o.err)
	}
	if o.res.ExitCode != -1 {
		t.Errorf("exit code = %d, want -1", o.res.ExitCode)
	}
	mustBeGone(t, pid)
}

// An already-ended context starts nothing.
func TestStreamContextDoneBeforeStart(t *testing.T) {
	marker := t.TempDir() + "/ran"
	ctx, cancel := context.WithCancel(bg)
	cancel()
	res, err := callStream(t, realRunner(t, "sh"), ctx, []string{"sh", "-c", "touch " + marker}, StreamOpts{}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	// Nothing was started, so there is no duration and no exit status to report.
	if res.Duration != 0 || res.ExitCode != 0 {
		t.Fatalf("a process was started: %+v", res)
	}
	time.Sleep(200 * time.Millisecond)
	notExecuted(t, marker)
}

func TestStreamParentDeadlineIsNotErrTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
	defer cancel()
	o, pid := followChild(t, ctx, StreamOpts{Timeout: time.Minute}, func(int) error { return nil })
	if !errors.Is(o.err, context.DeadlineExceeded) || errors.Is(o.err, ErrTimeout) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", o.err)
	}
	mustBeGone(t, pid)
}

func TestStreamCallbackErrorKillsAndIsReturned(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	pid := 0
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 & echo $!; echo two; echo three; wait"}, StreamOpts{}, func(l []byte) error {
		calls++
		if calls == 1 {
			pid, _ = strconv.Atoi(string(l))
			return boom
		}
		return nil
	})
	if !errors.Is(o.err, boom) {
		t.Fatalf("err = %v, want boom", o.err)
	}
	if calls != 1 {
		t.Errorf("onLine called %d times after it failed", calls)
	}
	if pid == 0 {
		t.Fatal("no pid")
	}
	mustBeGone(t, pid)
}

func TestStreamTotalTimeout(t *testing.T) {
	o, pid := followChild(t, bg, StreamOpts{Timeout: 300 * time.Millisecond}, func(int) error { return nil })
	if !errors.Is(o.err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", o.err)
	}
	mustBeGone(t, pid)
}

func TestStreamIdleTimeout(t *testing.T) {
	o, pid := followChild(t, bg, StreamOpts{IdleTimeout: 300 * time.Millisecond}, func(int) error { return nil })
	if !errors.Is(o.err, ErrIdleTimeout) || errors.Is(o.err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrIdleTimeout", o.err)
	}
	mustBeGone(t, pid)
}

// Lines keep an idle stream alive: it ends by itself after 0.9 s while the
// idle limit is 0.6 s, with a line every 0.2 s.
func TestStreamIdleTimeoutResetsOnLines(t *testing.T) {
	script := "for i in 1 2 3 4; do echo $i; sleep 0.2; done"
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", script}, StreamOpts{IdleTimeout: 600 * time.Millisecond}, nil)
	if o.err != nil || len(o.lines) != 4 {
		t.Fatalf("lines=%q err=%v", o.lines, o.err)
	}
}

// A dropped line is activity for the idle timer too.
func TestStreamIdleTimeoutResetsOnDroppedLines(t *testing.T) {
	script := "for i in 1 2 3 4; do echo toolong; sleep 0.2; done"
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", script}, StreamOpts{IdleTimeout: 600 * time.Millisecond, MaxLine: 3}, nil)
	if o.err != nil || o.res.DroppedLines != 4 {
		t.Fatalf("dropped=%d err=%v", o.res.DroppedLines, o.err)
	}
}

// The child exits while a grandchild holds stdout: Stream is bounded, reports
// IOIncomplete with ErrIOTimeout, and kills the grandchild.
func TestStreamGrandchildHoldingPipe(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })
	var pid int
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 & echo $!; exit 0"}, StreamOpts{}, func(l []byte) error {
		pid, _ = strconv.Atoi(string(l))
		return nil
	})
	if !errors.Is(o.err, ErrIOTimeout) || !o.res.IOIncomplete || o.res.ExitCode != 0 {
		t.Fatalf("res=%+v err=%v", o.res, o.err)
	}
	if pid == 0 {
		t.Fatal("no pid")
	}
	mustBeGone(t, pid)

	// Non-zero exit: the status comes back with a nil error.
	o = streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 & echo $!; exit 3"}, StreamOpts{}, func(l []byte) error {
		pid, _ = strconv.Atoi(string(l))
		return nil
	})
	if o.err != nil || !o.res.IOIncomplete || o.res.ExitCode != 3 {
		t.Fatalf("res=%+v err=%v", o.res, o.err)
	}
	mustBeGone(t, pid)
}

// A background grandchild that holds no pipe must be gone after a normal exit.
func TestStreamBackgroundGrandchildKilledAfterNormalExit(t *testing.T) {
	var pid int
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!"}, StreamOpts{}, func(l []byte) error {
		pid, _ = strconv.Atoi(string(l))
		return nil
	})
	if o.err != nil || pid == 0 {
		t.Fatalf("pid=%d err=%v", pid, o.err)
	}
	mustBeGone(t, pid)
}

// A slow consumer holds the reader back; ending the stream must still release
// every goroutine.
func TestStreamSlowConsumerCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	n := 0
	o := streamBounded(t, ctx, realRunner(t, "sh", "yes"), []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error {
		n++
		if n == 100 {
			cancel()
		}
		return nil
	})
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("err = %v", o.err)
	}
}

// fdCount is the number of open descriptors of this process; the directory
// listing's own descriptor is in every sample, so differences are exact.
func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("cannot count descriptors: %v", err)
	}
	return len(ents)
}

// resourcesSettle waits until the goroutine and descriptor counts are back at
// the values taken before, and fails with a stack dump when they are not.
func resourcesSettle(t *testing.T, name string, goroutines, fds int) {
	t.Helper()
	var g, f int
	for i := 0; i < 100; i++ {
		g, f = runtime.NumGoroutine(), fdCount(t)
		if g <= goroutines && f <= fds {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	buf = buf[:runtime.Stack(buf, true)]
	t.Fatalf("%s: %d goroutines and %d descriptors after, %d and %d before\n%s", name, g, f, goroutines, fds, buf)
}

// No goroutine or descriptor of Stream outlives it, on any way it can end.
func TestStreamLeavesNoGoroutines(t *testing.T) {
	r := realRunner(t, "sh", "sleep", "yes")
	run := func(name string, f func()) {
		t.Helper()
		g, fds := runtime.NumGoroutine(), fdCount(t)
		f()
		resourcesSettle(t, name, g, fds)
	}
	run("clean", func() {
		_, _ = callStream(t, r, bg, []string{"sh", "-c", "echo a; echo b >&2"}, StreamOpts{}, func([]byte) error { return nil })
	})
	run("nonzero", func() {
		_, _ = callStream(t, r, bg, []string{"sh", "-c", "exit 2"}, StreamOpts{}, nil)
	})
	run("callback error", func() {
		_, err := callStream(t, r, bg, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { return errors.New("stop") })
		if err == nil {
			t.Error("want error")
		}
	})
	run("cancel", func() {
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		_, err := callStream(t, r, ctx, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { cancel(); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	run("cancel while idle", func() {
		ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
		defer cancel()
		_, err := callStream(t, r, ctx, []string{"sleep", "30"}, StreamOpts{}, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v", err)
		}
	})
	run("timeouts", func() {
		_, err := callStream(t, r, bg, []string{"sleep", "30"}, StreamOpts{Timeout: 150 * time.Millisecond}, nil)
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("err = %v", err)
		}
		_, err = callStream(t, r, bg, []string{"sleep", "30"}, StreamOpts{IdleTimeout: 150 * time.Millisecond}, nil)
		if !errors.Is(err, ErrIdleTimeout) {
			t.Errorf("err = %v", err)
		}
	})
	run("refused", func() {
		_, _ = callStream(t, r, bg, []string{"touch", t.TempDir() + "/ran"}, StreamOpts{}, nil)
		_, _ = callStream(t, realRunner(t, "keepwatch-no-such-tool"), bg, []string{"keepwatch-no-such-tool"}, StreamOpts{}, nil)
	})
	run("held pipe", func() {
		old := waitDelay
		waitDelay = 200 * time.Millisecond
		defer func() { waitDelay = old }()
		_, _ = callStream(t, r, bg, []string{"sh", "-c", "sleep 30 & exit 0"}, StreamOpts{}, nil)
	})
}

func TestStreamConcurrent(t *testing.T) {
	r := realRunner(t, "sh")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var n int
			_, err := r.Stream(bg, []string{"sh", "-c", "i=0; while [ $i -lt 200 ]; do echo $i; i=$((i+1)); done"}, StreamOpts{}, func([]byte) error { n++; return nil })
			if err != nil || n != 200 {
				t.Errorf("n=%d err=%v", n, err)
			}
		}()
	}
	within(t, 30*time.Second, "8 concurrent streams", wg.Wait)
}

func TestStreamMissingBinaryMessage(t *testing.T) {
	_, err := callStream(t, realRunner(t, "keepwatch-no-such-tool"), bg, []string{"/usr/bin/keepwatch-no-such-tool"}, StreamOpts{}, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// Once the child exited, the grace period counts the wait for the next line,
// not the time spent in onLine: a slow consumer of a backlog loses nothing.
func TestStreamSlowConsumerAfterExitLosesNothing(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })
	n := 0
	start := time.Now()
	res, err := callStream(t, realRunner(t, "sh"), bg, []string{"sh", "-c", "i=0; while [ $i -lt 200 ]; do echo line$i; i=$((i+1)); done"}, StreamOpts{}, func([]byte) error {
		n++
		time.Sleep(3 * time.Millisecond)
		return nil
	})
	if time.Since(start) < 2*waitDelay {
		t.Fatalf("consumer took %s, not longer than the grace period; the test proves nothing", time.Since(start))
	}
	if err != nil || res.IOIncomplete || n != 200 {
		t.Fatalf("delivered %d/200 err=%v res=%+v", n, err, res)
	}
}

// A consumer that stalls for longer than the idle limit is not idleness of the
// program: the child never stops writing, so only the cancel ends the stream.
func TestStreamIdleTimeoutIgnoresSlowConsumer(t *testing.T) {
	// The limits leave room for a slow start of the child on a loaded host.
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(bg)
		n := 0
		_, err := callStream(t, realRunner(t, "sh", "yes"), ctx, []string{"sh", "-c", "yes"}, StreamOpts{IdleTimeout: 400 * time.Millisecond}, func([]byte) error {
			n++
			if n == 2 {
				cancel()
				return nil
			}
			time.Sleep(600 * time.Millisecond)
			return nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("run %d: err = %v, want context.Canceled", i, err)
		}
	}
}

// The idle limit stays armed after stdout was closed, until the program exits.
func TestStreamIdleTimeoutAfterStdoutClosed(t *testing.T) {
	start := time.Now()
	o := streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "echo up; exec >&-; exec sleep 30"}, StreamOpts{IdleTimeout: 300 * time.Millisecond}, nil)
	if !errors.Is(o.err, ErrIdleTimeout) {
		t.Fatalf("err = %v, want ErrIdleTimeout", o.err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %s", el)
	}
	// A quiet program with stdout still open times out as before.
	o = streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "echo up; sleep 0.5"}, StreamOpts{IdleTimeout: 300 * time.Millisecond}, nil)
	if !errors.Is(o.err, ErrIdleTimeout) {
		t.Fatalf("quiet running child: %v", o.err)
	}
	// Once the program has exited the limit no longer applies.
	o = streamBounded(t, bg, realRunner(t, "sh"), []string{"sh", "-c", "echo up; exit 0"}, StreamOpts{IdleTimeout: time.Second}, nil)
	if o.err != nil {
		t.Fatalf("exited child: %v", o.err)
	}
	// ... also while a leftover child still holds the pipe: the grace period
	// applies then, not the idle limit.
	old := waitDelay
	waitDelay = 1500 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })
	o = streamBounded(t, bg, realRunner(t, "sh", "sleep"), []string{"sh", "-c", "sleep 30 & exit 0"}, StreamOpts{IdleTimeout: 500 * time.Millisecond}, nil)
	if !errors.Is(o.err, ErrIOTimeout) || errors.Is(o.err, ErrIdleTimeout) {
		t.Fatalf("held pipe after exit: err = %v, want ErrIOTimeout", o.err)
	}
}

// escapeScript returns a shell fragment that starts a grandchild in a new
// session that ignores SIGPIPE and holds the inherited stdout and stderr, and
// waits until the grandchild recorded its pid in $M. tail is the perl code it
// runs afterwards.
func escapeScript(tail string) string {
	return `perl -e 'use POSIX qw(setsid); setsid(); $SIG{PIPE}="IGNORE"; $|=1; open(F,">$ARGV[0].tmp") or die; print F $$; close F; rename("$ARGV[0].tmp",$ARGV[0]); ` + tail + `' "$M" &
i=0; while [ ! -e "$M" ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done
`
}

const (
	silentEscapee = `exec("sleep","30")`
	chattyEscapee = `while (1) { print "tick\n"; select(undef,undef,undef,0.1); }`
)

// escapeSetup shortens the grace period and returns a function that makes a
// marker file for one escapee together with the options that pass it on. Every
// escapee is killed when the test ends.
func escapeSetup(t *testing.T) func() (string, StreamOpts) {
	t.Helper()
	if _, err := NewReal(nil).lookup("perl"); err != nil {
		t.Skip("no perl to start a grandchild in a new session")
	}
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })
	dir := t.TempDir()
	n := 0
	return func() (string, StreamOpts) {
		n++
		marker := dir + "/pid" + strconv.Itoa(n)
		t.Cleanup(func() { killMarked(marker) })
		return marker, StreamOpts{Env: []string{"PATH=" + SearchPath, "M=" + marker}}
	}
}

func killMarked(marker string) {
	if b, err := os.ReadFile(marker); err == nil {
		if pid, err := strconv.Atoi(string(b)); err == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// A pipe holder outside the process group survives the group kill. Stream must
// not wait for it: it returns within a bound, flags the output incomplete, and
// releases its goroutines and descriptors.
func TestStreamEscapeeHoldingPipesIsBounded(t *testing.T) {
	r := realRunner(t, "sh", "sleep")
	g, fds := runtime.NumGoroutine(), fdCount(t)
	newEscapee := escapeSetup(t)

	marker, opts := newEscapee()
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	start := time.Now()
	o := streamBounded(t, ctx, r, []string{"sh", "-c", escapeScript(silentEscapee) + "echo ready; sleep 30"}, opts, func([]byte) error { cancel(); return nil })
	if !errors.Is(o.err, context.Canceled) || !o.res.IOIncomplete {
		t.Fatalf("cancel: err=%v res=%+v", o.err, o.res)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("cancel took %s", el)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("escapee never started: %v", err)
	}

	marker, opts = newEscapee()
	start = time.Now()
	o = streamBounded(t, bg, r, []string{"sh", "-c", escapeScript(silentEscapee) + "exit 0"}, opts, nil)
	if !errors.Is(o.err, ErrIOTimeout) || !o.res.IOIncomplete {
		t.Fatalf("self-exit: err=%v res=%+v", o.err, o.res)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("self-exit took %s", el)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("escapee never started: %v", err)
	}
	resourcesSettle(t, "escapee", g, fds)
}

// A leftover that keeps writing stdout lines after the program exited must not
// keep the stream alive: the post-exit budget (wall time minus time inside
// onLine) and the byte cap end it with ErrIOTimeout and IOIncomplete.
func TestStreamChattyLeftoverAfterExitIsBounded(t *testing.T) {
	old := waitDelay
	waitDelay = 300 * time.Millisecond
	t.Cleanup(func() { waitDelay = old })
	longArg := "$(head -c 20000 /dev/zero | tr '\\0' a)"
	overArg := "$(head -c 70000 /dev/zero | tr '\\0' a)"
	cases := []struct {
		name     string
		script   string
		onLine   func([]byte) error
		within   time.Duration
		maxLines int
	}{
		{"group member writing every waitDelay/3", "(while :; do echo tick; sleep 0.1; done) & exit 0", nil, 3 * time.Second, 1000},
		{"flood, fast callback", "yes & exit 0", nil, 5 * time.Second, 1 << 20},
		{"flood of long lines, slow callback", "yes " + longArg + " & exit 0", func([]byte) error { time.Sleep(50 * time.Millisecond); return nil }, 10 * time.Second, 60},
		{"flood of dropped lines", "yes " + overArg + " & exit 0", nil, 5 * time.Second, 0},
		// The over-long lines are never delivered, so only their size can end
		// this stream: the slow callback keeps the wait budget from running out.
		{"dropped lines between short ones, slow callback", "L=" + overArg + "; while :; do echo \"$L\"; echo x; done & exit 0", func([]byte) error { time.Sleep(50 * time.Millisecond); return nil }, 8 * time.Second, 40},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(bg, 15*time.Second)
			defer cancel()
			n := 0
			start := time.Now()
			res, err := callStream(t, realRunner(t, "sh", "sleep", "yes", "head", "tr"), ctx, []string{"sh", "-c", c.script}, StreamOpts{}, func(l []byte) error {
				n++
				if c.onLine != nil {
					return c.onLine(l)
				}
				return nil
			})
			if !errors.Is(err, ErrIOTimeout) || !res.IOIncomplete {
				t.Fatalf("err=%v res=%+v after %s with %d lines", err, res, time.Since(start), n)
			}
			if el := time.Since(start); el > c.within {
				t.Fatalf("took %s, want within %s", el, c.within)
			}
			if n > c.maxLines {
				t.Fatalf("%d lines delivered, want at most %d", n, c.maxLines)
			}
			if c.name == "flood of dropped lines" && (res.DroppedLines == 0 || n != 0) {
				t.Fatalf("dropped=%d delivered=%d", res.DroppedLines, n)
			}
		})
	}
}

// The same with a chatty escapee in a new session, which no group kill reaches.
func TestStreamChattyEscapeeAfterExitIsBounded(t *testing.T) {
	newEscapee := escapeSetup(t)
	_, opts := newEscapee()
	ctx, cancel := context.WithTimeout(bg, 15*time.Second)
	defer cancel()
	start := time.Now()
	res, err := callStream(t, realRunner(t, "sh", "sleep"), ctx, []string{"sh", "-c", escapeScript(chattyEscapee) + "exit 0"}, opts, nil)
	if !errors.Is(err, ErrIOTimeout) || !res.IOIncomplete {
		t.Fatalf("err=%v res=%+v after %s", err, res, time.Since(start))
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("took %s", el)
	}
}

// A child that left its process group is ended by cancelling alone: the group
// kill misses it, so only the direct kill in cmd.Cancel reaches it.
func TestStreamChildOutsideItsGroupEndsOnCancel(t *testing.T) {
	if _, err := NewReal(nil).lookup("perl"); err != nil {
		t.Skip("no perl to move the child into another group")
	}
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	pid := 0
	t.Cleanup(func() {
		if pid != 0 {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	script := `use POSIX; $|=1; POSIX::setpgid(0, getpgrp(getppid())) or die "setpgid: $!"; print "$$\n"; exec("sleep","30")`
	start := time.Now()
	o := streamBounded(t, ctx, realRunner(t, "perl", "sleep"), []string{"perl", "-e", script}, StreamOpts{}, func(l []byte) error {
		pid, _ = strconv.Atoi(string(l))
		cancel()
		return nil
	})
	if pid == 0 {
		t.Skipf("the child could not leave its group: %+v", o.res)
	}
	if !errors.Is(o.err, context.Canceled) {
		t.Fatalf("err = %v", o.err)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("took %s", el)
	}
	mustBeGone(t, pid)
}

// On an abort the direct child has been reaped by the time Stream returns:
// its pid is gone at once, without polling.
func TestStreamChildIsReapedWhenAbortReturns(t *testing.T) {
	r := realRunner(t, "sh", "sleep")
	paths := map[string]func() (int, error){}
	run := func(opts StreamOpts, ctx context.Context, stopAt func(cancel func()) error) func() (int, error) {
		return func() (int, error) {
			pid := 0
			c, cancel := context.WithCancel(ctx)
			defer cancel()
			_, err := callStream(t, r, c, []string{"sh", "-c", "echo $$; exec sleep 30"}, opts, func(l []byte) error {
				pid, _ = strconv.Atoi(string(l))
				return stopAt(cancel)
			})
			return pid, err
		}
	}
	paths["cancel"] = run(StreamOpts{}, bg, func(cancel func()) error { cancel(); return nil })
	paths["callback error"] = run(StreamOpts{}, bg, func(func()) error { return errors.New("stop") })
	paths["timeout"] = run(StreamOpts{Timeout: 50 * time.Millisecond}, bg, func(func()) error { return nil })
	for name, f := range paths {
		for i := 0; i < 25; i++ {
			pid, err := f()
			if err == nil || pid == 0 {
				t.Fatalf("%s: pid=%d err=%v", name, pid, err)
			}
			if syscall.Kill(pid, 0) == nil {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("%s run %d: the child %d was not reaped when Stream returned", name, i, pid)
			}
		}
	}
}

// The deferred cleanup also runs when onLine panics and the caller recovers:
// the child is gone and no goroutine or descriptor is left.
func TestStreamPanicInCallbackReleasesEverything(t *testing.T) {
	r := realRunner(t, "sh", "sleep")
	g, fds := runtime.NumGoroutine(), fdCount(t)
	for i := 0; i < 5; i++ {
		pid := 0
		var recovered any
		within(t, 15*time.Second, "panicking Stream", func() {
			defer func() { recovered = recover() }()
			_, _ = r.Stream(bg, []string{"sh", "-c", "sleep 30 & echo $!; echo two; wait"}, StreamOpts{}, func(l []byte) error {
				pid, _ = strconv.Atoi(string(l))
				panic("callback failed")
			})
		})
		if recovered != "callback failed" {
			t.Fatalf("recovered = %v", recovered)
		}
		if pid == 0 {
			t.Fatal("no pid")
		}
		mustBeGone(t, pid)
	}
	resourcesSettle(t, "panic", g, fds)
}

// The process group is signalled once per stream, on every way a stream ends.
// Cancelling kills the direct child only (TestStreamCancelDoesNotSignalTheGroup
// pins that), so cleanup's signal is the only one.
func TestStreamKillsGroupOncePerStream(t *testing.T) {
	var kills atomic.Int32
	old := killProcessGroup
	killProcessGroup = func(c *exec.Cmd) { kills.Add(1); old(c) }
	t.Cleanup(func() { killProcessGroup = old })
	r := realRunner(t, "sh", "yes", "sleep")

	paths := map[string]func(){
		"clean exit": func() { callStream(t, r, bg, []string{"sh", "-c", "echo a"}, StreamOpts{}, nil) },
		"non-zero":   func() { callStream(t, r, bg, []string{"sh", "-c", "exit 3"}, StreamOpts{}, nil) },
		"callback error": func() {
			callStream(t, r, bg, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { return errors.New("stop") })
		},
		"cancel": func() {
			ctx, cancel := context.WithCancel(bg)
			defer cancel()
			callStream(t, r, ctx, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { cancel(); return nil })
		},
		"timeout": func() {
			callStream(t, r, bg, []string{"sleep", "30"}, StreamOpts{Timeout: 100 * time.Millisecond}, nil)
		},
		"panic": func() {
			within(t, 15*time.Second, "panicking Stream", func() {
				defer func() { recover() }()
				r.Stream(bg, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { panic("x") })
			})
		},
	}
	for name, f := range paths {
		kills.Store(0)
		f()
		if n := kills.Load(); n != 1 {
			t.Errorf("%s: group signalled %d times, want 1", name, n)
		}
	}
	kills.Store(0)
	callStream(t, r, bg, []string{"touch", t.TempDir() + "/ran"}, StreamOpts{}, nil)
	if n := kills.Load(); n != 0 {
		t.Errorf("refused program: group signalled %d times, want 0", n)
	}
}

// Cancelling a stream must not signal the process group: the group is left to
// cleanup's single signal. A grandchild is still alive when os/exec has run
// the cancel kill and cleanup is about to signal the group.
func TestStreamCancelDoesNotSignalTheGroup(t *testing.T) {
	var cancels atomic.Int32
	streamCmdHook = func(c *exec.Cmd) {
		orig := c.Cancel
		c.Cancel = func() error { cancels.Add(1); return orig() }
	}
	oldKill := killProcessGroup
	grandchild := 0
	aliveAtGroupKill := false
	killProcessGroup = func(c *exec.Cmd) {
		// Wait for os/exec to run the cancel kill, then let it land.
		for i := 0; i < 200 && cancels.Load() == 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(150 * time.Millisecond)
		aliveAtGroupKill = syscall.Kill(grandchild, 0) == nil
		oldKill(c)
	}
	t.Cleanup(func() { streamCmdHook, killProcessGroup = nil, oldKill })

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	callStream(t, realRunner(t, "sh", "sleep"), ctx, []string{"sh", "-c", "sleep 30 & echo $!; wait"}, StreamOpts{}, func(l []byte) error {
		grandchild, _ = strconv.Atoi(string(l))
		cancel()
		return nil
	})
	if cancels.Load() == 0 {
		t.Fatal("cmd.Cancel never ran")
	}
	if !aliveAtGroupKill {
		t.Fatal("the group was already signalled before cleanup: cancelling must kill the direct child only")
	}
	mustBeGone(t, grandchild)
}

// setGrace sets the grace period for one test.
func setGrace(t *testing.T, d time.Duration) {
	t.Helper()
	old := waitDelay
	waitDelay = d
	t.Cleanup(func() { waitDelay = old })
}

// defaultPipeBound is the documented value of postExitMaxBytes, written out so
// that the tests below pin it: the default pipe capacity plus one read.
func defaultPipeBound() int {
	return 16*os.Getpagesize() + 4096
}

// A dropped line far longer than the post-exit bound, read while the program
// still ran, does not count against that bound when its notice reaches the
// loop after the exit: the short lines behind it arrive and the stream ends
// clean. The first callback stalls, so the program has exited and the reader
// is past the long line before the loop looks again.
func TestStreamHugeDroppedLineBeforeExitLosesNothing(t *testing.T) {
	const size = 3000000
	huge := "head -c " + strconv.Itoa(size) + " /dev/zero | tr '\\0' a"
	if size < 2*postExitMaxBytes {
		t.Fatalf("the long line (%d bytes) is not far above the post-exit bound (%d)", size, postExitMaxBytes)
	}
	r := realRunner(t, "sh", "head", "tr")
	const runs, atOnce = 20, 4
	for i := 0; i < runs; i += atOnce {
		var wg sync.WaitGroup
		for j := 0; j < atOnce; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var got []string
				res, err := r.Stream(bg, []string{"sh", "-c", "echo first; " + huge + "; echo; echo a; echo b; echo c"}, StreamOpts{}, func(l []byte) error {
					got = append(got, string(l))
					if len(got) == 1 {
						time.Sleep(400 * time.Millisecond)
					}
					return nil
				})
				if err != nil || res.IOIncomplete || res.DroppedLines != 1 || res.ExitCode != 0 || strings.Join(got, "|") != "first|a|b|c" {
					t.Errorf("slow first callback: lines=%q err=%v res=%+v", got, err, res)
				}
			}()
		}
		within(t, 30*time.Second, "streams with a long dropped line", wg.Wait)
	}
	// The long line is the last one and has no newline; the consumer is fast.
	for i := 0; i < runs; i++ {
		n := 0
		res, err := callStream(t, r, bg, []string{"sh", "-c", huge}, StreamOpts{}, func([]byte) error { n++; return nil })
		if err != nil || res.IOIncomplete || res.DroppedLines != 1 || res.ExitCode != 0 || n != 0 {
			t.Fatalf("unterminated run %d: delivered=%d err=%v res=%+v", i, n, err, res)
		}
	}
}

// Nothing read while the program ran counts against the post-exit bound: a
// program that streams many times the bound and then exits loses no line. One
// late callback stalls, so the program exits with its last lines unread and
// the loop sees the exit with lines still to come.
func TestStreamVolumeBeforeExitIsNotCut(t *testing.T) {
	const lines, width, tail = 21000, 100, 100
	if lines*(width+1) < 2*int(postExitMaxBytes) {
		t.Fatalf("%d bytes are not far above the post-exit bound (%d)", lines*(width+1), postExitMaxBytes)
	}
	script := "i=0; while [ $i -lt " + strconv.Itoa(lines) + " ]; do printf '%0" + strconv.Itoa(width) + "d\\n' $i; i=$((i+1)); done"
	n, wrong := 0, ""
	res, err := callStream(t, realRunner(t, "sh"), bg, []string{"sh", "-c", script}, StreamOpts{}, func(l []byte) error {
		if want := fmt.Sprintf("%0*d", width, n); string(l) != want && wrong == "" {
			wrong = fmt.Sprintf("line %d = %q", n, l)
		}
		n++
		if n == lines-tail {
			time.Sleep(400 * time.Millisecond)
		}
		return nil
	})
	if err != nil || res.IOIncomplete || res.ExitCode != 0 || n != lines || wrong != "" {
		t.Fatalf("delivered %d/%d %s err=%v res=%+v", n, lines, wrong, err, res)
	}
}

// What a program left in a nearly full pipe when it exited is delivered in
// full, also to a consumer that takes longer than the grace period.
func TestStreamNearlyFullPipeBacklogIsDelivered(t *testing.T) {
	setGrace(t, 300*time.Millisecond)
	const lines, width, long = 560, 100, 20000
	// The long line is one write above 16 KiB, which makes darwin grow the
	// pipe to the 64 KiB a linux pipe has from the start.
	script := "B=$(head -c " + strconv.Itoa(long) + " /dev/zero | tr '\\0' b); echo first; echo $B; " +
		"i=0; while [ $i -lt " + strconv.Itoa(lines) + " ]; do printf '%0" + strconv.Itoa(width-1) + "d\\n' $i; i=$((i+1)); done"
	n, wrong := 0, ""
	start := time.Now()
	res, err := callStream(t, realRunner(t, "sh", "head", "tr"), bg, []string{"sh", "-c", script}, StreamOpts{}, func(l []byte) error {
		n++
		switch {
		case n == 1:
			time.Sleep(400 * time.Millisecond)
		case n == 2:
			if len(l) != long {
				wrong = fmt.Sprintf("long line has %d bytes", len(l))
			}
		default:
			if want := fmt.Sprintf("%0*d", width-1, n-3); string(l) != want && wrong == "" {
				wrong = fmt.Sprintf("line %d = %q", n, l)
			}
			time.Sleep(time.Millisecond)
		}
		return nil
	})
	if time.Since(start) < 2*waitDelay {
		t.Fatalf("consumer took %s, not longer than the grace period; the test proves nothing", time.Since(start))
	}
	if err != nil || res.IOIncomplete || res.ExitCode != 0 || n != lines+2 || wrong != "" {
		t.Fatalf("delivered %d/%d %s err=%v res=%+v", n, lines+2, wrong, err, res)
	}
}

// The post-exit bound is a byte volume: a leftover that floods stdout with
// short lines behind a slow onLine is cut once that many bytes were read,
// and onLine has been called for the lines in them. The grace period is far
// above the test's own limit, so only the byte bound can end this stream.
func TestStreamFloodOfShortLinesAfterExitEndsAtTheByteBound(t *testing.T) {
	setGrace(t, 20*time.Second)
	const width = 128 // bytes per line, newline included
	bound := defaultPipeBound()
	n := 0
	res, err := callStream(t, realRunner(t, "sh", "yes"), bg, []string{"sh", "-c", "yes " + strings.Repeat("y", width-1) + " & exit 0"}, StreamOpts{}, func(l []byte) error {
		n++
		time.Sleep(200 * time.Microsecond)
		return nil
	})
	if !errors.Is(err, ErrIOTimeout) || !res.IOIncomplete || res.ExitCode != 0 {
		t.Fatalf("err=%v res=%+v after %d lines", err, res, n)
	}
	// The reader runs ahead of the delivered lines by at most its buffer and
	// one line, in both directions: what it held when the exit was seen is
	// delivered on top of the bound, and what it holds when the bound is
	// passed is not delivered. A few lines may come before the exit is seen.
	const readAhead = 4096 + 2*width
	lo, hi := (bound-readAhead)/width, (bound+readAhead)/width+64
	if n < lo || n > hi {
		t.Fatalf("%d lines of %d bytes delivered, want %d to %d for a bound of %d bytes", n, width, lo, hi, bound)
	}
}

// Time spent inside onLine before the program exited is not credited to the
// post-exit budget: after slow callbacks during the run, a ticking leftover
// is cut about one grace period after the exit, not that time later.
func TestStreamCallbackTimeBeforeExitDoesNotExtendTheBudget(t *testing.T) {
	setGrace(t, 300*time.Millisecond)
	const slow = 500 * time.Millisecond
	script := "echo 1; echo 2; echo 3; sleep 2; (while :; do echo tick; sleep 0.1; done) & exit 0"
	n := 0
	var firstTick time.Time
	res, err := callStream(t, realRunner(t, "sh", "sleep"), bg, []string{"sh", "-c", script}, StreamOpts{}, func(l []byte) error {
		n++
		if n <= 3 {
			time.Sleep(slow)
		} else if firstTick.IsZero() {
			firstTick = time.Now()
		}
		return nil
	})
	if !errors.Is(err, ErrIOTimeout) || !res.IOIncomplete {
		t.Fatalf("err=%v res=%+v after %d lines", err, res, n)
	}
	if firstTick.IsZero() {
		t.Fatalf("no line from the leftover, %d lines", n)
	}
	// With the 1.5 s of earlier callback time credited, the stream would
	// last that much longer.
	if d := time.Since(firstTick); d > 3*waitDelay {
		t.Fatalf("the stream ended %s after the leftover's first line, want within %s", d, 3*waitDelay)
	}
}

// Cleanup waits for the child on every abort path. The hook holds the reaping
// back until well after the abort, so a Stream that did not wait would return
// while the child is still a zombie.
func TestStreamAbortWaitsForAHeldBackReap(t *testing.T) {
	const held = 300 * time.Millisecond
	var gate chan struct{}
	var hooked atomic.Int32
	streamWaitHook = func() { hooked.Add(1); <-gate }
	t.Cleanup(func() { streamWaitHook = nil })
	r := realRunner(t, "sh", "sleep")
	paths := []struct {
		name string
		opts StreamOpts
		stop func(cancel func()) error
	}{
		{"cancel", StreamOpts{}, func(cancel func()) error { cancel(); return nil }},
		{"callback error", StreamOpts{}, func(func()) error { return errors.New("stop") }},
		{"timeout", StreamOpts{Timeout: 50 * time.Millisecond}, func(func()) error { return nil }},
		{"idle timeout", StreamOpts{IdleTimeout: 50 * time.Millisecond}, func(func()) error { return nil }},
	}
	for i, p := range paths {
		gate = make(chan struct{})
		release := gate
		ctx, cancel := context.WithCancel(bg)
		pid := 0
		var aborted time.Time
		_, err := callStream(t, r, ctx, []string{"sh", "-c", "echo $$; exec sleep 30"}, p.opts, func(l []byte) error {
			pid, _ = strconv.Atoi(string(l))
			aborted = time.Now()
			time.AfterFunc(held, func() { close(release) })
			return p.stop(cancel)
		})
		waited := time.Since(aborted)
		zombie := pid != 0 && syscall.Kill(pid, 0) == nil
		cancel()
		if err == nil || pid == 0 {
			t.Fatalf("%s: pid=%d err=%v", p.name, pid, err)
		}
		if zombie {
			syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("%s: the child %d was not reaped when Stream returned", p.name, pid)
		}
		if waited < held {
			t.Fatalf("%s: Stream returned %s after the abort, before the reap was released after %s", p.name, waited, held)
		}
		if int(hooked.Load()) != i+1 {
			t.Fatalf("%s: the wait hook ran %d times, want %d", p.name, hooked.Load(), i+1)
		}
	}
}
