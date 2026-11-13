package execx

import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type streamOut struct {
	res   StreamResult
	err   error
	lines []string
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
	if _, err := r.Stream(bg, nil, StreamOpts{}, noLine); !errors.Is(err, ErrEmptyArgv) {
		t.Errorf("nil argv: %v", err)
	}
	if _, err := r.Stream(bg, []string{""}, StreamOpts{}, noLine); !errors.Is(err, ErrEmptyArgv) {
		t.Errorf("empty argv: %v", err)
	}
	if _, err := r.Stream(bg, []string{"touch", marker}, StreamOpts{}, noLine); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("not allowed: %v", err)
	}
	notExecuted(t, marker)
	if _, err := r.Stream(bg, []string{"./echo"}, StreamOpts{}, noLine); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("relative: %v", err)
	}
	if _, err := realRunner(t, "keepwatch-no-such-tool").Stream(bg, []string{"keepwatch-no-such-tool"}, StreamOpts{}, noLine); !errors.Is(err, ErrNotFound) {
		t.Errorf("not found: %v", err)
	}
	var got []string
	if _, err := r.Stream(bg, []string{"echo", "hi"}, StreamOpts{}, func(l []byte) error { got = append(got, string(l)); return nil }); err != nil || len(got) != 1 || got[0] != "hi" {
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
	res, err := realRunner(t, "sh").Stream(ctx, []string{"sh", "-c", "touch " + marker}, StreamOpts{}, nil)
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

func goroutinesSettle(t *testing.T, name string, base int) {
	t.Helper()
	var n int
	for i := 0; i < 100; i++ {
		n = runtime.NumGoroutine()
		if n <= base {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	buf := make([]byte, 1<<16)
	buf = buf[:runtime.Stack(buf, true)]
	t.Fatalf("%s: goroutines: %d after, %d before\n%s", name, n, base, buf)
}

// No goroutine started by Stream outlives it, on any way it can end.
func TestStreamLeavesNoGoroutines(t *testing.T) {
	r := realRunner(t, "sh", "sleep", "yes")
	run := func(name string, f func()) {
		t.Helper()
		base := runtime.NumGoroutine()
		f()
		goroutinesSettle(t, name, base)
	}
	run("clean", func() {
		_, _ = r.Stream(bg, []string{"sh", "-c", "echo a; echo b >&2"}, StreamOpts{}, func([]byte) error { return nil })
	})
	run("nonzero", func() {
		_, _ = r.Stream(bg, []string{"sh", "-c", "exit 2"}, StreamOpts{}, nil)
	})
	run("callback error", func() {
		_, err := r.Stream(bg, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { return errors.New("stop") })
		if err == nil {
			t.Error("want error")
		}
	})
	run("cancel", func() {
		ctx, cancel := context.WithCancel(bg)
		defer cancel()
		_, err := r.Stream(ctx, []string{"sh", "-c", "yes"}, StreamOpts{}, func([]byte) error { cancel(); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v", err)
		}
	})
	run("cancel while idle", func() {
		ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
		defer cancel()
		_, err := r.Stream(ctx, []string{"sleep", "30"}, StreamOpts{}, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v", err)
		}
	})
	run("timeouts", func() {
		_, err := r.Stream(bg, []string{"sleep", "30"}, StreamOpts{Timeout: 150 * time.Millisecond}, nil)
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("err = %v", err)
		}
		_, err = r.Stream(bg, []string{"sleep", "30"}, StreamOpts{IdleTimeout: 150 * time.Millisecond}, nil)
		if !errors.Is(err, ErrIdleTimeout) {
			t.Errorf("err = %v", err)
		}
	})
	run("refused", func() {
		_, _ = r.Stream(bg, []string{"touch", t.TempDir() + "/ran"}, StreamOpts{}, nil)
		_, _ = realRunner(t, "keepwatch-no-such-tool").Stream(bg, []string{"keepwatch-no-such-tool"}, StreamOpts{}, nil)
	})
	run("held pipe", func() {
		old := waitDelay
		waitDelay = 200 * time.Millisecond
		defer func() { waitDelay = old }()
		_, _ = r.Stream(bg, []string{"sh", "-c", "sleep 30 & exit 0"}, StreamOpts{}, nil)
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
	wg.Wait()
}

func TestStreamMissingBinaryMessage(t *testing.T) {
	_, err := realRunner(t, "keepwatch-no-such-tool").Stream(bg, []string{"/usr/bin/keepwatch-no-such-tool"}, StreamOpts{}, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
