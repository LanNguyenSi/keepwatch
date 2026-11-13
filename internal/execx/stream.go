package execx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"time"
)

var _ Streamer = (*Real)(nil)

// lineReaderBuf is the size of the stdout reader's buffer, which is also the
// most a single read takes from the pipe.
const lineReaderBuf = 4096

// postExitMaxBytes bounds how many bytes Stream reads from the stdout pipe
// after it saw the program exit. Only bytes read from then on count, whatever
// lines they belong to. What the program wrote and Stream had not read yet
// was inside the pipe when the program exited, so it is at most the pipe's
// capacity: 16 pages on linux (64 KiB with 4 KiB pages), and at most 64 KiB on
// darwin, which 16 pages cover as well. One reader buffer is added for a read
// that returned just before the exit was seen and is counted just after. A
// stream that reads more than this after the exit is fed by a leftover
// process, not by the program, and is ended with IOIncomplete. Two limits:
// a program that enlarged its own stdout pipe can leave more than this
// behind, and the rest is then cut as if a leftover had written it; and the
// bound is a volume, not a time, see Stream.
var postExitMaxBytes = int64(16*os.Getpagesize() + lineReaderBuf)

// killProcessGroup is killGroup; a variable so a test can count the calls.
var killProcessGroup = killGroup

// streamCmdHook, when set by a test, sees the command after it was set up and
// before it starts.
var streamCmdHook func(*exec.Cmd)

// streamWaitHook, when set by a test, runs on the goroutine that reaps the
// child, before it waits.
var streamWaitHook func()

// withDefaults fills the zero values. Timeout and IdleTimeout stay as given:
// zero (or negative) means no limit.
func (o StreamOpts) withDefaults() StreamOpts {
	if o.MaxLine <= 0 {
		o.MaxLine = DefaultMaxLine
	}
	if o.MaxStderr <= 0 {
		o.MaxStderr = DefaultMaxOutput
	}
	if o.Timeout < 0 {
		o.Timeout = 0
	}
	if o.IdleTimeout < 0 {
		o.IdleTimeout = 0
	}
	if o.Env == nil {
		o.Env = DefaultEnv
	}
	return o
}

// Stream implements Streamer. It applies the same allowlist and resolve rules
// as Run (ErrEmptyArgv, ErrNotAllowed and ErrNotFound are returned before
// anything starts), gives the child its own pipes and the same minimal
// environment, and on unix runs it in its own process group, which is killed
// when Stream returns on any path, so everything left in that group does not
// outlive the call (it is signalled once, by the cleanup; cancelling only
// kills the direct child). A grandchild that started a new session is outside
// the group and is not killed. No goroutine started by Stream outlives it,
// also when onLine panics and the caller recovers.
//
// Lines are split at '\n'; a final line without a newline is delivered too.
// A line longer than StreamOpts.MaxLine is dropped and counted, see
// StreamOpts. stderr is drained concurrently into a buffer capped at
// StreamOpts.MaxStderr.
//
// After the program exited, Stream keeps reading stdout until it ends, but
// gives up, with IOIncomplete, when a leftover child still holds the pipe and
// either the wall time since the exit minus the time spent inside onLine
// since then reaches the grace period Run uses, or more than postExitMaxBytes
// bytes were read from the pipe since the exit was seen. What the program
// itself left in a pipe of the default size is below that bound and is
// delivered in full even to a slow onLine. The second bound is a byte volume,
// not a time: a leftover process that floods stdout with short lines is cut
// after postExitMaxBytes bytes, and a slow onLine is still called once for
// every line in them. A caller that needs a time bound sets
// StreamOpts.Timeout.
func (r *Real) Stream(ctx context.Context, argv []string, opts StreamOpts, onLine func([]byte) error) (StreamResult, error) {
	if len(argv) == 0 || argv[0] == "" {
		return StreamResult{}, ErrEmptyArgv
	}
	path, err := r.resolve(argv[0])
	if err != nil {
		return StreamResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return StreamResult{}, err
	}
	opts = opts.withDefaults()

	// The command's own context is not derived from ctx: the child is ended
	// only by cleanup below, so that there is one place that kills it.
	kctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(kctx, path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Env = opts.Env
	cmd.Dir = opts.Dir
	outR, outW, err := os.Pipe()
	if err != nil {
		cancel()
		return StreamResult{}, fmt.Errorf("execx: stream %s: %w", argv[0], err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		cancel()
		outR.Close()
		outW.Close()
		return StreamResult{}, fmt.Errorf("execx: stream %s: %w", argv[0], err)
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	configureKill(cmd)
	// Cancelling kills the direct child only. The process group is signalled
	// by cleanup alone, once.
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	if streamCmdHook != nil {
		streamCmdHook(cmd)
	}

	start := time.Now()
	startErr := cmd.Start()
	outW.Close()
	errW.Close()
	if startErr != nil {
		cancel()
		outR.Close()
		errR.Close()
		if errors.Is(startErr, os.ErrNotExist) {
			return StreamResult{}, fmt.Errorf("%w: %s", ErrNotFound, argv[0])
		}
		if ctx.Err() != nil {
			return StreamResult{}, ctx.Err()
		}
		return StreamResult{}, fmt.Errorf("execx: stream %s: %w", argv[0], startErr)
	}
	var (
		stderr     limitBuffer
		abortErr   error
		waitErr    error
		exited     bool
		eof        bool
		incomplete bool
		cleaned    bool
	)
	stderr.limit = opts.MaxStderr
	errC := startCopy(errR, &stderr)

	waitC := make(chan error, 1)
	go func() {
		if streamWaitHook != nil {
			streamWaitHook()
		}
		waitC <- cmd.Wait()
	}()

	stop := make(chan struct{})
	rd := startLineReader(outR, opts.MaxLine, stop)

	// cleanup ends the child and everything left in its process group and
	// joins every goroutine and descriptor Stream owns: the reader, the
	// waiter and the stderr copy. It is the only place that signals the
	// process group, and it runs once, so the group is signalled once per
	// stream (cancel only kills the direct child, see cmd.Cancel). Once the
	// exit was seen, on the self-exit path and on an abort that comes after
	// it, that one signal comes after the child was reaped, as in Run. On an
	// abort before the exit was seen the signal is sent before cleanup waits
	// for the child, which as a rule is not reaped yet (the direct kill and
	// the reaping run on their own goroutines). It runs after the loop and,
	// if onLine panics, from the deferred call.
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		cancel()
		killProcessGroup(cmd)
		if !exited {
			waitErr = <-waitC
			exited = true
		}
		close(stop)
		outR.Close()
		<-rd.done
		if awaitCopies(errC) {
			incomplete = true
		}
	}
	defer cleanup()

	var total, idle, grace *time.Timer
	var totalC, idleC, graceC <-chan time.Time
	if opts.Timeout > 0 {
		total = time.NewTimer(opts.Timeout)
		defer total.Stop()
		totalC = total.C
	}
	if opts.IdleTimeout > 0 {
		idle = time.NewTimer(opts.IdleTimeout)
		defer idle.Stop()
		idleC = idle.C
	}
	defer func() {
		if grace != nil {
			grace.Stop()
		}
	}()

	// Post-exit bookkeeping: when the exit was seen, the time spent inside
	// onLine since then, and how many bytes the reader had taken from the
	// pipe at that moment.
	var (
		exitAt   time.Time
		cbSince  time.Duration
		exitRead int64
	)
	linesC := rd.lines
	wc := (<-chan error)(waitC)
loop:
	for !(exited && eof) {
		select {
		case m, ok := <-linesC:
			if !ok {
				eof = true
				linesC = nil
				continue
			}
			// Bytes the reader took from the pipe before the exit was seen
			// do not count, also when their line arrives here afterwards.
			var post int64
			if exited {
				post = rd.read.Load() - exitRead
			}
			if post > postExitMaxBytes {
				incomplete = true
				break loop
			}
			if onLine != nil && !m.dropped {
				began := time.Now()
				err := onLine(m.line)
				if exited {
					cbSince += time.Since(began)
				}
				if err != nil {
					abortErr = err
					break loop
				}
			}
			// The idle timer measures waiting for the reader, not time
			// inside onLine: it restarts once the line was handled.
			if idle != nil {
				resetTimer(idle, opts.IdleTimeout)
			}
			// The post-exit budget is wall time since the exit minus the
			// time inside onLine; it is not restarted by lines.
			if grace != nil {
				left := waitDelay - (time.Since(exitAt) - cbSince)
				if left <= 0 {
					incomplete = true
					break loop
				}
				resetTimer(grace, left)
			}
		case waitErr = <-wc:
			exited = true
			wc = nil
			// From here a leftover child is bounded by the post-exit budget
			// and by the bytes read from now on.
			idleC = nil
			exitAt = time.Now()
			exitRead = rd.read.Load()
			grace = time.NewTimer(waitDelay)
			graceC = grace.C
		case <-graceC:
			incomplete = true
			break loop
		case <-ctx.Done():
			abortErr = ctx.Err()
			break loop
		case <-totalC:
			abortErr = fmt.Errorf("%w after %s: %s", ErrTimeout, opts.Timeout, argv[0])
			break loop
		case <-idleC:
			abortErr = fmt.Errorf("%w (%s): %s", ErrIdleTimeout, opts.IdleTimeout, argv[0])
			break loop
		}
	}

	cleanup()
	res := StreamResult{
		Stderr:          stderr.buf.Bytes(),
		StderrTruncated: stderr.truncated,
		DroppedLines:    rd.dropped,
		IOIncomplete:    incomplete,
		Duration:        time.Since(start),
	}
	if abortErr != nil {
		res.ExitCode = -1
		return res, abortErr
	}
	var ee *exec.ExitError
	switch {
	case waitErr == nil:
		if incomplete {
			return res, fmt.Errorf("%w: %s", ErrIOTimeout, argv[0])
		}
		return res, nil
	case errors.As(waitErr, &ee) && ctx.Err() == nil:
		res.ExitCode = ee.ExitCode()
		res.Signaled = signaled(ee.ProcessState)
		return res, nil
	case ctx.Err() != nil:
		res.ExitCode = -1
		return res, ctx.Err()
	default:
		res.ExitCode = -1
		return res, fmt.Errorf("execx: stream %s: %w", argv[0], waitErr)
	}
}

// resetTimer restarts a timer that may or may not have fired.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// lineMsg is one line, or the notice that an over-long line was dropped.
type lineMsg struct {
	line    []byte
	dropped bool
}

// lineReader splits one pipe into lines on its own goroutine.
type lineReader struct {
	lines chan lineMsg
	done  chan struct{}
	// dropped is written by the goroutine and may be read only after done
	// is closed.
	dropped int
	// read counts the bytes taken from the pipe so far. It runs ahead of
	// the lines sent: by the reader's buffer and by the line being read.
	read atomic.Int64
}

// countingReader adds every byte read from r to n.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// startLineReader reads r until it ends or fails, sending each line to
// lines (closed when reading ends). It stops sending when stop is closed.
// Memory per line is bounded: a line that exceeds max is not accumulated.
func startLineReader(r *os.File, max int, stop <-chan struct{}) *lineReader {
	lr := &lineReader{lines: make(chan lineMsg), done: make(chan struct{})}
	go func() {
		defer close(lr.done)
		defer close(lr.lines)
		br := bufio.NewReaderSize(countingReader{r, &lr.read}, lineReaderBuf)
		var acc []byte
		over := false
		for {
			chunk, err := br.ReadSlice('\n')
			eol := err == nil
			data := chunk
			if eol {
				data = chunk[:len(chunk)-1]
			}
			if !over {
				if len(acc)+len(data) > max {
					over = true
					acc = nil
				} else {
					acc = append(acc, data...)
				}
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if eol || over || len(acc) > 0 {
				m := lineMsg{dropped: over}
				if over {
					lr.dropped++
				} else {
					m.line = append([]byte(nil), acc...)
				}
				// A dropped line is still sent: it counts as activity
				// for the idle timeout.
				select {
				case lr.lines <- m:
				case <-stop:
					return
				}
				acc, over = acc[:0], false
			}
			if !eol {
				return
			}
		}
	}()
	return lr
}
