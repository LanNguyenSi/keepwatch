package execx

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

var _ Streamer = (*Real)(nil)

// postExitMaxBytes bounds what Stream accepts from stdout after the program
// exited. A real backlog cannot exceed the pipe buffer (64 KiB on linux and
// darwin) plus the reader's own buffers and at most one pending line, so a
// stream that goes past this much is fed by a leftover process, not by the
// program, and is ended with IOIncomplete. Dropped lines count by their full
// length. One MaxLine is added to the cap, so a single legitimate long line
// in the backlog never trips it.
const postExitMaxBytes = 1 << 20

// killProcessGroup is killGroup; a variable so a test can count the calls.
var killProcessGroup = killGroup

// streamCmdHook, when set by a test, sees the command after it was set up and
// before it starts.
var streamCmdHook func(*exec.Cmd)

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
// bytes were read since the exit. A backlog the program left in the pipe is
// delivered in full even to a slow onLine; a leftover process that keeps
// writing cannot keep the stream alive.
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
	go func() { waitC <- cmd.Wait() }()

	stop := make(chan struct{})
	rd := startLineReader(outR, opts.MaxLine, stop)

	// cleanup ends the child and everything left in its process group and
	// joins every goroutine and descriptor Stream owns: the reader, the
	// waiter and the stderr copy. It is the only place that signals the
	// process group, and it runs once, so the group is signalled once per
	// stream (cancel only kills the direct child, see cmd.Cancel). On the
	// self-exit path that one signal comes after the child was reaped, as in
	// Run; on every abort path the child is still unreaped when it is sent.
	// It runs after the loop and, if onLine panics, from the deferred call.
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
	// onLine since then, and the bytes read since then.
	var (
		exitAt    time.Time
		cbSince   time.Duration
		postBytes int64
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
			if exited {
				postBytes += int64(m.size)
				if postBytes > postExitMaxBytes+int64(opts.MaxLine) {
					incomplete = true
					break loop
				}
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
			// From here a leftover child is bounded by the post-exit budget.
			idleC = nil
			exitAt = time.Now()
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
	// size is the number of bytes the line took from the pipe, its newline
	// included, whether or not the line was dropped.
	size int
}

// lineReader splits one pipe into lines on its own goroutine.
type lineReader struct {
	lines chan lineMsg
	done  chan struct{}
	// dropped is written by the goroutine and may be read only after done
	// is closed.
	dropped int
}

// startLineReader reads r until it ends or fails, sending each line to
// lines (closed when reading ends). It stops sending when stop is closed.
// Memory per line is bounded: a line that exceeds max is not accumulated.
func startLineReader(r *os.File, max int, stop <-chan struct{}) *lineReader {
	lr := &lineReader{lines: make(chan lineMsg), done: make(chan struct{})}
	go func() {
		defer close(lr.done)
		defer close(lr.lines)
		br := bufio.NewReaderSize(r, 4096)
		var acc []byte
		over := false
		size := 0
		for {
			chunk, err := br.ReadSlice('\n')
			size += len(chunk)
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
				m := lineMsg{dropped: over, size: size}
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
				acc, over, size = acc[:0], false, 0
			}
			if !eol {
				return
			}
		}
	}()
	return lr
}
