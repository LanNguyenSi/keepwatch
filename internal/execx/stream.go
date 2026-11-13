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

// killProcessGroup is killGroup; a variable so a test can count the calls.
var killProcessGroup = killGroup

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
// outlive the call. A grandchild that started a new session is outside the
// group and is not killed. No goroutine started by Stream outlives it, also
// when onLine panics and the caller recovers.
//
// Lines are split at '\n'; a final line without a newline is delivered too.
// A line longer than StreamOpts.MaxLine is dropped and counted, see
// StreamOpts. stderr is drained concurrently into a buffer capped at
// StreamOpts.MaxStderr.
//
// After the program exited, Stream keeps reading stdout until it ends, but
// gives up when no line arrives for the same grace period Run uses and a
// leftover child holds the pipe open (StreamResult.IOIncomplete). The grace
// period restarts after every line, so a slow onLine never causes it.
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
	// waiter and the stderr copy. It is the only place the stream path
	// kills, and it runs once, so the group is signalled once and never
	// again after the child was reaped, when its pid could have been reused.
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
			if onLine != nil && !m.dropped {
				if err := onLine(m.line); err != nil {
					abortErr = err
					break loop
				}
			}
			// The idle and grace timers measure waiting for the reader, not
			// time inside onLine: they restart once the line was handled.
			if idle != nil {
				resetTimer(idle, opts.IdleTimeout)
			}
			if grace != nil {
				resetTimer(grace, waitDelay)
			}
		case waitErr = <-wc:
			exited = true
			wc = nil
			// From here a leftover child is bounded by the grace period.
			idleC = nil
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
