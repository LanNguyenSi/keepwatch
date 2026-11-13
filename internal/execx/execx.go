// Package execx is the single seam through which keepwatch runs external
// programs. It never invokes a shell, only runs allowlisted programs, bounds
// time and output, and gives parsers a stable environment.
package execx

import (
	"context"
	"errors"
	"time"
)

// waitDelay is how long Run waits for output pipes to close after the child
// exited or was killed. A variable so tests can shorten it.
var waitDelay = 2 * time.Second

// Defaults applied when the corresponding Opts field is zero.
const (
	DefaultTimeout   = 10 * time.Second
	DefaultMaxOutput = int64(1 << 20) // per stream
	// SearchPath is the fixed directory list used to resolve bare program
	// names. The inherited PATH is deliberately ignored.
	SearchPath = "/usr/sbin:/usr/bin:/sbin:/bin"
)

// Typed errors, test with errors.Is.
var (
	ErrNotAllowed = errors.New("execx: program not allowed")
	ErrNotFound   = errors.New("execx: program not found")
	ErrTimeout    = errors.New("execx: timeout")
	ErrEmptyArgv  = errors.New("execx: empty argv")
	// ErrIOTimeout means the program exited successfully but a leftover
	// child kept its output pipes open past the grace period; output may be
	// incomplete. After a non-zero exit the same condition is reported only
	// through Result.IOIncomplete.
	ErrIOTimeout = errors.New("execx: output pipes held open after exit")
)

// Runner runs one program and returns its result. A non-zero exit status is
// not an error; it is reported in Result.ExitCode.
type Runner interface {
	Run(ctx context.Context, argv []string, opts Opts) (Result, error)
}

// Result is the outcome of a run.
type Result struct {
	// ExitCode is the exit status; -1 when the process was killed by a
	// signal (see Signaled) or the run ended by timeout or cancellation.
	ExitCode  int
	Signaled  bool // the process was terminated by a signal (unix only)
	Stdout    []byte
	Stderr    []byte
	Truncated bool // either stream was cut at MaxOutput
	// IOIncomplete is set, for every exit status, when the output pipes were
	// still open a grace period after the program exited (a leftover child
	// held them) and had to be cut. Stdout and Stderr then hold what was
	// read up to that point and may miss the tail; callers must not trust
	// them as complete.
	IOIncomplete bool
	Duration     time.Duration
}

// Opts tunes a single run. Zero values select the defaults.
type Opts struct {
	Timeout   time.Duration
	MaxOutput int64
	// Env replaces the minimal default environment when non-nil. It is for
	// trusted callers only and must never carry configuration values or
	// other user-controlled input (variables such as LD_PRELOAD change what
	// the child executes).
	Env []string
	Dir string
}

// DefaultMaxLine is the longest stdout line, in bytes and without its
// newline, that Stream delivers when StreamOpts.MaxLine is zero.
const DefaultMaxLine = 64 << 10

// ErrIdleTimeout means a Stream produced no stdout line for
// StreamOpts.IdleTimeout. It is opt-in: no default idle limit exists.
var ErrIdleTimeout = errors.New("execx: no output within the idle timeout")

// Streamer runs one long-lived program and hands its stdout to the caller
// line by line while it runs. Run-to-completion callers use Runner instead.
//
// Stream returns when the program has exited and its stdout is drained, when
// ctx ends (it then returns ctx.Err()), when onLine returns an error (that
// error is returned), or when an opt-in timeout fires. Unless the program
// ended by itself, it is killed first. A non-zero exit status is not an
// error; it is reported in StreamResult.ExitCode.
//
// onLine runs on the goroutine that called Stream, one line at a time, in
// order. The slice it receives is its own copy. While onLine runs, ctx
// cancellation and timeouts cannot interrupt it, so it must not block.
type Streamer interface {
	Stream(ctx context.Context, argv []string, opts StreamOpts, onLine func([]byte) error) (StreamResult, error)
}

// StreamOpts tunes a single stream. Zero values select the defaults. Unlike
// Opts there is no default Timeout: a follow stream is meant to run until the
// caller cancels it.
type StreamOpts struct {
	// MaxLine is the longest line (without its newline) that is delivered.
	// A longer line is not delivered at all, not even cut: it is dropped,
	// counted in StreamResult.DroppedLines, and the stream continues with
	// the next line. Zero selects DefaultMaxLine.
	MaxLine int
	// MaxStderr caps the stderr kept in StreamResult; the rest is read and
	// discarded so the child never blocks on a full pipe. Zero selects
	// DefaultMaxOutput.
	MaxStderr int64
	// Timeout, when positive, bounds the whole stream and ends it with
	// ErrTimeout. Zero means no limit.
	Timeout time.Duration
	// IdleTimeout, when positive, ends the stream with ErrIdleTimeout if no
	// stdout line arrives for that long (dropped lines count as arrivals).
	// It measures time spent waiting for the program, not time spent inside
	// onLine, and it stays armed until the program has exited, also after
	// its stdout was closed. Zero means no limit.
	IdleTimeout time.Duration
	// Env and Dir behave as in Opts.
	Env []string
	Dir string
}

// StreamResult is the outcome of a stream.
type StreamResult struct {
	// ExitCode is the exit status; -1 when the program was killed by a
	// signal (see Signaled) or the stream ended before it exited.
	ExitCode int
	Signaled bool
	// Stderr holds at most StreamOpts.MaxStderr bytes of the program's stderr.
	Stderr          []byte
	StderrTruncated bool
	// DroppedLines counts stdout lines longer than StreamOpts.MaxLine that
	// were not delivered.
	DroppedLines int
	// IOIncomplete is set when the program exited but the output pipes were
	// still open (a leftover child held them) and had to be cut: lines or
	// stderr may be missing. The cut happens when the wall time since the
	// exit, minus the time spent inside onLine since then, reaches the grace
	// period Run uses, or when more stdout than a pipe of the default size
	// holds (16 pages, 64 KiB with 4 KiB pages) was read after the exit was
	// seen. What the program itself left in such a pipe is delivered in
	// full, however slow onLine is; a program that enlarged its stdout pipe
	// can lose the rest of a larger backlog this way. A successful exit also
	// returns ErrIOTimeout, as Run does.
	IOIncomplete bool
	Duration     time.Duration
}
