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
	// ErrIOTimeout means the program exited but a leftover child kept its
	// output pipes open past the grace period; output may be incomplete.
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
	Duration  time.Duration
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
