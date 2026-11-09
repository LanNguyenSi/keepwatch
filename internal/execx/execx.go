// Package execx is the single seam through which keepwatch runs external
// programs. It never invokes a shell, only runs allowlisted programs, bounds
// time and output, and gives parsers a stable environment.
package execx

import (
	"context"
	"errors"
	"time"
)

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
)

// Runner runs one program and returns its result. A non-zero exit status is
// not an error; it is reported in Result.ExitCode.
type Runner interface {
	Run(ctx context.Context, argv []string, opts Opts) (Result, error)
}

// Result is the outcome of a run.
type Result struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool // either stream was cut at MaxOutput
	Duration  time.Duration
}

// Opts tunes a single run. Zero values select the defaults.
type Opts struct {
	Timeout   time.Duration
	MaxOutput int64
	// Env replaces the minimal default environment when non-nil.
	Env []string
	Dir string
}
