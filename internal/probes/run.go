package probes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// run executes argv and maps every way a run can go wrong to an Outcome:
// the returned Outcome is non-nil exactly when the caller must stop and
// return it. A zero timeout selects the execx default.
//
//	program not installed      skipped, program named
//	program not allowlisted    error (programming error)
//	timeout, io timeout        error
//	pipes cut after exit       error (Result.IOIncomplete, any exit status)
//	killed by a signal         error
//	output truncated           error
//
// A non-zero exit status is NOT mapped here: only the caller knows which
// statuses its command documents. It must treat every other status as error.
func run(ctx context.Context, env *Env, argv []string, timeout time.Duration) (execx.Result, *Outcome) {
	return runWith(ctx, env, argv, execx.Opts{Timeout: timeout}, false)
}

// runWith is run with full options. With keepTruncated a run whose output was
// cut at the size limit is NOT turned into an error outcome: the caller gets
// the result with Truncated set and must treat the output as incomplete (it
// may parse the complete lines of the prefix, but must never report pass).
func runWith(ctx context.Context, env *Env, argv []string, opts execx.Opts, keepTruncated bool) (execx.Result, *Outcome) {
	res, err := env.Runner.Run(ctx, argv, opts)
	switch {
	case err == nil:
	case errors.Is(err, execx.ErrNotFound):
		return res, &Outcome{Status: result.Skipped, Summary: fmt.Sprintf("program %q is not installed, check skipped", argv[0])}
	case errors.Is(err, execx.ErrNotAllowed):
		return res, errorOutcome("internal error: program %q is not on the execution allowlist", argv[0])
	case errors.Is(err, execx.ErrTimeout):
		return res, errorOutcome("%s timed out", argv[0])
	case errors.Is(err, execx.ErrIOTimeout):
		return res, errorOutcome("%s output may be incomplete: pipes still held open after exit", argv[0])
	default:
		return res, errorOutcome("running %s failed: %s", argv[0], err.Error())
	}
	switch {
	case res.IOIncomplete:
		// Set for every exit status: a non-zero exit gives no ErrIOTimeout,
		// so this is the only place that catches it for the probes.
		return res, errorOutcome("%s output may be incomplete: pipes still held open after exit", argv[0])
	case res.Signaled || res.ExitCode < 0:
		return res, errorOutcome("%s was terminated before it exited", argv[0])
	case res.Truncated && !keepTruncated:
		return res, errorOutcome("%s output was truncated at the size limit", argv[0])
	}
	return res, nil
}

func errorOutcome(format string, a ...any) *Outcome {
	return &Outcome{Status: result.Error, Summary: fmt.Sprintf(format, a...)}
}

// unexpectedExit builds the error outcome for an exit status the caller
// does not interpret, quoting the first line of stderr (as untrusted text).
func unexpectedExit(prog string, res execx.Result) *Outcome {
	msg := firstLine(res.Stderr)
	if msg == "" {
		msg = firstLine(res.Stdout)
	}
	if msg != "" {
		return errorOutcome("%s exited with status %d: %s", prog, res.ExitCode, msg)
	}
	return errorOutcome("%s exited with status %d", prog, res.ExitCode)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// quoted puts s in double quotes and changes nothing inside. Host text stays
// raw in a probe until the one redact.Redactor.Clean where it leaves the
// program: a cut, an escape (strconv.Quote, %q) or a "?" for an unprintable
// byte made here can split a secret or move the word boundary its pattern
// needs, so no pattern would match any more. How much output a probe holds is
// bounded where it is read (execx.Opts.MaxOutput), not here.
func quoted(s string) string { return `"` + s + `"` }
