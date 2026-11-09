package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultEnv is the environment given to child processes unless Opts.Env is set.
var DefaultEnv = []string{
	"PATH=" + SearchPath,
	"LANG=C.UTF-8",
	"LC_ALL=C",
}

// Real runs programs on the host.
type Real struct {
	allow  map[string]bool
	dirs   []trustedDir
	extras []extra
	// raw option inputs, consumed by NewReal
	rawDirs   []string
	rawExtras []string
}

// trustedDir is a search directory, kept in the literal form it was given in
// and in its symlink-resolved form. Both are computed once, at construction.
type trustedDir struct{ literal, resolved string }

// extra is a WithExtraPrograms entry with its target pinned at construction.
type extra struct{ path, pinned string }

// Option configures a Real runner.
type Option func(*Real)

// WithSearchDirs replaces the list of trusted directories used to resolve
// bare names (see resolve). Intended for tests. NewReal panics if an entry
// is not absolute: a relative directory would be checked against the process
// working directory but executed after the chdir to Opts.Dir.
func WithSearchDirs(dirs ...string) Option {
	return func(r *Real) { r.rawDirs = dirs }
}

// WithExtraPrograms permits specific programs outside the trusted search
// directories, given as absolute paths. This is the only way to run an
// off-path binary. NewReal panics if an entry is not absolute (a programmer
// error, caught at construction). Each entry is resolved once, at
// construction, and the target is pinned: Run accepts it only when argv[0]
// equals the configured path exactly AND the path still resolves to the
// pinned target at that moment. Pinning compares paths, not file contents:
// the pinned target and all its ancestor directories (and the configured
// path's own ancestors) must be root-owned and not group- or world-writable;
// this is not checked.
func WithExtraPrograms(paths ...string) Option {
	return func(r *Real) { r.rawExtras = append(r.rawExtras, paths...) }
}

// NewReal returns a runner that only executes programs whose base name is in
// allow (for example "sshd", "ss"), subject to the invariant documented on
// resolve. It panics if a WithSearchDirs or WithExtraPrograms entry is not an
// absolute path.
func NewReal(allow []string, opts ...Option) *Real {
	r := &Real{allow: map[string]bool{}, rawDirs: filepath.SplitList(SearchPath)}
	for _, a := range allow {
		r.allow[a] = true
	}
	for _, o := range opts {
		o(r)
	}
	for _, d := range r.rawDirs {
		if !filepath.IsAbs(d) {
			panic("execx: WithSearchDirs needs absolute paths, got " + strconv.Quote(d))
		}
		td := trustedDir{literal: filepath.Clean(d), resolved: filepath.Clean(d)}
		if rd, err := filepath.EvalSymlinks(d); err == nil {
			td.resolved = rd
		}
		r.dirs = append(r.dirs, td)
	}
	for _, x := range r.rawExtras {
		if !filepath.IsAbs(x) {
			panic("execx: WithExtraPrograms needs absolute paths, got " + strconv.Quote(x))
		}
		e := extra{path: filepath.Clean(x)}
		if t, err := filepath.EvalSymlinks(e.path); err == nil {
			e.pinned = t
		}
		r.extras = append(r.extras, e)
	}
	r.rawDirs, r.rawExtras = nil, nil
	return r
}

// resolve turns argv[0] into the path to execute, applying the allowlist.
//
// Invariant: the executed file's symlink-resolved location lies directly in
// one of the trusted directories, or it is a WithExtraPrograms entry whose
// target still equals the pinned one. Nothing else runs, however it is named.
//
// No symlink resolution is ever applied to a directory component supplied by
// the caller; doing so would be racy (the component could be swapped between
// the check and the use). Trusted directories are resolved once, at
// construction.
//
//   - A bare name is joined onto each trusted directory in order; the only
//     symlink followed is the final component, which lives in a trusted
//     directory. The inherited PATH is ignored.
//   - An absolute argv[0] is accepted only if its cleaned directory part
//     string-equals a trusted directory (literal or resolved form), without
//     resolving it; it is then handled like a bare name in that directory.
//     Everything else, including relative paths with '/', is refused.
//   - The resolved target must be directly in a trusted directory (resolved
//     form), and either the base name of the target or the base name of the
//     name as given must be allowlisted. The second clause supports
//     multi-call binaries such as busybox (/usr/bin/ss -> /bin/busybox).
//
// Residual: trust rests on the trusted directories being root-owned and not
// writable by untrusted users, and on the extras' pinned targets and their
// ancestors being the same. Go has no fexecve, so a check-then-exec gap on the final
// component remains for anyone able to write into those directories.
func (r *Real) resolve(name string) (string, error) {
	for _, e := range r.extras {
		if name != e.path {
			continue
		}
		t, err := filepath.EvalSymlinks(e.path)
		if err != nil || t != e.pinned {
			return "", fmt.Errorf("%w: %s (no longer resolves to the pinned target)", ErrNotAllowed, name)
		}
		return t, nil
	}
	var cand string
	switch {
	case !strings.ContainsRune(name, '/'):
		var err error
		if cand, err = r.lookup(name); err != nil {
			return "", err
		}
	case !filepath.IsAbs(name):
		return "", fmt.Errorf("%w: %q is neither a bare name nor an absolute path", ErrNotAllowed, name)
	default:
		cand = filepath.Clean(name)
		if !r.isTrustedForm(filepath.Dir(cand)) {
			return "", fmt.Errorf("%w: %s is not in a trusted directory", ErrNotAllowed, name)
		}
	}
	target, err := filepath.EvalSymlinks(cand)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return "", fmt.Errorf("execx: resolve %s: %w", name, err)
	}
	if !r.isResolvedTrusted(filepath.Dir(target)) {
		return "", fmt.Errorf("%w: %s (resolves to %s, outside the trusted directories)", ErrNotAllowed, name, target)
	}
	if r.allow[filepath.Base(target)] || r.allow[filepath.Base(cand)] {
		return target, nil
	}
	return "", fmt.Errorf("%w: %s (resolves to %s)", ErrNotAllowed, name, target)
}

// lookup finds the first executable regular file called name in the trusted
// directories. Directories and non-executable files are skipped.
func (r *Real) lookup(name string) (string, error) {
	for _, d := range r.dirs {
		p := filepath.Join(d.literal, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, name)
}

// isTrustedForm compares dir as a string, with no resolution, against the
// literal and resolved forms of the trusted directories.
func (r *Real) isTrustedForm(dir string) bool {
	for _, d := range r.dirs {
		if dir == d.literal || dir == d.resolved {
			return true
		}
	}
	return false
}

// isResolvedTrusted reports whether dir, an already symlink-resolved path,
// equals the resolved form of a trusted directory.
func (r *Real) isResolvedTrusted(dir string) bool {
	for _, d := range r.dirs {
		if dir == d.resolved {
			return true
		}
	}
	return false
}

// Run implements Runner.
//
// Timeout semantics: Opts.Timeout bounds the run; hitting it returns
// ErrTimeout. If the parent ctx ends first (cancelled or its own deadline
// expired, even when shorter than Opts.Timeout), Run returns ctx.Err()
// (context.Canceled or context.DeadlineExceeded), never ErrTimeout. In both
// cases the whole process group is killed.
//
// On unix the child runs in its own process group and the group is killed
// when Run returns on any path, so background grandchildren never outlive
// the call. If the child exits while a grandchild still holds its output
// pipes, Run gives up after a short grace period and returns ErrIOTimeout
// with the output read so far (ExitCode 0, as only a successful exit is
// reported this way). If such a child exits non-zero, the Go runtime reports
// the exit status alone: Run returns it with a nil error and the output read
// so far, and cannot tell that the pipes were cut.
func (r *Real) Run(ctx context.Context, argv []string, opts Opts) (Result, error) {
	if len(argv) == 0 || argv[0] == "" {
		return Result{}, ErrEmptyArgv
	}
	path, err := r.resolve(argv[0])
	if err != nil {
		return Result{}, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	limit := opts.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	env := opts.Env
	if env == nil {
		env = DefaultEnv
	}

	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(tctx, path, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Env = env
	cmd.Dir = opts.Dir
	var stdout, stderr limitBuffer
	stdout.limit, stderr.limit = limit, limit
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	configureKill(cmd)

	start := time.Now()
	runErr := cmd.Run()
	killGroup(cmd)
	res := Result{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
		Duration:  time.Since(start),
	}
	if tctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		res.ExitCode = -1
		return res, fmt.Errorf("%w after %s: %s", ErrTimeout, timeout, argv[0])
	}
	if errors.Is(runErr, exec.ErrWaitDelay) && ctx.Err() == nil {
		return res, fmt.Errorf("%w: %s", ErrIOTimeout, argv[0])
	}
	if runErr == nil {
		return res, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) && ctx.Err() == nil {
		res.ExitCode = ee.ExitCode()
		res.Signaled = signaled(ee.ProcessState)
		return res, nil
	}
	if ctx.Err() != nil {
		res.ExitCode = -1
		return res, ctx.Err()
	}
	if errors.Is(runErr, os.ErrNotExist) {
		return res, fmt.Errorf("%w: %s", ErrNotFound, argv[0])
	}
	return res, fmt.Errorf("execx: run %s: %w", argv[0], runErr)
}

// limitBuffer keeps at most limit bytes and drops the rest while still
// accepting writes, so the child never blocks on a full pipe.
type limitBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	room := b.limit - int64(b.buf.Len())
	if int64(len(p)) > room {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}
