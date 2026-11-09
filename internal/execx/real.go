package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	allow map[string]bool
	dirs  []string
	extra []string
}

// Option configures a Real runner.
type Option func(*Real)

// WithSearchDirs replaces the directory list used to resolve bare names and
// to decide which directories are trusted (see resolve). Intended for tests.
func WithSearchDirs(dirs ...string) Option {
	return func(r *Real) { r.dirs = dirs }
}

// WithExtraPrograms permits specific programs outside the trusted search
// directories, given as absolute paths. This is the only way to run an
// off-path binary; argv[0] alone never grants it. A program is matched by
// its symlink-resolved path, and callers pass argv[0] as that absolute path.
// Entries that are not absolute never match, because argv[0] must be absolute.
func WithExtraPrograms(paths ...string) Option {
	return func(r *Real) {
		for _, p := range paths {
			r.extra = append(r.extra, filepath.Clean(p))
		}
	}
}

// NewReal returns a runner that only executes programs whose base name is in
// allow (for example "sshd", "ss"), subject to the trusted-directory
// invariant documented on resolve.
func NewReal(allow []string, opts ...Option) *Real {
	r := &Real{allow: map[string]bool{}, dirs: filepath.SplitList(SearchPath)}
	for _, a := range allow {
		r.allow[a] = true
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// resolve turns argv[0] into the path to execute, applying the allowlist.
//
// Invariant: the program that is executed is a file whose symlink-resolved
// location lies directly in one of the trusted search directories (compared
// by exact directory equality after EvalSymlinks of those directories), or
// is one of the explicit WithExtraPrograms paths. Nothing else runs, however
// it is named.
//
//   - A bare name is looked up only in the trusted directories; the inherited
//     PATH is ignored.
//   - An absolute path is accepted only if its own directory, after
//     EvalSymlinks, is a trusted directory. Relative paths containing '/'
//     are refused.
//   - The resolved target must then also be in a trusted directory, and be
//     allowed: the base name of the target is allowlisted, OR the base name
//     of the name as given is allowlisted. The second clause supports
//     multi-call binaries such as busybox, where /usr/bin/ss is a symlink to
//     /bin/busybox. Because the target must be in a trusted directory, a
//     planted link such as /tmp/ss -> /bin/sh is refused.
func (r *Real) resolve(name string) (string, error) {
	var path string
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("%w: %q is neither a bare name nor an absolute path", ErrNotAllowed, name)
		}
		path = filepath.Clean(name)
	} else {
		var err error
		if path, err = r.lookup(name); err != nil {
			return "", err
		}
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return "", fmt.Errorf("execx: resolve %s: %w", name, err)
	}
	for _, x := range r.extra {
		if ex, err := filepath.EvalSymlinks(x); err == nil && ex == target && filepath.Clean(name) == x {
			return target, nil
		}
	}
	if !r.trusted(filepath.Dir(path)) || !r.trusted(filepath.Dir(target)) {
		return "", fmt.Errorf("%w: %s (resolves to %s, outside the trusted directories)", ErrNotAllowed, name, target)
	}
	if r.allow[filepath.Base(target)] || r.allow[filepath.Base(name)] {
		return target, nil
	}
	return "", fmt.Errorf("%w: %s (resolves to %s)", ErrNotAllowed, name, target)
}

func (r *Real) lookup(name string) (string, error) {
	for _, d := range r.dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNotFound, name)
}

// trusted reports whether dir, after EvalSymlinks, equals a trusted directory.
func (r *Real) trusted(dir string) bool {
	if rd, err := filepath.EvalSymlinks(dir); err == nil {
		dir = rd
	}
	for _, d := range r.dirs {
		if rd, err := filepath.EvalSymlinks(d); err == nil && rd == dir {
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
// with the output read so far.
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
		if cmd.ProcessState != nil {
			res.ExitCode = cmd.ProcessState.ExitCode()
			res.Signaled = signaled(cmd.ProcessState)
		}
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
