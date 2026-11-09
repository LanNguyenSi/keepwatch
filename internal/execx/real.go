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
}

// Option configures a Real runner.
type Option func(*Real)

// WithSearchDirs replaces the directory list used to resolve bare names and
// to decide which directories are trusted (see Run). Intended for tests.
func WithSearchDirs(dirs ...string) Option {
	return func(r *Real) { r.dirs = dirs }
}

// NewReal returns a runner that only executes programs whose base name is in
// allow (for example "sshd", "ss").
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
// Rule: a bare name is looked up in the fixed search directories only. The
// path is then passed through filepath.EvalSymlinks. The program is allowed
// when the base name of the resolved target is in the allowlist, OR when the
// base name of the name as given is in the allowlist AND the target lives in
// one of the trusted search directories. The second clause supports
// multi-call binaries such as busybox, where /usr/bin/ss is a symlink to
// /bin/busybox: the name says what is being asked for, the target is a
// system binary. A symlink named like an allowed program that points outside
// the trusted directories (for example into /tmp) is refused, so a planted
// link cannot smuggle in an arbitrary program.
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
	if r.allow[filepath.Base(target)] {
		return target, nil
	}
	if r.allow[filepath.Base(name)] && r.trusted(target) {
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

func (r *Real) trusted(target string) bool {
	dir := filepath.Dir(target)
	for _, d := range r.dirs {
		if rd, err := filepath.EvalSymlinks(d); err == nil && rd == dir {
			return true
		}
	}
	return false
}

// Run implements Runner.
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
	if runErr == nil {
		return res, nil
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) && ctx.Err() == nil {
		res.ExitCode = ee.ExitCode()
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
