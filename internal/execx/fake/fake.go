// Package fake provides a Runner for tests that replays fixture files
// instead of executing programs.
package fake

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"sync"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

// Call records one invocation.
type Call struct {
	Argv []string
	Opts execx.Opts
}

// FakeRunner maps joined argv to fixture results. Fixtures for name N live in
// the file system as N.stdout, N.stderr and N.exit (all optional; a missing
// file means empty output / exit 0, but at least one must exist).
type FakeRunner struct {
	fsys fs.FS

	mu      sync.Mutex
	entries map[string]entry
	calls   []Call
}

type entry struct {
	name string
	res  *execx.Result // set for inline results
	err  error         // set for injected errors
}

var _ execx.Runner = (*FakeRunner)(nil)

// New returns a FakeRunner reading fixtures from fsys.
func New(fsys fs.FS) *FakeRunner {
	return &FakeRunner{fsys: fsys, entries: map[string]entry{}}
}

// key joins argv with NUL so ["a b"] and ["a","b"] stay distinct.
func key(argv []string) string { return strings.Join(argv, "\x00") }

func display(argv []string) string { return strings.Join(argv, " ") }

// Add maps argv to the fixture files named name in the runner's file system.
func (f *FakeRunner) Add(argv []string, name string) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key(argv)] = entry{name: name}
	return f
}

// AddResult maps argv to an inline result.
func (f *FakeRunner) AddResult(argv []string, res execx.Result) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key(argv)] = entry{res: &res}
	return f
}

// AddError makes argv fail with err (for example execx.ErrTimeout).
func (f *FakeRunner) AddError(argv []string, err error) *FakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[key(argv)] = entry{err: err}
	return f
}

// Calls returns a copy of the recorded calls in order.
func (f *FakeRunner) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Run implements execx.Runner.
func (f *FakeRunner) Run(_ context.Context, argv []string, opts execx.Opts) (execx.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, Call{Argv: append([]string(nil), argv...), Opts: opts})
	e, ok := f.entries[key(argv)]
	f.mu.Unlock()
	if len(argv) == 0 || argv[0] == "" {
		return execx.Result{}, execx.ErrEmptyArgv
	}
	if !ok {
		return execx.Result{}, fmt.Errorf("%w: no fixture for %q", execx.ErrNotFound, display(argv))
	}
	if e.err != nil {
		return execx.Result{}, e.err
	}
	if e.res != nil {
		return *e.res, nil
	}
	return f.load(e.name)
}

func (f *FakeRunner) load(name string) (execx.Result, error) {
	var res execx.Result
	found := false
	read := func(ext string) ([]byte, bool, error) {
		b, err := fs.ReadFile(f.fsys, name+ext)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, false, nil
			}
			return nil, false, err
		}
		return b, true, nil
	}
	for _, p := range []struct {
		ext string
		set func([]byte) error
	}{
		{".stdout", func(b []byte) error { res.Stdout = b; return nil }},
		{".stderr", func(b []byte) error { res.Stderr = b; return nil }},
		{".exit", func(b []byte) error {
			n, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				return fmt.Errorf("fake: bad exit fixture %s.exit: %w", name, err)
			}
			res.ExitCode = n
			return nil
		}},
	} {
		b, ok, err := read(p.ext)
		if err != nil {
			return execx.Result{}, err
		}
		if ok {
			found = true
			if err := p.set(b); err != nil {
				return execx.Result{}, err
			}
		}
	}
	if !found {
		return execx.Result{}, fmt.Errorf("fake: no fixture files for %q", name)
	}
	return res, nil
}
