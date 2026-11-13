package fake

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

// Script is what a FakeStreamer replays for one argv.
type Script struct {
	// Lines are delivered in order, each as its own copy, without a newline.
	// A line longer than the call's MaxLine (execx.DefaultMaxLine when
	// zero) is dropped and counted, as the real streamer does.
	Lines []string
	// Err, when set, ends the stream after Lines with this error, like a
	// failure in the middle of a stream. Result is returned with it.
	Err error
	// Follow makes the stream block after Lines until ctx ends, then return
	// ctx.Err(), like a follow stream that never exits by itself. Err wins
	// over Follow.
	Follow bool
	// Result supplies ExitCode, Signaled, Stderr and IOIncomplete for a
	// stream that ends by itself. DroppedLines is computed from Lines.
	Result execx.StreamResult
}

// StreamCall records one invocation.
type StreamCall struct {
	Argv []string
	Opts execx.StreamOpts
}

// FakeStreamer replays scripted streams instead of running programs. Like
// FakeRunner it matches on the joined argv and records every call.
type FakeStreamer struct {
	mu      sync.Mutex
	scripts map[string]Script
	errs    map[string]error
	calls   []StreamCall
}

var _ execx.Streamer = (*FakeStreamer)(nil)

// NewStreamer returns an empty FakeStreamer.
func NewStreamer() *FakeStreamer {
	return &FakeStreamer{scripts: map[string]Script{}, errs: map[string]error{}}
}

// Add maps argv to a script.
func (f *FakeStreamer) Add(argv []string, s Script) *FakeStreamer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts[key(argv)] = s
	delete(f.errs, key(argv))
	return f
}

// AddError makes argv fail before anything is delivered (for example
// execx.ErrNotAllowed or execx.ErrNotFound).
func (f *FakeStreamer) AddError(argv []string, err error) *FakeStreamer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[key(argv)] = err
	delete(f.scripts, key(argv))
	return f
}

// Calls returns a copy of the recorded calls in order.
func (f *FakeStreamer) Calls() []StreamCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]StreamCall, len(f.calls))
	for i, c := range f.calls {
		out[i] = StreamCall{Argv: append([]string(nil), c.Argv...), Opts: c.Opts}
	}
	return out
}

// Stream implements execx.Streamer. It honours ctx between lines and returns
// the error onLine returns, as the real streamer does.
func (f *FakeStreamer) Stream(ctx context.Context, argv []string, opts execx.StreamOpts, onLine func([]byte) error) (execx.StreamResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, StreamCall{Argv: append([]string(nil), argv...), Opts: opts})
	s, ok := f.scripts[key(argv)]
	injected := f.errs[key(argv)]
	f.mu.Unlock()
	if len(argv) == 0 || argv[0] == "" {
		return execx.StreamResult{}, execx.ErrEmptyArgv
	}
	if injected != nil {
		return execx.StreamResult{}, injected
	}
	if !ok {
		return execx.StreamResult{}, fmt.Errorf("%w: no stream script for %q", execx.ErrNotFound, strings.Join(argv, " "))
	}
	max := opts.MaxLine
	if max <= 0 {
		max = execx.DefaultMaxLine
	}
	res := s.Result
	res.DroppedLines = 0
	for _, l := range s.Lines {
		if err := ctx.Err(); err != nil {
			res.ExitCode = -1
			return res, err
		}
		if len(l) > max {
			res.DroppedLines++
			continue
		}
		if onLine != nil {
			if err := onLine([]byte(l)); err != nil {
				res.ExitCode = -1
				return res, err
			}
		}
	}
	switch {
	case s.Err != nil:
		res.ExitCode = -1
		return res, s.Err
	case s.Follow:
		<-ctx.Done()
		res.ExitCode = -1
		return res, ctx.Err()
	}
	return res, nil
}
