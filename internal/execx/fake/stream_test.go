package fake

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

func collect(f *FakeStreamer, ctx context.Context, argv []string, opts execx.StreamOpts, fail func(n int) error) ([]string, execx.StreamResult, error) {
	var got []string
	res, err := f.Stream(ctx, argv, opts, func(l []byte) error {
		got = append(got, string(l))
		if fail != nil {
			return fail(len(got))
		}
		return nil
	})
	return got, res, err
}

var follow = []string{"journalctl", "--follow"}

func TestStreamScriptedLinesAndResult(t *testing.T) {
	f := NewStreamer().Add(follow, Script{
		Lines:  []string{"a", "", "c"},
		Result: execx.StreamResult{ExitCode: 3, Stderr: []byte("warn"), IOIncomplete: true},
	})
	got, res, err := collect(f, context.Background(), follow, execx.StreamOpts{}, nil)
	if err != nil || strings.Join(got, "|") != "a||c" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if res.ExitCode != 3 || string(res.Stderr) != "warn" || !res.IOIncomplete || res.DroppedLines != 0 {
		t.Fatalf("res=%+v", res)
	}
}

func TestStreamMidStreamError(t *testing.T) {
	boom := errors.New("read failed")
	f := NewStreamer().Add(follow, Script{Lines: []string{"a", "b"}, Err: boom, Follow: true})
	got, res, err := collect(f, context.Background(), follow, execx.StreamOpts{}, nil)
	if !errors.Is(err, boom) || strings.Join(got, "|") != "a|b" || res.ExitCode != -1 {
		t.Fatalf("got=%q res=%+v err=%v", got, res, err)
	}
}

func TestStreamFollowBlocksUntilCancel(t *testing.T) {
	f := NewStreamer().Add(follow, Script{Lines: []string{"a"}, Follow: true})
	ctx, cancel := context.WithCancel(context.Background())
	type out struct {
		got []string
		err error
	}
	ch := make(chan out, 1)
	first := make(chan struct{})
	go func() {
		var got []string
		_, err := f.Stream(ctx, follow, execx.StreamOpts{}, func(l []byte) error {
			got = append(got, string(l))
			close(first)
			return nil
		})
		ch <- out{got, err}
	}()
	<-first
	select {
	case <-ch:
		t.Fatal("returned before cancel")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case o := <-ch:
		if !errors.Is(o.err, context.Canceled) || len(o.got) != 1 {
			t.Fatalf("got=%q err=%v", o.got, o.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return after cancel")
	}
}

func TestStreamCancelledBeforeDelivery(t *testing.T) {
	f := NewStreamer().Add(follow, Script{Lines: []string{"a"}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _, err := collect(f, ctx, follow, execx.StreamOpts{}, nil)
	if !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestStreamCallbackErrorStops(t *testing.T) {
	stop := errors.New("stop")
	f := NewStreamer().Add(follow, Script{Lines: []string{"a", "b", "c"}})
	got, _, err := collect(f, context.Background(), follow, execx.StreamOpts{}, func(n int) error {
		if n == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || strings.Join(got, "|") != "a|b" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestStreamLongLinesDropped(t *testing.T) {
	long := strings.Repeat("x", 11)
	f := NewStreamer().Add(follow, Script{Lines: []string{"0123456789", long, "ok", long}})
	got, res, err := collect(f, context.Background(), follow, execx.StreamOpts{MaxLine: 10}, nil)
	if err != nil || strings.Join(got, "|") != "0123456789|ok" || res.DroppedLines != 2 {
		t.Fatalf("got=%q res=%+v err=%v", got, res, err)
	}
	// Default: DefaultMaxLine passes, one more is dropped.
	f = NewStreamer().Add(follow, Script{Lines: []string{strings.Repeat("y", execx.DefaultMaxLine), strings.Repeat("y", execx.DefaultMaxLine+1)}})
	got, res, err = collect(f, context.Background(), follow, execx.StreamOpts{}, nil)
	if err != nil || len(got) != 1 || res.DroppedLines != 1 {
		t.Fatalf("default: n=%d res=%+v err=%v", len(got), res, err)
	}
}

func TestStreamUnknownArgvEmptyAndInjected(t *testing.T) {
	f := NewStreamer().Add(follow, Script{}).AddError([]string{"x"}, execx.ErrNotAllowed)
	if _, _, err := collect(f, context.Background(), []string{"journalctl"}, execx.StreamOpts{}, nil); !errors.Is(err, execx.ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	for _, argv := range [][]string{nil, {""}} {
		if _, _, err := collect(f, context.Background(), argv, execx.StreamOpts{}, nil); !errors.Is(err, execx.ErrEmptyArgv) {
			t.Errorf("%q: %v", argv, err)
		}
	}
	if _, _, err := collect(f, context.Background(), []string{"x"}, execx.StreamOpts{}, nil); !errors.Is(err, execx.ErrNotAllowed) {
		t.Errorf("injected: %v", err)
	}
}

func TestStreamAddReplacesAddError(t *testing.T) {
	f := NewStreamer().AddError(follow, execx.ErrNotAllowed).Add(follow, Script{Lines: []string{"a"}})
	if got, _, err := collect(f, context.Background(), follow, execx.StreamOpts{}, nil); err != nil || len(got) != 1 {
		t.Fatalf("got=%q err=%v", got, err)
	}
	f.AddError(follow, execx.ErrNotAllowed)
	if _, _, err := collect(f, context.Background(), follow, execx.StreamOpts{}, nil); !errors.Is(err, execx.ErrNotAllowed) {
		t.Fatalf("err=%v", err)
	}
}

func TestStreamRecordsCalls(t *testing.T) {
	f := NewStreamer().Add(follow, Script{})
	o := execx.StreamOpts{MaxLine: 7, Dir: "/x"}
	_, _, _ = collect(f, context.Background(), follow, o, nil)
	_, _, _ = collect(f, context.Background(), []string{"nope"}, execx.StreamOpts{}, nil)
	c := f.Calls()
	if len(c) != 2 || c[0].Argv[1] != "--follow" || c[0].Opts.MaxLine != 7 || c[0].Opts.Dir != "/x" || c[1].Argv[0] != "nope" {
		t.Fatalf("calls = %+v", c)
	}
	c[0].Argv[0] = "changed"
	if f.Calls()[0].Argv[0] != "journalctl" {
		t.Error("Calls returned shared state")
	}
}

func TestStreamLineIsACopy(t *testing.T) {
	f := NewStreamer().Add(follow, Script{Lines: []string{"abc", "abc"}})
	var keep [][]byte
	_, err := f.Stream(context.Background(), follow, execx.StreamOpts{}, func(l []byte) error {
		keep = append(keep, l)
		if len(keep) == 1 {
			l[0] = 'Z'
		}
		return nil
	})
	if err != nil || string(keep[1]) != "abc" {
		t.Fatalf("keep=%q err=%v", keep, err)
	}
}
