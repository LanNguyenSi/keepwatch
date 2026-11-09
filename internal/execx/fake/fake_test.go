package fake

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

func TestFixtures(t *testing.T) {
	f := New(os.DirFS("testdata")).
		Add([]string{"sshd", "-T"}, "sshd_T").
		Add([]string{"false"}, "failing")

	res, err := f.Run(context.Background(), []string{"sshd", "-T"}, execx.Opts{})
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "Port 22\npasswordauthentication no\n" || string(res.Stderr) != "warning\n" {
		t.Fatalf("sshd -T: %+v %v", res, err)
	}
	res, err = f.Run(context.Background(), []string{"false"}, execx.Opts{})
	if err != nil || res.ExitCode != 1 || string(res.Stderr) != "boom\n" {
		t.Fatalf("false: %+v %v", res, err)
	}
}

func TestUnknownArgvIsNotFound(t *testing.T) {
	f := New(os.DirFS("testdata")).Add([]string{"sshd", "-T"}, "sshd_T")
	_, err := f.Run(context.Background(), []string{"sshd", "-t"}, execx.Opts{})
	if !errors.Is(err, execx.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestMissingFixtureFilesIsError(t *testing.T) {
	f := New(os.DirFS("testdata")).Add([]string{"x"}, "nonexistent")
	if _, err := f.Run(context.Background(), []string{"x"}, execx.Opts{}); err == nil {
		t.Fatal("want error")
	}
}

func TestInlineResultAndCalls(t *testing.T) {
	f := New(os.DirFS("testdata")).AddResult([]string{"ss", "-H"}, execx.Result{Stdout: []byte("ok")})
	o := execx.Opts{Dir: "/x"}
	res, err := f.Run(context.Background(), []string{"ss", "-H"}, o)
	if err != nil || string(res.Stdout) != "ok" {
		t.Fatalf("%+v %v", res, err)
	}
	_, _ = f.Run(context.Background(), []string{"nope"}, execx.Opts{})
	calls := f.Calls()
	if len(calls) != 2 || calls[0].Argv[0] != "ss" || calls[0].Opts.Dir != "/x" || calls[1].Argv[0] != "nope" {
		t.Fatalf("calls = %+v", calls)
	}
}
