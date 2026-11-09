package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/version"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUnknownCommandExits2(t *testing.T) {
	code, _, stderr := run("frobnicate")
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestNoArgsExits2(t *testing.T) {
	if code, _, _ := run(); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestBadFlagExits2(t *testing.T) {
	for _, args := range [][]string{{"check", "--nope"}, {"version", "--nope"}, {"config", "check", "--nope"}, {"check", "extra"}} {
		if code, _, stderr := run(args...); code != 2 || stderr == "" {
			t.Errorf("%v: exit = %d stderr = %q, want 2 with message", args, code, stderr)
		}
	}
}

func TestStubsExit3(t *testing.T) {
	for _, args := range [][]string{{"check"}, {"report"}, {"doctor"}, {"install"}, {"uninstall"}} {
		code, _, stderr := run(args...)
		if code != 3 || !strings.Contains(stderr, "not implemented") {
			t.Errorf("%v: exit = %d stderr = %q", args, code, stderr)
		}
	}
}

func TestConfigSubcommandErrors(t *testing.T) {
	for _, args := range [][]string{{"config"}, {"config", "bogus"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, code)
		}
	}
}

func TestVersionOutput(t *testing.T) {
	oldV, oldC, oldD := version.Version, version.Commit, version.Date
	t.Cleanup(func() { version.Version, version.Commit, version.Date = oldV, oldC, oldD })
	version.Version, version.Commit, version.Date = "1.2.3", "abc1234", "2030-01-02"
	code, stdout, _ := run("version")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"1.2.3", "abc1234", "2030-01-02"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %q lacks %q", stdout, want)
		}
	}
}

func TestVersionDefaults(t *testing.T) {
	if version.Version != "dev" || version.Commit != "unknown" || version.Date != "unknown" {
		t.Skip("overridden by ldflags")
	}
	_, stdout, _ := run("version")
	if !strings.Contains(stdout, "dev") || strings.Count(stdout, "unknown") != 2 {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestHelpListsCommands(t *testing.T) {
	for _, h := range []string{"help", "-h", "--help"} {
		code, stdout, _ := run(h)
		if code != 0 {
			t.Fatalf("%s: exit = %d", h, code)
		}
		for _, c := range commands {
			if !strings.Contains(stdout, c.name) {
				t.Errorf("%s: help lacks %q", h, c.name)
			}
		}
	}
}

func TestHelpFlagOnSubcommandIsQuiet(t *testing.T) {
	for _, args := range [][]string{{"check", "-h"}, {"config", "check", "-h"}, {"version", "-h"}} {
		code, stdout, stderr := run(args...)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage: keepwatch") {
			t.Errorf("%v: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}
