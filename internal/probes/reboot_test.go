package probes_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var needrestartArgv = []string{"needrestart", "-b", "-k", "-r", "l"}

const (
	rebootFile = "/var/run/reboot-required"
	pkgsFile   = rebootFile + ".pkgs"
)

func rebootProbe(t *testing.T) probes.Probe { return prepare(t, "reboot_required", nil) }

// needrestartOut builds batch output like the real tool prints it.
func needrestartOut(ksta string) string {
	return "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-45-generic\n" +
		"NEEDRESTART-KEXP: 6.8.0-48-generic\nNEEDRESTART-KSTA: " + ksta + "\nNEEDRESTART-UCSTA: 1\nNEEDRESTART-UCCUR: \n"
}

func TestRebootRequiredNeedrestartFixtures(t *testing.T) {
	for _, v := range versions {
		t.Run(v+"/kernel status unknown", func(t *testing.T) {
			o := exec(rebootProbe(t), newRunner().Add(needrestartArgv, v+"/needrestart_kernel"), nil)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "unknown to needrestart")
		})
		t.Run(v+"/inside a container", func(t *testing.T) {
			o := exec(rebootProbe(t), newRunner().Add(needrestartArgv, v+"/needrestart_kernel_in_container"), nil)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "not reported")
		})
	}
}

func TestRebootRequiredFile(t *testing.T) {
	current := newRunner().AddResult(needrestartArgv, inline(needrestartOut("1"), 0))
	t.Run("absent", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.MemFS{})
		wantStatus(t, o, result.Pass)
	})
	t.Run("present without package list", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.MemFS{rebootFile: "*** System restart required ***\n"})
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 1 || o.Evidence[0].Subject != "reboot-required" || strings.Contains(o.Evidence[0].Detail, "packages") {
			t.Fatalf("evidence = %+v", o.Evidence)
		}
	})
	t.Run("present with package list", func(t *testing.T) {
		fsys := probestest.MemFS{rebootFile: "*** System restart required ***\n", pkgsFile: "linux-image-6.8.0-48-generic\nlibc6\n\n"}
		o := exec(rebootProbe(t), current, fsys)
		wantStatus(t, o, result.Fail)
		if got := o.Evidence[0].Detail; !strings.Contains(got, "packages: linux-image-6.8.0-48-generic, libc6") {
			t.Fatalf("detail = %q", got)
		}
	})
	t.Run("package list is capped by count and shown escaped", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 30; i++ {
			b.WriteString("pkg" + strings.Repeat("x", i%3) + "\n")
		}
		b.WriteString("bad name\x1b[0m\n")
		fsys := probestest.MemFS{rebootFile: "x", pkgsFile: b.String()}
		o := exec(rebootProbe(t), current, fsys)
		wantStatus(t, o, result.Fail)
		if d := shown(o.Evidence[0].Detail); !strings.HasSuffix(d, ", ...") || strings.ContainsRune(d, 0x1b) {
			t.Fatalf("detail = %q", d)
		}
		fsys[pkgsFile] = "bad name\x1b[0m\n"
		o = exec(rebootProbe(t), current, fsys)
		if d := shown(o.Evidence[0].Detail); strings.ContainsRune(d, 0x1b) || !strings.Contains(d, `bad name\x1b[0m`) {
			t.Fatalf("detail = %q", d)
		}
	})
	t.Run("empty package list", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.MemFS{rebootFile: "x", pkgsFile: "\n"})
		wantStatus(t, o, result.Fail)
		if !strings.Contains(o.Evidence[0].Detail, "none listed") {
			t.Fatalf("detail = %q", o.Evidence[0].Detail)
		}
	})
	t.Run("oversized marker file still counts as present", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.MemFS{rebootFile: strings.Repeat("x", 70<<10)})
		wantStatus(t, o, result.Fail)
	})
	t.Run("oversized package list is an error", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.MemFS{rebootFile: "x", pkgsFile: strings.Repeat("x", 70<<10)})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "too large")
	})
	t.Run("unreadable marker file is an error, not a pass", func(t *testing.T) {
		o := exec(rebootProbe(t), current, probestest.ErrFS{Err: fs.ErrPermission})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, rebootFile)
	})
	t.Run("unreadable package list is an error", func(t *testing.T) {
		fsys := &pkgsErrFS{MemFS: probestest.MemFS{rebootFile: "x"}}
		o := exec(rebootProbe(t), current, fsys)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, pkgsFile)
	})
	t.Run("size cap passed to the file system", func(t *testing.T) {
		rec := &recordingFS{}
		exec(rebootProbe(t), current, rec)
		if len(rec.caps) == 0 || rec.caps[0] <= 0 || rec.caps[0] > 1<<20 {
			t.Fatalf("caps = %v", rec.caps)
		}
	})
}

type pkgsErrFS struct{ probestest.MemFS }

func (f *pkgsErrFS) ReadFile(path string, max int64) ([]byte, error) {
	if path == pkgsFile {
		return nil, fs.ErrPermission
	}
	return f.MemFS.ReadFile(path, max)
}

type recordingFS struct{ caps []int64 }

func (r *recordingFS) ReadFile(path string, max int64) ([]byte, error) {
	r.caps = append(r.caps, max)
	return nil, fs.ErrNotExist
}

func TestRebootRequiredNeedrestart(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		exit   int
		want   result.Status
		sub    string
	}{
		{"kernel current", needrestartOut("1"), 0, result.Pass, "no reboot is required"},
		{"kernel status unknown", needrestartOut("0"), 0, result.Pass, "unknown"},
		{"abi compatible upgrade pending", needrestartOut("2"), 0, result.Fail, "1 reason"},
		{"version upgrade pending", needrestartOut("3"), 0, result.Fail, "1 reason"},
		{"no kernel status line", "NEEDRESTART-VER: 3.6\n", 0, result.Pass, "not reported"},
		{"ksta out of range", needrestartOut("4"), 0, result.Error, "KSTA"},
		{"ksta negative", needrestartOut("-1"), 0, result.Error, "KSTA"},
		{"ksta not a number", needrestartOut("current"), 0, result.Error, "KSTA"},
		{"ksta empty", needrestartOut(""), 0, result.Error, "KSTA"},
		{"ksta with a plus sign", needrestartOut("+1"), 0, result.Error, "KSTA"},
		{"ksta with a plus sign, upgrade pending", needrestartOut("+3"), 0, result.Error, "KSTA"},
		{"ksta with a leading zero", needrestartOut("01"), 0, result.Error, "KSTA"},
		{"ksta with two digits", needrestartOut("10"), 0, result.Error, "KSTA"},
		{"ksta with two values", needrestartOut("1 3"), 0, result.Error, "KSTA"},
		{"ksta in hex", needrestartOut("0x1"), 0, result.Error, "KSTA"},
		{"version line twice", "NEEDRESTART-VER: 3.6\nNEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 1\n", 0, result.Error, "NEEDRESTART-VER more than once"},
		{"ksta twice, same value", needrestartOut("1") + "NEEDRESTART-KSTA: 1\n", 0, result.Error, "NEEDRESTART-KSTA more than once"},
		{"ksta twice, current then upgrade", needrestartOut("1") + "NEEDRESTART-KSTA: 3\n", 0, result.Error, "more than once"},
		{"ksta twice, upgrade then current", needrestartOut("3") + "NEEDRESTART-KSTA: 1\n", 0, result.Error, "more than once"},
		{"kernel version twice", needrestartOut("3") + "NEEDRESTART-KCUR: 1.0\n", 0, result.Error, "NEEDRESTART-KCUR more than once"},
		{"other keys may repeat if they are not NEEDRESTART", needrestartOut("1") + "X-OTHER: 1\nX-OTHER: 2\n", 0, result.Pass, "no reboot"},
		{"no version line", "NEEDRESTART-KSTA: 1\n", 0, result.Error, "NEEDRESTART-VER"},
		{"empty output", "", 0, result.Error, "NEEDRESTART-VER"},
		{"garbage", "<html>502</html>\n", 0, result.Error, "NEEDRESTART-VER"},
		{"exit 1 with a good looking output", needrestartOut("1"), 1, result.Error, "status 1"},
		{"exit 255", needrestartOut("1"), 255, result.Error, "status 255"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(needrestartArgv, inline(c.stdout, c.exit))
			o := exec(rebootProbe(t), r, probestest.MemFS{})
			wantStatus(t, o, c.want)
			wantSummary(t, o, c.sub)
			if c.want == result.Fail {
				e := o.Evidence[0]
				if e.Subject != "kernel" || !strings.Contains(e.Detail, "running 6.8.0-45-generic") || !strings.Contains(e.Detail, "expected 6.8.0-48-generic") {
					t.Fatalf("evidence = %+v", e)
				}
			}
		})
	}
	t.Run("version upgrade is named", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("3"), 0))
		o := exec(rebootProbe(t), r, probestest.MemFS{})
		if !strings.Contains(o.Evidence[0].Detail, "version upgrade") {
			t.Fatalf("detail = %q", o.Evidence[0].Detail)
		}
	})
}

func TestRebootRequiredCombinations(t *testing.T) {
	marker := probestest.MemFS{rebootFile: "x"}
	t.Run("file and kernel both fail", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("3"), 0))
		o := exec(rebootProbe(t), r, marker)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"reboot-required", "kernel"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
	t.Run("needrestart missing, no file: pass with a note", func(t *testing.T) {
		r := newRunner().AddError(needrestartArgv, execx.ErrNotFound)
		o := exec(rebootProbe(t), r, probestest.MemFS{})
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "needrestart not installed")
	})
	t.Run("needrestart missing, file present: still fail", func(t *testing.T) {
		r := newRunner().AddError(needrestartArgv, execx.ErrNotFound)
		o := exec(rebootProbe(t), r, marker)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"reboot-required"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
	t.Run("needrestart broken beats the marker file, which stays as evidence", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline("", 2))
		o := exec(rebootProbe(t), r, marker)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "needrestart exited with status 2")
		wantSummary(t, o, "partial, also found: reboot-required")
		if len(o.Evidence) != 1 || o.Evidence[0].Subject != "reboot-required" {
			t.Fatalf("evidence = %+v", o.Evidence)
		}
	})
	t.Run("needrestart broken, no marker: an error without evidence", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline("", 2))
		o := exec(rebootProbe(t), r, probestest.MemFS{})
		wantStatus(t, o, result.Error)
		if len(o.Evidence) != 0 || strings.Contains(o.Summary, "partial") {
			t.Fatalf("outcome = %+v", o)
		}
	})
	t.Run("every needrestart failure keeps the marker", func(t *testing.T) {
		failures := map[string]*fake.FakeRunner{
			"timeout":           newRunner().AddError(needrestartArgv, execx.ErrTimeout),
			"io timeout":        newRunner().AddError(needrestartArgv, execx.ErrIOTimeout),
			"not allowlisted":   newRunner().AddError(needrestartArgv, execx.ErrNotAllowed),
			"pipes cut":         newRunner().AddResult(needrestartArgv, execx.Result{Stdout: []byte(needrestartOut("1")), IOIncomplete: true}),
			"pipes cut, exit 1": newRunner().AddResult(needrestartArgv, execx.Result{Stdout: []byte(needrestartOut("1")), ExitCode: 1, IOIncomplete: true}),
			"truncated":         newRunner().AddResult(needrestartArgv, execx.Result{Stdout: []byte(needrestartOut("1")), Truncated: true}),
			"killed":            newRunner().AddResult(needrestartArgv, execx.Result{ExitCode: -1, Signaled: true}),
			"exit 255":          newRunner().AddResult(needrestartArgv, inline(needrestartOut("1"), 255)),
			"garbage":           newRunner().AddResult(needrestartArgv, inline("<html>502</html>\n", 0)),
			"duplicate key":     newRunner().AddResult(needrestartArgv, inline(needrestartOut("1")+"NEEDRESTART-KSTA: 3\n", 0)),
			"bad ksta":          newRunner().AddResult(needrestartArgv, inline(needrestartOut("+1"), 0)),
		}
		for name, r := range failures {
			t.Run(name, func(t *testing.T) {
				o := exec(rebootProbe(t), r, marker)
				wantStatus(t, o, result.Error)
				wantSummary(t, o, "partial, also found: reboot-required")
				if !eq(subjects(o), []string{"reboot-required"}) {
					t.Fatalf("subjects = %v", subjects(o))
				}
			})
		}
	})
	t.Run("marker unreadable, kernel upgrade pending: the kernel stays as evidence", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("3"), 0))
		o := exec(rebootProbe(t), r, probestest.ErrFS{Err: fs.ErrPermission})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, rebootFile)
		wantSummary(t, o, "partial, also found: kernel")
		if !eq(subjects(o), []string{"kernel"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
	t.Run("marker found, package list unreadable: the marker stays as evidence", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("1"), 0))
		o := exec(rebootProbe(t), r, &pkgsErrFS{MemFS: probestest.MemFS{rebootFile: "x"}})
		wantStatus(t, o, result.Error)
		wantSummary(t, o, pkgsFile)
		if !eq(subjects(o), []string{"reboot-required"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
	t.Run("both sources fail after the marker was found: marker and kernel are kept", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("3"), 0))
		o := exec(rebootProbe(t), r, &pkgsErrFS{MemFS: probestest.MemFS{rebootFile: "x"}})
		wantStatus(t, o, result.Error)
		if !eq(subjects(o), []string{"reboot-required", "kernel"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
	t.Run("needrestart timeout", func(t *testing.T) {
		r := newRunner().AddError(needrestartArgv, execx.ErrTimeout)
		wantStatus(t, exec(rebootProbe(t), r, probestest.MemFS{}), result.Error)
	})
	t.Run("needrestart not allowlisted", func(t *testing.T) {
		r := newRunner().AddError(needrestartArgv, execx.ErrNotAllowed)
		wantStatus(t, exec(rebootProbe(t), r, probestest.MemFS{}), result.Error)
	})
	t.Run("needrestart output truncated", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, execx.Result{Stdout: []byte(needrestartOut("1")), Truncated: true})
		wantStatus(t, exec(rebootProbe(t), r, probestest.MemFS{}), result.Error)
	})
	t.Run("needrestart killed", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, execx.Result{ExitCode: -1, Signaled: true})
		wantStatus(t, exec(rebootProbe(t), r, probestest.MemFS{}), result.Error)
	})
	t.Run("needrestart is told to list only", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline(needrestartOut("1"), 0))
		exec(rebootProbe(t), r, probestest.MemFS{})
		calls := r.Calls()
		if len(calls) != 1 || strings.Join(calls[0].Argv, " ") != "needrestart -b -k -r l" {
			t.Fatalf("calls = %+v", calls)
		}
	})
}

func TestRebootRequiredParams(t *testing.T) {
	prepare(t, "reboot_required", map[string]any{})
	prepareErr(t, "reboot_required", map[string]any{"file": "/tmp/x"})
}
