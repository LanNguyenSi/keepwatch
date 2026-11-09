package probes_test

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
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
	t.Run("package list is cut and sanitised", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 30; i++ {
			b.WriteString("pkg" + strings.Repeat("x", i%3) + "\n")
		}
		b.WriteString("bad name\x1b[0m\n")
		fsys := probestest.MemFS{rebootFile: "x", pkgsFile: b.String()}
		o := exec(rebootProbe(t), current, fsys)
		wantStatus(t, o, result.Fail)
		if d := o.Evidence[0].Detail; !strings.HasSuffix(d, ", ...") || strings.ContainsRune(d, 0x1b) {
			t.Fatalf("detail = %q", d)
		}
		fsys[pkgsFile] = "bad name\x1b[0m\n"
		o = exec(rebootProbe(t), current, fsys)
		if d := o.Evidence[0].Detail; strings.ContainsRune(d, 0x1b) || !strings.Contains(d, "bad name?[0m") {
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
	t.Run("needrestart broken beats the marker file", func(t *testing.T) {
		r := newRunner().AddResult(needrestartArgv, inline("", 2))
		wantStatus(t, exec(rebootProbe(t), r, marker), result.Error)
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
