package probes_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func diskProbe(t *testing.T, params map[string]any) probes.Probe {
	return prepare(t, "disk_usage", params)
}

// mi builds a mountinfo line.
func mi(id int, point, fstype string) string {
	return fmt.Sprintf("%d 1 8:%d / %s rw,relatime shared:%d - %s /dev/x rw\n", id, id, point, id, fstype)
}

func mountFS(lines ...string) probestest.MemFS {
	return probestest.MemFS{"/proc/self/mountinfo": strings.Join(lines, "")}
}

// usage builds a Statfs with the given block and inode percentages: 1000
// blocks (block size 4096), the inode figures out of 1000 as well.
func usage(blocksPct, inodesPct uint64) probes.Statfs {
	s := probes.Statfs{BlockSize: 4096, Blocks: 1000, Bfree: 1000 - blocksPct*10, Bavail: 1000 - blocksPct*10}
	if inodesPct != 1<<62 {
		s.Files, s.Ffree = 1000, 1000-inodesPct*10
	}
	return s
}

const noInodes = uint64(1 << 62)

// statfsMap serves usages by mount point and records the paths it was asked for.
type statfsMap struct {
	by     map[string]probes.Statfs
	errs   map[string]error
	called []string
}

func (s *statfsMap) fn(path string) (probes.Statfs, error) {
	s.called = append(s.called, path)
	if err, ok := s.errs[path]; ok {
		return probes.Statfs{}, err
	}
	u, ok := s.by[path]
	if !ok {
		return probes.Statfs{}, errors.New("no such mount")
	}
	return u, nil
}

func execDisk(p probes.Probe, files probes.FS, st *statfsMap) probes.Outcome {
	return p.Run(context.Background(), &probes.Env{Runner: fake.New(nil), FS: files, Statfs: st.fn})
}

func TestDiskUsageCapturedMountinfo(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			files := probestest.MemFS{"/proc/self/mountinfo": fixtureFile(t, v+"/mountinfo.stdout")}
			// the container's /etc/hosts and friends are ext4 bind mounts of single files
			st := &statfsMap{by: map[string]probes.Statfs{"/mnt/kw ext4": usage(95, 3), "/etc/hosts": usage(1, 1), "/etc/hostname": usage(1, 1), "/etc/resolv.conf": usage(1, 1)}}
			o := execDisk(diskProbe(t, nil), files, st)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"/mnt/kw ext4"}) || len(st.called) != 4 {
				t.Fatalf("subjects %v, statfs called for %q", subjects(o), st.called)
			}
			if d := o.Evidence[0].Detail; d != "95% of the blocks used, 3% of the inodes used (ext4)" {
				t.Fatalf("detail %q", d)
			}

			// the escapes of mountinfo are decoded before the path is used
			st = &statfsMap{by: map[string]probes.Statfs{
				"/mnt/kw ext4": usage(1, 1), "/mnt/kw tmp": usage(1, 1), `/mnt/kw\back`: usage(1, 1), "/mnt/kw-nl\nline": usage(95, 1),
				"/etc/hosts": usage(1, 1), "/etc/hostname": usage(1, 1), "/etc/resolv.conf": usage(1, 1),
				"/dev": usage(1, 1), "/dev/shm": usage(1, 1),
			}}
			o = execDisk(diskProbe(t, map[string]any{"fstypes": []any{"ext4", "tmpfs"}}), files, st)
			wantStatus(t, o, result.Fail)
			if len(st.called) != 9 {
				t.Fatalf("statfs called for %q", st.called)
			}
			if !eq(subjects(o), []string{"/mnt/kw-nl\nline"}) {
				t.Fatalf("the subject is the mount point as it is, a newline included: %q", subjects(o))
			}
			if strings.ContainsAny(shown(o.Summary), "\n") {
				t.Fatalf("a newline in a mount point must not reach the summary: %q", o.Summary)
			}
		})
	}
}

func TestDiskUsageThresholds(t *testing.T) {
	files := mountFS(mi(1, "/", "ext4"))
	cases := []struct {
		name         string
		blocks, inod uint64
		params       map[string]any
		want         result.Status
		sub          string
	}{
		{"well below", 10, 10, nil, result.Pass, "below 80%"},
		{"79", 79, 1, nil, result.Pass, ""},
		{"80 warns", 80, 1, nil, result.Warn, "at or above 80%"},
		{"89 warns", 89, 1, nil, result.Warn, ""},
		{"90 fails", 90, 1, nil, result.Fail, "at or above 90%"},
		{"100 fails", 100, 1, nil, result.Fail, ""},
		{"inodes warn", 10, 85, nil, result.Warn, ""},
		{"inodes fail", 10, 95, nil, result.Fail, ""},
		{"the higher of the two decides", 85, 95, nil, result.Fail, ""},
		{"no inode count: blocks only", 85, noInodes, nil, result.Warn, ""},
		{"custom thresholds, pass", 59, 1, map[string]any{"warn_percent": 60, "fail_percent": 70}, result.Pass, ""},
		{"custom thresholds, warn", 60, 1, map[string]any{"warn_percent": 60, "fail_percent": 70}, result.Warn, ""},
		{"custom thresholds, fail", 70, 1, map[string]any{"warn_percent": 60, "fail_percent": 70}, result.Fail, ""},
		{"warn equals fail", 50, 1, map[string]any{"warn_percent": 50, "fail_percent": 50}, result.Fail, ""},
		{"fail at 100 only", 99, 1, map[string]any{"fail_percent": 100}, result.Warn, ""},
		{"fail at 100 only, full", 100, 1, map[string]any{"fail_percent": 100}, result.Fail, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := &statfsMap{by: map[string]probes.Statfs{"/": usage(c.blocks, c.inod)}}
			o := execDisk(diskProbe(t, c.params), files, st)
			wantStatus(t, o, c.want)
			if c.sub != "" {
				wantSummary(t, o, c.sub)
			}
			if c.want == result.Pass && len(o.Evidence) != 0 {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
	}
	t.Run("rounding up like df", func(t *testing.T) {
		// 7999 of 10000 blocks used: 79.99%, which df shows as 80%
		st := &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 1, Blocks: 10000, Bfree: 2001, Bavail: 2001}}}
		wantStatus(t, execDisk(diskProbe(t, nil), files, st), result.Warn)
		st = &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 1, Blocks: 10000, Bfree: 2000, Bavail: 2000}}}
		wantStatus(t, execDisk(diskProbe(t, nil), files, st), result.Warn)
		st = &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 1, Blocks: 10000, Bfree: 2100, Bavail: 2100}}}
		wantStatus(t, execDisk(diskProbe(t, nil), files, st), result.Pass)
	})
	t.Run("reserved blocks count as used for the unprivileged user", func(t *testing.T) {
		// df: used / (used + available); 100 blocks are free but reserved for root
		st := &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 1, Blocks: 1000, Bfree: 100, Bavail: 0}}}
		wantStatus(t, execDisk(diskProbe(t, nil), files, st), result.Fail)
	})
	t.Run("huge file systems do not overflow", func(t *testing.T) {
		big := uint64(1_000_000_000_000_000_000)
		st := &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 4096, Blocks: big, Bfree: big / 10, Bavail: big / 10, Files: big, Ffree: big / 2}}}
		o := execDisk(diskProbe(t, nil), files, st)
		wantStatus(t, o, result.Fail)
		if d := o.Evidence[0].Detail; !strings.HasPrefix(d, "90% of the blocks used, 50% of the inodes") {
			t.Fatalf("detail %q", d)
		}
	})
	t.Run("an empty file system", func(t *testing.T) {
		st := &statfsMap{by: map[string]probes.Statfs{"/": {BlockSize: 4096}}}
		wantStatus(t, execDisk(diskProbe(t, nil), files, st), result.Pass)
	})
}

func TestDiskUsageMixAndSelection(t *testing.T) {
	files := mountFS(mi(1, "/", "ext4"), mi(2, "/data", "xfs"), mi(3, "/boot/efi", "vfat"), mi(4, "/srv", "btrfs"), mi(5, "/tank", "zfs"),
		mi(6, "/mnt/nfs", "nfs4"), mi(7, "/run", "tmpfs"), mi(8, "/proc", "proc"), mi(9, "/net", "fuse.sshfs"), mi(10, "/cifs", "cifs"))
	st := &statfsMap{by: map[string]probes.Statfs{
		"/": usage(10, 1), "/data": usage(85, 1), "/boot/efi": usage(95, noInodes), "/srv": usage(91, noInodes), "/tank": usage(5, noInodes),
	}}
	o := execDisk(diskProbe(t, nil), files, st)
	wantStatus(t, o, result.Fail)
	if !eq(subjects(o), []string{"/boot/efi", "/srv"}) {
		t.Fatalf("subjects %v", subjects(o))
	}
	// the evidence of a failing result holds the failing items only
	wantSummary(t, o, "2 of 5 file system(s) at or above 90%")
	wantSummary(t, o, "1 more at or above 80%")
	if len(st.called) != 5 {
		t.Fatalf("network and pseudo file systems must not be asked: %q", st.called)
	}
	for _, p := range st.called {
		if p == "/mnt/nfs" || p == "/net" || p == "/cifs" || p == "/run" || p == "/proc" {
			t.Fatalf("statfs called for %s", p)
		}
	}

	t.Run("the warnings of a failing result are carried separately", func(t *testing.T) {
		if got := []string{o.Warnings[0].Subject}; len(o.Warnings) != 1 || !eq(got, []string{"/data"}) {
			t.Fatalf("warnings %+v", o.Warnings)
		}
		if len(o.Evidence) != 2 {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("fstypes replaces the default", func(t *testing.T) {
		st := &statfsMap{by: map[string]probes.Statfs{"/run": usage(95, 1)}}
		o := execDisk(diskProbe(t, map[string]any{"fstypes": []any{"tmpfs"}}), files, st)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"/run"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
		// ext4 is no longer examined: the list was not extended
		if len(st.called) != 1 {
			t.Fatalf("statfs called for %q", st.called)
		}
	})
	t.Run("a Go list works as well as a YAML one", func(t *testing.T) {
		st := &statfsMap{by: map[string]probes.Statfs{"/": usage(1, 1)}}
		wantStatus(t, execDisk(diskProbe(t, map[string]any{"fstypes": []string{"ext4"}}), files, st), result.Pass)
	})
	t.Run("no mount of a checked type", func(t *testing.T) {
		o := execDisk(diskProbe(t, nil), mountFS(mi(1, "/", "overlay"), mi(2, "/proc", "proc")), &statfsMap{})
		wantStatus(t, o, result.Skipped)
	})
	t.Run("only warnings", func(t *testing.T) {
		st := &statfsMap{by: map[string]probes.Statfs{"/": usage(85, 1), "/data": usage(81, 1), "/boot/efi": usage(1, 1), "/srv": usage(1, 1), "/tank": usage(1, 1)}}
		o := execDisk(diskProbe(t, nil), files, st)
		wantStatus(t, o, result.Warn)
		if !eq(subjects(o), []string{"/", "/data"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("a mount point that appears twice: the last entry is the visible one", func(t *testing.T) {
		f := mountFS(mi(1, "/", "ext4"), mi(2, "/data", "ext4"), mi(3, "/data", "tmpfs"))
		st := &statfsMap{by: map[string]probes.Statfs{"/": usage(1, 1)}}
		wantStatus(t, execDisk(diskProbe(t, nil), f, st), result.Pass)
		if !eq(st.called, []string{"/"}) {
			t.Fatalf("statfs called for %q", st.called)
		}
		f = mountFS(mi(1, "/data", "tmpfs"), mi(2, "/data", "ext4"))
		st = &statfsMap{by: map[string]probes.Statfs{"/data": usage(95, 1)}}
		wantStatus(t, execDisk(diskProbe(t, nil), f, st), result.Fail)
	})
}

func TestDiskUsageUnreadableMountsAreError(t *testing.T) {
	files := mountFS(mi(1, "/", "ext4"), mi(2, "/data", "ext4"), mi(3, "/srv", "ext4"))
	t.Run("one statfs fails, the failing mount is kept", func(t *testing.T) {
		st := &statfsMap{by: map[string]probes.Statfs{"/": usage(95, 1), "/srv": usage(1, 1)}, errs: map[string]error{"/data": errors.New("input/output error")}}
		o := execDisk(diskProbe(t, nil), files, st)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "statfs /data")
		if !eq(subjects(o), []string{"/"}) {
			t.Fatalf("evidence %v", subjects(o))
		}
	})
	t.Run("inconsistent numbers", func(t *testing.T) {
		for name, s := range map[string]probes.Statfs{
			"free above total":      {Blocks: 10, Bfree: 11, Bavail: 5},
			"available above free":  {Blocks: 10, Bfree: 5, Bavail: 6},
			"free inodes above all": {Blocks: 10, Bfree: 5, Bavail: 5, Files: 5, Ffree: 6},
		} {
			st := &statfsMap{by: map[string]probes.Statfs{"/": s}}
			o := execDisk(diskProbe(t, nil), mountFS(mi(1, "/", "ext4")), st)
			if o.Status != result.Error {
				t.Errorf("%s: %s", name, o.Status)
			}
		}
	})
	t.Run("many failures are summarised", func(t *testing.T) {
		var lines []string
		st := &statfsMap{errs: map[string]error{}}
		for i := 0; i < 20; i++ {
			p := fmt.Sprintf("/m%02d", i)
			lines = append(lines, mi(i+1, p, "ext4"))
			st.errs[p] = errors.New("boom")
		}
		o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "and 15 more mounts could not be read")
	})
	t.Run("a statfs that hangs does not hang the run", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		env := &probes.Env{
			Runner: fake.New(nil), FS: mountFS(mi(1, "/", "ext4"), mi(2, "/hung", "ext4")), StatfsTimeout: 50 * time.Millisecond,
			Statfs: func(path string) (probes.Statfs, error) {
				if path == "/hung" {
					<-release
				}
				return usage(95, 1), nil
			},
		}
		done := make(chan probes.Outcome, 1)
		go func() { done <- diskProbe(t, nil).Run(context.Background(), env) }()
		select {
		case o := <-done:
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "timed out")
			if !eq(subjects(o), []string{"/"}) {
				t.Fatalf("evidence %v", subjects(o))
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the run hung")
		}
	})
	t.Run("a cancelled run", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		release := make(chan struct{})
		defer close(release)
		env := &probes.Env{Runner: fake.New(nil), FS: mountFS(mi(1, "/", "ext4")), Statfs: func(string) (probes.Statfs, error) { <-release; return probes.Statfs{}, nil }}
		start := time.Now()
		o := diskProbe(t, nil).Run(ctx, env)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "context canceled")
		if time.Since(start) > 3*time.Second {
			t.Fatalf("a cancelled run waited for the timeout")
		}
	})
}

func TestDiskUsageMountinfoIsParsedStrictly(t *testing.T) {
	st := func() *statfsMap { return &statfsMap{by: map[string]probes.Statfs{"/": usage(1, 1)}} }
	bad := map[string]string{
		"empty":                  "",
		"blank":                  "\n\n",
		"too few fields":         "1 2 3:4 / /\n",
		"no separator":           "1 2 3:4 / / rw shared:1 ext4 /dev/x rw\n",
		"separator too early":    "1 2 3:4 / - rw ext4 /dev/x rw\n",
		"nothing after the dash": "1 2 3:4 / / rw - ext4\n",
		"relative mount point":   "1 2 3:4 / mnt rw - ext4 /dev/x rw\n",
		"bad escape":             "1 2 3:4 / /m\\9 rw - ext4 /dev/x rw\n",
		"escape too large":       "1 2 3:4 / /m\\777 rw - ext4 /dev/x rw\n",
		"escape at the end":      "1 2 3:4 / /m\\04 rw - ext4 /dev/x rw\n",
		"lone backslash":         "1 2 3:4 / /m\\ rw - ext4 /dev/x rw\n",
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			o := execDisk(diskProbe(t, nil), probestest.MemFS{"/proc/self/mountinfo": content}, st())
			wantStatus(t, o, result.Error)
			if name == "separator too early" && !strings.Contains(o.Summary, "not a mountinfo line") {
				t.Fatalf("summary %q", o.Summary)
			}
			if !strings.Contains(o.Summary, "/proc/self/mountinfo: ") {
				t.Fatalf("a mountinfo problem must be named as one, not left to statfs: %q", o.Summary)
			}
		})
	}
	t.Run("optional fields before the separator", func(t *testing.T) {
		line := "36 35 98:0 /mnt1 / rw,noatime master:1 shared:2 propagate_from:3 - ext4 /dev/root rw,errors=continue\n"
		wantStatus(t, execDisk(diskProbe(t, nil), probestest.MemFS{"/proc/self/mountinfo": line}, st()), result.Pass)
	})
	t.Run("escapes", func(t *testing.T) {
		line := "1 2 3:4 / /a\\040b\\011c\\012d\\134e rw - ext4 /dev/x rw\n"
		s := &statfsMap{by: map[string]probes.Statfs{"/a b\tc\nd\\e": usage(95, 1)}}
		o := execDisk(diskProbe(t, nil), probestest.MemFS{"/proc/self/mountinfo": line}, s)
		wantStatus(t, o, result.Fail)
		if !eq(s.called, []string{"/a b\tc\nd\\e"}) {
			t.Fatalf("called %q", s.called)
		}
		if o.Evidence[0].Subject != "/a b\tc\nd\\e" {
			t.Fatalf("the subject is the decoded mount point, %q", o.Evidence[0].Subject)
		}
		if strings.ContainsAny(shown(o.Summary), "\n\t") {
			t.Fatalf("summary %q", o.Summary)
		}
	})
	t.Run("read errors", func(t *testing.T) {
		for _, fsys := range []probes.FS{probestest.MemFS{}, probestest.ErrFS{Err: errors.New("boom")}, probestest.MemFS{"/proc/self/mountinfo": strings.Repeat("x", 9<<20)}} {
			wantStatus(t, execDisk(diskProbe(t, nil), fsys, st()), result.Error)
		}
	})
}

func TestDiskUsageEvidenceIsLimited(t *testing.T) {
	var lines []string
	st := &statfsMap{by: map[string]probes.Statfs{}}
	for i := 0; i < 150; i++ {
		p := fmt.Sprintf("/m%03d", i)
		lines = append(lines, mi(i+1, p, "ext4"))
		st.by[p] = usage(95, 1)
	}
	o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 100 || o.Evidence[99].Subject != "(51 more not shown)" {
		t.Fatalf("%d items", len(o.Evidence))
	}
	wantCapped(t, o.Evidence, o.Set, 150)
}

// The warnings carried next to a failure are capped on their own, with their
// own set: the engine turns them into the evidence when exceptions cover the
// failures.
func TestDiskUsageWarningsAreLimited(t *testing.T) {
	var lines []string
	st := &statfsMap{by: map[string]probes.Statfs{}}
	lines = append(lines, mi(1, "/full", "ext4"))
	st.by["/full"] = usage(99, 1)
	for i := 0; i < 130; i++ {
		p := fmt.Sprintf("/w%03d", i)
		lines = append(lines, mi(i+2, p, "ext4"))
		st.by[p] = usage(85, 1)
	}
	o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 1 || o.Set != nil {
		t.Fatalf("the failing list: %+v", o.Evidence)
	}
	if len(o.Warnings) != 100 {
		t.Fatalf("%d warnings", len(o.Warnings))
	}
	wantCapped(t, o.Warnings, o.WarningsSet, 130)
}

// A warn outcome (nothing fails) with a cut list carries the set in Set.
func TestDiskUsageCutWarnListHasASet(t *testing.T) {
	var lines []string
	st := &statfsMap{by: map[string]probes.Statfs{}}
	for i := 0; i < 130; i++ {
		p := fmt.Sprintf("/w%03d", i)
		lines = append(lines, mi(i+1, p, "ext4"))
		st.by[p] = usage(85, 1)
	}
	o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
	wantStatus(t, o, result.Warn)
	wantCapped(t, o.Evidence, o.Set, 130)
	if o.WarningsSet != nil {
		t.Error("a warn outcome has no separate warnings")
	}
}

// An error that keeps the confirmed failures keeps their set too.
func TestDiskUsagePartialResultWithACutListHasASet(t *testing.T) {
	var lines []string
	st := &statfsMap{by: map[string]probes.Statfs{}, errs: map[string]error{"/broken": errors.New("boom")}}
	lines = append(lines, mi(1, "/broken", "ext4"))
	for i := 0; i < 130; i++ {
		p := fmt.Sprintf("/f%03d", i)
		lines = append(lines, mi(i+2, p, "ext4"))
		st.by[p] = usage(95, 1)
	}
	o := execDisk(diskProbe(t, nil), mountFS(lines...), st)
	wantStatus(t, o, result.Error)
	wantCapped(t, o.Evidence, o.Set, 130)
}

func TestDiskUsageParams(t *testing.T) {
	bad := map[string]map[string]any{
		"warn above fail":      {"warn_percent": 91},
		"warn above custom":    {"warn_percent": 60, "fail_percent": 50},
		"warn zero":            {"warn_percent": 0},
		"fail zero":            {"fail_percent": 0},
		"fail 101":             {"fail_percent": 101},
		"negative":             {"warn_percent": -1},
		"string":               {"warn_percent": "80"},
		"float":                {"warn_percent": 80.5},
		"fstypes empty":        {"fstypes": []any{}},
		"fstypes not a list":   {"fstypes": "ext4"},
		"fstypes bad element":  {"fstypes": []any{"ext4", "Ext 4"}},
		"fstypes number":       {"fstypes": []any{4}},
		"fstypes leading dash": {"fstypes": []any{"-x"}},
		"fstypes too long":     {"fstypes": []any{strings.Repeat("a", 40)}},
		"unknown":              {"threshold": 1},
	}
	for name, params := range bad {
		t.Run(name, func(t *testing.T) { prepareErr(t, "disk_usage", params) })
	}
	prepare(t, "disk_usage", map[string]any{"warn_percent": 1, "fail_percent": 100, "fstypes": []any{"fuse.x", "ext4"}})
}
