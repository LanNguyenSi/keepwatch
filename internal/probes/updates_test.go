package probes_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var aptArgv = []string{"apt-get", "-s", "-o", "Debug::NoLocking=true", "dist-upgrade"}

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// execAt runs p with a fixed clock.
func execAt(p probes.Probe, r execx.Runner, files probes.FS, now time.Time) probes.Outcome {
	return p.Run(context.Background(), &probes.Env{Runner: r, FS: files, Now: func() time.Time { return now }})
}

// lists is a file system whose newest InRelease file is age old.
func lists(age time.Duration) probestest.FakeFS {
	return probestest.FakeFS{Times: map[string]time.Time{
		"/var/lib/apt/lists/archive.example_dists_x-security_InRelease": t0.Add(-age),
		"/var/lib/apt/lists/archive.example_dists_x_InRelease":          t0.Add(-age - 100*time.Hour),
	}}
}

func updatesProbe(t *testing.T, params map[string]any) probes.Probe {
	return prepare(t, "security_updates", params)
}

func aptRunner(stdout string) *fake.FakeRunner {
	return newRunner().AddResult(aptArgv, inline(stdout, 0))
}

func TestSecurityUpdatesCaptured(t *testing.T) {
	for _, v := range versions {
		t.Run(v+"/pending", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_pending"), lists(5*time.Hour), t0)
			wantStatus(t, o, result.Fail)
			if got := subjects(o); len(got) != 3 || got[0] != "apt" || !strings.HasPrefix(got[1], "libapt-pkg") || got[2] != "libpcre2-8-0" {
				t.Fatalf("subjects = %v", got)
			}
			if d := o.Evidence[0].Detail; !strings.Contains(d, "-> 2.") || !strings.Contains(d, "-security") {
				t.Fatalf("detail %q", d)
			}
			wantSummary(t, o, "3 pending security update(s): apt")
			wantSummary(t, o, "package lists are 5 hours old")
		})
		t.Run(v+"/updates pocket only", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_updates_only"), lists(5*time.Hour), t0)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "3 other upgrade(s) pending")
		})
		t.Run(v+"/current", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_current"), lists(5*time.Hour), t0)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "no pending security updates")
		})
		t.Run(v+"/unprivileged run prints notes first", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_notroot"), lists(time.Hour), t0)
			wantStatus(t, o, result.Fail)
		})
		t.Run(v+"/apt fails", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_error"), lists(time.Hour), t0)
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "status 100")
		})
	}
}

func TestSecurityUpdatesListAge(t *testing.T) {
	current := aptRunner("Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")
	pending := aptRunner(aptOut(1, 0, "Inst libc6 [1] (2 Ubuntu:24.04/noble-security [arm64])\n"))
	cases := []struct {
		name   string
		params map[string]any
		fs     probestest.FakeFS
		run    *fake.FakeRunner
		want   result.Status
		sub    string
	}{
		{"fresh", nil, lists(time.Hour), current, result.Pass, "1 hours old"},
		{"exactly the limit", nil, lists(48 * time.Hour), current, result.Pass, "48 hours old"},
		{"one second over the limit", nil, lists(48*time.Hour + time.Second), current, result.Warn, "48 hours old"},
		{"days are shown beyond three", nil, lists(100 * time.Hour), current, result.Warn, "4 days old"},
		{"custom limit", map[string]any{"max_list_age_hours": 2}, lists(3 * time.Hour), current, result.Warn, "3 hours old"},
		{"custom limit, within", map[string]any{"max_list_age_hours": 2}, lists(2 * time.Hour), current, result.Pass, ""},
		{"no InRelease file", nil, probestest.FakeFS{}, current, result.Warn, "age is unknown"},
		{"timestamp in the future", nil, lists(-time.Hour), current, result.Warn, "future"},
		{"stale lists do not hide a pending update", nil, lists(500 * time.Hour), pending, result.Fail, "stale"},
		{"a pending update with fresh lists", nil, lists(time.Hour), pending, result.Fail, "1 hours old"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := execAt(updatesProbe(t, c.params), c.run, c.fs, t0)
			wantStatus(t, o, c.want)
			if c.sub != "" {
				wantSummary(t, o, c.sub)
			}
			if c.want == result.Warn {
				if len(o.Evidence) != 1 || o.Evidence[0].Subject != "apt-lists" {
					t.Fatalf("evidence %+v", o.Evidence)
				}
			}
		})
	}
	t.Run("a file that cannot be stat'ed is ignored, the others count", func(t *testing.T) {
		fsys := lists(time.Hour)
		fsys.Errs = map[string]error{"/var/lib/apt/lists/archive.example_dists_x-security_InRelease": fmt.Errorf("boom")}
		fsys.Times["/var/lib/apt/lists/other_InRelease"] = t0.Add(-10 * time.Hour)
		o := execAt(updatesProbe(t, nil), current, fsys, t0)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "10 hours old")
	})
	t.Run("a glob that fails is an error", func(t *testing.T) {
		o := execAt(updatesProbe(t, nil), current, probestest.FakeFS{GlobErr: fmt.Errorf("boom")}, t0)
		wantStatus(t, o, result.Error)
	})
	t.Run("a file system without the operations is an error", func(t *testing.T) {
		o := execAt(updatesProbe(t, nil), current, probestest.MemFS{}, t0)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "does not offer")
	})
}

// aptOut builds simulation output with n upgraded and m new packages and the
// given Inst lines.
func aptOut(n, m int, inst string) string {
	return fmt.Sprintf("Reading package lists...\nBuilding dependency tree...\nCalculating upgrade...\n%d upgraded, %d newly installed, 0 to remove and 0 not upgraded.\n%s", n, m, inst)
}

func TestSecurityUpdatesPockets(t *testing.T) {
	cases := []struct {
		origin   string
		security bool
	}{
		{"Ubuntu:24.04/noble-security", true},
		{"Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security", true},
		{"Ubuntu:22.04/jammy-security, Ubuntu:22.04/jammy-updates", true},
		{"UbuntuESM:24.04/noble-infra-security", true},
		{"UbuntuESM:24.04/noble-apps-security", true},
		{"Ubuntu:24.04/noble-updates", false},
		{"Ubuntu:24.04/noble-proposed", false},
		{"Ubuntu:24.04/noble-backports", false},
		{"Ubuntu:24.04/noble", false},
		{"Ubuntu:24.04/noble-security-staging", false},
		{"Ubuntu:24.04/noble-securityx", false},
		{"Ubuntu:24.04/security", false},
		{"Ubuntu:24.04/noble-extra-security", false},
		{"a-security/b:1/noble-updates", false},
		{"Third Party:1.0/stable", false},
	}
	for _, c := range cases {
		t.Run(c.origin, func(t *testing.T) {
			line := fmt.Sprintf("Inst pkg-a [1.0] (1.1 %s [amd64])\nConf pkg-a (1.1 %s [amd64])\n", c.origin, c.origin)
			o := execAt(updatesProbe(t, nil), aptRunner(aptOut(1, 0, line)), lists(time.Hour), t0)
			if c.security {
				wantStatus(t, o, result.Fail)
				if !eq(subjects(o), []string{"pkg-a"}) {
					t.Fatalf("subjects %v", subjects(o))
				}
			} else {
				wantStatus(t, o, result.Pass)
			}
		})
	}
	t.Run("a new package from the security pocket counts", func(t *testing.T) {
		o := execAt(updatesProbe(t, nil), aptRunner(aptOut(0, 1, "Inst linux-image-6.8 (6.8.1 Ubuntu:24.04/noble-security [amd64])\n")), lists(time.Hour), t0)
		wantStatus(t, o, result.Fail)
		if !strings.Contains(o.Evidence[0].Detail, "(new)") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("multiarch names and plus signs", func(t *testing.T) {
		line := "Inst libc6:i386 [1] (2 Ubuntu:24.04/noble-security [amd64])\nInst g++-13 [1] (2 Ubuntu:24.04/noble-security [amd64]) []\n"
		o := execAt(updatesProbe(t, nil), aptRunner(aptOut(2, 0, line)), lists(time.Hour), t0)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"g++-13", "libc6:i386"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("removals and kept-back packages are noted, not judged", func(t *testing.T) {
		out := "Reading package lists...\nThe following packages have been kept back:\n  held-pkg\nThe following packages will be REMOVED:\n  old\n" +
			"0 upgraded, 0 newly installed, 1 to remove and 2 not upgraded.\nRemv old [1]\n"
		o := execAt(updatesProbe(t, nil), aptRunner(out), lists(time.Hour), t0)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "2 package(s) not upgraded")
	})
}

func TestSecurityUpdatesUnderstandsOrErrors(t *testing.T) {
	inst := "Inst a [1] (2 Ubuntu:24.04/noble-security [amd64])\n"
	bad := map[string]string{
		"empty":                    "",
		"no summary":               "Reading package lists...\n" + inst,
		"two summaries":            aptOut(1, 0, inst) + "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
		"fewer Inst than promised": aptOut(2, 0, inst),
		"more Inst than promised":  aptOut(0, 0, inst),
		"unknown line":             aptOut(1, 0, inst) + "Surprise: something\n",
		"malformed Inst":           aptOut(1, 0, "Inst a [1] 2 Ubuntu:24.04/noble-security\n"),
		"bad package name":         aptOut(1, 0, "Inst A_b [1] (2 Ubuntu:24.04/noble-security [amd64])\n"),
		"name with a space":        aptOut(1, 0, "Inst a b [1] (2 Ubuntu:24.04/noble-security [amd64])\n"),
		"E line on stdout":         "E: Unable to locate package\n" + aptOut(0, 0, ""),
		"summary glued to text":    "Reading package lists...\nx 1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
		"negative count":           "Reading package lists...\n-1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
		"html":                     "<html><body>503</body></html>",
	}
	for name, out := range bad {
		t.Run(name, func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), aptRunner(out), lists(time.Hour), t0)
			wantStatus(t, o, result.Error)
		})
	}
	t.Run("plausible output with a failing exit status", func(t *testing.T) {
		for _, code := range []int{1, 100, 127} {
			r := newRunner().AddResult(aptArgv, inline(aptOut(0, 0, ""), code))
			wantStatus(t, execAt(updatesProbe(t, nil), r, lists(time.Hour), t0), result.Error)
		}
	})
	t.Run("a carriage return at the end of a line is tolerated", func(t *testing.T) {
		out := strings.ReplaceAll(aptOut(1, 0, inst), "\n", "\r\n")
		wantStatus(t, execAt(updatesProbe(t, nil), aptRunner(out), lists(time.Hour), t0), result.Fail)
	})
}

func TestSecurityUpdatesEvidenceIsLimited(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&b, "Inst pkg-%03d [1] (2 Ubuntu:24.04/noble-security [amd64])\n", i)
	}
	o := execAt(updatesProbe(t, nil), aptRunner(aptOut(150, 0, b.String())), lists(time.Hour), t0)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 100 {
		t.Fatalf("%d evidence items", len(o.Evidence))
	}
	last := o.Evidence[99]
	if last.Subject != "(51 more not shown)" || o.Evidence[98].Subject != "pkg-098" {
		t.Fatalf("last %+v, previous %+v", last, o.Evidence[98])
	}
	wantSummary(t, o, "150 pending security update(s)")
	wantSummary(t, o, "and 51 more")
}

func TestSecurityUpdatesCommonFailures(t *testing.T) {
	commonFailures(t, updatesProbe(t, nil), aptArgv, "apt-get", lists(time.Hour))
}

func TestSecurityUpdatesParams(t *testing.T) {
	for name, params := range map[string]map[string]any{
		"zero":      {"max_list_age_hours": 0},
		"negative":  {"max_list_age_hours": -5},
		"too large": {"max_list_age_hours": 24*365 + 1},
		"string":    {"max_list_age_hours": "48"},
		"float":     {"max_list_age_hours": 48.5},
		"bool":      {"max_list_age_hours": true},
		"unknown":   {"max_age": 1},
		"list":      {"max_list_age_hours": []any{1}},
	} {
		t.Run(name, func(t *testing.T) { prepareErr(t, "security_updates", params) })
	}
	prepare(t, "security_updates", map[string]any{"max_list_age_hours": 24 * 365})
	prepare(t, "security_updates", map[string]any{"max_list_age_hours": int64(5)})
}

func TestSecurityUpdatesArgvIsReadOnlyAndLockFree(t *testing.T) {
	r := newRunner().Add(aptArgv, "ubuntu2404/apt_current")
	execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	c := r.Calls()
	if len(c) != 1 || strings.Join(c[0].Argv, " ") != "apt-get -s -o Debug::NoLocking=true dist-upgrade" {
		t.Fatalf("calls %+v", c)
	}
}
