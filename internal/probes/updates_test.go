package probes_test

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var aptArgv = []string{"apt-get", "-s", "-o", "Debug::NoLocking=true", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "dist-upgrade"}

// policyArgv is what the probe asks apt-cache for the given packages.
func policyArgv(names ...string) []string {
	return append([]string{"apt-cache", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "policy", "--"}, names...)
}

var instUpgrade = regexp.MustCompile(`^Inst (\S+) \[(\S+)\] \((\S+) (.+?) \[[^\]]*\]\)`)

// instNames returns the sorted names of the packages that a simulation
// upgrades (the ones with an installed version).
func instNames(sim string) []string {
	var names []string
	for _, l := range strings.Split(sim, "\n") {
		if m := instUpgrade.FindStringSubmatch(l); m != nil {
			names = append(names, m[1])
		}
	}
	sort.Strings(names)
	return names
}

// withPolicy registers, for the upgraded packages of a simulation, an
// apt-cache policy answer that agrees with the Inst lines: the candidate on
// top, from the pockets the line names, and the installed version below it.
func withPolicy(r *fake.FakeRunner, sim string) *fake.FakeRunner {
	texts := map[string]string{}
	for _, l := range strings.Split(sim, "\n") {
		m := instUpgrade.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s:\n  Installed: %s\n  Candidate: %s\n  Version table:\n     %s 500\n", m[1], m[2], m[3], m[3])
		for _, origin := range strings.Split(m[4], ", ") {
			fmt.Fprintf(&b, "        500 http://archive.example %s/main amd64 Packages\n", origin[strings.LastIndex(origin, "/")+1:])
		}
		fmt.Fprintf(&b, " *** %s 100\n        100 /var/lib/dpkg/status\n", m[2])
		texts[m[1]] = b.String()
	}
	names := instNames(sim)
	for len(names) > 0 {
		n := min(100, len(names))
		var out strings.Builder
		for _, name := range names[:n] {
			out.WriteString(texts[name])
		}
		r.AddResult(policyArgv(names[:n]...), inline(out.String(), 0))
		names = names[n:]
	}
	return r
}

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
	return withPolicy(newRunner().AddResult(aptArgv, inline(stdout, 0)), stdout)
}

// aptFixtureRunner is a runner for a captured simulation and the captured
// apt-cache policy answer for the packages it upgrades.
func aptFixtureRunner(t *testing.T, v, sim, policy string) *fake.FakeRunner {
	t.Helper()
	names := instNames(fixtureFile(t, v+"/"+sim+".stdout"))
	if len(names) == 0 || len(names) > 100 {
		t.Fatalf("%s/%s: %d upgraded packages", v, sim, len(names))
	}
	return newRunner().Add(aptArgv, v+"/"+sim).Add(policyArgv(names...), v+"/"+policy)
}

func TestSecurityUpdatesCaptured(t *testing.T) {
	for _, v := range versions {
		t.Run(v+"/pending", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), aptFixtureRunner(t, v, "apt_pending", "apt_policy_pending"), lists(5*time.Hour), t0)
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
			o := execAt(updatesProbe(t, nil), aptFixtureRunner(t, v, "apt_updates_only", "apt_policy_updates_only"), lists(5*time.Hour), t0)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "3 other upgrade(s) pending")
		})
		t.Run(v+"/current", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), newRunner().Add(aptArgv, v+"/apt_current"), lists(5*time.Hour), t0)
			wantStatus(t, o, result.Pass)
			wantSummary(t, o, "no pending security updates")
		})
		t.Run(v+"/unprivileged run prints notes first", func(t *testing.T) {
			o := execAt(updatesProbe(t, nil), aptFixtureRunner(t, v, "apt_notroot", "apt_policy_pending"), lists(time.Hour), t0)
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
	t.Run("a reinstalled package is counted with the others", func(t *testing.T) {
		out := "Reading package lists...\n0 upgraded, 0 newly installed, 1 reinstalled, 0 to remove and 0 not upgraded.\n" +
			"Inst pkg-a [1] (1 Ubuntu:24.04/noble-security [amd64])\n"
		o := execAt(updatesProbe(t, nil), aptRunner(out), lists(time.Hour), t0)
		wantStatus(t, o, result.Fail)
		out = strings.Replace(out, "1 reinstalled", "0 reinstalled", 1)
		wantStatus(t, execAt(updatesProbe(t, nil), aptRunner(out), lists(time.Hour), t0), result.Error)
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
	prepareErr(t, "security_updates", map[string]any{"max_list_age_hours": int64(0)})
	prepareErr(t, "security_updates", map[string]any{"max_list_age_hours": int64(1) << 40})
}

func TestSecurityUpdatesArgvIsReadOnlyAndLockFree(t *testing.T) {
	r := aptFixtureRunner(t, "ubuntu2404", "apt_pending", "apt_policy_pending")
	execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	c := r.Calls()
	if len(c) != 2 {
		t.Fatalf("calls %+v", c)
	}
	if got := strings.Join(c[0].Argv, " "); got != "apt-get -s -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= dist-upgrade" {
		t.Fatalf("simulation: %s", got)
	}
	if got := strings.Join(c[1].Argv[:7], " "); got != "apt-cache -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= policy --" {
		t.Fatalf("policy: %s", got)
	}
}

// policyText builds the apt-cache policy answer for one package from rows
// given newest first: "*" before a version marks the installed one, and the
// suites follow after an at sign ("dpkg" is the status file).
func policyText(name string, rows ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n  Installed: x\n  Candidate: y\n  Version table:\n", name)
	for _, row := range rows {
		ver, suites, _ := strings.Cut(row, "@")
		if v, ok := strings.CutPrefix(ver, "*"); ok {
			fmt.Fprintf(&b, " *** %s 100\n", v)
		} else {
			fmt.Fprintf(&b, "     %s 500\n", ver)
		}
		for _, s := range strings.Fields(suites) {
			if s == "dpkg" {
				b.WriteString("        100 /var/lib/dpkg/status\n")
			} else {
				fmt.Fprintf(&b, "        500 http://archive.example %s/main amd64 Packages\n", s)
			}
		}
	}
	return b.String()
}

const instOne = "Inst pkg-a [1.0] (3.0 Ubuntu:24.04/noble-updates [amd64])\n"

func policyRunner(sim string, policy string) *fake.FakeRunner {
	return newRunner().AddResult(aptArgv, inline(sim, 0)).AddResult(policyArgv("pkg-a"), inline(policy, 0))
}

func TestSecurityUpdatesSupersededSecurityFix(t *testing.T) {
	sim := aptOut(1, 0, instOne)
	run := func(policy string) probes.Outcome {
		return execAt(updatesProbe(t, nil), policyRunner(sim, policy), lists(time.Hour), t0)
	}
	t.Run("captured on both releases", func(t *testing.T) {
		want := map[string]string{"ubuntu2204": "libapparmor1", "ubuntu2404": "krb5-locales"}
		for _, v := range versions {
			o := execAt(updatesProbe(t, nil), aptFixtureRunner(t, v, "apt_superseded", "apt_policy_superseded"), lists(time.Hour), t0)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{want[v]}) {
				t.Fatalf("%s: subjects %v", v, subjects(o))
			}
			d := o.Evidence[0].Detail
			if !strings.Contains(d, "-updates") && !strings.Contains(d, "security version") || !strings.Contains(d, "-security") {
				t.Fatalf("%s: detail %q", v, d)
			}
			// the same simulation without the policy answer would have passed
			wantSummary(t, o, "1 pending security update(s): "+want[v])
		}
	})
	t.Run("the candidate is newer than the security version", func(t *testing.T) {
		o := run(policyText("pkg-a", "3.0@noble-updates", "2.0@noble-security", "*1.0@noble dpkg"))
		wantStatus(t, o, result.Fail)
		d := o.Evidence[0].Detail
		if d != "1.0 -> 3.0, but the security version 2.0 from noble-security is newer than the installed one" {
			t.Fatalf("detail %q", d)
		}
	})
	t.Run("the newest security version is named", func(t *testing.T) {
		o := run(policyText("pkg-a", "4.0@noble-updates", "3.0@noble-security", "2.0@noble-security", "*1.0@dpkg"))
		wantStatus(t, o, result.Fail)
		if !strings.Contains(o.Evidence[0].Detail, "security version 3.0 ") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("a security version below the installed one does not count", func(t *testing.T) {
		wantStatus(t, run(policyText("pkg-a", "3.0@noble-updates", "*1.5@dpkg", "1.0@noble-security")), result.Pass)
	})
	t.Run("the installed version itself in a security pocket does not count", func(t *testing.T) {
		wantStatus(t, run(policyText("pkg-a", "3.0@noble-updates", "*1.0@noble-security dpkg")), result.Pass)
	})
	t.Run("the order of apt decides, not the version text", func(t *testing.T) {
		// an epoch makes 1:0.5 newer than 2.0; the code does not compare versions
		wantStatus(t, run(policyText("pkg-a", "1:0.5@noble-security", "*2.0@dpkg")), result.Fail)
		wantStatus(t, run(policyText("pkg-a", "3.0@noble-updates", "*2.0@dpkg", "1:0.5@noble-security")), result.Pass)
	})
	t.Run("every security pocket name counts", func(t *testing.T) {
		for _, pocket := range []string{"noble-security", "noble-infra-security", "noble-apps-security"} {
			wantStatus(t, run(policyText("pkg-a", "3.0@noble-updates", "2.0@"+pocket, "*1.0@dpkg")), result.Fail)
		}
		for _, pocket := range []string{"noble-updates", "noble-proposed", "noble-security-staging", "security", "noble-extra-security"} {
			wantStatus(t, run(policyText("pkg-a", "3.0@noble-updates", "2.0@"+pocket, "*1.0@dpkg")), result.Pass)
		}
	})
	t.Run("a candidate from a security pocket counts even when the table does not say so", func(t *testing.T) {
		sec := aptOut(1, 0, "Inst pkg-a [1.0] (3.0 Ubuntu:24.04/noble-security [amd64])\n")
		o := execAt(updatesProbe(t, nil), newRunner().AddResult(aptArgv, inline(sec, 0)).AddResult(policyArgv("pkg-a"), inline(policyText("pkg-a", "3.0@noble-updates", "*1.0@dpkg"), 0)), lists(time.Hour), t0)
		wantStatus(t, o, result.Fail)
		if o.Evidence[0].Detail != "1.0 -> 3.0 from noble-security" {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("a new package is not looked up", func(t *testing.T) {
		r := newRunner().AddResult(aptArgv, inline(aptOut(0, 1, "Inst pkg-b (3.0 Ubuntu:24.04/noble-updates [amd64])\n"), 0))
		wantStatus(t, execAt(updatesProbe(t, nil), r, lists(time.Hour), t0), result.Pass)
		if len(r.Calls()) != 1 {
			t.Fatalf("calls %+v", r.Calls())
		}
	})
	t.Run("stale lists are a warning next to the failure", func(t *testing.T) {
		o := execAt(updatesProbe(t, nil), policyRunner(sim, policyText("pkg-a", "3.0@noble-updates", "2.0@noble-security", "*1.0@dpkg")), lists(500*time.Hour), t0)
		wantStatus(t, o, result.Fail)
		if len(o.Warnings) != 1 || o.Warnings[0].Subject != "apt-lists" {
			t.Fatalf("warnings %+v", o.Warnings)
		}
		o = execAt(updatesProbe(t, nil), policyRunner(sim, policyText("pkg-a", "3.0@noble-updates", "2.0@noble-security", "*1.0@dpkg")), lists(time.Hour), t0)
		if len(o.Warnings) != 0 {
			t.Fatalf("warnings %+v", o.Warnings)
		}
	})
}

func TestSecurityUpdatesInstAnnotations(t *testing.T) {
	// "Inst x [old] (new origin [arch]) [pkg on dep] [pkg ]": apt appends the
	// packages it has to upgrade together
	// The captured state is the e2fsprogs family at the release pocket's
	// version. On 22.04 the security pocket has a fix that the updates pocket
	// has superseded, so the five packages are pending security updates; on
	// 24.04 the fix came through -updates only. Either way the line with
	// annotations is read and is not an error.
	o := execAt(updatesProbe(t, nil), aptFixtureRunner(t, "ubuntu2204", "apt_annotations", "apt_policy_annotations"), lists(time.Hour), t0)
	wantStatus(t, o, result.Fail)
	if got := subjects(o); len(got) != 5 || got[0] != "e2fsprogs" || !strings.HasPrefix(got[1], "libcom-err2") {
		t.Fatalf("subjects %v", got)
	}
	o = execAt(updatesProbe(t, nil), aptFixtureRunner(t, "ubuntu2404", "apt_annotations", "apt_policy_annotations"), lists(time.Hour), t0)
	wantStatus(t, o, result.Pass)
	wantSummary(t, o, "5 other upgrade(s) pending")
	if !strings.Contains(fixtureFile(t, "ubuntu2404/apt_annotations.stdout"), "] [e2fsprogs:arm64 ]") || !strings.Contains(fixtureFile(t, "ubuntu2204/apt_annotations.stdout"), "] [e2fsprogs:arm64 ]") {
		t.Fatal("the captured simulations lack the annotation groups")
	}
	line := "Inst a [1] (2 Ubuntu:24.04/noble-updates [amd64]) [b:amd64 on a:amd64] [b:amd64 ] [c]\n"
	wantStatus(t, execAt(updatesProbe(t, nil), aptRunner(aptOut(1, 0, line)), lists(time.Hour), t0), result.Pass)
	for name, bad := range map[string]string{
		"nested brackets": "Inst a [1] (2 Ubuntu:24.04/noble-updates [amd64]) [b [c]]\n",
		"text after":      "Inst a [1] (2 Ubuntu:24.04/noble-updates [amd64]) [b] trailing\n",
		"unclosed":        "Inst a [1] (2 Ubuntu:24.04/noble-updates [amd64]) [b\n",
	} {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, execAt(updatesProbe(t, nil), aptRunner(aptOut(1, 0, bad)), lists(time.Hour), t0), result.Error)
		})
	}
}

func TestSecurityUpdatesPolicyIsUnderstoodOrError(t *testing.T) {
	sim := aptOut(1, 0, instOne)
	good := policyText("pkg-a", "3.0@noble-updates", "*1.0@dpkg")
	run := func(res execResultT) probes.Outcome {
		r := newRunner().AddResult(aptArgv, inline(sim, 0)).AddResult(policyArgv("pkg-a"), res.Result)
		return execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	}
	wantStatus(t, run(execResult(good, "", 0)), result.Pass)
	bad := map[string]string{
		"nothing printed (unknown package)": "",
		"another package":                   policyText("pkg-b", "3.0@noble-updates", "*1.0@dpkg"),
		"the package twice":                 good + good,
		"no installed row":                  policyText("pkg-a", "3.0@noble-updates", "1.0@dpkg"),
		"two installed rows":                policyText("pkg-a", "*3.0@noble-updates", "*1.0@dpkg"),
		"unknown line":                      good + "Surprise: something\n",
		"line before a package":             "stray\n" + good,
		"origin before a version":           strings.Replace(good, "     3.0 500\n", "", 1),
		"bad version row":                   strings.Replace(good, "     3.0 500", "     3.0", 1),
		"bad origin line":                   strings.Replace(good, "500 http://archive.example noble-updates/main amd64 Packages", "500", 1),
		"html":                              "<html>503</html>",
	}
	for name, out := range bad {
		t.Run(name, func(t *testing.T) { wantStatus(t, run(execResult(out, "", 0)), result.Error) })
	}
	t.Run("exit status", func(t *testing.T) {
		for _, code := range []int{1, 100, 127} {
			o := run(execResult(good, "E: Unable to parse package file\n", code))
			wantStatus(t, o, result.Error)
			wantSummary(t, o, fmt.Sprintf("status %d", code))
		}
	})
	t.Run("apt-cache failures", func(t *testing.T) {
		pa := policyArgv("pkg-a")
		for name, c := range map[string]struct {
			err  error
			want result.Status
			sub  string
		}{
			"not installed":   {execx.ErrNotFound, result.Error, "apt-cache"},
			"not allowlisted": {execx.ErrNotAllowed, result.Error, "allowlist"},
			"timeout":         {execx.ErrTimeout, result.Error, "timed out"},
		} {
			t.Run(name, func(t *testing.T) {
				o := execAt(updatesProbe(t, nil), newRunner().AddResult(aptArgv, inline(sim, 0)).AddError(pa, c.err), lists(time.Hour), t0)
				wantStatus(t, o, c.want)
				wantSummary(t, o, c.sub)
			})
		}
		for name, res := range map[string]execx.Result{
			"truncated": {Stdout: []byte(good), Truncated: true},
			"signaled":  {Stdout: []byte(good), Signaled: true, ExitCode: -1},
		} {
			t.Run(name, func(t *testing.T) {
				o := execAt(updatesProbe(t, nil), newRunner().AddResult(aptArgv, inline(sim, 0)).AddResult(pa, res), lists(time.Hour), t0)
				wantStatus(t, o, result.Error)
			})
		}
	})
}

func TestSecurityUpdatesPolicyBatches(t *testing.T) {
	var inst strings.Builder
	for i := 0; i < 230; i++ {
		fmt.Fprintf(&inst, "Inst pkg-%03d [1] (2 Ubuntu:24.04/noble-updates [amd64])\n", i)
	}
	r := aptRunner(aptOut(230, 0, inst.String()))
	o := execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	wantStatus(t, o, result.Pass)
	calls := r.Calls()
	if len(calls) != 4 {
		t.Fatalf("%d calls, want the simulation and 3 batches", len(calls))
	}
	for i, want := range []int{100, 100, 30} {
		c := calls[i+1].Argv
		if got := len(c) - 7; got != want || c[6] != "--" {
			t.Fatalf("batch %d: %d names, argv %v", i, got, c[:8])
		}
	}
	// beyond the bound the check does not guess
	var many strings.Builder
	for i := 0; i < 2001; i++ {
		fmt.Fprintf(&many, "Inst pkg-%04d [1] (2 Ubuntu:24.04/noble-updates [amd64])\n", i)
	}
	o = execAt(updatesProbe(t, nil), newRunner().AddResult(aptArgv, inline(aptOut(2001, 0, many.String()), 0)), lists(time.Hour), t0)
	wantStatus(t, o, result.Error)
	wantSummary(t, o, "2000")
}
