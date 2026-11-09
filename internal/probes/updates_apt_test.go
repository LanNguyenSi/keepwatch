package probes_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// rawPolicy is the apt-cache policy answer for pkg-a with the given lines
// after "Version table:", for tests of single line shapes.
func rawPolicy(lines ...string) string {
	return "pkg-a:\n  Installed: 1.0\n  Candidate: 3.0\n  Version table:\n" + strings.Join(lines, "\n") + "\n"
}

func runRawPolicy(t *testing.T, policy string) probes.Outcome {
	t.Helper()
	return execAt(updatesProbe(t, nil), policyRunner(aptOut(1, 0, instOne), policy), lists(time.Hour), t0)
}

// The lines of apt-cache policy are those of the policy function of apt
// (apt-private/private-show.cc in 2.4.15 and 2.8.4):
//
//	version row:  "     " or " *** ", version, " ", priority, and for a phased version " (phased N%)"
//	origin line:  printf("       %4i %s\n", priority, description of the index file)
func TestSecurityUpdatesPolicyLineShapes(t *testing.T) {
	origin := func(prio int, desc string) string { return fmt.Sprintf("       %4d %s", prio, desc) }
	sec := origin(500, "http://archive.example noble-security/main amd64 Packages")
	installed := []string{" *** 1.0 100", origin(100, "/var/lib/dpkg/status")}
	ok := map[string][]string{
		"a phased version row":                   {"     3.0 500 (phased 40%)", sec},
		"a phased version at 0%":                 {"     3.0 500 (phased 0%)", sec},
		"a phased version at 99%":                {"     3.0 500 (phased 99%)", sec},
		"a phased version with a negative prio":  {"     3.0 -1 (phased 5%)", sec},
		"a priority of one digit":                {"     3.0 1", origin(1, "http://archive.example noble-security/main amd64 Packages")},
		"a priority of four digits":              {"     3.0 1001", origin(1001, "http://archive.example noble-security/main amd64 Packages")},
		"a negative priority":                    {"     3.0 -10", origin(-10, "http://archive.example noble-security/main amd64 Packages")},
		"a flat repository":                      {"     3.0 500", origin(500, "http://archive.example ./ Packages")},
		"a local file source":                    {"     3.0 500", origin(500, "file:/srv/repo noble-security/main amd64 Packages")},
		"a status file with a blank in its path": {"     3.0 500", origin(500, "/var/lib/dpkg/my status")},
	}
	for name, rows := range ok {
		t.Run("ok "+name, func(t *testing.T) {
			o := runRawPolicy(t, rawPolicy(append(append([]string{}, rows...), installed...)...))
			if o.Status == result.Error {
				t.Fatalf("%s", o.Summary)
			}
		})
	}
	// the installed version can be phased as well
	t.Run("ok a phased installed row", func(t *testing.T) {
		o := runRawPolicy(t, rawPolicy("     3.0 500", sec, " *** 1.0 100 (phased 40%)", origin(100, "/var/lib/dpkg/status")))
		wantStatus(t, o, result.Fail)
	})
	bad := map[string][]string{
		"phased at 100%":                 {"     3.0 500 (phased 100%)", sec},
		"phased with a leading zero":     {"     3.0 500 (phased 05%)", sec},
		"phased without the percent":     {"     3.0 500 (phased 40)", sec},
		"phased with a blank":            {"     3.0 500 (phased 40 %)", sec},
		"phased with a sign":             {"     3.0 500 (phased -1%)", sec},
		"phased in the middle":           {"     3.0 (phased 40%) 500", sec},
		"phased twice":                   {"     3.0 500 (phased 40%) (phased 40%)", sec},
		"text after phased":              {"     3.0 500 (phased 40%) x", sec},
		"another annotation":             {"     3.0 500 (held)", sec},
		"priority missing":               {"     3.0 (phased 40%)", sec},
		"origin priority of wrong width": {"     3.0 500", "         500 http://archive.example noble-security/main amd64 Packages"},
		"origin without Packages":        {"     3.0 500", origin(500, "http://archive.example noble-security/main amd64")},
		"origin ending in another word":  {"     3.0 500", origin(500, "http://archive.example noble-security/main amd64 Package")},
		"origin with an empty word":      {"     3.0 500", origin(500, "http://archive.example noble-security/main  Packages")},
		"origin with a number too large": {"     3.0 500", "       99999999999999999999 http://archive.example noble-security/main amd64 Packages"},
		"origin with an extra word":      {"     3.0 500", origin(500, "http://archive.example noble-security/main amd64 extra Packages")},
		"origin with a double blank":     {"     3.0 500", origin(500, "http://archive.example  noble-security/main amd64 Packages")},
		"origin suite without a slash":   {"     3.0 500", origin(500, "http://archive.example noble-security amd64 Packages")},
		"origin of a relative path":      {"     3.0 500", origin(500, "var/lib/dpkg/status")},
		"origin priority with a letter":  {"     3.0 500", "       50a http://archive.example noble-security/main amd64 Packages"},
	}
	for name, rows := range bad {
		t.Run("bad "+name, func(t *testing.T) {
			o := runRawPolicy(t, rawPolicy(append(append([]string{}, rows...), installed...)...))
			wantStatus(t, o, result.Error)
		})
	}
}

// The phased row is read, and a security version above the installed one is
// found whether or not the versions are phased.
func TestSecurityUpdatesPhasedVersionsStillFail(t *testing.T) {
	sec := "        500 http://archive.example noble-security/main amd64 Packages"
	upd := "        500 http://archive.example noble-updates/main amd64 Packages"
	dpkg := "        100 /var/lib/dpkg/status"
	for name, policy := range map[string]string{
		"updates and security both phased":   rawPolicy("     3.0 500 (phased 40%)", upd, sec, "     2.0 500 (phased 40%)", upd, sec, " *** 1.0 100", dpkg),
		"updates phased, security not":       rawPolicy("     3.0 500 (phased 0%)", upd, "     2.0 500", sec, " *** 1.0 100", dpkg),
		"the security version only, phased":  rawPolicy("     3.0 500 (phased 0%)", sec, " *** 1.0 100", dpkg),
		"phased on both sides of the status": rawPolicy("     3.0 500 (phased 0%)", sec, " *** 1.0 100 (phased 40%)", dpkg),
	} {
		t.Run(name, func(t *testing.T) {
			o := runRawPolicy(t, policy)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"pkg-a"}) {
				t.Fatalf("subjects %v", subjects(o))
			}
		})
	}
	t.Run("phased updates and no security pocket pass", func(t *testing.T) {
		wantStatus(t, runRawPolicy(t, rawPolicy("     3.0 500 (phased 0%)", upd, " *** 1.0 100", dpkg)), result.Pass)
	})
	t.Run("a phased version below the installed one does not count", func(t *testing.T) {
		wantStatus(t, runRawPolicy(t, rawPolicy("     3.0 500", upd, " *** 2.0 100", dpkg, "     1.0 500 (phased 0%)", sec)), result.Pass)
	})
}

// aptLocalRunner is a runner for the captured simulation and policy answer of
// the local repository scenarios of aptrepo.sh (the package is kwtest).
func aptLocalRunner(t *testing.T, v, sc string) *fake.FakeRunner {
	t.Helper()
	return newRunner().Add(aptArgv, v+"/aptlr_"+sc).Add(policyArgv("kwtest"), v+"/aptlr_"+sc+"_policy")
}

// Scenarios captured on both releases with a local repository (aptrepo.sh):
// kwtest 1.0 is installed, the security and updates suites hold newer versions
// in the states of the table.
func TestSecurityUpdatesLocalRepositoryScenarios(t *testing.T) {
	type want struct {
		status result.Status
		detail string // in the detail of the kwtest item, for a fail
		note   string // in the summary
	}
	cases := []struct {
		scenario string
		want     want
	}{
		{"plain", want{result.Fail, "the security version 1.1 from", ""}},
		{"superseded", want{result.Fail, "the security version 1.1 from", ""}},
		{"phased", want{result.Fail, "", ""}},
		{"phasedonly", want{result.Pass, "", ""}},
		{"secphased", want{result.Fail, "", ""}},
		{"hold", want{result.Fail, "kept back by apt", "1 package(s) not upgraded"}},
		{"holdupdate", want{result.Pass, "", "1 package(s) not upgraded"}},
		{"newdep", want{result.Fail, "kept back by apt", "1 package(s) not upgraded"}},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.scenario, func(t *testing.T) {
				o := execAt(updatesProbe(t, nil), aptLocalRunner(t, v, c.scenario), lists(time.Hour), t0)
				wantStatus(t, o, c.want.status)
				if c.want.status == result.Fail {
					if !eq(subjects(o), []string{"kwtest"}) {
						t.Fatalf("subjects %v", subjects(o))
					}
					if !strings.Contains(o.Evidence[0].Detail, c.want.detail) {
						t.Fatalf("detail %q, want %q in it", o.Evidence[0].Detail, c.want.detail)
					}
				}
				if c.want.note != "" {
					wantSummary(t, o, c.want.note)
				}
			})
		}
	}
	// the cases that the policy lookup of the kept back list closes: without it
	// the held package is not seen
	t.Run("the held package is found through the kept back list only", func(t *testing.T) {
		for _, v := range versions {
			r := newRunner().Add(aptArgv, v+"/aptlr_hold")
			o := execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
			wantStatus(t, o, result.Error) // the policy answer is missing from the runner: it was asked for
		}
	})
}

// A phased update of the real archive (Ubuntu 22.04 has some): the
// capture of apt_real_phased holds the " (phased 40%)" rows of apt-cache policy.
func TestSecurityUpdatesRealPhasedArchive(t *testing.T) {
	r := newRunner().Add(aptArgv, "ubuntu2204/apt_real_phased")
	names := instNames(fixtureFile(t, "ubuntu2204/apt_real_phased.stdout"))
	if len(names) == 0 {
		t.Fatal("the capture upgrades nothing")
	}
	r.Add(policyArgv(names...), "ubuntu2204/apt_policy_real_phased")
	if !strings.Contains(fixtureFile(t, "ubuntu2204/apt_policy_real_phased.stdout"), "(phased ") {
		t.Fatal("the captured policy answer has no phased row")
	}
	o := execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	wantStatus(t, o, result.Fail)
	found := false
	for _, s := range subjects(o) {
		found = found || strings.HasPrefix(s, "libnvidia-common-535-server")
	}
	if !found {
		t.Fatalf("subjects %v", subjects(o))
	}
}

func TestSecurityUpdatesKeptBackList(t *testing.T) {
	sec := "        500 http://archive.example noble-security/main amd64 Packages"
	dpkg := "        100 /var/lib/dpkg/status"
	secPolicy := func(name string) string {
		return strings.ReplaceAll(rawPolicy("     3.0 500", sec, " *** 1.0 100", dpkg), "pkg-a", name)
	}
	kept := func(lines ...string) string {
		return "Reading package lists...\nCalculating upgrade...\nThe following packages have been kept back:\n" + strings.Join(lines, "\n") +
			fmt.Sprintf("\n0 upgraded, 0 newly installed, 0 to remove and %d not upgraded.\n", len(strings.Fields(strings.Join(lines, " "))))
	}
	run := func(sim string, answers map[string]string) (probes.Outcome, *fake.FakeRunner) {
		r := newRunner().AddResult(aptArgv, inline(sim, 0))
		for argsKey, text := range answers {
			r.AddResult(policyArgv(strings.Fields(argsKey)...), inline(text, 0))
		}
		return execAt(updatesProbe(t, nil), r, lists(time.Hour), t0), r
	}
	t.Run("a name on one line", func(t *testing.T) {
		o, _ := run(kept("  pkg-a"), map[string]string{"pkg-a": secPolicy("pkg-a")})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"pkg-a"}) || !strings.Contains(o.Evidence[0].Detail, "kept back by apt") || !strings.Contains(o.Evidence[0].Detail, "installed 1.0") {
			t.Fatalf("evidence %+v", o.Evidence)
		}
	})
	t.Run("names on several lines are all looked up, sorted, after the upgraded ones", func(t *testing.T) {
		sim := "Reading package lists...\nThe following packages have been kept back:\n  zeta pkg-b\n  alpha:i386\n  pkg-b\n" +
			"1 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\nInst up [1] (2 Ubuntu:24.04/noble-updates [amd64])\n"
		names := "up alpha:i386 pkg-b zeta"
		answers := map[string]string{names: rawPolicyNames("up", "alpha:i386", "pkg-b", "zeta")}
		o, r := run(sim, answers)
		wantStatus(t, o, result.Pass)
		if got := strings.Join(r.Calls()[1].Argv[7:], " "); got != names {
			t.Fatalf("asked about %q, want %q", got, names)
		}
	})
	t.Run("apt 2.8 lists the phasing deferrals under a heading of their own", func(t *testing.T) {
		sim := "Reading package lists...\nThe following upgrades have been deferred due to phasing:\n  pkg-a\n  pkg-c\nThe following packages have been kept back:\n  pkg-b\n" +
			"0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n"
		o, r := run(sim, map[string]string{"pkg-a pkg-b pkg-c": secPolicy("pkg-a") + rawPolicyNames("pkg-b") + secPolicy("pkg-c")})
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"pkg-a", "pkg-c"}) || len(r.Calls()) != 2 {
			t.Fatalf("subjects %v, %d calls", subjects(o), len(r.Calls()))
		}
		// the count in the summary must be the sum of both lists
		short := strings.Replace(sim, "3 not upgraded", "2 not upgraded", 1)
		o, _ = run(short, map[string]string{"pkg-a pkg-b pkg-c": secPolicy("pkg-a") + rawPolicyNames("pkg-b") + secPolicy("pkg-c")})
		wantStatus(t, o, result.Error)
	})
	t.Run("the summary and the kept back lists must agree", func(t *testing.T) {
		for name, sim := range map[string]string{
			"a name is missing":      "Reading package lists...\nThe following packages have been kept back:\n  pkg-a\n0 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n",
			"a package is not named": "Reading package lists...\n0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n",
			"too many names":         "Reading package lists...\nThe following packages have been kept back:\n  pkg-a pkg-b\n0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n",
		} {
			o, _ := run(sim, map[string]string{"pkg-a": secPolicy("pkg-a"), "pkg-a pkg-b": secPolicy("pkg-a") + secPolicy("pkg-b")})
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "not upgraded")
			_ = name
		}
	})
	t.Run("a kept back package without a security version is not a failure", func(t *testing.T) {
		upd := rawPolicy("     3.0 500", "        500 http://archive.example noble-updates/main amd64 Packages", " *** 1.0 100", dpkg)
		o, _ := run(kept("  pkg-a"), map[string]string{"pkg-a": upd})
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "1 package(s) not upgraded")
	})
	t.Run("the list ends at the next line that is not indented", func(t *testing.T) {
		sim := "Reading package lists...\nThe following packages have been kept back:\n  pkg-a\nThe following packages will be upgraded:\n  not-a-kept-one\n" +
			"0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n"
		o, r := run(sim, map[string]string{"pkg-a": secPolicy("pkg-a")})
		wantStatus(t, o, result.Fail)
		if len(r.Calls()) != 2 {
			t.Fatalf("calls %+v", r.Calls())
		}
	})
	t.Run("a name that is not a package name is an error and never reaches apt-cache", func(t *testing.T) {
		for _, name := range []string{"A_b", "--version", "a;b", "é", "a/b"} {
			o, r := run(kept("  "+name), nil)
			wantStatus(t, o, result.Error)
			for _, c := range r.Calls() {
				if c.Argv[0] == "apt-cache" {
					t.Fatalf("apt-cache was run for %q", name)
				}
			}
		}
	})
	t.Run("the policy answer is required for a kept back package", func(t *testing.T) {
		o, _ := run(kept("  pkg-a"), map[string]string{"pkg-a": ""})
		wantStatus(t, o, result.Error)
		o, _ = run(kept("  pkg-a"), map[string]string{"pkg-a": secPolicy("pkg-b")})
		wantStatus(t, o, result.Error)
	})
	t.Run("kept back and upgraded packages share the bound", func(t *testing.T) {
		var inst, names strings.Builder
		for i := 0; i < 1500; i++ {
			fmt.Fprintf(&inst, "Inst up-%04d [1] (2 Ubuntu:24.04/noble-updates [amd64])\n", i)
		}
		for i := 0; i < 501; i++ {
			fmt.Fprintf(&names, "  kept-%04d\n", i)
		}
		sim := "Reading package lists...\nThe following packages have been kept back:\n" + names.String() +
			"1500 upgraded, 0 newly installed, 0 to remove and 501 not upgraded.\n" + inst.String()
		o := execAt(updatesProbe(t, nil), newRunner().AddResult(aptArgv, inline(sim, 0)), lists(time.Hour), t0)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "2000")
	})
}

// rawPolicyNames builds an apt-cache policy answer without a security version
// for several packages.
func rawPolicyNames(names ...string) string {
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + ":\n  Installed: 1.0\n  Candidate: 3.0\n  Version table:\n     3.0 500\n        500 http://archive.example noble-updates/main amd64 Packages\n *** 1.0 100\n        100 /var/lib/dpkg/status\n")
	}
	return b.String()
}
