package probes_test

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// The fixtures aptphasing_<context>_<mode> were captured by aptphasing.sh from
// one host with a local repository: kwdep needs a new package, kwph1 to kwph3
// have a phased update (Phased-Update-Percentage: 0), kwsec has a security fix
// and kwsecph a security fix that is phased. The context is "direct" (the
// commands run as root in a shell) or "service" (the same commands in a unit
// with the hardening of keepwatch-check.service). The mode is the apt options:
// "default" none, "fixed" the option the probe sets, "cap" the host has switched
// APT::Get::Phase-Policy on, "capfixed" both.

// phasedHeld matches the three phased packages under the heading apt puts
// them under: "kept back" (apt 2.4) or "deferred due to phasing" (apt 2.8).
var phasedHeld = regexp.MustCompile(`(kept back|deferred due to phasing):\n  kwph1 kwph2 kwph3\n`)

// phasingRunner answers the probe with the captured simulation and the
// captured apt-cache policy answer for the packages it names.
func phasingRunner(t *testing.T, v, ctx, mode string) *fake.FakeRunner {
	t.Helper()
	name := "aptphasing_" + ctx + "_" + mode
	names := instNames(fixtureFile(t, v+"/"+name+".stdout"))
	if len(names) == 0 {
		t.Fatalf("%s/%s names no package", v, name)
	}
	return newRunner().Add(aptArgv, v+"/"+name).Add(policyArgv(names...), v+"/"+name+"_policy")
}

func runPhasing(t *testing.T, v, ctx, mode string) probes.Outcome {
	t.Helper()
	return execAt(updatesProbe(t, nil), phasingRunner(t, v, ctx, mode), lists(time.Hour), t0)
}

// With the option the probe sets, the service and the direct run get the same
// answer from apt, byte for byte, and so the same summary and evidence.
func TestSecurityUpdatesPhasingSameInServiceAndDirectRun(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			for _, part := range []string{"", "_policy"} {
				d := fixtureFile(t, v+"/aptphasing_direct_fixed"+part+".stdout")
				s := fixtureFile(t, v+"/aptphasing_service_fixed"+part+".stdout")
				if d != s {
					t.Fatalf("the captured apt output differs between the contexts%s:\ndirect:\n%s\nservice:\n%s", part, d, s)
				}
			}
			direct := runPhasing(t, v, "direct", "fixed")
			service := runPhasing(t, v, "service", "fixed")
			wantStatus(t, direct, result.Fail)
			if !reflect.DeepEqual(direct, service) {
				t.Fatalf("direct and service differ:\n%+v\n%+v", direct, service)
			}
			if got := subjects(direct); !eq(got, []string{"kwsec", "kwsecph"}) {
				t.Fatalf("subjects %v", got)
			}
			// kwnew, kwdep and the three phased updates; nothing is held back
			wantSummary(t, direct, "5 other upgrade(s) pending")
			if strings.Contains(direct.Summary, "not upgraded") {
				t.Fatalf("summary %q", direct.Summary)
			}
		})
	}
}

// Without the option the two contexts differ in what apt holds back, and the
// captures show why: ischroot says "chroot" in the service. The security list is
// the same.
func TestSecurityUpdatesPhasingDifferenceWithoutTheOption(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			if got := strings.TrimSpace(fixtureFile(t, v+"/aptphasing_ischroot_direct.txt")); got != "ischroot -t: 1" {
				t.Fatalf("direct: %q", got)
			}
			if got := strings.TrimSpace(fixtureFile(t, v+"/aptphasing_ischroot_service.txt")); got != "ischroot -t: 0" {
				t.Fatalf("service: %q", got)
			}
			dsim := fixtureFile(t, v+"/aptphasing_direct_default.stdout")
			ssim := fixtureFile(t, v+"/aptphasing_service_default.stdout")
			if !phasedHeld.MatchString(dsim) || phasedHeld.MatchString(ssim) {
				t.Fatalf("the phased packages are not held back in the direct run only:\n%s\n%s", dsim, ssim)
			}
			if !strings.Contains(ssim, "Inst kwph1 [1.0] (1.1 ") {
				t.Fatalf("the service does not upgrade kwph1:\n%s", ssim)
			}
			direct := runPhasing(t, v, "direct", "default")
			service := runPhasing(t, v, "service", "default")
			wantStatus(t, direct, result.Fail)
			wantStatus(t, service, result.Fail)
			if !eq(subjects(direct), []string{"kwsec", "kwsecph"}) || !reflect.DeepEqual(direct.Evidence, service.Evidence) {
				t.Fatalf("the security lists differ:\n%+v\n%+v", direct.Evidence, service.Evidence)
			}
			wantSummary(t, direct, "2 other upgrade(s) pending; 3 package(s) not upgraded (kept back by apt)")
			wantSummary(t, service, "5 other upgrade(s) pending; package lists")
		})
	}
}

// A host that switches APT::Get::Phase-Policy on gets the priority of a phased
// version capped at 1, so a phased security fix is neither upgraded nor named
// as held back; with the option the probe sets, it is found.
func TestSecurityUpdatesPhasePolicyDoesNotHideASecurityFix(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			// what apt printed without the option: kwsecph is nowhere in it
			sim := fixtureFile(t, v+"/aptphasing_direct_cap.stdout")
			if strings.Contains(sim, "kwsecph") {
				t.Fatalf("the capture without the option names kwsecph:\n%s", sim)
			}
			if got := subjects(runPhasing(t, v, "direct", "cap")); !eq(got, []string{"kwsec"}) {
				t.Fatalf("without the option, subjects %v", got)
			}
			for _, ctx := range []string{"direct", "service"} {
				o := runPhasing(t, v, ctx, "capfixed")
				wantStatus(t, o, result.Fail)
				if got := subjects(o); !eq(got, []string{"kwsec", "kwsecph"}) {
					t.Fatalf("%s with the option, subjects %v", ctx, got)
				}
			}
		})
	}
}
