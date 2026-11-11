package probes_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// versions are the Ubuntu releases the fixtures were captured on.
var versions = []string{"ubuntu2204", "ubuntu2404"}

// newRunner returns a FakeRunner reading the captured fixtures.
func newRunner() *fake.FakeRunner { return fake.New(os.DirFS("testdata")) }

// shown is what a report prints for a text of a probe: the probes keep the
// text as the host gave it, and this one function is the only change made.
func shown(s string) string { return redact.Default().Clean(s) }

func prepare(t *testing.T, kind string, params map[string]any) probes.Probe {
	t.Helper()
	k, ok := probes.Lookup(kind)
	if !ok {
		t.Fatalf("kind %q is not registered", kind)
	}
	p, err := k.Prepare(params)
	if err != nil {
		t.Fatalf("Prepare(%v): %v", params, err)
	}
	return p
}

func prepareErr(t *testing.T, kind string, params map[string]any) error {
	t.Helper()
	k, ok := probes.Lookup(kind)
	if !ok {
		t.Fatalf("kind %q is not registered", kind)
	}
	p, err := k.Prepare(params)
	if err == nil {
		t.Fatalf("Prepare(%v) = %v, want an error", params, p)
	}
	if p != nil {
		t.Fatalf("Prepare returned a probe together with an error")
	}
	return err
}

// exec runs p with the given runner and files.
func exec(p probes.Probe, r execx.Runner, files probes.FS, allow ...probes.ListenerRule) probes.Outcome {
	if files == nil {
		files = probestest.MemFS{}
	}
	return p.Run(context.Background(), &probes.Env{Runner: r, FS: files, ListenerAllow: allow})
}

func wantStatus(t *testing.T, o probes.Outcome, want result.Status) {
	t.Helper()
	if o.Status != want {
		t.Fatalf("status = %s (%s), want %s; evidence %+v", o.Status, o.Summary, want, o.Evidence)
	}
	if o.Status == result.Skipped && len(o.Evidence) != 0 {
		t.Fatalf("skipped outcome carries evidence: %+v", o.Evidence)
	}
	// An error keeps confirmed failing items only when it says the picture
	// is partial.
	if o.Status == result.Error && len(o.Evidence) != 0 && !strings.Contains(o.Summary, "partial") {
		t.Fatalf("error outcome carries evidence without saying it is partial: %q %+v", o.Summary, o.Evidence)
	}
	if o.Summary == "" {
		t.Fatalf("empty summary")
	}
}

func wantSummary(t *testing.T, o probes.Outcome, sub string) {
	t.Helper()
	if !strings.Contains(o.Summary, sub) {
		t.Fatalf("summary %q does not contain %q", o.Summary, sub)
	}
}

func subjects(o probes.Outcome) []string {
	var s []string
	for _, e := range o.Evidence {
		s = append(s, e.Subject)
	}
	return s
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func inline(stdout string, exit int) execx.Result {
	return execx.Result{Stdout: []byte(stdout), ExitCode: exit}
}

// commonFailures runs the failure modes that every kind handles the same way
// against argv and checks the resulting status. setup registers whatever
// else the probe runs besides argv (the other half of a kind with two
// commands).
func commonFailures(t *testing.T, p probes.Probe, argv []string, program string, files probes.FS, setup ...func(*fake.FakeRunner)) {
	t.Helper()
	cases := []struct {
		name string
		add  func(*fake.FakeRunner)
		want result.Status
		sub  string
	}{
		{"program missing", func(f *fake.FakeRunner) { f.AddError(argv, execx.ErrNotFound) }, result.Skipped, program},
		{"not allowlisted", func(f *fake.FakeRunner) { f.AddError(argv, execx.ErrNotAllowed) }, result.Error, "allowlist"},
		{"timeout", func(f *fake.FakeRunner) { f.AddError(argv, execx.ErrTimeout) }, result.Error, "timed out"},
		{"io timeout", func(f *fake.FakeRunner) { f.AddError(argv, execx.ErrIOTimeout) }, result.Error, "incomplete"},
		{"pipes cut, exit 0", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{Stdout: []byte("x"), IOIncomplete: true})
		}, result.Error, "incomplete"},
		{"pipes cut, exit 1", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{Stdout: []byte("x"), ExitCode: 1, IOIncomplete: true})
		}, result.Error, "incomplete"},
		{"pipes cut, exit 3", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{Stdout: []byte("x"), ExitCode: 3, IOIncomplete: true})
		}, result.Error, "incomplete"},
		{"other error", func(f *fake.FakeRunner) { f.AddError(argv, os.ErrPermission) }, result.Error, "failed"},
		{"truncated", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{Stdout: []byte("x"), Truncated: true})
		}, result.Error, "truncated"},
		{"signaled", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{ExitCode: -1, Signaled: true})
		}, result.Error, "terminated"},
		{"killed without signal flag", func(f *fake.FakeRunner) {
			f.AddResult(argv, execx.Result{ExitCode: -1})
		}, result.Error, "terminated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := fake.New(os.DirFS("testdata"))
			for _, s := range setup {
				s(f)
			}
			c.add(f)
			o := exec(p, f, files)
			wantStatus(t, o, c.want)
			wantSummary(t, o, c.sub)
		})
	}
}

// execResultT wraps an execx.Result so tables can build one from strings.
type execResultT struct{ execx.Result }

func execResult(stdout, stderr string, exit int) execResultT {
	return execResultT{execx.Result{Stdout: []byte(stdout), Stderr: []byte(stderr), ExitCode: exit}}
}

// TestPlausibleOutputIsNotTrusted: output that looks like a pass is an error
// when the run was cut (truncated, killed), whatever the exit status says.
func TestPlausibleOutputIsNotTrusted(t *testing.T) {
	good := map[string]struct {
		params map[string]any
		argv   []string
		stdout string
	}{
		"service_active":    {map[string]any{"service": "ssh.service"}, svcArgv("ssh.service"), "active\n"},
		"package_installed": {map[string]any{"package": "fail2ban"}, pkgArgv("fail2ban"), "install ok installed\t1.0\n"},
		"sshd_effective":    {sshdParams("passwordauthentication", "no"), sshdArgv, "passwordauthentication no\n"},
		"fail2ban_jail":     {map[string]any{"jail": "sshd"}, jailArgv("sshd"), "Status for the jail: sshd\n"},
		"reboot_required":   {nil, needrestartArgv, needrestartOut("1")},
	}
	for kind, g := range good {
		p := prepare(t, kind, g.params)
		for name, res := range map[string]execx.Result{
			"truncated":                 {Stdout: []byte(g.stdout), Truncated: true},
			"pipes cut":                 {Stdout: []byte(g.stdout), IOIncomplete: true},
			"pipes cut after a failure": {Stdout: []byte(g.stdout), IOIncomplete: true, ExitCode: 1},
			"signaled":                  {Stdout: []byte(g.stdout), Signaled: true, ExitCode: -1},
			"killed":                    {Stdout: []byte(g.stdout), ExitCode: -1},
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				o := exec(p, newRunner().AddResult(g.argv, res), probestest.MemFS{})
				wantStatus(t, o, result.Error)
			})
		}
		t.Run(kind+"/sanity", func(t *testing.T) {
			o := exec(p, newRunner().AddResult(g.argv, inline(g.stdout, 0)), probestest.MemFS{})
			wantStatus(t, o, result.Pass)
		})
	}
	// listeners reads two commands: either one cut makes the check an error
	lp := prepare(t, "listeners", nil)
	tcp := "LISTEN 0 5 0.0.0.0:22 0.0.0.0:*\n"
	for _, cut := range []string{"tcp", "udp"} {
		r := newRunner()
		for proto, argv := range map[string][]string{"tcp": ssTCP, "udp": ssUDP} {
			res := inline("", 0)
			if proto == "tcp" {
				res = inline(tcp, 0)
			}
			if proto == cut {
				res.Truncated = true
			}
			r.AddResult(argv, res)
		}
		wantStatus(t, exec(lp, r, nil, rule("tcp", 22, "*")), result.Error)
	}
}

// wantCapped checks a capped evidence list and the set that goes with it: the
// list ends in the marker, the set has total distinct members, lists them all,
// and every item before the marker is a member.
func wantCapped(t *testing.T, ev []result.Evidence, set *result.EvidenceSet, total int) {
	t.Helper()
	if set == nil || len(ev) == 0 || !strings.HasSuffix(ev[len(ev)-1].Subject, " more not shown)") {
		t.Fatalf("the list does not end in a marker, or there is no set: set %v, %+v", set != nil, ev)
	}
	if set.Total != total || len(set.Keys) != total || set.Digest != result.DigestOfKeys(set.Keys) {
		t.Fatalf("set total %d, %d keys (want %d), digest %q", set.Total, len(set.Keys), total, set.Digest)
	}
	member := map[string]bool{}
	for _, k := range set.Keys {
		member[k] = true
	}
	for _, e := range ev[:len(ev)-1] {
		if !member[result.SubjectKey(e.Subject)] {
			t.Fatalf("item %q is not a member of the set", e.Subject)
		}
	}
}
