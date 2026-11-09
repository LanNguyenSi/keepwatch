package probes_test

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func svcArgv(unit string) []string { return []string{"systemctl", "is-active", "--", unit} }

func TestServiceActiveFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		unit    string
		want    result.Status
		detail  string // substring of the evidence detail on fail
	}{
		{"systemctl_active", "fail2ban.service", result.Pass, ""},
		{"systemctl_unattended", "unattended-upgrades.service", result.Pass, ""},
		{"systemctl_inactive", "fail2ban.service", result.Fail, "state: inactive"},
		{"systemctl_failed", "kwfail.service", result.Fail, "state: failed"},
		{"systemctl_activating", "kwslow.service", result.Fail, "state: activating"},
		{"systemctl_unknown_unit", "nosuchunit.service", result.Fail, "inactive"},
		{"systemctl_no_systemd", "fail2ban.service", result.Error, "System has not been booted"},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.fixture, func(t *testing.T) {
				p := prepare(t, "service_active", map[string]any{"service": c.unit})
				r := newRunner().Add(svcArgv(c.unit), v+"/"+c.fixture)
				o := exec(p, r, nil)
				wantStatus(t, o, c.want)
				switch c.want {
				case result.Fail:
					if len(o.Evidence) != 1 || o.Evidence[0].Subject != c.unit || !strings.Contains(o.Evidence[0].Detail, c.detail) {
						t.Fatalf("evidence = %+v", o.Evidence)
					}
				case result.Pass:
					if len(o.Evidence) != 0 {
						t.Fatalf("pass carries evidence: %+v", o.Evidence)
					}
				case result.Error:
					wantSummary(t, o, c.detail)
				}
			})
		}
	}
}

// Ubuntu 24.04 (systemd 255) exits 4 for a unit that does not exist, 22.04
// (systemd 249) exits 3; both print "inactive".
func TestServiceActiveUnknownUnitExit4(t *testing.T) {
	p := prepare(t, "service_active", map[string]any{"service": "nosuchunit.service"})
	o := exec(p, newRunner().Add(svcArgv("nosuchunit.service"), "ubuntu2404/systemctl_unknown_unit"), nil)
	wantStatus(t, o, result.Fail)
	wantSummary(t, o, "inactive")
	if !strings.Contains(o.Evidence[0].Detail, "not found") {
		t.Fatalf("detail = %q", o.Evidence[0].Detail)
	}
}

func TestServiceActiveStrictParsing(t *testing.T) {
	const unit = "fail2ban.service"
	cases := []struct {
		name   string
		stdout string
		exit   int
		want   result.Status
	}{
		{"active exit 0", "active\n", 0, result.Pass},
		{"reloading exit 0", "reloading\n", 0, result.Pass},
		{"inactive with exit 0", "inactive\n", 0, result.Error},
		{"active with exit 3", "active\n", 3, result.Error},
		{"active with exit 4", "active\n", 4, result.Error},
		{"failed with exit 4", "failed\n", 4, result.Error},
		{"empty output exit 0", "", 0, result.Error},
		{"empty output exit 3", "", 3, result.Error},
		{"two lines", "active\nactive\n", 0, result.Error},
		{"unknown state exit 3", "dead-ish\n", 3, result.Error},
		{"exit 1", "inactive\n", 1, result.Error},
		{"exit 2", "inactive\n", 2, result.Error},
		{"exit 5", "inactive\n", 5, result.Error},
		{"exit 255", "active\n", 255, result.Error},
		{"state cut short by a truncated pipe", "activ", 3, result.Error},
		{"non-printable state", "ina\x00ctive\n", 3, result.Error},
	}
	p := prepare(t, "service_active", map[string]any{"service": unit})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(svcArgv(unit), inline(c.stdout, c.exit))
			wantStatus(t, exec(p, r, nil), c.want)
		})
	}
}

func TestServiceActiveFailureModes(t *testing.T) {
	p := prepare(t, "service_active", map[string]any{"service": "ssh.service"})
	commonFailures(t, p, svcArgv("ssh.service"), "systemctl", nil)
}

func TestServiceActiveArgv(t *testing.T) {
	p := prepare(t, "service_active", map[string]any{"service": "ssh.service"})
	r := newRunner().AddResult(svcArgv("ssh.service"), inline("active\n", 0))
	exec(p, r, nil)
	calls := r.Calls()
	if len(calls) != 1 || strings.Join(calls[0].Argv, " ") != "systemctl is-active -- ssh.service" {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestServiceActiveParams(t *testing.T) {
	good := []string{"fail2ban", "fail2ban.service", "ssh@host.service", "a", "user@1000.service", "dev-sda1.device", "A_b:c"}
	for _, s := range good {
		prepare(t, "service_active", map[string]any{"service": s})
	}
	// option injection, shell metacharacters, whitespace, empty, path-like
	bad := []string{"-x", "--help", "--now", "-", "-f.service", "", " ", "a b", "a;b", "$(id)", "a`id`", "a\nb", "a/b", "../x", "a\\x20b", "ünit", "a*", strings.Repeat("a", 129)}
	for _, s := range bad {
		t.Run("service="+s, func(t *testing.T) {
			err := prepareErr(t, "service_active", map[string]any{"service": s})
			if strings.HasPrefix(s, "-") && !strings.Contains(err.Error(), "must not start with") {
				t.Fatalf("a leading dash must be rejected as such, got %v", err)
			}
		})
	}
	prepareErr(t, "service_active", nil)
	prepareErr(t, "service_active", map[string]any{})
	prepareErr(t, "service_active", map[string]any{"service": 42})
	prepareErr(t, "service_active", map[string]any{"service": []any{"ssh"}})
	err := prepareErr(t, "service_active", map[string]any{"service": "ssh", "serviec": "x", "other": 1})
	if !strings.Contains(err.Error(), `"serviec"`) || !strings.Contains(err.Error(), `"other"`) {
		t.Fatalf("unknown keys not named: %v", err)
	}
}
