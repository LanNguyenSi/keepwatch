package catalog

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// TestBaseCatalogIsValid fails the build when the embedded catalog is broken,
// not only at runtime: it parses and validates the real embedded file.
func TestBaseCatalogIsValid(t *testing.T) {
	c, err := Base()
	if err != nil {
		t.Fatalf("embedded catalog: %v", err)
	}
	if len(c.Entries()) < 12 {
		t.Fatalf("only %d entries", len(c.Entries()))
	}
}

func TestBaseCatalogCoverage(t *testing.T) {
	c, err := Base()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		kind  string
		param string // a parameter that identifies the check
		value any
	}{
		"services.fail2ban_active":                {"service_active", "service", "fail2ban.service"},
		"services.unattended_upgrades_active":     {"service_active", "service", "unattended-upgrades.service"},
		"packages.fail2ban_installed":             {"package_installed", "package", "fail2ban"},
		"packages.unattended_upgrades_installed":  {"package_installed", "package", "unattended-upgrades"},
		"packages.needrestart_installed":          {"package_installed", "package", "needrestart"},
		"ssh.password_authentication":             {"sshd_effective", "option", "passwordauthentication"},
		"ssh.permit_root_login":                   {"sshd_effective", "option", "permitrootlogin"},
		"ssh.keyboard_interactive_authentication": {"sshd_effective", "option", "kbdinteractiveauthentication"},
		"ssh.x11_forwarding":                      {"sshd_effective", "option", "x11forwarding"},
		"fail2ban.sshd_jail":                      {"fail2ban_jail", "jail", "sshd"},
		"network.listeners":                       {"listeners", "", nil},
		"system.reboot_required":                  {"reboot_required", "", nil},
	}
	for id, w := range want {
		e, ok := c.Get(id)
		if !ok {
			t.Errorf("missing check %s", id)
			continue
		}
		if e.Kind != w.kind {
			t.Errorf("%s: kind %s, want %s", id, e.Kind, w.kind)
		}
		if w.param != "" && e.Params[w.param] != w.value {
			t.Errorf("%s: %s = %v, want %v", id, w.param, e.Params[w.param], w.value)
		}
		if e.Title == "" || e.Rationale == "" || e.FixHint == "" {
			t.Errorf("%s: incomplete entry %+v", id, e)
		}
	}
	// sshd -T prints a configured "prohibit-password" as "without-password",
	// and 22.04 and 24.04 print the keyboard-interactive option under its
	// current name; the catalog has to allow exactly what they print.
	root, _ := c.Get("ssh.permit_root_login")
	allow := strings.Join(toStrings(root.Params["allow"]), ",")
	if allow != "no,prohibit-password,without-password" {
		t.Errorf("permitrootlogin allow = %s", allow)
	}
	kbd, _ := c.Get("ssh.keyboard_interactive_authentication")
	if a := toStrings(kbd.Params["aliases"]); len(a) != 1 || a[0] != "challengeresponseauthentication" {
		t.Errorf("kbd aliases = %v", a)
	}
}

func toStrings(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, e := range l {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func TestEntriesAreOrderedAndCopied(t *testing.T) {
	c, err := Base()
	if err != nil {
		t.Fatal(err)
	}
	a := c.Entries()
	if a[0].ID != "services.fail2ban_active" {
		t.Fatalf("first = %s", a[0].ID)
	}
	a[0].ID = "tampered"
	if c.Entries()[0].ID != "services.fail2ban_active" {
		t.Fatal("Entries returned the internal slice")
	}
	if !c.Has("ssh.x11_forwarding") || c.Has("nope.nope") {
		t.Fatal("Has")
	}
	if _, ok := c.Get("nope.nope"); ok {
		t.Fatal("Get found a missing id")
	}
}

const okEntry = `
  - id: a.b
    title: T
    kind: service_active
    params: {service: ssh.service}
    severity: low
    rationale: R
    fix_hint: F
`

func doc(entries ...string) []byte { return []byte("checks:\n" + strings.Join(entries, "")) }

func TestParse(t *testing.T) {
	if c, err := Parse(doc(okEntry)); err != nil || len(c.Entries()) != 1 || c.Entries()[0].Severity != result.Low {
		t.Fatalf("valid catalog: %v", err)
	}
	cases := []struct {
		name string
		data []byte
		want string // substring of the error
	}{
		{"duplicate id", doc(okEntry, okEntry), "duplicate id"},
		{"unknown kind", doc(strings.Replace(okEntry, "service_active", "teleport", 1)), `unknown kind "teleport"`},
		{"empty kind", doc(strings.Replace(okEntry, "kind: service_active", "kind: ''", 1)), "unknown kind"},
		{"bad severity", doc(strings.Replace(okEntry, "severity: low", "severity: urgent", 1)), "severity"},
		{"upper-case severity", doc(strings.Replace(okEntry, "severity: low", "severity: High", 1)), "severity"},
		{"missing severity", doc(strings.Replace(okEntry, "    severity: low\n", "", 1)), "severity"},
		{"missing title", doc(strings.Replace(okEntry, "title: T", "title: ''", 1)), "title is required"},
		{"missing rationale", doc(strings.Replace(okEntry, "rationale: R", "rationale: '  '", 1)), "rationale is required"},
		{"missing fix_hint", doc(strings.Replace(okEntry, "    fix_hint: F\n", "", 1)), "fix_hint is required"},
		{"single-segment id", doc(strings.Replace(okEntry, "id: a.b", "id: exception_expired", 1)), "id must be dotted"},
		{"upper-case id", doc(strings.Replace(okEntry, "id: a.b", "id: A.b", 1)), "id must be dotted"},
		{"id with space", doc(strings.Replace(okEntry, "id: a.b", "id: 'a. b'", 1)), "id must be dotted"},
		{"id with trailing dot", doc(strings.Replace(okEntry, "id: a.b", "id: 'a.b.'", 1)), "id must be dotted"},
		{"params the kind rejects", doc(strings.Replace(okEntry, "ssh.service", "-x", 1)), "must not start with"},
		{"unknown param", doc(strings.Replace(okEntry, "{service: ssh.service}", "{service: ssh.service, extra: 1}", 1)), `unknown parameter "extra"`},
		{"missing param", doc(strings.Replace(okEntry, "params: {service: ssh.service}", "params: {}", 1)), "service: required"},
		{"no params at all", doc(strings.Replace(okEntry, "    params: {service: ssh.service}\n", "", 1)), "service: required"},
		{"unknown yaml key", doc(strings.Replace(okEntry, "rationale: R", "rationale: R\n    owner: me", 1)), "owner"},
		{"unknown top-level key", append(doc(okEntry), []byte("version: 2\n")...), "version"},
		{"duplicate yaml key", doc(strings.Replace(okEntry, "title: T", "title: T\n    title: U", 1)), "already defined"},
		{"two documents", append(doc(okEntry), []byte("---\nchecks: []\n")...), "more than one"},
		{"empty input", []byte(""), "empty"},
		{"no checks", []byte("checks: []\n"), "no checks"},
		{"checks not a list", []byte("checks: {a: b}\n"), "catalog"},
		{"not yaml", []byte("checks: [unclosed\n"), "catalog"},
		{"severity not a string", doc(strings.Replace(okEntry, "severity: low", "severity: [low]", 1)), "catalog"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, err := Parse(c.data)
			if err == nil {
				t.Fatalf("Parse succeeded: %+v", cat.Entries())
			}
			if cat != nil {
				t.Fatalf("catalog returned together with an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	bad := strings.NewReplacer("kind: service_active", "kind: nope", "severity: low", "severity: nope")
	_, err := Parse(doc(bad.Replace(okEntry), strings.Replace(okEntry, "a.b", "A.B", 1)))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, sub := range []string{"unknown kind", "severity", "id must be dotted"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error %q lacks %q", err, sub)
		}
	}
}
