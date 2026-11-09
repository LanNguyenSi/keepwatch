package probes_test

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var sshdArgv = []string{"sshd", "-T"}

func sshdParams(option string, allow ...string) map[string]any {
	l := make([]any, len(allow))
	for i, a := range allow {
		l[i] = a
	}
	return map[string]any{"option": option, "allow": l}
}

func TestSSHDEffectiveFixtures(t *testing.T) {
	rootAllow := []string{"no", "prohibit-password", "without-password"}
	type tc struct {
		fixture string
		params  map[string]any
		want    result.Status
		detail  string
	}
	pw := sshdParams("passwordauthentication", "no")
	root := sshdParams("permitrootlogin", rootAllow...)
	kbd := map[string]any{"option": "kbdinteractiveauthentication", "aliases": []any{"challengeresponseauthentication"}, "allow": []any{"no"}}
	x11 := sshdParams("x11forwarding", "no")
	cases := []tc{
		// distribution defaults
		{"sshd_T_default", pw, result.Fail, "effective value: yes"},
		{"sshd_T_default", root, result.Pass, ""},
		{"sshd_T_default", kbd, result.Pass, ""},
		{"sshd_T_default", x11, result.Fail, "effective value: yes"},
		// a drop-in under sshd_config.d overrides values sshd_config sets
		// explicitly (PasswordAuthentication yes, X11Forwarding yes, ...)
		{"sshd_T_dropin_hardened", pw, result.Pass, ""},
		{"sshd_T_dropin_hardened", root, result.Pass, ""},
		{"sshd_T_dropin_hardened", kbd, result.Pass, ""},
		{"sshd_T_dropin_hardened", x11, result.Pass, ""},
		{"sshd_T_rootlogin_no", pw, result.Pass, ""},
		{"sshd_T_rootlogin_no", root, result.Pass, ""},
		{"sshd_T_dropin_open", pw, result.Fail, "effective value: yes"},
		{"sshd_T_dropin_open", root, result.Fail, "effective value: yes"},
		{"sshd_T_dropin_open", kbd, result.Fail, "effective value: yes"},
		{"sshd_T_dropin_open", x11, result.Fail, "effective value: yes"},
		// failures of sshd -T itself are always error, never pass
		{"sshd_T_bad_config", pw, result.Error, "Bad configuration option"},
		{"sshd_T_no_privsep_dir", pw, result.Error, "privilege separation"},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.fixture+"/"+c.params["option"].(string), func(t *testing.T) {
				p := prepare(t, "sshd_effective", c.params)
				o := exec(p, newRunner().Add(sshdArgv, v+"/"+c.fixture), nil)
				wantStatus(t, o, c.want)
				switch c.want {
				case result.Fail:
					if len(o.Evidence) != 1 || o.Evidence[0].Subject != c.params["option"] || !strings.Contains(o.Evidence[0].Detail, c.detail) {
						t.Fatalf("evidence = %+v", o.Evidence)
					}
				case result.Error:
					wantSummary(t, o, c.detail)
				}
			})
		}
	}
}

// The distribution drop-in case: the main file says "PasswordAuthentication
// yes" after the Include, the drop-in says no, and sshd -T shows the winner.
func TestSSHDEffectiveDropInOverridesMainFile(t *testing.T) {
	for _, v := range versions {
		p := prepare(t, "sshd_effective", sshdParams("passwordauthentication", "no"))
		o := exec(p, newRunner().Add(sshdArgv, v+"/sshd_T_dropin_hardened"), nil)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "passwordauthentication is no")
	}
}

func TestSSHDEffectiveStrictParsing(t *testing.T) {
	pw := prepare(t, "sshd_effective", sshdParams("passwordauthentication", "no"))
	alias := prepare(t, "sshd_effective", map[string]any{
		"option": "kbdinteractiveauthentication", "aliases": []any{"challengeresponseauthentication"}, "allow": []any{"no"}})
	cases := []struct {
		name   string
		p      probes.Probe
		stdout string
		exit   int
		want   result.Status
	}{
		{"pass", pw, "port 22\npasswordauthentication no\n", 0, result.Pass},
		{"case and whitespace in value", pw, "port 22\npasswordauthentication   No \n", 0, result.Pass},
		{"fail", pw, "port 22\npasswordauthentication yes\n", 0, result.Fail},
		{"value that merely contains the allowed one", pw, "passwordauthentication nope\n", 0, result.Fail},
		{"two values, one not allowed", pw, "passwordauthentication no\npasswordauthentication yes\n", 0, result.Fail},
		{"prefix of option is not the option", pw, "passwordauthenticationx no\n", 0, result.Error},
		{"option absent", pw, "port 22\nusepam yes\n", 0, result.Error},
		{"empty output", pw, "", 0, result.Error},
		{"only blank lines", pw, "\n\n", 0, result.Error},
		{"garbage line", pw, "passwordauthentication no\nBad Request: <html>\n", 0, result.Error},
		{"garbage instead of output", pw, "<html>502</html>\n", 0, result.Error},
		{"upper-case keyword", pw, "PasswordAuthentication no\n", 0, result.Error},
		{"leading space on a line", pw, " passwordauthentication no\n", 0, result.Error},
		{"pass output but exit 1", pw, "passwordauthentication no\n", 1, result.Error},
		{"pass output but exit 255", pw, "passwordauthentication no\n", 255, result.Error},
		{"exit 2", pw, "passwordauthentication no\n", 2, result.Error},
		{"keyword without value fails the allowed set", pw, "passwordauthentication\n", 0, result.Fail},
		{"alias used when the option is absent", alias, "challengeresponseauthentication no\n", 0, result.Pass},
		{"alias value is checked", alias, "challengeresponseauthentication yes\n", 0, result.Fail},
		{"primary wins over alias", alias, "kbdinteractiveauthentication yes\nchallengeresponseauthentication no\n", 0, result.Fail},
		{"neither option nor alias", alias, "port 22\n", 0, result.Error},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(sshdArgv, inline(c.stdout, c.exit))
			wantStatus(t, exec(c.p, r, nil), c.want)
		})
	}
}

func TestSSHDEffectiveEmptyOutput(t *testing.T) {
	p := prepare(t, "sshd_effective", sshdParams("passwordauthentication", "no"))
	for _, out := range []string{"", "\n\n"} {
		o := exec(p, newRunner().AddResult(sshdArgv, inline(out, 0)), nil)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "empty output")
	}
}

func TestSSHDEffectiveFailureModes(t *testing.T) {
	p := prepare(t, "sshd_effective", sshdParams("passwordauthentication", "no"))
	commonFailures(t, p, sshdArgv, "sshd", nil)
}

func TestSSHDEffectiveParams(t *testing.T) {
	prepare(t, "sshd_effective", sshdParams("passwordauthentication", "no"))
	prepare(t, "sshd_effective", sshdParams("authenticationmethods", "publickey", "publickey,password"))
	prepare(t, "sshd_effective", map[string]any{"option": "x11forwarding", "allow": []string{"no"}, "aliases": []string{"other"}})

	bad := map[string]map[string]any{
		"missing":             nil,
		"no allow":            {"option": "x11forwarding"},
		"no option":           {"allow": []any{"no"}},
		"empty allow":         {"option": "x11forwarding", "allow": []any{}},
		"allow not a list":    {"option": "x11forwarding", "allow": "no"},
		"allow element int":   {"option": "x11forwarding", "allow": []any{1}},
		"allow upper case":    {"option": "x11forwarding", "allow": []any{"No"}},
		"allow empty value":   {"option": "x11forwarding", "allow": []any{""}},
		"allow with space":    {"option": "x11forwarding", "allow": []any{"a b"}},
		"allow leading dash":  {"option": "x11forwarding", "allow": []any{"-x"}},
		"option upper case":   {"option": "X11Forwarding", "allow": []any{"no"}},
		"option leading dash": {"option": "-T", "allow": []any{"no"}},
		"option empty":        {"option": "", "allow": []any{"no"}},
		"option int":          {"option": 7, "allow": []any{"no"}},
		"option with space":   {"option": "x11 forwarding", "allow": []any{"no"}},
		"alias bad":           {"option": "x11forwarding", "allow": []any{"no"}, "aliases": []any{"Bad Name"}},
		"alias not a list":    {"option": "x11forwarding", "allow": []any{"no"}, "aliases": "other"},
		"unknown key":         {"option": "x11forwarding", "allow": []any{"no"}, "config": "/etc/ssh/sshd_config"},
	}
	for name, params := range bad {
		t.Run(name, func(t *testing.T) { prepareErr(t, "sshd_effective", params) })
	}
}
