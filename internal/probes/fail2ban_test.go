package probes_test

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func jailArgv(jail string) []string { return []string{"fail2ban-client", "--", "status", jail} }

func TestFail2banJailFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		jail    string
		want    result.Status
	}{
		{"fail2ban_status_sshd", "sshd", result.Pass},
		{"fail2ban_status_nojail", "nosuchjail", result.Fail},
		// A server that is not running does not prove the jail is absent.
		{"fail2ban_status_server_down", "sshd", result.Error},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.fixture, func(t *testing.T) {
				p := prepare(t, "fail2ban_jail", map[string]any{"jail": c.jail})
				o := exec(p, newRunner().Add(jailArgv(c.jail), v+"/"+c.fixture), nil)
				wantStatus(t, o, c.want)
				if c.want == result.Fail && (len(o.Evidence) != 1 || o.Evidence[0].Subject != "jail/"+c.jail) {
					t.Fatalf("evidence = %+v", o.Evidence)
				}
				if c.want == result.Error {
					wantSummary(t, o, "socket")
				}
			})
		}
	}
}

func TestFail2banJailStrictParsing(t *testing.T) {
	const jail = "sshd"
	cases := []struct {
		name string
		res  execResultT
		want result.Status
	}{
		{"running", execResult("Status for the jail: sshd\n|- Filter\n", "", 0), result.Pass},
		{"running, no trailing newline", execResult("Status for the jail: sshd", "", 0), result.Pass},
		{"running, other jail named", execResult("Status for the jail: recidive\n", "", 0), result.Error},
		{"running, jail name only a prefix", execResult("Status for the jail: sshd-ddos\n", "", 0), result.Error},
		{"exit 0 without output", execResult("", "", 0), result.Error},
		{"exit 0 with the not-exist text", execResult("Sorry but the jail 'sshd' does not exist\n", "", 0), result.Error},
		{"missing jail", execResult("Sorry but the jail 'sshd' does not exist\n", "ERROR NOK\n", 255), result.Fail},
		{"missing jail text for another jail", execResult("Sorry but the jail 'other' does not exist\n", "", 255), result.Error},
		{"missing jail text with another exit status", execResult("Sorry but the jail 'sshd' does not exist\n", "", 1), result.Error},
		{"exit 255 without the text", execResult("", "ERROR Failed to access socket path\n", 255), result.Error},
		{"exit 255 and nothing else", execResult("", "", 255), result.Error},
		{"exit 1", execResult("Status for the jail: sshd\n", "", 1), result.Error},
		{"exit 2", execResult("", "", 2), result.Error},
		{"garbage", execResult("<html>\n", "", 0), result.Error},
	}
	p := prepare(t, "fail2ban_jail", map[string]any{"jail": jail})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(jailArgv(jail), c.res.Result)
			wantStatus(t, exec(p, r, nil), c.want)
		})
	}
}

func TestFail2banJailFailureModes(t *testing.T) {
	p := prepare(t, "fail2ban_jail", map[string]any{"jail": "sshd"})
	commonFailures(t, p, jailArgv("sshd"), "fail2ban-client", nil)
}

func TestFail2banJailParams(t *testing.T) {
	for _, s := range []string{"sshd", "nginx-http-auth", "a", "my_jail.2", "Jail1"} {
		prepare(t, "fail2ban_jail", map[string]any{"jail": s})
	}
	// the command is run after "--"; the rejected leading dash is a second
	// guard that keeps the value from being read as an option.
	bad := []string{"-x", "--help", "-v", "-", "", " ", "a b", "a;b", "$(id)", "a/b", "a\nb", ".hidden", "_x", strings.Repeat("a", 65)}
	for _, s := range bad {
		t.Run("jail="+s, func(t *testing.T) {
			err := prepareErr(t, "fail2ban_jail", map[string]any{"jail": s})
			if strings.HasPrefix(s, "-") && !strings.Contains(err.Error(), "must not start with") {
				t.Fatalf("a leading dash must be rejected as such, got %v", err)
			}
		})
	}
	prepareErr(t, "fail2ban_jail", nil)
	prepareErr(t, "fail2ban_jail", map[string]any{"jail": 1})
	prepareErr(t, "fail2ban_jail", map[string]any{"jail": "sshd", "x": 1})
}

// The jail name is passed after "--" and "status", never as the first
// argument: the argv is pinned.
func TestFail2banJailArgv(t *testing.T) {
	r := newRunner().Add(jailArgv("sshd"), "ubuntu2404/fail2ban_status_sshd")
	exec(prepare(t, "fail2ban_jail", map[string]any{"jail": "sshd"}), r, nil)
	calls := r.Calls()
	if len(calls) != 1 || strings.Join(calls[0].Argv, " ") != "fail2ban-client -- status sshd" {
		t.Fatalf("calls = %+v", calls)
	}
}
