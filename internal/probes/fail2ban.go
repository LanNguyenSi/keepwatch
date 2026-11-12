package probes

import (
	"context"
	"fmt"
	"regexp"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// jailPattern limits jail names to letters, digits and "_.-", starting with
// a letter or digit.
var jailPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// fail2banJail checks that a fail2ban jail is configured and running.
//
// Parameters:
//
//	jail  (string, required)  jail name, for example "sshd"
//
// It runs "fail2ban-client -- status <jail>". The "--" ends option parsing
// (fail2ban-client 0.11 and 1.0 both accept it before the command), and the
// name pattern with its rejected leading "-" is a second guard that keeps
// the value from becoming an option. The documented exit statuses it
// interprets:
//
//	0    the first stdout line is "Status for the jail: <jail>": pass.
//	255  stdout is "Sorry but the jail '<jail>' does not exist" (the jail
//	     is not configured or not enabled in the running server): fail.
//	     fail2ban-client also exits 255 for every other failure, for
//	     example a server that is not running ("Failed to access socket
//	     path"); that is error, because the jail's state is unknown.
//
// Any other status, or output that does not match, is error.
//
// The kind has no list parameters.
type fail2banJail struct{}

func (fail2banJail) Name() string       { return "fail2ban_jail" }
func (fail2banJail) Programs() []string { return []string{"fail2ban-client"} }

func (fail2banJail) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	jail := p.str("jail", true, "", argPattern("jail name", jailPattern))
	if err := p.err(); err != nil {
		return nil, err
	}
	return jailProbe{jail: jail}, nil
}

type jailProbe struct{ jail string }

func (j jailProbe) Run(ctx context.Context, env *Env) Outcome {
	res, out := run(ctx, env, []string{"fail2ban-client", "--", "status", j.jail}, 0)
	if out != nil {
		return *out
	}
	first := firstLine(res.Stdout)
	switch res.ExitCode {
	case 0:
		if first == "Status for the jail: "+j.jail {
			return Outcome{Status: result.Pass, Summary: fmt.Sprintf("fail2ban jail %s is running", j.jail)}
		}
		return *errorOutcome("fail2ban-client -- status %s: unexpected output %s", j.jail, quoted(first))
	case 255:
		if first == "Sorry but the jail '"+j.jail+"' does not exist" {
			return Outcome{
				Status:   result.Fail,
				Summary:  fmt.Sprintf("fail2ban jail %s does not exist", j.jail),
				Evidence: []result.Evidence{{Subject: "jail/" + j.jail, Detail: "the running fail2ban server has no such jail"}},
			}
		}
	}
	return *unexpectedExit("fail2ban-client", res)
}
