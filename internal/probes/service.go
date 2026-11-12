package probes

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// unitPattern is the set of systemd unit names accepted: ASCII letters,
// digits and ":_.@-", starting with a letter or digit. The backslash escape
// of systemd is not accepted.
var unitPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,127}$`)

// serviceActive checks that a systemd unit is active.
//
// Parameters:
//
//	service  (string, required)  unit name, for example "fail2ban.service"
//
// It runs "systemctl is-active -- <service>" and reads the state systemctl
// prints. The documented exit statuses it interprets:
//
//	0  active, reloading or refreshing: the unit is running; pass.
//	3  inactive, failed, activating, deactivating or maintenance: fail,
//	   with the printed state as the detail. systemd 249 (Ubuntu 22.04)
//	   also uses 3 with state "inactive" for a unit that does not exist.
//	4  state "inactive": the unit does not exist (systemd 255, Ubuntu
//	   24.04); fail.
//
// Any other status is error, as is a state that does not belong to the
// status or output with more than one line (for example systemctl failing
// to reach systemd: "System has not been booted with systemd as init
// system" exits 1 and is an error, not a fail).
//
// The kind has no list parameters.
type serviceActive struct{}

func (serviceActive) Name() string       { return "service_active" }
func (serviceActive) Programs() []string { return []string{"systemctl"} }

func (serviceActive) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	svc := p.str("service", true, "", argPattern("unit name", unitPattern))
	if err := p.err(); err != nil {
		return nil, err
	}
	return serviceProbe{unit: svc}, nil
}

type serviceProbe struct{ unit string }

var (
	runningStates = map[string]bool{"active": true, "reloading": true, "refreshing": true}
	stoppedStates = map[string]bool{"inactive": true, "failed": true, "activating": true, "deactivating": true, "maintenance": true}
)

func (s serviceProbe) Run(ctx context.Context, env *Env) Outcome {
	argv := []string{"systemctl", "is-active", "--", s.unit}
	res, out := run(ctx, env, argv, 0)
	if out != nil {
		return *out
	}
	if code := res.ExitCode; code != 0 && code != 3 && code != 4 {
		return *unexpectedExit("systemctl", res)
	}
	state, ok := singleLine(res.Stdout)
	if !ok {
		return *errorOutcome("systemctl is-active %s: expected one line of output, got %d bytes", s.unit, len(res.Stdout))
	}
	switch res.ExitCode {
	case 0:
		if runningStates[state] {
			return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%s is %s", s.unit, state)}
		}
	case 3:
		if stoppedStates[state] {
			return s.fail(state, state)
		}
	case 4:
		if state == "inactive" {
			return s.fail(state, "inactive (unit not found)")
		}
	}
	return *errorOutcome("systemctl is-active %s: state %s does not fit exit status %d", s.unit, quoted(state), res.ExitCode)
}

func (s serviceProbe) fail(state, detail string) Outcome {
	return Outcome{
		Status:   result.Fail,
		Summary:  fmt.Sprintf("%s is not active (%s)", s.unit, state),
		Evidence: []result.Evidence{{Subject: s.unit, Detail: "state: " + detail}},
	}
}

// singleLine returns the output as one trimmed, non-empty line.
func singleLine(b []byte) (string, bool) {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" || strings.ContainsAny(s, "\n\r") {
		return "", false
	}
	return strings.TrimSpace(s), true
}
