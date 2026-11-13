package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// sshd line shapes. The user name is attacker-chosen and may contain
// spaces, newlines or the text "from 1.2.3.4 port 5", so the patterns are
// anchored at both ends and the address is the last "from <addr> port <n>"
// of the line, which is the part sshd itself appends after the name.
var (
	sshFailedRE  = regexp.MustCompile(`(?s)\AFailed (?:password|none|keyboard-interactive/pam) for (?:invalid user )?.* from (\S+) port [0-9]+(?: ssh2)?\z`)
	sshInvalidRE = regexp.MustCompile(`(?s)\AInvalid user .* from (\S+) port [0-9]+\z`)
)

// SSHBruteForce fires when one source IP causes Threshold "Failed password"
// or "Invalid user" lines from sshd within Window. Only lines logged by the
// ssh.service or sshd.service unit as root are counted. Lines without a
// port, and any other shape, are ignored.
type SSHBruteForce struct {
	c *windowCounter
	w time.Duration
	n int
}

// NewSSHBruteForce returns the rule, or an error for invalid params.
func NewSSHBruteForce(p Params) (*SSHBruteForce, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &SSHBruteForce{c: newWindowCounter(p), w: p.Window, n: p.Threshold}, nil
}

// ID implements Rule.
func (r *SSHBruteForce) ID() string { return IDSSHBruteForce }

func sshUnit(u string) bool { return u == "ssh.service" || u == "sshd.service" }

// parseSSHFailure returns the raw source address of a failed-login line.
func parseSSHFailure(msg string) (string, bool) {
	m := sshFailedRE.FindStringSubmatch(msg)
	if m == nil {
		m = sshInvalidRE.FindStringSubmatch(msg)
	}
	if m == nil {
		return "", false
	}
	if _, err := netip.ParseAddr(m[1]); err != nil {
		return "", false
	}
	return m[1], true
}

// Evaluate implements Rule.
func (r *SSHBruteForce) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if ev.Kind != event.KindJournal || !sshUnit(ev.SystemdUnit) || !isRoot(ev) {
		return nil
	}
	ip, ok := parseSSHFailure(ev.Message)
	if !ok {
		return nil
	}
	at, crossed := r.c.hit(ip, now)
	if !crossed {
		return nil
	}
	return []event.Signal{{
		RuleID:      IDSSHBruteForce,
		Fingerprint: event.FingerprintOf(IDSSHBruteForce, ip),
		Severity:    SeveritySSHBruteForce,
		Time:        at,
		Notify:      true,
		Subject:     ip,
		Summary:     fmt.Sprintf("%d failed ssh logins from %s within %s", r.n, ip, r.w),
	}}
}
