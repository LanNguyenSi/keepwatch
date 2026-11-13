package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// sshd line shapes. The user name is attacker-chosen and may contain
// spaces, newlines or the text "from 1.2.3.4 port 5", so the patterns are
// anchored at both ends and the address is the last "<addr> port <n>" of the
// line, which is the part sshd itself appends after the name.
//
// Besides "Failed password" and "Invalid user", the per-connection
// "Connection closed by" and "Disconnected from" lines of a pre-auth
// connection are counted: sshd writes them for every refused connection,
// including keyboard-interactive and public key guessing against existing
// accounts, which produce no "Failed ..." line.
var sshFailureREs = []*regexp.Regexp{
	regexp.MustCompile(`(?s)\AFailed (?:password|none|keyboard-interactive(?:/pam)?) for (?:invalid user )?.* from (\S+) port [0-9]+(?: ssh2)?\z`),
	regexp.MustCompile(`(?s)\AInvalid user .* from (\S+) port [0-9]+\z`),
	regexp.MustCompile(`(?s)\AConnection closed by (?:authenticating|invalid) user (?:.* )?(\S+) port [0-9]+ \[preauth\]\z`),
	regexp.MustCompile(`(?s)\ADisconnected from (?:authenticating|invalid) user (?:.* )?(\S+) port [0-9]+ \[preauth\]\z`),
}

// SSHBruteForce fires when one source causes Threshold counted sshd lines
// within Window. Only lines logged by ssh.service, sshd.service or a
// per-connection ssh@<instance>.service or sshd@<instance>.service unit as
// root are counted. IPv4 sources are keyed by address; IPv6 sources by their
// /64 prefix, so a host holding a whole /64 cannot stay below the threshold
// by rotating addresses. Lines without a port, and any other shape, are
// ignored.
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

// sshUnit reports whether u is the ssh service or a per-connection instance
// of the ssh template unit (Accept=yes socket activation).
func sshUnit(u string) bool {
	if u == "ssh.service" || u == "sshd.service" {
		return true
	}
	for _, prefix := range []string{"ssh@", "sshd@"} {
		if strings.HasPrefix(u, prefix) && strings.HasSuffix(u, ".service") &&
			len(u) > len(prefix)+len(".service") {
			return true
		}
	}
	return false
}

// sourceKey returns the key of a source address: the address for IPv4
// (IPv4-mapped IPv6 counts as IPv4) and the /64 prefix for IPv6.
func sourceKey(raw string) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	a = a.WithZone("").Unmap()
	if a.Is4() {
		return a.String(), true
	}
	return netip.PrefixFrom(a, 64).Masked().String(), true
}

// parseSSHFailure returns the source key of a counted sshd line.
func parseSSHFailure(msg string) (string, bool) {
	for _, re := range sshFailureREs {
		if m := re.FindStringSubmatch(msg); m != nil {
			return sourceKey(m[1])
		}
	}
	return "", false
}

// Evaluate implements Rule.
func (r *SSHBruteForce) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if ev.Kind != event.KindJournal || !sshUnit(ev.SystemdUnit) || !isRoot(ev) {
		return nil
	}
	key, ok := parseSSHFailure(ev.Message)
	if !ok {
		return nil
	}
	at, crossed := r.c.hit(key, now)
	if !crossed {
		return nil
	}
	return []event.Signal{{
		RuleID:      IDSSHBruteForce,
		Fingerprint: event.FingerprintOf(IDSSHBruteForce, key),
		Severity:    SeveritySSHBruteForce,
		Time:        at,
		Notify:      true,
		Subject:     key,
		Summary:     fmt.Sprintf("%d failed ssh logins from %s within %s", r.n, key, r.w),
	}}
}
