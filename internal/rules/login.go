package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// IDLoginAnomaly is the rule id of the login rule.
const IDLoginAnomaly = "login_anomaly"

// Severities emitted by the login rule.
const (
	SeverityLoginLearning = result.Info
	SeverityLoginAnomaly  = result.High
)

// Accepted login line shapes, as journald stores sshd's MESSAGE. The user
// name is chosen by the client and may contain spaces, newlines and the
// text "from 1.2.3.4 port 5", so the patterns are anchored at both ends and
// the greedy user makes the address the last one before " port <n>": the
// part sshd itself appends after the name. A publickey line also ends with
// the sshd-appended key type and the "SHA256:" fingerprint, captured as the
// last blank-delimited word. A line that does not match exactly yields
// nothing. The password and keyboard-interactive/pam alternatives carry no
// key: for those logins only the source address is known-checkable.
var loginAcceptedREs = []*regexp.Regexp{
	regexp.MustCompile(`(?s)\AAccepted publickey for (.+) from (\S+) port [0-9]+ ssh2: \S+ (SHA256:\S+)\z`),
	regexp.MustCompile(`(?s)\AAccepted (?:password|keyboard-interactive/pam) for (.+) from (\S+) port [0-9]+ ssh2\z`),
}

// LoginParams configures the login rule. The values come from the caller
// (the daemon takes LearningPeriod from config.Watch.LearningPeriod).
type LoginParams struct {
	// LearningPeriod is how long, measured from the baseline's
	// LearningStart, unknown source addresses and keys are learned as
	// info findings without notifying. It must be positive.
	LearningPeriod time.Duration
}

var errLoginPeriod = errors.New("rules: learning period must be positive")

func (p LoginParams) validate() error {
	if p.LearningPeriod <= 0 {
		return errLoginPeriod
	}
	return nil
}

// LoginAnomaly watches successful logins against a Baseline. During the
// learning phase (while now is before LearningStart + LearningPeriod) every
// new source address or key is added to the baseline and reported as an
// info signal that does not notify. From LearningStart + LearningPeriod on
// (the boundary instant included in "after"), a login from a source address
// or key that is not in the baseline raises one high notifying signal, and
// the entry is added only then, so the same source alerts once. Keys named
// in config authorized_keys.expected can be seeded into the baseline with
// AddKey and count as known from the start.
//
// Only sshd lines are consulted, and only with the trust gate of the brute
// force rule: journald-set unit ssh.service, sshd.service or an ssh@ /
// sshd@ instance, and UID 0. The signal fingerprint is built from the
// rule id and the RAW user with the RAW address (when the address is what
// is new) or the RAW fingerprint of the line (when the key is what is
// new); the baseline stores the canonical address (an IPv6 keeps its full
// form; an IPv4-mapped IPv6 maps to its IPv4, the same source sshd
// reports) and the normalized fingerprint so that equivalent spellings of
// one source match.
//
// The clock follows the Rule contract: a zero now is ignored, a step back
// of at most LearningPeriod is clamped to the latest value seen. A larger
// step back adopts the new value like the other rules, but does not throw
// the baseline away: unlike window state, the baseline is knowledge the
// caller persists, and losing it would mean an alert for every known
// source, which is the wrong direction for a clock correction. A baseline
// restored without a LearningStart (the zero instant) is past its learning
// phase, so unknown sources notify from the first login.
type LoginAnomaly struct {
	mu   sync.Mutex
	p    LoginParams
	b    *Baseline
	last time.Time
}

// NewLoginAnomaly returns the rule over the given baseline, or an error for
// invalid params or a nil baseline.
func NewLoginAnomaly(p LoginParams, b *Baseline) (*LoginAnomaly, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("rules: login rule needs a baseline")
	}
	return &LoginAnomaly{p: p, b: b}, nil
}

// ID implements Rule.
func (r *LoginAnomaly) ID() string { return IDLoginAnomaly }

// parseLoginAddr validates a source address sshd logged and returns its
// canonical form: IPv4-mapped IPv6 becomes the IPv4, everything else keeps
// its full form (an IPv6 is not shortened to a prefix here). A token that
// is not an address is not a login line.
func parseLoginAddr(raw string) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// parseLoginAccepted returns the raw user and raw address, and the raw key
// fingerprint (empty when the line type has no key) of an accepted login
// line, or ok = false. Oversized parsed fields are refused: a field longer
// than the baseline's length bound is not real, and refusing it cannot
// drop an alert a genuine line would raise.
func parseLoginAccepted(msg string) (user, ip, key string, ok bool) {
	for _, re := range loginAcceptedREs {
		m := re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		user, ip = m[1], m[2]
		if len(m) > 3 {
			key = m[3]
		}
		if len(user) > maxBaselineUserLen || len(ip) > maxBaselineEntryLen || len(key) > maxBaselineEntryLen {
			return "", "", "", false
		}
		if key != "" && normalizeKeyFP(key) == "" {
			return "", "", "", false
		}
		return user, ip, key, true
	}
	return "", "", "", false
}

// Evaluate implements Rule.
func (r *LoginAnomaly) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if now.IsZero() {
		return nil
	}
	if ev.Kind != event.KindJournal || !sshUnit(ev.SystemdUnit) || !isRoot(ev) {
		return nil
	}
	user, rawIP, rawKey, ok := parseLoginAccepted(ev.Message)
	if !ok {
		return nil
	}
	ip, ok := parseLoginAddr(rawIP)
	if !ok {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	at, _ := monotonic(&r.last, now, r.p.LearningPeriod)
	ipKnown := r.b.KnownIP(user, ip)
	keyKnown := true
	if rawKey != "" {
		keyKnown = r.b.KnownKey(user, rawKey)
	}
	if ipKnown && keyKnown {
		return nil
	}
	learning := at.Before(r.b.LearningStart().Add(r.p.LearningPeriod))

	// One signal names what is new: the raw address when the address is
	// unknown, else the raw fingerprint of the line.
	part := rawIP
	summary := fmt.Sprintf("login for %s from %s: new source ip %s", user, rawIP, rawIP)
	if ipKnown {
		part = rawKey
		summary = fmt.Sprintf("login for %s from %s: new key %s", user, rawIP, rawKey)
	} else if !keyKnown {
		summary = fmt.Sprintf("login for %s from %s: new source ip %s and new key %s", user, rawIP, rawIP, rawKey)
	}
	sev, notify := SeverityLoginAnomaly, true
	if learning {
		sev, notify = SeverityLoginLearning, false
	}

	// The add comes after the signal is built and, past learning, after
	// the alert: the same source is then known and cannot fire again.
	// A refused add (a cap) leaves it unknown, so it keeps alerting.
	if !ipKnown {
		r.b.AddIP(user, ip)
	}
	if rawKey != "" && !keyKnown {
		r.b.AddKey(user, rawKey)
	}

	return []event.Signal{{
		RuleID:      IDLoginAnomaly,
		Fingerprint: event.FingerprintOf(IDLoginAnomaly, user, part),
		Severity:    sev,
		Time:        at,
		Notify:      notify,
		Subject:     user + "@" + part,
		Summary:     summary,
	}}
}
