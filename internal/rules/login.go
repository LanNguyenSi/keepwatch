package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
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

// Accepted login line shapes, as journald stores sshd's MESSAGE:
// "Accepted <method> for <user> from <addr> port <n> ssh2", with a
// ": <key info>" tail on publickey lines. The user name is chosen by the
// client and may contain spaces, newlines and the text "from 1.2.3.4 port
// 5", so the pattern is anchored at both ends and the greedy user makes
// the address the last one before " port <n>": the part sshd itself
// appends after the name. That greedy choice is only sound when the line
// admits exactly one such split; a certificate ID is free text and can
// carry a " from <addr> port <n> ssh2: ..." fragment of its own, and then
// no split can be trusted (see parseLoginAccepted and the ambiguous
// branch of Evaluate). Every method sshd can print (publickey,
// password, keyboard-interactive, keyboard-interactive/pam, none,
// hostbased, gssapi-with-mic) is accepted; the key is checked only when
// the tail parses (see parseLoginKey). A line that does not match yields
// nothing; an address that is not an address drops the line, since there
// is then nothing to check.
var loginAcceptedRE = regexp.MustCompile(`(?s)\AAccepted (\S+) for (.+) from (\S+) port [0-9]+ ssh2(?:: (.*)\z)?\z`)

// loginSplitTailRE matches one candidate user/address split of an
// Accepted line from its " from " on: an address token with no blank,
// the port, and the line end or the ": <key info>" tail. Each " from "
// occurrence whose suffix matches is a split the line admits; the
// greedy group of loginAcceptedRE picks the last one.
var loginSplitTailRE = regexp.MustCompile(`(?s)\A from \S+ port [0-9]+ ssh2(: .*)?\z`)

// countLoginSplits counts the user/address/port splits of msg, a line
// that loginAcceptedRE matched: every " from <addr> port <n> ssh2" at or
// after userStart (the start of the user group, so the user is
// non-empty) whose suffix ends the line or starts its ": " key info. The
// greedy match itself is always one of them, so a line that matched
// counts at least one; a count above one means the line is ambiguous.
func countLoginSplits(msg string, userStart int) int {
	n := 0
	for off := userStart; off < len(msg); {
		i := strings.Index(msg[off:], " from ")
		if i < 0 {
			return n
		}
		i += off
		if i > userStart && loginSplitTailRE.MatchString(msg[i:]) {
			n++
			if n > 1 {
				return n
			}
		}
		off = i + 1
	}
	return n
}

// parseLoginKey parses the key info an sshd publickey line appends after
// "ssh2: ". The first blank-delimited word is the key type; the user key
// fingerprint is the first following word that starts with "SHA256:",
// which for a certificate line (OpenSSH 8.9, 9.6: "ED25519-CERT
// SHA256:... ID <comment> (serial N) CA <type> SHA256:...") is the
// certificate's own fingerprint, with the ID, serial and CA parts
// ignored. A key part with no usable "SHA256:" fingerprint (an MD5
// fingerprint, a missing or empty one, one that does not normalize to a
// valid stored fingerprint, see validKeyFP) does not parse: the login is
// then checked by address only.
func parseLoginKey(info string) (fp, keyType string, ok bool) {
	typ, rest, found := strings.Cut(info, " ")
	if !found || typ == "" {
		return "", "", false
	}
	for _, w := range strings.Fields(rest) {
		if !strings.HasPrefix(w, "SHA256:") {
			continue
		}
		if validKeyFP(normalizeKeyFP(w)) {
			return w, typ, true
		}
		return "", "", false
	}
	return "", "", false
}

// LoginParams configures the login rule. The values come from the caller
// (the daemon takes LearningPeriod from config.Watch.LearningPeriod and
// KnownKeys from the config authorized_keys.expected entries).
type LoginParams struct {
	// LearningPeriod is how long, measured from the baseline's
	// LearningStart, unknown source addresses and keys are learned as
	// info findings without notifying: learning runs while
	// LearningStart <= now < LearningStart + LearningPeriod, and a time
	// before LearningStart counts as after the learning phase. It must
	// be positive.
	LearningPeriod time.Duration

	// KnownKeys maps a user name to the key fingerprints of config
	// authorized_keys.expected, in any of the forms normalizeKeyFP
	// accepts. They are consulted next to the baseline: a login with one
	// of them is known-key even if the baseline never saw it. They are
	// never written into the baseline and never count against its caps,
	// so a key removed from this input is unknown again on the next
	// construction unless it was learned on its own. Entries that do
	// not normalize to a valid stored fingerprint (see validKeyFP), and
	// user names that are not valid baseline user names (see
	// validUserName), are dropped.
	KnownKeys map[string][]string
}

var errLoginPeriod = errors.New("rules: learning period must be positive")

func (p LoginParams) validate() error {
	if p.LearningPeriod <= 0 {
		return errLoginPeriod
	}
	return nil
}

// LoginAnomaly watches successful logins against a Baseline. Learning runs
// while now is in [LearningStart, LearningStart + LearningPeriod): every
// new source address or key is added to the baseline and reported as an
// info signal that does not notify. At or after LearningStart +
// LearningPeriod (the boundary instant included in "after"), and also at a
// time before LearningStart, a login from a source address or key that is
// neither in the baseline nor in the KnownKeys input raises one high
// notifying signal, and the entry is added only then, so the same source
// alerts once. Keys given in LoginParams.KnownKeys (config
// authorized_keys.expected) are known from the start; they are consulted
// beside the baseline, never written into it, and never counted against
// its caps. Once the rule has seen a time at or past the end of the
// window it marks the baseline's learning phase done, and a later clock
// step back never reopens it.
//
// Every "Accepted <method> for <user> from <addr> port <n> ssh2" line is
// consulted, whichever method sshd printed; the key is checked only when
// the line's key info parses (see parseLoginKey), otherwise the login is
// checked by address only. A line that admits more than one
// user/address/port split (a free-text certificate ID can carry a " from
// <addr> port <n> ssh2: ..." fragment of its own) cannot be trusted for
// any split: it raises one high notifying signal saying it was
// ambiguous, and nothing is learned from it (see parseLoginAccepted).
// Consultation uses the trust gate of the brute
// force rule: journald-set unit ssh.service, sshd.service or an ssh@ /
// sshd@ instance, and UID 0. The signal fingerprint is built from the
// rule id and the RAW user with the RAW address (when the address is what
// is new) or the RAW fingerprint of the line (when the key is what is
// new); the baseline stores the canonical address (an IPv6 keeps its full
// form; an IPv4-mapped IPv6 maps to its IPv4, the same source sshd
// reports) and the normalized fingerprint so that equivalent spellings of
// one source match. The known key type, when the key is what is new, is
// carried into the signal summary.
//
// The clock follows the Rule contract: a zero now is ignored, a step back
// of at most LearningPeriod is clamped to the latest value seen. A larger
// step back adopts the new value like the other rules, but does not throw
// the baseline away: unlike window state, the baseline is knowledge the
// caller persists, and losing it would mean an alert for every known
// source, which is the wrong direction for a clock correction. It also
// cannot reopen the learning phase once a time at or past its end has
// been seen (see the latch above). A baseline restored without a
// LearningStart (the zero instant) is past its learning phase, so unknown
// sources notify from the first login.
type LoginAnomaly struct {
	mu        sync.Mutex
	p         LoginParams
	knownKeys map[string]map[string]bool // user -> normalized KnownKeys input
	b         *Baseline
	last      time.Time
}

// NewLoginAnomaly returns the rule over the given baseline, or an error for
// invalid params or a nil baseline. The KnownKeys input is normalized and
// copied here, so the rule is unaffected by later changes to the caller's
// maps; construct a new rule to apply new config keys.
func NewLoginAnomaly(p LoginParams, b *Baseline) (*LoginAnomaly, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("rules: login rule needs a baseline")
	}
	known := make(map[string]map[string]bool, len(p.KnownKeys))
	for user, fps := range p.KnownKeys {
		if !validUserName(user) {
			continue
		}
		for _, fp := range fps {
			norm := normalizeKeyFP(fp)
			if !validKeyFP(norm) {
				continue
			}
			set := known[user]
			if set == nil {
				set = map[string]bool{}
				known[user] = set
			}
			set[norm] = true
		}
	}
	return &LoginAnomaly{p: p, knownKeys: known, b: b}, nil
}

// ID implements Rule.
func (r *LoginAnomaly) ID() string { return IDLoginAnomaly }

// parseLoginAddr validates a source address sshd logged and returns its
// canonical form: IPv4-mapped IPv6 becomes the IPv4, everything else keeps
// its full form (an IPv6 is not shortened to a prefix here). A token that
// is not an address is not a login line, and an address whose canonical
// form fails validAddrEntry (over the length bound, or an IPv6 zone using
// characters outside the allowed set; netip accepts zones keepwatch will
// not store) yields no signal and no baseline change.
func parseLoginAddr(raw string) (string, bool) {
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	ip := a.Unmap().String()
	if !validAddrEntry(ip) {
		return "", false
	}
	return ip, true
}

// parseLoginAccepted splits an accepted login line into its raw user and
// raw address, and the raw key fingerprint with its key type when the
// line's key info parses (both empty otherwise), or ok = false. It also
// reports the number of user/address/port splits the line admits (see
// countLoginSplits): a certificate ID is free text and may carry a " from
// <addr> port <n> ssh2: ..." fragment of its own, so when more than one
// split is possible the greedy regex would take the wrong one (and an
// oversized greedy user would even drop the line); the line is then
// reported through the ambiguous branch of Evaluate and none of its
// fields are returned. A unique split with a user over the baseline's
// length bound is refused: such a user is not real, and refusing it
// cannot drop an alert a genuine line would raise; an oversized or
// degenerate fingerprint merely leaves the key unparseable, which
// downgrades the check to the address.
func parseLoginAccepted(msg string) (user, ip, key, keyType string, splits int, ok bool) {
	m := loginAcceptedRE.FindStringSubmatchIndex(msg)
	if m == nil {
		return "", "", "", "", 0, false
	}
	splits = countLoginSplits(msg, m[4])
	if splits > 1 {
		return "", "", "", "", splits, true
	}
	user, ip = msg[m[4]:m[5]], msg[m[6]:m[7]]
	if len(user) > maxBaselineUserLen {
		return "", "", "", "", splits, false
	}
	info := ""
	if m[8] >= 0 {
		info = msg[m[8]:m[9]]
	}
	key, keyType, _ = parseLoginKey(info)
	return user, ip, key, keyType, splits, true
}

// Evaluate implements Rule.
func (r *LoginAnomaly) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if now.IsZero() {
		return nil
	}
	if ev.Kind != event.KindJournal || !sshUnit(ev.SystemdUnit) || !isRoot(ev) {
		return nil
	}
	user, rawIP, rawKey, keyType, splits, ok := parseLoginAccepted(ev.Message)
	if !ok {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	at, _ := monotonic(&r.last, now, r.p.LearningPeriod)

	// The latch: a time at or past the end of the learning window ends
	// it for good, whatever this line does.
	start := r.b.LearningStart()
	end := start.Add(r.p.LearningPeriod)
	done := r.b.LearningDone()
	if !done && !at.Before(end) {
		r.b.MarkLearningDone()
		done = true
	}

	if splits > 1 {
		// An ambiguous line: more than one " from <addr> port <n>
		// ssh2" could be the split sshd wrote (the user name and a
		// certificate ID are free text), so no field of it can be
		// trusted. One high notifying signal names the line as
		// ambiguous, whatever the learning phase says, and nothing is
		// learned from it: the baseline is left exactly as it was.
		return []event.Signal{{
			RuleID:      IDLoginAnomaly,
			Fingerprint: event.FingerprintOf(IDLoginAnomaly, ev.Message),
			Severity:    SeverityLoginAnomaly,
			Time:        at,
			Notify:      true,
			Subject:     ev.Message,
			Summary: fmt.Sprintf("accepted login line with %d possible user/address/port splits is ambiguous, nothing learned: %s",
				splits, ev.Message),
		}}
	}

	ip, ok := parseLoginAddr(rawIP)
	if !ok {
		return nil
	}

	ipKnown := r.b.KnownIP(user, ip)
	keyKnown := true
	if rawKey != "" {
		keyKnown = r.b.KnownKey(user, rawKey) || r.knownKeys[user][normalizeKeyFP(rawKey)]
	}
	if ipKnown && keyKnown {
		return nil
	}

	// One signal names what is new: the raw address when the address is
	// unknown, else the raw fingerprint of the line. A known key type is
	// named with the key.
	part := rawIP
	newKey := "new key " + rawKey
	if keyType != "" {
		newKey += " (" + keyType + ")"
	}
	summary := fmt.Sprintf("login for %s from %s: new source ip %s", user, rawIP, rawIP)
	if ipKnown {
		part = rawKey
		summary = fmt.Sprintf("login for %s from %s: %s", user, rawIP, newKey)
	} else if !keyKnown {
		summary = fmt.Sprintf("login for %s from %s: new source ip %s and %s", user, rawIP, rawIP, newKey)
	}
	sev, notify := SeverityLoginAnomaly, true
	// done is false here only if at is still before end (the latch above),
	// so the window test is exactly LearningStart <= at < end.
	if !done && !at.Before(start) {
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
