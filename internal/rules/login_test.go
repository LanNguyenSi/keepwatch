package rules

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// loginRule returns a rule over a fresh baseline whose learning phase starts
// at start, with the given period; tests pass both explicitly.
func loginRule(t *testing.T, start time.Time, period time.Duration) (*LoginAnomaly, *Baseline) {
	t.Helper()
	b := NewBaseline(start)
	r, err := NewLoginAnomaly(LoginParams{LearningPeriod: period}, b)
	if err != nil {
		t.Fatal(err)
	}
	return r, b
}

const loginPeriod = 7 * 24 * time.Hour

func acceptedPub(user, ip, typ, fp string) string {
	return fmt.Sprintf("Accepted publickey for %s from %s port 4242 ssh2: %s %s", user, ip, typ, fp)
}

func acceptedPass(user, ip string) string {
	return fmt.Sprintf("Accepted password for %s from %s port 4242 ssh2", user, ip)
}

func acceptedKbd(user, ip string) string {
	return fmt.Sprintf("Accepted keyboard-interactive/pam for %s from %s port 4242 ssh2", user, ip)
}

func TestLoginParamsValidation(t *testing.T) {
	b := NewBaseline(t0)
	if _, err := NewLoginAnomaly(LoginParams{}, nil); err == nil {
		t.Error("zero period: want error")
	}
	if _, err := NewLoginAnomaly(LoginParams{LearningPeriod: -time.Second}, b); err == nil {
		t.Error("negative period: want error")
	}
	if _, err := NewLoginAnomaly(LoginParams{LearningPeriod: time.Hour}, nil); err == nil {
		t.Error("nil baseline: want error")
	}
}

// During the learning phase every new source is added and reported as an
// info signal that does not notify; the second login from it is silent.
func TestLoginLearningPhaseAddsAndStaysSilent(t *testing.T) {
	r, b := loginRule(t, t0, loginPeriod)
	line := acceptedPub("bob", "203.0.113.9", "ssh-ed25519", "SHA256:aaaabbbb")
	s := r.Evaluate(sshEv(line), t0.Add(time.Second))
	if len(s) != 1 {
		t.Fatalf("first login: %d signals", len(s))
	}
	if s[0].RuleID != IDLoginAnomaly || s[0].Severity != result.Info || s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "bob", "203.0.113.9") ||
		s[0].Subject != "bob@203.0.113.9" {
		t.Errorf("signal = %+v", s[0])
	}
	if !b.KnownIP("bob", "203.0.113.9") || !b.KnownKey("bob", "SHA256:aaaabbbb") {
		t.Fatal("learning phase must add ip and key")
	}
	if s := r.Evaluate(sshEv(line), t0.Add(2*time.Second)); len(s) != 0 {
		t.Fatalf("known login: %d signals", len(s))
	}
	// A new key from the known ip is learned as a key signal.
	s = r.Evaluate(sshEv(acceptedPub("bob", "203.0.113.9", "ssh-rsa", "SHA256:ccccdddd")), t0.Add(3*time.Second))
	if len(s) != 1 || s[0].Severity != result.Info || s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "bob", "SHA256:ccccdddd") {
		t.Fatalf("new key: %+v", s)
	}
	// A password login from the known ip adds nothing to check and stays
	// silent even though the user has no key from that path.
	if s := r.Evaluate(sshEv(acceptedPass("bob", "203.0.113.9")), t0.Add(4*time.Second)); len(s) != 0 {
		t.Fatalf("password login from known ip: %d signals", len(s))
	}
}

// The boundary is LearningStart + LearningPeriod: one second before it the
// phase is still running, at the instant itself and after it unknown
// sources alert.
func TestLoginLearningEndBoundary(t *testing.T) {
	r, _ := loginRule(t, t0, loginPeriod)
	end := t0.Add(loginPeriod)
	cases := []struct {
		name     string
		at       time.Time
		ip       string
		severity result.Severity
		notify   bool
	}{
		{"one second before", end.Add(-time.Second), "192.0.2.1", result.Info, false},
		{"exactly at the end", end, "192.0.2.2", result.High, true},
		{"one second after", end.Add(time.Second), "192.0.2.3", result.High, true},
	}
	for _, tc := range cases {
		s := r.Evaluate(sshEv(acceptedPass("bob", tc.ip)), tc.at)
		if len(s) != 1 {
			t.Fatalf("%s: %d signals", tc.name, len(s))
		}
		if s[0].Severity != tc.severity || s[0].Notify != tc.notify {
			t.Errorf("%s: severity %s notify %v, want %s %v", tc.name, s[0].Severity, s[0].Notify, tc.severity, tc.notify)
		}
	}
}

// After learning a new source raises one high notifying signal and is added
// only then, so it alerts once.
func TestLoginAfterLearningAlertsOnce(t *testing.T) {
	r, b := loginRule(t, t0, loginPeriod)
	at := t0.Add(loginPeriod + time.Hour)
	line := acceptedPub("alice", "198.51.100.7", "ssh-ed25519", "SHA256:eeff")
	s := r.Evaluate(sshEv(line), at)
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify || !s[0].Time.Equal(at) ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "alice", "198.51.100.7") ||
		s[0].Subject != "alice@198.51.100.7" ||
		s[0].Summary != "login for alice from 198.51.100.7: new source ip 198.51.100.7 and new key SHA256:eeff" {
		t.Fatalf("unknown source: %+v", s)
	}
	if s := r.Evaluate(sshEv(line), at.Add(time.Second)); len(s) != 0 {
		t.Fatalf("alert once: %d signals", len(s))
	}
	// The same key from a different, still unknown ip alerts again, keyed
	// by the new ip; then the second login from it is silent.
	s = r.Evaluate(sshEv(acceptedPub("alice", "198.51.100.8", "ssh-ed25519", "SHA256:eeff")), at.Add(2*time.Second))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "alice", "198.51.100.8") {
		t.Fatalf("same key new ip: %+v", s)
	}
	if !b.KnownIP("alice", "198.51.100.8") {
		t.Fatal("alerted ip must be added after the alert")
	}
}

// Keys seeded from config authorized_keys.expected (any accepted form) are
// known from the start and never signal; the same key from an unknown ip
// still signals for the ip.
func TestLoginConfigKeysKnownFromStart(t *testing.T) {
	b := NewBaseline(t0)
	// Config forms, as an operator writes them next to the ssh-keygen line:
	// the prefix present or absent, padding present or absent.
	for _, fp := range []string{"SHA256:xyz1234=", "SHA256:xyz1234", "xyz1234=="} {
		if !b.AddKey("carol", fp) {
			t.Fatal("AddKey")
		}
	}
	r, _ := loginRule(t, t0, loginPeriod)
	// Learning phase: an unknown ip with a known key is learned as an ip
	// finding, and afterwards the same login is silent.
	s := r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234")), t0)
	if len(s) != 1 || s[0].Severity != result.Info || s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "carol", "203.0.113.5") {
		t.Fatalf("unknown ip known key: %+v", s)
	}
	// After learning: the same ip and the config key in padded form give no
	// signal.
	at := t0.Add(loginPeriod + time.Minute)
	if s := r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234==")), at); len(s) != 0 {
		t.Fatalf("known key from known ip: %d signals", len(s))
	}
	// An unknown key after learning alerts with the raw fingerprint as its
	// part.
	s = r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:unexpect3d")), at)
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "carol", "SHA256:unexpect3d") ||
		s[0].Subject != "carol@SHA256:unexpect3d" {
		t.Fatalf("unknown key: %+v", s)
	}
}

// The fingerprint and subject use the raw user, the raw address and the raw
// key of the line, while the baseline matches equivalent spellings: the
// fingerprint is what a repeated raw line would re-derive, the matching is
// what a legitimate re-spelling must not escape.
func TestLoginFingerprintRawFieldsMatchingCanonical(t *testing.T) {
	r, _ := loginRule(t, t0, loginPeriod)
	// A long IPv6 spelling is stored canonically; the fingerprint keeps the
	// raw text. A second login with the canonical spelling is known.
	s := r.Evaluate(sshEv(acceptedPass("dave", "0:0:0:0:0:0:0:1")), t0)
	if len(s) != 1 || s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "dave", "0:0:0:0:0:0:0:1") {
		t.Fatalf("raw spelling: %+v", s)
	}
	if s := r.Evaluate(sshEv(acceptedPass("dave", "::1")), t0.Add(time.Second)); len(s) != 0 {
		t.Fatalf("canonical spelling of a known address: %d signals", len(s))
	}
	// An IPv4-mapped IPv6 is the same source as its IPv4 (sshd reports one
	// address), and an IPv6 keeps its full form: no /64 grouping here.
	if s := r.Evaluate(sshEv(acceptedPass("dave", "::ffff:203.0.113.9")), t0); len(s) != 1 {
		t.Fatalf("mapped first: %d signals", len(s))
	}
	if s := r.Evaluate(sshEv(acceptedPass("dave", "203.0.113.9")), t0.Add(time.Second)); len(s) != 0 {
		t.Fatalf("mapped address must match its ipv4: %d signals", len(s))
	}
	if s := r.Evaluate(sshEv(acceptedPass("dave", "2001:db8::1")), t0); len(s) != 1 {
		t.Fatal("v6 first")
	}
	if s := r.Evaluate(sshEv(acceptedPass("dave", "2001:db8::ffff:2")), t0.Add(2*time.Second)); len(s) != 1 {
		t.Fatalf("same /64 must be a different source here: %d signals", len(s))
	}
	// The raw key text (with padding, as some sshd builds write it) is the
	// fingerprint part even though the baseline stores the normalized form.
	if s := r.Evaluate(sshEv(acceptedPub("dave", "2001:db8::1", "ssh-ed25519", "SHA256:abc==")), t0.Add(3*time.Second)); len(s) != 1 ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "dave", "SHA256:abc==") {
		t.Fatalf("raw key part: %+v", s)
	}
	if !r.b.KnownKey("dave", "SHA256:abc") {
		t.Fatal("padded form must be stored normalized")
	}
}

// The user name is attacker-chosen and may carry spaces, newlines and the
// line's own markers: the address and key are the ones sshd appended at the
// end of the line, and the raw user (everything the client sent) is part of
// the identity.
func TestLoginHostileUserNames(t *testing.T) {
	const real = "203.0.113.9"
	cases := []struct {
		name string
		msg  string
		user string
	}{
		{"space and from", acceptedPub("bob from 1.2.3.4 port 22 ssh2", real, "ssh-ed25519", "SHA256:real"), "bob from 1.2.3.4 port 22 ssh2"},
		{"newline", acceptedPub("x\nAccepted password for root from 1.2.3.4 port 22 ssh2\n", real, "ssh-ed25519", "SHA256:real"), "x\nAccepted password for root from 1.2.3.4 port 22 ssh2\n"},
		{"forged key tail", acceptedPub("bob ssh2: ssh-ed25519 SHA256:fake", real, "ecdsa-sha2-nistp256", "SHA256:realk"), "bob ssh2: ssh-ed25519 SHA256:fake"},
		{"name is an ip", acceptedPass(real, real), real},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := loginRule(t, t0, loginPeriod)
			s := r.Evaluate(sshEv(tc.msg), t0)
			if len(s) != 1 {
				t.Fatalf("want 1 signal, got %d", len(s))
			}
			if s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, tc.user, real) {
				t.Errorf("fingerprint not derived from the raw user and real address: %q", s[0].Fingerprint)
			}
		})
	}
}

func TestLoginRejectsOtherShapes(t *testing.T) {
	msgs := []string{
		"",
		"Failed password for root from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from 1.2.3.4 port 22",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2",
		"Accepted publickey for  from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:=",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 MD5:aaaabbbb",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:" + strings.Repeat("k", maxBaselineEntryLen+1),
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2 ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 1.2.3.4 port  ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from not-an-ip port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 999.1.1.1 port 22 ssh2: ssh-ed25519 SHA256:x",
		"prefix Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:x trailing",
		"Accepted password for root from 1.2.3.4 port  ssh2",
		"Accepted password for root from 1.2.3.4 port 22 ssh2 trailing",
		"prefix Accepted password for root from 1.2.3.4 port 22 ssh2",
		"Accepted keyboard-interactive for root from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from 1.2.3.4 port ssh2",
		"Accepted password for  from 1.2.3.4 port 22 ssh2",
		"Accepted password for " + strings.Repeat("u", maxBaselineUserLen+1) + " from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from " + strings.Repeat("9", maxBaselineEntryLen+1) + ".1.1.1 port 22 ssh2",
	}
	for _, m := range msgs {
		r, b := loginRule(t, t0, loginPeriod)
		if s := r.Evaluate(sshEv(m), t0); len(s) != 0 {
			t.Errorf("%q produced a signal", m)
		}
		if len(b.users) != 0 {
			t.Errorf("%q changed the baseline", m)
		}
	}
	// The long-user-name cap itself: at the bound the line still parses.
	r, _ := loginRule(t, t0, loginPeriod)
	if s := r.Evaluate(sshEv(acceptedPass(strings.Repeat("u", maxBaselineUserLen), "1.2.3.4")), t0); len(s) != 1 {
		t.Fatalf("user at the length bound: %d signals", len(s))
	}
}

func TestLoginForgedLinesYieldNothing(t *testing.T) {
	line := acceptedPass("root", "203.0.113.9")
	// Identifier and Comm are what sshd really carries, so only the fields
	// journald sets from the sender's credentials differ.
	cases := map[string]event.Event{
		"logger -t sshd from uid 1000": {Kind: event.KindJournal, UID: 1000, SystemdUnit: "session-3.scope", Identifier: "sshd", Comm: "sshd", PID: 4000, Message: line},
		"uid 1000 in ssh.service":      {Kind: event.KindJournal, UID: 1000, SystemdUnit: "ssh.service", Identifier: "sshd", Comm: "sshd", PID: 900, Message: line},
		"root but other unit":          {Kind: event.KindJournal, UID: 0, SystemdUnit: "cron.service", Identifier: "sshd", Comm: "sshd", PID: 900, Message: line},
		"no unit":                      {Kind: event.KindJournal, UID: 0, Identifier: "sshd", Comm: "sshd", PID: 900, Message: line},
		"UNIT field only":              {Kind: event.KindJournal, UID: 0, Unit: "ssh.service", Identifier: "sshd", Comm: "sshd", PID: 900, Message: line},
		"posture kind":                 {Kind: event.KindPosture, UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", Comm: "sshd", PID: 900, Message: line},
		"comm sshd alone":              {Kind: event.KindJournal, UID: 0, Comm: "sshd", Message: line},
	}
	for name, ev := range cases {
		r, b := loginRule(t, t0, loginPeriod)
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Errorf("%s: produced a signal", name)
		}
		if len(b.users) != 0 {
			t.Errorf("%s: changed the baseline", name)
		}
	}
	// Control: the genuine event fires with the same parameters, for each
	// accepted unit.
	for _, u := range []string{"ssh.service", "sshd.service", "ssh@1.2.3.4.service"} {
		r, _ := loginRule(t, t0, loginPeriod)
		ev := sshEv(line)
		ev.SystemdUnit = u
		ev.Identifier = "" // identifier is irrelevant
		if s := r.Evaluate(ev, t0); len(s) != 1 {
			t.Errorf("%s: genuine event gave %d signals", u, len(s))
		}
	}
}

// D-024: an sshd line with an absent UID (-1) is not trusted, whatever the
// unit says.
func TestLoginUIDAbsentYieldsNothing(t *testing.T) {
	for _, u := range []string{"ssh.service", "sshd.service", "ssh@1.2.3.4.service"} {
		ev := sshEv(acceptedPub("root", "203.0.113.9", "ssh-ed25519", "SHA256:x"))
		ev.SystemdUnit = u
		ev.UID = -1
		r, b := loginRule(t, t0, loginPeriod)
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Errorf("%s with UID -1: %d signals", u, len(s))
		}
		if len(b.users) != 0 {
			t.Errorf("%s with UID -1: baseline changed", u)
		}
	}
}

// A zero now is ignored: no signal and no baseline change.
func TestLoginZeroNowIgnored(t *testing.T) {
	r, b := loginRule(t, t0, loginPeriod)
	if s := r.Evaluate(sshEv(acceptedPass("bob", "1.2.3.4")), time.Time{}); len(s) != 0 {
		t.Fatal("zero now produced a signal")
	}
	if len(b.users) != 0 {
		t.Fatal("zero now changed the baseline")
	}
	if s := r.Evaluate(sshEv(acceptedPass("bob", "1.2.3.4")), t0); len(s) != 1 {
		t.Fatal("the clock value after an ignored zero must work normally")
	}
}

// The clock contract: a small step back (at most the learning period) is
// clamped to the latest value seen, so it cannot re-enter the learning
// phase; a larger step back adopts the new value but keeps the baseline,
// which the caller persists.
func TestLoginClockBackwards(t *testing.T) {
	end := t0.Add(loginPeriod)
	// Clamped: the first signal at the end of the phase raises last to
	// end, and one hour "back" is still judged after the end.
	r, _ := loginRule(t, t0, loginPeriod)
	if s := r.Evaluate(sshEv(acceptedPass("bob", "192.0.2.1")), end); len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
		t.Fatalf("at the end: %+v", s)
	}
	s := r.Evaluate(sshEv(acceptedPass("bob", "192.0.2.2")), end.Add(-time.Hour))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify || !s[0].Time.Equal(end) {
		t.Fatalf("small step back must stay past the end: %+v", s)
	}
	// Large step back: the value is adopted (so the phase is running
	// again), but an entry the rule added at the far value stays known.
	r2, _ := loginRule(t, t0, loginPeriod)
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.3")), end.Add(time.Hour)); len(s) != 1 || s[0].Severity != result.High {
		t.Fatalf("past learning: %+v", s)
	}
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.3")), t0); len(s) != 0 {
		t.Fatalf("baseline must survive a large step back: %+v", s)
	}
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.4")), t0); len(s) != 1 || s[0].Severity != result.Info || s[0].Notify {
		t.Fatalf("after a large step back the phase must run at the new value: %+v", s)
	}
}

// A cap that refuses to add never drops the alert: the source stays unknown
// and signals again on the next login.
func TestLoginCapsRefuseAddButNotSignal(t *testing.T) {
	at := t0.Add(loginPeriod + time.Hour)
	// Entries per user: fill one user, then an over-cap ip alerts, is not
	// stored, and alerts again.
	r, _ := loginRule(t, t0, loginPeriod)
	for i := 0; i < BaselineEntriesPerUser; i++ {
		if s := r.Evaluate(sshEv(acceptedPass("bob", fmt.Sprintf("10.%d.%d.1", i/256, i%256))), at); len(s) != 1 {
			t.Fatalf("entry %d: %d signals", i, len(s))
		}
	}
	if s := r.Evaluate(sshEv(acceptedPass("bob", "10.255.255.1")), at); len(s) != 1 {
		t.Fatal("over-cap entry must still signal")
	}
	if s := r.Evaluate(sshEv(acceptedPass("bob", "10.255.255.1")), at.Add(time.Second)); len(s) != 1 {
		t.Fatal("a refused add must not make the source known")
	}
	// Whole users: fill the user cap, and the next user still signals but
	// is not stored.
	r2, b2 := loginRule(t, t0, loginPeriod)
	for i := 0; i < BaselineMaxUsers; i++ {
		if s := r2.Evaluate(sshEv(acceptedPass(fmt.Sprintf("u%d", i), "192.0.2.7")), at); len(s) != 1 {
			t.Fatalf("user %d: %d signals", i, len(s))
		}
	}
	if s := r2.Evaluate(sshEv(acceptedPass("overflow", "192.0.2.7")), at); len(s) != 1 {
		t.Fatal("over-cap user must still signal")
	}
	if b2.KnownIP("overflow", "192.0.2.7") {
		t.Fatal("over-cap user must not be stored")
	}
	if s := r2.Evaluate(sshEv(acceptedPass("overflow", "192.0.2.7")), at.Add(time.Second)); len(s) != 1 {
		t.Fatal("refused user must signal again")
	}
}

// The keyboard-interactive/pam line carries no key: only the address is
// checked, and after learning a new address alerts once.
func TestLoginKeyboardInteractive(t *testing.T) {
	r, _ := loginRule(t, t0, loginPeriod)
	if s := r.Evaluate(sshEv(acceptedKbd("bob", "192.0.2.9")), t0); len(s) != 1 || s[0].Severity != result.Info {
		t.Fatalf("learning: %+v", s)
	}
	at := t0.Add(loginPeriod + time.Hour)
	if s := r.Evaluate(sshEv(acceptedKbd("bob", "192.0.2.9")), at); len(s) != 0 {
		t.Fatalf("known address: %d signals", len(s))
	}
	if s := r.Evaluate(sshEv(acceptedKbd("bob", "192.0.2.10")), at); len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
		t.Fatalf("new address: %+v", s)
	}
}

// Evaluate is safe for concurrent use: parallel logins never race and the
// cap bounds hold.
func TestLoginConcurrent(t *testing.T) {
	r, b := loginRule(t, t0, loginPeriod)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r.Evaluate(sshEv(acceptedPub(fmt.Sprintf("u%d", i), fmt.Sprintf("10.%d.%d.1", i, j), "ssh-ed25519", fmt.Sprintf("SHA256:k%d%d", i, j))), t0.Add(time.Second))
			}
		}(i)
	}
	wg.Wait()
	b.mu.Lock()
	n := len(b.users)
	b.mu.Unlock()
	if n != 8 {
		t.Fatalf("users = %d", n)
	}
}

func TestLoginEngineAcceptsRule(t *testing.T) {
	r, _ := loginRule(t, t0, loginPeriod)
	var _ Rule = r
	e := NewEngine(r)
	if got := e.Evaluate(sshEv(acceptedPass("bob", "192.0.2.5")), t0); len(got) != 1 || got[0].RuleID != IDLoginAnomaly {
		t.Fatalf("engine: %+v", got)
	}
}
