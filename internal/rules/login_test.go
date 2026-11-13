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
	if _, err := NewLoginAnomaly(LoginParams{}, b); err == nil {
		t.Error("zero period with a baseline: want error")
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
		s[0].Summary != "login for alice from 198.51.100.7: new source ip 198.51.100.7 and new key SHA256:eeff (ssh-ed25519)" {
		t.Fatalf("unknown source: %+v", s)
	}
	if s := r.Evaluate(sshEv(line), at.Add(time.Second)); len(s) != 0 {
		t.Fatalf("alert once: %d signals", len(s))
	}
	// A new key from the known ip alerts once, named by the raw
	// fingerprint with the known key type in the summary.
	s = r.Evaluate(sshEv(acceptedPub("alice", "198.51.100.7", "ecdsa-sha2-nistp256", "SHA256:next")), at.Add(2*time.Second))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "alice", "SHA256:next") ||
		s[0].Summary != "login for alice from 198.51.100.7: new key SHA256:next (ecdsa-sha2-nistp256)" {
		t.Fatalf("new key after learning: %+v", s)
	}
	// A key whose info carries text after the fingerprint (a comment, or
	// a certificate line's ID, serial and CA parts) still names that
	// fingerprint: only the key info before it and after it is ignored.
	s = r.Evaluate(sshEv(acceptedPub("alice", "198.51.100.7", "ssh-ed25519", "SHA256:tail trailing text")), at.Add(3*time.Second))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "alice", "SHA256:tail") ||
		s[0].Summary != "login for alice from 198.51.100.7: new key SHA256:tail (ssh-ed25519)" {
		t.Fatalf("key with trailing text: %+v", s)
	}
	// The same key from a different, still unknown ip alerts again, keyed
	// by the new ip; then the second login from it is silent.
	s = r.Evaluate(sshEv(acceptedPub("alice", "198.51.100.8", "ssh-ed25519", "SHA256:eeff")), at.Add(4*time.Second))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify ||
		s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "alice", "198.51.100.8") {
		t.Fatalf("same key new ip: %+v", s)
	}
	if !b.KnownIP("alice", "198.51.100.8") {
		t.Fatal("alerted ip must be added after the alert")
	}
}

// Keys given through the KnownKeys input (config authorized_keys.expected)
// are known from the start, in any accepted form, in the learning phase
// and after it; the baseline never sees them, and a key the input does
// not name is unknown: the same login without the input signals.
func TestLoginConfigKeysKnownFromStart(t *testing.T) {
	// Config forms, as an operator writes them next to the ssh-keygen
	// line: the prefix present or absent, padding present or absent.
	forms := []string{"SHA256:xyz1234=", "SHA256:xyz1234", "xyz1234=="}
	newRule := func(b *Baseline, keys map[string][]string) *LoginAnomaly {
		r, err := NewLoginAnomaly(LoginParams{LearningPeriod: loginPeriod, KnownKeys: keys}, b)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, phase := range []struct {
		name string
		at   time.Time
	}{{"learning", t0.Add(time.Second)}, {"after learning", t0.Add(loginPeriod + time.Minute)}} {
		b := NewBaseline(t0)
		if !b.AddIP("carol", "203.0.113.5") {
			t.Fatal("AddIP")
		}
		keys := map[string][]string{"carol": forms}
		r := newRule(b, keys)
		// A config key from a known address is silent in both phases.
		if s := r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234")), phase.at); len(s) != 0 {
			t.Fatalf("%s: config key from known ip: %+v", phase.name, s)
		}
		if b.KnownKey("carol", "SHA256:xyz1234") {
			t.Fatalf("%s: a config key must not be written into the baseline", phase.name)
		}
		// Negative control: the same login with the same baseline but
		// without the config input is a key signal.
		r2 := newRule(b, nil)
		if s := r2.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234")), phase.at); len(s) != 1 ||
			s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "carol", "SHA256:xyz1234") {
			t.Fatalf("%s: without the config input: %+v", phase.name, s)
		}
	}
	// A config key from an unknown address signals for the address, and
	// the key stays out of the baseline afterwards: the input, not the
	// baseline, is what makes it known.
	b := NewBaseline(t0)
	r := newRule(b, map[string][]string{"carol": {"SHA256:xyz1234"}})
	s := r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.6", "ssh-ed25519", "SHA256:xyz1234")), t0)
	if len(s) != 1 || s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, "carol", "203.0.113.6") ||
		s[0].Summary != "login for carol from 203.0.113.6: new source ip 203.0.113.6" {
		t.Fatalf("config key unknown ip: %+v", s)
	}
	if b.KnownKey("carol", "SHA256:xyz1234") {
		t.Fatal("a config key must not be learned into the baseline")
	}
	// The config input does not count against the baseline caps: with
	// carol's entries at the cap, a config key from a known address is
	// still silent, and the same key without the input is refused by the
	// cap and keeps alerting.
	if !b.AddIP("carol", "203.0.113.5") {
		t.Fatal("AddIP")
	}
	for i := 0; i < BaselineEntriesPerUser-2; i++ {
		if !b.AddKey("carol", fmt.Sprintf("SHA256:fill%d", i)) {
			t.Fatal("AddKey")
		}
	}
	if s := r.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234")), t0.Add(2*time.Second)); len(s) != 0 {
		t.Fatalf("config key at the cap: %+v", s)
	}
	r3 := newRule(b, nil)
	if s := r3.Evaluate(sshEv(acceptedPub("carol", "203.0.113.5", "ssh-ed25519", "SHA256:xyz1234")), t0.Add(2*time.Second)); len(s) != 1 {
		t.Fatalf("a baseline key over the cap must still signal: %+v", s)
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

// A known address is found through every equivalent spelling, in both
// directions: known in the short form and looked up in the long one, and
// an IPv4 known as itself and looked up in its IPv4-mapped form.
func TestLoginKnownAddressAnySpelling(t *testing.T) {
	r, _ := loginRule(t, t0, loginPeriod)
	if s := r.Evaluate(sshEv(acceptedPass("gina", "::1")), t0); len(s) != 1 {
		t.Fatal("short v6 first")
	}
	if s := r.Evaluate(sshEv(acceptedPass("gina", "0:0:0:0:0:0:0:1")), t0.Add(time.Second)); len(s) != 0 {
		t.Fatalf("long spelling of a known address: %d signals", len(s))
	}
	if s := r.Evaluate(sshEv(acceptedPass("gina", "203.0.113.11")), t0); len(s) != 1 {
		t.Fatal("v4 first")
	}
	if s := r.Evaluate(sshEv(acceptedPass("gina", "::ffff:203.0.113.11")), t0.Add(2*time.Second)); len(s) != 0 {
		t.Fatalf("ipv4-mapped form of a known ipv4: %d signals", len(s))
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

// Real lines from OpenSSH 8.9 and 9.6 whose key part is not the plain
// "SHA256:<fp>" shape: a certificate line gives the user key's
// fingerprint (its ID comment, serial and CA parts are ignored, and the
// CA key is not learned), and a line whose key part does not parse
// (MD5-only fingerprint, no fingerprint, an empty or degenerate one, one
// oversized beyond the entry bound) is checked by address only, never
// dropped.
func TestLoginCertificateAndUnparsedKeyLines(t *testing.T) {
	cases := []struct {
		name    string
		msg     string
		user    string
		ip      string
		learned string // fingerprint the baseline must end up knowing, "" for none
		summary string
	}{
		{
			"ed25519 certificate",
			"Accepted publickey for alice from 127.0.0.1 port 47988 ssh2: ED25519-CERT SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg ID key id with spaces (serial 7) CA ED25519 SHA256:ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zyxwvut",
			"alice", "127.0.0.1", "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg",
			"login for alice from 127.0.0.1: new source ip 127.0.0.1 and new key SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg (ED25519-CERT)",
		},
		{
			"md5 fingerprint",
			"Accepted publickey for alice from 127.0.0.1 port 47990 ssh2: ED25519 MD5:c1:b2:a3:94:85:76:67:58:49:3a:2b:1c:0d:fe:ef:de",
			"alice", "127.0.0.1", "",
			"login for alice from 127.0.0.1: new source ip 127.0.0.1",
		},
		{
			"none method",
			"Accepted none for nopw from 127.0.0.1 port 48072 ssh2",
			"nopw", "127.0.0.1", "",
			"login for nopw from 127.0.0.1: new source ip 127.0.0.1",
		},
		{
			"hostbased method",
			"Accepted hostbased for bob from 192.0.2.1 port 48080 ssh2",
			"bob", "192.0.2.1", "",
			"login for bob from 192.0.2.1: new source ip 192.0.2.1",
		},
		{
			"gssapi-with-mic method",
			"Accepted gssapi-with-mic for bob from 192.0.2.2 port 48081 ssh2",
			"bob", "192.0.2.2", "",
			"login for bob from 192.0.2.2: new source ip 192.0.2.2",
		},
		{
			"keyboard-interactive method",
			"Accepted keyboard-interactive for bob from 192.0.2.3 port 48082 ssh2",
			"bob", "192.0.2.3", "",
			"login for bob from 192.0.2.3: new source ip 192.0.2.3",
		},
		{
			"publickey without key info",
			"Accepted publickey for bob from 192.0.2.4 port 48083 ssh2",
			"bob", "192.0.2.4", "",
			"login for bob from 192.0.2.4: new source ip 192.0.2.4",
		},
		{
			"publickey type without fingerprint",
			"Accepted publickey for bob from 192.0.2.5 port 22 ssh2: ssh-ed25519",
			"bob", "192.0.2.5", "",
			"login for bob from 192.0.2.5: new source ip 192.0.2.5",
		},
		{
			"publickey empty fingerprint",
			"Accepted publickey for bob from 192.0.2.6 port 22 ssh2: ssh-ed25519 SHA256:",
			"bob", "192.0.2.6", "",
			"login for bob from 192.0.2.6: new source ip 192.0.2.6",
		},
		{
			"publickey padding-only fingerprint",
			"Accepted publickey for bob from 192.0.2.7 port 22 ssh2: ssh-ed25519 SHA256:=",
			"bob", "192.0.2.7", "",
			"login for bob from 192.0.2.7: new source ip 192.0.2.7",
		},
		{
			"publickey oversized fingerprint",
			"Accepted publickey for bob from 192.0.2.8 port 22 ssh2: ssh-ed25519 SHA256:" + strings.Repeat("k", maxBaselineEntryLen+1),
			"bob", "192.0.2.8", "",
			"login for bob from 192.0.2.8: new source ip 192.0.2.8",
		},
		{
			"publickey key info without a type",
			"Accepted publickey for bob from 192.0.2.9 port 22 ssh2:  SHA256:x",
			"bob", "192.0.2.9", "",
			"login for bob from 192.0.2.9: new source ip 192.0.2.9",
		},
		{
			"publickey empty fingerprint before a later one",
			"Accepted publickey for bob from 192.0.2.10 port 22 ssh2: ssh-ed25519 SHA256: CA ed25519 SHA256:later",
			"bob", "192.0.2.10", "",
			"login for bob from 192.0.2.10: new source ip 192.0.2.10",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, b := loginRule(t, t0, loginPeriod)
			s := r.Evaluate(sshEv(tc.msg), t0)
			if len(s) != 1 || s[0].Severity != result.Info || s[0].Notify ||
				s[0].Fingerprint != event.FingerprintOf(IDLoginAnomaly, tc.user, tc.ip) ||
				s[0].Summary != tc.summary {
				t.Fatalf("first login: %+v", s)
			}
			if !b.KnownIP(tc.user, tc.ip) {
				t.Fatal("the address must be learned")
			}
			if tc.learned != "" && !b.KnownKey(tc.user, tc.learned) {
				t.Fatal("the user key of the certificate line must be learned")
			}
			if b.KnownKey(tc.user, "SHA256:ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210zyxwvut") {
				t.Fatal("the CA key of a certificate line must not be learned")
			}
			if tc.learned == "" {
				b.mu.Lock()
				n := len(b.users[tc.user].keys)
				b.mu.Unlock()
				if n != 0 {
					t.Fatalf("an unparsed key part must not enter the baseline: %d keys", n)
				}
			}
			if s := r.Evaluate(sshEv(tc.msg), t0.Add(time.Second)); len(s) != 0 {
				t.Fatalf("the same login must now be silent: %+v", s)
			}
			// Past learning the same address-only shape alerts once.
			r2, b2 := loginRule(t, t0, loginPeriod)
			at := t0.Add(loginPeriod + time.Hour)
			if s := r2.Evaluate(sshEv(tc.msg), at); len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
				t.Fatalf("past learning: %+v", s)
			}
			if s := r2.Evaluate(sshEv(tc.msg), at.Add(time.Second)); len(s) != 0 {
				t.Fatalf("past learning once: %+v", s)
			}
			if tc.learned != "" && !b2.KnownKey(tc.user, tc.learned) {
				t.Fatal("the alerted key must be added after the alert")
			}
		})
	}
}

// Lines that are not accepted login lines at all, and lines whose address
// cannot be checked, yield no signal and never touch the baseline.
func TestLoginRejectsOtherShapes(t *testing.T) {
	msgs := []string{
		"",
		"Failed password for root from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from 1.2.3.4 port 22",
		"Accepted publickey for  from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 1.2.3.4 port 22 ssh2 ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 1.2.3.4 port  ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from not-an-ip port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted publickey for root from 999.1.1.1 port 22 ssh2: ssh-ed25519 SHA256:x",
		"prefix Accepted publickey for root from 1.2.3.4 port 22 ssh2: ssh-ed25519 SHA256:x",
		"Accepted password for root from 1.2.3.4 port  ssh2",
		"Accepted password for root from 1.2.3.4 port 22 ssh2 trailing",
		"prefix Accepted password for root from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from 1.2.3.4 port ssh2",
		"Accepted password for  from 1.2.3.4 port 22 ssh2",
		"Accepted password for " + strings.Repeat("u", maxBaselineUserLen+1) + " from 1.2.3.4 port 22 ssh2",
		"Accepted password for root from " + strings.Repeat("9", maxBaselineEntryLen+1) + ".1.1.1 port 22 ssh2",
		// An IPv6 zone can outlive any address bound: netip.ParseAddr
		// accepts it, so only the address-length conjunct refuses this.
		"Accepted publickey for root from fe80::1%" + strings.Repeat("z", 300) + " port 22 ssh2: ssh-ed25519 SHA256:x",
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

// An sshd line with an absent UID (-1) is not trusted, whatever the
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
// which the caller persists, and never reopens a learning phase whose
// end has already been seen.
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
	// Large step back: the value is adopted and the baseline survives,
	// but the seen end of the learning phase stays recorded.
	r2, b2 := loginRule(t, t0, loginPeriod)
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.3")), end.Add(time.Hour)); len(s) != 1 || s[0].Severity != result.High {
		t.Fatalf("past learning: %+v", s)
	}
	if !b2.LearningDone() {
		t.Fatal("a time past the end must record that learning ended")
	}
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.3")), t0); len(s) != 0 {
		t.Fatalf("baseline must survive a large step back: %+v", s)
	}
	if s := r2.Evaluate(sshEv(acceptedPass("bob", "192.0.2.4")), t0); len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
		t.Fatalf("a large step back into the window must not reopen learning: %+v", s)
	}
	// The end is recorded even by a login that is fully known and gives
	// no signal.
	r3, _ := loginRule(t, t0, loginPeriod)
	if s := r3.Evaluate(sshEv(acceptedPass("bob", "192.0.2.5")), t0); len(s) != 1 || s[0].Severity != result.Info {
		t.Fatalf("learned login: %+v", s)
	}
	if s := r3.Evaluate(sshEv(acceptedPass("bob", "192.0.2.5")), end.Add(time.Second)); len(s) != 0 {
		t.Fatalf("known login at the end must stay silent: %+v", s)
	}
	if s := r3.Evaluate(sshEv(acceptedPass("bob", "192.0.2.6")), t0); len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
		t.Fatalf("the silent end login must have latched the end: %+v", s)
	}
}

// Learning runs only from LearningStart on: a time before LearningStart
// counts as after the learning phase and alerts, without ending the
// phase for the window that follows.
func TestLoginTimeBeforeLearningStartAlerts(t *testing.T) {
	r, b := loginRule(t, t0, loginPeriod)
	s := r.Evaluate(sshEv(acceptedPass("bob", "192.0.2.1")), t0.Add(-time.Hour))
	if len(s) != 1 || s[0].Severity != result.High || !s[0].Notify {
		t.Fatalf("time before the learning start: %+v", s)
	}
	if !b.KnownIP("bob", "192.0.2.1") {
		t.Fatal("the alerted source must be added")
	}
	if b.LearningDone() {
		t.Fatal("a time before the start must not end the learning phase")
	}
	// The window itself still learns.
	if s := r.Evaluate(sshEv(acceptedPass("bob", "192.0.2.2")), t0); len(s) != 1 || s[0].Severity != result.Info || s[0].Notify {
		t.Fatalf("time at the start must learn: %+v", s)
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
