package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// BaselineSchemaVersion is the schema_version of the persisted baseline
// form. Unmarshal refuses any other version: a file written by a future
// keepwatch may hold fields this one would silently drop.
const BaselineSchemaVersion = 1

// Baseline caps bound memory under hostile input: BaselineMaxUsers counts
// whole users, BaselineEntriesPerUser counts the sum of known source
// addresses and known
// key fingerprints of one user. A Baseline method refuses to add beyond a
// cap (it returns false); the caller still reports the finding, so a cap
// can make a source alert repeatedly but never go unnoticed.
//
// The content bounds keep out what real sshd output never carries: a
// user name is valid UTF-8 with no control byte (below 0x20 and 0x7f)
// and at most maxBaselineUserLen bytes; a source address is an IP
// address in the exact canonical form parseLoginAddr produces (it parses
// with netip.ParseAddr and equals its unmapped String form), at most
// maxBaselineEntryLen bytes long and, if it is an IPv6 with a zone, with
// a zone that is a non-empty run of A-Za-z0-9._-; a key fingerprint,
// after normalizeKeyFP, is 1 to maxBaselineEntryLen bytes of the base64
// alphabet A-Za-z0-9+/.
const (
	BaselineMaxUsers       = 256
	BaselineEntriesPerUser = 128
	maxBaselineUserLen     = 64
	maxBaselineEntryLen    = 64

	// maxBaselineUnmarshalBytes bounds an Unmarshal input. It is derived
	// from the caps and the length bounds with no JSON escape factor:
	// Marshal writes with SetEscapeHTML(false), entries carry only base64
	// and address characters, and user names carry no control byte, so
	// the only bytes that can grow are user name bytes: a quote or a
	// backslash (1 byte) doubles, and U+2028 and U+2029 (3 bytes) are
	// written as a six-byte \uXXXX escape, which doubles them too, so
	// no user name byte more than doubles (2*maxBaselineUserLen). Per user: that
	// name with its quoted "user" field, the "ips" and "keys" field
	// syntax, and every entry with its quotes and a comma
	// (maxBaselineEntryLen+3). The fixed syntax of the top object and
	// the commas between the users fit in the 512 slack.
	maxBaselineUnmarshalBytes = 512 + BaselineMaxUsers*
		(2*maxBaselineUserLen+29+
			BaselineEntriesPerUser*(maxBaselineEntryLen+3))
)

// ErrBaselineSchema is returned by Unmarshal for a baseline whose
// schema_version this keepwatch does not know.
var ErrBaselineSchema = errors.New("rules: unsupported baseline schema_version")

// errBaselineCorrupt reports baseline data that does not parse or exceeds a
// documented bound; Unmarshal returns it instead of loading such data.
var errBaselineCorrupt = errors.New("rules: corrupt baseline")

// normalizeKeyFP returns the comparable form of an SSH key fingerprint. Both
// input forms are mapped onto the same value:
//
//   - a config entry from authorized_keys.expected, "SHA256:<base64>", with
//     or without trailing "=" padding, as ssh-keygen or the operator writes
//     it (the stage-0 authorized_keys probe trims the padding the same way);
//   - the fingerprint an sshd "Accepted publickey" line carries,
//     "SHA256:<base64>" without padding.
//
// The comparison is on the base64 with every leading "SHA256:" prefix and
// the trailing padding removed; stripping every prefix, not just one, makes
// the function idempotent, so "SHA256:SHA256:<fp>" and "SHA256:<fp>" are
// one entry. The standard alphabet keeps any other "=" inside the text, so
// only real padding is trimmed. A result that is not a valid fingerprint
// (see validKeyFP) is refused by the callers, which never accept an empty
// or degenerate fingerprint.
func normalizeKeyFP(s string) string {
	for strings.HasPrefix(s, "SHA256:") {
		s = s[len("SHA256:"):]
	}
	return strings.TrimRight(s, "=")
}

// validUserName reports whether user is a storable user name: non-empty,
// valid UTF-8, no control byte (below 0x20 and 0x7f), and at most
// maxBaselineUserLen bytes.
func validUserName(user string) bool {
	if user == "" || len(user) > maxBaselineUserLen || !utf8.ValidString(user) {
		return false
	}
	for i := 0; i < len(user); i++ {
		if c := user[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// validAddrEntry reports whether s is a storable canonical source address:
// at most maxBaselineEntryLen bytes, with an IPv6 zone (if present) made
// of A-Za-z0-9._- only, and an IP address that netip.ParseAddr reads and
// writes back unchanged after Unmap, which is exactly the form
// parseLoginAddr produces (so "::ffff:1.2.3.4" and an uncompressed IPv6
// are not canonical). netip.ParseAddr itself refuses the empty string
// and an empty zone, but accepts zones outside the character set, so the
// rule enforces the set too, and this function keeps the same rule for
// stored entries.
func validAddrEntry(s string) bool {
	if len(s) > maxBaselineEntryLen {
		return false
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		zone := s[i+1:]
		for j := 0; j < len(zone); j++ {
			switch c := zone[j]; {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
				c == '.', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Unmap().String() == s
}

// validKeyFP reports whether s is a storable normalized key fingerprint:
// 1 to maxBaselineEntryLen bytes, each one of the base64 alphabet
// A-Za-z0-9+/ (sshd and ssh-keygen print no other byte).
func validKeyFP(s string) bool {
	if s == "" || len(s) > maxBaselineEntryLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}

type baselineUser struct {
	ips  map[string]bool // canonical source address form
	keys map[string]bool // normalized key fingerprints
}

// Baseline is the set of source addresses and SSH key fingerprints a user
// has logged in with, plus the instant the learning phase started and a
// latch recording that the login rule has seen a time at or past the end
// of that phase (after which the learning phase never reopens, not even
// for a clock step back). The login rule consults and extends it; Marshal
// and Unmarshal carry it to and from the state directory so the learning
// survives a restart.
//
// Its methods are safe for concurrent use. The login rule holds its own
// mutex across a check-then-add pair, so a baseline shared between rules
// still answers each check against the state as of one complete Evaluate.
// The source addresses are stored in the canonical form returned by
// parseLoginAddr (an IPv6 keeps its full form; only an IPv4-mapped IPv6 is
// mapped to its IPv4); the fingerprints are stored normalized by
// normalizeKeyFP. A user name that is empty, not valid UTF-8, carries a
// control byte or exceeds maxBaselineUserLen, and an address, fingerprint
// or zone failing the content bounds documented with the caps, are all
// refused (added: not stored, reported: not found) because such a field
// is not real sshd output.
type Baseline struct {
	mu            sync.Mutex
	learningStart time.Time
	learningDone  bool
	users         map[string]*baselineUser
}

// NewBaseline returns an empty baseline whose learning phase starts at
// learningStart. The caller takes that instant from the state directory on
// first start (and config.Watch.LearningPeriod from the configuration as
// the rule's period); the zero instant means the learning phase is over,
// so an unknown source notifies from the first login: the safe direction
// for a restored baseline that never recorded its start.
func NewBaseline(learningStart time.Time) *Baseline {
	return &Baseline{learningStart: learningStart, users: map[string]*baselineUser{}}
}

// LearningStart returns the instant the learning phase started.
func (b *Baseline) LearningStart() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.learningStart
}

// LearningDone reports whether a time at or past the end of the learning
// phase has been seen and recorded with MarkLearningDone. Once true the
// learning phase is over for good: a clock step back to a time inside the
// window does not reopen it.
func (b *Baseline) LearningDone() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.learningDone
}

// MarkLearningDone records that a time at or past the end of the learning
// phase has been seen, latching the end of the learning phase into the
// persisted baseline. It is called by the login rule; the flag is carried
// by Marshal and Unmarshal.
func (b *Baseline) MarkLearningDone() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.learningDone = true
}

// known reports whether user has the entry (already in its stored form) in
// the set named by toIPs.
func (b *Baseline) known(user string, toIPs bool, entry string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.users[user]
	if u == nil {
		return false
	}
	if toIPs {
		return u.ips[entry]
	}
	return u.keys[entry]
}

// add stores entry (already in its stored form) for user and reports
// whether it was stored: false when the user name fails validUserName,
// when the entry fails validAddrEntry (addresses) or validKeyFP
// (fingerprints), when the user is new and the user cap is reached, or
// when the user's entry cap is reached. An entry already known counts
// against no cap.
func (b *Baseline) add(user string, toIPs bool, entry string) bool {
	if !validUserName(user) {
		return false
	}
	if toIPs {
		if !validAddrEntry(entry) {
			return false
		}
	} else if !validKeyFP(entry) {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	u := b.users[user]
	if u == nil {
		if len(b.users) >= BaselineMaxUsers {
			return false
		}
		u = &baselineUser{ips: map[string]bool{}, keys: map[string]bool{}}
		b.users[user] = u
	}
	set := u.keys
	if toIPs {
		set = u.ips
	}
	if set[entry] {
		return true
	}
	if len(u.ips)+len(u.keys) >= BaselineEntriesPerUser {
		return false
	}
	set[entry] = true
	return true
}

// KnownIP reports whether user has logged in from the address ip, which
// must be in the canonical form returned by parseLoginAddr. An address
// failing validAddrEntry is never known.
func (b *Baseline) KnownIP(user, ip string) bool {
	if !validAddrEntry(ip) {
		return false
	}
	return b.known(user, true, ip)
}

// KnownKey reports whether user has logged in with the key whose
// fingerprint is fp, in any of the forms normalizeKeyFP accepts. A
// fingerprint that does not normalize to a validKeyFP value is never
// known.
func (b *Baseline) KnownKey(user, fp string) bool {
	norm := normalizeKeyFP(fp)
	if !validKeyFP(norm) {
		return false
	}
	return b.known(user, false, norm)
}

// AddIP stores the canonical address ip for user and reports whether it
// was stored. See the Baseline cap documentation: a refused add leaves the
// source unknown, so it keeps alerting rather than going unnoticed.
func (b *Baseline) AddIP(user, ip string) bool {
	return b.add(user, true, ip)
}

// AddKey stores the key fingerprint fp (normalized by normalizeKeyFP) for
// user and reports whether it was stored.
func (b *Baseline) AddKey(user, fp string) bool {
	return b.add(user, false, normalizeKeyFP(fp))
}

// baselineUserWire is one user of the persisted form. The lists are sorted
// by Marshal, so a baseline with unchanged content writes byte-identical
// JSON and a file can be diffed.
type baselineUserWire struct {
	User string   `json:"user"`
	IPs  []string `json:"ips"`
	Keys []string `json:"keys"`
}

type baselineWire struct {
	SchemaVersion int                `json:"schema_version"`
	LearningStart time.Time          `json:"learning_start"`
	LearningDone  bool               `json:"learning_done"`
	Users         []baselineUserWire `json:"users"`
}

// Marshal returns the JSON form of the baseline: schema_version, the
// learning start, the latch recording whether the learning phase has
// ended, and the users with their source addresses and normalized key
// fingerprints, sorted. HTML escaping is off so a user name byte never
// more than doubles (a quote, a backslash, or a byte of U+2028 or
// U+2029), which is what the Unmarshal size bound is derived against.
// The output has no trailing newline.
func (b *Baseline) Marshal() ([]byte, error) {
	b.mu.Lock()
	users := make([]baselineUserWire, 0, len(b.users))
	for name, u := range b.users {
		ips := make([]string, 0, len(u.ips))
		for ip := range u.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		keys := make([]string, 0, len(u.keys))
		for k := range u.keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		users = append(users, baselineUserWire{User: name, IPs: ips, Keys: keys})
	}
	start := b.learningStart
	done := b.learningDone
	b.mu.Unlock()
	sort.Slice(users, func(i, j int) bool { return users[i].User < users[j].User })
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(baselineWire{SchemaVersion: BaselineSchemaVersion, LearningStart: start, LearningDone: done, Users: users}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Unmarshal returns the baseline stored in data by Marshal. A data longer
// than maxBaselineUnmarshalBytes, another schema_version (an error wrapping
// ErrBaselineSchema), a repeated user, a duplicate entry, an entry or user
// name failing the content bounds documented with the caps (so a document
// carrying such an entry is refused) and a count above the documented caps
// are all refused with an error: a baseline is loaded whole or not at all.
// What to do when a file cannot be loaded (a missing, corrupt or newer
// file, for instance) is the caller's decision; Unmarshal only says that
// this data is not a baseline this keepwatch can trust. Fingerprints are
// normalized, so a file written with config-form entries reads as the keys
// the log lines carry.
func Unmarshal(data []byte) (*Baseline, error) {
	if len(data) > maxBaselineUnmarshalBytes {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", errBaselineCorrupt, len(data), maxBaselineUnmarshalBytes)
	}
	var w baselineWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%w: %v", errBaselineCorrupt, err)
	}
	if w.SchemaVersion != BaselineSchemaVersion {
		return nil, fmt.Errorf("%w: file has %d, this keepwatch reads %d", ErrBaselineSchema, w.SchemaVersion, BaselineSchemaVersion)
	}
	if len(w.Users) > BaselineMaxUsers {
		return nil, fmt.Errorf("%w: %d users exceeds %d", errBaselineCorrupt, len(w.Users), BaselineMaxUsers)
	}
	b := &Baseline{learningStart: w.LearningStart, learningDone: w.LearningDone, users: map[string]*baselineUser{}}
	for _, uw := range w.Users {
		if !validUserName(uw.User) {
			return nil, fmt.Errorf("%w: unusable user name", errBaselineCorrupt)
		}
		if _, dup := b.users[uw.User]; dup {
			return nil, fmt.Errorf("%w: user %q appears twice", errBaselineCorrupt, uw.User)
		}
		if len(uw.IPs)+len(uw.Keys) > BaselineEntriesPerUser {
			return nil, fmt.Errorf("%w: user %q has more than %d entries", errBaselineCorrupt, uw.User, BaselineEntriesPerUser)
		}
		u := &baselineUser{ips: map[string]bool{}, keys: map[string]bool{}}
		for _, ip := range uw.IPs {
			if !validAddrEntry(ip) || u.ips[ip] {
				return nil, fmt.Errorf("%w: user %q has a bad or repeated source address", errBaselineCorrupt, uw.User)
			}
			u.ips[ip] = true
		}
		for _, fp := range uw.Keys {
			norm := normalizeKeyFP(fp)
			if !validKeyFP(norm) || u.keys[norm] {
				return nil, fmt.Errorf("%w: user %q has a bad or repeated key fingerprint", errBaselineCorrupt, uw.User)
			}
			u.keys[norm] = true
		}
		b.users[uw.User] = u
	}
	return b, nil
}
