package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
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
const (
	BaselineMaxUsers          = 1024
	BaselineEntriesPerUser    = 256
	maxBaselineUserLen        = 256
	maxBaselineEntryLen       = 256
	maxBaselineUnmarshalBytes = 8 << 20
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
// The comparison is on the base64 with the "SHA256:" prefix and the trailing
// padding removed; the standard alphabet keeps any other "=" inside the
// text, so only real padding is trimmed. The empty result (a bare
// "SHA256:" or "=" entry) is refused by the callers, which never accept an
// empty fingerprint.
func normalizeKeyFP(s string) string {
	return strings.TrimRight(strings.TrimPrefix(s, "SHA256:"), "=")
}

type baselineUser struct {
	ips  map[string]bool // canonical source address form
	keys map[string]bool // normalized key fingerprints
}

// Baseline is the set of source addresses and SSH key fingerprints a user
// has logged in with, plus the instant the learning phase started. The
// login rule consults and extends it; Marshal and Unmarshal carry it to and
// from the state directory so the learning survives a restart.
//
// Its methods are safe for concurrent use. The login rule holds its own
// mutex across a check-then-add pair, so a baseline shared between rules
// still answers each check against the state as of one complete Evaluate.
// The source addresses are stored in the canonical form returned by
// parseLoginAddr (an IPv6 keeps its full form; only an IPv4-mapped IPv6 is
// mapped to its IPv4); the fingerprints are stored normalized by
// normalizeKeyFP. A user name, an address or a fingerprint longer than
// maxBaselineUserLen or maxBaselineEntryLen is refused (added: not stored,
// reported: not found) because a field that long is not real.
type Baseline struct {
	mu            sync.Mutex
	learningStart time.Time
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
// whether it was stored: false when the user is new and the user cap is
// reached, when the user's entry cap is reached, or when a length bound is
// exceeded. An entry already known counts against no cap.
func (b *Baseline) add(user string, toIPs bool, entry string) bool {
	if len(user) > maxBaselineUserLen || len(entry) == 0 || len(entry) > maxBaselineEntryLen {
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
// must be in the canonical form returned by parseLoginAddr. An empty or
// oversized address is never known.
func (b *Baseline) KnownIP(user, ip string) bool {
	if ip == "" || len(ip) > maxBaselineEntryLen {
		return false
	}
	return b.known(user, true, ip)
}

// KnownKey reports whether user has logged in with the key whose
// fingerprint is fp, in any of the forms normalizeKeyFP accepts. A
// fingerprint that normalizes to empty or oversized is never known.
func (b *Baseline) KnownKey(user, fp string) bool {
	norm := normalizeKeyFP(fp)
	if norm == "" || len(norm) > maxBaselineEntryLen {
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
	Users         []baselineUserWire `json:"users"`
}

// Marshal returns the JSON form of the baseline: schema_version, the
// learning start and the users with their source addresses and normalized
// key fingerprints, sorted.
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
	b.mu.Unlock()
	sort.Slice(users, func(i, j int) bool { return users[i].User < users[j].User })
	return json.Marshal(baselineWire{SchemaVersion: BaselineSchemaVersion, LearningStart: start, Users: users})
}

// Unmarshal returns the baseline stored in data by Marshal. A data longer
// than maxBaselineUnmarshalBytes, another schema_version (an error wrapping
// ErrBaselineSchema), a repeated user, a duplicate or oversized entry and a
// count above the documented caps are all refused with an error: a baseline
// is loaded whole or not at all, and a caller that cannot load it starts a
// fresh learning phase instead of trusting a file it cannot verify.
// Fingerprints are normalized, so a file written with config-form entries
// reads as the keys the log lines carry.
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
	b := &Baseline{learningStart: w.LearningStart, users: map[string]*baselineUser{}}
	for _, uw := range w.Users {
		if uw.User == "" || len(uw.User) > maxBaselineUserLen {
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
			if ip == "" || len(ip) > maxBaselineEntryLen || u.ips[ip] {
				return nil, fmt.Errorf("%w: user %q has a bad or repeated source address", errBaselineCorrupt, uw.User)
			}
			u.ips[ip] = true
		}
		for _, fp := range uw.Keys {
			norm := normalizeKeyFP(fp)
			if norm == "" || len(norm) > maxBaselineEntryLen || u.keys[norm] {
				return nil, fmt.Errorf("%w: user %q has a bad or repeated key fingerprint", errBaselineCorrupt, uw.User)
			}
			u.keys[norm] = true
		}
		b.users[uw.User] = u
	}
	return b, nil
}
