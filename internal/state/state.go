// Package state keeps what keepwatch saw in its last run so that the next run
// can report what changed.
//
// The state is one JSON file, state.json, in the state directory. It holds a
// snapshot per check: id, kind, status, severity and the failing items, each
// identified by the SHA-256 of its raw subject (what the diff compares) and a
// cleaned, redacted subject for display. For a check whose list the probe cut
// it also holds the complete set of the item keys (see Check.Keys), so that two
// runs are compared as sets and not by what happened to be listed. It
// deliberately holds no evidence detail text and no summary: that text comes
// from host output and is only needed for the report of the run that produced
// it.
//
// keepwatch runs as root and the state decides what an operator is told, so
// the file and its directory are not trusted blindly:
//
//   - The state directory is cleaned with filepath.Clean and must be an
//     absolute path. It is created with mode 0700 when absent; otherwise it
//     must be a real directory (not a symlink), owned by root or the running
//     user, and neither group- nor other-writable. All file access goes
//     through an os.Root opened on the directory after it was checked, and
//     the opened directory must be the one that was checked.
//   - The state file is opened with O_NOFOLLOW and O_NONBLOCK and checked on
//     the open descriptor: regular file, owned by root or the running user,
//     not group- or other-writable, at most MaxFileSize bytes.
//   - A state file that is missing is a first run. One that is a symlink,
//     foreign-owned, too large, truncated, not valid JSON, of another schema
//     version or semantically invalid is reported as a problem and treated as
//     no previous state: the run is a new baseline, never an abort and never
//     a silent "nothing changed". Files of an older schema version are in
//     that group: they lack the key sets, and a comparison without them would
//     be a guess.
//   - A write goes to a temporary file in the same directory (created with
//     O_EXCL and O_NOFOLLOW, mode 0600), is flushed to disk, renamed over the
//     state file, and the directory is flushed too. A failure at any step
//     leaves the previous state file untouched and removes the temporary file.
package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// SchemaVersion is the version of the state file format keepwatch writes and
// the only one it reads.
//
// Version 3 replaced the sort cutoff and the exact mark of version 2 with the
// complete key set of a capped check (Check.Total, Check.Keys, Check.Digest).
// Version 4 added the delivery record (State.Delivery). Files of an older
// version cannot be compared with it and are not read.
const SchemaVersion = 4

// FileName is the name of the state file inside the state directory.
const FileName = "state.json"

// MaxFileSize bounds the state file that is read and written.
//
// The size is dominated by key sets. A key costs 72 bytes in the indented file
// (64 hex characters, quotes, a comma, a newline and four spaces of indent), a
// check lists at most result.MaxKeys = 10000 keys, so one capped check takes at
// most 720,000 bytes. Only the kinds that cap their evidence can have a set (six
// of the 18 checks of the base catalog). Were all 18 capped and full, each with
// 99 display items of the longest escaped subject, the state would be 15.3 MB,
// so 16 MiB holds even that; a test builds that worst case and checks it
// against this constant.
const MaxFileSize = 16 << 20

// Limits applied when a state file is read, so a hostile or corrupt file
// cannot make the diff do unbounded work.
const (
	maxChecks     = 1000
	maxItems      = 1000
	maxIDLen      = 200
	maxSubjectLen = 2048
	maxTotal      = 1 << 40
	displayRunes  = 200
	// displayItems is how many items a list keeps for display when it has to
	// be cut here (a probe that returned more than maxItems items without
	// cutting them itself).
	displayItems = 99
)

// State is the snapshot of one run.
type State struct {
	SchemaVersion int       `json:"schema_version"`
	RunAt         time.Time `json:"run_at"`
	Checks        []Check   `json:"checks"`
	// Delivery is set when the last notification could not be delivered. A
	// run that sends notifications does not move the snapshot forward until
	// a delivery succeeds (see the cli package), so the checks above are
	// then the last snapshot whose changes were delivered, and the next run
	// reports the same changes again.
	Delivery *Delivery `json:"delivery,omitempty"`
}

// Kinds of a failed delivery.
const (
	// DeliveryCheck: the notification of the changes of a `check --notify`
	// run. The snapshot did not move forward because of it.
	DeliveryCheck = "check"
	// DeliveryBaseline: the notice of a first run (or of a run whose previous
	// state was unusable). There was no change to hold the snapshot for: the
	// next notification sends the open findings of that run.
	DeliveryBaseline = "baseline"
	// DeliveryWeekly: the weekly report. The snapshot is the one of the last
	// run and is not held back.
	DeliveryWeekly = "weekly"
)

// Limits of a delivery record.
const (
	maxDeliveryReason   = 500
	maxDeliveryFailures = 1 << 30
)

// Delivery records a notification that could not be delivered.
type Delivery struct {
	// FailedAt is the time of the latest failed attempt, Failures the number
	// of failed runs in a row.
	FailedAt time.Time `json:"failed_at"`
	Failures int       `json:"failures"`
	// Kind is DeliveryCheck, DeliveryWeekly or DeliveryBaseline.
	Kind string `json:"kind"`
	// Reason says why, in cleaned and redacted words; it never holds the
	// message or the address of the server.
	Reason string `json:"reason"`
}

// Check is the snapshot of one check.
type Check struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Status   result.Status   `json:"status"`
	Severity result.Severity `json:"severity"`
	// Items are the evidence items of the check that are listed, without the
	// marker item that says more were left out. For a check whose list is
	// complete they are all its items; for a capped one they are a prefix of
	// the list, for display and for naming what changed.
	Items []Item `json:"items"`
	// Total, Keys and Digest describe the complete list of a check whose
	// probe cut it, and are zero, nil and empty for any other check. Total is
	// the number of distinct items before the cut. Keys is the sorted list of
	// all their keys when Total is at most result.MaxKeys, and empty above
	// that. Digest is the digest of the complete sorted key list (see
	// result.EvidenceSet). The listed items are members of the set. A
	// comparison of two runs uses the keys when it has them and the digest
	// when it has not.
	Total  int      `json:"total,omitempty"`
	Keys   []string `json:"keys,omitempty"`
	Digest string   `json:"digest,omitempty"`
}

// Item is one evidence item.
type Item struct {
	// Key identifies the item: the hex SHA-256 of the raw subject. The diff
	// compares keys, so two subjects that differ only in characters that are
	// not displayed (or are redacted to the same text) stay two items.
	Key string `json:"key"`
	// Subject is the cleaned and redacted subject, for display.
	Subject string `json:"subject"`
	// Excepted is true when an exception covers the item.
	Excepted bool `json:"excepted,omitempty"`
}

// Capped reports whether the probe cut the list.
func (c *Check) Capped() bool { return c.Digest != "" }

// SetTotal is the number of distinct items of the check, before any cut.
func (c *Check) SetTotal() int {
	if c.Capped() {
		return c.Total
	}
	return len(c.Items)
}

// SetKeys returns the sorted key list of all the items of the check, and false
// when the check has too many to list (only the digest is known). The result
// must not be modified. The keys of excepted items are in it: an exception
// does not remove an item from the list, only from the failing ones.
func (c *Check) SetKeys() ([]string, bool) {
	if c.Capped() {
		return c.Keys, c.Total <= result.MaxKeys
	}
	keys := make([]string, 0, len(c.Items))
	for _, it := range c.Items {
		keys = append(keys, it.Key)
	}
	sort.Strings(keys)
	return slices.Compact(keys), true
}

// SetDigest returns the digest of the complete key list: the stored one for a
// capped check, computed for any other.
func (c *Check) SetDigest() string {
	if c.Capped() {
		return c.Digest
	}
	keys, _ := c.SetKeys()
	return result.DigestOfKeys(keys)
}

// Find returns the check with the given id, or nil.
func (s *State) Find(id string) *Check {
	for i := range s.Checks {
		if s.Checks[i].ID == id {
			return &s.Checks[i]
		}
	}
	return nil
}

var keyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// statusRank orders statuses from least to most severe, for merging results
// that share a check id.
var statusRank = map[result.Status]int{
	result.Skipped: 0, result.Pass: 1, result.Excepted: 2, result.Warn: 3, result.Error: 4, result.Fail: 5,
}

// FromResults builds the snapshot of a run. clean turns an untrusted string
// into the text that may be stored and shown (control characters escaped,
// secrets redacted); a nil clean stores subjects unchanged.
//
// Results that share a check id (the engine reports one exception_expired
// result per expired exception) are merged into one check: the most severe
// status, the highest severity and the union of the items. If any of them is
// capped, the merged check carries the union of their sets.
func FromResults(rs []result.Result, now time.Time, clean func(string) string) *State {
	if clean == nil {
		clean = func(s string) string { return s }
	}
	// part is what one result contributes to a check.
	type part struct {
		items []result.Evidence
		set   *result.EvidenceSet // nil when the result was not capped
	}
	st := &State{SchemaVersion: SchemaVersion, RunAt: now.UTC().Truncate(time.Second)}
	index := map[string]int{}
	var parts [][]part // per check
	for _, r := range rs {
		items, set := r.Listed(), r.Set
		if set == nil && len(items) > maxItems {
			// A probe that did not cut its list: cut it here, so that the
			// state stays valid and the whole list is still compared.
			set = result.NewEvidenceSet(items)
			items = append([]result.Evidence(nil), items...)
			sort.SliceStable(items, func(i, j int) bool { return items[i].Subject < items[j].Subject })
			items = items[:displayItems]
		}
		i, dup := index[r.CheckID]
		if !dup {
			i = len(st.Checks)
			index[r.CheckID] = i
			st.Checks = append(st.Checks, Check{ID: r.CheckID, Kind: r.Kind, Status: r.Status, Severity: r.Severity, Items: []Item{}})
			parts = append(parts, nil)
		} else {
			c := &st.Checks[i]
			if statusRank[r.Status] > statusRank[c.Status] {
				c.Status = r.Status
			}
			if rankOfSeverity(r.Severity) > rankOfSeverity(c.Severity) {
				c.Severity = r.Severity
			}
		}
		parts[i] = append(parts[i], part{items, set})
		c := &st.Checks[i]
		for _, ev := range items {
			addItem(c, ev, clean)
		}
	}
	for i, ps := range parts {
		var sets []*result.EvidenceSet
		capped := false
		for _, p := range ps {
			capped = capped || p.set != nil
		}
		if !capped {
			continue
		}
		for _, p := range ps {
			if p.set == nil {
				p.set = result.NewEvidenceSet(p.items)
			}
			sets = append(sets, p.set)
		}
		set := unionSets(sets)
		c := &st.Checks[i]
		c.Total, c.Keys, c.Digest = set.Total, set.Keys, set.Digest
	}
	return st
}

// unionSets returns the set of the union of the lists that sets describe. When
// every set lists its keys the union is exact. When one does not, the union
// cannot be formed; the result then keeps the sum of the totals and a digest
// over the parts' digests, which changes whenever a part changes.
func unionSets(sets []*result.EvidenceSet) *result.EvidenceSet {
	if len(sets) == 1 {
		return sets[0]
	}
	var keys []string
	complete := true
	for _, s := range sets {
		if !s.Complete() {
			complete = false
			break
		}
		keys = append(keys, s.Keys...)
	}
	if complete {
		if u, ok := result.SetOfKeys(keys); ok {
			return u
		}
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "merged\n")
	total := 0
	for _, s := range sets {
		total += s.Total
		_, _ = io.WriteString(h, s.Digest+"\n")
	}
	return &result.EvidenceSet{Total: total, Digest: hex.EncodeToString(h.Sum(nil))}
}

func rankOfSeverity(s result.Severity) int {
	for i, v := range result.Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// addItem adds an evidence item, or folds it into the item with the same key:
// the item counts as excepted only if every occurrence is.
func addItem(c *Check, ev result.Evidence, clean func(string) string) {
	key := result.SubjectKey(ev.Subject)
	for i := range c.Items {
		if c.Items[i].Key == key {
			c.Items[i].Excepted = c.Items[i].Excepted && ev.Excepted
			return
		}
	}
	c.Items = append(c.Items, Item{Key: key, Subject: truncate(clean(ev.Subject), displayRunes), Excepted: ev.Excepted})
}

func truncate(s string, runes int) string {
	if utf8.RuneCountInString(s) <= runes {
		return s
	}
	r := []rune(s)
	return string(r[:runes]) + "..."
}

// problem is why a state file could not be used.
type problem struct{ msg string }

func (p *problem) Error() string { return p.msg }

func problemf(format string, a ...any) error { return &problem{fmt.Sprintf(format, a...)} }

// parse decodes and validates a state file's content.
func parse(b []byte) (*State, error) {
	// The version is read first and on its own, so that a file of another
	// version is named as that and not as a file with unknown fields.
	var head struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, problemf("not a valid state file: %v", err)
	}
	if head.SchemaVersion != SchemaVersion {
		return nil, problemf("schema version %d, this keepwatch reads version %d only", head.SchemaVersion, SchemaVersion)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, problemf("not a valid state file: %v", err)
	}
	if err := validate(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// validateDelivery checks the delivery record of a decoded state.
func validateDelivery(d *Delivery) error {
	switch {
	case d == nil:
		return nil
	case d.Kind != DeliveryCheck && d.Kind != DeliveryWeekly && d.Kind != DeliveryBaseline:
		return problemf("delivery: unknown kind %q", d.Kind)
	case d.Failures < 1 || d.Failures > maxDeliveryFailures:
		return problemf("delivery: invalid failure count")
	case d.FailedAt.IsZero():
		return problemf("delivery: no time of failure")
	case len(d.Reason) > maxDeliveryReason:
		return problemf("delivery: the reason is longer than %d bytes", maxDeliveryReason)
	}
	return nil
}

// validate checks a decoded state. encoding/json replaces invalid UTF-8 with
// U+FFFD while decoding, so the strings here are valid UTF-8 already.
func validate(s *State) error {
	if len(s.Checks) == 0 {
		return problemf("no checks in the state file")
	}
	if err := validateDelivery(s.Delivery); err != nil {
		return err
	}
	if len(s.Checks) > maxChecks {
		return problemf("%d checks, at most %d are accepted", len(s.Checks), maxChecks)
	}
	seen := map[string]bool{}
	for i := range s.Checks {
		c := &s.Checks[i]
		where := "checks[" + strconv.Itoa(i) + "]"
		if c.ID == "" || len(c.ID) > maxIDLen {
			return problemf("%s: invalid id", where)
		}
		if seen[c.ID] {
			return problemf("%s: duplicate id", where)
		}
		seen[c.ID] = true
		if len(c.Kind) > maxIDLen {
			return problemf("%s: invalid kind", where)
		}
		if _, ok := statusRank[c.Status]; !ok {
			return problemf("%s: unknown status %q", where, string(c.Status))
		}
		if _, err := result.ParseSeverity(string(c.Severity)); err != nil {
			return problemf("%s: %v", where, err)
		}
		if len(c.Items) > maxItems {
			return problemf("%s: %d items, at most %d are accepted", where, len(c.Items), maxItems)
		}
		keys := map[string]bool{}
		for j, it := range c.Items {
			if !keyRe.MatchString(it.Key) || keys[it.Key] {
				return problemf("%s.items[%d]: invalid or duplicate key", where, j)
			}
			keys[it.Key] = true
			if len(it.Subject) > maxSubjectLen {
				return problemf("%s.items[%d]: invalid subject", where, j)
			}
		}
		if err := validateSet(c, where); err != nil {
			return err
		}
	}
	return nil
}

// validateSet checks the key set of a check. A check has none, or all of
// Total, Digest and (when Total is at most result.MaxKeys) Keys, and they
// agree with each other and with the listed items.
func validateSet(c *Check, where string) error {
	if c.Total == 0 && c.Digest == "" && len(c.Keys) == 0 {
		return nil
	}
	if c.Total < 1 || c.Total > maxTotal {
		return problemf("%s: invalid total", where)
	}
	if !keyRe.MatchString(c.Digest) {
		return problemf("%s: invalid digest", where)
	}
	if c.Total > result.MaxKeys {
		if len(c.Keys) != 0 {
			return problemf("%s: %d keys listed for a total of %d, more than %d are not listed", where, len(c.Keys), c.Total, result.MaxKeys)
		}
		return nil
	}
	if len(c.Keys) != c.Total {
		return problemf("%s: %d keys for a total of %d", where, len(c.Keys), c.Total)
	}
	for j, k := range c.Keys {
		if !keyRe.MatchString(k) {
			return problemf("%s.keys[%d]: invalid key", where, j)
		}
		if j > 0 && c.Keys[j-1] >= k {
			return problemf("%s.keys[%d]: keys are not sorted and unique", where, j)
		}
	}
	if result.DigestOfKeys(c.Keys) != c.Digest {
		return problemf("%s: the digest does not match the keys", where)
	}
	for j, it := range c.Items {
		if _, ok := slices.BinarySearch(c.Keys, it.Key); !ok {
			return problemf("%s.items[%d]: the item is not in the key set", where, j)
		}
	}
	return nil
}

// CheckConsistency verifies the key sets of a state that this run built (the
// output of FromResults), before it is compared with the previous one. It is
// deliberately narrower than the check applied to a state file: the limits
// that exist for foreign files (number of checks, items per check, id and
// subject lengths, at least one check) are not applied, so a legitimate run
// can never fail it. Per check it applies validateSet (keys hash-sized, sorted
// and unique, the total, the digest, every listed item in the set) and requires
// that no more items are listed than the set holds. The error names the check
// and the rule, never a subject.
func CheckConsistency(s *State) error {
	for i := range s.Checks {
		c := &s.Checks[i]
		where := "check " + strconv.Quote(c.ID)
		if err := validateSet(c, where); err != nil {
			return err
		}
		if c.Capped() && len(c.Items) > c.Total {
			return problemf("%s: %d items listed for a total of %d", where, len(c.Items), c.Total)
		}
	}
	return nil
}

// Marshal encodes a state the way Save writes it.
func Marshal(s *State) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
