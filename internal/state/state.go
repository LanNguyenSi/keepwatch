// Package state keeps what keepwatch saw in its last run so that the next run
// can report what changed.
//
// The state is one JSON file, state.json, in the state directory. It holds a
// snapshot per check: id, kind, status, severity and the failing items, each
// identified by the SHA-256 of its raw subject (what the diff compares) and a
// cleaned, redacted subject for display. It deliberately holds no evidence
// detail text and no summary: that text comes from host output and is only
// needed for the report of the run that produced it.
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
//     a silent "nothing changed".
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
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// SchemaVersion is the version of the state file format keepwatch writes.
//
// Version 2 added the sort cutoff of a capped check (Check.Cutoff) and the
// Exact mark of an item. A version 1 file is still read: it has neither, so
// the diff treats every capped list in it as one whose cutoff is unknown (the
// behaviour version 1 had). Any other version is not read.
const SchemaVersion = 2

// oldestSchemaVersion is the oldest version that is still read.
const oldestSchemaVersion = 1

// FileName is the name of the state file inside the state directory.
const FileName = "state.json"

// MaxFileSize bounds the state file that is read. A real state is a few
// kilobytes: 18 checks with at most 100 failing items each.
const MaxFileSize = 4 << 20

// Limits applied when a state file is read, so a hostile or corrupt file
// cannot make the diff do unbounded work.
const (
	maxChecks     = 1000
	maxItems      = 1000
	maxIDLen      = 200
	maxSubjectLen = 2048
	maxHidden     = 1 << 30
	displayRunes  = 200
	markerSubject = `^\((\d+) more not shown\)$`
	markerDetail  = `^(\d+) further items are not listed, the limit is (\d+) items$`
)

// State is the snapshot of one run.
type State struct {
	SchemaVersion int       `json:"schema_version"`
	RunAt         time.Time `json:"run_at"`
	Checks        []Check   `json:"checks"`
}

// Check is the snapshot of one check.
type Check struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Status   result.Status   `json:"status"`
	Severity result.Severity `json:"severity"`
	// Items are the evidence items of the check, without the marker item
	// that says more were left out.
	Items []Item `json:"items"`
	// Hidden is the number of items the probe left out because of its
	// evidence cap; 0 when the list is complete.
	Hidden int `json:"hidden,omitempty"`
	// Cutoff is where a capped list was cut: the raw subject of its last
	// listed item. The probes list the first items in byte order of the raw
	// subject, so an item that sorts before the cutoff was listed if it
	// existed, and one that sorts after it may have been hidden. The diff
	// uses this to see a new item in a capped list. It is nil when the
	// list is complete, or when the cutoff is not known: it is stored only
	// when that last subject is exactly the display subject that is stored
	// anyway (valid UTF-8, nothing escaped, redacted or cut), so it adds no
	// text that could hold a secret. A hash would not do: it keeps no order.
	Cutoff *string `json:"cutoff,omitempty"`
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
	// Exact is true when Subject is the raw subject, byte for byte: nothing
	// was escaped, redacted or cut. Only then can the diff place the item
	// relative to a Cutoff.
	Exact bool `json:"exact,omitempty"`
}

// Capped reports whether the probe left items out.
func (c *Check) Capped() bool { return c.Hidden > 0 }

// Total is the number of items the check had before the cap.
func (c *Check) Total() int { return len(c.Items) + c.Hidden }

// Find returns the check with the given id, or nil.
func (s *State) Find(id string) *Check {
	for i := range s.Checks {
		if s.Checks[i].ID == id {
			return &s.Checks[i]
		}
	}
	return nil
}

// SubjectKey returns the key of a raw subject.
func SubjectKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

var (
	markerSubjectRe = regexp.MustCompile(markerSubject)
	markerDetailRe  = regexp.MustCompile(markerDetail)
	keyRe           = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// splitMarker separates the cap marker that the probes append when they left
// items out. The marker is recognised only when it is the last item and its
// subject, its detail and the item count all agree with the text and the
// numbers the probes write, so a subject that merely looks like the marker
// (for example a container name chosen by a local user) stays an ordinary
// item: such an item would have to come with a detail of exactly the marker's
// wording, in the last place of a list of exactly the announced length.
func splitMarker(ev []result.Evidence) ([]result.Evidence, int) {
	if len(ev) == 0 {
		return ev, 0
	}
	last := ev[len(ev)-1]
	sm := markerSubjectRe.FindStringSubmatch(last.Subject)
	dm := markerDetailRe.FindStringSubmatch(last.Detail)
	if sm == nil || dm == nil || last.Excepted {
		return ev, 0
	}
	hidden, err1 := strconv.Atoi(sm[1])
	hidden2, err2 := strconv.Atoi(dm[1])
	limit, err3 := strconv.Atoi(dm[2])
	if err1 != nil || err2 != nil || err3 != nil || hidden <= 0 || hidden > maxHidden || hidden != hidden2 || limit != len(ev) {
		return ev, 0
	}
	return ev[:len(ev)-1], hidden
}

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
// status, the highest severity and the union of the items.
func FromResults(rs []result.Result, now time.Time, clean func(string) string) *State {
	if clean == nil {
		clean = func(s string) string { return s }
	}
	st := &State{SchemaVersion: SchemaVersion, RunAt: now.UTC().Truncate(time.Second)}
	index := map[string]int{}
	for _, r := range rs {
		items, hidden := splitMarker(r.Evidence)
		i, dup := index[r.CheckID]
		if !dup {
			i = len(st.Checks)
			index[r.CheckID] = i
			st.Checks = append(st.Checks, Check{ID: r.CheckID, Kind: r.Kind, Status: r.Status, Severity: r.Severity, Items: []Item{}})
		} else {
			c := &st.Checks[i]
			if statusRank[r.Status] > statusRank[c.Status] {
				c.Status = r.Status
			}
			if rankOfSeverity(r.Severity) > rankOfSeverity(c.Severity) {
				c.Severity = r.Severity
			}
		}
		c := &st.Checks[i]
		switch {
		case dup && (hidden > 0 || c.Hidden > 0):
			// A capped list merged with other items has no single cutoff.
			c.Cutoff = nil
		case hidden > 0:
			c.Cutoff = cutoffOf(items, clean)
		}
		c.Hidden += hidden
		for _, ev := range items {
			addItem(c, ev, clean)
		}
	}
	return st
}

// cutoffOf returns the cutoff of a capped list: the raw subject of its last
// item, or nil when that cannot be stored safely. The probes sort their list
// by raw subject before they cut it; a list that is not in that order is not
// trusted. A subject is stored only when it is exactly its display text (see
// Check.Cutoff).
func cutoffOf(items []result.Evidence, clean func(string) string) *string {
	if len(items) == 0 {
		return nil
	}
	for i := 1; i < len(items); i++ {
		if items[i-1].Subject > items[i].Subject {
			return nil
		}
	}
	last := items[len(items)-1].Subject
	if !isExact(last, clean) {
		return nil
	}
	return &last
}

// isExact reports whether the display text of subject is subject itself.
func isExact(subject string, clean func(string) string) bool {
	return utf8.ValidString(subject) && utf8.RuneCountInString(subject) <= displayRunes && clean(subject) == subject
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
	key := SubjectKey(ev.Subject)
	for i := range c.Items {
		if c.Items[i].Key == key {
			c.Items[i].Excepted = c.Items[i].Excepted && ev.Excepted
			return
		}
	}
	c.Items = append(c.Items, Item{
		Key: key, Subject: truncate(clean(ev.Subject), displayRunes), Excepted: ev.Excepted,
		Exact: isExact(ev.Subject, clean),
	})
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
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, problemf("not a valid state file: %v", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, problemf("not a valid state file: data after the JSON document")
	}
	if s.SchemaVersion < oldestSchemaVersion || s.SchemaVersion > SchemaVersion {
		return nil, problemf("schema version %d, this keepwatch reads versions %d to %d", s.SchemaVersion, oldestSchemaVersion, SchemaVersion)
	}
	if s.SchemaVersion < 2 {
		// The cutoff and the exact mark do not exist in version 1: whatever
		// such a file claims about them is not trusted.
		for i := range s.Checks {
			s.Checks[i].Cutoff = nil
			for j := range s.Checks[i].Items {
				s.Checks[i].Items[j].Exact = false
			}
		}
	}
	if err := validate(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// validate checks a decoded state. encoding/json replaces invalid UTF-8 with
// U+FFFD while decoding, so the strings here are valid UTF-8 already.
func validate(s *State) error {
	if len(s.Checks) == 0 {
		return problemf("no checks in the state file")
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
		if c.Hidden < 0 || c.Hidden > maxHidden {
			return problemf("%s: invalid hidden count", where)
		}
		if c.Cutoff != nil && (c.Hidden == 0 || len(*c.Cutoff) > maxSubjectLen) {
			return problemf("%s: invalid cutoff", where)
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
