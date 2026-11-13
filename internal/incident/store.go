package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// FileName is the name of the incident file inside the state directory.
const FileName = "incidents.json"

// SchemaVersion is the version of the file format.
const SchemaVersion = 1

// Limits.
const (
	// MaxIncidents is how many incidents are kept. When a new fingerprint
	// arrives at the cap, the closed incident with the oldest LastSeen is
	// evicted to make room. Open and acked incidents are never evicted: when
	// only those are left, Apply returns ErrFull and stores nothing.
	MaxIncidents = 500
	// MaxTitleRunes and MaxSummaryRunes cut the display text of an incident
	// so that the file stays within MaxFileSize.
	MaxTitleRunes   = 200
	MaxSummaryRunes = 1000
	// MaxFileSize bounds the file that is read and written. MaxIncidents
	// incidents of maximal size, with every character written as a six byte
	// JSON escape, stay below it.
	MaxFileSize = 8 << 20
)

// Errors returned by the store. Use errors.Is.
var (
	// ErrUnknownIncident is returned for an id no incident has.
	ErrUnknownIncident = errors.New("unknown incident")
	// ErrInvalidTransition is returned when a request action is not allowed
	// from the current state (see CanTransition).
	ErrInvalidTransition = errors.New("invalid incident transition")
	// ErrFull is returned by Apply when a new incident would exceed
	// MaxIncidents and no closed incident can be evicted.
	ErrFull = errors.New("incident store is full of open incidents")
	// ErrInvalidSignal is returned by Apply for a signal without a usable
	// fingerprint.
	ErrInvalidSignal = errors.New("invalid signal")
	// ErrCorrupt is returned by Open for a file that is not valid incident
	// data. The file is left as it is.
	ErrCorrupt = errors.New("incident file is corrupt")
	// ErrSchema is returned by Open for a file with another schema_version.
	// The file is left as it is.
	ErrSchema = errors.New("unsupported incident file schema_version")
)

// TransitionError is the error of an Ack or Close that the state does not
// allow. It wraps ErrInvalidTransition.
type TransitionError struct {
	ID       string
	From, To State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("incident %s: cannot move from %s to %s", e.ID, e.From, e.To)
}

func (e *TransitionError) Unwrap() error { return ErrInvalidTransition }

// Display is the text the store keeps for an incident. Both fields must
// already be cleaned (red.Clean) by the caller: the store never cleans, it
// only cuts them to MaxTitleRunes and MaxSummaryRunes.
type Display struct {
	Title   string
	Summary string
}

// Outcome tells what Apply did.
type Outcome int

const (
	// Opened: the fingerprint was unknown, a new incident was created.
	Opened Outcome = iota + 1
	// Updated: an open or acked incident got another occurrence.
	Updated
	// Reopened: a closed incident was opened again.
	Reopened
)

func (o Outcome) String() string {
	switch o {
	case Opened:
		return "opened"
	case Updated:
		return "updated"
	case Reopened:
		return "reopened"
	}
	return "unknown"
}

// Result is what Apply returns.
type Result struct {
	Outcome  Outcome
	Incident Incident
	// Notify is true when the caller should notify: the incident was Opened
	// or Reopened and the signal asked for it. An Updated incident never
	// notifies.
	Notify bool
	// Evicted lists the ids of closed incidents dropped to make room.
	Evicted []string
}

// Store keeps the incidents of the daemon in FileName in the state
// directory.
//
// The daemon is the only writer: the store does no locking and must not be
// shared between goroutines without the caller's own mutual exclusion. Every
// change is written (atomically, through securefile) before it becomes
// visible in memory; if the write fails, the store is unchanged.
//
// Title and Summary must be cleaned by the caller (red.Clean) before they are
// passed in a Display. The store never calls red.Clean itself and never sees
// raw signal text: the signal's own Subject and Summary are not read.
type Store struct {
	dir  *securefile.Dir
	list []Incident
}

// wire types: the file format, independent of the in-memory model.
type fileDoc struct {
	SchemaVersion int        `json:"schema_version"`
	Incidents     []wireItem `json:"incidents"`
}

type wireItem struct {
	ID          string    `json:"id"`
	Fingerprint string    `json:"fingerprint"`
	RuleID      string    `json:"rule_id"`
	Severity    string    `json:"severity"`
	State       string    `json:"state"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Notify      bool      `json:"notify"`
	ReopenCount int       `json:"reopen_count"`
	NotifiedAt  time.Time `json:"notified_at"`
}

func toWire(in Incident) wireItem {
	return wireItem{
		ID: in.ID, Fingerprint: string(in.Fingerprint), RuleID: in.RuleID,
		Severity: string(in.Severity), State: string(in.State),
		Title: in.Title, Summary: in.Summary, Count: in.Count,
		FirstSeen: in.FirstSeen, LastSeen: in.LastSeen, Notify: in.Notify,
		ReopenCount: in.ReopenCount, NotifiedAt: in.NotifiedAt,
	}
}

func fromWire(w wireItem) Incident {
	return Incident{
		ID: w.ID, Fingerprint: event.Fingerprint(w.Fingerprint), RuleID: w.RuleID,
		Severity: result.Severity(w.Severity), State: State(w.State),
		Title: w.Title, Summary: w.Summary, Count: w.Count,
		FirstSeen: w.FirstSeen, LastSeen: w.LastSeen, Notify: w.Notify,
		ReopenCount: w.ReopenCount, NotifiedAt: w.NotifiedAt,
	}
}

// Open loads the store from dir. A missing file is an empty store. A file
// that is unreadable, too large, not valid JSON, of another schema_version or
// inconsistent (duplicate ids or fingerprints, unknown state, more than
// MaxIncidents) is an error and is never replaced: the caller decides what to
// do with it. An unknown schema_version returns an error wrapping ErrSchema,
// invalid content one wrapping ErrCorrupt.
func Open(dir *securefile.Dir) (*Store, error) {
	if dir == nil {
		return nil, errors.New("incident store: no state directory")
	}
	s := &Store{dir: dir}
	b, err := dir.ReadCapped(FileName, MaxFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", FileName, err)
	}
	list, err := decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	s.list = list
	return s, nil
}

func decode(b []byte) ([]Incident, error) {
	// Look at the version first, so a later format is reported as such even
	// when its other fields do not fit this one.
	// json.Unmarshal also refuses data after the document.
	var head struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if head.SchemaVersion == nil {
		return nil, fmt.Errorf("%w: schema_version is missing", ErrCorrupt)
	}
	if *head.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: file has %d, this keepwatch reads %d", ErrSchema, *head.SchemaVersion, SchemaVersion)
	}
	var doc fileDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if len(doc.Incidents) > MaxIncidents {
		return nil, fmt.Errorf("%w: %d incidents, the limit is %d", ErrCorrupt, len(doc.Incidents), MaxIncidents)
	}
	ids := map[string]bool{}
	fps := map[string]bool{}
	out := make([]Incident, 0, len(doc.Incidents))
	for i, w := range doc.Incidents {
		switch State(w.State) {
		case StateOpen, StateAcked, StateClosed:
		default:
			return nil, fmt.Errorf("%w: incident %d has state %q", ErrCorrupt, i, w.State)
		}
		if w.ID == "" || w.Fingerprint == "" {
			return nil, fmt.Errorf("%w: incident %d has no id or fingerprint", ErrCorrupt, i)
		}
		if ids[w.ID] || fps[w.Fingerprint] {
			return nil, fmt.Errorf("%w: incident %d repeats an id or fingerprint", ErrCorrupt, i)
		}
		ids[w.ID], fps[w.Fingerprint] = true, true
		out = append(out, fromWire(w))
	}
	return out, nil
}

func (s *Store) save(list []Incident) error {
	doc := fileDoc{SchemaVersion: SchemaVersion, Incidents: make([]wireItem, 0, len(list))}
	for _, in := range list {
		doc.Incidents = append(doc.Incidents, toWire(in))
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode incidents: %w", err)
	}
	b = append(b, '\n')
	if err := s.dir.WriteAtomic(FileName, b, MaxFileSize); err != nil {
		return fmt.Errorf("cannot write %s: %w", FileName, err)
	}
	return nil
}

// List returns a copy of the incidents in the order they were opened.
func (s *Store) List() []Incident { return append([]Incident(nil), s.list...) }

// Get returns the incident with id.
func (s *Store) Get(id string) (Incident, bool) {
	for _, in := range s.list {
		if in.ID == id {
			return in, true
		}
	}
	return Incident{}, false
}

func validFingerprint(f event.Fingerprint) bool {
	if f == "" || len(f) > 64 {
		return false
	}
	for _, c := range string(f) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// idPrefix is the shortest id length tried.
const idPrefix = 8

// newID derives the id from the fingerprint: its first idPrefix characters,
// extended one character at a time until no kept incident has that id. The
// same fingerprint thus gets the same id in an empty store, and two
// fingerprints never share an id. Distinct fingerprints differ somewhere, so
// the loop ends at the latest at the full fingerprint. A file can carry an
// id of its own choosing that equals the full fingerprint of another
// incident; then a numeric suffix (-2, -3, ...) keeps the id unique.
func newID(f event.Fingerprint, list []Incident) string {
	taken := func(id string) bool {
		for _, in := range list {
			if in.ID == id {
				return true
			}
		}
		return false
	}
	for n := idPrefix; n < len(f); n++ {
		if id := string(f[:n]); !taken(id) {
			return id
		}
	}
	for i := 1; ; i++ {
		id := string(f)
		if i > 1 {
			id = fmt.Sprintf("%s-%d", f, i)
		}
		if !taken(id) {
			return id
		}
	}
}

func cut(s string, n int) string {
	if len(s) <= n { // fewer bytes than n means fewer runes than n
		return s
	}
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func rank(s result.Severity) int {
	for i, v := range result.Severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Apply records one signal. display holds the cleaned text (see Store).
//
//   - unknown fingerprint: a new incident is opened (Opened), after evicting
//     the oldest closed incident when MaxIncidents is reached; if none can be
//     evicted, ErrFull is returned and nothing changes.
//   - open or acked incident: Count and LastSeen are updated (Updated), the
//     state stays, Title, Summary and a higher Severity are taken over.
//   - closed incident: it is reopened (Reopened) and ReopenCount grows.
//
// Result.Notify is true for Opened and Reopened when signal.Notify is set.
// The incident's Notify flag takes the signal's value when it is opened or
// reopened and is left alone on an update. LastSeen never moves backwards.
func (s *Store) Apply(sig event.Signal, display Display) (Result, error) {
	if !validFingerprint(sig.Fingerprint) {
		return Result{}, fmt.Errorf("%w: fingerprint %q", ErrInvalidSignal, sig.Fingerprint)
	}
	title := cut(display.Title, MaxTitleRunes)
	summary := cut(display.Summary, MaxSummaryRunes)
	list := append([]Incident(nil), s.list...)

	idx := -1
	for i, in := range list {
		if in.Fingerprint == sig.Fingerprint {
			idx = i
			break
		}
	}
	var res Result
	if idx < 0 {
		if len(list) >= MaxIncidents {
			ev := -1
			for i, in := range list {
				if in.State == StateClosed && (ev < 0 || in.LastSeen.Before(list[ev].LastSeen)) {
					ev = i
				}
			}
			if ev < 0 {
				return Result{}, fmt.Errorf("%w (%d)", ErrFull, MaxIncidents)
			}
			res.Evicted = append(res.Evicted, list[ev].ID)
			list = append(list[:ev], list[ev+1:]...)
		}
		in := Incident{
			ID: newID(sig.Fingerprint, list), Fingerprint: sig.Fingerprint, RuleID: sig.RuleID,
			Severity: sig.Severity, State: StateOpen, Title: title, Summary: summary,
			Count: 1, FirstSeen: sig.Time, LastSeen: sig.Time, Notify: sig.Notify,
		}
		list = append(list, in)
		res.Outcome, res.Incident, res.Notify = Opened, in, sig.Notify
	} else {
		in := list[idx]
		in.Count++
		if sig.Time.After(in.LastSeen) {
			in.LastSeen = sig.Time
		}
		in.Title, in.Summary = title, summary
		if rank(sig.Severity) > rank(in.Severity) {
			in.Severity = sig.Severity
		}
		if CanReopen(in.State) {
			in.State = StateOpen
			in.ReopenCount++
			in.Notify = sig.Notify
			res.Outcome, res.Notify = Reopened, sig.Notify
		} else {
			res.Outcome = Updated
		}
		list[idx] = in
		res.Incident = in
	}
	if err := s.save(list); err != nil {
		return Result{}, err
	}
	s.list = list
	return res, nil
}

// Ack moves an open incident to acked.
func (s *Store) Ack(id string) (Incident, error) { return s.transition(id, StateAcked) }

// Close moves an open or acked incident to closed.
func (s *Store) Close(id string) (Incident, error) { return s.transition(id, StateClosed) }

func (s *Store) transition(id string, to State) (Incident, error) {
	for i, in := range s.list {
		if in.ID != id {
			continue
		}
		if !CanTransition(in.State, to) {
			return Incident{}, &TransitionError{ID: id, From: in.State, To: to}
		}
		list := append([]Incident(nil), s.list...)
		list[i].State = to
		if err := s.save(list); err != nil {
			return Incident{}, err
		}
		s.list = list
		return list[i], nil
	}
	return Incident{}, fmt.Errorf("%w: %q", ErrUnknownIncident, id)
}
