package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// FileName is the name of the incident file inside the state directory.
const FileName = "incidents.json"

// SchemaVersion is the version of the file format: incidents with their
// state, counts and times, plus the retired id list, and NotifiedAt as the
// time the notification of an incident was taken over. A file with another
// schema_version is refused with ErrSchema (the file is left as it is).
const SchemaVersion = 2

// Limits.
const (
	// MaxIncidents is how many incidents are kept. At the cap a new
	// fingerprint makes room by eviction, see Apply.
	MaxIncidents = 500
	// MaxTitleRunes and MaxSummaryRunes cut the display text of an incident
	// so that the file stays within MaxFileSize.
	MaxTitleRunes   = 200
	MaxSummaryRunes = 1000
	// MaxRuleIDRunes cuts the rule id.
	MaxRuleIDRunes = 64
	// MaxIDLen bounds an incident id in a file (a fingerprint is 64 long,
	// a collision suffix adds a few characters).
	MaxIDLen = 80
	// MaxRetiredIDs is how many ids of evicted incidents are remembered so
	// that they are not handed out again; the oldest are dropped first.
	MaxRetiredIDs = 2000
	// MaxFileSize bounds the file that is read and written. MaxIncidents
	// incidents of maximal size, with every character written as a six byte
	// JSON escape, plus MaxRetiredIDs retired ids, stay below it.
	MaxFileSize = 8 << 20
	// DefaultIdleClose is how long an open or acked incident may go without
	// a signal before it is closed automatically.
	DefaultIdleClose = 7 * 24 * time.Hour
)

// Errors returned by the store. Use errors.Is.
var (
	// ErrUnknownIncident is returned for an id no incident has.
	ErrUnknownIncident = errors.New("unknown incident")
	// ErrInvalidTransition is returned when a request action is not allowed
	// from the current state (see CanTransition).
	ErrInvalidTransition = errors.New("invalid incident transition")
	// ErrFull is returned by Apply when a new incident would exceed
	// MaxIncidents and every kept incident outranks the signal. The Result
	// returned with it has Outcome Refused; nothing was stored.
	ErrFull = errors.New("incident store is full of more severe incidents")
	// ErrInvalidSignal is returned by Apply for a signal without a usable
	// fingerprint, with a severity that is not a known one or with a time
	// that cannot be recorded (see usableTime). MarkNotified and Sweep
	// return it for such a time of their own.
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
	// Refused: the store was at MaxIncidents and every kept incident is
	// more severe than the signal's, so nothing was stored (returned
	// together with ErrFull).
	Refused
)

func (o Outcome) String() string {
	switch o {
	case Opened:
		return "opened"
	case Updated:
		return "updated"
	case Reopened:
		return "reopened"
	case Refused:
		return "refused"
	}
	return "unknown"
}

// Removed describes an incident that was evicted to make room.
type Removed struct {
	ID          string
	Fingerprint event.Fingerprint
	// State is the state the incident had when it was evicted.
	State State
}

// Result is what Apply returns. Evicted and AutoClosed are reported only in
// the result of the call that produced them: the change is saved before the
// result is returned, so a caller that crashes before recording them loses
// that report (the stored incidents themselves are not affected).
type Result struct {
	Outcome Outcome
	// Incident is the incident after the change. With Outcome Refused it is
	// the incident that would have been opened, without an ID.
	Incident Incident
	// Notify is true when the caller should notify: the incident was Opened
	// or Reopened and the signal asked for it.
	Notify bool
	// Pending is true when the signal updated an open incident that wants a
	// notification and has none recorded since it was last opened or
	// reopened (NotifiedAt is zero): an earlier result was lost, or the
	// notification was never marked. The caller treats Notify || Pending as
	// "notify now" and calls MarkNotified when it has taken the notification
	// over. Pending is never set for Opened or Reopened (see Notify), for an
	// acked incident, or for an incident that does not want notification.
	Pending bool
	// Evicted lists the incidents dropped to make room, with their state, so
	// that the caller can audit each one.
	Evicted []Removed
	// AutoClosed lists the open or acked incidents that were closed because
	// they had been idle longer than the idle-close period (their State is
	// closed), so that the caller can audit each one.
	AutoClosed []Incident
}

// Option configures Open.
type Option func(*Store)

// WithIdleClose sets how long an open or acked incident may go without a
// signal before Apply or Sweep closes it. The default is DefaultIdleClose;
// zero or less switches idle closing off.
func WithIdleClose(d time.Duration) Option { return func(s *Store) { s.idleClose = d } }

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
	dir       *securefile.Dir
	list      []Incident
	retired   []string
	idleClose time.Duration
}

// wire types: the file format, independent of the in-memory model.
type fileDoc struct {
	SchemaVersion int        `json:"schema_version"`
	Incidents     []wireItem `json:"incidents"`
	RetiredIDs    []string   `json:"retired_ids"`
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
// inconsistent is an error and is never replaced: the caller decides what to
// do with it. An unknown schema_version returns an error wrapping ErrSchema,
// invalid content one wrapping ErrCorrupt. Invalid content is: an unknown
// state or severity, a negative count, an empty, over-long or repeated id, a
// fingerprint that is not lowercase hex of at most 64 characters, a repeated
// fingerprint, text beyond its bound, a retired id that is repeated or in
// use, or more than MaxIncidents incidents or MaxRetiredIDs retired ids.
func Open(dir *securefile.Dir, opts ...Option) (*Store, error) {
	if dir == nil {
		return nil, errors.New("incident store: no state directory")
	}
	s := &Store{dir: dir, idleClose: DefaultIdleClose}
	for _, o := range opts {
		o(s)
	}
	b, err := dir.ReadCapped(FileName, MaxFileSize)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", FileName, err)
	}
	list, retired, err := decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	s.list, s.retired = list, retired
	return s, nil
}

func tooLong(s string, n int) bool { return utf8.RuneCountInString(s) > n }

func decode(b []byte) ([]Incident, []string, error) {
	// Look at the version first, so a later format is reported as such even
	// when its other fields do not fit this one.
	// json.Unmarshal also refuses data after the document.
	var head struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if head.SchemaVersion == nil {
		return nil, nil, fmt.Errorf("%w: schema_version is missing", ErrCorrupt)
	}
	if *head.SchemaVersion != SchemaVersion {
		return nil, nil, fmt.Errorf("%w: file has %d, this keepwatch reads %d", ErrSchema, *head.SchemaVersion, SchemaVersion)
	}
	var doc fileDoc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if len(doc.Incidents) > MaxIncidents {
		return nil, nil, fmt.Errorf("%w: %d incidents, the limit is %d", ErrCorrupt, len(doc.Incidents), MaxIncidents)
	}
	if len(doc.RetiredIDs) > MaxRetiredIDs {
		return nil, nil, fmt.Errorf("%w: %d retired ids, the limit is %d", ErrCorrupt, len(doc.RetiredIDs), MaxRetiredIDs)
	}
	ids := map[string]bool{}
	fps := map[string]bool{}
	out := make([]Incident, 0, len(doc.Incidents))
	for i, w := range doc.Incidents {
		switch State(w.State) {
		case StateOpen, StateAcked, StateClosed:
		default:
			return nil, nil, fmt.Errorf("%w: incident %d has state %q", ErrCorrupt, i, w.State)
		}
		if rank(result.Severity(w.Severity)) < 0 {
			return nil, nil, fmt.Errorf("%w: incident %d has severity %q", ErrCorrupt, i, w.Severity)
		}
		if w.ID == "" || len(w.ID) > MaxIDLen {
			return nil, nil, fmt.Errorf("%w: incident %d has an empty or over-long id", ErrCorrupt, i)
		}
		if !validFingerprint(event.Fingerprint(w.Fingerprint)) {
			return nil, nil, fmt.Errorf("%w: incident %d has an invalid fingerprint", ErrCorrupt, i)
		}
		if w.Count < 0 || w.ReopenCount < 0 {
			return nil, nil, fmt.Errorf("%w: incident %d has a negative count", ErrCorrupt, i)
		}
		if tooLong(w.Title, MaxTitleRunes) || tooLong(w.Summary, MaxSummaryRunes) || tooLong(w.RuleID, MaxRuleIDRunes) {
			return nil, nil, fmt.Errorf("%w: incident %d has text beyond its bound", ErrCorrupt, i)
		}
		if ids[w.ID] || fps[w.Fingerprint] {
			return nil, nil, fmt.Errorf("%w: incident %d repeats an id or fingerprint", ErrCorrupt, i)
		}
		ids[w.ID], fps[w.Fingerprint] = true, true
		out = append(out, fromWire(w))
	}
	seen := map[string]bool{}
	for i, id := range doc.RetiredIDs {
		if id == "" || len(id) > MaxIDLen {
			return nil, nil, fmt.Errorf("%w: retired id %d is empty or over-long", ErrCorrupt, i)
		}
		if seen[id] || ids[id] {
			return nil, nil, fmt.Errorf("%w: retired id %d is repeated or in use", ErrCorrupt, i)
		}
		seen[id] = true
	}
	return out, append([]string(nil), doc.RetiredIDs...), nil
}

func (s *Store) save(list []Incident, retired []string) error {
	doc := fileDoc{SchemaVersion: SchemaVersion, Incidents: make([]wireItem, 0, len(list)), RetiredIDs: append([]string{}, retired...)}
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

// usableTime reports whether t is a time the store may record: not the zero
// time, and with a year between 1 and 9999. Apply, MarkNotified and Sweep
// reject any other time with ErrInvalidSignal rather than storing a time the
// file format cannot round-trip.
func usableTime(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	y := t.Year()
	return y >= 1 && y <= 9999
}

// idPrefix is the shortest id length tried.
const idPrefix = 8

// newID derives the id from the fingerprint: its first idPrefix characters,
// extended one character at a time until neither a kept incident nor a
// retired id has that id. The same fingerprint thus gets the same id in an
// empty store, and two fingerprints never share an id, and an id of an
// evicted incident is not handed out again while it is remembered (see
// MaxRetiredIDs). Distinct fingerprints differ somewhere, so the loop ends
// at the latest at the full fingerprint. A file can carry an id of its own
// choosing that equals the full fingerprint of another incident; then a
// numeric suffix (-2, -3, ...) keeps the id unique.
func newID(f event.Fingerprint, list []Incident, retired []string) string {
	taken := func(id string) bool {
		for _, in := range list {
			if in.ID == id {
				return true
			}
		}
		for _, r := range retired {
			if r == id {
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

// victimBefore reports whether a should be evicted before b: closed
// incidents first (oldest LastSeen first), then open or acked ones with the
// lowest severity, those that do not want notification before those that do,
// then the oldest LastSeen.
func victimBefore(a, b Incident) bool {
	ac, bc := a.State == StateClosed, b.State == StateClosed
	if ac != bc {
		return ac
	}
	if !ac {
		if ra, rb := rank(a.Severity), rank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Notify != b.Notify {
			return !a.Notify
		}
	}
	return a.LastSeen.Before(b.LastSeen)
}

// sweepList closes the open and acked incidents of list that have been idle
// longer than idle at now, in place, and returns them. A non-positive idle
// closes nothing. Its caller passes a usable time (see usableTime), so a
// zero now cannot reach it.
func sweepList(list []Incident, now time.Time, idle time.Duration) []Incident {
	if idle <= 0 {
		return nil
	}
	var closed []Incident
	for i := range list {
		if list[i].State != StateClosed && now.Sub(list[i].LastSeen) > idle {
			list[i].State = StateClosed
			closed = append(closed, list[i])
		}
	}
	return closed
}

func addRetired(retired []string, id string) []string {
	retired = append(retired, id)
	if len(retired) > MaxRetiredIDs {
		retired = retired[len(retired)-MaxRetiredIDs:]
	}
	return retired
}

// Sweep closes the open and acked incidents that have been idle longer than
// the idle-close period at now (see WithIdleClose) and returns them, closed,
// so that the caller can audit them. Apply does the same with the signal's
// time; Sweep is for the daemon's idle moments. A time that cannot be
// recorded (see usableTime) is ErrInvalidSignal and closes nothing.
func (s *Store) Sweep(now time.Time) ([]Incident, error) {
	if !usableTime(now) {
		return nil, fmt.Errorf("%w: sweep time %v is zero or outside the years 1 to 9999", ErrInvalidSignal, now)
	}
	list := append([]Incident(nil), s.list...)
	closed := sweepList(list, now, s.idleClose)
	if len(closed) == 0 {
		return nil, nil
	}
	if err := s.save(list, s.retired); err != nil {
		return nil, err
	}
	s.list = list
	return closed, nil
}

// Apply records one signal. display holds the cleaned text (see Store).
//
// First, open and acked incidents idle longer than the idle-close period at
// the signal's time are closed (Result.AutoClosed). Then:
//
//   - unknown fingerprint: a new incident is opened (Opened). At
//     MaxIncidents one incident is evicted first (Result.Evicted, its id is
//     retired): a closed one, the one with the oldest LastSeen; if none is
//     closed, the open or acked one with the lowest severity, one that does
//     not want notification before one that does, then the oldest LastSeen. A
//     signal never evicts an incident more severe than itself: if the
//     candidate is, nothing is stored and Apply returns ErrFull with a Result
//     of Outcome Refused.
//   - open or acked incident: Count and LastSeen are updated (Updated), the
//     state stays, Title and Summary are replaced and the severity only
//     escalates.
//   - closed incident: it is reopened (Reopened), ReopenCount grows, NotifiedAt
//     is cleared and the severity is the reopening signal's.
//
// Result.Notify is true for Opened and Reopened when signal.Notify is set;
// Result.Pending covers a notification that was not marked (see Pending). The
// incident's Notify flag takes the signal's value when it is opened or
// reopened and is left alone on an update. LastSeen never moves backwards.
// A severity that is not one of result.Severities is ErrInvalidSignal, as is
// a signal time that cannot be recorded (see usableTime).
func (s *Store) Apply(sig event.Signal, display Display) (Result, error) {
	if !validFingerprint(sig.Fingerprint) {
		return Result{}, fmt.Errorf("%w: fingerprint %q", ErrInvalidSignal, sig.Fingerprint)
	}
	if rank(sig.Severity) < 0 {
		return Result{}, fmt.Errorf("%w: severity %q", ErrInvalidSignal, sig.Severity)
	}
	if !usableTime(sig.Time) {
		return Result{}, fmt.Errorf("%w: signal time %v is zero or outside the years 1 to 9999", ErrInvalidSignal, sig.Time)
	}
	title := cut(display.Title, MaxTitleRunes)
	summary := cut(display.Summary, MaxSummaryRunes)
	ruleID := cut(sig.RuleID, MaxRuleIDRunes)
	list := append([]Incident(nil), s.list...)
	retired := append([]string(nil), s.retired...)

	var res Result
	res.AutoClosed = sweepList(list, sig.Time, s.idleClose)

	idx := -1
	for i, in := range list {
		if in.Fingerprint == sig.Fingerprint {
			idx = i
			break
		}
	}
	if idx < 0 {
		fresh := Incident{
			Fingerprint: sig.Fingerprint, RuleID: ruleID,
			Severity: sig.Severity, State: StateOpen, Title: title, Summary: summary,
			Count: 1, FirstSeen: sig.Time, LastSeen: sig.Time, Notify: sig.Notify,
		}
		if len(list) >= MaxIncidents {
			ev := 0
			for i := range list {
				if victimBefore(list[i], list[ev]) {
					ev = i
				}
			}
			if v := list[ev]; v.State != StateClosed && rank(v.Severity) > rank(sig.Severity) {
				return Result{Outcome: Refused, Incident: fresh}, fmt.Errorf("%w (%d)", ErrFull, MaxIncidents)
			}
			res.Evicted = append(res.Evicted, Removed{ID: list[ev].ID, Fingerprint: list[ev].Fingerprint, State: list[ev].State})
			retired = addRetired(retired, list[ev].ID)
			list = append(list[:ev], list[ev+1:]...)
		}
		fresh.ID = newID(sig.Fingerprint, list, retired)
		list = append(list, fresh)
		res.Outcome, res.Incident, res.Notify = Opened, fresh, sig.Notify
	} else {
		in := list[idx]
		in.Count++
		if sig.Time.After(in.LastSeen) {
			in.LastSeen = sig.Time
		}
		in.Title, in.Summary = title, summary
		if CanReopen(in.State) {
			in.State = StateOpen
			in.ReopenCount++
			in.Notify = sig.Notify
			in.Severity = sig.Severity
			in.NotifiedAt = time.Time{}
			res.Outcome, res.Notify = Reopened, sig.Notify
		} else {
			if rank(sig.Severity) > rank(in.Severity) {
				in.Severity = sig.Severity
			}
			res.Outcome = Updated
			res.Pending = in.State == StateOpen && in.Notify && in.NotifiedAt.IsZero()
		}
		list[idx] = in
		res.Incident = in
	}
	if err := s.save(list, retired); err != nil {
		return Result{}, err
	}
	s.list, s.retired = list, retired
	return res, nil
}

// MarkNotified records that the notification of the incident was taken over
// at the given time (NotifiedAt), so that later updates are no longer
// Pending. It is written like a transition. A time that cannot be recorded
// (see usableTime) is ErrInvalidSignal and changes nothing.
func (s *Store) MarkNotified(id string, at time.Time) (Incident, error) {
	if !usableTime(at) {
		return Incident{}, fmt.Errorf("%w: notification time %v is zero or outside the years 1 to 9999", ErrInvalidSignal, at)
	}
	for i, in := range s.list {
		if in.ID != id {
			continue
		}
		list := append([]Incident(nil), s.list...)
		list[i].NotifiedAt = at
		if err := s.save(list, s.retired); err != nil {
			return Incident{}, err
		}
		s.list = list
		return list[i], nil
	}
	return Incident{}, fmt.Errorf("%w: %q", ErrUnknownIncident, id)
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
		if err := s.save(list, s.retired); err != nil {
			return Incident{}, err
		}
		s.list = list
		return list[i], nil
	}
	return Incident{}, fmt.Errorf("%w: %q", ErrUnknownIncident, id)
}
