// Package watch is the core loop of the `keepwatch watch` daemon: it follows
// the journal, decodes each line, runs the rules, keeps incidents, writes the
// audit log, hands notifications to the alert worker and remembers how far it
// has read.
//
// # Order of work
//
// For each journal line: decode, evaluate the rules, and for each signal
// build the display text (the one place that cleans host text, see display),
// apply it to the incident store, append the audit records and enqueue the
// notification. Then the login baseline is saved when the line changed it
// (see Login baseline). Only then is the line "handled", and only handled
// lines move the cursor. A crash between the work and the cursor save replays the line
// on the next start (at least once, never lost). A crash between the incident
// store write and the audit record leaves an incident the log does not mention.
// Rule windows live in memory, so the replayed line of a threshold rule gives
// no signal again, and nothing but the housekeeping pass finds the incident;
// it writes an incident_update record "found without a recorded notification"
// the first time it takes over such an incident in a process, before it
// notifies. (A rule that fires on a single line, such as the OOM rule, gives
// its signal again and the replay audits as incident_update.)
//
// # Single transformation
//
// Raw host text (event fields, request names, error texts that quote input)
// goes through Deps.Clean in exactly one function, Daemon.safe. The incident
// store, the audit log and the notification only ever see its output. The
// message of an incident is formatted from the incident's own cleaned fields
// with an identity function, so nothing is transformed twice.
//
// # Policies
//   - A line that cannot be decoded, or has no timestamp, is skipped and the
//     cursor moves past it when the line names one. Such lines are audited as
//     journal_line_invalid with a rate limit: the first one of a kind at once,
//     the rest as one record with a count per NoiseInterval, so a local user
//     cannot fill the audit log with them. The same limiter serves every other
//     warning-like record (refused audit records, clock clamps, store full,
//     dropped notifications).
//   - An audit write failure stops the daemon with an error (no unaudited
//     operation). When the log is at its size limit the daemon writes one
//     terminal daemon_error record into the reserve and stops with
//     ErrAuditFull. A record the log refuses as invalid is counted and
//     audited as input_error, and auditing goes on.
//   - Audit volume: whoever can make the host log lines can make signals at
//     will, so every audit record about an incident (open, update, reopen,
//     the closes and evictions a signal causes, idle closes, the takeover
//     record of the housekeeping retry) goes through one function, admit.
//     Per rule and NoiseInterval it writes at most AuditBudget records, and
//     at most one incident_update per incident; the rest of a rule's window
//     is counted into one record when the window ends. A rule's flood
//     therefore cannot use up another rule's budget. The record of an
//     incident whose notification the worker accepted is written even over
//     the budget, so nothing is sent for an incident the log does not
//     mention; such records are bounded by GlobalPerMinute, which the daemon
//     counts itself for incident notifications (sent or failed), as the
//     worker gives a slot back when a send fails. An incident is marked as
//     mentioned only when its record was
//     written, so the takeover record covers the ones over the budget.
//     The incident store is unchanged; only the audit volume is bounded.
//     Worst case per NoiseInterval (1m) at the defaults, with R = 5 rules
//     (the four journal rules and posture), B = AuditBudget = 10 and
//     G = GlobalPerMinute (1 to 60, default 6):
//     R*B = 50 incident records and R = 5 count records; at most G incident
//     records over the budget; at most G notify_sent or notify_failed records
//     of incident notifications; at most maxNotices*(1+60s/
//     HousekeepingInterval) = 8*3 = 24 records of daemon notices; and two
//     records for each of the 19 rate-limited keys (journal_line_invalid,
//     line_too_long, audit_refused, clock_clamp, incident_full,
//     signal_invalid, stream_restart, journal_gap, requests_pending,
//     requests_sweep, results_lost, posture_poll, posture_overflow and
//     notify_dropped for each of its six reasons) = 38. That is 117+2G
//     records: 129 at G = 6, 237 at G = 60.
//     Every summary but the terminal record's is cut to 512 bytes
//     (maxRecordSummary), and with Deps.Clean = the redact
//     package's Clean (control characters escaped) a record line is at most
//     1536 bytes, so the log grows by at most 193.5 KiB (G = 6) or 355.5 KiB
//     (G = 60) per minute, and DefaultMaxSize (256 MiB) lasts at least
//     22.5 hours (G = 6) or 12.2 hours (G = 60) of a flood that reaches
//     every bound at once.
//     The other records are not in an outsider's hands: request_rejected
//     (the spool is writable by root only), the records of applied requests
//     (see Requests), cursor_reset, the input_error of a login baseline
//     reset, and the start and stop records of a process. The records of
//     applied requests (incident_ack, incident_close and request_rejected
//     for a request that cannot be applied) are incident records outside
//     admit, written by requestRecord alone and bounded by
//     requests.MaxPending per pass: at most
//     MaxPending*(1+60s/HousekeepingInterval) = 100*3 = 300 per minute at the
//     defaults, at most 450 KiB, on top of the flood above only when root
//     fills the spool. The daemon sends one high-priority notice
//     when the log passes 80 % of its limit (once per process) and one when
//     it stops because the log is full, from whichever step found it full
//     (a line, a stream end, the flush at shutdown); the second is handed to
//     the worker before the terminal record is written into the reserve and
//     before the worker is stopped. While the worker's queue is full it is
//     handed on again, for at most DrainTimeout, and the worker's global
//     limit has room for it (see Notifications). It is still lost when its
//     one send fails or the queue does not clear within DrainTimeout; the
//     terminal record says why the daemon stopped either way.
//   - Audit start: Run does not verify the chain. Open resumes from the last
//     intact record, and a full verification would read up to the whole log on
//     every start of a restart loop; `keepwatch audit verify` and doctor are
//     the places for that. A start that fails writes at most one terminal
//     record per audit writer, so a restart loop is bounded by the unit's
//     start limit.
//   - Clock: the rules get the journal's own timestamp of the line, never the
//     daemon clock (the two are never mixed), and a line without a timestamp
//     is not evaluated. A signal time more than ClockSkew ahead of the daemon
//     clock is clamped to the daemon clock and the clamp is audited.
//   - The stream: when journalctl exits or the stream fails it is restarted
//     after a capped exponential backoff from the last cursor. journalctl
//     refuses a malformed cursor ("Failed to seek to cursor: Invalid
//     argument", exit 1); that is audited as cursor_reset ("journalctl
//     refused the saved cursor as invalid") and the stream restarts at now
//     without a backoff. A cursor whose entry was vacuumed or whose journal
//     was replaced is not an error: journalctl continues from the oldest
//     entry it still has. The daemon therefore compares the first line after
//     a restart with the saved cursor, once per stream: journald numbers the
//     entries of all its files from one counter, so a seqnum (i=) that is
//     not the saved one plus one is audited as journal_gap (no
//     notification). The seqnum id (s=) alone says nothing, as each journal
//     file (system, each user) has its own. The record counts missing
//     entries only for the same seqnum id with a seqnum further ahead. In
//     every other case it says that the seqnum does not follow the saved
//     cursor and that entries may be missing or the journal files were
//     replaced, because the daemon cannot tell: journald of systemd 249
//     starts its files with a new seqnum id and a seqnum of 1 after it was
//     killed, without losing an entry, so on such a host a journal_gap
//     record after a journald crash is no proof of a loss. After
//     MaxRestarts consecutive failures without progress, or when journalctl
//     cannot be started at all, Run returns an error, so the process exits
//     non-zero and the service manager restarts it. Run returns nil only
//     after the context was cancelled. A Sleep error that is not the
//     context's ends the loop with that error.
//   - Notifications: the daemon paces retries of failed sends itself (the
//     alert worker gives the slot back on failure). An incident that wants a
//     notification and has none recorded is retried by the housekeeping pass,
//     at most once per max(PerIncidentInterval/4, the longest Retry-After the
//     ntfy client waits for) and with doubling gaps after each failure, up to
//     PerIncidentInterval. The ntfy client waits for a Retry-After of up to
//     that long inside the send; a longer one is not visible to the daemon (the
//     error carries no such field), so the doubling gap is what honours it.
//     Notices of the daemon itself (an audit recovery, a full spool, the audit
//     log filling up or full, a login baseline reset) stay in a small pending set until they were
//     sent; every housekeeping pass sends the ones not in flight. They go
//     first: while one waits to be sent, no incident notification is handed
//     to the worker (those stay unnotified for the housekeeping retry), so
//     incidents cannot take the place in the queue a notice needs. Notices
//     are not counted against GlobalPerMinute, so one that keeps failing
//     cannot use up the limit of the incidents; their own bound is
//     maxNotices per pass. The worker's global limit is GlobalPerMinute +
//     maxNotices (AlertParams): incident notifications hold at most
//     GlobalPerMinute of its slots, and each notice key at most one, as
//     long as PerIncidentInterval is at least a minute.
//   - Requests: the request pass applies the accepted ack and close
//     requests of the spool (at most requests.MaxPending per pass) through
//     the incident store. It runs once in start, after the stores are open
//     and before the stream is followed, and then in every housekeeping
//     pass, so an ack or close takes effect within one
//     HousekeepingInterval (30s by default). The order is apply, then audit,
//     then Remove. A request the store refuses (an unknown, retired or
//     evicted id, a target state already reached, any move CanTransition
//     does not allow) is audited as request_rejected with the reason and
//     removed. The note is cleaned first and then cut; RequestedAt is the
//     writer's claim and appears in the summary as such, never as the
//     record time, which is the daemon clock. A crash after the store write
//     and before the record leaves the transition without its record, like
//     the signal crash window above; a crash after the record and before
//     Remove leaves the file. Either way the next start replays the request
//     in its first request pass, before any line of the new process can
//     reopen the incident, finds the target state reached and writes
//     request_rejected "already acked" (or closed, or "cannot move" for an
//     ack whose incident was closed meanwhile), never a second incident_ack
//     or incident_close. This holds when the pass at start lists the spool:
//     a listing failure at start is audited as input_error (not fatal) and
//     leaves the replay to the first housekeeping pass, and while the spool
//     is overfull the examined window is not in submission order, so a
//     request may wait beyond the pass at start. A request_rejected for a
//     known incident carries its id and fingerprint. A fatal error of the
//     pass at start (audit full, a store that cannot save) stops the start.
//     A name whose record was written is remembered while Remove keeps
//     failing, so it is neither applied nor audited again; the memory ends
//     when the name leaves the listing. A failing Remove is silent (no
//     record), and while MaxPending applied names cannot be removed they
//     fill the window requests.Pending returns, so acks and closes behind
//     them stop until the files are gone; only root can create that state.
//     A pass applies requests before it
//     retries notifications, and the retry wants an open incident, so an ack
//     or a close stops a notification that was still pending (no retry, no
//     reconcile send after it). A notification the worker accepted before the
//     ack can still be sent: the worker has no way to take a job back.
//   - Cursor saves are throttled: a line that produced a signal saves at once,
//     other lines at most once per CursorInterval, and the stream end, the
//     housekeeping pass and the shutdown save what is pending.
//
// # Posture
//
// The housekeeping pass polls Deps.Posture (nil switches it off) with the
// daemon clock, after the request pass and before the notification retry.
// The first state the source sees is its baseline and gives nothing, so a
// change shows up from the second state on (see the posture package).
// Each signal takes the journal-signal path (handleSignal: display, which
// cleans its subject and summary again although the state file holds
// cleaned text, as the file is input; the incident store; admit), with rule
// id "posture" and Notify false set by the daemon whatever the source
// returned. A signal whose fingerprint belongs to a stored incident of
// another rule is refused and counted (signal_invalid), so it cannot take
// over that incident's Notify; the posture package puts its rule id first
// into every fingerprint, so its signals never meet that case. Every
// notification path (the open, the reopen, an update that is pending, the
// refused path, the takeover of the housekeeping retry) asks the incident's
// or the signal's Notify, and an incident takes Notify only from the signal
// that opens or reopens it, so a posture incident is never notified; that
// holds while no journal rule uses the rule id "posture" (a test pins it).
// `check --notify` is the one path that notifies about posture. Posture
// records count against the budget of rule "posture", so a posture flood
// does not use up a journal rule's budget, and the store's eviction rule (a
// signal never evicts an open or acked incident more severe than itself,
// and refuses with ErrFull instead) keeps a posture flood from pushing out
// more severe journal incidents; among incidents of one severity those that
// do not want notification, posture ones, go first.
//
// A pass handles at most posturePerPass signals: the rule's budget shared
// by the most passes one budget window can see, which is one more than the
// interval ratio, as a window starts at its first record and a pass can
// come a moment late (AuditBudget/(NoiseInterval/HousekeepingInterval + 1),
// at least 1 and at most AuditBudget; 3 at the defaults), so a backlog of
// signals that each write one record is written, not counted
// (a signal that evicts an incident writes two, and those are counted over
// the budget). The rest wait in a queue of at most postureQueueMax (500, the
// incident store's cap) for the next passes: across polls in the order of
// the polls, within one poll the most severe first (stable). Signals that do
// not fit the queue, the least severe of the poll, are dropped and counted
// through the noise path (posture_overflow): the first drop of a window is
// written at once, the rest as one count record when the window ends. The
// queue lives in memory: a clean stop counts the signals still queued
// through the same key, with its own text, and does not handle them; a crash
// loses them without a record. The baseline of the posture source is in
// memory too, so these changes do not come back after a restart; `check
// --notify` still reports them. A poll error is audited as input_error
// through the noise path (posture_poll), cleaned, on every pass it happens,
// and the queue is worked on anyway. The stall under d.mu a pass adds is one
// load of the state file (state.MaxFileSize, 16 MiB, and its comparison
// with the run before) and at most posturePerPass incident store writes with
// their records, no more than AuditBudget signals of one journal line.
//
// # Login baseline
//
// The login rule's baseline lives in BaselineFile in the state directory
// (BaselineStore; nil Deps.Baseline switches persistence off). The wiring
// loads it before it builds the rules engine; start acts on what the load
// found, before the stream starts:
//   - A missing file gives a new baseline whose learning starts at the load,
//     and that baseline is saved at once, so a restart does not restart
//     learning.
//   - A file that fails the trust checks of securefile (owner, mode, symlink,
//     not a regular file), and any other read error, stops the start with
//     ErrBaselineLoad, like the cursor; the error text goes through safe.
//   - A file that is over MaxBaselineBytes (refused before it is read), that
//     rules.Unmarshal refuses (corrupt, an unknown schema_version, a bound),
//     or that is empty, is not trusted as a baseline: the daemon starts with
//     the zero LearningStart (no learning phase: every login from an unknown
//     source notifies), writes an input_error record and a daemon notice
//     naming the reason (through safe), keeps the file as BaselineAsideFile,
//     and saves the new baseline. The copy is a hard link made before the
//     new baseline replaces the file, so a crash in between finds the file
//     again; there is at most one copy, the next reset replaces it. When
//     the copy cannot be made, or the held directory has no copy
//     afterwards, the start stops with ErrBaselineLoad and the file stays
//     as it is. An earlier copy satisfies that check, so a path swap by
//     whoever can write the parent of the state directory (root) can still
//     lose the new copy; a link operation in securefile would close it.
//
// The read is bounded by MaxBaselineBytes, the bound rules.Unmarshal applies
// itself, and there is no streaming decoder: the worst document at the bound
// measured (a users array of about 1.1 million bare numbers) peaks at about
// 190 MB resident on linux while encoding/json decodes it, about 130 MB
// under GOMEMLIMIT=64MiB, next to the unit's MemoryMax=256M. That is a decision for a trusted file:
// it passed the securefile checks, so only root or the daemon's user can
// have written it, and either can already stop the daemon.
//
// The baseline is saved after every change, with no throttle, after the
// signals of the line were handled and before the cursor save: a crash in
// between replays the line against the saved baseline, and a source that
// was learned but whose signal was not handled is not saved as known. A
// change includes the learning latch flipping on a line that gives no
// signal, and entries learned in the learning phase (their info signals do
// not notify). A save failure stops the daemon. Change detection costs O(1)
// per line: the baseline is marshalled only when the line gave a login
// signal or LearningDone differs from its value at the last save (the login
// rule adds an entry only in an Evaluate that returns a signal for it, and
// a test pins that), and written only when the JSON differs from the file.
//
// A baseline reset (a new or reset baseline) with a resumed cursor: the
// backlog after the cursor is evaluated against the new baseline, and its
// login lines carry journal times before the new LearningStart, which the
// login rule counts as after the learning phase, so every unknown source in
// the backlog notifies. With a reset baseline (zero LearningStart) that holds
// for every line anyway.
//
// # Assembly
//
// Assemble builds Deps and Options from the configuration and the state
// directory, in one place: the constants the configuration does not have,
// the precedence of watch.notify (a set value wins, zero is the default) and
// the caller's preconditions (the watch lock held, an error is a failed
// start) are documented there.
package watch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
)

// Errors returned by Run. Each means the process must exit non-zero.
var (
	// ErrStreamEnded: the journal stream ended and could not be restarted.
	ErrStreamEnded = errors.New("watch: the journal stream ended and could not be restarted")
	// ErrAuditFull: the audit log reached its size limit.
	ErrAuditFull = errors.New("watch: the audit log is full")
)

// Defaults applied by New to zero Options fields.
const (
	DefaultBackoffMin           = time.Second
	DefaultBackoffMax           = time.Minute
	DefaultMaxRestarts          = 10
	DefaultStableAfter          = 30 * time.Second
	DefaultNoiseInterval        = time.Minute
	DefaultClockSkew            = 5 * time.Minute
	DefaultDrainTimeout         = 10 * time.Second
	DefaultHousekeepingInterval = 30 * time.Second
	DefaultCursorInterval       = 2 * time.Second
	DefaultTempAge              = time.Hour
	DefaultTempSweepInterval    = 10 * time.Minute
	// DefaultAuditBudget is the per-rule and per-interval budget of incident
	// records, see the package comment for the fill time it gives.
	DefaultAuditBudget = 10
	// DefaultGlobalPerMinute is the notification limit when Options leave it
	// zero; it matches the configuration's default.
	DefaultGlobalPerMinute = 6
)

// Deps are the injected parts of the daemon.
type Deps struct {
	Streamer  execx.Streamer
	Clock     func() time.Time // nil means time.Now
	Clean     func(string) string
	Engine    *rules.Engine
	Incidents *incident.Store
	Audit     *audit.Writer
	// Worker delivers notifications; nil means no notifier is configured.
	// New installs the daemon's own OnResult on it. It must be built with
	// Options.AlertParams (see there for what other limits cost).
	Worker *alert.Worker
	Cursor *CursorStore
	// Recovery is what audit.Open returned for a torn tail; the daemon
	// notifies it as a security-relevant event.
	Recovery *audit.Recovery
	// Requests is the request spool; nil switches the pass off.
	Requests *RequestOps
	// Baseline is the store of the login rule's baseline, loaded before the
	// engine was built; nil switches its persistence off.
	Baseline *BaselineStore
	// Posture is polled by the housekeeping pass (see Posture); nil
	// switches it off.
	Posture PostureSource
}

// Options tune the daemon. A zero field selects its default; a negative
// CursorInterval saves the cursor after every handled line.
type Options struct {
	// Program is the journalctl executable name; default "journalctl".
	Program string
	// BackoffMin and BackoffMax bound the wait before a stream restart.
	BackoffMin, BackoffMax time.Duration
	// MaxRestarts is how many consecutive restarts without progress Run
	// tries before it gives up. A stream that delivered a line or ran for
	// StableAfter made progress.
	MaxRestarts int
	StableAfter time.Duration
	// NoiseInterval is the rate-limit window of repeated warning records.
	NoiseInterval time.Duration
	// ClockSkew is how far a signal time may be ahead of the daemon clock.
	ClockSkew time.Duration
	// DrainTimeout bounds how long shutdown waits for queued notifications.
	DrainTimeout time.Duration
	// HousekeepingInterval is the period of the housekeeping pass. It is also
	// the latency of an ack or close request: the pass applies them.
	HousekeepingInterval time.Duration
	// HousekeepingTick is the tick source of the housekeeping pass: each value
	// received starts one pass. Nil means a time.Ticker with
	// HousekeepingInterval. Tests replace it; it must not be closed while Run
	// runs.
	HousekeepingTick <-chan time.Time
	CursorInterval   time.Duration
	// PerIncidentInterval is the least time between two notices of one
	// incident, and the base of the retry pacing. The alert worker has the
	// same parameter with another zero meaning (off), so the wiring sets it
	// once here and builds the worker's Params with AlertParams. Zero selects
	// one hour; there is no "off".
	PerIncidentInterval time.Duration
	// AuditBudget is how many incident records (opens, updates, reopens,
	// closes, evictions) one rule may write per NoiseInterval; the excess is
	// counted into one record per rule and interval. Zero selects
	// DefaultAuditBudget.
	AuditBudget int
	// GlobalPerMinute is how many incident notifications the worker may accept
	// per minute, sent or failed. The worker has a limit of its own but gives
	// a slot back when a send fails, so the daemon keeps its own count; the
	// wiring sets it once here and builds the worker's Params with
	// AlertParams. Zero selects DefaultGlobalPerMinute; New refuses a negative
	// value, a negative AuditBudget, and a PerIncidentInterval that is
	// negative or below one minute.
	GlobalPerMinute int
	// TempAge and TempSweepInterval govern the sweep of stale temporary
	// request files.
	TempAge           time.Duration
	TempSweepInterval time.Duration
	// Sleep waits for d or until ctx ends; nil uses a timer. Tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (o Options) withDefaults() Options {
	def := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	if o.Program == "" {
		o.Program = "journalctl"
	}
	def(&o.BackoffMin, DefaultBackoffMin)
	def(&o.BackoffMax, DefaultBackoffMax)
	def(&o.StableAfter, DefaultStableAfter)
	def(&o.NoiseInterval, DefaultNoiseInterval)
	def(&o.ClockSkew, DefaultClockSkew)
	def(&o.DrainTimeout, DefaultDrainTimeout)
	def(&o.HousekeepingInterval, DefaultHousekeepingInterval)
	def(&o.CursorInterval, DefaultCursorInterval)
	def(&o.PerIncidentInterval, time.Hour)
	def(&o.TempAge, DefaultTempAge)
	def(&o.TempSweepInterval, DefaultTempSweepInterval)
	if o.AuditBudget == 0 {
		o.AuditBudget = DefaultAuditBudget
	}
	if o.GlobalPerMinute == 0 {
		o.GlobalPerMinute = DefaultGlobalPerMinute
	}
	if o.MaxRestarts == 0 {
		o.MaxRestarts = DefaultMaxRestarts
	}
	if o.BackoffMax < o.BackoffMin {
		o.BackoffMax = o.BackoffMin
	}
	if o.Sleep == nil {
		o.Sleep = sleepTimer
	}
	return o
}

// AlertParams returns the worker parameters whose per-incident interval and
// global limit follow the daemon's, so both are set in one place. The
// worker's global limit is GlobalPerMinute + maxNotices: the daemon itself
// keeps incident notifications at GlobalPerMinute, and the rest is room for
// its own notices, so a notice (the stop notice above all) is not dropped
// because incident notifications used the limit up.
//
// Deps.Worker must be built with these parameters. The daemon counts on
// them: with a lower global limit in the worker, its notices use up the
// slots of the incident notifications, which are then dropped as rate
// limited and marked notified without a message. So a worker with other
// limits loses incident notifications, not only notices.
func (o Options) AlertParams(queueSize int, sendTimeout time.Duration) alert.Params {
	o = o.withDefaults()
	return alert.Params{
		QueueSize: queueSize, PerIncidentInterval: o.PerIncidentInterval,
		GlobalPerMinute: o.GlobalPerMinute + maxNotices, SendTimeout: sendTimeout,
	}
}

func sleepTimer(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Daemon is the core loop. Create it with New and call Run once.
type Daemon struct {
	deps Deps
	opt  Options

	// mu guards everything below. It is held while a line, an alert result or
	// a housekeeping pass is handled, so the incident store (which does no
	// locking of its own) has one user at a time.
	mu            sync.Mutex
	cur, saved    string // cursor of the last handled line, and of the one on disk
	lastSave      time.Time
	delivered     int // lines the current stream delivered
	noisy         map[string]*noiseState
	inflight      map[string]int // accepted notification jobs by fingerprint
	inflightTotal int
	tries         map[string]tryState
	rejAudited    map[string]bool
	overfull      bool
	lastTempSweep time.Time
	notices       map[string]notice    // daemon notices not yet sent, by fingerprint
	logged        map[string]bool      // incident ids the audit log mentions in this process
	updated       map[string]time.Time // time of the last incident_update record, by incident id
	attempts      []time.Time          // when the worker accepted an incident notification, last minute
	fillNoticed   bool
	gapFrom       string         // saved cursor to compare the first line of a stream with
	gapSkipped    bool           // a line of the current stream named no usable cursor
	postureQueue  []event.Signal // posture signals waiting for a later pass

	results   chan alert.Result
	resMu     sync.RWMutex
	resClosed bool
	lost      atomic.Int64

	failMu    sync.Mutex
	failErr   error
	cancelRun context.CancelFunc
	started   bool
}

// New checks deps and returns the daemon.
func New(deps Deps, opt Options) (*Daemon, error) {
	switch {
	case deps.Streamer == nil:
		return nil, errors.New("watch: no streamer")
	case deps.Clean == nil:
		return nil, errors.New("watch: no clean function")
	case deps.Engine == nil:
		return nil, errors.New("watch: no rules engine")
	case deps.Incidents == nil:
		return nil, errors.New("watch: no incident store")
	case deps.Audit == nil:
		return nil, errors.New("watch: no audit writer")
	case deps.Cursor == nil:
		return nil, errors.New("watch: no cursor store")
	}
	if opt.GlobalPerMinute < 0 || opt.AuditBudget < 0 {
		return nil, errors.New("watch: GlobalPerMinute and AuditBudget must not be negative")
	}
	// The room for notices in the worker's limit (see AlertParams) is one
	// slot per notice key and minute, which a shorter interval does not keep.
	if opt.PerIncidentInterval != 0 && opt.PerIncidentInterval < time.Minute {
		return nil, errors.New("watch: PerIncidentInterval must be zero or at least one minute")
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	d := &Daemon{
		deps: deps, opt: opt.withDefaults(),
		noisy: map[string]*noiseState{}, inflight: map[string]int{},
		tries: map[string]tryState{}, rejAudited: map[string]bool{},
		notices: map[string]notice{}, logged: map[string]bool{}, updated: map[string]time.Time{},
		results: make(chan alert.Result, 4096),
	}
	if deps.Worker != nil {
		deps.Worker.OnResult = d.onResult
	}
	return d, nil
}

// fail records the first fatal error and ends the stream.
func (d *Daemon) fail(err error) {
	d.failMu.Lock()
	if d.failErr == nil {
		d.failErr = err
	}
	cancel := d.cancelRun
	d.failMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (d *Daemon) failure() error {
	d.failMu.Lock()
	defer d.failMu.Unlock()
	return d.failErr
}

// Run follows the journal until ctx is cancelled (nil) or a fatal error
// occurs (the error). It may be called once.
func (d *Daemon) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return errors.New("watch: Run was called twice")
	}
	d.started = true
	d.mu.Unlock()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.failMu.Lock()
	d.cancelRun = cancel
	d.failMu.Unlock()

	// The worker and the result loop run before start: the first records can
	// already notify (a recovery), and a start that fails because the audit
	// log is full still sends its stop notice.
	workerCtx, workerCancel := context.WithCancel(context.Background())
	workerDone, resultsDone, hkDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	if d.deps.Worker != nil {
		go func() { defer close(workerDone); d.deps.Worker.Run(workerCtx) }()
	} else {
		close(workerDone)
	}
	go d.resultLoop(resultsDone)

	d.mu.Lock()
	err := d.start()
	d.mu.Unlock()
	var loopErr error
	if err != nil {
		loopErr = err
		close(hkDone)
	} else {
		hkCtx, hkCancel := context.WithCancel(context.Background())
		go d.housekeepLoop(hkCtx, hkDone)
		loopErr = d.streamLoop(runCtx)
		hkCancel()
		<-hkDone
	}

	// Shutdown: a clean stop lets queued notifications finish, then the
	// pending cursor and counts are written. A stop because the audit log is
	// full, found by any step (a line, a stream end, the flush here), hands
	// one notice to the worker before the worker is stopped. Each wait is
	// bounded by DrainTimeout.
	stopErr := d.failure()
	if stopErr == nil {
		stopErr = loopErr
	}
	if stopErr == nil {
		d.drain()
	}
	stopErr = d.flushAtStop(stopErr)
	if errors.Is(stopErr, ErrAuditFull) {
		d.deliverStopNotice()
	}
	workerCancel()
	<-workerDone
	d.closeResults()
	<-resultsDone
	return d.finish(stopErr)
}

// flushAtStop saves the pending cursor and, when there is no error yet
// (also none recorded while draining), writes the pending counts. It returns
// the error Run ends with.
func (d *Daemon) flushAtStop(err error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil {
		err = d.failure()
	}
	if cerr := d.flushCursor(); err == nil {
		err = cerr
	}
	if err == nil {
		err = d.flushNoise(true)
	}
	if err == nil {
		err = d.countQueuedAtStop()
	}
	return err
}

// stopNoticeKey is the key of the notice of a stop because the audit log is
// full.
const stopNoticeKey = "audit_full"

// deliverStopNotice hands the notice of a stop because the audit log is full
// to the worker and waits until nothing is in flight, at most DrainTimeout.
// While the worker has not accepted the notice (its queue is full) it is
// handed on again. A notice the worker accepted is not handed on a second
// time, whatever became of its send. The terminal record is written after
// this, into the log's reserve.
func (d *Daemon) deliverStopNotice() {
	fp := noticeFingerprint(stopNoticeKey)
	d.mu.Lock()
	d.alertEvent(stopNoticeKey, "keepwatch: audit log is full, the watch daemon stopped",
		"The audit log reached its size limit and the watch daemon stopped, because it does not run without auditing. Move the log aside as described in the audit documentation and start the daemon again.")
	accepted := d.inflight[fp] > 0
	d.mu.Unlock()
	deadline := time.Now().Add(d.opt.DrainTimeout)
	for {
		d.mu.Lock()
		_, pending := d.notices[fp]
		if pending && !accepted {
			accepted = d.sendNotice(fp)
		}
		waiting := d.inflightTotal > 0 || (pending && !accepted)
		d.mu.Unlock()
		if !waiting || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// drain waits until no notification is in flight, but at most DrainTimeout.
func (d *Daemon) drain() {
	deadline := time.Now().Add(d.opt.DrainTimeout)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := d.inflightTotal
		d.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// start writes daemon_start, loads the cursor, acts on the loaded login
// baseline (see Login baseline), notifies a recovery and runs the request
// pass once.
func (d *Daemon) start() error {
	cur, err := d.deps.Cursor.Load()
	reason := ""
	switch {
	case err == nil:
	case errors.Is(err, ErrInvalidCursor):
		reason = fmt.Sprintf("the saved cursor is unusable (%s); starting at now", d.safe(err.Error()))
		cur = ""
	default:
		return fmt.Errorf("watch: cannot read the cursor: %w", err)
	}
	how := "starting at now"
	if cur != "" {
		how = "resuming from the saved cursor"
	}
	if err := d.record(audit.DaemonStart, "", "", "daemon started, "+how); err != nil {
		return err
	}
	if reason != "" {
		if err := d.deps.Cursor.Save(""); err != nil {
			return fmt.Errorf("watch: cannot reset the cursor: %w", err)
		}
		if err := d.record(audit.CursorReset, "", "", reason); err != nil {
			return err
		}
	}
	if err := d.startBaseline(); err != nil {
		return err
	}
	d.cur, d.saved = cur, cur
	if r := d.deps.Recovery; r != nil {
		d.alertEvent("audit_recovered", "keepwatch: audit log damaged and recovered",
			fmt.Sprintf("The audit log ended in a torn region (offset %d, %d bytes, sha256 %s, terminated %t, completed %t); a record accounts for it. Check the log with keepwatch audit verify.",
				r.Offset, r.Length, r.Hash, r.Terminated, r.Completed))
	}
	// The request pass runs once before the stream is followed, so a request
	// replayed after a restart meets the state the previous process left,
	// before a line can reopen its incident.
	return d.requestsPass()
}
