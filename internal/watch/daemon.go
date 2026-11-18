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
// notification. Only then is the line "handled", and only handled lines move
// the cursor. A crash between the work and the cursor save replays the line
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
//     counts itself (sent or failed), as the worker gives a slot back when a
//     send fails. An incident is marked as mentioned only when its record was
//     written, so the takeover record covers the ones over the budget.
//     The incident store is unchanged; only the audit volume is bounded.
//     Worst case per NoiseInterval (1m) at the defaults, with R = 4 rules,
//     B = AuditBudget = 10 and G = GlobalPerMinute (1 to 60, default 6):
//     R*B = 40 incident records and R = 4 count records; at most G incident
//     records over the budget; at most G notify_sent or notify_failed records
//     of incident notifications; at most maxNotices*(1+60s/
//     HousekeepingInterval) = 8*3 = 24 records of daemon notices; and two
//     records for each of the 17 rate-limited keys (journal_line_invalid,
//     line_too_long, audit_refused, clock_clamp, incident_full,
//     signal_invalid, stream_restart, journal_gap, requests_pending,
//     requests_sweep, results_lost and notify_dropped for each of its six
//     reasons) = 34. That is 102+2G records: 114 at G = 6, 222 at G = 60.
//     Every summary but the terminal record's is cut to 512 bytes
//     (maxRecordSummary), and with Deps.Clean = the redact
//     package's Clean (control characters escaped) a record line is at most
//     1536 bytes, so the log grows by at most 171 KiB (G = 6) or 333 KiB
//     (G = 60) per minute, and DefaultMaxSize (256 MiB) lasts at least
//     25.5 hours (G = 6) or 13.1 hours (G = 60) of a flood that reaches
//     every bound at once.
//     The other records are not in an outsider's hands: request_rejected
//     (the spool is writable by root only), cursor_reset, and the start and
//     stop records of a process. The daemon sends one high-priority notice
//     when the log passes 80 % of its limit (once per process) and one when
//     it stops because the log is full, from whichever step found it full
//     (a line, a stream end, the flush at shutdown); the second is queued
//     before the terminal record is written into the reserve and before the
//     worker is stopped, and is sent within DrainTimeout.
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
//     file (system, each user) has its own; with a changed one and a seqnum
//     that does not follow, the record says the journal was replaced. After
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
//     log filling up or full) stay in a small pending set until they were
//     sent; every housekeeping pass sends the ones not in flight. They go
//     first: while one waits to be sent, no incident notification is handed
//     to the worker (those stay unnotified for the housekeeping retry), so
//     incidents cannot take the slots of the global limit a notice needs.
//   - Cursor saves are throttled: a line that produced a signal saves at once,
//     other lines at most once per CursorInterval, and the stream end, the
//     housekeeping pass and the shutdown save what is pending.
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
	// New installs the daemon's own OnResult on it.
	Worker *alert.Worker
	Cursor *CursorStore
	// Recovery is what audit.Open returned for a torn tail; the daemon
	// notifies it as a security-relevant event.
	Recovery *audit.Recovery
	// Requests is the request spool; nil switches the pass off.
	Requests *RequestOps
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
	// HousekeepingInterval is the period of the housekeeping pass.
	HousekeepingInterval time.Duration
	CursorInterval       time.Duration
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
	// GlobalPerMinute is how many notification jobs the worker may accept per
	// minute, sent or failed. The worker has the same limit but gives a slot
	// back when a send fails, so the daemon keeps its own count; the wiring
	// sets it once here and builds the worker's Params with AlertParams. Zero
	// selects DefaultGlobalPerMinute.
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
// global limit are the daemon's, so both are set in one place.
func (o Options) AlertParams(queueSize int, sendTimeout time.Duration) alert.Params {
	o = o.withDefaults()
	return alert.Params{
		QueueSize: queueSize, PerIncidentInterval: o.PerIncidentInterval,
		GlobalPerMinute: o.GlobalPerMinute, SendTimeout: sendTimeout,
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
	attempts      []time.Time          // when the worker accepted a job, last minute
	fillNoticed   bool
	gapFrom       string // saved cursor to compare the first line of a stream with

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
		d.fail(err)
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
	// full, found by any step (a line, a stream end, the flush here), sends
	// one notice before the worker is stopped. Each wait is bounded by
	// DrainTimeout.
	stopErr := d.failure()
	if stopErr == nil {
		stopErr = loopErr
	}
	if stopErr == nil {
		d.drain()
	}
	stopErr = d.flushAtStop(stopErr)
	if d.stopNotice(stopErr) {
		d.drain()
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
	return err
}

// stopNotice queues the notice of a stop because the audit log is full and
// reports whether it did. The terminal record is written after it, into the
// log's reserve.
func (d *Daemon) stopNotice(err error) bool {
	if !errors.Is(err, ErrAuditFull) {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.alertEvent("audit_full", "keepwatch: audit log is full, the watch daemon stopped",
		"The audit log reached its size limit and the watch daemon stopped, because it does not run without auditing. Move the log aside as described in the audit documentation and start the daemon again.")
	return true
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

// start writes daemon_start, loads the cursor and notifies a recovery.
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
	d.cur, d.saved = cur, cur
	if r := d.deps.Recovery; r != nil {
		d.alertEvent("audit_recovered", "keepwatch: audit log damaged and recovered",
			fmt.Sprintf("The audit log ended in a torn region (offset %d, %d bytes, sha256 %s, terminated %t, completed %t); a record accounts for it. Check the log with keepwatch audit verify.",
				r.Offset, r.Length, r.Hash, r.Terminated, r.Completed))
	}
	return nil
}
