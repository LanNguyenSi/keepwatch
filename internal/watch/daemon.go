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
// on the next start (at least once, never lost). A replayed signal is then an
// update of the incident it opened, so its audit record says incident_update
// where the lost one said incident_open.
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
//
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
//     after a capped exponential backoff from the last cursor. A restart that
//     is refused because of the cursor (journal rotated or vacuumed) is
//     audited as cursor_reset and restarts at now without a backoff. After
//     MaxRestarts consecutive failures without progress, or when journalctl
//     cannot be started at all, Run returns an error, so the process exits
//     non-zero and the service manager restarts it. Run returns nil only
//     after the context was cancelled.
//   - Notifications: the daemon paces retries of failed sends itself (the
//     alert worker gives the slot back on failure). An incident that wants a
//     notification and has none recorded is retried by the housekeeping pass,
//     at most once per max(PerIncidentInterval/4, the longest Retry-After the
//     ntfy client waits for) and with doubling gaps after each failure, up to
//     PerIncidentInterval. The ntfy client waits for a Retry-After of up to
//     that long inside the send; a longer one is not visible to the daemon (the
//     error carries no such field), so the doubling gap is what honours it.
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
	"github.com/LanNguyenSi/keepwatch/internal/journal"
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
	// PerIncidentInterval is the alert worker's per-incident interval; the
	// retry pacing derives from it. Zero selects one hour.
	PerIncidentInterval time.Duration
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

	d.mu.Lock()
	err := d.start()
	d.mu.Unlock()
	if err != nil {
		d.fail(err)
		return d.finish(err)
	}

	workerCtx, workerCancel := context.WithCancel(context.Background())
	workerDone, resultsDone, hkDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	if d.deps.Worker != nil {
		go func() { defer close(workerDone); d.deps.Worker.Run(workerCtx) }()
	} else {
		close(workerDone)
	}
	go d.resultLoop(resultsDone)
	hkCtx, hkCancel := context.WithCancel(context.Background())
	go d.housekeepLoop(hkCtx, hkDone)

	loopErr := d.streamLoop(runCtx)

	hkCancel()
	<-hkDone
	if loopErr == nil && d.failure() == nil {
		d.drain()
	}
	workerCancel()
	<-workerDone
	d.closeResults()
	<-resultsDone
	return d.finish(loopErr)
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

// streamLoop runs journalctl until the context ends or the loop gives up.
func (d *Daemon) streamLoop(ctx context.Context) error {
	backoff, fails := d.opt.BackoffMin, 0
	for {
		if ctx.Err() != nil {
			return d.failure()
		}
		d.mu.Lock()
		cur := d.cur
		d.delivered = 0
		d.mu.Unlock()
		args, err := journal.Args(cur)
		if err != nil {
			return fmt.Errorf("watch: %w", err)
		}
		res, serr := d.deps.Streamer.Stream(ctx, append([]string{d.opt.Program}, args...), execx.StreamOpts{}, d.onLine)
		if f := d.failure(); f != nil {
			return f
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(serr, execx.ErrNotAllowed) || errors.Is(serr, execx.ErrNotFound) {
			return fmt.Errorf("%w: %s cannot be started: %v", ErrStreamEnded, d.opt.Program, serr)
		}
		d.mu.Lock()
		reset, progress, err := d.streamEnded(res, serr, cur)
		d.mu.Unlock()
		if err != nil {
			return err
		}
		if reset {
			continue
		}
		if progress || res.Duration >= d.opt.StableAfter {
			backoff, fails = d.opt.BackoffMin, 0
		}
		fails++
		if fails > d.opt.MaxRestarts {
			return fmt.Errorf("%w: %d restarts without progress, last exit %d", ErrStreamEnded, fails-1, res.ExitCode)
		}
		if err := d.opt.Sleep(ctx, backoff); err != nil {
			return d.failure()
		}
		backoff = min(backoff*2, d.opt.BackoffMax)
	}
}
