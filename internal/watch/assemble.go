package watch

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/posture"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// The values of the daemon that the configuration does not have. They are
// decided here, in one place; Assemble is their only user.
const (
	// OOMWindow is how long the OOM rule remembers a reported victim, so the
	// several lines of one kill give one signal.
	OOMWindow = 10 * time.Minute
	// RuleMaxKeys caps the distinct keys (sources, units, victims) each
	// windowed rule remembers.
	RuleMaxKeys = rules.DefaultMaxKeys
	// IdleClose is how long an incident may go without a signal before the
	// store closes it.
	IdleClose = incident.DefaultIdleClose
	// DefaultQueue is the worker's queue size when watch.notify.queue is
	// zero; it matches the configuration's default (a test pins it).
	DefaultQueue = 100
	// MaxQueue and MaxGlobalPerMinute are the upper bounds of
	// watch.notify.queue and watch.notify.global_per_minute in the
	// configuration. Assemble refuses more: the audit volume arithmetic of
	// the package comment holds for G up to 60.
	MaxQueue           = 1000
	MaxGlobalPerMinute = 60
	// SendTimeout bounds one send of the worker. It is an upper bound with a
	// margin of the longest a ntfy send takes: two tries of DefaultTimeout
	// and one wait of max(DefaultBackoff, MaxRetryAfter) between them; the
	// sum adds both waits, a margin of DefaultBackoff.
	SendTimeout = 2*notify.DefaultTimeout + notify.DefaultBackoff + notify.MaxRetryAfter
	// The least severity of a posture signal is PostureMinSeverity
	// (posture.go), wired into posture.New here.
)

// var _ keeps posture.Source a PostureSource.
var _ PostureSource = (*posture.Source)(nil)

// Injections are the parts of the daemon Assemble does not build from the
// configuration.
type Injections struct {
	// Streamer runs journalctl; required (New refuses a nil one).
	Streamer execx.Streamer
	// Notifier sends notifications; a nil interface means no notifier is
	// configured, and the daemon runs without a worker. An interface that
	// holds a nil pointer (or another nil value, such as a nil func) is
	// refused: a worker over it would panic on its first send.
	Notifier notify.Notifier
	// Clock is the daemon clock for the daemon, the worker, the audit
	// writer and the baseline load; nil means time.Now.
	Clock func() time.Time

	// fail, when set, is called after each step with its name and the
	// assembly so far (tests).
	fail func(step string, a *Assembly) error
}

// Assembly is a daemon built by Assemble with what it holds open.
type Assembly struct {
	Daemon *Daemon
	// Dropped names each authorized_keys.expected entry the login rule
	// does not use, with the reason; the caller reports them.
	Dropped []string

	deps Deps
	opt  Options
	dir  *securefile.Dir
	aw   *audit.Writer
}

// Close closes what Assemble opened (the audit writer and the state
// directory handle). Call it after Run returned.
func (a *Assembly) Close() error {
	var errs []error
	if a.aw != nil {
		errs = append(errs, a.aw.Close())
	}
	if a.dir != nil {
		errs = append(errs, a.dir.Close())
	}
	return errors.Join(errs...)
}

// Assemble builds the daemon from cfg and the state directory stateDir:
// the rules engine (ssh brute force, restart loop, login anomaly, OOM) with
// the configured parameters, the incident store, the audit writer and its
// Recovery, the cursor store, the login baseline (loaded once; the login
// rule is built over exactly that store's baseline and the same store is
// Deps.Baseline, never nil), the posture source over the state file of
// check, the request spool and, when a notifier is injected, the alert
// worker.
//
// Options are built once, here: GlobalPerMinute and PerIncidentInterval
// come from watch.notify, and the worker's parameters are built from that
// same value with AlertParams, so the daemon and the worker cannot
// disagree. A zero watch.notify value (a Config not from config.Load)
// selects the daemon's default, which equals the configuration's default;
// a set value wins. Every other Options field keeps its default, among them
// AuditBudget, NoiseInterval and HousekeepingInterval (30s), which the
// configuration does not expose and the volume arithmetic of the package
// comment assumes.
//
// Precondition: the caller holds the watch lock of stateDir before it calls
// Assemble, because audit.Open resumes the log and may append to it. An
// error, from any step including New, is a failed start: the process exits
// non-zero. Everything opened by then is closed before Assemble returns.
//
// Every step that does not need the audit writer (the option checks of New,
// the redact patterns, the baseline and the rules, the posture source, the
// incident store) runs before audit.Open, so a refused start leaves a torn
// tail of the log as it is and the next start recovers it and notifies.
// Only the worker and New come after audit.Open, and with the checks before
// it neither can refuse; should one fail after all, the recovery notice of
// that start is lost (the audit_recovered record stays in the log).
func Assemble(cfg *config.Config, stateDir string, in Injections) (*Assembly, error) {
	if cfg == nil {
		return nil, errors.New("watch: Assemble needs a configuration")
	}
	n := cfg.Watch.Notify
	switch {
	case n.GlobalPerMinute < 0 || n.GlobalPerMinute > MaxGlobalPerMinute:
		return nil, fmt.Errorf("watch: watch.notify.global_per_minute must be 0 (default) or 1 to %d, got %d", MaxGlobalPerMinute, n.GlobalPerMinute)
	case n.Queue < 0 || n.Queue > MaxQueue:
		return nil, fmt.Errorf("watch: watch.notify.queue must be 0 (default) or 1 to %d, got %d", MaxQueue, n.Queue)
	case n.PerIncidentInterval != 0 && n.PerIncidentInterval < time.Minute:
		// The rule of New (a negative value included), checked before
		// anything is opened.
		return nil, fmt.Errorf("watch: watch.notify.per_incident_interval must be 0 (default) or at least 1m, got %v", n.PerIncidentInterval)
	case typedNil(in.Notifier):
		return nil, errors.New("watch: the notifier is an interface holding a nil value; pass a nil interface for no notifier")
	}
	a := &Assembly{}
	if err := a.build(cfg, stateDir, in); err != nil {
		a.Close()
		return nil, err
	}
	return a, nil
}

// build runs the steps of Assemble; what it opened stays in a, so the caller
// closes it on an error.
func (a *Assembly) build(cfg *config.Config, stateDir string, in Injections) (err error) {
	n := cfg.Watch.Notify
	clock := in.Clock
	if clock == nil {
		clock = time.Now
	}
	step := func(name string, e error) error {
		if e == nil && in.fail != nil {
			e = in.fail(name, a)
		}
		if e != nil {
			return fmt.Errorf("watch: %s: %w", name, e)
		}
		return nil
	}

	a.dir, err = securefile.OpenDir(stateDir, false, securefile.DefaultOwnerOf)
	if err = step("state directory", err); err != nil {
		return err
	}
	red, err := redact.New(cfg.Redact.Patterns)
	if err = step("redact patterns", err); err != nil {
		return err
	}
	baseline := NewBaselineStore(a.dir)
	var known map[string][]string
	known, a.Dropped = knownKeys(cfg.AuthorizedKeys.Expected)
	engine, err := buildEngine(cfg.Watch, known, baseline.Load(clock()))
	if err = step("rules", err); err != nil {
		return err
	}
	st, err := state.Open(stateDir)
	if err = step("posture", err); err != nil {
		return err
	}
	store, err := incident.Open(a.dir, incident.WithIdleClose(IdleClose))
	if err = step("incident store", err); err != nil {
		return err
	}
	// The writer is held as a.aw: the daemon names Deps.Audit only where it
	// writes records (a source pin in the tests).
	var rec *audit.Recovery
	a.aw, rec, err = audit.Open(a.dir, audit.Options{Now: clock})
	if err = step("audit log", err); err != nil {
		return err
	}
	a.deps = Deps{Streamer: in.Streamer, Clock: clock, Clean: red.Clean, Engine: engine, Incidents: store,
		Audit: a.aw, Recovery: rec, Cursor: NewCursorStore(a.dir), Requests: StateRequests(stateDir),
		Baseline: baseline, Posture: postureOf(posture.New(st, PostureMinSeverity))}

	a.opt = Options{GlobalPerMinute: n.GlobalPerMinute, PerIncidentInterval: n.PerIncidentInterval}
	if in.Notifier != nil {
		queue := n.Queue
		if queue == 0 {
			queue = DefaultQueue
		}
		w, werr := alert.NewWorker(in.Notifier, a.opt.AlertParams(queue, SendTimeout), nil)
		if err = step("alert worker", werr); err != nil {
			return err
		}
		w.Clock = clock
		a.deps.Worker = w
	}
	a.Daemon, err = New(a.deps, a.opt)
	if err = step("daemon", err); err != nil {
		return err
	}
	return nil
}

// typedNil reports whether v is a non-nil interface that holds a nil
// pointer, map, func, chan, interface or slice.
func typedNil(v any) bool {
	if v == nil {
		return false
	}
	switch r := reflect.ValueOf(v); r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Chan, reflect.Interface, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// postureOf returns src as a PostureSource, and a nil interface (posture
// off) for a nil *posture.Source, never an interface holding a nil pointer.
func postureOf(src *posture.Source) PostureSource {
	if src == nil {
		return nil
	}
	return src
}

// buildEngine builds the four journal rules from the watch section, the
// login rule over b with the known keys.
func buildEngine(w config.Watch, known map[string][]string, b *rules.Baseline) (*rules.Engine, error) {
	ssh, err1 := rules.NewSSHBruteForce(rules.Params{Threshold: w.SSHBruteforce.Threshold, Window: w.SSHBruteforce.Window, MaxKeys: RuleMaxKeys})
	restart, err2 := rules.NewRestartLoop(rules.Params{Threshold: w.RestartLoop.Threshold, Window: w.RestartLoop.Window, MaxKeys: RuleMaxKeys})
	login, err3 := rules.NewLoginAnomaly(rules.LoginParams{LearningPeriod: w.LearningPeriod, KnownKeys: known}, b)
	oom, err4 := rules.NewOOMKill(rules.OOMParams{Window: OOMWindow, MaxKeys: RuleMaxKeys})
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, err
	}
	return rules.NewEngine(ssh, restart, login, oom), nil
}

// Bounds of the login rule's known keys, the same as the baseline's (the
// rules package keeps them unexported): a user name and a normalized
// fingerprint are at most 64 bytes.
const (
	maxKnownUser = 64
	maxKnownKey  = 64
)

// knownKeys returns the authorized_keys.expected entries the login rule can
// use, and a reason for each one it cannot: a user name that is empty, over
// maxKnownUser bytes, not UTF-8 or with a control byte, and a fingerprint
// that does not normalize (SHA256: prefixes and = padding removed) to 1 to
// maxKnownKey bytes of the base64 alphabet. The rule drops the same entries
// silently; the reasons go to the caller. Reasons quote no input but the
// user name, cleaned by redact.Escape.
func knownKeys(expected map[string][]string) (map[string][]string, []string) {
	out := map[string][]string{}
	var dropped []string
	for user, fps := range expected {
		if !validKnownUser(user) {
			dropped = append(dropped, fmt.Sprintf("authorized_keys.expected: user \"%s\" is not a usable user name, its %d keys are not known to the login rule", redact.Escape(user), len(fps)))
			continue
		}
		for i, fp := range fps {
			if !validKnownKey(fp) {
				dropped = append(dropped, fmt.Sprintf("authorized_keys.expected.%s[%d]: not a SHA256 key fingerprint, not known to the login rule", redact.Escape(user), i))
				continue
			}
			out[user] = append(out[user], fp)
		}
	}
	slices.Sort(dropped)
	return out, dropped
}

func validKnownUser(u string) bool {
	if u == "" || len(u) > maxKnownUser || !utf8.ValidString(u) {
		return false
	}
	for i := 0; i < len(u); i++ {
		if c := u[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func validKnownKey(fp string) bool {
	for strings.HasPrefix(fp, "SHA256:") {
		fp = fp[len("SHA256:"):]
	}
	fp = strings.TrimRight(fp, "=")
	if fp == "" || len(fp) > maxKnownKey {
		return false
	}
	for i := 0; i < len(fp); i++ {
		switch c := fp[i]; {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		default:
			return false
		}
	}
	return true
}
