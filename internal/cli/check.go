package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/render"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// env holds what `check` needs from the outside; tests replace it. The zero
// value of each field means "the real thing".
type env struct {
	ctx      context.Context
	catalog  *catalog.Catalog
	runner   execx.Runner
	fs       probes.FS
	statfs   probes.StatfsFunc
	now      func() time.Time
	hostname func() (string, error)
	ownerOf  state.OwnerOf
	// buildState turns the results into the state of the run; nil means
	// state.FromResults. Tests replace it to hand the command a state that is
	// inconsistent, which FromResults never produces.
	buildState func([]result.Result, time.Time, func(string) string) *state.State
	// notifier replaces the ntfy notifier built from the configuration;
	// notifyOpts customise that one (tests set the backoff and the clock of
	// its retry).
	notifier   notify.Notifier
	notifyOpts []notify.Option
	// afterSend runs in `report --weekly --notify` after a failed delivery
	// and before the failure is recorded; tests change the state there, as a
	// concurrent `check` would.
	afterSend func()
}

func (e env) withDefaults() env {
	if e.ctx == nil {
		e.ctx = context.Background()
	}
	if e.fs == nil {
		e.fs = probes.OSFS{}
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.hostname == nil {
		e.hostname = os.Hostname
	}
	return e
}

// DefaultFailOn is the severity from which a failing check makes `check`
// exit 1.
const DefaultFailOn = result.Medium

// runCheck implements `keepwatch check`. See docs/running.md for the contract:
// the flags, the formats, the exit codes and the state handling.
func runCheck(e env, args []string, stdout, stderr io.Writer) int {
	e = e.withDefaults()
	var cfgPath, formatS, failOnS string
	var noState, doNotify bool
	if code, done := parse("check", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file (default "+config.DefaultPath+")")
		fs.StringVar(&formatS, "format", string(render.Text), "output format: text, json or markdown")
		fs.BoolVar(&noState, "no-state", false, "only check: neither read nor write the state of the last run")
		fs.BoolVar(&doNotify, "notify", false, "send the changes worth an alert (and, on the first run, the open findings) to the configured ntfy topic")
		fs.StringVar(&failOnS, "fail-on", string(DefaultFailOn), "lowest severity that makes the exit code 1 (info, low, medium, high, critical)")
	}); done {
		return code
	}
	format, err := render.ParseFormat(formatS)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch check: %v\n", err)
		return ExitUsage
	}
	failOn, err := result.ParseSeverity(failOnS)
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch check: --fail-on: %v\n", err)
		return ExitUsage
	}
	if doNotify && noState {
		fmt.Fprintln(stderr, "keepwatch check: --notify needs the state of the last run to know what changed: it cannot be combined with --no-state")
		return ExitUsage
	}

	// Until the redactor exists, messages go through the built-in patterns.
	red := redact.Default()
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "keepwatch check: %s\n", red.Clean(fmt.Sprintf(format, a...)))
		return ExitInternal
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		var errs config.Errors
		if errors.As(err, &errs) {
			for _, ce := range errs {
				fmt.Fprintln(stderr, red.Clean(ce.Error()))
			}
			return ExitInternal
		}
		return fail("%v", err)
	}
	if red, err = redact.New(cfg.Redact.Patterns); err != nil {
		return fail("%v", err)
	}
	var ntf notify.Notifier
	if doNotify {
		// Before anything runs: a notification that cannot be sent is a
		// configuration problem, and the checks are not worth running for it.
		if ntf, err = e.newNotifier(cfg); err != nil {
			return fail("--notify: %v", err)
		}
	}

	cat := e.catalog
	if cat == nil {
		if cat, err = catalog.Base(); err != nil {
			return fail("%v", err)
		}
	}
	runner := e.runner
	if runner == nil {
		runner = execx.NewReal(engine.Programs(cat))
	}
	plan, err := engine.Prepare(cat, cfg, engine.Deps{Runner: runner, FS: e.fs, Now: e.now, Statfs: e.statfs})
	if err != nil {
		return fail("%v", err)
	}

	now := e.now()
	results := plan.Run(e.ctx)
	if e.ctx.Err() != nil {
		// Results of an interrupted run are partial: report nothing and
		// leave the stored state as it is.
		return fail("interrupted: %v", e.ctx.Err())
	}

	in := render.Input{GeneratedAt: now, FailOn: failOn, Results: results}
	if h, herr := e.hostname(); herr == nil {
		in.Host = h
	} else {
		in.Host = "unknown"
	}
	code := ExitCode(results, failOn)

	var store *state.Store
	var cur, prev *state.State
	stateFailed, saveState := false, false
	if !noState {
		in.State.Used = true
		build := e.buildState
		if build == nil {
			build = state.FromResults
		}
		cur = build(results, now, red.Clean)
		var opts []state.Option
		if e.ownerOf != nil {
			opts = append(opts, state.WithOwnerOf(e.ownerOf))
		}
		var serr error
		if store, serr = state.Open(cfg.StateDir, opts...); serr != nil {
			stateFailed = true
			in.State.Baseline, in.State.Reason = true, "the state directory is not usable (see warnings)"
			in.Warnings = append(in.Warnings, fmt.Sprintf("state is neither read nor written: %v", serr))
		} else if cerr := state.CheckConsistency(cur); cerr != nil {
			// The state this run built contradicts itself: a diff over it
			// would be silently wrong, and saving it would hand the same
			// contradiction to the next run. This is a keepwatch defect, not
			// a property of the host.
			stateFailed = true
			in.State.Baseline, in.State.Reason = true, "the state of this run is inconsistent (see warnings)"
			in.Warnings = append(in.Warnings, fmt.Sprintf("internal inconsistency in the state of this run, it is neither compared nor saved: %v", cerr))
		} else if lr, lerr := store.Load(); lerr != nil {
			stateFailed = true
			in.State.Baseline, in.State.Reason = true, "the state directory is not usable (see warnings)"
			in.Warnings = append(in.Warnings, fmt.Sprintf("state is neither read nor written: %v", lerr))
		} else {
			switch {
			case lr.State != nil:
				prev = lr.State
				in.Diff = diff.Compute(lr.State, cur)
				in.State.PrevRunAt = lr.State.RunAt
			case lr.Missing:
				in.State.Baseline, in.State.Reason = true, "no previous state (first run)"
			default:
				in.State.Baseline, in.State.Reason = true, "the previous state was not usable (see warnings)"
				in.Warnings = append(in.Warnings, "previous state not used, this run is a new baseline: "+lr.Problem)
			}
		}
		saveState = !stateFailed
	}
	if stateFailed {
		code = ExitInternal
	}
	in.ExitCode = code

	// A notification that could not be delivered earlier is told in the
	// report; with --notify it is sent again together with this run's
	// changes (the stored state is the last one whose changes were
	// delivered, so they are in this run's comparison). Without --notify a
	// run does not move that state forward: it would mark changes as seen
	// that nobody was told.
	var prevDel *render.DeliveryNote
	holdState := false
	if prev != nil && prev.Delivery != nil {
		prevDel = deliveryNote(prev.Delivery)
		in.Warnings = append(in.Warnings, deliveryWarning(prev.Delivery, doNotify))
		holdState = !doNotify && prev.Delivery.Kind == state.DeliveryCheck
	}
	var notice render.Notice
	send := false
	switch {
	case doNotify && stateFailed:
		in.Warnings = append(in.Warnings, "no notification is sent: the state could not be used, so what changed is not known")
	case doNotify:
		notice, send = render.BuildNotice(in, prevDel, red)
	}

	for _, w := range in.Warnings {
		fmt.Fprintf(stderr, "keepwatch check: warning: %s\n", red.Clean(w))
	}
	var buf bytes.Buffer
	if err := render.Render(&buf, format, in, red); err != nil {
		return fail("render: %v", err)
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		// The report did not get out, so the changes in it were not told to
		// anyone: leave the state as it is, the next run reports them again.
		fmt.Fprintf(stderr, "keepwatch check: cannot write the report: %s\n", red.Clean(err.Error()))
		return ExitInternal
	}
	var deliveryErr error
	if send {
		deliveryErr = ntf.Send(e.ctx, toMessage(notice))
		if e.ctx.Err() != nil {
			// A signal during the delivery: the run is interrupted like
			// one that was interrupted during the checks. Nothing is
			// stored, so the next run reports (and, if it was not
			// delivered, sends) the same changes again.
			return fail("interrupted: %v", e.ctx.Err())
		}
		if deliveryErr != nil {
			fmt.Fprintf(stderr, "keepwatch check: the notification was not delivered: %s\n", red.Clean(deliveryErr.Error()))
		}
	}
	if saveState {
		// The state moves forward only after the report was written and,
		// with --notify, only after the notification was delivered. A
		// failure here cannot be part of the report any more: it is told on
		// stderr and the exit code is 3 (the exit code printed in the report
		// is the one of the checks).
		toSave, committed := cur, true
		switch {
		case deliveryErr != nil:
			// The snapshot stays where it was, with a record of the
			// failure, so the next run compares with it again and reports
			// the same changes. Without a previous snapshot (a first run)
			// the current one is stored: it holds no change to lose.
			kind := state.DeliveryCheck
			if in.State.Baseline || (prev != nil && prev.Delivery != nil && prev.Delivery.Kind == state.DeliveryBaseline) {
				// The message was the notice of a first run, or the
				// resend of it: what is owed is the list of open
				// findings, not the changes since a snapshot.
				kind = state.DeliveryBaseline
			}
			toSave, committed = failedState(prev, cur, kind, now, deliveryErr, red), false
		case holdState:
			toSave, committed = nil, false
			fmt.Fprintln(stderr, "keepwatch check: warning: the state is not moved forward: the last notification was not delivered yet, run with --notify")
		case prev != nil && prev.Delivery != nil && prev.Delivery.Kind != state.DeliveryCheck && !doNotify:
			d := *prev.Delivery
			cur.Delivery = &d
		}
		if toSave != nil {
			if err := store.Save(toSave); err != nil {
				fmt.Fprintf(stderr, "keepwatch check: warning: the state could not be saved, the next run compares with an older one: %s\n", red.Clean(err.Error()))
				return ExitInternal
			}
		}
		if committed {
			if n := len(in.Diff.Alerts(result.Info)); n > 0 && !doNotify && cfg.Notify.Ntfy != nil { // a baseline run has no changes, hence no alerts
				fmt.Fprintf(stderr, "keepwatch check: warning: this run did not use --notify and moved the state forward past %d alert-worthy %s that no notification will tell\n", n, plural(n, "change", "changes"))
			}
			recordHistory(cfg.StateDir, now, in, red, stderr)
		}
	}
	if deliveryErr != nil {
		return ExitDelivery
	}
	return code
}

// prodEnv is the environment of the real command: signals cancel the run.
func prodEnv() (env, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return env{ctx: ctx}, stop
}
