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

// runCheck implements `keepwatch check`. See the README for the contract:
// the flags, the formats, the exit codes and the state handling.
func runCheck(e env, args []string, stdout, stderr io.Writer) int {
	e = e.withDefaults()
	var cfgPath, formatS, failOnS string
	var noState bool
	if code, done := parse("check", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file (default "+config.DefaultPath+")")
		fs.StringVar(&formatS, "format", string(render.Text), "output format: text, json or markdown")
		fs.BoolVar(&noState, "no-state", false, "only check: neither read nor write the state of the last run")
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
	var cur *state.State
	stateFailed := false
	if !noState {
		in.State.Used = true
		cur = state.FromResults(results, now, red.Clean)
		var opts []state.Option
		if e.ownerOf != nil {
			opts = append(opts, state.WithOwnerOf(e.ownerOf))
		}
		var serr error
		if store, serr = state.Open(cfg.StateDir, opts...); serr != nil {
			stateFailed = true
			in.State.Baseline, in.State.Reason = true, "the state directory is not usable (see warnings)"
			in.Warnings = append(in.Warnings, fmt.Sprintf("state is neither read nor written: %v", serr))
		} else if lr, lerr := store.Load(); lerr != nil {
			stateFailed = true
			in.State.Baseline, in.State.Reason = true, "the state directory is not usable (see warnings)"
			in.Warnings = append(in.Warnings, fmt.Sprintf("state is neither read nor written: %v", lerr))
		} else {
			switch {
			case lr.State != nil:
				in.Diff = diff.Compute(lr.State, cur)
				in.State.PrevRunAt = lr.State.RunAt
			case lr.Missing:
				in.State.Baseline, in.State.Reason = true, "no previous state (first run)"
			default:
				in.State.Baseline, in.State.Reason = true, "the previous state was not usable (see warnings)"
				in.Warnings = append(in.Warnings, "previous state not used, this run is a new baseline: "+lr.Problem)
			}
		}
		if store != nil && !stateFailed {
			if serr = store.Save(cur); serr != nil {
				stateFailed = true
				in.Warnings = append(in.Warnings, fmt.Sprintf("the state could not be saved, the next run compares with an older one: %v", serr))
			}
		}
	}
	if stateFailed {
		code = ExitInternal
	}
	in.ExitCode = code

	for _, w := range in.Warnings {
		fmt.Fprintf(stderr, "keepwatch check: warning: %s\n", red.Clean(w))
	}
	var buf bytes.Buffer
	if err := render.Render(&buf, format, in, red); err != nil {
		return fail("render: %v", err)
	}
	if _, err := stdout.Write(buf.Bytes()); err != nil {
		fmt.Fprintf(stderr, "keepwatch check: cannot write the report: %s\n", red.Clean(err.Error()))
		return ExitInternal
	}
	return code
}

// prodEnv is the environment of the real command: signals cancel the run.
func prodEnv() (env, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return env{ctx: ctx}, stop
}
