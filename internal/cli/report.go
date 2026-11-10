package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/render"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// weeklyDays is the period of the weekly report.
const weeklyDays = 7

// runReport implements `keepwatch report`. Only --weekly exists: the digest
// of the open findings of the last run and of the changes of the last seven
// days. It runs no checks; it reads the state and the history that `check`
// keeps in state_dir. Without --weekly the command is what it was, a stub.
func runReport(e env, args []string, stdout, stderr io.Writer) int {
	e = e.withDefaults()
	var cfgPath, formatS string
	var weekly, doNotify bool
	if code, done := parse("report", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&cfgPath, "config", "", "main configuration file (default "+config.DefaultPath+")")
		fs.BoolVar(&weekly, "weekly", false, "the weekly digest: open findings and the changes of the last 7 days")
		fs.BoolVar(&doNotify, "notify", false, "send the digest to the configured ntfy topic instead of printing it")
		fs.StringVar(&formatS, "format", string(render.Text), "output format when printing: text or markdown")
	}); done {
		return code
	}
	if !weekly {
		fmt.Fprintln(stderr, "keepwatch report: not implemented without --weekly")
		return ExitNotImplemented
	}
	format, err := render.ParseFormat(formatS)
	if err != nil || format == render.JSON {
		fmt.Fprintf(stderr, "keepwatch report: --format: %q is not one of text, markdown\n", formatS)
		return ExitUsage
	}

	red := redact.Default()
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "keepwatch report: %s\n", red.Clean(fmt.Sprintf(format, a...)))
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
	if doNotify {
		if _, err := e.newNotifier(cfg); err != nil {
			return fail("--notify: %v", err)
		}
	}

	var opts []state.Option
	if e.ownerOf != nil {
		opts = append(opts, state.WithOwnerOf(e.ownerOf))
	}
	store, err := state.Open(cfg.StateDir, opts...)
	if err != nil {
		return fail("%v", err)
	}
	lr, err := store.Load()
	if err != nil {
		return fail("state is not usable: %v", err)
	}
	now := e.now()
	in := render.DigestInput{GeneratedAt: now, Days: weeklyDays, State: lr.State}
	switch {
	case lr.State != nil:
	case lr.Missing:
		in.StateNote = "no run has been recorded yet"
	default:
		in.StateNote = lr.Problem
		fmt.Fprintf(stderr, "keepwatch report: warning: the state was not used: %s\n", red.Clean(lr.Problem))
	}
	if h, herr := e.hostname(); herr == nil {
		in.Host = h
	} else {
		in.Host = "unknown"
	}
	if lr.State != nil && lr.State.Delivery != nil {
		in.PrevDelivery = deliveryNote(lr.State.Delivery)
	}
	hs, err := history.Open(cfg.StateDir)
	if err != nil {
		return fail("%v", err)
	}
	hl, err := hs.Load()
	if err != nil {
		return fail("history is not usable: %v", err)
	}
	in.Runs = hl.File.Since(now.Add(-weeklyDays * 24 * time.Hour))
	if hl.Problem != "" {
		in.HistoryNote = hl.Problem
		fmt.Fprintf(stderr, "keepwatch report: warning: the history was not used: %s\n", red.Clean(hl.Problem))
	}

	if !doNotify {
		n := render.BuildDigest(in, format == render.Markdown, red)
		if _, err := io.WriteString(stdout, n.Body); err != nil {
			fmt.Fprintf(stderr, "keepwatch report: cannot write the report: %s\n", red.Clean(err.Error()))
			return ExitInternal
		}
		return ExitOK
	}

	n := render.BuildDigest(in, true, red)
	ntf, err := e.newNotifier(cfg)
	if err != nil {
		return fail("--notify: %v", err)
	}
	if derr := ntf.Send(e.ctx, toMessage(n)); derr != nil {
		fmt.Fprintf(stderr, "keepwatch report: the weekly report was not delivered: %s\n", red.Clean(derr.Error()))
		// Record it, so the next `check --notify` says so. A record that is
		// already there stays: it is about changes that were never told,
		// which weighs more than a digest.
		//
		// The state read at the start is up to a minute old (two timeouts and
		// a wait), and a `check` may have committed in between: its snapshot
		// must not be rolled back. So the state is read again right before
		// it is written, and the failure is recorded only on the snapshot
		// that was read at the start and has no record. What remains is the
		// time between that read and the rename (there is no lock; see
		// the README).
		if e.afterSend != nil {
			e.afterSend()
		}
		if lr.State != nil && lr.State.Delivery == nil {
			lr2, _ := store.Load() // an error leaves State nil
			switch {
			case lr2.State == nil || lr2.State.Delivery != nil || !lr2.State.RunAt.Equal(lr.State.RunAt):
				fmt.Fprintln(stderr, "keepwatch report: warning: the state changed while the report was being sent, the failure is not recorded in it")
			default:
				if serr := store.Save(failedState(lr2.State, lr2.State, state.DeliveryWeekly, e.now(), derr, red)); serr != nil {
					fmt.Fprintf(stderr, "keepwatch report: warning: the failure could not be recorded in the state: %s\n", red.Clean(serr.Error()))
					return ExitInternal
				}
			}
		}
		return ExitDelivery
	}
	fmt.Fprintln(stdout, "keepwatch report: the weekly report was sent")
	return ExitOK
}
