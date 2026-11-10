package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/render"
	"github.com/LanNguyenSi/keepwatch/internal/state"
	"github.com/LanNguyenSi/keepwatch/internal/version"
)

// newNotifier returns the notifier of the configuration: the one the
// environment carries (tests), else ntfy.
func (e env) newNotifier(cfg *config.Config) (notify.Notifier, error) {
	if e.notifier != nil {
		return e.notifier, nil
	}
	nf := cfg.Notify.Ntfy
	if nf == nil {
		return nil, errors.New("notify.ntfy is not configured")
	}
	nc := notify.NtfyConfig{URL: nf.URL, Topic: nf.Topic, UserAgent: "keepwatch/" + version.Version}
	if nf.TokenFile != "" {
		// Read when a message is sent, through the checks of the config
		// package, which look at the file again.
		nc.ReadToken = cfg.ReadToken
	}
	return notify.NewNtfy(nc, e.notifyOpts...)
}

// toMessage turns a notice into a message for the channel.
func toMessage(n render.Notice) notify.Message {
	m := notify.Message{Title: n.Title, Body: n.Body, Markdown: true, Tags: n.Tags}
	if n.Severity != "" {
		m.Priority = notify.PriorityOf(n.Severity)
	}
	return m
}

func deliveryNote(d *state.Delivery) *render.DeliveryNote {
	return &render.DeliveryNote{At: d.FailedAt, Failures: d.Failures, Kind: d.Kind, Reason: d.Reason}
}

// deliveryWarning is the line of the report about an undelivered
// notification.
func deliveryWarning(d *state.Delivery, notifying bool) string {
	what := "the notification of the changes of an earlier run"
	if d.Kind == state.DeliveryWeekly {
		what = "the weekly report"
	}
	s := fmt.Sprintf("last delivery failed: %s could not be delivered at %s (%d in a row): %s", what, d.FailedAt.UTC().Format(time.RFC3339), d.Failures, d.Reason)
	switch {
	case notifying:
		return s + "; it is told again with this run"
	case d.Kind == state.DeliveryCheck:
		return s + "; the state is not moved forward until a run with --notify delivers it"
	}
	return s
}

// maxReasonRunes keeps a recorded reason inside the limit of the state file.
const maxReasonRunes = 120

// failureReason is the text recorded for a failed delivery: the error,
// redacted, on one line, short.
func failureReason(err error, red *redact.Redactor) string {
	r := []rune(red.Clean(err.Error()))
	if len(r) > maxReasonRunes {
		return string(r[:maxReasonRunes]) + "..."
	}
	return string(r)
}

// failedState returns the state to store after a delivery of kind failed: the
// previous snapshot (cur when there is none) with the record of the failure.
func failedState(prev, cur *state.State, kind string, now time.Time, err error, red *redact.Redactor) *state.State {
	var st state.State
	if prev != nil {
		st = *prev
	} else {
		st = *cur
	}
	failures := 1
	if prev != nil && prev.Delivery != nil {
		failures = prev.Delivery.Failures + 1
	}
	st.Delivery = &state.Delivery{
		FailedAt: now.UTC().Truncate(time.Second),
		Failures: failures,
		Kind:     kind,
		Reason:   failureReason(err, red),
	}
	return &st
}

// recordHistory adds the run to the history used by the weekly report. The
// history is a convenience: a problem with it is a warning and never changes
// the exit code.
func recordHistory(dir string, now time.Time, in render.Input, red *redact.Redactor, stderr io.Writer) {
	rep := in.Diff
	rep.Baseline = in.State.Baseline
	hs, err := history.Open(dir)
	if err == nil {
		var problem string
		if problem, err = hs.Append(history.FromReport(now, rep, red.Clean)); problem != "" {
			fmt.Fprintf(stderr, "keepwatch check: warning: the previous history was not used and is replaced: %s\n", red.Clean(problem))
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "keepwatch check: warning: the history for the weekly report could not be written: %s\n", red.Clean(err.Error()))
	}
}
