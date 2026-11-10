// Package render writes the report of a keepwatch run as text, JSON or
// Markdown.
//
// Everything in a report that did not come from this package's own constants
// is untrusted: summaries and evidence derive from host output, and the check
// ids, subjects and reasons can hold whatever a local user or a configuration
// file put there. Render therefore builds one cleaned view of the input
// (every string passes through redact.Redactor.Clean: secrets redacted,
// control characters escaped, length bounded, one line) and all three
// formats are written from that view only. On top of that:
//
//   - JSON is produced by encoding/json, which quotes control characters and
//     escapes <, > and & (and U+2028/2029); nothing is concatenated by hand.
//   - Markdown never places untrusted text in running text. It goes into
//     code spans whose fence is longer than any backtick run in the text, so
//     it cannot open a link, an image, an HTML tag or a heading, and a pipe
//     in a table cell is escaped.
//   - Text puts untrusted strings on lines the renderer has built; the
//     escaping of newlines means a field cannot start a line of its own.
package render

import (
	"fmt"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Format is an output format.
type Format string

// The output formats.
const (
	Text     Format = "text"
	JSON     Format = "json"
	Markdown Format = "markdown"
)

// ParseFormat returns the format named s.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case Text, JSON, Markdown:
		return Format(s), nil
	}
	return "", fmt.Errorf("format %q is not one of text, json, markdown", s)
}

// SchemaVersion is the version of the JSON report format.
const SchemaVersion = 1

// StateInfo says how the run related to the stored state.
type StateInfo struct {
	// Used is false when the run did not read or write state (--no-state).
	Used bool
	// Baseline is true when there was no usable previous state, so no
	// changes were computed.
	Baseline bool
	// Reason says why it is a baseline: the first run, or the problem found
	// with the state.
	Reason string
	// PrevRunAt is the time of the previous run; zero for a baseline.
	PrevRunAt time.Time
}

// Input is everything a report is made of.
type Input struct {
	GeneratedAt time.Time
	Host        string
	FailOn      result.Severity
	ExitCode    int
	State       StateInfo
	// Warnings are problems of the run itself, such as an unusable state
	// file.
	Warnings []string
	Results  []result.Result
	// Diff is the comparison with the previous run; ignored when
	// State.Used is false or State.Baseline is true.
	Diff diff.Report
}

// view is the cleaned report. Its JSON form is the JSON report.
type view struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Host          string       `json:"host"`
	FailOn        string       `json:"fail_on"`
	ExitCode      int          `json:"exit_code"`
	Counts        viewCounts   `json:"counts"`
	State         viewState    `json:"state"`
	Warnings      []string     `json:"warnings"`
	Changes       []viewChange `json:"changes"`
	StillFailing  []viewRef    `json:"still_failing"`
	StillWarning  []viewRef    `json:"still_warning"`
	Results       []viewResult `json:"results"`
}

type viewCounts struct {
	Total    int `json:"total"`
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	Warn     int `json:"warn"`
	Error    int `json:"error"`
	Skipped  int `json:"skipped"`
	Excepted int `json:"excepted"`
}

type viewState struct {
	Used          bool   `json:"used"`
	Baseline      bool   `json:"baseline"`
	Reason        string `json:"reason,omitempty"`
	PreviousRunAt string `json:"previous_run_at,omitempty"`
}

type viewChange struct {
	Kind      string `json:"kind"`
	CheckID   string `json:"check_id"`
	CheckKind string `json:"check_kind"`
	Severity  string `json:"severity"`
	From      string `json:"from,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	// OldTotal and NewTotal are set for a set_changed change only.
	OldTotal int `json:"old_total,omitempty"`
	NewTotal int `json:"new_total,omitempty"`
	// HiddenNew is set for a hidden_new change only, HiddenGone for a
	// hidden_gone change only.
	HiddenNew  int `json:"hidden_new,omitempty"`
	HiddenGone int `json:"hidden_gone,omitempty"`
	// FromSeverity and ToSeverity are set for a severity_change only.
	FromSeverity string `json:"from_severity,omitempty"`
	ToSeverity   string `json:"to_severity,omitempty"`
	Alert        bool   `json:"alert"`
}

type viewRef struct {
	CheckID   string `json:"check_id"`
	CheckKind string `json:"check_kind"`
	Severity  string `json:"severity"`
}

type viewResult struct {
	CheckID          string         `json:"check_id"`
	Kind             string         `json:"kind"`
	Status           string         `json:"status"`
	Severity         string         `json:"severity"`
	Summary          string         `json:"summary"`
	Evidence         []viewEvidence `json:"evidence"`
	ExceptionReasons []string       `json:"exception_reasons,omitempty"`
}

type viewEvidence struct {
	Subject         string `json:"subject"`
	Detail          string `json:"detail"`
	Excepted        bool   `json:"excepted"`
	ExceptionReason string `json:"exception_reason,omitempty"`
}

const timeLayout = time.RFC3339

// buildView cleans the input. A nil redactor uses the built-in patterns.
func buildView(in Input, red *redact.Redactor) view {
	c := func(s string) string { return red.Clean(s) }
	v := view{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   in.GeneratedAt.UTC().Format(timeLayout),
		Host:          c(in.Host),
		FailOn:        c(string(in.FailOn)),
		ExitCode:      in.ExitCode,
		State:         viewState{Used: in.State.Used, Baseline: in.State.Used && in.State.Baseline},
		Warnings:      []string{},
		Changes:       []viewChange{},
		StillFailing:  []viewRef{},
		StillWarning:  []viewRef{},
		Results:       []viewResult{},
	}
	if in.State.Used {
		v.State.Reason = c(in.State.Reason)
		if !in.State.PrevRunAt.IsZero() {
			v.State.PreviousRunAt = in.State.PrevRunAt.UTC().Format(timeLayout)
		}
	}
	for _, w := range in.Warnings {
		v.Warnings = append(v.Warnings, c(w))
	}
	if in.State.Used && !in.State.Baseline {
		for _, ch := range in.Diff.Changes {
			v.Changes = append(v.Changes, viewChange{
				Kind: c(string(ch.Kind)), CheckID: c(ch.CheckID), CheckKind: c(ch.CheckKind), Severity: c(string(ch.Severity)),
				From: c(string(ch.From)), To: c(string(ch.To)), Subject: c(ch.Subject),
				OldTotal: ch.OldTotal, NewTotal: ch.NewTotal, HiddenNew: ch.HiddenNew, HiddenGone: ch.HiddenGone, Alert: ch.Alert,
				FromSeverity: c(string(ch.FromSeverity)), ToSeverity: c(string(ch.ToSeverity)),
			})
		}
		for _, r := range in.Diff.StillFailing {
			v.StillFailing = append(v.StillFailing, viewRef{c(r.CheckID), c(r.CheckKind), c(string(r.Severity))})
		}
		for _, r := range in.Diff.StillWarning {
			v.StillWarning = append(v.StillWarning, viewRef{c(r.CheckID), c(r.CheckKind), c(string(r.Severity))})
		}
	}
	for _, r := range in.Results {
		vr := viewResult{
			CheckID: c(r.CheckID), Kind: c(r.Kind), Status: c(string(r.Status)), Severity: c(string(r.Severity)),
			Summary: c(r.Summary), Evidence: []viewEvidence{},
		}
		for _, e := range r.Evidence {
			vr.Evidence = append(vr.Evidence, viewEvidence{
				Subject: c(e.Subject), Detail: c(e.Detail), Excepted: e.Excepted, ExceptionReason: c(e.ExceptionReason),
			})
		}
		for _, reason := range r.ExceptionReasons {
			vr.ExceptionReasons = append(vr.ExceptionReasons, c(reason))
		}
		v.Results = append(v.Results, vr)
		v.Counts.Total++
		switch r.Status {
		case result.Pass:
			v.Counts.Pass++
		case result.Fail:
			v.Counts.Fail++
		case result.Warn:
			v.Counts.Warn++
		case result.Error:
			v.Counts.Error++
		case result.Skipped:
			v.Counts.Skipped++
		case result.Excepted:
			v.Counts.Excepted++
		}
	}
	return v
}
