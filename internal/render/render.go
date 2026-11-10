package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/redact"
)

// Render writes the report of in to w in format f. Every string of the report
// passes through red.Clean first (a nil red uses the built-in patterns). The
// report is built in memory and written with one call, so a failed render
// writes nothing.
func Render(w io.Writer, f Format, in Input, red *redact.Redactor) error {
	v := buildView(in, red)
	var buf bytes.Buffer
	switch f {
	case Text:
		writeText(&buf, v)
	case JSON:
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return err
		}
	case Markdown:
		writeMarkdown(&buf, v)
	default:
		return fmt.Errorf("unknown format %q", string(f))
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func countsLine(c viewCounts) string {
	return fmt.Sprintf("%d %s: %d pass, %d fail, %d warn, %d error, %d skipped, %d excepted",
		c.Total, plural(c.Total, "check", "checks"), c.Pass, c.Fail, c.Warn, c.Error, c.Skipped, c.Excepted)
}

// stateLine is the one-line description of the state handling.
func stateLine(s viewState) string {
	switch {
	case !s.Used:
		return "state not used (--no-state): no comparison with the previous run"
	case s.Baseline:
		return "baseline run, no changes are reported: " + s.Reason
	case s.PreviousRunAt != "":
		return "changes since the previous run at " + s.PreviousRunAt
	}
	return "changes since the previous run"
}

// changeText describes a change in a few words.
func changeText(c viewChange) string {
	switch c.Kind {
	case "new_failure":
		return fmt.Sprintf("now failing (was %s)", c.From)
	case "fixed":
		return "fixed (was failing)"
	case "status_change":
		return fmt.Sprintf("%s -> %s", c.From, c.To)
	case "check_added":
		return fmt.Sprintf("new check, status %s", c.To)
	case "check_removed":
		return fmt.Sprintf("check removed (was %s)", c.From)
	case "subject_new":
		return "new item"
	case "subject_gone":
		return "item gone"
	case "hidden_new":
		return fmt.Sprintf("%d new %s not listed (the check lists only some of its items)", c.HiddenNew, plural(c.HiddenNew, "item", "items"))
	case "hidden_gone":
		return fmt.Sprintf("%d %s gone, not listed (the check lists only some of its items)", c.HiddenGone, plural(c.HiddenGone, "item", "items"))
	case "set_changed":
		return fmt.Sprintf("the items changed (%d -> %d; too many to compare one by one)", c.OldTotal, c.NewTotal)
	case "severity_change":
		return fmt.Sprintf("severity %s -> %s (status %s)", c.FromSeverity, c.ToSeverity, c.To)
	}
	return c.Kind
}

// statusLabel returns the upper-case label of a status. A status that is not
// one of the six the engine produces (which cannot happen, but the report is
// not the place to trust that) is shown as UNKNOWN.
func statusLabel(s string) string {
	switch s {
	case "pass", "fail", "warn", "error", "skipped", "excepted":
		return strings.ToUpper(s)
	}
	return "UNKNOWN"
}

// nonPass reports whether a result is worth a section of its own.
func nonPass(status string) bool {
	return status != "pass" && status != "skipped"
}

func listIDs(rs []viewResult, status string) []string {
	var ids []string
	for _, r := range rs {
		if r.Status == status {
			ids = append(ids, r.CheckID)
		}
	}
	return ids
}

func refIDs(rs []viewRef) []string {
	ids := make([]string, 0, len(rs))
	for _, r := range rs {
		ids = append(ids, r.CheckID)
	}
	return ids
}

func writeText(b *bytes.Buffer, v view) {
	fmt.Fprintf(b, "keepwatch check: host %s, %s\n", v.Host, v.GeneratedAt)
	fmt.Fprintf(b, "%s\n", countsLine(v.Counts))
	fmt.Fprintf(b, "fail-on %s, exit code %d\n", v.FailOn, v.ExitCode)
	fmt.Fprintf(b, "state: %s\n", stateLine(v.State))

	if len(v.Warnings) > 0 {
		b.WriteString("\nwarnings:\n")
		for _, w := range v.Warnings {
			fmt.Fprintf(b, "  - %s\n", w)
		}
	}
	if v.State.Used && !v.State.Baseline {
		fmt.Fprintf(b, "\nchanges (%d):\n", len(v.Changes))
		if len(v.Changes) == 0 {
			b.WriteString("  none\n")
		}
		for _, c := range v.Changes {
			mark := " "
			if c.Alert {
				mark = "!"
			}
			fmt.Fprintf(b, "  %s %s (%s): %s", mark, c.CheckID, c.Severity, changeText(c))
			if c.Subject != "" {
				fmt.Fprintf(b, ": %s", c.Subject)
			}
			b.WriteString("\n")
		}
		if len(v.StillFailing) > 0 {
			fmt.Fprintf(b, "still failing (%d): %s\n", len(v.StillFailing), strings.Join(refIDs(v.StillFailing), ", "))
		}
		if len(v.StillWarning) > 0 {
			fmt.Fprintf(b, "still warning (%d): %s\n", len(v.StillWarning), strings.Join(refIDs(v.StillWarning), ", "))
		}
	}

	first := true
	for _, r := range v.Results {
		if !nonPass(r.Status) {
			continue
		}
		if first {
			b.WriteString("\nfindings:\n")
			first = false
		}
		fmt.Fprintf(b, "  [%s] %s (%s) %s\n", statusLabel(r.Status), r.CheckID, r.Severity, r.Summary)
		for _, e := range r.Evidence {
			fmt.Fprintf(b, "      - %s", e.Subject)
			if e.Detail != "" {
				fmt.Fprintf(b, ": %s", e.Detail)
			}
			if e.Excepted {
				fmt.Fprintf(b, " [excepted: %s]", e.ExceptionReason)
			}
			b.WriteString("\n")
		}
	}
	if first {
		b.WriteString("\nno findings\n")
	}
	if ids := listIDs(v.Results, "pass"); len(ids) > 0 {
		fmt.Fprintf(b, "\npassing (%d): %s\n", len(ids), strings.Join(ids, ", "))
	}
	if ids := listIDs(v.Results, "skipped"); len(ids) > 0 {
		fmt.Fprintf(b, "skipped (%d): %s\n", len(ids), strings.Join(ids, ", "))
	}
}

// mdCode returns s as a Markdown code span. The fence is one backtick longer
// than the longest run of backticks in s, and one space pads each side (a
// code span drops one space at each end), so s comes back exactly and cannot
// end the span early. In a code span nothing is interpreted: no link, image,
// HTML or emphasis. s is already one line.
func mdCode(s string) string {
	if s == "" {
		return "_(empty)_"
	}
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	return fence + " " + s + " " + fence
}

// mdCell is mdCode for a table cell, where a pipe would end the cell and must
// be escaped (GFM reads \| inside a code span as a pipe in the cell).
func mdCell(s string) string { return mdCode(strings.ReplaceAll(s, "|", `\|`)) }

func mdCodes(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = mdCode(s)
	}
	return strings.Join(out, ", ")
}

func writeMarkdown(b *bytes.Buffer, v view) {
	fmt.Fprintf(b, "# keepwatch check\n\n")
	fmt.Fprintf(b, "- **Host:** %s\n", mdCode(v.Host))
	fmt.Fprintf(b, "- **Generated:** %s\n", mdCode(v.GeneratedAt))
	fmt.Fprintf(b, "- **Checks:** %s\n", mdCode(countsLine(v.Counts)))
	fmt.Fprintf(b, "- **Fail on:** %s, **exit code:** %d\n", mdCode(v.FailOn), v.ExitCode)
	fmt.Fprintf(b, "- **State:** %s\n", mdCode(stateLine(v.State)))

	if len(v.Warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		for _, w := range v.Warnings {
			fmt.Fprintf(b, "- %s\n", mdCode(w))
		}
	}
	if v.State.Used && !v.State.Baseline {
		fmt.Fprintf(b, "\n## Changes (%d)\n\n", len(v.Changes))
		if len(v.Changes) == 0 {
			b.WriteString("None.\n")
		}
		for _, c := range v.Changes {
			alert := ""
			if c.Alert {
				alert = "**ALERT** "
			}
			fmt.Fprintf(b, "- %s%s (%s): %s", alert, mdCode(c.CheckID), mdCode(c.Severity), mdCode(changeText(c)))
			if c.Subject != "" {
				fmt.Fprintf(b, ": %s", mdCode(c.Subject))
			}
			b.WriteString("\n")
		}
		if len(v.StillFailing) > 0 {
			fmt.Fprintf(b, "\nStill failing (%d): %s\n", len(v.StillFailing), mdCodes(refIDs(v.StillFailing)))
		}
		if len(v.StillWarning) > 0 {
			fmt.Fprintf(b, "\nStill warning (%d): %s\n", len(v.StillWarning), mdCodes(refIDs(v.StillWarning)))
		}
	}

	first := true
	for _, r := range v.Results {
		if !nonPass(r.Status) {
			continue
		}
		if first {
			b.WriteString("\n## Findings\n")
			first = false
		}
		fmt.Fprintf(b, "\n### %s %s (%s)\n\n%s\n", statusLabel(r.Status), mdCode(r.CheckID), mdCode(r.Severity), mdCode(r.Summary))
		if len(r.Evidence) > 0 {
			b.WriteString("\n")
		}
		for _, e := range r.Evidence {
			fmt.Fprintf(b, "- %s", mdCode(e.Subject))
			if e.Detail != "" {
				fmt.Fprintf(b, ": %s", mdCode(e.Detail))
			}
			if e.Excepted {
				fmt.Fprintf(b, " (excepted: %s)", mdCode(e.ExceptionReason))
			}
			b.WriteString("\n")
		}
	}
	if first {
		b.WriteString("\n## Findings\n\nNone.\n")
	}

	b.WriteString("\n## All checks\n\n| Check | Status | Severity |\n|---|---|---|\n")
	for _, r := range v.Results {
		fmt.Fprintf(b, "| %s | %s | %s |\n", mdCell(r.CheckID), mdCell(r.Status), mdCell(r.Severity))
	}
}
