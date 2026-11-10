package render

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// DigestInput is everything the weekly report is made of.
type DigestInput struct {
	GeneratedAt time.Time
	Host        string
	// Days is the length of the period, normally 7.
	Days int
	// State is the state of the last run, nil when there is none that could
	// be used; StateNote then says why.
	State     *state.State
	StateNote string
	// Runs are the runs of the period, oldest first. HistoryNote says what
	// is wrong with the history (empty when nothing is).
	Runs        []history.Run
	HistoryNote string
	// PrevDelivery is set when the last notification was not delivered.
	PrevDelivery *DeliveryNote
}

// Lines of the digest per section.
const (
	maxDigestOpen    = 20
	maxDigestChanges = 25
)

// digestFmt writes the digest as Markdown (the notification) or as plain
// text (the terminal). In Markdown untrusted text goes into code spans only.
type digestFmt struct {
	md bool
}

func (f digestFmt) code(s string) string {
	if f.md {
		return mdCode(s)
	}
	return s
}

func (f digestFmt) bold(s string) string {
	if f.md {
		return "**" + s + "**"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (f digestFmt) codes(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = f.code(s)
	}
	return strings.Join(out, ", ")
}

// BuildDigest builds the weekly report. A nil red uses the built-in
// patterns. markdown selects the format of the body: Markdown for a
// notification, plain text for the terminal.
func BuildDigest(in DigestInput, markdown bool, red *redact.Redactor) Notice {
	f := digestFmt{md: markdown}
	c := func(s string) string { return red.Clean(s) }
	host := c(in.Host)
	var b bodyBuilder
	days := in.Days
	if days <= 0 {
		days = 7
	}
	b.add(fmt.Sprintf("%s for host %s, %s, last %d days.", f.bold("keepwatch weekly report"), f.code(host), f.code(in.GeneratedAt.UTC().Format(timeLayout)), days))
	if in.PrevDelivery != nil {
		b.blank()
		b.add(f.deliveryLine(in.PrevDelivery, c))
	}

	// Open findings, from the state of the last run.
	var opens []state.Check
	checks := 0
	if in.State != nil {
		checks = len(in.State.Checks)
		for _, ck := range in.State.Checks {
			if ck.Status == result.Fail || ck.Status == result.Warn || ck.Status == result.Error {
				opens = append(opens, ck)
			}
		}
	}
	sort.SliceStable(opens, func(i, j int) bool {
		if ri, rj := rankOf(opens[i].Severity), rankOf(opens[j].Severity); ri != rj {
			return ri > rj
		}
		return opens[i].ID < opens[j].ID
	})
	b.blank()
	switch {
	case in.State == nil:
		b.add(f.bold("Open findings") + " are unknown: " + f.code(c(in.StateNote)) + ".")
	default:
		b.add(fmt.Sprintf("%s (%d of %d checks), state of %s:", f.bold("Open findings"), len(opens), checks, f.code(in.State.RunAt.UTC().Format(timeLayout))))
		if len(opens) == 0 {
			b.add("None.")
		} else {
			b.blank()
		}
	}
	for i, ck := range opens {
		if i == maxDigestOpen {
			b.add(fmt.Sprintf("and %d more.", len(opens)-maxDigestOpen))
			break
		}
		b.add(f.openLine(ck, c))
	}

	// Changes of the period, newest first.
	type dated struct {
		at time.Time
		ch history.Change
	}
	var changes []dated
	alerts, fixed := 0, 0
	for _, r := range in.Runs {
		for _, ch := range r.Changes {
			changes = append(changes, dated{r.RunAt, ch})
			switch {
			case ch.Alert:
				alerts++
			case ch.Kind == "fixed" || ch.Kind == "subject_gone" || ch.Kind == "hidden_gone":
				fixed++
			}
		}
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].at.After(changes[j].at) })
	b.blank()
	b.add(fmt.Sprintf("%s (%d %s recorded, %d %s, %d %s, %d fixed or gone):",
		f.bold(fmt.Sprintf("Changes in the last %d days", days)), len(in.Runs), plural(len(in.Runs), "run", "runs"),
		len(changes), plural(len(changes), "change", "changes"), alerts, plural(alerts, "alert", "alerts"), fixed))
	if in.HistoryNote != "" {
		b.add("The history is incomplete: " + f.code(c(in.HistoryNote)) + ".")
	}
	if len(changes) == 0 {
		b.add("None.")
	} else {
		b.blank()
	}
	for i, d := range changes {
		if i == maxDigestChanges {
			b.add(fmt.Sprintf("and %d more (older).", len(changes)-maxDigestChanges))
			break
		}
		b.add(f.changeLine(d.at, d.ch, c))
	}
	truncated := 0
	for _, r := range in.Runs {
		truncated += r.Dropped
	}
	if truncated > 0 {
		b.add(fmt.Sprintf("%d more %s were recorded by the runs but not kept.", truncated, plural(truncated, "change", "changes")))
	}

	n := Notice{
		Title:    fmt.Sprintf("keepwatch %s: weekly report, %d open %s", shortHost(host), len(opens), plural(len(opens), "finding", "findings")),
		Body:     b.String(),
		Severity: result.Low,
		Tags:     []string{"keepwatch", "calendar"},
	}
	if len(opens) > 0 {
		n.Severity = result.Medium
	}
	return n
}

func (f digestFmt) deliveryLine(p *DeliveryNote, c func(string) string) string {
	what := "the notification of an earlier run"
	if p.Kind == "weekly" {
		what = "the last weekly report"
	}
	reason := c(p.Reason)
	if reason == "" {
		reason = "no reason recorded"
	}
	return fmt.Sprintf("%s %s could not be delivered at %s (%d %s in a row): %s.",
		f.bold("Last delivery failed:"), what, f.code(p.At.UTC().Format(timeLayout)), p.Failures, plural(p.Failures, "run", "runs"), f.code(reason))
}

// openLine is an open finding of the state. A check in error lists no items.
func (f digestFmt) openLine(ck state.Check, c func(string) string) string {
	line := fmt.Sprintf("- %s %s (%s)", statusLabel(string(ck.Status)), f.code(c(ck.ID)), f.code(c(string(ck.Severity))))
	if ck.Status == result.Error {
		return line
	}
	var subjects []string
	n := 0
	for _, it := range ck.Items {
		if it.Excepted {
			continue
		}
		n++
		if len(subjects) < maxSubjectsListed {
			subjects = append(subjects, c(it.Subject))
		}
	}
	if total := ck.SetTotal(); ck.Capped() && total > n {
		n = total
	}
	if len(subjects) > 0 {
		line += ": " + f.codes(subjects)
		if n > len(subjects) {
			line += fmt.Sprintf(" and %d more", n-len(subjects))
		}
	}
	return line
}

func (f digestFmt) changeLine(at time.Time, ch history.Change, c func(string) string) string {
	vc := viewChange{
		Kind: c(ch.Kind), CheckID: c(ch.CheckID), CheckKind: c(ch.CheckKind), Severity: c(ch.Severity),
		From: c(ch.From), To: c(ch.To), Subject: c(ch.Subject),
		OldTotal: ch.OldTotal, NewTotal: ch.NewTotal, HiddenNew: ch.HiddenNew, HiddenGone: ch.HiddenGone,
		FromSeverity: c(ch.FromSeverity), ToSeverity: c(ch.ToSeverity), Alert: ch.Alert,
	}
	mark := ""
	if vc.Alert {
		mark = "ALERT "
		if f.md {
			mark = "**ALERT** "
		}
	}
	line := fmt.Sprintf("- %s%s %s (%s): %s", mark, f.code(at.UTC().Format(timeLayout)), f.code(vc.CheckID), f.code(vc.Severity), f.code(changeText(vc)))
	if vc.Subject != "" {
		line += ": " + f.code(vc.Subject)
	}
	return line
}
