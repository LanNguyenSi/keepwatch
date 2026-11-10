package render

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Notice is a notification: a title, a Markdown body and what decides its
// priority. It is built from the same cleaned view as the report, so every
// string went through the redactor, and untrusted text appears in the body
// only inside code spans.
//
// Markdown in a notification. ntfy renders a message as Markdown only when
// the sender says so (the Markdown header); the web app does it with
// remark-parse 9, which follows CommonMark and has neither the GFM table nor
// the autolink extension and no raw HTML (HTML in the source is not
// rendered), the Android app with a CommonMark library. The argument of the
// output-safety section of this package therefore holds for ntfy as well:
// untrusted text is in a code span whose fence is longer than any backtick run
// in it, and a code span interprets nothing. What keepwatch writes outside
// a code span is its own: bold words, list markers, digits and a few fixed
// phrases. A table is never used (ntfy does not render it). The title is not
// Markdown at all.
type Notice struct {
	Title string
	// Body is Markdown, at most MaxNoticeBytes bytes.
	Body string
	// Severity is the highest severity among what the notice is about; empty
	// when it is about no check. The caller maps it to a priority.
	Severity result.Severity
	// Tags are fixed words, never derived from untrusted text.
	Tags []string
}

// MaxNoticeBytes is the longest body a notice has. ntfy accepts 4096 bytes by
// default; the margin is for the line that says how much was left out.
const MaxNoticeBytes = 3600

const (
	// maxNoticeRunes cuts every string that comes from the host or the
	// configuration in a notice, so that one long subject (the report allows
	// 2000 characters, 6000 bytes of CJK) cannot use up the body.
	maxNoticeRunes    = 200
	maxTitleHostRunes = 60
	maxSubjectsListed = 3
	maxStillListed    = 10
)

// DeliveryNote describes a notification that could not be delivered earlier.
type DeliveryNote struct {
	At       time.Time
	Failures int
	// Kind is "check" or "weekly".
	Kind   string
	Reason string
}

// BuildNotice builds the notification of a `check --notify` run, and says
// whether there is one: yes for a baseline run (one notice, with the open
// findings), yes when at least one change is an alert, and yes when an
// earlier notification could not be delivered. A run whose only changes are
// not alerts (a fix, an item that is gone) sends nothing.
//
// The decision is made from the comparison itself, never from the exit code
// of the run (which says that something fails now, not that something
// changed). A check in error contributes its change of status and nothing per
// evidence item.
func BuildNotice(in Input, prev *DeliveryNote, red *redact.Redactor) (Notice, bool) {
	if !in.State.Used {
		return Notice{}, false
	}
	v := cutView(buildView(in, red))
	c := func(s string) string { return cutRunes(red.Clean(s), maxNoticeRunes) }
	switch {
	case in.State.Baseline:
		return baselineNotice(v, in.Results, prev, false, c), true
	case prev != nil && prev.Kind == "baseline":
		// The first notification was never delivered: send the open
		// findings now, in the form of a first report.
		return baselineNotice(v, in.Results, prev, true, c), true
	}
	var alerts, others []viewChange
	for _, ch := range v.Changes {
		if ch.Alert {
			alerts = append(alerts, ch)
		} else {
			others = append(others, ch)
		}
	}
	if len(alerts) == 0 && prev == nil {
		return Notice{}, false
	}
	return changeNotice(v, alerts, others, prev, c), true
}

// cutRunes cuts s to n runes (not bytes: a character is never split) and
// marks the cut with "...".
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "..."
}

// cutView cuts the strings of a view that a notice shows. The report itself
// keeps its longer limit.
func cutView(v view) view {
	c := func(s string) string { return cutRunes(s, maxNoticeRunes) }
	v.Host, v.State.Reason = c(v.Host), c(v.State.Reason)
	changes := make([]viewChange, len(v.Changes))
	for i, ch := range v.Changes {
		ch.Kind, ch.CheckID, ch.CheckKind, ch.Severity = c(ch.Kind), c(ch.CheckID), c(ch.CheckKind), c(ch.Severity)
		ch.From, ch.To, ch.Subject = c(ch.From), c(ch.To), c(ch.Subject)
		ch.FromSeverity, ch.ToSeverity = c(ch.FromSeverity), c(ch.ToSeverity)
		changes[i] = ch
	}
	v.Changes = changes
	refs := make([]viewRef, len(v.StillFailing))
	for i, r := range v.StillFailing {
		r.CheckID = c(r.CheckID)
		refs[i] = r
	}
	v.StillFailing = refs
	return v
}

// bodyBuilder collects lines up to a budget and counts the ones left out.
type bodyBuilder struct {
	lines   []string
	size    int
	dropped int
}

// add appends a line, or counts it as dropped when the budget is used up.
func (b *bodyBuilder) add(line string) {
	if b.size+len(line)+1 > MaxNoticeBytes-120 {
		b.dropped++
		return
	}
	b.lines = append(b.lines, line)
	b.size += len(line) + 1
}

// blank adds an empty line.
func (b *bodyBuilder) blank() { b.add("") }

func (b *bodyBuilder) String() string {
	lines := b.lines
	if b.dropped > 0 {
		lines = append(lines, "", fmt.Sprintf("%d more %s not shown.", b.dropped, plural(b.dropped, "line", "lines")))
	}
	return strings.Join(lines, "\n") + "\n"
}

// shortHost cuts an already cleaned host name for a title.
func shortHost(h string) string {
	if utf8.RuneCountInString(h) > maxTitleHostRunes {
		return string([]rune(h)[:maxTitleHostRunes]) + "..."
	}
	return h
}

// changeLine is one change as a list item.
func changeLine(c viewChange) string {
	line := fmt.Sprintf("- %s (%s): %s", mdCode(c.CheckID), mdCode(c.Severity), mdCode(changeText(c)))
	if c.Subject != "" {
		line += ": " + mdCode(c.Subject)
	}
	return line
}

func deliveryLine(p *DeliveryNote, c func(string) string) string {
	what := "the notification of an earlier run"
	switch p.Kind {
	case "weekly":
		what = "the weekly report"
	case "baseline":
		what = "the first notification (the open findings)"
	}
	reason := c(p.Reason)
	if reason == "" {
		reason = "no reason recorded"
	}
	return fmt.Sprintf("**Last delivery failed:** %s could not be delivered at %s (%d %s in a row): %s.",
		what, mdCode(p.At.UTC().Format(timeLayout)), p.Failures, plural(p.Failures, "run", "runs"), mdCode(reason))
}

func changeNotice(v view, alerts, others []viewChange, prev *DeliveryNote, c func(string) string) Notice {
	var b bodyBuilder
	head := fmt.Sprintf("**%d %s**", len(alerts), plural(len(alerts), "alert", "alerts"))
	if v.State.PreviousRunAt != "" {
		head += " since the previous run at " + mdCode(v.State.PreviousRunAt)
	}
	b.add(head + ".")
	if prev != nil {
		b.blank()
		b.add(deliveryLine(prev, c))
		if prev.Kind == "check" {
			b.add("")
			b.add("The changes below are everything since the last report that was delivered.")
		}
	}
	var sev result.Severity
	if len(alerts) > 0 {
		b.blank()
		b.add("**Alerts**")
		b.blank()
		// Highest severity first: when the body is too small for all of
		// them, it is the low ones that are left out.
		sort.SliceStable(alerts, func(i, j int) bool {
			return rankOf(result.Severity(alerts[i].Severity)) > rankOf(result.Severity(alerts[j].Severity))
		})
		for _, ch := range alerts {
			b.add(changeLine(ch))
			if rankOf(result.Severity(ch.Severity)) > rankOf(sev) {
				sev = result.Severity(ch.Severity)
			}
		}
	}
	if len(others) > 0 {
		b.blank()
		b.add("**Other changes**")
		b.blank()
		for _, ch := range others {
			b.add(changeLine(ch))
		}
	}
	if len(v.StillFailing) > 0 {
		b.blank()
		ids := refIDs(v.StillFailing)
		more := ""
		if len(ids) > maxStillListed {
			more = fmt.Sprintf(" and %d more", len(ids)-maxStillListed)
			ids = ids[:maxStillListed]
		}
		b.add(fmt.Sprintf("Still failing (%d): %s%s.", len(v.StillFailing), mdCodes(ids), more))
	}
	title := fmt.Sprintf("keepwatch %s: %d %s", shortHost(v.Host), len(alerts), plural(len(alerts), "alert", "alerts"))
	tags := []string{"keepwatch"}
	switch {
	case len(alerts) == 0:
		title = fmt.Sprintf("keepwatch %s: earlier notification was not delivered", shortHost(v.Host))
		tags = append(tags, "warning")
	case rankOf(sev) >= rankOf(result.High):
		tags = append(tags, "rotating_light")
	default:
		tags = append(tags, "warning")
	}
	return Notice{Title: title, Body: b.String(), Severity: sev, Tags: tags}
}

func baselineNotice(v view, results []result.Result, prev *DeliveryNote, resend bool, c func(string) string) Notice {
	var b bodyBuilder
	if resend {
		b.add("**First report:** the notification of the first run could not be delivered, so these are the open findings now.")
	} else {
		b.add("**First run:** there is no previous run to compare with, so no changes are reported. " + mdCode(v.State.Reason))
	}
	b.blank()
	b.add(mdCode(countsLine(v.Counts)))
	if prev != nil {
		b.blank()
		b.add(deliveryLine(prev, c))
	}
	var sev result.Severity
	open := 0
	for _, r := range results {
		if r.Status != result.Fail && r.Status != result.Warn && r.Status != result.Error {
			continue
		}
		if open == 0 {
			b.blank()
			b.add("**Open findings**")
			b.blank()
		}
		open++
		b.add(findingLine(r, c))
		if r.Status != result.Warn && rankOf(r.Severity) > rankOf(sev) {
			sev = r.Severity
		}
	}
	if open == 0 {
		b.blank()
		b.add("No open findings.")
	}
	tags := []string{"keepwatch", "information_source"}
	if rankOf(sev) >= rankOf(result.High) {
		tags = []string{"keepwatch", "rotating_light"}
	}
	first := "first run"
	if resend {
		first = "first report"
	}
	return Notice{
		Title:    fmt.Sprintf("keepwatch %s: %s, %d open %s", shortHost(v.Host), first, open, plural(open, "finding", "findings")),
		Body:     b.String(),
		Severity: sev,
		Tags:     tags,
	}
}

// findingLine is an open finding as a list item. A check in error lists no
// evidence: the evidence of an error is a partial picture and one finding must
// not become a message per item. The marker of a cut list is not an item.
func findingLine(r result.Result, c func(string) string) string {
	line := fmt.Sprintf("- %s %s (%s)", statusLabel(string(r.Status)), mdCode(c(r.CheckID)), mdCode(c(string(r.Severity))))
	if r.Status == result.Error {
		return line
	}
	var subjects []string
	n := 0
	for _, e := range r.Listed() {
		if e.Excepted {
			continue
		}
		n++
		if len(subjects) < maxSubjectsListed {
			subjects = append(subjects, c(e.Subject))
		}
	}
	if len(subjects) > 0 {
		line += ": " + mdCodes(subjects)
		if n > len(subjects) {
			line += fmt.Sprintf(" and %d more", n-len(subjects))
		}
	}
	return line
}

func rankOf(s result.Severity) int {
	for i, v := range result.Severities {
		if v == s {
			return i
		}
	}
	return -1
}
