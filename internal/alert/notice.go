package alert

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

const cutMark = "..."

// BuildMessage builds the notification of an incident. It reads only the
// incident (whose text is cleaned already, never a raw event field) and
// passes each text field through clean exactly once; the lines are put
// together after that, with real line breaks (clean escapes the ones inside a
// field), and the cut to the limits of notify comes last, so a secret that
// straddles the cut is redacted whole before anything is cut off. The message
// is plain text.
func BuildMessage(inc incident.Incident, clean func(string) string) notify.Message {
	f := fields{
		title:    clean(inc.Title),
		id:       clean(inc.ID),
		rule:     clean(inc.RuleID),
		severity: clean(string(inc.Severity)),
		summary:  clean(inc.Summary),
	}
	return notify.Message{
		Title:    cutBytes(oneLine(titleText(inc, f)), notify.MaxTitleBytes),
		Body:     cutBytes(bodyText(inc, f), notify.MaxBodyBytes),
		Priority: notify.PriorityOf(inc.Severity),
		Tags:     tags(inc),
	}
}

// fields are the cleaned text fields of an incident.
type fields struct{ title, id, rule, severity, summary string }

func titleText(inc incident.Incident, f fields) string {
	t := f.title
	if inc.ReopenCount > 0 {
		t = "Reopened: " + t
	}
	return "[" + f.severity + "] " + t
}

func bodyText(inc incident.Incident, f fields) string {
	var b strings.Builder
	b.WriteString("Incident " + f.id + " (rule " + f.rule + ")\n")
	b.WriteString("Severity: " + f.severity + "\n")
	b.WriteString("Seen " + strconv.Itoa(inc.Count) + " times")
	if inc.ReopenCount > 0 {
		b.WriteString(", reopened " + strconv.Itoa(inc.ReopenCount) + " times")
	}
	b.WriteString("\nFirst seen: " + inc.FirstSeen.UTC().Format("2006-01-02T15:04:05Z") + "\n")
	b.WriteString("Last seen: " + inc.LastSeen.UTC().Format("2006-01-02T15:04:05Z") + "\n")
	if f.summary != "" {
		b.WriteString("\n" + f.summary + "\n")
	}
	return b.String()
}

// tags are fixed words: the tag for the severity is only used when the
// severity is one the program knows.
func tags(inc incident.Incident) []string {
	t := []string{"keepwatch"}
	switch inc.Severity {
	case result.Critical, result.High, result.Medium, result.Low, result.Info:
		t = append(t, string(inc.Severity))
	}
	if inc.ReopenCount > 0 {
		t = append(t, "reopened")
	}
	return t
}

// oneLine turns every line break and tab into a space; the title is a header.
func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
}

// cutBytes cuts s to at most n bytes without splitting a character, and marks
// the cut.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	end := n - len(cutMark)
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + cutMark
}
