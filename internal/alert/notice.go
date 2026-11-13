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
// passes each output string through clean exactly once; the cut to the limits
// of notify comes after that, so a secret that straddles the cut is redacted
// whole before anything is cut off. The message is plain text.
func BuildMessage(inc incident.Incident, clean func(string) string) notify.Message {
	title := cutBytes(oneLine(clean(titleText(inc))), notify.MaxTitleBytes)
	body := cutBytes(clean(bodyText(inc)), notify.MaxBodyBytes)
	return notify.Message{
		Title:    title,
		Body:     body,
		Priority: notify.PriorityOf(inc.Severity),
		Tags:     tags(inc),
	}
}

func titleText(inc incident.Incident) string {
	t := inc.Title
	if inc.ReopenCount > 0 {
		t = "Reopened: " + t
	}
	return "[" + string(inc.Severity) + "] " + t
}

func bodyText(inc incident.Incident) string {
	var b strings.Builder
	b.WriteString("Incident " + inc.ID + " (rule " + inc.RuleID + ")\n")
	b.WriteString("Severity: " + string(inc.Severity) + "\n")
	b.WriteString("Seen " + strconv.Itoa(inc.Count) + " times")
	if inc.ReopenCount > 0 {
		b.WriteString(", reopened " + strconv.Itoa(inc.ReopenCount) + " times")
	}
	b.WriteString("\nFirst seen: " + inc.FirstSeen.UTC().Format("2006-01-02T15:04:05Z") + "\n")
	b.WriteString("Last seen: " + inc.LastSeen.UTC().Format("2006-01-02T15:04:05Z") + "\n")
	if inc.Summary != "" {
		b.WriteString("\n" + inc.Summary + "\n")
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
