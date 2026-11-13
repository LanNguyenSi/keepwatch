package alert

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func inc() incident.Incident {
	return incident.Incident{
		ID: "inc-1", RuleID: "ssh-brute", Severity: result.High, Title: "ssh failures",
		Summary: "many failed logins", Count: 7,
		FirstSeen: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		LastSeen:  time.Date(2026, 1, 2, 4, 4, 5, 0, time.UTC),
	}
}

func ident(s string) string { return s }

func TestBuildMessageBasics(t *testing.T) {
	m := BuildMessage(inc(), ident)
	if m.Title != "[high] ssh failures" || m.Priority != 4 || m.Markdown {
		t.Errorf("message = %+v", m)
	}
	for _, w := range []string{"inc-1", "ssh-brute", "Seen 7 times", "2026-01-02T03:04:05Z", "many failed logins"} {
		if !strings.Contains(m.Body, w) {
			t.Errorf("body lacks %q:\n%s", w, m.Body)
		}
	}
	if strings.Join(m.Tags, ",") != "keepwatch,high" {
		t.Errorf("tags = %v", m.Tags)
	}
	i := inc()
	i.ReopenCount = 2
	m = BuildMessage(i, ident)
	if !strings.HasPrefix(m.Title, "[high] Reopened: ") || !strings.Contains(m.Body, "reopened 2 times") ||
		strings.Join(m.Tags, ",") != "keepwatch,high,reopened" {
		t.Errorf("reopened message = %+v", m)
	}
	i.Severity = "bogus tag!"
	if m := BuildMessage(i, ident); strings.Join(m.Tags, ",") != "keepwatch,reopened" || m.Priority != 3 {
		t.Errorf("unknown severity message = %+v", m)
	}
}

func TestLimits(t *testing.T) {
	i := inc()
	i.Title = strings.Repeat("ü", 400)
	i.Summary = strings.Repeat("ü", 5000)
	m := BuildMessage(i, ident)
	if len(m.Title) > notify.MaxTitleBytes || len(m.Body) > notify.MaxBodyBytes {
		t.Errorf("sizes: title %d body %d", len(m.Title), len(m.Body))
	}
	if !utf8.ValidString(m.Title) || !utf8.ValidString(m.Body) {
		t.Error("cut inside a character")
	}
	if !strings.HasSuffix(m.Title, "...") || !strings.HasSuffix(m.Body, "...") {
		t.Error("cut not marked")
	}
	if len(m.Tags) > 5 {
		t.Errorf("tags = %v", m.Tags)
	}
	i.Title = "a\nb\tc"
	if m := BuildMessage(i, ident); strings.ContainsAny(m.Title, "\r\n\t") {
		t.Errorf("title = %q", m.Title)
	}
}

// A secret that straddles the cut must be redacted whole before the cut.
func TestCleanBeforeCut(t *testing.T) {
	clean := func(s string) string { return strings.ReplaceAll(s, "SECRETTOKEN", "[X]") }
	i := inc()
	i.Title = strings.Repeat("a", 235) + "SECRETTOKEN"
	m := BuildMessage(i, clean)
	if strings.Contains(m.Title, "SEC") {
		t.Errorf("secret fragment survived the cut: %q", m.Title[200:])
	}
	i = inc()
	i.Summary = ""
	// Put the secret so that the cut of the raw body would land inside it.
	head := len(BuildMessage(i, ident).Body) + 1
	pad := notify.MaxBodyBytes - len(cutMark) - head - 5
	i.Summary = strings.Repeat("a", pad) + "SECRETTOKEN" + strings.Repeat("b", 400)
	m = BuildMessage(i, clean)
	if strings.Contains(m.Body, "SEC") {
		t.Errorf("secret fragment survived the body cut")
	}
	if len(m.Body) > notify.MaxBodyBytes {
		t.Errorf("body %d bytes", len(m.Body))
	}
}

func TestCleanAppliedOncePerField(t *testing.T) {
	i := inc()
	calls := map[string]int{}
	BuildMessage(i, func(s string) string { calls[s]++; return s })
	want := []string{i.Title, i.ID, i.RuleID, string(i.Severity), i.Summary}
	if len(calls) != len(want) {
		t.Errorf("clean saw %v", calls)
	}
	for _, f := range want {
		if calls[f] != 1 {
			t.Errorf("clean called %d times for %q", calls[f], f)
		}
	}
}

// The real redactor escapes line breaks inside a field; the lines of the
// body are joined after that, so they stay real.
func TestBodyKeepsLineBreaks(t *testing.T) {
	red, err := redact.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	i := inc()
	i.Summary = "first\nsecond"
	m := BuildMessage(i, red.Clean)
	if got := strings.Count(m.Body, "\n"); got < 6 {
		t.Errorf("only %d real line breaks:\n%q", got, m.Body)
	}
	if strings.Contains(m.Body, `\n`) && !strings.Contains(m.Body, `first\nsecond`) {
		t.Errorf("literal backslash-n from the template: %q", m.Body)
	}
	if !strings.HasPrefix(m.Body, "Incident inc-1 (rule ssh-brute)\nSeverity: high\n") {
		t.Errorf("body = %q", m.Body)
	}
	// The only literal backslash-n is the one inside the summary field.
	if strings.Count(m.Body, `\n`) != 1 {
		t.Errorf("body = %q", m.Body)
	}
}

func TestMessageHasNoRawToken(t *testing.T) {
	red, err := redact.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := "ghp_" + strings.Repeat("A1b2", 9)
	i := inc()
	i.Title = "login with " + tok
	i.Summary = "token " + tok + " seen"
	i.RuleID = tok
	m := BuildMessage(i, red.Clean)
	all := m.Title + "\n" + m.Body + "\n" + strings.Join(m.Tags, ",")
	if strings.Contains(all, tok) || strings.Contains(all, "ghp_") {
		t.Errorf("token in message:\n%s", all)
	}
	if !strings.Contains(all, "[REDACTED]") {
		t.Errorf("not redacted:\n%s", all)
	}
}
