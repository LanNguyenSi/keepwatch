package probes_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// outcomeText is the number of bytes of text an outcome holds to be shown.
func outcomeText(summary string, ev []result.Evidence) int {
	n := len(summary)
	for _, e := range ev {
		n += len(e.Subject) + len(e.Detail)
	}
	return n
}

// A best-effort ss -p run that fails with a very long line must not put that
// line into every listener's detail: with 150 listeners and a 1 MiB line the
// outcome would hold 150 copies. The note stands once, cut.
func TestListenersFailingProcessRunIsNotRepeatedPerListener(t *testing.T) {
	var sockets strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&sockets, "LISTEN 0 5 0.0.0.0:%d 0.0.0.0:*\n", 9000+i)
	}
	huge := strings.Repeat("x", 1<<20)
	r := newRunner().AddResult(ssTCP, inline(sockets.String(), 0)).AddResult(ssUDP, inline("", 0)).
		AddResult(ssTCPp, execx.Result{ExitCode: 1, Stderr: []byte(huge + "\n")}).AddResult(ssUDPp, inline("", 0))
	o := exec(listenersProbe(t, nil), r, nil)
	wantStatus(t, o, result.Fail)
	if n := outcomeText(o.Summary, o.Evidence); n > 128<<10 {
		t.Fatalf("the outcome holds %d bytes of text for one 1 MiB line", n)
	}
	all := o.Summary
	for _, e := range o.Evidence {
		all += "\n" + e.Detail
	}
	if got := strings.Count(all, "process names may be missing"); got != 1 {
		t.Fatalf("the note stands %d times, want once", got)
	}
	for _, e := range o.Evidence {
		if strings.HasPrefix(e.Subject, "tcp/") && !strings.Contains(e.Detail, "processes: unknown") {
			t.Fatalf("detail %q", e.Detail)
		}
	}
}

// Text of the host is cut far beyond what a report shows, so a secret that
// starts inside the first 2000 runes is whole when Clean redacts it, the cut
// leaves valid UTF-8, and the length is bounded.
func TestHostTextIsCutOnlyFarBeyondTheReportCut(t *testing.T) {
	const token = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	run := func(first string) result.Result {
		o := exec(prepare(t, "fail2ban_jail", map[string]any{"jail": "sshd"}), newRunner().AddResult(jailArgv("sshd"), inline(first+"\n", 0)), nil)
		wantStatus(t, o, result.Error)
		return result.Result{Summary: o.Summary}
	}
	t.Run("a token across the report cut is redacted", func(t *testing.T) {
		got := run(strings.Repeat("a", 1930) + " " + token + " " + strings.Repeat("b", 1<<20)).Summary
		if len(got) > 33<<10 {
			t.Fatalf("summary is %d bytes", len(got))
		}
		if s := shown(got); strings.Contains(s, "ZZZZ") || !strings.Contains(s, "[REDACTED]") {
			t.Fatalf("shown summary %.100q ... %.60q", s, s[max(0, len(s)-60):])
		}
	})
	t.Run("the cut keeps valid UTF-8 and ends in dots", func(t *testing.T) {
		got := run(strings.Repeat("€", 20000)).Summary
		if !utf8.ValidString(got) || !strings.HasSuffix(got, `..."`) || len(got) > 33<<10 {
			t.Fatalf("summary: valid %v, %d bytes, ends %q", utf8.ValidString(got), len(got), got[len(got)-8:])
		}
	})
	t.Run("a short text is not cut", func(t *testing.T) {
		in := strings.Repeat("c", 30<<10)
		if got := run(in).Summary; !strings.Contains(got, `"`+in+`"`) {
			t.Fatalf("a text below the limit was changed")
		}
	})
}

// With a failing ss -p run and a failing ss run of the other protocol the
// summary carries the note once as well.
func TestListenersPartialResultStatesTheProcessNoteOnce(t *testing.T) {
	r := newRunner().AddResult(ssTCP, inline("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\n", 0)).
		AddResult(ssUDP, execx.Result{ExitCode: 1, Stderr: []byte("udp broke\n")}).
		AddResult(ssTCPp, execx.Result{ExitCode: 1, Stderr: []byte("pids broke\n")})
	o := exec(listenersProbe(t, nil), r, nil)
	wantStatus(t, o, result.Error)
	wantSummary(t, o, "process names may be missing")
	wantSummary(t, o, "pids broke")
	if got := strings.Count(o.Summary, "process names may be missing"); got != 1 {
		t.Fatalf("the note stands %d times in %q", got, o.Summary)
	}
}

// Wherever the probes of these kinds put a piece of host text into a summary
// or a detail, a megabyte of it is cut.
func TestEveryPieceOfHostTextIsBounded(t *testing.T) {
	huge := strings.Repeat("a", 1<<20)
	for _, role := range commandRoles() {
		t.Run(role.name, func(t *testing.T) {
			o := role.run(t, huge)
			if n := outcomeText(o.Summary, o.Evidence); n > 2*(33<<10) {
				t.Fatalf("the outcome holds %d bytes of text", n)
			}
		})
	}
}
