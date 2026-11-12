package probes_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
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
// outcome would hold 150 copies. The note stands once.
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
	if n := outcomeText(o.Summary, o.Evidence); n > len(huge)+(256<<10) {
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

// A piece of host text is copied into an outcome at most twice (a firewall
// table that drops for both address families is named in both), never once per
// item of a list.
func TestNoPieceOfHostTextIsCopiedMoreThanTwice(t *testing.T) {
	big := strings.Repeat("a", 100<<10)
	for _, role := range commandRoles() {
		t.Run(role.name, func(t *testing.T) {
			o := role.run(t, big)
			if n := outcomeText(o.Summary, o.Evidence); n > 2*len(big)+4096 {
				t.Fatalf("a piece of %d bytes is in the outcome %.1f times", len(big), float64(n)/float64(len(big)))
			}
		})
	}
}

// Host text is long, and a pattern that matches a lot sits in front of a
// secret: no step between the host and the report may cut the text where it
// would split the secret, however the text came to be that long. Both cases
// are followed to every output.
func TestLongHostTextIsRedactedBeforeItIsCut(t *testing.T) {
	const token = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	var role corpusRole
	for _, r := range commandRoles() {
		if r.name == "run command that cannot be started" {
			role = r
		}
	}
	red := redact.Default()
	for name, frag := range map[string]string{
		// bytes that are not valid UTF-8 after the token
		"token, then 33 KiB of continuation bytes":    "x. " + token + " " + strings.Repeat("\x80", 33<<10),
		"token glued to 33 KiB of continuation bytes": "x. " + token + strings.Repeat("\x80", 33<<10),
		// a long value that Clean redacts to a few characters, so that what
		// stands at byte 32768 of the host text is within the first runes of
		// the shown text
		"long redacted value, token at byte 32768":     "password=" + strings.Repeat("v", 32768-len("password=")-len(token)-12) + " x " + token + " tail",
		"long redacted value, token across byte 32768": "password=" + strings.Repeat("v", 32768-len("password=")-20) + " x " + token + " tail",
	} {
		t.Run(name, func(t *testing.T) {
			o := role.run(t, frag)
			saw := false
			for out, b := range outputsOf(t, role, o, red) {
				if leak := leakIn(b, "ghp_ZZZZ"); leak != "" || strings.Contains(string(b), "ZZZZZZ") {
					t.Fatalf("%s holds the token", out)
				}
				saw = saw || strings.Contains(string(b), "[REDACTED]")
			}
			if !saw {
				t.Fatal("nothing was redacted in any output")
			}
		})
	}
}
