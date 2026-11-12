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
// table that drops for both address families is named in both). This guards a
// piece against being copied into a list of items, with the 150-listener test
// above as the guard for the note of a failed ss -p run (the listeners role
// here has two sockets, so a copy per item is three copies). It also holds that
// the whole piece is still in the text of the outcome: a probe that cuts a
// piece, at whatever length, fails it.
func TestNoPieceOfHostTextIsCopiedMoreThanTwiceOrCut(t *testing.T) {
	for _, role := range commandRoles() {
		t.Run(role.name, func(t *testing.T) {
			// not a valid keyword, package name or number: the place keeps it
			big := "A." + strings.Repeat("a", hostFileLimit(role, 100<<10))
			o := role.run(t, big)
			if n := outcomeText(o.Summary, o.Evidence); n > 2*len(big)+4096 {
				t.Fatalf("a piece of %d bytes is in the outcome %.1f times", len(big), float64(n)/float64(len(big)))
			}
			if !outcomeHolds(o.Summary, o.Evidence, big) {
				t.Fatalf("the piece of %d bytes is cut in the outcome", len(big))
			}
		})
	}
}

// hostFileLimit is n, or less where the host text comes from a file that the
// probe refuses above a size (the package list of a reboot check: 64 KiB).
func hostFileLimit(role corpusRole, n int) int {
	if role.name == "reboot package list" {
		return min(n, 60<<10)
	}
	return n
}

// outcomeHolds says whether want is whole in the summary or in a detail.
func outcomeHolds(summary string, ev []result.Evidence, want string) bool {
	if strings.Contains(summary, want) {
		return true
	}
	for _, e := range ev {
		if strings.Contains(e.Detail, want) || strings.Contains(e.Subject, want) {
			return true
		}
	}
	return false
}

const longToken = "ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"

// longHostTexts are texts in which a token stands across, or ends at, a byte
// offset where a cut of that length would split it: after a long value that
// Clean redacts to a few characters (so the offset lands in the shown text),
// or followed by bytes that are not valid UTF-8 (so a walk back to a character
// boundary would drop the end of the token). sep is what stands around the
// token: white space where the place allows it.
//
// tail is what follows the token in the second text: bytes that are not valid
// UTF-8 (for a place that can hold them) or a valid character.
func longHostTexts(sep, tail string) map[string]string {
	m := map[string]string{}
	pw := "password="
	for _, at := range []int{16384, 32768, 65536} {
		m[fmt.Sprintf("token across byte %d after a long value", at)] = pw + strings.Repeat("v", at-20-len(pw)-len(sep)) + sep + longToken + sep + "tail"
		m[fmt.Sprintf("token ending at byte %d, then %d bytes of tail", at, 33<<10)] = pw + strings.Repeat("v", at-len(longToken)-len(pw)-len(sep)) + sep + longToken + strings.Repeat(tail, 33<<10/len(tail))
	}
	return m
}

// Every command role keeps such a text whole, and the token in it is gone from
// every output when the text is followed to the report.
func TestLongHostTextIsKeptWholeByEveryRole(t *testing.T) {
	for _, role := range commandRoles() {
		sep := " "
		if role.noWS {
			sep = ","
		}
		tail := "\x80"
		if strings.HasPrefix(role.name, "firewall nft") {
			tail = "€" // JSON cannot carry a byte that is not UTF-8
		}
		for name, frag := range longHostTexts(sep, tail) {
			if len(frag) > hostFileLimit(role, len(frag)) {
				continue
			}
			t.Run(role.name+"/"+name, func(t *testing.T) {
				o := role.run(t, frag)
				if o.Status != role.status {
					t.Fatalf("status %s (%.80q), want %s", o.Status, o.Summary, role.status)
				}
				if !outcomeHolds(o.Summary, o.Evidence, frag) {
					t.Fatalf("the text of %d bytes is cut in the outcome", len(frag))
				}
			})
		}
	}
}

// Host text is long, and a pattern that matches a lot sits in front of a
// secret: no step between the host and the report may cut the text where it
// would split the secret, however the text came to be that long. The texts of
// longHostTexts are followed to every output.
func TestLongHostTextIsRedactedBeforeItIsCut(t *testing.T) {
	var role corpusRole
	for _, r := range commandRoles() {
		if r.name == "run command that cannot be started" {
			role = r
		}
	}
	red := redact.Default()
	for name, frag := range longHostTexts(" ", "\x80") {
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
