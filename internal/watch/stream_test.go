package watch

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
)

func TestCursorResetRecordSaysInvalid(t *testing.T) {
	h := newHarness(t, hopts{})
	h.d.cur, h.d.saved = cur("1"), cur("1")
	if _, _, err := h.d.streamEnded(execx.StreamResult{ExitCode: 1, Stderr: []byte("Failed to seek to cursor: Invalid argument")}, nil, cur("1")); err != nil {
		t.Fatal(err)
	}
	rs := h.records()
	if s := rs[len(rs)-1].Summary; rs[len(rs)-1].Kind != audit.CursorReset || !strings.Contains(s, "as invalid") || strings.Contains(s, "vacuum") || strings.Contains(s, "rotat") {
		t.Fatalf("record = %+v", rs[len(rs)-1])
	}
}

func curS(s, i string) string { return "s=" + s + ";i=" + i + ";b=2;m=3;t=4;x=5" }

func TestJournalGapAfterRestart(t *testing.T) {
	cases := []struct {
		name  string
		saved string
		first string
		want  string // substring of the gap record, "" for none
	}{
		{"next entry", curS("1", "5"), curS("1", "6"), ""},
		{"hex numbers, next entry", curS("1", "9"), curS("1", "a"), ""},
		{"one entry missing", curS("1", "5"), curS("1", "7"), "1 journal entries"},
		{"hex numbers, one missing", curS("1", "a"), curS("1", "c"), "1 journal entries"},
		{"many missing", curS("1", "13d"), curS("1", "146"), "8 journal entries"},
		{"same entry", curS("1", "5"), curS("1", "5"), gapUnknown},
		{"seqnum goes back", curS("1", "5"), curS("1", "2"), gapUnknown},
		{"next entry in another journal file", curS("1", "5"), curS("2", "6"), ""},
		// Another seqnum id: a replaced journal and journald of systemd 249
		// after a kill look the same, so the record claims no loss.
		{"another seqnum id, seqnum starts over", curS("1", "5"), curS("2", "1"), gapUnknown},
		{"another seqnum id, seqnum ahead", curS("1", "5"), curS("2", "9"), gapUnknown},
		{"another seqnum id, same seqnum", curS("1", "5"), curS("2", "5"), gapUnknown},
		{"saved cursor without i", "s=1;b=2", curS("1", "9"), ""},
		{"first cursor without s", curS("1", "5"), "i=9;b=2", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{setup: func(h *harness) {
				if err := h.cursor.Save(c.saved); err != nil {
					t.Fatal(err)
				}
			}})
			h.script(c.saved, fake.Script{Follow: true, Lines: []string{plainLine(c.first, t0)}})
			if err := h.runUntil("line", func() bool { return h.savedCursor() == c.first && (c.want == "" || h.count(KindJournalGap) == 1) }); err != nil {
				t.Fatal(err)
			}
			var got string
			for _, r := range h.records() {
				if r.Kind == KindJournalGap {
					got = r.Summary
				}
			}
			if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
				t.Fatalf("journal_gap record = %q, want %q", got, c.want)
			}
			// Only a counted jump under the same seqnum id claims a loss.
			if c.want == gapUnknown && (strings.Contains(got, "are missing") || strings.Contains(got, "gone")) {
				t.Fatalf("journal_gap record = %q claims a loss it cannot know", got)
			}
			if len(h.notif.sent()) != 0 {
				t.Fatal("a gap is audited, not notified")
			}
		})
	}
}

// The comparison is made once per stream, and again after a restart.
func TestJournalGapIsCheckedOncePerStream(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Err: errors.New("x"), Lines: []string{plainLine(curS("1", "5"), t0)}})
	h.script(curS("1", "5"), fake.Script{Follow: true, Lines: []string{plainLine(curS("1", "9"), t0), plainLine(curS("1", "20"), t0)}})
	if err := h.runUntil("lines", func() bool { return h.savedCursor() == curS("1", "20") }); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range h.records() {
		if r.Kind == KindJournalGap {
			n++
			if !strings.Contains(r.Summary, "3 journal entries") {
				t.Errorf("record = %q", r.Summary)
			}
		}
	}
	if n != 1 {
		t.Fatalf("journal_gap records = %d, want 1 (the first stream had no saved cursor, the second compares once)", n)
	}
}

func TestOverlongLinesAreCountedAtShutdown(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true, Lines: []string{strings.Repeat("a", execx.DefaultMaxLine+1)}})
	if err := h.runUntil("start", func() bool { return len(h.fs.Calls()) == 1 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.JournalLineInvalid) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

func TestLineWithAnUnusableCursorIsABadLine(t *testing.T) {
	for name, c := range map[string]string{
		"space": "s=1;i=1;b=a b", "non-ASCII": "s=1;i=1;b=é", "too long": "s=1;i=1;b=" + strings.Repeat("a", MaxCursorBytes),
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.script("", fake.Script{Follow: true, Lines: []string{plainLine(c, t0), plainLine(cur("2"), t0)}})
			if err := h.runUntil("good line", func() bool { return h.savedCursor() == cur("2") }); err != nil {
				t.Fatalf("Run = %v, want nil: a bad cursor must not stop the daemon", err)
			}
			if h.count(audit.JournalLineInvalid) != 1 {
				t.Fatalf("kinds = %v", h.kinds())
			}
		})
	}
	t.Run("only the bad line", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.script("", fake.Script{Follow: true, Lines: []string{plainLine("a b", t0)}})
		if err := h.runUntil("line", func() bool { return h.count(audit.JournalLineInvalid) == 1 }); err != nil {
			t.Fatal(err)
		}
		if h.savedCursor() != "" {
			t.Fatalf("cursor = %q, must not move past a line it cannot save", h.savedCursor())
		}
	})
	t.Run("error line with an unusable cursor", func(t *testing.T) {
		h := newHarness(t, hopts{})
		h.script("", fake.Script{Follow: true, Lines: []string{jline("a b", t0, map[string]string{"_PID": "x"})}})
		if err := h.runUntil("line", func() bool { return h.count(audit.JournalLineInvalid) == 1 }); err != nil {
			t.Fatal(err)
		}
		if h.savedCursor() != "" {
			t.Fatalf("cursor = %q", h.savedCursor())
		}
	})
}

func TestSleepErrorEndsTheLoopWithThatError(t *testing.T) {
	boom := errors.New("sleep broke")
	h := newHarness(t, hopts{opt: Options{Sleep: func(context.Context, time.Duration) error { return boom }}})
	h.script("", fake.Script{Result: execx.StreamResult{ExitCode: 1}})
	err := h.start().wait(t)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want the sleep error", err)
	}
	if h.count(audit.DaemonStop) != 0 || h.count(audit.DaemonError) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
}

// The first line after a resume may be one that cannot be decoded. Its cursor
// is compared like any other, so the line after it is not taken for the
// first one (which would report one entry missing).
func TestJournalGapIsCheckedOnABadFirstLine(t *testing.T) {
	bad := func(c string) string { return jline(c, t0, map[string]string{"_PID": "x", "MESSAGE": "m"}) }
	for name, c := range map[string]struct {
		first string
		want  string
	}{
		"the bad line follows the saved cursor":   {curS("1", "6"), ""},
		"entries are missing before the bad line": {curS("1", "8"), "2 journal entries"},
	} {
		t.Run(name, func(t *testing.T) {
			saved := curS("1", "5")
			h := newHarness(t, hopts{setup: func(h *harness) {
				if err := h.cursor.Save(saved); err != nil {
					t.Fatal(err)
				}
			}})
			h.script(saved, fake.Script{Follow: true, Lines: []string{bad(c.first), plainLine(curS("1", "9"), t0)}})
			if err := h.runUntil("lines", func() bool { return h.savedCursor() == curS("1", "9") }); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range h.records() {
				if r.Kind == KindJournalGap {
					got = append(got, r.Summary)
				}
			}
			if h.count(audit.JournalLineInvalid) != 1 {
				t.Fatalf("the first line was not a bad line: %v", h.kinds())
			}
			if (c.want == "" && len(got) != 0) || (c.want != "" && (len(got) != 1 || !strings.Contains(got[0], c.want))) {
				t.Fatalf("journal_gap records = %q, want %q", got, c.want)
			}
		})
	}
}
