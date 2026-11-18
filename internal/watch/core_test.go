package watch

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
)

func TestEndToEnd(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true, Lines: []string{
		plainLine(cur("1"), t0.Add(-3*time.Second)),
		sshLine(cur("2"), t0.Add(-2*time.Second), "203.0.113.9"),
		sshLine(cur("3"), t0.Add(-time.Second), "203.0.113.9"), // threshold 1: fires once per burst
		sshLine(cur("4"), t0, "203.0.113.10"),
	}})
	err := h.runUntil("both notifications and the cursor", func() bool {
		return len(h.notif.sent()) == 2 && h.savedCursor() == cur("4") && h.count(audit.NotifySent) == 2
	})
	if err != nil {
		t.Fatalf("Run = %v, want nil after cancel", err)
	}
	h.verify()
	k := h.kinds()
	if k[0] != audit.DaemonStart || k[len(k)-1] != audit.DaemonStop {
		t.Fatalf("kinds = %v", k)
	}
	if got := h.count(audit.IncidentOpen); got != 2 {
		t.Fatalf("incident_open = %d, want 2", got)
	}
	list := h.store.List()
	if len(list) != 2 || list[0].Count != 1 || list[0].State != incident.StateOpen {
		t.Fatalf("incidents = %+v", list)
	}
	for _, in := range list {
		if in.NotifiedAt.IsZero() {
			t.Errorf("incident %s not marked notified", in.ID)
		}
		if !in.FirstSeen.Equal(in.LastSeen) && !in.LastSeen.After(in.FirstSeen) {
			t.Errorf("times %v %v", in.FirstSeen, in.LastSeen)
		}
	}
	// The incident time is the journal's timestamp, not the daemon clock.
	if !list[0].FirstSeen.Equal(t0.Add(-2 * time.Second)) {
		t.Errorf("FirstSeen = %v, want the journal timestamp", list[0].FirstSeen)
	}
	m := h.notif.sent()[0]
	if m.Priority != 4 || !strings.Contains(m.Title, "ssh_brute_force") {
		t.Errorf("message = %+v", m)
	}
	// The command line was journalctl from the saved cursor (none), at now.
	if c := h.fs.Calls(); len(c) != 1 || strings.Join(c[0].Argv, " ") != strings.Join(args(""), " ") {
		t.Errorf("calls = %+v", c)
	}
}

// A line is handled completely before the cursor moves: when the audit write
// of its signal fails, the cursor stays where it was and Run fails.
func TestCursorNotSavedWhenHandlingFails(t *testing.T) {
	h := newHarness(t, hopts{})
	// The audit writer is closed once the daemon has started, so the record
	// of the first signal cannot be written.
	var once sync.Once
	st := streamFunc(func(ctx context.Context, argv []string, o execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		once.Do(func() { h.aw.Close() })
		if err := on([]byte(sshLine(cur("1"), t0, "203.0.113.9"))); err != nil {
			return execx.StreamResult{}, err
		}
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
	h.d.deps.Streamer = st
	err := h.start().wait(t)
	if err == nil || !strings.Contains(err.Error(), "audit write failed") {
		t.Fatalf("Run = %v, want an audit write failure", err)
	}
	if c := h.savedCursor(); c != "" {
		t.Fatalf("cursor = %q: it moved past a line that was not handled", c)
	}
}

type streamFunc func(context.Context, []string, execx.StreamOpts, func([]byte) error) (execx.StreamResult, error)

func (f streamFunc) Stream(ctx context.Context, a []string, o execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
	return f(ctx, a, o, on)
}

// A crash after the work and before the cursor save replays the line, never
// loses it: on the next start the saved cursor is the one before the line.
func TestRestartResumesFromSavedCursor(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Err: errors.New("journalctl died"), Lines: []string{
		plainLine(cur("1"), t0.Add(-2*time.Second)),
		sshLine(cur("2"), t0.Add(-time.Second), "203.0.113.9"),
	}})
	h.script(cur("2"), fake.Script{Follow: true, Lines: []string{sshLine(cur("3"), t0, "203.0.113.11")}})
	err := h.runUntil("the second stream's line", func() bool { return h.savedCursor() == cur("3") })
	if err != nil {
		t.Fatal(err)
	}
	calls := h.fs.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	if got := calls[1].Argv[len(calls[1].Argv)-1]; got != "--after-cursor="+cur("2") {
		t.Fatalf("restart argv = %v", calls[1].Argv)
	}
	if s := h.slept(); len(s) != 1 || s[0] != DefaultBackoffMin {
		t.Fatalf("sleeps = %v", s)
	}
	if n := len(h.store.List()); n != 2 {
		t.Fatalf("incidents = %d, want 2", n)
	}
}

// A new process resumes from the cursor file.
func TestStartResumesFromCursorFile(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		if err := h.cursor.Save(cur("7")); err != nil {
			t.Fatal(err)
		}
	}})
	h.script(cur("7"), fake.Script{Follow: true})
	if err := h.runUntil("the stream", func() bool { return len(h.fs.Calls()) == 1 }); err != nil {
		t.Fatal(err)
	}
	if got := h.fs.Calls()[0].Argv; got[len(got)-1] != "--after-cursor="+cur("7") {
		t.Fatalf("argv = %v", got)
	}
	if !strings.Contains(h.records()[0].Summary, "resuming") {
		t.Fatalf("daemon_start = %q", h.records()[0].Summary)
	}
}

func TestBackoffCappedAndGivesUp(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{BackoffMax: 3 * time.Second, MaxRestarts: 3}})
	h.script("", fake.Script{Result: execx.StreamResult{ExitCode: 1, Stderr: []byte("boom")}})
	err := h.start().wait(t)
	if !errors.Is(err, ErrStreamEnded) {
		t.Fatalf("Run = %v, want ErrStreamEnded", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}
	if got := h.slept(); len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("sleeps = %v, want %v", got, want)
	}
	h.verify()
	k := h.kinds()
	if k[len(k)-1] != audit.DaemonError {
		t.Fatalf("last record = %v, want daemon_error", k)
	}
}

// Progress (a delivered line) resets the failure count.
func TestProgressResetsRestartBudget(t *testing.T) {
	h := newHarness(t, hopts{opt: Options{MaxRestarts: 1}})
	// Each run delivers one line and then fails; with the reset the daemon
	// never reaches its budget (the third script ends the test with Follow).
	h.script("", fake.Script{Err: errors.New("x"), Lines: []string{plainLine(cur("1"), t0)}})
	h.script(cur("1"), fake.Script{Err: errors.New("x"), Lines: []string{plainLine(cur("2"), t0)}})
	h.script(cur("2"), fake.Script{Follow: true})
	if err := h.runUntil("third stream", func() bool { return len(h.fs.Calls()) == 3 }); err != nil {
		t.Fatalf("Run = %v", err)
	}
}

func TestUnstartableJournalctlIsFatal(t *testing.T) {
	for name, cause := range map[string]error{"not allowed": execx.ErrNotAllowed, "not found": execx.ErrNotFound} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.fs.AddError(args(""), cause)
			err := h.start().wait(t)
			if !errors.Is(err, ErrStreamEnded) || !strings.Contains(err.Error(), cause.Error()) {
				t.Fatalf("Run = %v", err)
			}
			if s := h.slept(); len(s) != 0 || len(h.fs.Calls()) != 1 {
				t.Fatalf("an unstartable program is not retried: sleeps = %v, calls = %d", s, len(h.fs.Calls()))
			}
		})
	}
}

// Cursor rejected by journalctl: audited as cursor_reset, restart at now.
func TestRejectedCursorIsResetAndAudited(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		if err := h.cursor.Save(cur("old")); err != nil {
			t.Fatal(err)
		}
	}})
	h.script(cur("old"), fake.Script{Result: execx.StreamResult{ExitCode: 1, Stderr: []byte("Failed to seek to cursor: No data available\n")}})
	h.script("", fake.Script{Follow: true})
	if err := h.runUntil("restart at now", func() bool { return len(h.fs.Calls()) == 2 }); err != nil {
		t.Fatal(err)
	}
	if h.count(audit.CursorReset) != 1 {
		t.Fatalf("kinds = %v", h.kinds())
	}
	if got := h.fs.Calls()[1].Argv; got[len(got)-1] != "--lines=0" {
		t.Fatalf("argv = %v", got)
	}
	if s := h.slept(); len(s) != 0 {
		t.Fatalf("a reset must not back off: %v", s)
	}
	if c := h.savedCursor(); c != "" {
		t.Fatalf("cursor = %q, want cleared", c)
	}
}

// Each input of the reset decision on its own: the saved cursor, a line
// delivered before the failure, and the word "cursor" on stderr.
func TestCursorResetDecision(t *testing.T) {
	cases := []struct {
		name      string
		saved     string
		delivered int
		stderr    string
		want      bool
	}{
		{"cursor, no progress, stderr names it", cur("1"), 0, "Failed to seek to cursor: x", true},
		{"stderr in upper case", cur("1"), 0, "CURSOR invalid", true},
		{"cursor, no progress, other stderr", cur("1"), 0, "Failed to open journal", false},
		{"no saved cursor, stderr names it", "", 0, "Failed to seek to cursor: x", false},
		{"cursor, progress, stderr names it", cur("1"), 3, "Failed to seek to cursor: x", false},
		{"nothing set", "", 0, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			h.d.cur, h.d.saved, h.d.delivered = c.saved, c.saved, c.delivered
			reset, progress, err := h.d.streamEnded(execx.StreamResult{ExitCode: 1, Stderr: []byte(c.stderr)}, nil, c.saved)
			if err != nil || reset != c.want || progress != (c.delivered > 0) {
				t.Fatalf("reset=%v progress=%v err=%v, want reset=%v", reset, progress, err, c.want)
			}
		})
	}
}

func TestGracefulShutdownSavesCursorAndWritesStop(t *testing.T) {
	// A long cursor interval keeps the cursor of a non-signal line unsaved
	// until shutdown.
	h := newHarness(t, hopts{opt: Options{CursorInterval: time.Hour}})
	h.d.lastSave = h.clk.now() // within the interval
	h.script("", fake.Script{Follow: true, Lines: []string{plainLine(cur("1"), t0), plainLine(cur("2"), t0)}})
	var cursorDuring string
	err := h.runUntil("two lines", func() bool {
		h.d.mu.Lock()
		defer h.d.mu.Unlock()
		cursorDuring = h.savedCursor()
		return h.d.cur == cur("2")
	})
	if err != nil {
		t.Fatalf("Run = %v, want nil", err)
	}
	if cursorDuring != "" {
		t.Fatalf("cursor %q was saved before shutdown", cursorDuring)
	}
	if got := h.savedCursor(); got != cur("2") {
		t.Fatalf("cursor after shutdown = %q", got)
	}
	h.verify()
	k := h.kinds()
	if k[len(k)-1] != audit.DaemonStop {
		t.Fatalf("kinds = %v", k)
	}
}

// ---- redaction boundary ----

const hostileToken = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB"

func TestHostileLineNeverReachesStoreAuditOrNotifier(t *testing.T) {
	h := newHarness(t, hopts{})
	h.script("", fake.Script{Follow: true, Lines: []string{
		kernLine(cur("1"), t0, "Out of memory: Killed process 4242 ("+hostileToken+") total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:1kB oom_score_adj:0"),
	}})
	err := h.runUntil("notification and result audit", func() bool {
		return len(h.notif.sent()) == 1 && h.count(audit.NotifySent) == 1
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"incidents.json", audit.FileName} {
		if strings.Contains(h.file(f), hostileToken) {
			t.Errorf("%s holds the raw token", f)
		}
	}
	if !strings.Contains(h.file("incidents.json"), "[REDACTED]") {
		t.Errorf("incidents.json holds no redaction mark: %s", h.file("incidents.json"))
	}
	for _, m := range h.notif.sent() {
		if strings.Contains(m.Title+m.Body, hostileToken) || !strings.Contains(m.Body, "[REDACTED]") {
			t.Errorf("notification = %+v", m)
		}
	}
}

// Clean runs once per string that is persisted or sent: the subject and the
// summary of a signal reach it once each, and nothing is cleaned twice on the
// way to the store, the audit log and the message.
func TestCleanOncePerString(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	clean := func(s string) string {
		mu.Lock()
		calls[s]++
		mu.Unlock()
		return strings.ReplaceAll(s, "203.0.113.9", "ADDR")
	}
	h := newHarness(t, hopts{clean: clean})
	h.script("", fake.Script{Follow: true, Lines: []string{sshLine(cur("1"), t0, "203.0.113.9")}})
	if err := h.runUntil("notification", func() bool { return h.count(audit.NotifySent) == 1 }); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"ssh_brute_force: 203.0.113.9", "1 ssh login failure lines from 203.0.113.9 within 1m0s"} {
		if calls[want] != 1 {
			t.Errorf("Clean(%q) called %d times, want 1 (all: %v)", want, calls[want], calls)
		}
	}
	for s, n := range calls {
		if strings.Contains(s, "ADDR") {
			t.Errorf("cleaned text %q was cleaned again (%d)", s, n)
		}
	}
	if !strings.Contains(h.notif.sent()[0].Body, "ADDR") || strings.Contains(h.notif.sent()[0].Body, "203.0.113.9") {
		t.Errorf("body = %q", h.notif.sent()[0].Body)
	}
}

// The package has exactly one call of the clean function.
func TestOneCleanCallSite(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sites []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Clean" {
					sites = append(sites, fset.Position(c.Pos()).String())
				}
			}
			return true
		})
	}
	if len(sites) != 1 {
		t.Fatalf("Clean is called at %v, want one site", sites)
	}
}

// Incident records reach the audit log only through admit: no other call
// names an incident kind, and writeSig, which writes them, is called only by
// admit.
func TestIncidentRecordsOnlyThroughAdmit(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	incidentKinds := map[string]bool{"IncidentOpen": true, "IncidentUpdate": true, "IncidentReopen": true, "IncidentClose": true}
	writers := map[string]bool{"record": true, "appendRecord": true, "recordNoise": true, "noise": true, "noiseN": true}
	var bad []string
	writeSigCalls := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range af.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "writeSig" {
					writeSigCalls++
					if fn.Name.Name != "admit" {
						bad = append(bad, fset.Position(c.Pos()).String()+": writeSig outside admit")
					}
				}
				if !writers[sel.Sel.Name] {
					return true
				}
				for _, a := range c.Args {
					if k, ok := a.(*ast.SelectorExpr); ok && incidentKinds[k.Sel.Name] {
						bad = append(bad, fset.Position(c.Pos()).String()+": "+sel.Sel.Name+" with audit."+k.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if len(bad) > 0 || writeSigCalls == 0 {
		t.Fatalf("incident records outside admit: %v (writeSig calls %d)", bad, writeSigCalls)
	}
}
