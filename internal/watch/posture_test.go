package watch

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/posture"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// postureFake is a posture source that returns what the test queues for each
// poll; a poll with nothing queued returns nothing.
type postureFake struct {
	mu    sync.Mutex
	polls []postureReply
	times []time.Time
}

type postureReply struct {
	sigs []event.Signal
	err  error
}

func (p *postureFake) Poll(now time.Time) ([]event.Signal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.times = append(p.times, now)
	if len(p.polls) == 0 {
		return nil, nil
	}
	r := p.polls[0]
	p.polls = p.polls[1:]
	return r.sigs, r.err
}

func (p *postureFake) push(sigs []event.Signal, err error) {
	p.mu.Lock()
	p.polls = append(p.polls, postureReply{sigs, err})
	p.mu.Unlock()
}

// hostileSig is a posture signal as a hostile source could return it: it
// claims another rule and wants a notification.
func hostileSig(key string, sev result.Severity) event.Signal {
	return event.Signal{
		RuleID: "ssh_brute_force", Fingerprint: event.FingerprintOf(posture.RuleID, key),
		Severity: sev, Time: t0, Notify: true, Subject: "check " + key, Summary: "check " + key + ": new",
	}
}

func postureSigs(prefix string, n int, sev result.Severity) []event.Signal {
	out := make([]event.Signal, n)
	for i := range out {
		out[i] = hostileSig(fmt.Sprintf("%s-%d", prefix, i), sev)
	}
	return out
}

func withPosture(h *harness) *postureFake {
	src := &postureFake{}
	h.d.deps.Posture = src
	return src
}

// No posture signal reaches the notifier, whatever the source claims: not
// when it opens, updates (pending), reopens or is refused by a full store,
// and not in the housekeeping retry.
func TestPostureSignalsNeverNotify(t *testing.T) {
	h := newHarness(t, hopts{setup: func(h *harness) {
		// One place left, the rest more severe than any posture signal here.
		writeIncidents(t, h, incident.MaxIncidents-1, result.Critical, t0)
	}})
	src := withPosture(h)
	h.script("", fake.Script{Follow: true})
	r := h.start()
	waitFor(t, "start", func() bool { return len(h.fs.Calls()) == 1 })
	a := hostileSig("a", result.High)
	src.push([]event.Signal{a}, nil) // open
	housekeepOnce(t, h)
	src.push([]event.Signal{a}, nil) // update of an unnotified incident
	housekeepOnce(t, h)
	h.d.mu.Lock()
	var id string
	for _, in := range h.store.List() {
		if in.Fingerprint == a.Fingerprint {
			id = in.ID
		}
	}
	if _, err := h.store.Close(id); err != nil {
		t.Error(err)
	}
	h.d.mu.Unlock()
	src.push([]event.Signal{a}, nil) // reopen
	housekeepOnce(t, h)
	src.push([]event.Signal{hostileSig("b", result.Low)}, nil) // refused: the store is full
	housekeepOnce(t, h)
	h.clk.add(3 * time.Hour)
	housekeepOnce(t, h) // the retry of unnotified incidents
	h.d.mu.Lock()
	attempts, inflight, tries := len(h.d.attempts), h.d.inflightTotal, len(h.d.tries)
	h.d.mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || inflight != 0 || tries != 0 || len(h.notif.sent()) != 0 {
		t.Fatalf("attempts = %d, in flight = %d, tries = %d, sends = %d: a posture signal was handed to the notifier", attempts, inflight, tries, len(h.notif.sent()))
	}
	for _, k := range []audit.Kind{audit.NotifySent, audit.NotifyFailed, audit.NotifyDropped} {
		if n := h.count(k); n != 0 {
			t.Errorf("%s records = %d", k, n)
		}
	}
	// Every path was taken.
	if h.count(audit.IncidentOpen) != 1 || h.count(audit.IncidentUpdate) != 1 || h.count(audit.IncidentReopen) != 1 {
		t.Errorf("kinds = %v", h.kinds())
	}
	full := false
	for _, rec := range h.records() {
		full = full || strings.Contains(rec.Summary, "a signal was refused")
	}
	if !full {
		t.Errorf("the refused path was not taken: %v", h.kinds())
	}
	in, ok := h.store.Get(id)
	if !ok || in.RuleID != posture.RuleID || in.Notify || in.State != incident.StateOpen {
		t.Fatalf("posture incident = %+v", in)
	}
}

// The pass polls with the daemon clock.
func TestPosturePollUsesTheDaemonClock(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	src := withPosture(h)
	h.clk.add(time.Hour)
	housekeepOnce(t, h)
	if len(src.times) != 1 || !src.times[0].Equal(t0.Add(time.Hour)) {
		t.Fatalf("poll times = %v", src.times)
	}
}

const hostileText = "\x1b[31m" + hostileToken + "\nsecond line"

// Posture text is cleaned again on the way in: the state file is input.
func TestHostilePostureTextIsCleaned(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	src := withPosture(h)
	sig := hostileSig("x", result.High)
	sig.Subject, sig.Summary = "subject "+hostileText, "summary "+hostileText
	src.push([]event.Signal{sig}, nil)
	housekeepOnce(t, h)
	in := h.store.List()
	if len(in) != 1 {
		t.Fatalf("incidents = %+v", in)
	}
	var texts []string
	texts = append(texts, in[0].Title, in[0].Summary)
	for _, rec := range h.records() {
		texts = append(texts, rec.Summary)
	}
	for _, s := range texts {
		if strings.ContainsAny(s, "\x1b\n") || strings.Contains(s, hostileToken) {
			t.Errorf("uncleaned text %q", s)
		}
	}
	if !strings.Contains(in[0].Title, "[REDACTED]") || !strings.Contains(in[0].Summary, `\x1b`) {
		t.Errorf("incident = %+v", in[0])
	}
}

// Cleaning text that was cleaned before changes nothing, so the second clean
// of posture text keeps what the state file shows.
func TestCleanIsIdempotentOnItsOutput(t *testing.T) {
	clean := redact.Default().Clean
	for _, raw := range []string{
		"", "plain text", "sshd_config: weak_cipher aes128-cbc", hostileText,
		"password=hunter2 token " + hostileToken, "tab\there\r\n", "bad utf8 \xff\xfe",
		"zero\u200bwidth \u202e rtl", strings.Repeat("long ", 2000), `already \x1b escaped [REDACTED]`,
	} {
		once := clean(raw)
		if twice := clean(once); twice != once {
			t.Errorf("Clean(%q): once %q, twice %q", raw, once, twice)
		}
	}
}

// A flood is handled posturePerPass signals per pass; what does not fit the
// queue is counted, not dropped silently.
func TestPostureFloodIsCappedQueuedAndCounted(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	src := withPosture(h)
	const over = 100
	src.push(postureSigs("f", postureQueueMax+over, result.Low), nil)
	housekeepOnce(t, h)
	h.d.mu.Lock()
	queued := len(h.d.postureQueue)
	h.d.mu.Unlock()
	if n := len(h.store.List()); n != posturePerPass || queued != postureQueueMax-posturePerPass {
		t.Fatalf("after one pass: %d incidents, %d queued", n, queued)
	}
	housekeepOnce(t, h)
	if n := len(h.store.List()); n != 2*posturePerPass {
		t.Fatalf("after two passes: %d incidents", n)
	}
	h.d.mu.Lock()
	err := h.d.flushNoise(true)
	h.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	const drop = "a posture signal was dropped because the posture queue was full"
	var got []string
	for _, rec := range h.records() {
		if strings.Contains(rec.Summary, drop) {
			got = append(got, rec.Summary)
		}
	}
	if len(got) != 2 || got[0] != drop || got[1] != fmt.Sprintf("%d more within 1m0s: %s", over-1, drop) {
		t.Fatalf("drop records = %q", got)
	}
	// The queue keeps the order of the source: the first signals went first.
	want := map[event.Fingerprint]bool{}
	for _, s := range postureSigs("f", 2*posturePerPass, result.Low) {
		want[s.Fingerprint] = true
	}
	for _, in := range h.store.List() {
		if !want[in.Fingerprint] {
			t.Fatalf("incident %s is not one of the first signals", in.Title)
		}
	}
}

// A poll error is audited through the noise path, cleaned, and the queue is
// still worked on.
func TestPosturePollErrorsAreRateLimitedAndCleaned(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	src := withPosture(h)
	src.push(postureSigs("q", posturePerPass+5, result.Low), nil)
	for i := 0; i < 3; i++ {
		src.push(nil, errors.New("posture: state not usable: "+hostileText))
	}
	for i := 0; i < 4; i++ {
		housekeepOnce(t, h)
	}
	if n := len(h.store.List()); n != posturePerPass+5 {
		t.Fatalf("incidents = %d, the queue was not worked on after the error", n)
	}
	h.d.mu.Lock()
	err := h.d.flushNoise(true)
	h.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, rec := range h.records() {
		if strings.Contains(rec.Summary, "cannot read the posture state") {
			got = append(got, rec.Summary)
			if rec.Kind != audit.InputError || strings.ContainsAny(rec.Summary, "\x1b\n") || strings.Contains(rec.Summary, hostileToken) {
				t.Errorf("record = %+v", rec)
			}
		}
	}
	if len(got) != 2 || !strings.HasPrefix(got[1], "2 more within 1m0s: ") {
		t.Fatalf("poll error records = %q", got)
	}
}

// A posture flood does not push out more severe incidents: the store refuses
// a signal whose eviction candidate is open (or acked) and more severe.
func TestPostureFloodKeepsMoreSevereIncidents(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true, setup: func(h *harness) {
		writeIncidents(t, h, incident.MaxIncidents, result.High, t0)
	}})
	src := withPosture(h)
	for i := 0; i < 3; i++ {
		src.push(postureSigs(fmt.Sprintf("m%d", i), 3*posturePerPass, result.Medium), nil)
		housekeepOnce(t, h)
	}
	list := h.store.List()
	for _, in := range list {
		if in.RuleID != "seed" {
			t.Fatalf("a posture incident took a place: %+v", in)
		}
	}
	if len(list) != incident.MaxIncidents || h.count(audit.IncidentClose) != 0 {
		t.Fatalf("incidents = %d, closes = %d", len(list), h.count(audit.IncidentClose))
	}
	// Less severe incidents do make room.
	h2 := newHarness(t, hopts{noWorker: true, setup: func(h *harness) {
		writeIncidents(t, h, incident.MaxIncidents, result.Low, t0)
	}})
	src2 := withPosture(h2)
	src2.push(postureSigs("m", posturePerPass, result.Medium), nil)
	housekeepOnce(t, h2)
	n := 0
	for _, in := range h2.store.List() {
		if in.RuleID == posture.RuleID {
			n++
		}
	}
	if n != posturePerPass {
		t.Fatalf("posture incidents = %d, want %d", n, posturePerPass)
	}
}

// Posture records go through the budget of rule "posture": a posture flood
// leaves a journal rule's records alone and is counted as the posture rule.
func TestPostureFloodUsesTheBudgetOfThePostureRule(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	src := withPosture(h)
	for i := 0; i < 3; i++ {
		src.push(postureSigs(fmt.Sprintf("b%d", i), posturePerPass, result.Low), nil)
		housekeepOnce(t, h)
	}
	h.steps(sshLine(cur("1"), t0, "203.0.113.1"))
	if err := h.runUntil("line", func() bool { return h.savedCursor() == cur("1") }); err != nil {
		t.Fatal(err)
	}
	opens, counted := 0, false
	for _, rec := range h.records() {
		if rec.Kind == audit.IncidentOpen {
			opens++
		}
		counted = counted || rec.Summary == fmt.Sprintf("%d more within 1m0s: %s", 2*DefaultAuditBudget, (&Daemon{}).aggText(posture.RuleID))
	}
	if opens != DefaultAuditBudget+1 || !counted {
		t.Fatalf("incident_open records = %d, posture count record = %v: %v", opens, counted, h.kinds())
	}
}

// Without a source the pass does nothing.
func TestNilPostureSourceIsOff(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	housekeepOnce(t, h)
	if len(h.records()) != 0 || len(h.store.List()) != 0 {
		t.Fatalf("records = %v", h.kinds())
	}
}

// rateLimitedKeys is the number of keys of the noise path the package
// comment counts: the literal keys below and one notify_dropped key per
// drop reason.
const rateLimitedKeys = 19

// The keys of the noise path are the ones the package comment counts.
func TestRateLimitedKeysAreCounted(t *testing.T) {
	want := []string{
		"audit_refused", "clock_clamp", "incident_full", "journal_gap", "journal_line_invalid", "line_too_long",
		"posture_overflow", "posture_poll", "requests_pending", "requests_sweep", "results_lost", "signal_invalid",
		"stream_restart",
	}
	reasons := []alert.DropReason{alert.DropQueueFull, alert.DropIncident, alert.DropGlobal, alert.DropShutdown, alert.DropWorkerEnded, alert.DropInvalid}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	var prefixes []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "noise" && sel.Sel.Name != "noiseN") {
				return true
			}
			switch a := c.Args[0].(type) {
			case *ast.BasicLit:
				s, _ := strconv.Unquote(a.Value)
				keys[s] = true
			case *ast.BinaryExpr:
				lit, ok := a.X.(*ast.BasicLit)
				if !ok {
					t.Errorf("%s: a noise key that is not a literal", fset.Position(c.Pos()))
					return true
				}
				s, _ := strconv.Unquote(lit.Value)
				prefixes = append(prefixes, s)
			case *ast.Ident:
				// noise passes its own key on to noiseN.
			default:
				t.Errorf("%s: a noise key that is not a literal", fset.Position(c.Pos()))
			}
			return true
		})
	}
	var got []string
	for k := range keys {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("literal noise keys = %v, want %v", got, want)
	}
	for _, p := range prefixes {
		if p != "notify_dropped:" {
			t.Errorf("noise key prefix %q", p)
		}
	}
	if len(want)+len(reasons) != rateLimitedKeys {
		t.Fatalf("%d keys, the package comment counts %d", len(want)+len(reasons), rateLimitedKeys)
	}
}

// A fatal error of the posture pass (a store that cannot save, a full audit
// log) ends the housekeeping pass with that error.
func TestPosturePassFatalErrorsEndThePass(t *testing.T) {
	t.Run("store", func(t *testing.T) {
		h := newHarness(t, hopts{noWorker: true})
		src := withPosture(h)
		src.push(postureSigs("s", 1, result.Low), nil)
		h.storeDir.Close()
		h.d.mu.Lock()
		err := h.d.housekeep()
		h.d.mu.Unlock()
		if err == nil || !strings.Contains(err.Error(), "incident store") {
			t.Fatalf("housekeep = %v, want the store error", err)
		}
	})
	t.Run("overflow record with a full audit log", func(t *testing.T) {
		// Invalid signals open the signal_invalid window in the first pass,
		// so in the second the overflow record is the only write.
		invalid := func(n int) []event.Signal {
			out := postureSigs("i", n, result.Low)
			for i := range out {
				out[i].Fingerprint = "not hex"
			}
			return out
		}
		pass := func(h *harness) error {
			h.d.mu.Lock()
			defer h.d.mu.Unlock()
			return h.d.housekeep()
		}
		probe := newHarness(t, hopts{noWorker: true})
		withPosture(probe).push(invalid(1), nil)
		if err := pass(probe); err != nil {
			t.Fatal(err)
		}
		first := lineSizes(probe)[0]
		h := newHarness(t, hopts{noWorker: true, auditMax: audit.ReserveBytes + first + 10})
		src := withPosture(h)
		src.push(invalid(1), nil)
		if err := pass(h); err != nil {
			t.Fatal(err)
		}
		h.clk.add(DefaultHousekeepingInterval)
		src.push(invalid(postureQueueMax+1), nil)
		if err := pass(h); !errors.Is(err, ErrAuditFull) {
			t.Fatalf("housekeep = %v, want ErrAuditFull", err)
		}
	})
	t.Run("poll error with a full audit log", func(t *testing.T) {
		h := newHarness(t, hopts{noWorker: true, auditMax: audit.ReserveBytes + 10})
		src := withPosture(h)
		src.push(nil, errors.New("posture: unreadable"))
		h.d.mu.Lock()
		err := h.d.housekeep()
		h.d.mu.Unlock()
		if !errors.Is(err, ErrAuditFull) {
			t.Fatalf("housekeep = %v, want ErrAuditFull", err)
		}
	})
}
