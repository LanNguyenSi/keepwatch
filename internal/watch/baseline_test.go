package watch

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

const learningPeriod = time.Hour

func loginMsgLine(cursor string, at time.Time, msg string) string {
	return jline(cursor, at, map[string]string{
		"MESSAGE": msg, "_SYSTEMD_UNIT": "ssh.service",
		"_UID": "0", "_PID": "800", "_TRANSPORT": "syslog", "SYSLOG_IDENTIFIER": "sshd",
	})
}

func loginLine(cursor string, at time.Time, user, ip string) string {
	return loginMsgLine(cursor, at, "Accepted password for "+user+" from "+ip+" port 22 ssh2")
}

// openStateDir opens a second handle of the state directory, so a test can
// close it to make the baseline writes fail.
func openStateDir(t *testing.T, path string, ownerOf securefile.OwnerOf) *securefile.Dir {
	t.Helper()
	if ownerOf == nil {
		ownerOf = securefile.DefaultOwnerOf
	}
	d, err := securefile.OpenDir(path, true, ownerOf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// withBaseline loads a baseline store over the state directory of h at the
// harness clock and gives the daemon a login rule (and the brute force rule)
// over it.
func withBaseline(t *testing.T, h *harness, d *Daemon, dir *securefile.Dir) *BaselineStore {
	t.Helper()
	if dir == nil {
		dir = openStateDir(t, h.path, nil)
	}
	s := NewBaselineStore(dir)
	login, err := rules.NewLoginAnomaly(rules.LoginParams{LearningPeriod: learningPeriod}, s.Load(h.clk.now()))
	if err != nil {
		t.Fatal(err)
	}
	ssh, _ := rules.NewSSHBruteForce(rules.Params{Threshold: 1, Window: time.Minute})
	d.deps.Engine = rules.NewEngine(ssh, login)
	d.deps.Baseline = s
	return s
}

// restarted returns a second daemon over the same state as h (no worker), as
// a process started after h's daemon stopped.
func restarted(t *testing.T, h *harness) *Daemon {
	t.Helper()
	deps := h.d.deps
	deps.Worker = nil
	d, err := New(deps, h.d.opt)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// runDaemon runs d over the given steps (lines and funcs, see harness.steps)
// and stops it once they are done; it returns Run's result. A Run that ends
// by itself (a fatal error) returns at once.
func runDaemon(t *testing.T, h *harness, d *Daemon, items ...any) error {
	t.Helper()
	done := make(chan struct{})
	saved := h.d
	h.d = d
	h.steps(append(items, func() { close(done) })...)
	h.d = saved
	r := (&harness{t: t, d: d}).start()
	select {
	case <-done:
		return r.stop(t)
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func readBaseline(t *testing.T, h *harness) *rules.Baseline {
	t.Helper()
	b, err := rules.Unmarshal([]byte(h.file(BaselineFile)))
	if err != nil {
		t.Fatalf("baseline file: %v", err)
	}
	return b
}

func writeState(t *testing.T, h *harness, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.path, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func highLoginIncidents(h *harness, ip string) int {
	n := 0
	for _, in := range h.store.List() {
		if in.RuleID == rules.IDLoginAnomaly && in.Severity == result.High && strings.Contains(in.Title, ip) {
			n++
		}
	}
	return n
}

func TestBaselineRestartKeepsLearnedSource(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	withBaseline(t, h, h.d, nil)
	if err := runDaemon(t, h, h.d, loginLine(cur("1"), t0.Add(time.Minute), "alice", "10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	h.clk.add(3 * time.Hour)
	d2 := restarted(t, h)
	withBaseline(t, h, d2, nil)
	late := t0.Add(3 * time.Hour)
	if err := runDaemon(t, h, d2,
		loginLine(cur("2"), late, "alice", "10.0.0.1"),
		loginLine(cur("3"), late.Add(time.Second), "alice", "10.0.0.2")); err != nil {
		t.Fatal(err)
	}
	if n := highLoginIncidents(h, "10.0.0.1"); n != 0 {
		t.Fatalf("the learned source alerted after the restart (%d incidents)", n)
	}
	if n := highLoginIncidents(h, "10.0.0.2"); n != 1 {
		t.Fatalf("a new source after learning: %d high incidents, want 1", n)
	}
}

func TestBaselineLearningStartSavedOnFirstStart(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	withBaseline(t, h, h.d, nil)
	if err := runDaemon(t, h, h.d); err != nil {
		t.Fatal(err)
	}
	if got := readBaseline(t, h).LearningStart(); !got.Equal(t0) {
		t.Fatalf("saved learning start %v, want %v", got, t0)
	}
	h.clk.add(2 * time.Hour)
	s := NewBaselineStore(openStateDir(t, h.path, nil))
	if got := s.Load(h.clk.now()).LearningStart(); !got.Equal(t0) {
		t.Fatalf("a restart restarted learning: %v, want %v", got, t0)
	}
}

// A line that gives no signal but ends the learning phase saves the latch
// before the cursor moves: when the cursor save fails, the latch is on disk.
func TestBaselineLatchSavedBeforeCursor(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	withBaseline(t, h, h.d, nil)
	err := runDaemon(t, h, h.d,
		loginLine(cur("1"), t0.Add(time.Minute), "alice", "10.0.0.1"),
		func() { h.curDir.Close() },
		loginLine(cur("2"), t0.Add(2*time.Hour), "alice", "10.0.0.1"))
	if err == nil {
		t.Fatal("Run went on after a failed cursor save")
	}
	if got := h.savedCursor(); got != cur("1") {
		t.Fatalf("cursor %q, want %q", got, cur("1"))
	}
	if !readBaseline(t, h).LearningDone() {
		t.Fatal("the learning latch was not saved before the cursor")
	}
}

// The baseline is saved after the signals of a line were handled: a source
// whose incident could not be stored is not saved as known, so the replayed
// line alerts again.
func TestBaselineSavedAfterSignals(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	b := rules.NewBaseline(t0.Add(-2 * time.Hour))
	b.MarkLearningDone()
	data, _ := b.Marshal()
	writeState(t, h, BaselineFile, data)
	withBaseline(t, h, h.d, nil)
	err := runDaemon(t, h, h.d,
		func() { h.storeDir.Close() },
		loginLine(cur("1"), t0, "alice", "10.0.0.9"))
	if err == nil {
		t.Fatal("Run went on after a failed incident write")
	}
	if readBaseline(t, h).KnownIP("alice", "10.0.0.9") {
		t.Fatal("the source was saved as known before its signal was handled")
	}
}

func TestBaselineUntrustedContentResets(t *testing.T) {
	cases := map[string][]byte{
		"corrupt":        []byte(`{"schema_version":1,`),
		"unknown schema": []byte(`{"schema_version":2,"learning_start":"2025-10-09T12:00:00Z","learning_done":false,"users":[]}`),
		"empty":          {},
		"repeated user":  []byte(`{"schema_version":1,"learning_start":"2025-10-09T12:00:00Z","learning_done":false,"users":[{"user":"a","ips":[],"keys":[]},{"user":"a","ips":[],"keys":[]}]}`),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{})
			writeState(t, h, BaselineFile, bad)
			h.d.deps.Clean = func(s string) string { return "<" + s + ">" }
			s := withBaseline(t, h, h.d, nil)
			if !s.b.LearningStart().IsZero() {
				t.Fatalf("learning start %v, want the zero time", s.b.LearningStart())
			}
			h.steps()
			r := h.start()
			waitFor(t, "the reset notice", func() bool {
				for _, m := range h.notif.sent() {
					if strings.Contains(m.Title, "login baseline reset") {
						return true
					}
				}
				return false
			})
			if err := r.stop(t); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, rec := range h.records() {
				if rec.Kind == audit.InputError && strings.Contains(rec.Summary, "login baseline not trusted (<") {
					found = true
				}
			}
			if !found {
				t.Fatalf("no cleaned input_error record: %v", h.kinds())
			}
			if got := h.file(BaselineAsideFile); got != string(bad) {
				t.Fatalf("set aside %q, want %q", got, bad)
			}
			if b := readBaseline(t, h); !b.LearningStart().IsZero() {
				t.Fatalf("saved learning start %v, want the zero time", b.LearningStart())
			}
		})
	}
}

// At most one copy is kept: a second reset replaces the first copy.
func TestBaselineAsideKeepsOneCopy(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	writeState(t, h, BaselineFile, []byte("first"))
	withBaseline(t, h, h.d, nil)
	if err := runDaemon(t, h, h.d); err != nil {
		t.Fatal(err)
	}
	writeState(t, h, BaselineFile, []byte("second"))
	d2 := restarted(t, h)
	withBaseline(t, h, d2, nil)
	if err := runDaemon(t, h, d2); err != nil {
		t.Fatal(err)
	}
	if got := h.file(BaselineAsideFile); got != "second" {
		t.Fatalf("aside copy %q, want the second file", got)
	}
	entries, _ := os.ReadDir(h.path)
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), BaselineFile) {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("%d baseline files in the state directory, want the baseline and one copy", n)
	}
}

func TestBaselineTrustRefusalIsFatal(t *testing.T) {
	valid, _ := rules.NewBaseline(t0).Marshal()
	cases := map[string]struct {
		setup   func(t *testing.T, h *harness)
		ownerOf securefile.OwnerOf
	}{
		"group writable": {setup: func(t *testing.T, h *harness) {
			writeState(t, h, BaselineFile, valid)
			if err := os.Chmod(filepath.Join(h.path, BaselineFile), 0o620); err != nil {
				t.Fatal(err)
			}
		}},
		"symlink": {setup: func(t *testing.T, h *harness) {
			writeState(t, h, "other", valid)
			if err := os.Symlink("other", filepath.Join(h.path, BaselineFile)); err != nil {
				t.Fatal(err)
			}
		}},
		"directory": {setup: func(t *testing.T, h *harness) {
			if err := os.Mkdir(filepath.Join(h.path, BaselineFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		"foreign owner": {
			setup: func(t *testing.T, h *harness) { writeState(t, h, BaselineFile, valid) },
			ownerOf: func(fi fs.FileInfo) (int, error) {
				if fi.Name() == BaselineFile {
					return 4242, nil
				}
				return securefile.DefaultOwnerOf(fi)
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, hopts{noWorker: true})
			c.setup(t, h)
			h.d.deps.Clean = func(s string) string { return "<" + s + ">" }
			withBaseline(t, h, h.d, openStateDir(t, h.path, c.ownerOf))
			streamed := false
			err := runDaemon(t, h, h.d, func() { streamed = true })
			if !errors.Is(err, ErrBaselineLoad) {
				t.Fatalf("Run: %v, want ErrBaselineLoad", err)
			}
			if !strings.Contains(err.Error(), ": <") {
				t.Fatalf("error text not cleaned: %v", err)
			}
			if streamed {
				t.Fatal("the stream started")
			}
			if h.file(BaselineAsideFile) != "" {
				t.Fatal("a refused file was set aside")
			}
		})
	}
}

func TestBaselineNotLoadedIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	h.d.deps.Baseline = NewBaselineStore(h.dir)
	if err := runDaemon(t, h, h.d); !errors.Is(err, ErrBaselineLoad) {
		t.Fatalf("Run: %v, want ErrBaselineLoad", err)
	}
}

func TestBaselineSaveFailureAtStartIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	dir := openStateDir(t, h.path, nil)
	withBaseline(t, h, h.d, dir)
	dir.Close()
	err := runDaemon(t, h, h.d)
	if err == nil || !strings.Contains(err.Error(), "cannot save the login baseline") {
		t.Fatalf("Run: %v, want a save error", err)
	}
}

func TestBaselineSaveFailureOnLineIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	dir := openStateDir(t, h.path, nil)
	withBaseline(t, h, h.d, dir)
	err := runDaemon(t, h, h.d,
		plainLine(cur("1"), t0),
		func() { dir.Close() },
		loginLine(cur("2"), t0.Add(time.Minute), "alice", "10.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "cannot save the login baseline") {
		t.Fatalf("Run: %v, want a save error", err)
	}
	if got := h.savedCursor(); got != cur("1") {
		t.Fatalf("cursor %q moved past the line whose baseline save failed", got)
	}
}

// padded returns a valid baseline document padded with trailing blanks to n
// bytes (JSON allows them).
func padded(t *testing.T, n int) []byte {
	t.Helper()
	b := rules.NewBaseline(t0)
	b.AddIP("alice", "10.0.0.1")
	data, _ := b.Marshal()
	if len(data) > n {
		t.Fatal("document longer than the padding target")
	}
	return append(data, bytes.Repeat([]byte(" "), n-len(data))...)
}

func TestBaselineSizeBound(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	writeState(t, h, BaselineFile, padded(t, MaxBaselineBytes))
	s := NewBaselineStore(openStateDir(t, h.path, nil))
	if b := s.Load(t0.Add(time.Hour)); s.resetErr != nil || !b.LearningStart().Equal(t0) || !b.KnownIP("alice", "10.0.0.1") {
		t.Fatalf("a document at the bound did not load: %v", s.resetErr)
	}

	writeState(t, h, BaselineFile, padded(t, MaxBaselineBytes+1))
	s = NewBaselineStore(openStateDir(t, h.path, nil))
	b := s.Load(t0.Add(time.Hour))
	if !errors.Is(s.resetErr, securefile.ErrTooLarge) {
		t.Fatalf("an oversized file was not refused before decoding: %v", s.resetErr)
	}
	if !b.LearningStart().IsZero() || b.KnownIP("alice", "10.0.0.1") {
		t.Fatal("an oversized file was trusted")
	}
}

// A document at the caps of the rules package (every user name as long as
// allowed and doubled by escaping, every entry as long as allowed) loads.
func TestBaselineDocumentAtRulesCapsLoads(t *testing.T) {
	b := rules.NewBaseline(t0)
	for u := 0; u < rules.BaselineMaxUsers; u++ {
		name := make([]byte, 64)
		for i := range name {
			name[i] = '"'
			if i < 8 && u&(1<<i) != 0 {
				name[i] = '\\'
			}
		}
		for k := 0; k < rules.BaselineEntriesPerUser; k++ {
			if !b.AddKey(string(name), fmt.Sprintf("%064d", k)) {
				t.Fatalf("add refused for user %d key %d", u, k)
			}
		}
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > MaxBaselineBytes {
		t.Fatalf("a document at the rules caps is %d bytes, over the bound %d", len(data), MaxBaselineBytes)
	}
	h := newHarness(t, hopts{noWorker: true})
	writeState(t, h, BaselineFile, data)
	s := NewBaselineStore(openStateDir(t, h.path, nil))
	got := s.Load(t0.Add(time.Hour))
	if s.resetErr != nil || s.loadErr != nil || !got.LearningStart().Equal(t0) {
		t.Fatalf("the document did not load: %v %v", s.resetErr, s.loadErr)
	}
	t.Logf("document at the caps: %d bytes, bound %d", len(data), MaxBaselineBytes)
}

const ambiguousLogin = "Accepted publickey for bob from 10.0.0.5 port 1 ssh2: x from 10.0.0.6 port 2 ssh2"

// Lines that cannot change the baseline cost no Marshal; lines that may (a
// login signal, the latch) do, and only a changed baseline is written.
func TestBaselineChangeDetectionCost(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	s := withBaseline(t, h, h.d, nil)
	at := t0.Add(time.Minute)
	items := []any{loginLine(cur("1"), at, "alice", "10.0.0.1")}
	n := 2
	next := func() string { n++; return cur(fmt.Sprint(n - 1)) }
	type obs struct{ marshals, writes, wantM, wantW int }
	var seen []obs
	mark := func(wantM, wantW int) {
		items = append(items, func() { seen = append(seen, obs{s.marshals, s.writes, wantM, wantW}) })
	}
	// The start save and the learned source.
	mark(2, 2)
	for i := 0; i < 50; i++ {
		items = append(items,
			plainLine(next(), at),
			sshLine(next(), at, fmt.Sprintf("203.0.113.%d", i)),
			loginLine(next(), at, "alice", "10.0.0.1"))
	}
	mark(2, 2)
	// A login signal that learns nothing: a Marshal, no write.
	items = append(items, loginMsgLine(next(), at, ambiguousLogin))
	mark(3, 2)
	// A known source past learning flips the latch without a signal.
	items = append(items, loginLine(next(), t0.Add(2*time.Hour), "alice", "10.0.0.1"))
	mark(4, 3)
	for i := 0; i < 20; i++ {
		items = append(items, loginLine(next(), t0.Add(2*time.Hour), "alice", "10.0.0.1"))
	}
	mark(4, 3)
	if err := runDaemon(t, h, h.d, items...); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("%d observations, want 5", len(seen))
	}
	for i, o := range seen {
		if o.marshals != o.wantM || o.writes != o.wantW {
			t.Errorf("step %d: %d marshals and %d writes, want %d and %d", i, o.marshals, o.writes, o.wantM, o.wantW)
		}
	}
	if !readBaseline(t, h).LearningDone() {
		t.Fatal("the latch was not saved")
	}
}

// The change detection relies on the login rule changing its baseline only
// in an Evaluate that returns a login signal, or by flipping the learning
// latch. This pins that contract over the kinds of login lines.
func TestLoginRuleChangesBaselineOnlyWithSignalOrLatch(t *testing.T) {
	b := rules.NewBaseline(t0)
	login, _ := rules.NewLoginAnomaly(rules.LoginParams{LearningPeriod: learningPeriod, KnownKeys: map[string][]string{"carol": {"SHA256:" + strings.Repeat("A", 43)}}}, b)
	key := func(i int) string { return fmt.Sprintf("SHA256:%043d", i) }
	type line struct {
		at  time.Time
		msg string
		uid int
	}
	var lines []line
	add := func(at time.Time, msg string) { lines = append(lines, line{at, msg, 0}) }
	in, late := t0.Add(time.Minute), t0.Add(2*time.Hour)
	add(in, "Accepted password for alice from 10.0.0.1 port 22 ssh2")
	add(in, "Accepted password for alice from 10.0.0.1 port 22 ssh2")
	add(in, "Accepted publickey for alice from 10.0.0.1 port 22 ssh2: ED25519 "+key(1))
	add(in, "Accepted publickey for carol from 10.0.0.3 port 22 ssh2: ED25519 SHA256:"+strings.Repeat("A", 43))
	add(in, ambiguousLogin)
	add(in, "Accepted password for alice from ::ffff:10.0.0.1 port 22 ssh2")
	add(in, "Accepted password for alice from not-an-ip port 22 ssh2")
	for i := 0; i < rules.BaselineEntriesPerUser+3; i++ {
		add(in, fmt.Sprintf("Accepted publickey for dave from 10.0.0.4 port 22 ssh2: RSA %s", key(i)))
	}
	add(late, "Accepted password for alice from 10.0.0.1 port 22 ssh2")
	add(late, "Accepted password for alice from 10.0.0.2 port 22 ssh2")
	add(in, "Accepted password for erin from 10.0.0.7 port 22 ssh2")
	lines = append(lines, line{late, "Accepted password for mallory from 10.9.9.9 port 22 ssh2", 1000})
	prev, _ := b.Marshal()
	prevDone := b.LearningDone()
	for i, l := range lines {
		sigs := login.Evaluate(event.Event{Kind: event.KindJournal, SystemdUnit: "ssh.service", UID: l.uid, Message: l.msg, Time: l.at}, l.at)
		cur, _ := b.Marshal()
		signalled := false
		for _, s := range sigs {
			signalled = signalled || s.RuleID == rules.IDLoginAnomaly
		}
		if !bytes.Equal(cur, prev) && !signalled && b.LearningDone() == prevDone {
			t.Fatalf("line %d (%q) changed the baseline without a signal or the latch", i, l.msg)
		}
		prev, prevDone = cur, b.LearningDone()
	}
	if !prevDone {
		t.Fatal("the lines never reached the end of the learning phase")
	}
}

// A loaded baseline that does not change is not written again.
func TestBaselineLoadedUnchangedNotRewritten(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	b := rules.NewBaseline(t0.Add(-2 * time.Hour))
	b.MarkLearningDone()
	data, _ := b.Marshal()
	writeState(t, h, BaselineFile, data)
	s := withBaseline(t, h, h.d, nil)
	if err := runDaemon(t, h, h.d, loginMsgLine(cur("1"), t0, ambiguousLogin)); err != nil {
		t.Fatal(err)
	}
	if s.marshals != 1 || s.writes != 0 {
		t.Fatalf("%d marshals and %d writes, want 1 and 0", s.marshals, s.writes)
	}
}

func inputErrorCount(h *harness) int { return h.count(audit.InputError) }

// A reset whose save fails stops the start, leaves the untrusted file in
// place with its copy and its record, and the next start completes it.
func TestBaselineResetSaveFailure(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	bad := []byte("garbage")
	writeState(t, h, BaselineFile, bad)
	dir := openStateDir(t, h.path, nil)
	withBaseline(t, h, h.d, dir)
	// The reason is cleaned after the copy was made and before the record
	// and the save: closing the store's handle there makes the save fail.
	clean := h.d.deps.Clean
	h.d.deps.Clean = func(s string) string {
		if strings.Contains(s, "corrupt baseline") {
			dir.Close()
		}
		return clean(s)
	}
	err := runDaemon(t, h, h.d)
	if err == nil || !strings.Contains(err.Error(), "cannot save the login baseline") {
		t.Fatalf("Run: %v, want the save error", err)
	}
	if got := h.file(BaselineFile); got != string(bad) {
		t.Fatalf("baseline file %q after the failed reset, want the untrusted bytes", got)
	}
	if got := h.file(BaselineAsideFile); got != string(bad) {
		t.Fatalf("aside copy %q, want the untrusted bytes", got)
	}
	if n := inputErrorCount(h); n != 1 {
		t.Fatalf("%d input_error records, want 1", n)
	}
	d2 := restarted(t, h)
	withBaseline(t, h, d2, nil)
	if err := runDaemon(t, h, d2); err != nil {
		t.Fatal(err)
	}
	if b := readBaseline(t, h); !b.LearningStart().IsZero() {
		t.Fatalf("learning start %v after the completed reset, want the zero time", b.LearningStart())
	}
	if got := h.file(BaselineAsideFile); got != string(bad) {
		t.Fatalf("aside copy %q, want the untrusted bytes", got)
	}
	if n := inputErrorCount(h); n != 2 {
		t.Fatalf("%d input_error records, want 2", n)
	}
}

// A set-aside that fails stops the start with a cleaned error, before the
// stream starts, and leaves the untrusted file as it is.
func TestBaselineSetAsideFailureIsFatal(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	bad := []byte("garbage")
	writeState(t, h, BaselineFile, bad)
	if err := os.MkdirAll(filepath.Join(h.path, BaselineAsideFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	h.d.deps.Clean = func(s string) string { return "<" + s + ">" }
	withBaseline(t, h, h.d, nil)
	streamed := false
	err := runDaemon(t, h, h.d, func() { streamed = true })
	if !errors.Is(err, ErrBaselineLoad) || !strings.Contains(err.Error(), "aside: <") {
		t.Fatalf("Run: %v, want a cleaned ErrBaselineLoad", err)
	}
	if streamed {
		t.Fatal("the stream started")
	}
	if got := h.file(BaselineFile); got != string(bad) {
		t.Fatalf("baseline file %q, want the untrusted bytes", got)
	}
	if n := inputErrorCount(h); n != 0 {
		t.Fatalf("%d input_error records, want none", n)
	}
}

// When the state directory's path no longer names the directory the store
// holds, the reset still works in the held directory: the copy is made there,
// and the directory now at the path is not touched.
func TestBaselineAsideUsesHeldDirectory(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	bad := []byte("garbage")
	writeState(t, h, BaselineFile, bad)
	withBaseline(t, h, h.d, nil)
	moved := h.path + "-moved"
	if err := os.Rename(h.path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.path, 0o700); err != nil {
		t.Fatal(err)
	}
	writeState(t, h, BaselineFile, []byte("decoy"))
	writeState(t, h, BaselineAsideFile, []byte("decoy copy"))
	if err := runDaemon(t, h, h.d); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, rerr := os.ReadFile(filepath.Join(moved, BaselineAsideFile))
	if rerr != nil || string(got) != string(bad) {
		t.Fatalf("aside copy in the held directory: %q %v, want the untrusted bytes", got, rerr)
	}
	if got := h.file(BaselineFile); got != "decoy" {
		t.Fatalf("decoy baseline %q, want it untouched", got)
	}
	if got := h.file(BaselineAsideFile); got != "decoy copy" {
		t.Fatalf("decoy copy %q, want it untouched", got)
	}
	entries, err := os.ReadDir(h.path)
	if err != nil || len(entries) != 2 {
		t.Fatalf("decoy directory has %d entries (%v), want 2", len(entries), err)
	}
}

// An oversized file goes through the whole reset: its copy is larger than the
// read bound and is still made.
func TestBaselineOversizedFileReset(t *testing.T) {
	h := newHarness(t, hopts{noWorker: true})
	writeState(t, h, BaselineFile, padded(t, MaxBaselineBytes+1))
	withBaseline(t, h, h.d, nil)
	if err := runDaemon(t, h, h.d); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(h.file(BaselineAsideFile)); n != MaxBaselineBytes+1 {
		t.Fatalf("aside copy of %d bytes, want %d", n, MaxBaselineBytes+1)
	}
	if b := readBaseline(t, h); !b.LearningStart().IsZero() {
		t.Fatalf("learning start %v, want the zero time", b.LearningStart())
	}
	if n := inputErrorCount(h); n != 1 {
		t.Fatalf("%d input_error records, want 1", n)
	}
}
