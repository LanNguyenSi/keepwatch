package watch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

var t0 = time.Date(2025, 10, 9, 12, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeNotifier struct {
	mu   sync.Mutex
	msgs []notify.Message
	fail func(n int) error
}

func (f *fakeNotifier) Send(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, m)
	if f.fail != nil {
		return f.fail(len(f.msgs))
	}
	return nil
}

func (f *fakeNotifier) sent() []notify.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notify.Message(nil), f.msgs...)
}

var errTransient = &notify.Error{Class: notify.Transient, Status: 503, Msg: "server error"}

type hopts struct {
	noWorker bool
	params   alert.Params
	opt      Options
	store    []incident.Option
	recovery *audit.Recovery
	auditMax int64
	clean    func(string) string
	reqs     *RequestOps
	// beforeOpen runs after the state directory exists.
	setup func(h *harness)
}

type harness struct {
	t      *testing.T
	path   string
	dir    *securefile.Dir
	clk    *fakeClock
	fs     *fake.FakeStreamer
	notif  *fakeNotifier
	worker *alert.Worker
	store  *incident.Store
	aw     *audit.Writer
	d      *Daemon
	cursor *CursorStore

	mu     sync.Mutex
	sleeps []time.Duration
}

func args(cursor string) []string {
	a := []string{"journalctl", "--output=json", "--follow", "--no-pager"}
	if cursor == "" {
		return append(a, "--lines=0")
	}
	return append(a, "--after-cursor="+cursor)
}

func newHarness(t *testing.T, o hopts) *harness {
	t.Helper()
	h := &harness{t: t, clk: &fakeClock{t: t0}, fs: fake.NewStreamer(), notif: &fakeNotifier{}}
	h.path = filepath.Join(t.TempDir(), "state")
	dir, err := securefile.OpenDir(h.path, true, securefile.DefaultOwnerOf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	h.dir = dir
	h.cursor = NewCursorStore(dir)
	if o.setup != nil {
		o.setup(h)
	}
	h.store, err = incident.Open(dir, o.store...)
	if err != nil {
		t.Fatal(err)
	}
	aw, rec, err := audit.Open(dir, audit.Options{MaxSize: o.auditMax, Now: h.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aw.Close() })
	h.aw = aw
	if rec != nil && o.recovery == nil {
		o.recovery = rec
	}
	ssh, _ := rules.NewSSHBruteForce(rules.Params{Threshold: 1, Window: time.Minute})
	restart, _ := rules.NewRestartLoop(rules.Params{Threshold: 100, Window: time.Minute})
	oom, _ := rules.NewOOMKill(rules.OOMParams{Window: 10 * time.Minute})
	deps := Deps{
		Streamer: h.fs, Clock: h.clk.now, Clean: o.clean, Engine: rules.NewEngine(ssh, restart, oom),
		Incidents: h.store, Audit: aw, Cursor: h.cursor, Recovery: o.recovery, Requests: o.reqs,
	}
	if deps.Clean == nil {
		deps.Clean = redact.Default().Clean
	}
	if !o.noWorker {
		p := o.params
		if p.QueueSize == 0 {
			p = alert.Params{QueueSize: 16, PerIncidentInterval: 40 * time.Minute}
		}
		w, err := alert.NewWorker(h.notif, p, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.Clock = h.clk.now
		deps.Worker, h.worker = w, w
	}
	opt := o.opt
	if opt.PerIncidentInterval == 0 {
		opt.PerIncidentInterval = 40 * time.Minute
	}
	if opt.CursorInterval == 0 {
		opt.CursorInterval = -1
	}
	if opt.Sleep == nil {
		opt.Sleep = func(_ context.Context, d time.Duration) error {
			h.mu.Lock()
			h.sleeps = append(h.sleeps, d)
			h.mu.Unlock()
			return nil
		}
	}
	d, err := New(deps, opt)
	if err != nil {
		t.Fatal(err)
	}
	h.d = d
	return h
}

func (h *harness) slept() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

// running is a Run in a goroutine.
type running struct {
	cancel context.CancelFunc
	done   chan error
}

func (h *harness) start() *running {
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- h.d.Run(ctx) }()
	h.t.Cleanup(cancel)
	return r
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	return r.wait(t)
}

func (r *running) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// run runs the daemon until the scripted lines are handled (the script must
// end in Follow) and cond holds, then stops it.
func (h *harness) runUntil(what string, cond func() bool) error {
	r := h.start()
	waitFor(h.t, what, cond)
	return r.stop(h.t)
}

func (h *harness) file(name string) string {
	b, err := os.ReadFile(filepath.Join(h.path, name))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *harness) savedCursor() string { return strings.TrimSpace(h.file(CursorFile)) }

func (h *harness) records() []audit.Record {
	h.t.Helper()
	f, err := os.Open(filepath.Join(h.path, audit.FileName))
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Record
	if err := audit.Show(f, audit.Filter{}, func(r audit.Record) error { out = append(out, r); return nil }); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *harness) kinds() []audit.Kind {
	var k []audit.Kind
	for _, r := range h.records() {
		k = append(k, r.Kind)
	}
	return k
}

func (h *harness) count(k audit.Kind) int {
	n := 0
	for _, r := range h.records() {
		if r.Kind == k {
			n++
		}
	}
	return n
}

func (h *harness) verify() {
	h.t.Helper()
	f, err := os.Open(filepath.Join(h.path, audit.FileName))
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	if _, err := audit.Verify(f); err != nil {
		h.t.Fatalf("audit.Verify: %v", err)
	}
}

// ---- journal lines ----

func cur(i string) string { return "s=1;i=" + i + ";b=2;m=3;t=4;x=5" }

func micro(t time.Time) string { return itoa(t.UnixMicro()) }

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func jline(cursor string, at time.Time, f map[string]string) string {
	m := map[string]string{"__CURSOR": cursor, "PRIORITY": "6"}
	if !at.IsZero() {
		m["__REALTIME_TIMESTAMP"] = micro(at)
	}
	for k, v := range f {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func sshLine(cursor string, at time.Time, ip string) string {
	return jline(cursor, at, map[string]string{
		"MESSAGE": "Failed password for root from " + ip + " port 22 ssh2", "_SYSTEMD_UNIT": "ssh.service",
		"_UID": "0", "_PID": "800", "_TRANSPORT": "syslog", "SYSLOG_IDENTIFIER": "sshd",
	})
}

func kernLine(cursor string, at time.Time, msg string) string {
	return jline(cursor, at, map[string]string{"MESSAGE": msg, "_TRANSPORT": "kernel", "_UID": "0", "_PID": "0"})
}

func plainLine(cursor string, at time.Time) string {
	return jline(cursor, at, map[string]string{"MESSAGE": "hello", "_TRANSPORT": "syslog", "_UID": "1000", "_PID": "42"})
}

// script adds a script for the argv of the given cursor.
func (h *harness) script(cursor string, s fake.Script) { h.fs.Add(args(cursor), s) }
