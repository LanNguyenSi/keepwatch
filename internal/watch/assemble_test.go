package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/alert"
	"github.com/LanNguyenSi/keepwatch/internal/audit"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/incident"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/posture"
	"github.com/LanNguyenSi/keepwatch/internal/requests"
	"github.com/LanNguyenSi/keepwatch/internal/rules"
	"github.com/LanNguyenSi/keepwatch/internal/securefile"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// loadConfig loads yaml as the main configuration file, trusting every
// owner on the path.
func loadConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := loadConfigErr(t, yaml)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// loadConfigErr loads yaml from a directory reached without symlinks (the
// configuration refuses a symlinked ancestor such as /var on darwin).
func loadConfigErr(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "keepwatch.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Load(p, config.WithOwnerOf(func(fs.FileInfo) (int, error) { return 0, nil }))
}

func newStateDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// feed is a streamer that delivers its lines once, closes done and waits for
// the context.
type feed struct {
	lines []string
	done  chan struct{}
}

func newFeed(lines ...string) *feed { return &feed{lines: lines, done: make(chan struct{})} }

func (f *feed) streamer() execx.Streamer {
	return streamFunc(func(ctx context.Context, _ []string, _ execx.StreamOpts, on func([]byte) error) (execx.StreamResult, error) {
		for _, l := range f.lines {
			if err := on([]byte(l)); err != nil {
				return execx.StreamResult{}, err
			}
		}
		close(f.done)
		<-ctx.Done()
		return execx.StreamResult{}, ctx.Err()
	})
}

func assembleT(t *testing.T, cfg *config.Config, dir string, in Injections) *Assembly {
	t.Helper()
	if in.Streamer == nil {
		in.Streamer = newFeed().streamer()
	}
	a, err := Assemble(cfg, dir, in)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

// runFeed assembles a daemon over f, runs it until the lines are handled and
// stops it; it returns Run's result.
func runFeed(t *testing.T, cfg *config.Config, dir string, clk *fakeClock, f *feed) (*Assembly, error) {
	t.Helper()
	a := assembleT(t, cfg, dir, Injections{Streamer: f.streamer(), Clock: clk.now})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Daemon.Run(ctx) }()
	select {
	case <-f.done:
		cancel()
	case err := <-done:
		return a, err
	case <-time.After(10 * time.Second):
		t.Fatal("the lines were not handled")
	}
	select {
	case err := <-done:
		return a, err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
		return nil, nil
	}
}

func ruleIncidents(a *Assembly, rule string) int {
	n := 0
	for _, in := range a.deps.Incidents.List() {
		if in.RuleID == rule {
			n++
		}
	}
	return n
}

// The defaults of watch and of the configuration are the same values, and
// the bounds Assemble refuses beyond are the configuration's bounds.
func TestAssembleDefaultsMatchConfig(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	n := cfg.Watch.Notify
	if n.Queue != DefaultQueue || n.GlobalPerMinute != DefaultGlobalPerMinute || n.PerIncidentInterval != time.Hour {
		t.Fatalf("config defaults %+v, watch defaults queue %d, global %d, per incident 1h", n, DefaultQueue, DefaultGlobalPerMinute)
	}
	// The configuration's upper bounds are accepted by Assemble too.
	top := loadConfig(t, fmt.Sprintf("watch:\n  notify:\n    queue: %d\n    global_per_minute: %d\n", MaxQueue, MaxGlobalPerMinute))
	assembleT(t, top, newStateDir(t), Injections{Notifier: &fakeNotifier{}})
	for _, y := range []string{
		fmt.Sprintf("watch:\n  notify:\n    queue: %d\n", MaxQueue+1),
		fmt.Sprintf("watch:\n  notify:\n    global_per_minute: %d\n", MaxGlobalPerMinute+1),
	} {
		if _, err := loadConfigErr(t, y); err == nil {
			t.Errorf("config accepts %q, beyond the bound Assemble keeps", y)
		}
	}
}

// limits measures the worker: the jobs it accepts within one minute before
// the global limit drops one (0 when the queue filled first), the queue size
// (jobs accepted until the queue was full, the clock moved on past each
// global window), and whether the per-incident interval holds a second job
// of one fingerprint for exactly want.
func limits(t *testing.T, w *alert.Worker, clk *fakeClock, want time.Duration) (global, queue int, perIncident bool) {
	t.Helper()
	start := clk.now()
	// steps bounds the loop also when the global window never ends (a
	// worker that does not run on clk).
	steps := 0
	for i := 0; i < 5000 && steps < 10000; i++ {
		steps++
		switch r := w.Enqueue(alert.Job{Fingerprint: fmt.Sprintf("fp-%d", i)}); r {
		case alert.NotDropped:
			queue++
		case alert.DropGlobal:
			if global == 0 {
				global = queue
			}
			clk.add(61 * time.Second)
			i--
		case alert.DropQueueFull:
			set := func(at time.Time) alert.DropReason {
				clk.mu.Lock()
				clk.t = at
				clk.mu.Unlock()
				return w.Enqueue(alert.Job{Fingerprint: "fp-0"})
			}
			perIncident = set(start.Add(want-time.Second)) == alert.DropIncident && set(start.Add(want)) != alert.DropIncident
			return global, queue, perIncident
		default:
			t.Fatalf("job %d dropped: %s", i, r)
		}
	}
	t.Fatal("the queue never filled")
	return
}

// Precedence of watch.notify: a value the configuration sets reaches both
// the daemon and the worker; an absent one gives the configuration's
// default, a zero one (a Config not from config.Load) the daemon's, which is
// the same. The set value wins.
func TestAssembleNotifyPrecedence(t *testing.T) {
	cases := []struct {
		name  string
		yaml  string
		zero  bool
		gpm   int
		every time.Duration
		queue int
	}{
		{name: "all absent", yaml: "watch:\n  enabled: true\n", gpm: 6, every: time.Hour, queue: 100},
		{name: "global set", yaml: "watch:\n  notify:\n    global_per_minute: 60\n", gpm: 60, every: time.Hour, queue: 100},
		{name: "per incident set", yaml: "watch:\n  notify:\n    per_incident_interval: 2h\n", gpm: 6, every: 2 * time.Hour, queue: 100},
		{name: "queue set", yaml: "watch:\n  notify:\n    queue: 5\n", gpm: 6, every: time.Hour, queue: 5},
		{name: "all set", yaml: "watch:\n  notify:\n    global_per_minute: 60\n    per_incident_interval: 90m\n    queue: 200\n", gpm: 60, every: 90 * time.Minute, queue: 200},
		{name: "all zero", yaml: "watch:\n  enabled: true\n", zero: true, gpm: 6, every: time.Hour, queue: 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := loadConfig(t, c.yaml)
			if c.zero {
				cfg.Watch.Notify = config.WatchNotify{}
			}
			clk := &fakeClock{t: t0}
			a := assembleT(t, cfg, newStateDir(t), Injections{Notifier: &fakeNotifier{}, Clock: clk.now})
			d := a.Daemon
			if d.opt.GlobalPerMinute != c.gpm || d.opt.PerIncidentInterval != c.every {
				t.Errorf("daemon: global %d, per incident %v; want %d, %v", d.opt.GlobalPerMinute, d.opt.PerIncidentInterval, c.gpm, c.every)
			}
			if d.deps.Worker != a.deps.Worker || d.deps.Worker == nil {
				t.Fatal("the daemon does not hold the assembled worker")
			}
			global, queue, perIncident := limits(t, d.deps.Worker, clk, c.every)
			wantGlobal := c.gpm + maxNotices
			if c.queue < wantGlobal {
				wantGlobal = 0
			}
			if global != wantGlobal || queue != c.queue || !perIncident {
				t.Errorf("worker: global %d, queue %d, per incident %v holds: %t; want %d, %d, true", global, queue, c.every, perIncident, wantGlobal, c.queue)
			}
		})
	}
}

// Without a notifier there is no worker.
func TestAssembleNoNotifierNoWorker(t *testing.T) {
	a := assembleT(t, loadConfig(t, "watch:\n  enabled: true\n"), newStateDir(t), Injections{})
	if a.deps.Worker != nil || a.Daemon.deps.Worker != nil {
		t.Fatal("a worker without a notifier")
	}
}

// Values beyond the configuration's bounds are refused before anything is
// opened.
func TestAssembleRefusesOutOfRangeNotify(t *testing.T) {
	for _, n := range []config.WatchNotify{
		{GlobalPerMinute: MaxGlobalPerMinute + 1}, {GlobalPerMinute: -1},
		{Queue: MaxQueue + 1}, {Queue: -1},
	} {
		cfg := loadConfig(t, "watch:\n  enabled: true\n")
		cfg.Watch.Notify = n
		missing := filepath.Join(t.TempDir(), "none")
		_, err := Assemble(cfg, missing, Injections{Streamer: newFeed().streamer(), Notifier: &fakeNotifier{}})
		if err == nil || !strings.Contains(err.Error(), "watch.notify") {
			t.Errorf("%+v: %v", n, err)
		}
	}
	// A per-incident interval New refuses is refused before anything is
	// opened too.
	for _, d := range []time.Duration{30 * time.Second, -time.Minute} {
		cfg := loadConfig(t, "watch:\n  enabled: true\n")
		cfg.Watch.Notify.PerIncidentInterval = d
		_, err := Assemble(cfg, filepath.Join(t.TempDir(), "none"), Injections{Streamer: newFeed().streamer()})
		if err == nil || !strings.Contains(err.Error(), "per_incident_interval") {
			t.Errorf("per-incident interval %v: %v", d, err)
		}
	}
}

func fpOf(c string) string { return "SHA256:" + strings.Repeat(c, 43) }

// The known keys of authorized_keys.expected reach the login rule next to
// the baseline, per user; unusable entries are dropped with a reason.
func TestAssembleKnownKeysMatrix(t *testing.T) {
	k, other := fpOf("K"), fpOf("Q")
	badUser := "bad\x07user"
	cases := []struct {
		name      string
		expected  map[string][]string
		inBase    bool
		alerts    int
		dropped   []string
		keepFirst bool
	}{
		{name: "config only", expected: map[string][]string{"alice": {k}}},
		{name: "baseline only", inBase: true},
		{name: "both", expected: map[string][]string{"alice": {k}}, inBase: true},
		{name: "neither", expected: map[string][]string{"alice": {other}}, alerts: 1},
		{name: "other user", expected: map[string][]string{"bob": {k}}, alerts: 1},
		{name: "invalid fingerprint dropped", expected: map[string][]string{"alice": {"SHA256:not a key!", k}},
			dropped: []string{"authorized_keys.expected.alice[0]: not a SHA256 key fingerprint"}},
		{name: "invalid user dropped", expected: map[string][]string{badUser: {k}}, alerts: 1,
			dropped: []string{`user "bad\x07user" is not a usable user name`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := newStateDir(t)
			b := rules.NewBaseline(time.Time{}) // past its learning phase
			b.AddIP("alice", "10.0.0.1")
			if c.inBase {
				b.AddKey("alice", k)
			}
			data, err := b.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, BaselineFile), data, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := loadConfig(t, "watch:\n  enabled: true\n")
			cfg.AuthorizedKeys.Expected = c.expected
			clk := &fakeClock{t: t0}
			a, err := runFeed(t, cfg, dir, clk, newFeed(
				loginMsgLine(cur("1"), t0, "Accepted publickey for alice from 10.0.0.1 port 22 ssh2: ED25519 "+k)))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if n := ruleIncidents(a, rules.IDLoginAnomaly); n != c.alerts {
				t.Errorf("login incidents %d, want %d", n, c.alerts)
			}
			if len(a.Dropped) != len(c.dropped) {
				t.Fatalf("dropped %q, want %d", a.Dropped, len(c.dropped))
			}
			for i, want := range c.dropped {
				if !strings.Contains(a.Dropped[i], want) || strings.ContainsRune(a.Dropped[i], '\x07') {
					t.Errorf("dropped %q, want it to name %q (escaped)", a.Dropped[i], want)
				}
			}
		})
	}
}

// The login rule is built over the baseline of Deps.Baseline, which is never
// nil: a refused baseline file fails the start, and a learned source
// survives a restart.
func TestAssembleBaselineWiring(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  learning_period: 1h\n")
	t.Run("never nil and shared", func(t *testing.T) {
		a := assembleT(t, cfg, newStateDir(t), Injections{})
		if a.deps.Baseline == nil || a.Daemon.deps.Baseline != a.deps.Baseline {
			t.Fatal("Deps.Baseline is not the assembled store")
		}
	})
	t.Run("refused file fails the start", func(t *testing.T) {
		dir := newStateDir(t)
		p := filepath.Join(dir, BaselineFile)
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
		_, err := runFeed(t, cfg, dir, &fakeClock{t: t0}, newFeed())
		if !errors.Is(err, ErrBaselineLoad) {
			t.Fatalf("Run: %v, want ErrBaselineLoad", err)
		}
	})
	t.Run("learned source survives a restart", func(t *testing.T) {
		dir := newStateDir(t)
		learn := t0.Add(10 * time.Minute)
		a, err := runFeed(t, cfg, dir, &fakeClock{t: t0}, newFeed(loginLine(cur("1"), learn, "alice", "10.0.0.9")))
		if err != nil {
			t.Fatal(err)
		}
		// The baseline was loaded at the injected clock, so the line is
		// in its learning phase.
		for _, in := range a.deps.Incidents.List() {
			if in.Notify {
				t.Fatalf("a login in the learning phase notifies: %s", in.Summary)
			}
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		later := t0.Add(2 * time.Hour)
		a, err = runFeed(t, cfg, dir, &fakeClock{t: later}, newFeed(
			loginLine(cur("2"), later, "alice", "10.0.0.9"), loginLine(cur("3"), later, "alice", "10.0.0.8")))
		if err != nil {
			t.Fatal(err)
		}
		high := 0
		for _, in := range a.deps.Incidents.List() {
			if in.RuleID == rules.IDLoginAnomaly && in.Notify {
				high++
				if strings.Contains(in.Summary, "10.0.0.9") {
					t.Errorf("the learned source alerted after the restart: %s", in.Summary)
				}
			}
		}
		if high != 1 {
			t.Errorf("%d notifying login incidents, want 1 (the new source)", high)
		}
	})
}

// The windowed rules take threshold and window from the configuration.
func TestAssembleRuleParams(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  ssh_bruteforce:\n    threshold: 2\n    window: 1m\n  restart_loop:\n    threshold: 2\n    window: 1m\n")
	restart := func(c string, at time.Time) string {
		return jline(c, at, map[string]string{"MESSAGE": "foo.service: Scheduled restart job, restart counter is at 1.", "_UID": "0", "_PID": "1", "_TRANSPORT": "journal"})
	}
	for _, c := range []struct {
		name  string
		gap   time.Duration
		count int
		want  int
	}{
		{"below threshold", 0, 1, 0},
		{"at threshold in window", 30 * time.Second, 2, 1},
		{"at threshold beyond window", 2 * time.Minute, 2, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			var lines []string
			for i := 0; i < c.count; i++ {
				at := t0.Add(time.Duration(i) * c.gap)
				lines = append(lines, sshLine(cur(fmt.Sprint(2*i+1)), at, "10.0.0.7"), restart(cur(fmt.Sprint(2*i+2)), at))
			}
			a, err := runFeed(t, cfg, newStateDir(t), &fakeClock{t: t0.Add(time.Hour)}, newFeed(lines...))
			if err != nil {
				t.Fatal(err)
			}
			if s, r := ruleIncidents(a, rules.IDSSHBruteForce), ruleIncidents(a, rules.IDRestartLoop); s != c.want || r != c.want {
				t.Errorf("ssh %d, restart %d incidents, want %d each", s, r, c.want)
			}
		})
	}
	zero := loadConfig(t, "watch:\n  enabled: true\n")
	zero.Watch.SSHBruteforce = config.WatchRule{}
	if _, err := Assemble(zero, newStateDir(t), Injections{Streamer: newFeed().streamer()}); err == nil {
		t.Error("a zero rule threshold was accepted")
	}
}

// The posture source reads the state file with PostureMinSeverity, and a
// missing source is a nil interface.
func TestAssemblePosture(t *testing.T) {
	a := assembleT(t, loadConfig(t, "watch:\n  enabled: true\n"), newStateDir(t), Injections{})
	src, ok := a.deps.Posture.(*posture.Source)
	if !ok || src == nil || a.Daemon.deps.Posture != a.deps.Posture {
		t.Fatalf("Deps.Posture is %T", a.deps.Posture)
	}
	if got := reflect.ValueOf(src).Elem().FieldByName("min").String(); got != string(PostureMinSeverity) {
		t.Errorf("posture min severity %q, want %q", got, PostureMinSeverity)
	}
	if p := postureOf(nil); p != nil {
		t.Errorf("postureOf(nil) = %#v, want a nil interface", p)
	}
	if a.Daemon.deps.Audit != a.aw || a.aw == nil {
		t.Error("the daemon does not write through the assembled audit writer")
	}
	if a.deps.Requests == nil || a.deps.Cursor == nil {
		t.Error("no request spool or cursor store")
	}
}

// tornTail leaves an audit log in dir that ends in a torn record.
func tornTail(t *testing.T, dir string) {
	t.Helper()
	sd, err := securefile.OpenDir(dir, false, securefile.DefaultOwnerOf)
	if err != nil {
		t.Fatal(err)
	}
	w, _, err := audit.Open(sd, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(audit.Record{Time: t0, Kind: audit.DaemonStart, Summary: "x"}); err != nil {
		t.Fatal(err)
	}
	w.Close()
	sd.Close()
	f, err := os.OpenFile(filepath.Join(dir, audit.FileName), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"seq":2,"ti`)
	f.Close()
}

// The Recovery of audit.Open reaches the daemon.
func TestAssembleHandsRecovery(t *testing.T) {
	dir := newStateDir(t)
	tornTail(t, dir)
	at := t0.Add(time.Hour)
	a := assembleT(t, loadConfig(t, "watch:\n  enabled: true\n"), dir, Injections{Clock: (&fakeClock{t: at}).now})
	if a.deps.Recovery == nil || a.Daemon.deps.Recovery != a.deps.Recovery {
		t.Fatal("the recovery did not reach the daemon")
	}
	a.Close()
	h := &harness{t: t, path: dir}
	recs := h.records()
	if last := recs[len(recs)-1]; last.Kind != audit.AuditRecovered || !last.Time.Equal(at) {
		t.Errorf("last record %s at %v, want audit_recovered at the injected clock %v", last.Kind, last.Time, at)
	}
}

var assembleSteps = []string{"state directory", "redact patterns", "rules", "posture", "incident store", "audit log", "alert worker", "daemon"}

// closedState reports what of a is still open.
func stillOpen(a *Assembly) []string {
	var open []string
	if a.dir != nil {
		if _, err := a.dir.ReadCapped(CursorFile, MaxCursorBytes); !errors.Is(err, os.ErrClosed) {
			open = append(open, "state directory")
		}
	}
	if a.aw != nil {
		if _, err := a.aw.Append(audit.Record{Time: t0, Kind: audit.DaemonStart, Summary: "x"}); !errors.Is(err, audit.ErrClosed) {
			open = append(open, "audit writer")
		}
	}
	return open
}

// A failure at any step closes what the earlier steps opened.
func TestAssembleCleanupOnFailure(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	var seen []string
	assembleT(t, cfg, newStateDir(t), Injections{Notifier: &fakeNotifier{}, fail: func(s string, _ *Assembly) error {
		seen = append(seen, s)
		return nil
	}})
	if !reflect.DeepEqual(seen, assembleSteps) {
		t.Fatalf("steps %q, want %q", seen, assembleSteps)
	}
	errInjected := errors.New("injected")
	for _, step := range assembleSteps {
		t.Run(step, func(t *testing.T) {
			var got *Assembly
			_, err := Assemble(cfg, newStateDir(t), Injections{Streamer: newFeed().streamer(), Notifier: &fakeNotifier{},
				fail: func(s string, a *Assembly) error {
					got = a
					if s == step {
						return errInjected
					}
					return nil
				}})
			if !errors.Is(err, errInjected) {
				t.Fatalf("Assemble: %v", err)
			}
			if open := stillOpen(got); len(open) > 0 {
				t.Errorf("still open after a failure at %s: %q", step, open)
			}
			afterAudit := slices.Index(assembleSteps, step) >= slices.Index(assembleSteps, "audit log")
			if got.dir == nil || afterAudit != (got.aw != nil) {
				t.Errorf("the failure at %s found nothing opened", step)
			}
		})
	}
	t.Run("corrupt incident store", func(t *testing.T) {
		dir := newStateDir(t)
		if err := os.WriteFile(filepath.Join(dir, incident.FileName), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		var got *Assembly
		_, err := Assemble(cfg, dir, Injections{Streamer: newFeed().streamer(), fail: func(_ string, a *Assembly) error { got = a; return nil }})
		if err == nil {
			t.Fatal("a corrupt incident store was accepted")
		}
		if open := stillOpen(got); len(open) > 0 {
			t.Errorf("still open: %q", open)
		}
	})
	t.Run("New's option rule checked before anything is opened", func(t *testing.T) {
		bad := loadConfig(t, "watch:\n  enabled: true\n")
		bad.Watch.Notify.PerIncidentInterval = time.Second
		var got *Assembly
		_, err := Assemble(bad, newStateDir(t), Injections{Streamer: newFeed().streamer(), fail: func(_ string, a *Assembly) error { got = a; return nil }})
		if err == nil || got != nil {
			t.Fatalf("Assemble: %v, steps run: %t", err, got != nil)
		}
	})
	t.Run("Close", func(t *testing.T) {
		a := assembleT(t, cfg, newStateDir(t), Injections{})
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		if open := stillOpen(a); len(open) > 0 {
			t.Errorf("still open after Close: %q", open)
		}
	})
}

// The OOM rule reports a victim once per OOMWindow.
func TestAssembleOOMWindow(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	for _, c := range []struct {
		gap   time.Duration
		count int
	}{{OOMWindow / 2, 1}, {OOMWindow + time.Minute, 2}} {
		a, err := runFeed(t, cfg, newStateDir(t), &fakeClock{t: t0.Add(time.Hour)}, newFeed(oomAt(cur("1"), t0), oomAt(cur("2"), t0.Add(c.gap))))
		if err != nil {
			t.Fatal(err)
		}
		list := a.deps.Incidents.List()
		if len(list) != 1 || list[0].Count != c.count {
			t.Errorf("gap %v: incidents %+v, want one with count %d", c.gap, list, c.count)
		}
	}
}

// The posture source, the request spool and the clean function are bound
// to the state directory and the configuration.
func TestAssembleBindings(t *testing.T) {
	dir := newStateDir(t)
	if err := os.WriteFile(filepath.Join(dir, state.FileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, state.FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := requests.Submit(dir, requests.Request{Action: requests.ActionAck, IncidentID: "abcdef12"}); err != nil {
		t.Fatal(err)
	}
	cfg := loadConfig(t, "watch:\n  enabled: true\nredact:\n  patterns:\n    - 'zebra[0-9]+'\n")
	a := assembleT(t, cfg, dir, Injections{Notifier: &fakeNotifier{}})
	if _, err := a.deps.Posture.Poll(t0); err == nil {
		t.Error("the posture source does not read the state file of the state directory")
	}
	if b, err := a.deps.Requests.Pending(); err != nil || len(b.Items) != 1 {
		t.Errorf("request spool: %d items, %v; want the one submitted", len(b.Items), err)
	}
	if got := a.deps.Clean("token zebra42"); strings.Contains(got, "zebra42") {
		t.Errorf("Clean(%q) = %q, the configured pattern is not applied", "token zebra42", got)
	}
	timeout := reflect.ValueOf(a.deps.Worker).Elem().FieldByName("p").FieldByName("SendTimeout").Int()
	if time.Duration(timeout) != SendTimeout || SendTimeout != 62*time.Second {
		t.Errorf("worker send timeout %v, want SendTimeout %v (62s)", time.Duration(timeout), SendTimeout)
	}
}

// knownKeys keeps what the login rule can use and names the rest.
func TestKnownKeysBounds(t *testing.T) {
	b64 := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		user, fp string
		keep     bool
	}{
		{"alice", "SHA256:" + b64(43), true},
		{"alice", "SHA256:SHA256:" + b64(43) + "==", true},
		{"alice", b64(64), true},
		{"alice", b64(65), false},
		{"alice", "SHA256:", false},
		{"alice", "SHA256:===", false},
		{"alice", "AZaz09+/", true},
		{"alice", "ab-c", false},
		{"alice", "ab c", false},
		{"alice", "ab[", false},
		{"alice", "ab{", false},
		{"alice", "ab:", false},
		{"alice", "ab@", false},
		{"alice", "ab`", false},
		{"alice", "ab.", false},
		{strings.Repeat("u", 64), "AA", true},
		{strings.Repeat("u", 65), "AA", false},
		{"", "AA", false},
		{"bad\xffname", "AA", false},
		{"a\x1fb", "AA", false},
		{"a\x7fb", "AA", false},
		{"a b~", "AA", true},
	}
	for _, c := range cases {
		out, dropped := knownKeys(map[string][]string{c.user: {c.fp}})
		kept := len(out[c.user]) == 1
		if kept != c.keep || kept == (len(dropped) == 1) {
			t.Errorf("user %q key %q: kept %t, dropped %q; want kept %t", c.user, c.fp, kept, dropped, c.keep)
		}
	}
}

// The reasons come sorted, whatever the order of the map.
func TestKnownKeysReasonsSorted(t *testing.T) {
	in := map[string][]string{}
	for i := 0; i < 12; i++ {
		in[fmt.Sprintf("user%02d", i)] = []string{"not a key"}
	}
	_, dropped := knownKeys(in)
	if len(dropped) != 12 || !slices.IsSorted(dropped) {
		t.Errorf("dropped %q, want 12 sorted reasons", dropped)
	}
}

// Assemble needs a configuration, a streamer and an existing state
// directory.
func TestAssembleRefusesMissingParts(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	st := newFeed().streamer()
	if _, err := Assemble(nil, newStateDir(t), Injections{Streamer: st}); err == nil {
		t.Error("a nil configuration was accepted")
	}
	if _, err := Assemble(cfg, newStateDir(t), Injections{}); err == nil {
		t.Error("a missing streamer was accepted")
	}
	if _, err := Assemble(cfg, filepath.Join(t.TempDir(), "none"), Injections{Streamer: st}); err == nil || !strings.Contains(err.Error(), "state directory") {
		t.Errorf("a missing state directory: %v", err)
	}
}

// An interface holding a nil notifier is refused before anything is
// opened; a worker over it would panic on its first send.
func TestAssembleRefusesTypedNilNotifier(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	var ntfy *notify.Ntfy
	var fn notifierFunc
	for _, n := range []notify.Notifier{ntfy, fn} {
		var got *Assembly
		_, err := Assemble(cfg, newStateDir(t), Injections{Streamer: newFeed().streamer(), Notifier: n,
			fail: func(_ string, a *Assembly) error { got = a; return nil }})
		if err == nil || !strings.Contains(err.Error(), "nil") || got != nil {
			t.Errorf("%T: %v, steps run: %t", n, err, got != nil)
		}
	}
	if typedNil(&fakeNotifier{}) || typedNil(nil) {
		t.Error("typedNil misreads a real notifier or a nil interface")
	}
}

// The rules remember more than one key: interleaved ssh sources and units
// each reach the threshold, and an OOM victim seen again inside OOMWindow is not
// reported again while another victim came in between.
func TestAssembleRuleKeyCap(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  ssh_bruteforce:\n    threshold: 2\n    window: 1m\n  restart_loop:\n    threshold: 2\n    window: 1m\n")
	restart := func(c, unit string, at time.Time) string {
		return jline(c, at, map[string]string{"MESSAGE": unit + ": Scheduled restart job, restart counter is at 1.", "_UID": "0", "_PID": "1", "_TRANSPORT": "journal"})
	}
	victim := func(c, name string, at time.Time) string {
		return kernLine(c, at, strings.Replace(oomKillLine, "77 (worker)", "78 ("+name+")", 1))
	}
	a, err := runFeed(t, cfg, newStateDir(t), &fakeClock{t: t0.Add(time.Hour)}, newFeed(
		sshLine(cur("1"), t0, "10.0.0.7"), sshLine(cur("2"), t0, "10.0.0.8"),
		sshLine(cur("3"), t0.Add(time.Second), "10.0.0.7"), sshLine(cur("4"), t0.Add(time.Second), "10.0.0.8"),
		oomAt(cur("5"), t0), victim(cur("6"), "other", t0.Add(time.Minute)), oomAt(cur("7"), t0.Add(2*time.Minute)),
		restart(cur("8"), "a.service", t0), restart(cur("9"), "b.service", t0),
		restart(cur("10"), "a.service", t0.Add(time.Second)), restart(cur("11"), "b.service", t0.Add(time.Second))))
	if err != nil {
		t.Fatal(err)
	}
	if s, r := ruleIncidents(a, rules.IDSSHBruteForce), ruleIncidents(a, rules.IDRestartLoop); s != 2 || r != 2 {
		t.Errorf("%d ssh and %d restart incidents, want 2 each (one per key)", s, r)
	}
	var counts []int
	for _, in := range a.deps.Incidents.List() {
		if in.RuleID == rules.IDOOMKill {
			counts = append(counts, in.Count)
		}
	}
	if len(counts) != 2 || counts[0] != 1 || counts[1] != 1 {
		t.Errorf("OOM incident counts %v, want two victims reported once each", counts)
	}
}

// Contract with the login rule: every fingerprint and user name knownKeys
// keeps is known to rules.NewLoginAnomaly given the same entry unfiltered.
func TestKnownKeysContractWithLoginRule(t *testing.T) {
	b64 := func(n int) string { return strings.Repeat("a", n) }
	entries := []struct{ user, fp string }{
		{"alice", "SHA256:" + b64(43)}, {"alice", "SHA256:SHA256:" + b64(43) + "=="}, {"alice", b64(64)},
		{"alice", b64(65)}, {"alice", "AZaz09+/"}, {"alice", "ab-c"}, {"alice", "SHA256:" + b64(64) + "="},
		{"alice", "SHA256:" + b64(1)}, {"alice", "SHA256:"}, {strings.Repeat("u", 64), b64(43)},
		{strings.Repeat("u", 65), b64(43)}, {"a b~", b64(43)},
	}
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signals := func(user, fp string, known map[string][]string) int {
		b := rules.NewBaseline(time.Time{})
		b.AddIP(user, "10.0.0.1")
		r, err := rules.NewLoginAnomaly(rules.LoginParams{LearningPeriod: time.Hour, KnownKeys: known}, b)
		if err != nil {
			t.Fatal(err)
		}
		norm := strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(fp, "SHA256:"), "SHA256:"), "=")
		ev := event.Event{Kind: event.KindJournal, Time: at, UID: 0, SystemdUnit: "ssh.service", PID: 800,
			Message: "Accepted publickey for " + user + " from 10.0.0.1 port 22 ssh2: ED25519 SHA256:" + norm}
		return len(r.Evaluate(ev, at))
	}
	keptAny := 0
	for _, e := range entries {
		out, _ := knownKeys(map[string][]string{e.user: {e.fp}})
		if len(out[e.user]) != 1 {
			continue
		}
		keptAny++
		if n := signals(e.user, e.fp, map[string][]string{e.user: {e.fp}}); n != 0 {
			t.Errorf("knownKeys keeps user %q key %q, the login rule does not know it (%d signals)", e.user, e.fp, n)
		}
	}
	// Negative control: the same login without known keys signals.
	if keptAny < 6 || signals("alice", "SHA256:"+b64(43), nil) != 1 {
		t.Errorf("the contract measured nothing: %d kept entries, or no signal for an unknown key", keptAny)
	}
}

// A start refused before audit.Open leaves a torn tail as it is, so the
// next start gets the Recovery and notifies it.
func TestAssembleKeepsRecoveryOnRefusedStart(t *testing.T) {
	cfg := loadConfig(t, "watch:\n  enabled: true\n")
	for _, c := range []struct {
		name  string
		spoil func(*config.Config)
	}{
		{"rules refused", func(c *config.Config) { c.Watch.SSHBruteforce = config.WatchRule{} }},
		{"New's option rule", func(c *config.Config) { c.Watch.Notify.PerIncidentInterval = time.Second }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := newStateDir(t)
			tornTail(t, dir)
			bad := *cfg
			c.spoil(&bad)
			if _, err := Assemble(&bad, dir, Injections{Streamer: newFeed().streamer()}); err == nil {
				t.Fatal("the spoiled configuration was accepted")
			}
			a := assembleT(t, cfg, dir, Injections{})
			if a.deps.Recovery == nil {
				t.Fatal("the start after a refused one has no Recovery to notify")
			}
		})
	}
}
