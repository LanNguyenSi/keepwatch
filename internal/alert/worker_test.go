package alert

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

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

type sink struct {
	mu sync.Mutex
	rs []Result
	ch chan Result
}

func newSink() *sink { return &sink{ch: make(chan Result, 256)} }
func (s *sink) on(r Result) {
	s.mu.Lock()
	s.rs = append(s.rs, r)
	s.mu.Unlock()
	s.ch <- r
}
func (s *sink) next(t *testing.T) Result {
	t.Helper()
	select {
	case r := <-s.ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
		return Result{}
	}
}

type fakeNotifier struct {
	mu   sync.Mutex
	sent []notify.Message
	err  error
}

func (f *fakeNotifier) Send(_ context.Context, m notify.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return f.err
}

type blockNotifier struct{ started chan struct{} }

func (b *blockNotifier) Send(ctx context.Context, _ notify.Message) error {
	select {
	case b.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func job(id string) Job {
	return Job{IncidentID: "inc-" + id, Fingerprint: id, Msg: notify.Message{Title: id}}
}

func mk(t *testing.T, n notify.Notifier, p Params, s *sink, c *fakeClock) *Worker {
	t.Helper()
	w, err := NewWorker(n, p, s.on)
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		w.Clock = c.now
	}
	return w
}

func TestNewWorkerValidation(t *testing.T) {
	n := &fakeNotifier{}
	for name, p := range map[string]Params{
		"zero queue":   {},
		"neg interval": {QueueSize: 1, PerIncidentInterval: -1},
		"neg global":   {QueueSize: 1, GlobalPerMinute: -1},
		"neg timeout":  {QueueSize: 1, SendTimeout: -1},
	} {
		if _, err := NewWorker(n, p, nil); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := NewWorker(nil, Params{QueueSize: 1}, nil); err == nil {
		t.Error("nil notifier: want error")
	}
}

func TestSendAndResults(t *testing.T) {
	s := newSink()
	fn := &fakeNotifier{}
	w := mk(t, fn, Params{QueueSize: 4}, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Fatalf("enqueue: %q", r)
	}
	if r := s.next(t); r.Status != Sent || r.Job.Fingerprint != "a" {
		t.Errorf("result = %+v", r)
	}
	fn.mu.Lock()
	fn.err = &notify.Error{Class: notify.Transient, Msg: "server error"}
	fn.mu.Unlock()
	w.Enqueue(job("b"))
	r := s.next(t)
	if r.Status != Failed || r.Class != notify.Transient || r.Detail != "ntfy: server error" {
		t.Errorf("failed result = %+v", r)
	}
	fn.mu.Lock()
	fn.err = errors.New("secret-bearing text")
	fn.mu.Unlock()
	w.Enqueue(job("c"))
	r = s.next(t)
	if r.Status != Failed || r.Class != notify.Permanent || r.Detail != "send failed" {
		t.Errorf("plain error result = %+v", r)
	}
	cancel()
	<-done
}

func TestEnqueueNeverBlocksWhenQueueFull(t *testing.T) {
	s := newSink()
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 2}, s, nil)
	// Run is not started: the queue fills.
	finished := make(chan DropReason, 1)
	go func() {
		w.Enqueue(job("a"))
		w.Enqueue(job("b"))
		finished <- w.Enqueue(job("c"))
	}()
	select {
	case r := <-finished:
		if r != DropQueueFull {
			t.Errorf("reason = %q", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked on a full queue")
	}
	if r := s.next(t); r.Status != Dropped || r.Reason != DropQueueFull || r.Job.Fingerprint != "c" {
		t.Errorf("drop result = %+v", r)
	}
}

func TestQueueFullDoesNotChargeLimits(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 1, PerIncidentInterval: time.Hour, GlobalPerMinute: 2}, s, c)
	w.Enqueue(job("a"))
	if r := w.Enqueue(job("b")); r != DropQueueFull {
		t.Fatalf("b: %q", r)
	}
	// b was never queued, so neither its incident slot nor a global slot is used.
	w.mu.Lock()
	_, hasB := w.lastSent["b"]
	n := len(w.window)
	w.mu.Unlock()
	if hasB || n != 1 {
		t.Errorf("limits charged for a dropped job: hasB=%v window=%d", hasB, n)
	}
}

func TestPerIncidentLimit(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 50, PerIncidentInterval: 10 * time.Minute}, s, c)
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Fatalf("first: %q", r)
	}
	for i := 0; i < 5; i++ {
		c.add(time.Minute)
		if r := w.Enqueue(job("a")); r != DropIncident {
			t.Fatalf("flood %d: %q", i, r)
		}
	}
	if r := w.Enqueue(job("other")); r != NotDropped {
		t.Errorf("another incident is limited: %q", r)
	}
	c.add(5 * time.Minute) // 10 minutes since the first
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Errorf("after the interval: %q", r)
	}
}

func TestGlobalLimit(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 50, GlobalPerMinute: 3}, s, c)
	for i := 0; i < 3; i++ {
		if r := w.Enqueue(job("i" + strconv.Itoa(i))); r != NotDropped {
			t.Fatalf("%d: %q", i, r)
		}
	}
	if r := w.Enqueue(job("x")); r != DropGlobal {
		t.Fatalf("4th: %q", r)
	}
	c.add(59 * time.Second)
	if r := w.Enqueue(job("x")); r != DropGlobal {
		t.Fatalf("within the minute: %q", r)
	}
	c.add(time.Second) // exactly 60 s after the first three
	if r := w.Enqueue(job("x")); r != NotDropped {
		t.Fatalf("at exactly the minute: %q", r)
	}
}

func TestLimitCombinations(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	// Both set: the per-incident limit is checked first and wins for the
	// same incident; the global one is what stops different incidents.
	s := newSink()
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 50, PerIncidentInterval: time.Hour, GlobalPerMinute: 2}, s, c)
	w.Enqueue(job("a"))
	if r := w.Enqueue(job("a")); r != DropIncident {
		t.Errorf("same incident: %q", r)
	}
	w.Enqueue(job("b"))
	if r := w.Enqueue(job("c")); r != DropGlobal {
		t.Errorf("third incident: %q", r)
	}
	// Neither set: nothing is limited except the queue.
	w2 := mk(t, &fakeNotifier{}, Params{QueueSize: 50}, newSink(), c)
	for i := 0; i < 20; i++ {
		if r := w2.Enqueue(job("a")); r != NotDropped {
			t.Fatalf("unlimited %d: %q", i, r)
		}
	}
}

func TestSendBoundedByTimeout(t *testing.T) {
	s := newSink()
	bn := &blockNotifier{started: make(chan struct{}, 1)}
	w := mk(t, bn, Params{QueueSize: 2, SendTimeout: 20 * time.Millisecond}, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.Enqueue(job("a"))
	r := s.next(t)
	if r.Status != Failed {
		t.Errorf("timed out send = %+v", r)
	}
}

func TestCancelDrainsQueueAndLeaksNothing(t *testing.T) {
	before := runtime.NumGoroutine()
	s := newSink()
	bn := &blockNotifier{started: make(chan struct{}, 1)}
	w := mk(t, bn, Params{QueueSize: 5}, s, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	w.Enqueue(job("a")) // blocks inside Send
	<-bn.started
	w.Enqueue(job("b"))
	w.Enqueue(job("c"))
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on cancel")
	}
	got := map[string]DropReason{}
	for i := 0; i < 3; i++ {
		r := s.next(t)
		if r.Status != Dropped {
			t.Errorf("result %+v is not a drop", r)
		}
		got[r.Job.Fingerprint] = r.Reason
	}
	for _, id := range []string{"a", "b", "c"} {
		if got[id] != DropShutdown {
			t.Errorf("%s: reason %q", id, got[id])
		}
	}
	if r := w.Enqueue(job("late")); r != DropWorkerEnded {
		t.Errorf("enqueue after stop: %q", r)
	}
	if r := s.next(t); r.Reason != DropWorkerEnded {
		t.Errorf("late result = %+v", r)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Errorf("goroutines: %d before, %d after", before, n)
	}
}

func TestPrunesExpiredIncidents(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: minPrune + 10, PerIncidentInterval: time.Minute}, newSink(), c)
	for i := 0; i < minPrune; i++ {
		w.Enqueue(job("i" + strconv.Itoa(i)))
	}
	c.add(2 * time.Minute)
	w.Enqueue(job("fresh"))
	w.mu.Lock()
	n := len(w.lastSent)
	w.mu.Unlock()
	if n != 1 {
		t.Errorf("tracked incidents = %d, want 1", n)
	}
}

func TestEmptyFingerprintRejected(t *testing.T) {
	s := newSink()
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 2, PerIncidentInterval: time.Hour}, s, nil)
	if r := w.Enqueue(Job{IncidentID: "inc-1"}); r != DropInvalid {
		t.Fatalf("reason = %q", r)
	}
	if r := s.next(t); r.Status != Dropped || r.Reason != DropInvalid {
		t.Errorf("result = %+v", r)
	}
	if len(w.queue) != 0 {
		t.Error("invalid job queued")
	}
}

// The limit keys on the fingerprint: two incident ids with one fingerprint
// share a slot, and one incident id with two fingerprints does not.
func TestLimitKeyIsFingerprint(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 10, PerIncidentInterval: time.Hour}, newSink(), c)
	if r := w.Enqueue(Job{IncidentID: "i1", Fingerprint: "fp"}); r != NotDropped {
		t.Fatal(r)
	}
	if r := w.Enqueue(Job{IncidentID: "i2", Fingerprint: "fp"}); r != DropIncident {
		t.Errorf("same fingerprint, new id: %q", r)
	}
	if r := w.Enqueue(Job{IncidentID: "i1", Fingerprint: "other"}); r != NotDropped {
		t.Errorf("same id, other fingerprint: %q", r)
	}
}

func TestBackwardsClock(t *testing.T) {
	c := &fakeClock{t: time.Unix(100000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 10, PerIncidentInterval: time.Hour, GlobalPerMinute: 1}, newSink(), c)
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Fatal(r)
	}
	c.add(-24 * time.Hour)
	// Both slots lie in the future: they count as expired.
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Errorf("per-incident slot in the future still limits: %q", r)
	}
	c.add(-24 * time.Hour)
	if r := w.Enqueue(job("b")); r != NotDropped {
		t.Errorf("global entries in the future still limit: %q", r)
	}
	// And the limits work again from the new time.
	if r := w.Enqueue(job("b")); r != DropIncident {
		t.Errorf("after the step: %q", r)
	}
	if r := w.Enqueue(job("c")); r != DropGlobal {
		t.Errorf("after the step: %q", r)
	}
}

// Both channels ready at the start of Run: no job may be sent with a dead
// context. The select picks at random, so repeat.
func TestRunAfterCancelSendsNothing(t *testing.T) {
	for round := 0; round < 40; round++ {
		s := newSink()
		fn := &fakeNotifier{}
		w := mk(t, fn, Params{QueueSize: 20}, s, nil)
		for i := 0; i < 20; i++ {
			if r := w.Enqueue(job("j" + strconv.Itoa(i))); r != NotDropped {
				t.Fatal(r)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w.Run(ctx)
		fn.mu.Lock()
		n := len(fn.sent)
		fn.mu.Unlock()
		if n != 0 {
			t.Fatalf("round %d: %d sends after cancel", round, n)
		}
		for i := 0; i < 20; i++ {
			if r := s.next(t); r.Status != Dropped || r.Reason != DropShutdown {
				t.Fatalf("round %d: result %+v", round, r)
			}
		}
	}
}

func TestFailedSendReleasesSlots(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	fn := &fakeNotifier{err: &notify.Error{Class: notify.Transient, Msg: "down"}}
	w := mk(t, fn, Params{QueueSize: 4, PerIncidentInterval: time.Hour, GlobalPerMinute: 1}, s, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	w.Enqueue(job("a"))
	if r := s.next(t); r.Status != Failed {
		t.Fatalf("result = %+v", r)
	}
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Errorf("retry after a failed send: %q", r)
	}
	// A sent job keeps its slots.
	fn.mu.Lock()
	fn.err = nil
	fn.mu.Unlock()
	if r := s.next(t); r.Status != Sent {
		t.Fatalf("result = %+v", r)
	}
	if r := w.Enqueue(job("a")); r != DropIncident {
		t.Errorf("after a sent job: %q", r)
	}
	if r := w.Enqueue(job("b")); r != DropGlobal {
		t.Errorf("after a sent job: %q", r)
	}
}

func TestShutdownReleasesSlots(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	bn := &blockNotifier{started: make(chan struct{}, 1)}
	w := mk(t, bn, Params{QueueSize: 4, PerIncidentInterval: time.Hour, GlobalPerMinute: 10}, s, c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	w.Enqueue(job("a")) // in flight
	<-bn.started
	w.Enqueue(job("b")) // queued
	cancel()
	<-done
	w.mu.Lock()
	n, nw := len(w.lastSent), len(w.window)
	w.mu.Unlock()
	if n != 0 || nw != 0 {
		t.Errorf("slots kept after shutdown: %d incidents, %d window entries", n, nw)
	}
}

// A large map of unexpired entries is not scanned on every Enqueue.
func TestPruneDoesNotRescanEveryCall(t *testing.T) {
	c := &fakeClock{t: time.Unix(1000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 6000, PerIncidentInterval: time.Hour}, newSink(), c)
	scans := 0
	w.onPrune = func() { scans++ }
	for i := 0; i < 5000; i++ {
		if r := w.Enqueue(job("i" + strconv.Itoa(i))); r != NotDropped {
			t.Fatal(r)
		}
	}
	// The map doubles between scans: 1024, 2048, 4096 (and nothing is
	// expired, so each scan keeps everything).
	if scans > 4 {
		t.Errorf("%d scans for 5000 unexpired incidents", scans)
	}
	if scans == 0 {
		t.Error("never pruned")
	}
}
