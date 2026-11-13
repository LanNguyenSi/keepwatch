package alert

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// Concurrent Enqueue of one fingerprint with the real clock: the per-incident
// limit admits exactly one job.
func TestConcurrentEnqueueSameFingerprint(t *testing.T) {
	const rounds, g = 1000, 16
	for r := 0; r < rounds; r++ {
		w, err := NewWorker(&fakeNotifier{}, Params{QueueSize: 64, PerIncidentInterval: time.Hour}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var acc atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < g; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if w.Enqueue(job("same")) == NotDropped {
					acc.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if n := acc.Load(); n != 1 {
			t.Fatalf("round %d: %d jobs admitted for one fingerprint, want 1", r, n)
		}
	}
}

// Concurrent Enqueue of distinct fingerprints with the real clock: the
// global limit admits at most its number.
func TestConcurrentEnqueueGlobalLimit(t *testing.T) {
	const rounds, g, limit = 500, 32, 4
	for r := 0; r < rounds; r++ {
		w, err := NewWorker(&fakeNotifier{}, Params{QueueSize: 64, GlobalPerMinute: limit}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var acc atomic.Int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < g; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if w.Enqueue(job("k"+strconv.Itoa(i))) == NotDropped {
					acc.Add(1)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if n := acc.Load(); n != limit {
			t.Fatalf("round %d: %d jobs admitted, want %d", r, n, limit)
		}
	}
}

type flakyNotifier struct {
	mu sync.Mutex
	n  int
}

func (f *flakyNotifier) Send(ctx context.Context, _ notify.Message) error {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	if n%2 == 0 {
		return &notify.Error{Class: notify.Transient, Msg: "down"}
	}
	return ctx.Err()
}

// Every job gets exactly one result under concurrent Enqueue, failing sends
// and cancel, and nothing stays in the queue.
func TestConservationUnderConcurrency(t *testing.T) {
	for round := 0; round < 20; round++ {
		var mu sync.Mutex
		got := map[string]int{}
		on := func(r Result) {
			mu.Lock()
			got[r.Job.IncidentID]++
			mu.Unlock()
		}
		w, err := NewWorker(&flakyNotifier{}, Params{QueueSize: 8, PerIncidentInterval: time.Millisecond, GlobalPerMinute: 100000, SendTimeout: time.Second}, on)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { w.Run(ctx); close(done) }()
		var wg sync.WaitGroup
		const g, per = 8, 300
		for a := 0; a < g; a++ {
			wg.Add(1)
			go func(a int) {
				defer wg.Done()
				for i := 0; i < per; i++ {
					id := strconv.Itoa(a) + "-" + strconv.Itoa(i)
					w.Enqueue(Job{IncidentID: id, Fingerprint: "fp" + strconv.Itoa(i%5)})
					if i == per/2 && a == 0 {
						cancel()
					}
				}
			}(a)
		}
		wg.Wait()
		cancel()
		<-done
		mu.Lock()
		if len(got) != g*per {
			t.Errorf("round %d: %d results for %d jobs", round, len(got), g*per)
		}
		for id, n := range got {
			if n != 1 {
				t.Errorf("round %d: job %s has %d results", round, id, n)
			}
		}
		mu.Unlock()
		if len(w.queue) != 0 {
			t.Errorf("round %d: %d jobs left in the queue", round, len(w.queue))
		}
	}
}

// gateNotifier waits for a token per Send and returns it as the result.
type gateNotifier struct {
	started chan struct{}
	gate    chan error
}

func (g *gateNotifier) Send(ctx context.Context, _ notify.Message) error {
	g.started <- struct{}{}
	select {
	case e := <-g.gate:
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}

var errDown = &notify.Error{Class: notify.Transient, Msg: "down"}

// Job A is in flight, the interval passes, job B takes the same fingerprint,
// then A fails: B keeps its slot, and the other window entries stay.
func TestLateFailureKeepsLaterSlot(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	g := &gateNotifier{started: make(chan struct{}, 4), gate: make(chan error)}
	w := mk(t, g, Params{QueueSize: 4, PerIncidentInterval: time.Minute, GlobalPerMinute: 5}, s, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	if r := w.Enqueue(job("x")); r != NotDropped {
		t.Fatal(r)
	}
	<-g.started
	c.add(2 * time.Minute)
	if r := w.Enqueue(job("x")); r != NotDropped { // B, queued behind A
		t.Fatal(r)
	}
	if r := w.Enqueue(job("y")); r != NotDropped {
		t.Fatal(r)
	}
	g.gate <- errDown // A fails
	if r := s.next(t); r.Status != Failed {
		t.Fatalf("%+v", r)
	}
	w.mu.Lock()
	_, has := w.lastSent["x"]
	nw := len(w.window)
	w.mu.Unlock()
	if !has || nw != 2 {
		t.Errorf("late failure removed a later job's slot: has=%v window=%d, want true and 2", has, nw)
	}
	if r := w.Enqueue(job("x")); r != DropIncident {
		t.Errorf("third x: %q", r)
	}
}

// The failed job's own window entry has expired already: its release must
// not remove an entry that is not its own.
func TestFailureAfterOwnWindowEntryExpiredKeepsOthers(t *testing.T) {
	s := newSink()
	c := &fakeClock{t: time.Unix(1000, 0)}
	g := &gateNotifier{started: make(chan struct{}, 4), gate: make(chan error)}
	w := mk(t, g, Params{QueueSize: 4, PerIncidentInterval: time.Hour, GlobalPerMinute: 5}, s, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	if r := w.Enqueue(job("a")); r != NotDropped {
		t.Fatal(r)
	}
	<-g.started
	c.add(90 * time.Second) // a's window entry expires at the next admission
	if r := w.Enqueue(job("b")); r != NotDropped {
		t.Fatal(r)
	}
	g.gate <- errDown // a fails
	if r := s.next(t); r.Status != Failed {
		t.Fatalf("%+v", r)
	}
	w.mu.Lock()
	_, hasA := w.lastSent["a"]
	_, hasB := w.lastSent["b"]
	nw := len(w.window)
	w.mu.Unlock()
	if hasA || !hasB || nw != 1 {
		t.Errorf("hasA=%v hasB=%v window=%d, want false, true, 1", hasA, hasB, nw)
	}
}

// After the clock went back, the prune scan drops the entries that lie in
// the future instead of keeping them.
func TestPruneDropsFutureEntries(t *testing.T) {
	c := &fakeClock{t: time.Unix(100000, 0)}
	w := mk(t, &fakeNotifier{}, Params{QueueSize: 10, PerIncidentInterval: time.Hour}, newSink(), c)
	w.pruneAt = 3
	for _, k := range []string{"a", "b", "c"} {
		if r := w.Enqueue(job(k)); r != NotDropped {
			t.Fatal(r)
		}
	}
	c.add(-24 * time.Hour)
	if r := w.Enqueue(job("d")); r != NotDropped {
		t.Fatal(r)
	}
	w.mu.Lock()
	n := len(w.lastSent)
	w.mu.Unlock()
	if n != 1 {
		t.Errorf("tracked fingerprints = %d, want 1 (only d)", n)
	}
}
