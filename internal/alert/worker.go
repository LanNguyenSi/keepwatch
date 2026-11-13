// Package alert delivers incident notifications without ever stalling the
// caller.
//
// A Worker owns a bounded queue and one goroutine (Run) that hands messages
// to a notify.Notifier. Enqueue never blocks: when the queue is full or a
// rate limit is hit the message is dropped, and the drop is reported like any
// other outcome so the daemon can count and audit it. Slow or dead ntfy
// therefore costs messages, never journal reading time.
//
// This package defines no default values: the caller passes the limits
// (they come from the watch section of the configuration).
package alert

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/notify"
)

// Job is one message to send. IncidentID is the key of the per-incident rate
// limit; the message must already be cleaned.
type Job struct {
	IncidentID  string
	Fingerprint string
	Msg         notify.Message
}

// Status is the outcome of a Job.
type Status string

// The outcomes.
const (
	Sent    Status = "sent"
	Failed  Status = "failed"
	Dropped Status = "dropped"
)

// DropReason says why a job was dropped.
type DropReason string

// The reasons. NotDropped (the empty reason) means the job was accepted.
const (
	NotDropped      DropReason = ""
	DropQueueFull   DropReason = "queue_full"
	DropIncident    DropReason = "rate_limit_incident"
	DropGlobal      DropReason = "rate_limit_global"
	DropShutdown    DropReason = "shutdown"
	DropWorkerEnded DropReason = "worker_stopped"
)

// Result reports what became of a Job.
type Result struct {
	Job    Job
	Status Status
	// Reason is set when Status is Dropped.
	Reason DropReason
	// Class is the failure class; meaningful when Status is Failed.
	Class notify.Class
	// Detail is the notifier's own short error text (it never holds the
	// server address, the token or the message); set when Status is Failed.
	Detail string
	At     time.Time
}

// Params are the limits of a Worker. Zero PerIncidentInterval or zero
// GlobalPerMinute switches that limit off; QueueSize must be at least 1.
type Params struct {
	QueueSize           int
	PerIncidentInterval time.Duration
	GlobalPerMinute     int
	// SendTimeout bounds one Send; zero leaves it to the run context.
	SendTimeout time.Duration
}

// Worker queues and sends notifications.
type Worker struct {
	Notifier notify.Notifier
	// Clock returns the current time; nil means time.Now.
	Clock func() time.Time
	// OnResult receives every outcome. It is called from Run's goroutine for
	// sends and from the caller's goroutine for drops at Enqueue, so it must
	// be safe for concurrent use and must not block for long.
	OnResult func(Result)

	p     Params
	queue chan Job

	mu       sync.Mutex
	closed   bool
	lastSent map[string]time.Time
	window   []time.Time
}

// maxTracked is the size at which expired per-incident entries are pruned.
const maxTracked = 1024

// NewWorker validates p and returns a Worker.
func NewWorker(n notify.Notifier, p Params, onResult func(Result)) (*Worker, error) {
	if n == nil {
		return nil, errors.New("alert: no notifier")
	}
	if p.QueueSize < 1 {
		return nil, errors.New("alert: queue size must be at least 1")
	}
	if p.PerIncidentInterval < 0 || p.GlobalPerMinute < 0 || p.SendTimeout < 0 {
		return nil, errors.New("alert: limits must not be negative")
	}
	return &Worker{
		Notifier: n,
		OnResult: onResult,
		p:        p,
		queue:    make(chan Job, p.QueueSize),
		lastSent: map[string]time.Time{},
	}, nil
}

func (w *Worker) now() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

func (w *Worker) report(r Result) {
	if w.OnResult != nil {
		w.OnResult(r)
	}
}

// Enqueue accepts j for sending, or drops it and says why. It never blocks.
// A dropped job is also reported through OnResult. A job that was accepted
// has used its slot in both rate limits, even if the send later fails.
func (w *Worker) Enqueue(j Job) DropReason {
	now := w.now()
	w.mu.Lock()
	reason := w.admit(j, now)
	w.mu.Unlock()
	if reason != NotDropped {
		w.report(Result{Job: j, Status: Dropped, Reason: reason, At: now})
	}
	return reason
}

// admit decides under w.mu. A rate limit is only charged when the job
// actually entered the queue.
func (w *Worker) admit(j Job, now time.Time) DropReason {
	if w.closed {
		return DropWorkerEnded
	}
	if iv := w.p.PerIncidentInterval; iv > 0 {
		if last, ok := w.lastSent[j.IncidentID]; ok && now.Sub(last) < iv {
			return DropIncident
		}
	}
	if n := w.p.GlobalPerMinute; n > 0 {
		cut := now.Add(-time.Minute)
		kept := w.window[:0]
		for _, t := range w.window {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		w.window = kept
		if len(w.window) >= n {
			return DropGlobal
		}
	}
	select {
	case w.queue <- j:
	default:
		return DropQueueFull
	}
	if w.p.PerIncidentInterval > 0 {
		if len(w.lastSent) >= maxTracked {
			for k, t := range w.lastSent {
				if now.Sub(t) >= w.p.PerIncidentInterval {
					delete(w.lastSent, k)
				}
			}
		}
		w.lastSent[j.IncidentID] = now
	}
	if w.p.GlobalPerMinute > 0 {
		w.window = append(w.window, now)
	}
	return NotDropped
}

// Run sends queued jobs until ctx is cancelled. On cancel it returns
// promptly: the job in flight and every job still queued are reported as
// dropped with DropShutdown, and later Enqueue calls are dropped with
// DropWorkerEnded. Notifier.Send must honour its context.
func (w *Worker) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.shutdown()
			return
		case j := <-w.queue:
			if ctx.Err() != nil {
				// Both channels were ready and the queue case won.
				w.report(Result{Job: j, Status: Dropped, Reason: DropShutdown, At: w.now()})
				w.shutdown()
				return
			}
			w.send(ctx, j)
		}
	}
}

func (w *Worker) send(ctx context.Context, j Job) {
	sctx, cancel := ctx, context.CancelFunc(func() {})
	if w.p.SendTimeout > 0 {
		sctx, cancel = context.WithTimeout(ctx, w.p.SendTimeout)
	}
	err := w.Notifier.Send(sctx, j.Msg)
	cancel()
	r := Result{Job: j, At: w.now()}
	switch {
	case err == nil:
		r.Status = Sent
	case ctx.Err() != nil:
		r.Status, r.Reason = Dropped, DropShutdown
	default:
		r.Status, r.Class, r.Detail = Failed, notify.Permanent, "send failed"
		if ne := notify.AsError(err); ne != nil {
			r.Class, r.Detail = ne.Class, ne.Error()
		}
	}
	w.report(r)
}

func (w *Worker) shutdown() {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	for {
		select {
		case j := <-w.queue:
			w.report(Result{Job: j, Status: Dropped, Reason: DropShutdown, At: w.now()})
		default:
			return
		}
	}
}
