// Package rules turns event.Event values into event.Signal values.
//
// Rules are pure state machines: they take the clock as an argument, never
// read the wall clock, touch no files and start no goroutines. They work on
// RAW event fields only (no redaction happens here) and base every trust
// decision on journald-set fields: sshd lines count only from the ssh
// service as root, systemd unit lines only from PID 1 as root, kernel lines
// only from the kernel transport. SYSLOG_IDENTIFIER, UNIT and _COMM are
// never trusted on their own, because any local user can set them.
//
// Parameters such as thresholds and windows come from the caller (the daemon
// takes them from the loaded config); this package defines no defaults of
// its own. Thresholds count matching log lines, not login attempts: sshd
// writes more than one counted line for a single failed attempt (an unknown
// user gives "Invalid user" and "Failed password for invalid user", and a
// refused connection adds a "Connection closed ... [preauth]" line), so a
// configured threshold is in lines. The only built-in numbers are the safety
// caps below, which bound memory under hostile input.
package rules

import (
	"container/list"
	"errors"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Rule IDs, used in signals and fingerprints.
const (
	IDSSHBruteForce = "ssh_brute_force"
	IDRestartLoop   = "restart_loop"
	IDOOMKill       = "oom_kill"
)

// Severities emitted by the rules.
const (
	SeveritySSHBruteForce = result.High
	SeverityRestartLoop   = result.Medium
	SeverityOOMKill       = result.High
)

// DefaultMaxKeys is the cap on distinct keys (source IPs, units, victims)
// a rule remembers when Params.MaxKeys is zero. When the cap is reached the
// least recently seen key is evicted, so hostile input cannot grow memory
// without bound.
const DefaultMaxKeys = 4096

// maxKeyLen bounds the length of a parsed key (unit name, command name).
// A longer value is not tracked and yields no signal.
const maxKeyLen = 256

// Rule evaluates one event and returns zero or more signals.
type Rule interface {
	// ID returns the stable rule identifier.
	ID() string
	// Evaluate looks at ev with the injected clock value now. It never
	// panics, whatever ev contains, and is safe for concurrent use.
	//
	// Clock contract: now must come from one clock that event senders
	// cannot set (the journal's own timestamp or the daemon's clock),
	// and the two must never be mixed across calls. A zero now is
	// ignored (no state change, no signal). A step back of at most the
	// rule's window is clamped to the latest value seen; a larger step
	// back resets the rule's state, so a mixed or sender-controlled
	// clock would blind the rule.
	Evaluate(ev event.Event, now time.Time) []event.Signal
}

// Params configures a windowed rule: it fires when Threshold matching lines
// of one key are seen within Window. The values come from the caller.
type Params struct {
	// Threshold is the number of matching lines per key that triggers a
	// signal. It must be at least 1.
	Threshold int
	// Window is the sliding window. It must be positive.
	Window time.Duration
	// MaxKeys caps the distinct keys remembered; zero means DefaultMaxKeys.
	MaxKeys int
}

// OOMParams configures the OOM kill rule. A victim is reported once per
// Window.
type OOMParams struct {
	// Window is how long a reported victim is remembered, so that the
	// several lines the kernel and systemd write for one kill produce one
	// signal. It must be positive.
	Window time.Duration
	// MaxKeys caps the distinct victims remembered; zero means
	// DefaultMaxKeys.
	MaxKeys int
}

var (
	errThreshold = errors.New("rules: threshold must be at least 1")
	errWindow    = errors.New("rules: window must be positive")
)

func (p Params) validate() error {
	if p.Threshold < 1 {
		return errThreshold
	}
	if p.Window <= 0 {
		return errWindow
	}
	return nil
}

func capOrDefault(n int) int {
	if n <= 0 {
		return DefaultMaxKeys
	}
	return n
}

// Engine runs a fixed set of rules over each event.
type Engine struct {
	rules []Rule
}

// NewEngine returns an Engine over rules, evaluated in the given order.
func NewEngine(rules ...Rule) *Engine {
	return &Engine{rules: append([]Rule(nil), rules...)}
}

// Evaluate returns the signals of all rules for ev, in rule order.
func (e *Engine) Evaluate(ev event.Event, now time.Time) []event.Signal {
	var out []event.Signal
	for _, r := range e.rules {
		out = append(out, r.Evaluate(ev, now)...)
	}
	return out
}

// monotonic returns the effective clock value and whether the caller must
// drop its stored state. A small step back (at most window) is clamped to the
// latest value seen, so it cannot reopen expired windows. A larger step back
// means the clock itself was corrected, or one far-future value was seen: the
// stored latest is no longer credible, so now is adopted and the state is
// reset (reset is true). Without this, one bad value would freeze the rule
// until restart.
func monotonic(last *time.Time, now time.Time, window time.Duration) (time.Time, bool) {
	if now.Before(*last) {
		if last.Sub(now) > window {
			*last = now
			return now, true
		}
		return *last, false
	}
	*last = now
	return now, false
}

type keyState struct {
	key   string
	times []time.Time
	fired bool
	el    *list.Element
}

// windowCounter is a capped per-key sliding window counter. It is guarded
// by mu.
type windowCounter struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	maxKeys   int
	keys      map[string]*keyState
	order     *list.List // front = least recently seen
	last      time.Time
}

func newWindowCounter(p Params) *windowCounter {
	return &windowCounter{
		threshold: p.Threshold,
		window:    p.Window,
		maxKeys:   capOrDefault(p.MaxKeys),
		keys:      map[string]*keyState{},
		order:     list.New(),
	}
}

// hit records one line for key and reports the effective time and whether
// this line crossed the threshold. It reports true once per burst: further
// lines while the count stays at or above the threshold do not, and the
// state re-arms only after the window has drained below the threshold.
func (c *windowCounter) hit(key string, now time.Time) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now, reset := monotonic(&c.last, now, c.window)
	if reset {
		c.keys = map[string]*keyState{}
		c.order = list.New()
	}
	st, ok := c.keys[key]
	if ok {
		c.order.MoveToBack(st.el)
	} else {
		for len(c.keys) >= c.maxKeys {
			front := c.order.Front()
			old := front.Value.(*keyState)
			c.order.Remove(front)
			delete(c.keys, old.key)
		}
		st = &keyState{key: key}
		st.el = c.order.PushBack(st)
		c.keys[key] = st
	}
	cutoff := now.Add(-c.window)
	i := 0
	for i < len(st.times) && !st.times[i].After(cutoff) {
		i++
	}
	st.times = append(st.times[:0], st.times[i:]...)
	st.times = append(st.times, now)
	if len(st.times) > c.threshold {
		st.times = append(st.times[:0], st.times[len(st.times)-c.threshold:]...)
	}
	if len(st.times) < c.threshold {
		st.fired = false
		return now, false
	}
	if st.fired {
		return now, false
	}
	st.fired = true
	return now, true
}

// size returns the number of tracked keys.
func (c *windowCounter) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.keys)
}

type seenEntry struct {
	key string
	at  time.Time
	el  *list.Element
}

// seenSet remembers keys for a time-to-live, capped, evicting the least
// recently added. It is guarded by mu.
type seenSet struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxKeys int
	keys    map[string]*seenEntry
	order   *list.List
	last    time.Time
}

func newSeenSet(ttl time.Duration, maxKeys int) *seenSet {
	return &seenSet{
		ttl:     ttl,
		maxKeys: capOrDefault(maxKeys),
		keys:    map[string]*seenEntry{},
		order:   list.New(),
	}
}

// add reports the effective time and whether the event is new: true when none
// of keys was seen within the ttl. Every key that is not seen within the ttl
// is marked (added, or refreshed when it had expired), also when the event
// is suppressed, so the several lines of one kill suppress each other
// whatever their order. A key seen within the ttl is not refreshed.
func (s *seenSet) add(now time.Time, keys ...string) (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, reset := monotonic(&s.last, now, s.ttl)
	if reset {
		s.keys = map[string]*seenEntry{}
		s.order = list.New()
	}
	fresh := true
	for _, k := range keys {
		if e, ok := s.keys[k]; ok && now.Sub(e.at) < s.ttl {
			fresh = false
		}
	}
	for _, k := range keys {
		if e, ok := s.keys[k]; ok {
			if now.Sub(e.at) >= s.ttl {
				e.at = now
				s.order.MoveToBack(e.el)
			}
			continue
		}
		for len(s.keys) >= s.maxKeys {
			front := s.order.Front()
			old := front.Value.(*seenEntry)
			s.order.Remove(front)
			delete(s.keys, old.key)
		}
		e := &seenEntry{key: k, at: now}
		e.el = s.order.PushBack(e)
		s.keys[k] = e
	}
	return now, fresh
}

func (s *seenSet) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keys)
}

func isRoot(ev event.Event) bool { return ev.UID == 0 }

// fromSystemd reports whether ev was logged by PID 1 as root. Only these
// lines can be believed to come from the service manager itself.
func fromSystemd(ev event.Event) bool { return ev.PID == 1 && isRoot(ev) }
