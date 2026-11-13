package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

type stubRule struct {
	id  string
	out []event.Signal
}

func (s stubRule) ID() string { return s.id }
func (s stubRule) Evaluate(event.Event, time.Time) []event.Signal {
	return s.out
}

func TestEngineSignalOrderFollowsRuleOrder(t *testing.T) {
	a := stubRule{"a", []event.Signal{{RuleID: "a1"}, {RuleID: "a2"}}}
	b := stubRule{"b", []event.Signal{{RuleID: "b1"}}}
	got := NewEngine(a, b).Evaluate(event.Event{}, t0)
	var ids []string
	for _, s := range got {
		ids = append(ids, s.RuleID)
	}
	if strings.Join(ids, ",") != "a1,a2,b1" {
		t.Fatalf("order = %v", ids)
	}
}

// Internal invariants of the capped structures: the list and the map always
// describe the same keys, whatever is repeated.
func TestCappedStructuresStayConsistent(t *testing.T) {
	c := newWindowCounter(Params{Threshold: 3, Window: time.Hour, MaxKeys: 4})
	for i := 0; i < 50; i++ {
		c.hit(fmt.Sprintf("k%d", i%7), t0.Add(time.Duration(i)*time.Second))
		if c.order.Len() != len(c.keys) || len(c.keys) > 4 {
			t.Fatalf("window counter after %d: list %d, map %d", i, c.order.Len(), len(c.keys))
		}
	}
	s := newSeenSet(10*time.Second, 4)
	for i := 0; i < 50; i++ {
		s.add(t0.Add(time.Duration(i)*time.Second), fmt.Sprintf("k%d", i%7), "shared")
		if s.order.Len() != len(s.keys) || len(s.keys) > 4 {
			t.Fatalf("seen set after %d: list %d, map %d", i, s.order.Len(), len(s.keys))
		}
	}
	t.Run("after a clock reset", clockResetDropsTheEvictionOrder)
}

// A clock reset drops the eviction order together with the keys. Afterwards
// the structures are filled to the cap again, with a key from before the
// reset among the new ones: the next key evicts the oldest key added since
// the reset, not the re-added one, and the list holds no entry of before.
func clockResetDropsTheEvictionOrder(t *testing.T) {
	const w = time.Minute
	late := t0.Add(time.Hour)

	c := newWindowCounter(Params{Threshold: 2, Window: w, MaxKeys: 3})
	c.hit("A", late)
	c.hit("B", late)
	c.hit("X", t0) // a step back of an hour: reset, X is the first key after it
	if c.order.Len() != 1 || len(c.keys) != 1 {
		t.Errorf("window counter after the reset: list %d, map %d, want 1 and 1", c.order.Len(), len(c.keys))
	}
	c.hit("A", t0)
	c.hit("C", t0) // at the cap: X, A, C
	if c.order.Len() != len(c.keys) || len(c.keys) != 3 {
		t.Errorf("window counter at the cap: list %d, map %d, want 3 and 3", c.order.Len(), len(c.keys))
	}
	c.hit("D", t0) // evicts X, the least recently seen key since the reset
	if _, ok := c.keys["X"]; ok {
		t.Error("window counter: X was not evicted")
	}
	for _, k := range []string{"A", "C", "D"} {
		if _, ok := c.keys[k]; !ok {
			t.Errorf("window counter: %s was evicted, want X", k)
		}
	}
	if c.order.Len() != len(c.keys) || len(c.keys) != 3 {
		t.Errorf("window counter after the eviction: list %d, map %d, want 3 and 3", c.order.Len(), len(c.keys))
	}
	if front := c.order.Front().Value.(*keyState).key; front != "A" {
		t.Errorf("window counter: next key to evict is %s, want A", front)
	}
	// A kept its hit since the reset (and none of before): the next one crosses the threshold.
	if _, fired := c.hit("A", t0); !fired {
		t.Error("window counter: the re-added key lost its hit")
	}

	s := newSeenSet(w, 3)
	s.add(late, "A", "B")
	s.add(t0, "X") // reset
	if s.order.Len() != 1 || len(s.keys) != 1 {
		t.Errorf("seen set after the reset: list %d, map %d, want 1 and 1", s.order.Len(), len(s.keys))
	}
	if _, fresh := s.add(t0, "A"); !fresh {
		t.Error("seen set: a key of before the reset was still remembered")
	}
	s.add(t0, "C") // at the cap: X, A, C
	if s.order.Len() != len(s.keys) || len(s.keys) != 3 {
		t.Errorf("seen set at the cap: list %d, map %d, want 3 and 3", s.order.Len(), len(s.keys))
	}
	s.add(t0, "D") // evicts X, the oldest key since the reset
	if _, ok := s.keys["X"]; ok {
		t.Error("seen set: X was not evicted")
	}
	for _, k := range []string{"A", "C", "D"} {
		if _, ok := s.keys[k]; !ok {
			t.Errorf("seen set: %s was evicted, want X", k)
		}
	}
	if s.order.Len() != len(s.keys) || len(s.keys) != 3 {
		t.Errorf("seen set after the eviction: list %d, map %d, want 3 and 3", s.order.Len(), len(s.keys))
	}
	if front := s.order.Front().Value.(*seenEntry).key; front != "A" {
		t.Errorf("seen set: next key to evict is %s, want A", front)
	}
	if _, fresh := s.add(t0, "A"); fresh {
		t.Error("seen set: the re-added key was forgotten")
	}

	// The same through a rule: after a reset at the cap, the address that
	// was counted before the reset and again after it keeps its count.
	r := mustBrute(t, Params{Threshold: 2, Window: w, MaxKeys: 3})
	r.Evaluate(sshEv(failed("192.0.2.1")), late)
	r.Evaluate(sshEv(failed("192.0.2.2")), late)
	n := 0
	for _, ip := range []string{"192.0.2.9", "192.0.2.1", "192.0.2.3", "192.0.2.4", "192.0.2.1"} {
		n += len(r.Evaluate(sshEv(failed(ip)), t0))
	}
	if n != 1 {
		t.Errorf("ssh rule after a reset at the cap: %d signals, want 1 (two lines of 192.0.2.1 since the reset)", n)
	}
}

func TestWindowCounterTouchedKeyIsKept(t *testing.T) {
	c := newWindowCounter(Params{Threshold: 3, Window: time.Hour, MaxKeys: 3})
	for _, k := range []string{"A", "B", "C", "A"} { // A is touched last
		c.hit(k, t0)
	}
	c.hit("D", t0) // evicts the least recently seen key, B
	if _, ok := c.keys["B"]; ok {
		t.Fatal("B should have been evicted")
	}
	if _, fired := c.hit("A", t0); !fired {
		t.Fatal("A was evicted although it was touched: its count was lost")
	}
}

func TestSeenSetBoundariesAndOrder(t *testing.T) {
	const ttl = 10 * time.Second
	// A key exactly ttl old has expired and is refreshed.
	s := newSeenSet(ttl, 10)
	if _, fresh := s.add(t0, "k"); !fresh {
		t.Fatal("first add")
	}
	if _, fresh := s.add(t0.Add(ttl), "k"); !fresh {
		t.Fatal("key exactly ttl old must be fresh")
	}
	if _, fresh := s.add(t0.Add(ttl+5*time.Second), "k"); fresh {
		t.Fatal("refreshed key must suppress for another ttl")
	}
	// A key seen within the ttl is not refreshed by the suppressed add.
	s2 := newSeenSet(ttl, 10)
	s2.add(t0, "k")
	if _, fresh := s2.add(t0.Add(6*time.Second), "k"); fresh {
		t.Fatal("within ttl")
	}
	if _, fresh := s2.add(t0.Add(11*time.Second), "k"); !fresh {
		t.Fatal("a suppressed add must not extend the ttl")
	}
	// Eviction removes the oldest key.
	s3 := newSeenSet(time.Hour, 2)
	s3.add(t0, "A")
	s3.add(t0, "B")
	s3.add(t0, "C") // evicts A
	if _, fresh := s3.add(t0, "B"); fresh {
		t.Fatal("B must still be remembered")
	}
	if _, fresh := s3.add(t0, "A"); !fresh {
		t.Fatal("A must have been evicted")
	}
	// A refreshed key moves to the back of the eviction order.
	s4 := newSeenSet(ttl, 2)
	s4.add(t0, "A")
	s4.add(t0.Add(time.Second), "B")
	s4.add(t0.Add(ttl), "A")             // A expired, refreshed: order B, A
	s4.add(t0.Add(ttl+time.Second), "C") // evicts B
	if _, fresh := s4.add(t0.Add(ttl+2*time.Second), "A"); fresh {
		t.Fatal("A was evicted although it had just been refreshed")
	}
	// Marks every unseen key also when suppressed.
	s5 := newSeenSet(time.Hour, 10)
	s5.add(t0, "A")
	if _, fresh := s5.add(t0, "A", "B"); fresh {
		t.Fatal("suppressed by A")
	}
	if _, fresh := s5.add(t0, "B"); fresh {
		t.Fatal("B must have been marked by the suppressed add")
	}
}

func TestUnitNameCharacters(t *testing.T) {
	units := []string{
		"app.service", "App.service", "app2.service", "my_app.service", "a-b.service",
		"a:b.service", `dev-disk-by\x2duuid.service`, "user@1000.service", "getty@tty1.service",
		"a.b.service", "x.socket", "x.timer", "mnt-data.mount", "x.path",
	}
	for _, u := range units {
		r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		s := r.Evaluate(sysdEv(u+": Scheduled restart job, restart counter is at 1."), t0)
		if len(s) != 1 || s[0].Subject != u {
			t.Errorf("unit %q: %+v", u, s)
		}
		o, _ := NewOOMKill(OOMParams{Window: time.Minute})
		s = o.Evaluate(sysdEv(u+": A process of this unit has been killed by the OOM killer."), t0)
		if len(s) != 1 || s[0].Subject != u {
			t.Errorf("oom unit %q: %+v", u, s)
		}
	}
	for _, u := range []string{".service", "a b.service", "a/b.service", "a.slice", "a.scope", "a.target", "a.serviceX", "a.service.x", "é.service"} {
		r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sysdEv(u+": Scheduled restart job, restart counter is at 1."), t0); len(s) != 0 {
			t.Errorf("unit %q gave a signal", u)
		}
	}
}

func TestRestartLineDetailsAndSummary(t *testing.T) {
	for _, m := range []string{
		"a.service: Scheduled restart job, restart counter is at .",
		"a.service: Scheduled restart job, restart counter is at x.",
		"a.service: Scheduled restart job, restart counter is at 3",
		"a.service: Scheduled restart job restart counter is at 3.",
		"a.service: Scheduled restart job, restart counter is 3.",
	} {
		r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sysdEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	r, _ := NewRestartLoop(Params{Threshold: 3, Window: time.Minute})
	var got []event.Signal
	for i := 1; i <= 3; i++ {
		got = append(got, r.Evaluate(sysdEv(fmt.Sprintf("app.service: Scheduled restart job, restart counter is at %d.", i)), t0)...)
	}
	if len(got) != 1 || got[0].Summary != "app.service restarted 3 times within 1m0s" || got[0].RuleID != IDRestartLoop {
		t.Fatalf("got %+v", got)
	}
	// A unit of exactly maxKeyLen bytes is accepted, one more is not.
	exact := strings.Repeat("a", maxKeyLen-len(".service")) + ".service"
	re, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	if s := re.Evaluate(sysdEv(exact+": Scheduled restart job, restart counter is at 1."), t0); len(s) != 1 {
		t.Error("unit of maxKeyLen bytes must be accepted")
	}
	re2, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	if s := re2.Evaluate(sysdEv("a"+exact+": Scheduled restart job, restart counter is at 1."), t0); len(s) != 0 {
		t.Error("unit of maxKeyLen+1 bytes must be ignored")
	}
}

func TestSignalTimeIsEffectiveClock(t *testing.T) {
	// ssh and restart: the second line arrives with a clock 20s behind.
	b := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	b.Evaluate(sshEv(failed("192.0.2.1")), t0.Add(30*time.Second))
	if s := b.Evaluate(sshEv(failed("192.0.2.1")), t0.Add(10*time.Second)); len(s) != 1 || !s[0].Time.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("ssh: %+v", s)
	}
	rl, _ := NewRestartLoop(Params{Threshold: 2, Window: time.Minute})
	line := "a.service: Scheduled restart job, restart counter is at 1."
	rl.Evaluate(sysdEv(line), t0.Add(30*time.Second))
	if s := rl.Evaluate(sysdEv(line), t0.Add(10*time.Second)); len(s) != 1 || !s[0].Time.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("restart: %+v", s)
	}
	oo, _ := NewOOMKill(OOMParams{Window: time.Hour})
	oo.Evaluate(sysdEv("a.service: A process of this unit has been killed by the OOM killer."), t0.Add(30*time.Second))
	if s := oo.Evaluate(sysdEv("b.service: A process of this unit has been killed by the OOM killer."), t0.Add(10*time.Second)); len(s) != 1 || !s[0].Time.Equal(t0.Add(30*time.Second)) {
		t.Fatalf("oom: %+v", s)
	}
}

func TestOOMKillLineDetails(t *testing.T) {
	const memcg = "/system.slice/a.service"
	base := func(constraint, tail string) string {
		return "oom-kill:constraint=" + constraint + ",nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=" + memcg + tail
	}
	for _, m := range []string{
		base("", ",task=x,pid=1,uid=0"),
		base("CONSTRAINT_NONE", ",task=x,pid=,uid=0"),
		base("CONSTRAINT_NONE", ",task=x,pid=1,uid="),
		base("CONSTRAINT_NONE", ",task=x,pid=1,uid=0,"),
		strings.Replace(base("CONSTRAINT_NONE", ",task=x,pid=1,uid=0"), "cpuset=/", "cpuset=", 1) + "x",
		base("CONSTRAINT_NONE", ",task=x,pid=1,uid=0x"),
		base("CONSTRAINT_NONE", ",task=x,pid=1x,uid=0"),
		base("CONSTRAINT_NONE", ",tusk=x,pid=1,uid=0"),
		base("CONSTRAINT_NONE", ",task=x,pid=1"),
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=x,cpuset=/,mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cgroup=/,mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null)cpuset=/,mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
		"oom-kill:constraint=CONSTRAINT_NONE,cpuset=/,mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
		"oom-kill:constraint=constraint_none,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/a.service,task=x,pid=1,uid=0",
	} {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(kernEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	for _, m := range []string{
		"Out of memory: Killed process 1234 (app)",
		"Out of memory: Killed process 1234 (app) total-vm 1kB",
		"Out of memory: Killed process  (app) total-vm:1kB",
		"Out of memory: Killed process 1234 app total-vm:1kB",
		"Out of memory: Killed process 1234 (app total-vm:1kB",
	} {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(kernEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	// The command name is everything up to the last ") total-vm:".
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	s := r.Evaluate(kernEv("Out of memory: Killed process 7 (a) total-vm:(b) total-vm:1kB"), t0)
	if len(s) != 1 || s[0].Subject != "a) total-vm:(b" {
		t.Fatalf("greedy comm: %+v", s)
	}
	if s[0].Summary != "out of memory: process a) total-vm:(b was killed by the OOM killer" {
		t.Fatalf("summary: %q", s[0].Summary)
	}
	// systemd's second line also reports a kill on its own, and needs its dot.
	r2, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r2.Evaluate(sysdEv("a.service: Failed with result 'oom-kill'."), t0); len(s) != 1 {
		t.Fatal("Failed with result line alone must report")
	}
	r3, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r3.Evaluate(sysdEv("a.service: Failed with result 'oom-kill'"), t0); len(s) != 0 {
		t.Fatal("missing dot")
	}
	r4, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r4.Evaluate(sysdEv("a.service: A process of this unit has been killed by the OOM killer"), t0); len(s) != 0 {
		t.Fatal("missing dot")
	}
	// The unit summary names the unit.
	r5, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r5.Evaluate(sysdEv("a.service: Failed with result 'oom-kill'."), t0); len(s) != 1 || s[0].Summary != "out of memory: a process of unit a.service was killed by the OOM killer" {
		t.Fatalf("unit summary: %+v", s)
	}
}

func TestOOMVictimKeys(t *testing.T) {
	line := func(comm string, pid int) event.Event {
		return kernEv(fmt.Sprintf("oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/docker/x,task_memcg=/docker/x,task=%s,pid=%d,uid=0", comm, pid))
	}
	killed := func(comm string, pid int) event.Event {
		return kernEv(fmt.Sprintf("Memory cgroup out of memory: Killed process %d (%s) total-vm:1kB", pid, comm))
	}
	count := func(evs ...event.Event) int {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		n := 0
		for i, ev := range evs {
			n += len(r.Evaluate(ev, t0.Add(time.Duration(i)*time.Minute)))
		}
		return n
	}
	if n := count(line("a", 5), line("b", 5)); n != 2 {
		t.Errorf("same pid, different command: %d signals, want 2", n)
	}
	if n := count(line("a", 5), line("a", 6)); n != 2 {
		t.Errorf("same command, different pid: %d signals, want 2", n)
	}
	if n := count(line("a", 5), line("a", 5)); n != 1 {
		t.Errorf("same victim twice: %d signals, want 1", n)
	}
	if n := count(killed("a", 5), killed("b", 5)); n != 2 {
		t.Errorf("Killed lines, same pid, different command: %d signals, want 2", n)
	}
	if n := count(killed("a", 5), killed("a", 6)); n != 2 {
		t.Errorf("Killed lines, same command, different pid: %d signals, want 2", n)
	}
	if n := count(killed("a", 5), killed("a", 5)); n != 1 {
		t.Errorf("Killed line repeated: %d signals, want 1", n)
	}
	// The oom-kill line and the Killed line of one victim share a key.
	if n := count(line("a", 5), killed("a", 5)); n != 1 {
		t.Errorf("one victim, two kernel lines: %d signals, want 1", n)
	}
}

func TestOOMKeyLengthBounds(t *testing.T) {
	exactUnit := strings.Repeat("a", maxKeyLen-len(".service")) + ".service"
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r.Evaluate(sysdEv(exactUnit+": A process of this unit has been killed by the OOM killer."), t0); len(s) != 1 {
		t.Error("unit of maxKeyLen bytes must be accepted")
	}
	r2, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r2.Evaluate(sysdEv("a"+exactUnit+": A process of this unit has been killed by the OOM killer."), t0); len(s) != 0 {
		t.Error("unit of maxKeyLen+1 bytes must be ignored")
	}
}

func TestSSHLineDetails(t *testing.T) {
	for _, m := range []string{
		"Failed password for root from 203.0.113.9 port ",
		"Failed password for root from 203.0.113.9 port  ssh2",
		"Failed password for root from 203.0.113.9 port x ssh2",
		"Failed password for rootfrom 203.0.113.9 port 22 ssh2",
		"Failed password for root from 203.0.113.9 port 22 ssh3",
		"Invalid user a from 203.0.113.9 port ",
		"Invalid user a from 203.0.113.9 port x",
		"Invalid user afrom 203.0.113.9 port 22",
		"Connection closed by authenticating user root 203.0.113.9 port  [preauth]",
		"Connection closed by authenticating user root 203.0.113.9 port x [preauth]",
		"Connection closed by authenticating user root 203.0.113.9 port 22 ",
		"Connection closed by authenticating user root 203.0.113.9 port 22",
		"Connection closed by authenticating 203.0.113.9 port 22 [preauth]",
		"Connection closed by invalid 203.0.113.9 port 22 [preauth]",
		"Connection closed by authenticating user root203.0.113.9 port 22 [preauth]",
		"Connection closed by authenticating user root 203.0.113.9port 22 [preauth]",
		"error: PAM: Authentication failure for rootfrom 203.0.113.9",
		"error: PAM: Authentication failur for root from 203.0.113.9",
		"error: PAM: Authentication failure for root from ",
	} {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sshEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	// "invalid user" and "illegal user" are part of the name and are absorbed.
	for _, m := range []string{
		"Failed password for invalid user admin from 203.0.113.9 port 22 ssh2",
		"error: PAM: Authentication failure for illegal user admin from 203.0.113.9",
	} {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sshEv(m), t0); len(s) != 1 || s[0].Subject != "203.0.113.9" {
			t.Errorf("%q: %+v", m, s)
		}
	}
	// A matched shape with an unparsable address is not counted.
	r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	if s := r.Evaluate(sshEv("Failed password for root from not-an-ip port 22 ssh2"), t0); len(s) != 0 {
		t.Error("unparsable address counted")
	}
}

func TestSSHConstructorKeepsParams(t *testing.T) {
	b := mustBrute(t, Params{Threshold: 2, Window: time.Minute, MaxKeys: 7})
	if b.c.maxKeys != 7 || b.c.threshold != 2 || b.c.window != time.Minute || b.n != 2 || b.w != time.Minute {
		t.Fatalf("ssh rule = %+v", b)
	}
	rl, _ := NewRestartLoop(Params{Threshold: 2, Window: time.Minute, MaxKeys: 7})
	if rl.c.maxKeys != 7 || rl.c.threshold != 2 || rl.n != 2 {
		t.Fatalf("restart rule = %+v", rl.c)
	}
	oo, _ := NewOOMKill(OOMParams{Window: time.Minute, MaxKeys: 7})
	if oo.s.maxKeys != 7 || oo.s.ttl != time.Minute {
		t.Fatalf("oom rule = %+v", oo.s)
	}
	if b.ID() != IDSSHBruteForce || rl.ID() != IDRestartLoop || oo.ID() != IDOOMKill {
		t.Fatal("ids")
	}
}
