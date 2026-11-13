package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func TestSSHUnitMatching(t *testing.T) {
	cases := map[string]bool{
		"ssh.service":  true,
		"sshd.service": true,
		"ssh@0-127.0.0.1:22-127.0.0.1:54232.service": true,
		"sshd@1-10.0.0.1:22-10.0.0.2:5555.service":   true,
		"ssh@a.service":                 true,
		"xssh@a.service":                false,
		"ssh@a.scope":                   false,
		"ssh@abcdefghijkl.scope":        false,
		"ssh@abcdefghijkl.service.evil": false,
		"ssh.service.evil":              false,
		"ssh@.service":                  false,
		"ssh@":                          false,
		"sshd@.service":                 false,
		"xssh.service":                  false,
		"session-3.scope":               false,
		"":                              false,
	}
	for unit, want := range cases {
		if got := sshUnit(unit); got != want {
			t.Errorf("sshUnit(%q) = %v, want %v", unit, got, want)
		}
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		ev := sshEv(failed("203.0.113.9"))
		ev.SystemdUnit = unit
		if got := len(r.Evaluate(ev, t0)) == 1; got != want {
			t.Errorf("event with unit %q: signal = %v, want %v", unit, got, want)
		}
		// Instances are accepted only together with UID 0.
		ev.UID = 1000
		if len(r.Evaluate(ev, t0)) != 0 {
			t.Errorf("unit %q with uid 1000 gave a signal", unit)
		}
	}
}

func TestSSHFailedAlternatives(t *testing.T) {
	for _, msg := range []string{
		"Failed password for root from 203.0.113.9 port 51234 ssh2",
		"Failed none for invalid user admin from 203.0.113.9 port 51234 ssh2",
		"Failed keyboard-interactive/pam for root from 203.0.113.9 port 51234 ssh2",
		"Failed keyboard-interactive for root from 203.0.113.9 port 51234 ssh2",
		"Invalid user admin from 203.0.113.9 port 51234",
		"Connection closed by authenticating user root 203.0.113.9 port 51234 [preauth]",
		"Connection closed by invalid user admin 203.0.113.9 port 51234 [preauth]",
		"Disconnected from authenticating user root 203.0.113.9 port 51234 [preauth]",
		"Disconnected from invalid user admin 203.0.113.9 port 51234 [preauth]",
	} {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		s := r.Evaluate(sshEv(msg), t0)
		if len(s) != 1 || s[0].Subject != "203.0.113.9" {
			t.Errorf("%q: %+v", msg, s)
		}
	}
}

// Anchoring: every sshd shape needs full-length prefixed and suffixed
// negatives so that a removed anchor is caught.
func TestSSHPatternsAreAnchored(t *testing.T) {
	bases := []string{
		"Failed password for root from 203.0.113.9 port 51234 ssh2",
		"Invalid user admin from 203.0.113.9 port 51234",
		"Connection closed by authenticating user root 203.0.113.9 port 51234 [preauth]",
		"Disconnected from invalid user admin 203.0.113.9 port 51234 [preauth]",
	}
	for _, b := range bases {
		for _, m := range []string{"x " + b, "[sshd] " + b, b + " trailing", b + "\nnext line", "x\n" + b} {
			r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
			if s := r.Evaluate(sshEv(m), t0); len(s) != 0 {
				t.Errorf("%q gave a signal", m)
			}
		}
	}
	// Disconnected from a session user (no "authenticating"/"invalid") is post-auth.
	r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	if s := r.Evaluate(sshEv("Disconnected from user mallory 127.0.0.1 port 38012"), t0); len(s) != 0 {
		t.Error("post-auth disconnect must not count")
	}
}

// Lines captured from OpenSSH 8.9p1 (Ubuntu 22.04) and 9.6p1 (24.04); the
// hostile ones carry a forged address in the user name.
func TestSSHRealLines(t *testing.T) {
	const real = "127.0.0.1"
	lines := []string{
		"Failed password for root from 127.0.0.1 port 58494 ssh2",
		"Connection closed by authenticating user root 127.0.0.1 port 58494 [preauth]",
		"Invalid user nosuchuser from 127.0.0.1 port 52052",
		"Failed password for invalid user nosuchuser from 127.0.0.1 port 52052 ssh2",
		"Connection closed by invalid user nosuchuser 127.0.0.1 port 52052 [preauth]",
		"Invalid user bob from 1.2.3.4 port 22 from 127.0.0.1 port 45728",
		"Failed password for invalid user bob from 1.2.3.4 port 22 from 127.0.0.1 port 45728 ssh2",
		"Connection closed by invalid user bob from 1.2.3.4 port 22 127.0.0.1 port 45728 [preauth]",
		"Invalid user from 1.2.3.4 port 22 ssh2 from 127.0.0.1 port 45736",
		"Failed password for invalid user from 1.2.3.4 port 22 ssh2 from 127.0.0.1 port 45736 ssh2",
		"Connection closed by invalid user from 1.2.3.4 port 22 ssh2 127.0.0.1 port 45736 [preauth]",
		"Connection closed by authenticating user mallory 127.0.0.1 port 34710 [preauth]",
	}
	for _, l := range lines {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		s := r.Evaluate(sshEv(l), t0)
		if len(s) != 1 || s[0].Subject != real {
			t.Errorf("%q: %+v", l, s)
		}
	}
	// Keyboard-interactive guessing against an existing account writes only
	// the pre-auth close line per connection; three connections fire.
	r := mustBrute(t, Params{Threshold: 3, Window: time.Minute})
	n := 0
	for i, port := range []int{55852, 34710, 34714} {
		n += len(r.Evaluate(sshEv(fmt.Sprintf("Connection closed by authenticating user mallory 127.0.0.1 port %d [preauth]", port)), t0.Add(time.Duration(i)*time.Second)))
	}
	if n != 1 {
		t.Fatalf("keyboard-interactive probing gave %d signals, want 1", n)
	}
	// A genuine instance unit from the capture fires.
	ev := sshEv("Failed password for root from 127.0.0.1 port 54232 ssh2")
	ev.SystemdUnit = "ssh@0-127.0.0.1:22-127.0.0.1:54232.service"
	r1 := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	if len(r1.Evaluate(ev, t0)) != 1 {
		t.Fatal("per-connection instance unit gave no signal")
	}
}

func TestRestartRealLines(t *testing.T) {
	// 22.04 (systemd 249) and 24.04 (systemd 255): same restart line, plus
	// start lines that differ and must not count.
	p := Params{Threshold: 3, Window: time.Minute}
	restart := func(unit string, n int) event.Event {
		return sysdEv(fmt.Sprintf("%s: Scheduled restart job, restart counter is at %d.", unit, n))
	}
	r, _ := NewRestartLoop(p)
	n := 0
	for i := 1; i <= 5; i++ {
		n += len(r.Evaluate(restart("flap.service", i), t0.Add(time.Duration(i)*time.Second)))
	}
	if n != 1 {
		t.Fatalf("flapping unit: %d signals, want 1", n)
	}
	for name, lines := range map[string][]string{
		"22.04 starts": {"Started Flapping demo.", "Started OpenBSD Secure Shell server.", "Failed to start Flapping demo.",
			"flap.service: Failed with result 'exit-code'."},
		"24.04 starts": {"Started flap.service - Flapping demo.", "Failed to start flap.service - Flapping demo.",
			"Started user@1001.service - User Manager for UID 1001.", "Stopped user@1001.service - User Manager for UID 1001."},
	} {
		rr, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		for _, l := range lines {
			if s := rr.Evaluate(sysdEv(l), t0); len(s) != 0 {
				t.Errorf("%s: %q gave a signal", name, l)
			}
		}
	}
	// Three user logins in a row start the user manager three times: no signal.
	rl, _ := NewRestartLoop(Params{Threshold: 3, Window: 15 * time.Minute})
	for i := 0; i < 3; i++ {
		for _, l := range []string{"Started user@1001.service - User Manager for UID 1001.", "Stopping user@1001.service - User Manager for UID 1001...", "Stopped user@1001.service - User Manager for UID 1001."} {
			if s := rl.Evaluate(sysdEv(l), t0.Add(time.Duration(i)*12*time.Second)); len(s) != 0 {
				t.Fatalf("login produced a restart signal on %q", l)
			}
		}
	}
}

func TestRestartAnchorsAndKind(t *testing.T) {
	const ok = "app.service: Scheduled restart job, restart counter is at 3."
	for _, m := range []string{"x " + ok, "[systemd] " + ok, ok + " trailing", ok + "\nmore", "x\n" + ok, "Started app.service - My App."} {
		r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sysdEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	ev := sysdEv(ok)
	ev.Kind = event.KindPosture
	if s := r.Evaluate(ev, t0); len(s) != 0 {
		t.Error("posture event gave a signal")
	}
	if s := r.Evaluate(sysdEv(ok), t0); len(s) != 1 {
		t.Error("control: journal event gave no signal")
	}
}

func TestServiceOfCgroup(t *testing.T) {
	cases := []struct{ path, want string }{
		{"/system.slice/app.service", "app.service"},
		{"/system.slice/app.service/sub", "app.service"},
		{"/system.slice/system-getty.slice/getty@tty1.service", "getty@tty1.service"},
		{"/user.slice/user-1000.slice/user@1000.service", "user@1000.service"},
		{"/user.slice/user-1000.slice/user@1000.service/app.slice/postgresql.service", "user@1000.service"},
		{"/user.slice/user-1000.slice/user@1000.service/postgresql.service", "user@1000.service"},
		{"/docker/f4e3903d/system.slice/hog.service", ""},
		{"/docker/f4e3903d/user.slice/user-1000.slice/user@1000.service", ""},
		{"/user.slice/user-1000.slice/session-3.scope", ""},
		{"/system.slice/docker-abc.scope", ""},
		{"/user.slice/user-1000.slice/session-3.scope/x.service", ""},
		{"/system.slice/x.scope/y.service", ""},
		{"/x.service/system.slice", "x.service"},
		{"/", ""},
		{"", ""},
		{"/.service", ""},
		{"/.slice/x.service", ""},
		{"/system.slice/", ""},
	}
	for _, c := range cases {
		if got := serviceOfCgroup(c.path); got != c.want {
			t.Errorf("serviceOfCgroup(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func kernOOM(memcg, comm string, pid int) string {
	return fmt.Sprintf("oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=%s,task_memcg=%s,task=%s,pid=%d,uid=1000", memcg, memcg, comm, pid)
}

func TestOOMUnitAttribution(t *testing.T) {
	cases := []struct {
		name, memcg, subject string
		fp                   event.Fingerprint
	}{
		{"system unit", "/system.slice/hog.service", "hog.service", event.FingerprintOf(IDOOMKill, "unit", "hog.service")},
		{"user manager", "/user.slice/user-1000.slice/user@1000.service/app.slice/postgresql.service", "user@1000.service", event.FingerprintOf(IDOOMKill, "unit", "user@1000.service")},
		{"docker", "/docker/d9bee284/system.slice/hog.service", "tail", event.FingerprintOf(IDOOMKill, "comm", "tail")},
		{"scope", "/user.slice/user-1000.slice/session-3.scope", "tail", event.FingerprintOf(IDOOMKill, "comm", "tail")},
		{"nested under scope", "/system.slice/x.scope/postgresql.service", "tail", event.FingerprintOf(IDOOMKill, "comm", "tail")},
	}
	for _, c := range cases {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		s := r.Evaluate(kernEv(kernOOM(c.memcg, "tail", 77)), t0)
		if len(s) != 1 || s[0].Subject != c.subject || s[0].Fingerprint != c.fp {
			t.Errorf("%s: %+v", c.name, s)
		}
		if len(s) == 1 && s[0].Fingerprint == event.FingerprintOf(IDOOMKill, "unit", "postgresql.service") {
			t.Errorf("%s: user-chosen unit name steered the fingerprint", c.name)
		}
	}
}

// One kill of one unit as the journal records it on 24.04: the kernel's two
// lines and systemd's two lines give one signal; a second kill of the same
// unit after the window gives another.
func TestOOMRealSequenceOneSignal(t *testing.T) {
	const memcg = "/system.slice/hog.service"
	lines := []event.Event{
		kernEv("tail invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0"),
		kernEv(" oom_kill_process+0x1f8/0x3e0"),
		kernEv("[  pid  ]   uid  tgid total_vm      rss rss_anon rss_file rss_shmem pgtables_bytes swapents oom_score_adj name"),
		kernEv("oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=" + memcg + ",task_memcg=" + memcg + ",task=tail,pid=183820,uid=0"),
		kernEv("Memory cgroup out of memory: Killed process 183820 (tail) total-vm:27120kB, anon-rss:24448kB, file-rss:1408kB, shmem-rss:0kB, UID:0 pgtables:92kB oom_score_adj:0"),
		sysdEv("hog.service: A process of this unit has been killed by the OOM killer."),
		sysdEv("hog.service: Failed with result 'oom-kill'."),
	}
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	var got []event.Signal
	for i, ev := range lines {
		got = append(got, r.Evaluate(ev, t0.Add(time.Duration(i)*time.Millisecond))...)
	}
	if len(got) != 1 || got[0].Subject != "hog.service" || got[0].Severity != result.High {
		t.Fatalf("one kill gave %d signals: %+v", len(got), got)
	}
	// User-manager kill: kernel line and PID 1's user@ line agree.
	r3, _ := NewOOMKill(OOMParams{Window: time.Hour})
	um := "/user.slice/user-1001.slice/user@1001.service/app.slice/postgresql.service"
	n := len(r3.Evaluate(kernEv(kernOOM(um, "tail", 191418)), t0)) +
		len(r3.Evaluate(sysdEv("user@1001.service: A process of this unit has been killed by the OOM killer."), t0))
	if n != 1 {
		t.Fatalf("user-manager kill gave %d signals", n)
	}
	// The user manager's own lines (uid 1001, not PID 1) are ignored.
	ev := sysdEv("postgresql.service: A process of this unit has been killed by the OOM killer.")
	ev.UID, ev.PID, ev.SystemdUnit = 1001, 393, "user@1001.service"
	if s := r3.Evaluate(ev, t0); len(s) != 0 {
		t.Fatal("user-manager line gave a signal")
	}
}

func TestOOMNodeLists(t *testing.T) {
	for _, nm := range []struct{ node, mems string }{
		{"(null)", "0"}, {"0-1", "0-1"}, {"0,2-3", "0,2-3"}, {"0", "0,2"},
	} {
		line := fmt.Sprintf("oom-kill:constraint=CONSTRAINT_NONE,nodemask=%s,cpuset=/,mems_allowed=%s,global_oom,task_memcg=/system.slice/app.service,task=app,pid=1,uid=0", nm.node, nm.mems)
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		s := r.Evaluate(kernEv(line), t0)
		if len(s) != 1 || s[0].Subject != "app.service" {
			t.Errorf("nodemask=%s mems_allowed=%s: %+v", nm.node, nm.mems, s)
		}
	}
}

func TestOOMAnchorsKindAndBounds(t *testing.T) {
	kernelBases := []string{
		"oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/app.service,task=app,pid=1234,uid=0",
		"Out of memory: Killed process 1234 (app) total-vm:1000kB, anon-rss:900kB",
		"Memory cgroup out of memory: Killed process 1234 (app) total-vm:1000kB, anon-rss:900kB",
	}
	for _, b := range kernelBases {
		for _, m := range []string{"x " + b, "[  1.0] " + b, b + " trailing", b + "\nnext", "x\n" + b} {
			if strings.HasPrefix(b, "Out of") || strings.HasPrefix(b, "Memory") {
				if strings.HasSuffix(m, "trailing") || strings.HasSuffix(m, "\nnext") {
					continue // the Killed process shapes end open by design
				}
			}
			r, _ := NewOOMKill(OOMParams{Window: time.Hour})
			if s := r.Evaluate(kernEv(m), t0); len(s) != 0 {
				t.Errorf("%q gave a signal", m)
			}
		}
	}
	const sd = "app.service: A process of this unit has been killed by the OOM killer."
	for _, m := range []string{"x " + sd, sd + " trailing", sd + "\nnext", "x\n" + sd, "app.service: Failed with result 'oom-kill'. trailing", "x " + "app.service: Failed with result 'oom-kill'."} {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(sysdEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	// Kind gate.
	for _, ev := range []event.Event{kernEv(kernelBases[0]), sysdEv(sd)} {
		ev.Kind = event.KindPosture
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Error("posture event gave a signal")
		}
	}
	// Length bound: over-long unit and comm are ignored; at the bound they work.
	long := strings.Repeat("a", maxKeyLen)
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := r.Evaluate(sysdEv(long+".service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 0 {
		t.Error("over-long unit gave a signal")
	}
	if s := r.Evaluate(kernEv("Out of memory: Killed process 5 ("+long+"x) total-vm:1kB"), t0); len(s) != 0 {
		t.Error("over-long comm gave a signal")
	}
	if s := r.Evaluate(kernEv("Out of memory: Killed process 6 ("+long+") total-vm:1kB"), t0); len(s) != 1 {
		t.Error("comm at the bound must work")
	}
	if s := r.Evaluate(kernEv(kernOOM("/system.slice/"+long+".service", "tail", 9)), t0); len(s) != 0 {
		t.Error("over-long cgroup unit gave a signal")
	}
}

func TestWindowCounterTimestampsStayBounded(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 5, Window: time.Hour})
	for i := 0; i < 3000; i++ {
		r.Evaluate(sshEv(failed("192.0.2.1")), t0.Add(time.Duration(i)*time.Millisecond))
	}
	r.c.mu.Lock()
	defer r.c.mu.Unlock()
	if n := len(r.c.keys["192.0.2.1"].times); n > 5 {
		t.Fatalf("stored %d timestamps, want at most the threshold 5", n)
	}
}

func TestEngineKeepsOrderAndCopiesRules(t *testing.T) {
	a := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	rl, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	rules := []Rule{a, rl}
	e := NewEngine(rules...)
	rules[0] = rl
	if got := e.Evaluate(sshEv(failed("192.0.2.1")), t0); len(got) != 1 || got[0].RuleID != IDSSHBruteForce {
		t.Fatalf("engine must keep its own copy: %+v", got)
	}
}
