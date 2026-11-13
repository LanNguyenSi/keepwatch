package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func sshEv(msg string) event.Event {
	return event.Event{Kind: event.KindJournal, UID: 0, SystemdUnit: "ssh.service", Identifier: "sshd", PID: 900, Message: msg}
}

func sysdEv(msg string) event.Event {
	return event.Event{Kind: event.KindJournal, UID: 0, SystemdUnit: "init.scope", Identifier: "systemd", PID: 1, Message: msg}
}

func kernEv(msg string) event.Event {
	return event.Event{Kind: event.KindJournal, UID: -1, Transport: "kernel", Identifier: "kernel", Message: msg}
}

func mustBrute(t *testing.T, p Params) *SSHBruteForce {
	t.Helper()
	r, err := NewSSHBruteForce(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func failed(ip string) string {
	return "Failed password for root from " + ip + " port 4242 ssh2"
}

func TestParamsValidation(t *testing.T) {
	bad := []Params{{Threshold: 0, Window: time.Minute}, {Threshold: 3}, {Threshold: 3, Window: -time.Second}}
	for _, p := range bad {
		if _, err := NewSSHBruteForce(p); err == nil {
			t.Errorf("ssh %+v: want error", p)
		}
		if _, err := NewRestartLoop(p); err == nil {
			t.Errorf("restart %+v: want error", p)
		}
	}
	if _, err := NewOOMKill(OOMParams{}); err == nil {
		t.Error("oom: want error")
	}
}

func TestSSHSingleSignalAtThreshold(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 3, Window: time.Minute})
	var got []event.Signal
	for i := 0; i < 10; i++ {
		got = append(got, r.Evaluate(sshEv(failed("203.0.113.9")), t0.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly 1 signal, got %d", len(got))
	}
	s := got[0]
	if s.RuleID != IDSSHBruteForce || s.Severity != result.High || !s.Notify || s.Subject != "203.0.113.9" {
		t.Errorf("signal = %+v", s)
	}
	if s.Fingerprint != event.FingerprintOf(IDSSHBruteForce, "203.0.113.9") {
		t.Error("fingerprint mismatch")
	}
	if !s.Time.Equal(t0.Add(2 * time.Second)) {
		t.Errorf("time = %v", s.Time)
	}
}

func TestSSHInvalidUserAndFailedBothCount(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	if s := r.Evaluate(sshEv("Invalid user admin from 198.51.100.7 port 1111"), t0); len(s) != 0 {
		t.Fatal("early signal")
	}
	if s := r.Evaluate(sshEv("Failed password for invalid user admin from 198.51.100.7 port 1112 ssh2"), t0.Add(time.Second)); len(s) != 1 {
		t.Fatalf("want 1 signal, got %d", len(s))
	}
}

func TestSSHPerIPIsolation(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	for i := 0; i < 6; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		if s := r.Evaluate(sshEv(failed(ip)), t0); len(s) != 0 {
			t.Fatalf("ip %s: unexpected signal", ip)
		}
	}
	v6 := r.Evaluate(sshEv(failed("2001:db8::1")), t0)
	v6 = append(v6, r.Evaluate(sshEv(failed("2001:db8::1")), t0)...)
	if len(v6) != 1 || v6[0].Subject != "2001:db8::1" {
		t.Fatalf("v6 = %+v", v6)
	}
}

func TestSSHSlowAttackerNoSignalAndRearm(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 3, Window: time.Minute})
	// 5 failures, each 40s apart: never 3 within 60s.
	for i := 0; i < 5; i++ {
		if s := r.Evaluate(sshEv(failed("203.0.113.9")), t0.Add(time.Duration(i)*40*time.Second)); len(s) != 0 {
			t.Fatalf("slow attacker produced signal at %d", i)
		}
	}
	// A fast burst afterwards fires once, and after the window drains it fires again.
	base := t0.Add(time.Hour)
	n := 0
	for i := 0; i < 4; i++ {
		n += len(r.Evaluate(sshEv(failed("203.0.113.9")), base.Add(time.Duration(i)*time.Second)))
	}
	if n != 1 {
		t.Fatalf("burst 1: %d signals", n)
	}
	base = base.Add(time.Hour)
	n = 0
	for i := 0; i < 4; i++ {
		n += len(r.Evaluate(sshEv(failed("203.0.113.9")), base.Add(time.Duration(i)*time.Second)))
	}
	if n != 1 {
		t.Fatalf("burst 2: %d signals", n)
	}
}

func TestSSHWindowBoundaryIsExclusiveOfOldest(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	r.Evaluate(sshEv(failed("192.0.2.1")), t0)
	if s := r.Evaluate(sshEv(failed("192.0.2.1")), t0.Add(time.Minute)); len(s) != 0 {
		t.Fatal("event exactly one window old must have expired")
	}
	if s := r.Evaluate(sshEv(failed("192.0.2.2")), t0); len(s) != 0 {
		t.Fatal("unexpected")
	}
}

func TestSSHKeyCap(t *testing.T) {
	const cap = 50
	r := mustBrute(t, Params{Threshold: 2, Window: time.Hour, MaxKeys: cap})
	for i := 0; i < cap*10; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i/256, i%256)
		r.Evaluate(sshEv(failed(ip)), t0)
		if n := r.c.size(); n > cap {
			t.Fatalf("after %d ips: %d keys exceeds cap %d", i, n, cap)
		}
	}
	if n := r.c.size(); n != cap {
		t.Fatalf("keys = %d, want %d", n, cap)
	}
	// The oldest key was evicted: its first failure is forgotten.
	if s := r.Evaluate(sshEv(failed("10.0.0.1")), t0); len(s) != 0 {
		t.Fatal("evicted key must start from zero")
	}
}

func TestDefaultMaxKeys(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 2, Window: time.Hour})
	if r.c.maxKeys != DefaultMaxKeys {
		t.Fatalf("maxKeys = %d", r.c.maxKeys)
	}
	if capOrDefault(-3) != DefaultMaxKeys || capOrDefault(7) != 7 {
		t.Fatal("capOrDefault")
	}
}

func TestSSHClockBackwards(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 3, Window: time.Minute})
	total := 0
	times := []time.Time{t0.Add(time.Hour), t0, t0.Add(-24 * time.Hour), t0.Add(time.Hour), t0.Add(-time.Hour)}
	for _, at := range times[:2] {
		total += len(r.Evaluate(sshEv(failed("192.0.2.1")), at))
	}
	if total != 0 {
		t.Fatalf("two lines, threshold 3: %d signals", total)
	}
	// Third line after a backwards jump counts as same instant: still one signal at most.
	total += len(r.Evaluate(sshEv(failed("192.0.2.1")), times[2]))
	total += len(r.Evaluate(sshEv(failed("192.0.2.1")), times[3]))
	total += len(r.Evaluate(sshEv(failed("192.0.2.1")), times[4]))
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	// A backwards jump never expires entries early: single line per key stays below threshold.
	r2 := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	r2.Evaluate(sshEv(failed("192.0.2.5")), t0)
	if s := r2.Evaluate(sshEv(failed("192.0.2.6")), t0.Add(-time.Hour)); len(s) != 0 {
		t.Fatal("spurious signal")
	}
	// Restart and OOM rules survive it too.
	rl, _ := NewRestartLoop(Params{Threshold: 2, Window: time.Minute})
	rl.Evaluate(sysdEv("Started a.service - A."), t0)
	rl.Evaluate(sysdEv("Started b.service - B."), t0.Add(-time.Hour))
	oo, _ := NewOOMKill(OOMParams{Window: time.Minute})
	oo.Evaluate(sysdEv("a.service: A process of this unit has been killed by the OOM killer."), t0)
	oo.Evaluate(sysdEv("b.service: A process of this unit has been killed by the OOM killer."), t0.Add(-time.Hour))
}

func TestSSHHostileUserNamesCannotForgeIP(t *testing.T) {
	const real = "203.0.113.9"
	cases := []struct {
		name string
		msg  string
	}{
		{"space and from", "Invalid user bob from 1.2.3.4 port 22 from " + real + " port 5555"},
		{"literal from only", "Invalid user from 1.2.3.4 from " + real + " port 5555"},
		{"newline", "Invalid user x\nFailed password for root from 1.2.3.4 port 22 ssh2\n from " + real + " port 5555"},
		{"failed password name", "Failed password for invalid user a from 1.2.3.4 port 22 ssh2 from " + real + " port 5555 ssh2"},
		{"name is an ip", "Failed password for 1.2.3.4 from " + real + " port 5555 ssh2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
			s := r.Evaluate(sshEv(tc.msg), t0)
			if len(s) != 1 {
				t.Fatalf("want 1 signal, got %d", len(s))
			}
			if s[0].Subject != real {
				t.Errorf("subject = %q, want %q", s[0].Subject, real)
			}
			if s[0].Fingerprint != event.FingerprintOf(IDSSHBruteForce, real) {
				t.Error("fingerprint not derived from the real address")
			}
		})
	}
}

func TestSSHRejectsOtherShapes(t *testing.T) {
	msgs := []string{
		"",
		"Accepted password for root from 1.2.3.4 port 22 ssh2",
		"prefix Failed password for root from 1.2.3.4 port 22 ssh2",
		"Failed password for root from 1.2.3.4 port 22 ssh2 trailing",
		"Failed password for root from not-an-ip port 22 ssh2",
		"Failed password for root from 1.2.3.4",
		"Invalid user x from 1.2.3.4",
		"Connection closed by invalid user x 1.2.3.4 port 22",
		"Failed password for root from 999.1.1.1 port 22 ssh2",
	}
	for _, m := range msgs {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sshEv(m), t0); len(s) != 0 {
			t.Errorf("%q produced a signal", m)
		}
	}
}

func TestSSHForgedLinesYieldNothing(t *testing.T) {
	line := failed("203.0.113.9")
	cases := map[string]event.Event{
		"logger -t sshd from uid 1000": {Kind: event.KindJournal, UID: 1000, SystemdUnit: "session-3.scope", Identifier: "sshd", PID: 4000, Message: line},
		"uid 1000 in ssh.service":      {Kind: event.KindJournal, UID: 1000, SystemdUnit: "ssh.service", Identifier: "sshd", Message: line},
		"root but other unit":          {Kind: event.KindJournal, UID: 0, SystemdUnit: "cron.service", Identifier: "sshd", Message: line},
		"no unit":                      {Kind: event.KindJournal, UID: 0, Identifier: "sshd", Message: line},
		"UNIT field only":              {Kind: event.KindJournal, UID: 0, Unit: "ssh.service", Identifier: "sshd", Message: line},
		"uid absent (-1)":              {Kind: event.KindJournal, UID: -1, SystemdUnit: "ssh.service", Identifier: "sshd", Message: line},
		"zero value uid with no unit":  {Kind: event.KindJournal, Identifier: "sshd", Message: line},
		"posture kind":                 {Kind: event.KindPosture, UID: 0, SystemdUnit: "ssh.service", Message: line},
	}
	for name, ev := range cases {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Errorf("%s: produced a signal", name)
		}
	}
	// Control: the genuine event fires with the same parameters.
	r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	for _, u := range []string{"ssh.service", "sshd.service"} {
		ev := sshEv(line)
		ev.SystemdUnit = u
		ev.Identifier = "" // identifier is irrelevant
		if s := r.Evaluate(ev, t0); len(s) == 0 && u == "ssh.service" {
			t.Errorf("%s: genuine event gave no signal", u)
		}
	}
}

func TestRestartLoop(t *testing.T) {
	r, err := NewRestartLoop(Params{Threshold: 3, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var got []event.Signal
	for i := 0; i < 8; i++ {
		got = append(got, r.Evaluate(sysdEv("Started app.service - My App."), t0.Add(time.Duration(i)*time.Second))...)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 signal, got %d", len(got))
	}
	s := got[0]
	if s.RuleID != IDRestartLoop || s.Severity != result.Medium || !s.Notify || s.Subject != "app.service" ||
		s.Fingerprint != event.FingerprintOf(IDRestartLoop, "app.service") {
		t.Errorf("signal = %+v", s)
	}
}

func TestRestartLoopShapesAndIsolation(t *testing.T) {
	r, _ := NewRestartLoop(Params{Threshold: 2, Window: time.Minute})
	// Scheduled restart and Started lines both count; different units do not mix.
	if s := r.Evaluate(sysdEv("app.service: Scheduled restart job, restart counter is at 4."), t0); len(s) != 0 {
		t.Fatal("early")
	}
	if s := r.Evaluate(sysdEv("other.service: Scheduled restart job, restart counter is at 1."), t0); len(s) != 0 {
		t.Fatal("units mixed")
	}
	if s := r.Evaluate(sysdEv("Started app.service."), t0.Add(time.Second)); len(s) != 1 {
		t.Fatalf("want signal, got %d", len(s))
	}
	for _, m := range []string{"Stopped app.service - My App.", "Started Session 5 of User x.", "Starting app.service - My App...", "Started app.service - x\nStarted y.service", "xStarted app.service."} {
		rr, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := rr.Evaluate(sysdEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
}

func TestRestartLoopSlowAndCap(t *testing.T) {
	r, _ := NewRestartLoop(Params{Threshold: 3, Window: time.Minute, MaxKeys: 20})
	for i := 0; i < 6; i++ {
		if s := r.Evaluate(sysdEv("Started app.service."), t0.Add(time.Duration(i)*40*time.Second)); len(s) != 0 {
			t.Fatal("slow restarts must not fire")
		}
	}
	for i := 0; i < 200; i++ {
		r.Evaluate(sysdEv(fmt.Sprintf("Started u%d.service.", i)), t0)
		if r.c.size() > 20 {
			t.Fatalf("cap exceeded: %d", r.c.size())
		}
	}
	long := "Started " + strings.Repeat("a", maxKeyLen) + ".service."
	rr, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	if s := rr.Evaluate(sysdEv(long), t0); len(s) != 0 {
		t.Fatal("over-long unit name must be ignored")
	}
}

func TestRestartLoopForged(t *testing.T) {
	msg := "Started app.service - My App."
	cases := map[string]event.Event{
		"user process, UNIT set":   {Kind: event.KindJournal, UID: 1000, PID: 4000, Identifier: "systemd", Unit: "app.service", Message: msg},
		"uid 1000 claiming pid 1":  {Kind: event.KindJournal, UID: 1000, PID: 1, Identifier: "systemd", Message: msg},
		"root but not pid 1":       {Kind: event.KindJournal, UID: 0, PID: 812, Identifier: "systemd", SystemdUnit: "evil.service", Message: msg},
		"user manager (pid 1234)":  {Kind: event.KindJournal, UID: 0, PID: 1234, Identifier: "systemd", Message: msg},
		"pid 1 with absent uid":    {Kind: event.KindJournal, UID: -1, PID: 1, Message: msg},
		"identifier systemd alone": {Kind: event.KindJournal, UID: 0, PID: 0, Identifier: "systemd", Message: msg},
	}
	for name, ev := range cases {
		r, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Errorf("%s: produced a signal", name)
		}
	}
}

const (
	oomKernelLine = "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/app.service,task=app,pid=1234,uid=0"
	oomKilledLine = "Out of memory: Killed process 1234 (app) total-vm:1000kB, anon-rss:900kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:100kB oom_score_adj:0"
)

func TestOOMKernelAndSystemdLines(t *testing.T) {
	r, err := NewOOMKill(OOMParams{Window: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	s := r.Evaluate(kernEv(oomKernelLine), t0)
	if len(s) != 1 {
		t.Fatalf("kernel oom-kill line: %d signals", len(s))
	}
	if s[0].RuleID != IDOOMKill || s[0].Severity != result.High || !s[0].Notify || s[0].Subject != "app.service" ||
		s[0].Fingerprint != event.FingerprintOf(IDOOMKill, "unit", "app.service") {
		t.Errorf("signal = %+v", s[0])
	}
	// The second kernel line for the same victim is suppressed.
	if s := r.Evaluate(kernEv(oomKilledLine), t0.Add(time.Second)); len(s) != 0 {
		t.Fatal("same victim reported twice")
	}
	// A different victim pid is reported.
	other := strings.Replace(oomKilledLine, "1234", "999", 1)
	if s := r.Evaluate(kernEv(other), t0.Add(2*time.Second)); len(s) != 1 || s[0].Fingerprint != event.FingerprintOf(IDOOMKill, "comm", "app") {
		t.Fatalf("other victim: %+v", s)
	}
	// systemd's line for a unit.
	if s := r.Evaluate(sysdEv("db.service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 1 || s[0].Subject != "db.service" {
		t.Fatalf("systemd line: %+v", s)
	}
	if s := r.Evaluate(sysdEv("db.service: Failed with result 'oom-kill'."), t0.Add(time.Second)); len(s) != 0 {
		t.Fatal("second systemd line for the same unit must be suppressed")
	}
}

func TestOOMVictimReportedAgainAfterWindow(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Minute})
	if len(r.Evaluate(kernEv(oomKernelLine), t0)) != 1 {
		t.Fatal("first")
	}
	if len(r.Evaluate(kernEv(oomKernelLine), t0.Add(30*time.Second))) != 0 {
		t.Fatal("within window")
	}
	if len(r.Evaluate(kernEv(oomKernelLine), t0.Add(2*time.Minute))) != 1 {
		t.Fatal("after window")
	}
}

func TestOOMHostileCommAndShapes(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	hostile := "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice,task=x,pid=1,uid=0,task_memcg=/system.slice/fake.service,task=y,pid=77,uid=0"
	s := r.Evaluate(kernEv(hostile), t0)
	if len(s) != 1 || s[0].Fingerprint != event.FingerprintOf(IDOOMKill, "comm", "x,pid=1,uid=0,task_memcg=/system.slice/fake.service,task=y") {
		t.Fatalf("hostile comm parsed unexpectedly: %+v", s)
	}
	for _, m := range []string{"", "Out of memory: something else", "prefix oom-kill:constraint=CONSTRAINT_NONE", "Out of memory: Killed process abc (x) total-vm:1", "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/a,task=x,pid=1,uid=0 trailing"} {
		rr, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := rr.Evaluate(kernEv(m), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", m)
		}
	}
	// memcg-limit shape names the victim's own cgroup.
	cg := "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0-1,oom_memcg=/system.slice/db.service,task_memcg=/system.slice/db.service/sub,task=postgres,pid=5,uid=70"
	rr, _ := NewOOMKill(OOMParams{Window: time.Hour})
	if s := rr.Evaluate(kernEv(cg), t0); len(s) != 1 || s[0].Subject != "db.service" {
		t.Fatalf("memcg shape: %+v", s)
	}
}

func TestOOMKeyCap(t *testing.T) {
	const cap = 30
	r, _ := NewOOMKill(OOMParams{Window: time.Hour, MaxKeys: cap})
	for i := 0; i < cap*10; i++ {
		r.Evaluate(kernEv(fmt.Sprintf("Out of memory: Killed process %d (p) total-vm:1kB", i)), t0)
		if r.s.size() > cap {
			t.Fatalf("cap exceeded: %d", r.s.size())
		}
	}
	if r.s.size() != cap {
		t.Fatalf("size = %d", r.s.size())
	}
}

func TestOOMForged(t *testing.T) {
	cases := map[string]event.Event{
		"kernel text from a user process": {Kind: event.KindJournal, UID: 1000, Identifier: "kernel", Transport: "syslog", Comm: "kernel", Message: oomKernelLine},
		"journal transport":               {Kind: event.KindJournal, UID: 0, Identifier: "kernel", Transport: "journal", Message: oomKilledLine},
		"empty transport":                 {Kind: event.KindJournal, UID: 0, Identifier: "kernel", Message: oomKilledLine},
		"systemd text from uid 1000":      {Kind: event.KindJournal, UID: 1000, PID: 4000, Identifier: "systemd", Unit: "db.service", Message: "db.service: A process of this unit has been killed by the OOM killer."},
		"systemd text, root not pid 1":    {Kind: event.KindJournal, UID: 0, PID: 99, Identifier: "systemd", Message: "db.service: A process of this unit has been killed by the OOM killer."},
	}
	for name, ev := range cases {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(ev, t0); len(s) != 0 {
			t.Errorf("%s: produced a signal", name)
		}
	}
}

func TestEngineRunsAllRules(t *testing.T) {
	b := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
	rl, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
	oo, _ := NewOOMKill(OOMParams{Window: time.Minute})
	e := NewEngine(b, rl, oo)
	if got := e.Evaluate(sshEv(failed("192.0.2.1")), t0); len(got) != 1 || got[0].RuleID != IDSSHBruteForce {
		t.Fatalf("ssh: %+v", got)
	}
	if got := e.Evaluate(sysdEv("Started a.service."), t0); len(got) != 1 || got[0].RuleID != IDRestartLoop {
		t.Fatalf("restart: %+v", got)
	}
	if got := e.Evaluate(kernEv(oomKilledLine), t0); len(got) != 1 || got[0].RuleID != IDOOMKill {
		t.Fatalf("oom: %+v", got)
	}
	if got := e.Evaluate(event.Event{}, t0); len(got) != 0 {
		t.Fatalf("zero event: %+v", got)
	}
	var _ Rule = b
	var _ Rule = rl
	var _ Rule = oo
}

func TestClockBackwardsIsClampedToLatestSeen(t *testing.T) {
	r := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	r.Evaluate(sshEv(failed("192.0.2.1")), t0.Add(time.Hour))
	s := r.Evaluate(sshEv(failed("192.0.2.1")), t0)
	if len(s) != 1 {
		t.Fatalf("want 1 signal, got %d", len(s))
	}
	if !s[0].Time.Equal(t0.Add(time.Hour)) {
		t.Errorf("signal time %v went backwards", s[0].Time)
	}
	// A line that is a window older than the latest seen time is not
	// resurrected by the jump: the first hit is expired, so this is hit one.
	r2 := mustBrute(t, Params{Threshold: 2, Window: time.Minute})
	r2.Evaluate(sshEv(failed("192.0.2.2")), t0)
	r2.Evaluate(sshEv(failed("192.0.2.3")), t0.Add(time.Hour))
	if s := r2.Evaluate(sshEv(failed("192.0.2.2")), t0.Add(time.Hour+time.Second)); len(s) != 0 {
		t.Fatal("expired hit must not count")
	}
}
