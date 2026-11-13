package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// The tests in this file go field by field through the text a rule parses
// and that someone other than root on the host can choose: cgroup names
// (below a user manager, or as root in a container), command names, ssh user
// names, and text that PID 1 repeats in its own lines. Each case puts the
// delimiters or the marker text of the line shape into such a field and
// checks that the identity of the signal does not follow it.

// containerID stands for the 64 hex digits of a container id in a captured
// line.
var containerID = strings.Repeat("ab", 32)

// oomSummary builds the kernel's kill summary. scope is "global_oom" or
// "oom_memcg=<path>".
func oomSummary(cpuset, scope, taskMemcg, comm string, pid, uid int) string {
	return fmt.Sprintf("oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=%s,mems_allowed=0,%s,task_memcg=%s,task=%s,pid=%d,uid=%d",
		cpuset, scope, taskMemcg, comm, pid, uid)
}

func killedLine(comm string, pid int) string {
	return fmt.Sprintf("Memory cgroup out of memory: Killed process %d (%s) total-vm:26940kB, anon-rss:24448kB, file-rss:1280kB, shmem-rss:0kB, UID:1000 pgtables:96kB oom_score_adj:0", pid, comm)
}

// userManagerEv is a line of the service manager of uid 1000. It is the same
// program as PID 1 and carries the same identifier and command name; only
// the uid and the pid journald records tell the two apart.
func userManagerEv(msg string) event.Event {
	ev := sysdEv(msg)
	ev.UID, ev.PID, ev.SystemdUnit = 1000, 347, "user@1000.service"
	return ev
}

var (
	unitFP = func(unit string) event.Fingerprint { return event.FingerprintOf(IDOOMKill, "unit", unit) }
	commFP = func(comm string) event.Fingerprint { return event.FingerprintOf(IDOOMKill, "comm", comm) }
)

// The line a user without privileges produced on Ubuntu 22.04 and 24.04: a
// cgroup below the user manager, created with mkdir, whose directory names
// are "a,task_memcg=", "system.slice" and "postgresql.service,task=x". The
// container id is replaced; nothing else is changed.
func capturedCommaLine() string {
	p := "/docker/" + containerID + "/user.slice/user-1000.slice/user@1000.service/a,task_memcg=/system.slice/postgresql.service,task=x"
	return "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=" + containerID + ",mems_allowed=0,oom_memcg=" + p + ",task_memcg=" + p + ",task=tail,pid=352057,uid=1000"
}

// TestSweepOOMCapturedCommaCgroup: the captured line must not report, mark or
// fingerprint postgresql.service, and a real kill of that unit afterwards is
// still reported.
func TestSweepOOMCapturedCommaCgroup(t *testing.T) {
	hostForm := strings.ReplaceAll(strings.Replace(capturedCommaLine(), "cpuset="+containerID, "cpuset=/", 1), "/docker/"+containerID, "")
	if !strings.Contains(hostForm, ",oom_memcg=/user.slice/user-1000.slice/user@1000.service/a,task_memcg=/system.slice/postgresql.service,task=x,task_memcg=/user.slice/") {
		t.Fatalf("host form not built: %q", hostForm)
	}
	for name, line := range map[string]string{"as captured in a container": capturedCommaLine(), "as a host prints it": hostForm} {
		t.Run(name, func(t *testing.T) {
			r, _ := NewOOMKill(OOMParams{Window: time.Hour})
			s := r.Evaluate(kernEv(line), t0)
			if len(s) != 1 || s[0].Subject != "tail" || s[0].Fingerprint != commFP("tail") {
				t.Fatalf("comma cgroup line: %+v", s)
			}
			if s[0].Summary != "out of memory: process tail was killed by the OOM killer" {
				t.Fatalf("summary: %q", s[0].Summary)
			}
			// The kernel's second line and the user manager's own line (not PID 1) add nothing.
			if s := r.Evaluate(kernEv(killedLine("tail", 352057)), t0); len(s) != 0 {
				t.Fatalf("Killed line of the same victim: %+v", s)
			}
			if s := r.Evaluate(userManagerEv("-.slice: A process of this unit has been killed by the OOM killer."), t0); len(s) != 0 {
				t.Fatalf("user manager line: %+v", s)
			}
			// The user manager also names units of its own; a name it shares with a system unit is not that unit.
			if s := r.Evaluate(userManagerEv("postgresql.service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 0 {
				t.Fatalf("user manager line for a unit of its own: %+v", s)
			}
			// PID 1 names the unit the kill really happened in.
			if s := r.Evaluate(sysdEv("user@1000.service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 1 || s[0].Fingerprint != unitFP("user@1000.service") {
				t.Fatalf("PID 1 line for the user manager: %+v", s)
			}
			// Ten minutes later, inside the window, postgresql.service is really killed.
			var got []event.Signal
			for i, ev := range killLines("postgresql.service", 812) {
				got = append(got, r.Evaluate(ev, t0.Add(10*time.Minute+time.Duration(i)*time.Millisecond))...)
			}
			if len(got) != 1 || got[0].Subject != "postgresql.service" || got[0].Fingerprint != unitFP("postgresql.service") {
				t.Fatalf("real kill of postgresql.service after the forged line: %+v", got)
			}
		})
	}
}

// TestSweepOOMKillSummaryFields puts commas, line breaks and field names into
// each name of the kill summary. want is the subject; a unit is expected only
// where wantUnit is set.
func TestSweepOOMKillSummaryFields(t *testing.T) {
	const (
		svc  = "/system.slice/app.service"
		user = "/user.slice/user-1000.slice/user@1000.service"
	)
	cases := []struct {
		name     string
		line     string
		want     string
		wantUnit bool
		// pairs: the Killed line of the same pid and command name adds no signal.
		pairs bool
	}{
		// Controls: the same shapes without hostile text give the unit.
		{"control, cgroup kill in the unit's own cgroup", oomSummary("/", "oom_memcg="+svc, svc, "tail", 77, 0), "app.service", true, true},
		{"control, victim below the limited cgroup", oomSummary("/", "oom_memcg="+svc, svc+"/sub", "tail", 77, 0), "app.service", true, true},
		{"control, global kill", oomSummary("/", "global_oom", svc, "tail", 77, 0), "app.service", true, true},
		{"control, limit on the root cgroup", oomSummary("/", "oom_memcg=/", svc, "tail", 77, 0), "app.service", true, true},
		{"control, limit on a slice", oomSummary("/", "oom_memcg=/system.slice", svc, "tail", 77, 0), "app.service", true, true},

		// cpuset: the name of one cgroup directory.
		{"cpuset name with a comma", oomSummary("a,b", "oom_memcg="+svc, svc, "tail", 77, 0), "tail", false, true},
		{"cpuset name ending in a comma", oomSummary("a,", "oom_memcg="+svc, svc, "tail", 77, 0), "tail", false, true},
		{"cpuset name that carries the rest of a summary", oomSummary("x,mems_allowed=0,global_oom,task_memcg=/system.slice/postgresql.service,task=y,pid=1,uid=0", "oom_memcg=/docker/c1", "/docker/c1", "tail", 77, 0), "tail", false, true},
		{"cpuset name that makes the kill look global", oomSummary("x,mems_allowed=0,global_oom", "oom_memcg="+svc, svc, "tail", 77, 0), "tail", false, true},
		{"cpuset name that carries a cgroup scope", oomSummary("x,mems_allowed=0,oom_memcg=/system.slice/postgresql.service", "oom_memcg="+svc, svc, "tail", 77, 0), "tail", false, true},

		// oom_memcg: the path of the limited cgroup.
		{"comma in oom_memcg only", oomSummary("/", "oom_memcg="+svc+",y", svc, "tail", 77, 0), "tail", false, true},
		{"task_memcg text in oom_memcg", oomSummary("/", "oom_memcg="+user+"/a,task_memcg=/system.slice/postgresql.service", user+"/a,task_memcg=/system.slice/postgresql.service/x", "tail", 77, 1000), "tail", false, true},
		{"task text in oom_memcg", oomSummary("/", "oom_memcg="+user+"/a,task=x", user+"/b", "tail", 77, 1000), "tail", false, true},

		// task_memcg: the path of the victim's cgroup.
		{"comma in task_memcg only", oomSummary("/", "oom_memcg="+svc, svc+"/a,b", "tail", 77, 0), "tail", false, true},
		{"comma in both paths", oomSummary("/", "oom_memcg="+user+"/a,b", user+"/a,b", "tail", 77, 1000), "tail", false, true},
		{"task text in task_memcg", oomSummary("/", "oom_memcg="+svc, svc+"/a,task=y", "tail", 77, 0), "tail", false, true},
		{"pid and uid text in task_memcg", oomSummary("/", "oom_memcg="+svc, svc+"/a,pid=1,uid=0", "tail", 77, 0), "tail", false, true},
		{"a whole summary tail in task_memcg", oomSummary("/", "global_oom", "/user.slice,task=x,pid=1,uid=0,task_memcg=/system.slice/postgresql.service", "tail", 77, 0), "tail", false, true},
		{"victim outside the limited cgroup", oomSummary("/", "oom_memcg=/system.slice/a.service", "/system.slice/postgresql.service", "tail", 77, 0), "tail", false, true},
		{"limited cgroup is only a name prefix", oomSummary("/", "oom_memcg=/system.slice/db", "/system.slice/db.service", "tail", 77, 0), "tail", false, true},
		{"unit name below a user manager", oomSummary("/", "oom_memcg="+user+"/app.slice/postgresql.service", user+"/app.slice/postgresql.service", "tail", 77, 1000), "user@1000.service", true, true},
		{"unit name below a container", oomSummary(containerID, "oom_memcg=/docker/"+containerID+"/system.slice/postgresql.service", "/docker/"+containerID+"/system.slice/postgresql.service", "tail", 77, 0), "tail", false, true},

		// A line break in a name is treated like a comma: no unit. The
		// other fields of each case are those of a control above.
		{"cpuset name with a line break", oomSummary("a\nb", "oom_memcg="+svc, svc, "tail", 77, 0), "tail", false, true},
		{"cpuset name with a line break, global kill", oomSummary("a\nb", "global_oom", svc, "tail", 77, 0), "tail", false, true},
		{"line break in oom_memcg, consistent task_memcg below a user manager", oomSummary("/", "oom_memcg="+user+"/a\nb", user+"/a\nb", "tail", 77, 1000), "tail", false, true},
		{"line break in oom_memcg, victim below it", oomSummary("/", "oom_memcg="+user+"/a\nb", user+"/a\nb/c", "tail", 77, 1000), "tail", false, true},
		{"line break in task_memcg only", oomSummary("/", "oom_memcg="+svc, svc+"/a\nb", "tail", 77, 0), "tail", false, true},
		{"line break in task_memcg only, global kill", oomSummary("/", "global_oom", svc+"/a\nb", "tail", 77, 0), "tail", false, true},
		{"line break in task_memcg below a user manager", oomSummary("/", "oom_memcg="+user, user+"/a\nb", "tail", 77, 1000), "tail", false, true},
		{"line break at the end of task_memcg", oomSummary("/", "oom_memcg="+svc, svc+"\n", "tail", 77, 0), "tail", false, true},
		{"line break in a slice name above a unit name", oomSummary("/", "global_oom", "/a\nb.slice/postgresql.service", "tail", 77, 0), "tail", false, true},

		// Fields the kernel writes itself, read strictly before a unit is derived.
		{"mems_allowed is not a node list", strings.Replace(oomSummary("/", "global_oom", svc, "tail", 77, 0), "mems_allowed=0", "mems_allowed=x", 1), "tail", false, true},
		{"neither global_oom nor oom_memcg", strings.Replace(oomSummary("/", "global_oom", svc, "tail", 77, 0), "global_oom", "other", 1), "tail", false, true},
		{"no cgroup fields at all", "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,task=tail,pid=77,uid=0", "tail", false, true},
		{"text after the task_memcg path", strings.Replace(oomSummary("/", "global_oom", svc, "tail", 77, 0), ",task=tail", ",x,task=tail", 1), "tail", false, true},

		// task: the command name, at most 15 bytes chosen by the process.
		{"command name with pid and uid text", oomSummary("/", "oom_memcg="+svc, svc, "x,pid=1,uid=0", 77, 0), "app.service", true, true},
		{"command name with a comma", oomSummary("/", "oom_memcg="+svc, svc, "a,b", 77, 0), "app.service", true, true},
		{"command name with a space", oomSummary("/", "oom_memcg="+svc, svc, "a b", 77, 0), "app.service", true, true},
		{"command name with a newline", oomSummary("/", "oom_memcg="+svc, svc, "a\nb", 77, 0), "app.service", true, true},
		{"command name with a newline, no unit", oomSummary("/", "oom_memcg=/docker/c1", "/docker/c1", "a\nb", 77, 0), "a\nb", false, true},
		{"command name with task text", oomSummary("/", "oom_memcg="+svc, svc, "a,task=b", 77, 0), "b", false, false},
		{"command name with task_memcg text", oomSummary("/", "oom_memcg="+svc, svc, ",task_memcg=/x", 77, 0), ",task_memcg=/x", false, true},
		{"command name that is a unit name", oomSummary("/", "oom_memcg=/user.slice/user-1000.slice/session-3.scope", "/user.slice/user-1000.slice/session-3.scope", "cron.service", 77, 1000), "cron.service", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := NewOOMKill(OOMParams{Window: time.Hour})
			s := r.Evaluate(kernEv(c.line), t0)
			if len(s) != 1 {
				t.Fatalf("%d signals, want 1: %+v", len(s), s)
			}
			wantFP := commFP(c.want)
			if c.wantUnit {
				wantFP = unitFP(c.want)
			}
			if s[0].Subject != c.want || s[0].Fingerprint != wantFP {
				t.Fatalf("subject %q, unit=%v; want %q, unit=%v", s[0].Subject, s[0].Fingerprint == unitFP(s[0].Subject), c.want, c.wantUnit)
			}
			if s[0].Fingerprint == unitFP("postgresql.service") {
				t.Fatal("a name in the summary steered the fingerprint to postgresql.service")
			}
			// The pid is the kernel's: the Killed line of pid 77 is the same victim.
			comm := c.line[strings.LastIndex(c.line, ",task=")+len(",task="):]
			comm = comm[:strings.LastIndex(comm, ",pid=")]
			if !c.pairs {
				comm = "a,task=b"
			}
			n := len(r.Evaluate(kernEv(killedLine(comm, 77)), t0))
			if c.pairs && n != 0 {
				t.Fatalf("Killed line of the same victim gave %d signals", n)
			}
			if !c.pairs && n != 1 {
				t.Fatalf("Killed line with the full command name gave %d signals, want 1", n)
			}
			// No summary marks a unit it does not name: postgresql.service is still reported.
			if s := r.Evaluate(sysdEv("postgresql.service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 1 {
				t.Fatalf("a later kill of postgresql.service was suppressed: %+v", s)
			}
		})
	}
}

// A process that names itself like a unit is reported as a process: other
// fingerprint, other summary, and the unit's own kill is still reported.
func TestSweepOOMCommandNameLikeAUnit(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	s := r.Evaluate(kernEv(killedLine("cron.service", 4000)), t0)
	if len(s) != 1 || s[0].Subject != "cron.service" || s[0].Fingerprint != commFP("cron.service") {
		t.Fatalf("process named like a unit: %+v", s)
	}
	if s[0].Fingerprint == unitFP("cron.service") {
		t.Fatal("a command name shares the fingerprint of a unit")
	}
	if s[0].Summary != "out of memory: process cron.service was killed by the OOM killer" {
		t.Fatalf("summary: %q", s[0].Summary)
	}
	u := r.Evaluate(sysdEv("cron.service: A process of this unit has been killed by the OOM killer."), t0)
	if len(u) != 1 || u[0].Fingerprint != unitFP("cron.service") || u[0].Summary != "out of memory: a process of unit cron.service was killed by the OOM killer" {
		t.Fatalf("the unit's own kill: %+v", u)
	}
	// A command name cannot stand for a victim key either.
	r2, _ := NewOOMKill(OOMParams{Window: time.Hour})
	r2.Evaluate(kernEv(killedLine("systemd/app.service", 7)), t0)
	if s := r2.Evaluate(sysdEv("app.service: A process of this unit has been killed by the OOM killer."), t0); len(s) != 1 {
		t.Fatalf("a command name marked a unit key: %+v", s)
	}
}

// The Killed process line: the pid is in front of the command name, and the
// name is everything up to the last ") total-vm:".
func TestSweepOOMKilledLineCommandNames(t *testing.T) {
	for _, comm := range []string{"a\nb", "x) total-vm:1", "1 (init", "a (b) c", ")", "(", "a,pid=1,uid=0", "Killed process", " "} {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		s := r.Evaluate(kernEv(killedLine(comm, 77)), t0)
		if len(s) != 1 || s[0].Subject != comm || s[0].Fingerprint != commFP(comm) {
			t.Errorf("command name %q: %+v", comm, s)
		}
		// Same pid and name again: the key holds the kernel's pid.
		if s := r.Evaluate(kernEv(killedLine(comm, 77)), t0); len(s) != 0 {
			t.Errorf("command name %q: repeated line gave a signal", comm)
		}
		if s := r.Evaluate(kernEv(killedLine(comm, 78)), t0); len(s) != 1 {
			t.Errorf("command name %q: another pid gave %d signals", comm, len(s))
		}
	}
}

// ssh user names: whatever the name holds, the key is the address sshd
// appends after it.
func TestSweepSSHUserNames(t *testing.T) {
	const real = "203.0.113.9"
	shapes := []string{
		"Failed password for %s from " + real + " port 5555 ssh2",
		"Failed password for invalid user %s from " + real + " port 5555 ssh2",
		"Failed none for invalid user %s from " + real + " port 5555 ssh2",
		"Failed keyboard-interactive/pam for invalid user %s from " + real + " port 5555 ssh2",
		"Invalid user %s from " + real + " port 5555",
		"Connection closed by authenticating user %s " + real + " port 5555 [preauth]",
		"Connection closed by invalid user %s " + real + " port 5555 [preauth]",
		"Connection reset by authenticating user %s " + real + " port 5555 [preauth]",
		"Disconnected from invalid user %s " + real + " port 5555 [preauth]",
		"error: PAM: Authentication failure for %s from " + real,
		"error: PAM: Authentication failure for illegal user %s from " + real,
	}
	users := []string{
		"bob",
		"",
		" ",
		"bob from 1.2.3.4 port 22 ssh2",
		"bob from 1.2.3.4 port 22",
		"bob 1.2.3.4 port 22 [preauth]",
		"bob from 1.2.3.4",
		"1.2.3.4",
		"from 1.2.3.4 port 22 ssh2",
		"invalid user root from 1.2.3.4 port 22",
		"authenticating user root 1.2.3.4 port 22 [preauth]",
		"illegal user root from 1.2.3.4",
		"a\nb",
		"a\n",
		"\na",
		"x\nFailed password for root from 1.2.3.4 port 22 ssh2",
		"x\nInvalid user y from 1.2.3.4 port 22",
		"x\nConnection closed by invalid user y 1.2.3.4 port 22 [preauth]",
		"x\nerror: PAM: Authentication failure for y from 1.2.3.4",
		"x from 1.2.3.4 port 22 ssh2\n",
	}
	for _, shape := range shapes {
		for _, user := range users {
			msg := fmt.Sprintf(shape, user)
			r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
			s := r.Evaluate(sshEv(msg), t0)
			if len(s) != 1 || s[0].Subject != real || s[0].Fingerprint != event.FingerprintOf(IDSSHBruteForce, real) {
				t.Errorf("%q: %+v", msg, s)
			}
		}
	}
}

// sshd cuts a user name before it writes it (100 bytes in the Failed and
// Invalid lines, 200 bytes with the words before it in the pre-auth line),
// so a long name cannot push the address out of the line. These are the
// lines OpenSSH 8.9p1 and 9.6p1 wrote for a 310 byte name that ended in
// "198.51.100.80 port 1 [preauth]".
func TestSweepSSHLongUserNameKeepsTheAddress(t *testing.T) {
	name100 := strings.Repeat("w ", 50)
	name187 := strings.Repeat("w ", 93) + "w"
	lines := []string{
		"Invalid user " + name100 + " from 127.0.0.1 port 60880",
		"Failed password for invalid user " + name100 + " from 127.0.0.1 port 60880 ssh2",
		"Connection closed by invalid user " + name187 + " 127.0.0.1 port 60880 [preauth]",
	}
	for i, want := range []int{139, 164, 252} {
		if len(lines[i]) != want {
			t.Fatalf("line %d is %d bytes, the captured line has %d", i, len(lines[i]), want)
		}
	}
	for _, l := range lines {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sshEv(l), t0); len(s) != 1 || s[0].Subject != "127.0.0.1" {
			t.Errorf("%q: %+v", l, s)
		}
	}
	// A line that ends inside the name (no address of sshd's own) is not counted.
	for _, l := range []string{
		"Invalid user " + name100,
		"Failed password for invalid user " + name100,
		"Connection closed by invalid user " + name187,
	} {
		r := mustBrute(t, Params{Threshold: 1, Window: time.Minute})
		if s := r.Evaluate(sshEv(l), t0); len(s) != 0 {
			t.Errorf("%q gave a signal", l)
		}
	}
}

// PID 1 repeats text chosen by others in its own lines (a unit description,
// the path of a mount point). Such text, followed by a line break and a
// complete line of the counted shape, is not a line of that shape.
func TestSweepSystemdEmbeddedLines(t *testing.T) {
	const restart = "app.service: Scheduled restart job, restart counter is at 1."
	const oom = "app.service: A process of this unit has been killed by the OOM killer."
	const failed = "app.service: Failed with result 'oom-kill'."
	for _, fake := range []string{restart, oom, failed} {
		for _, m := range []string{
			"Unmounted /home/mallory/x\n" + fake,
			"Mounted /home/mallory/x\n" + fake + "\n.",
			"Started Session 3 of User mallory.\n" + fake,
			"home-mallory-x.mount: Deactivated successfully.\n" + fake,
			fake + "\nx",
			fake + " " + fake,
			"x " + fake,
		} {
			rl, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
			if s := rl.Evaluate(sysdEv(m), t0); len(s) != 0 {
				t.Errorf("restart: %q gave a signal", m)
			}
			oo, _ := NewOOMKill(OOMParams{Window: time.Hour})
			if s := oo.Evaluate(sysdEv(m), t0); len(s) != 0 {
				t.Errorf("oom: %q gave a signal", m)
			}
		}
	}
	// A unit name takes no space, comma, slash or line break, so the name
	// in front of the colon is the whole name.
	for _, unit := range []string{"a b.service", "a,b.service", "a/b.service", "a\nb.service", "a.service b.service", "a.service: b.service"} {
		rl, _ := NewRestartLoop(Params{Threshold: 1, Window: time.Minute})
		if s := rl.Evaluate(sysdEv(unit+": Scheduled restart job, restart counter is at 1."), t0); len(s) != 0 {
			t.Errorf("restart: unit %q gave a signal", unit)
		}
		oo, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := oo.Evaluate(sysdEv(unit+": A process of this unit has been killed by the OOM killer."), t0); len(s) != 0 {
			t.Errorf("oom: unit %q gave a signal", unit)
		}
	}
}

func TestInCgroup(t *testing.T) {
	cases := []struct {
		path, root string
		want       bool
	}{
		{"/system.slice/a.service", "/system.slice/a.service", true},
		{"/system.slice/a.service/sub", "/system.slice/a.service", true},
		{"/system.slice/a.service", "/system.slice", true},
		{"/system.slice/a.service", "/", true},
		{"/", "/", true},
		{"/system.slice/a.service", "", true},
		{"/system.slice/b.service", "/system.slice/a.service", false},
		{"/system.slice/a.service2", "/system.slice/a.service", false},
		{"/system.slice", "/system.slice/a.service", false},
		{"system.slice/a.service", "/", false},
		{"", "/system.slice", false},
	}
	for _, c := range cases {
		if got := inCgroup(c.path, c.root); got != c.want {
			t.Errorf("inCgroup(%q, %q) = %v, want %v", c.path, c.root, got, c.want)
		}
	}
}
