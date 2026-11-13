package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

func groupLine(memcg string) event.Event {
	return kernEv("Tasks in " + memcg + " are going to be killed due to memory.oom.group set")
}

func killedEv(comm string, pid int) event.Event {
	return kernEv(killedLine(comm, pid))
}

func summaryEv(memcg, comm string, pid int) event.Event {
	return kernEv(oomSummary("/", "oom_memcg="+memcg, memcg, comm, pid, 0))
}

func invokedEv(comm string) event.Event {
	return kernEv(comm + " invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0")
}

// subjects runs evs through a fresh rule, one millisecond apart, and returns
// the subjects of the signals in order.
func subjects(t *testing.T, evs ...event.Event) []string {
	t.Helper()
	r, err := NewOOMKill(OOMParams{Window: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i, ev := range evs {
		for _, s := range r.Evaluate(ev, t0.Add(time.Duration(i)*time.Millisecond)) {
			out = append(out, s.Subject)
		}
	}
	return out
}

func wantSubjects(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("%s: signals %q, want %q", what, got, want)
	}
}

// memory.oom.group (OOMPolicy=kill), as the journal recorded it on 22.04 and
// 24.04: the kill summary and the victim's Killed line, the "Tasks in" line,
// then one Killed line per process of the cgroup (the victim again first),
// then systemd's lines. One kill, one signal.
func TestOOMGroupKillOneSignal(t *testing.T) {
	const memcg = "/system.slice/hoggroup.service"
	kernel := []event.Event{
		invokedEv("tail"),
		summaryEv(memcg, "tail", 349789),
		killedEv("tail", 349789),
		groupLine(memcg),
		killedEv("tail", 349789),
		killedEv("sleep", 349790),
		killedEv("sleep", 349791),
	}
	slices := []event.Event{
		sysdEv("system.slice: A process of this unit has been killed by the OOM killer."),
		sysdEv("-.slice: A process of this unit has been killed by the OOM killer."),
	}
	unit := []event.Event{
		sysdEv("hoggroup.service: A process of this unit has been killed by the OOM killer."),
		sysdEv("hoggroup.service: Main process exited, code=killed, status=9/KILL"),
		sysdEv("hoggroup.service: Failed with result 'oom-kill'."),
	}
	// 24.04 order: kernel lines, then PID 1.
	wantSubjects(t, "kernel first", subjects(t, append(append(append([]event.Event{}, kernel...), unit...), slices...)...), "hoggroup.service")
	// 22.04 order: PID 1's slice lines reach the journal before the kernel's.
	wantSubjects(t, "slices first", subjects(t, append(append(append([]event.Event{}, slices...), kernel...), unit...)...), "hoggroup.service")
	// PID 1's unit lines first.
	wantSubjects(t, "unit first", subjects(t, append(append([]event.Event{}, unit...), kernel...)...), "hoggroup.service")
	// The same lines as a container's kernel prints them (no unit can be derived): one signal by command name.
	c := "/docker/" + containerID + memcg
	wantSubjects(t, "container form", subjects(t,
		summaryEv(c, "tail", 349789), killedEv("tail", 349789), groupLine(c),
		killedEv("tail", 349789), killedEv("sleep", 349790), killedEv("sleep", 349791)), "tail")
}

// An episode covers the Killed lines that follow the "Tasks in" line and
// ends at the next kernel line of another shape.
func TestOOMGroupEpisodeEnds(t *testing.T) {
	const memcg = "/system.slice/hoggroup.service"
	open := []event.Event{summaryEv(memcg, "tail", 100), killedEv("tail", 100), groupLine(memcg), killedEv("tail", 100), killedEv("sleep", 101)}
	with := func(more ...event.Event) []event.Event { return append(append([]event.Event{}, open...), more...) }

	// The next kill has its own summary: both of its lines are judged on their own.
	wantSubjects(t, "next kill with a summary", subjects(t, with(
		summaryEv("/docker/c1", "redis-server", 200), killedEv("redis-server", 200))...), "hoggroup.service", "redis-server")
	// After that summary the episode is over for later lines too.
	wantSubjects(t, "summary ends the episode", subjects(t, with(
		summaryEv("/docker/c1", "redis-server", 200), killedEv("redis-server", 200), killedEv("node", 300))...), "hoggroup.service", "redis-server", "node")
	// A summary that is itself suppressed (same victim again) ends it as well.
	wantSubjects(t, "suppressed summary ends the episode", subjects(t, with(
		summaryEv(memcg, "tail", 100), killedEv("node", 300))...), "hoggroup.service", "node")
	// Any other kernel line ends it.
	wantSubjects(t, "the next kill's first line ends the episode", subjects(t, with(
		invokedEv("node"), killedEv("node", 300))...), "hoggroup.service", "node")
	wantSubjects(t, "an unrelated kernel line ends the episode", subjects(t, with(
		kernEv("oom_reaper: reaped process 100 (tail), now anon-rss:0kB, file-rss:0kB, shmem-rss:0kB"), killedEv("node", 300))...), "hoggroup.service", "node")
	wantSubjects(t, "an empty kernel line ends the episode", subjects(t, with(kernEv(""), killedEv("node", 300))...), "hoggroup.service", "node")
	// Lines of other transports do not end it: the journal interleaves them.
	other := sshEv(failed("203.0.113.9"))
	forged := kernEv("x invoked oom-killer")
	forged.Transport, forged.UID = "syslog", 1000
	wantSubjects(t, "other transports do not end the episode", subjects(t, with(
		sysdEv("hoggroup.service: A process of this unit has been killed by the OOM killer."), other, forged, killedEv("sleep", 102))...), "hoggroup.service")
	// A second group kill opens its own episode after the first has ended.
	wantSubjects(t, "two group kills", subjects(t, with(
		summaryEv("/system.slice/other.service", "java", 500), killedEv("java", 500), groupLine("/system.slice/other.service"),
		killedEv("java", 500), killedEv("sh", 501))...), "hoggroup.service", "other.service")
	// Without a "Tasks in" line there is no episode, however close the lines are.
	wantSubjects(t, "no group line, no episode", subjects(t,
		summaryEv(memcg, "tail", 100), killedEv("tail", 100), killedEv("sleep", 101), killedEv("sleep", 102)), "hoggroup.service", "sleep", "sleep")
	// A Killed line long after the group's lines is still part of the episode
	// when no kernel line came between: there is no time window.
	r, _ := NewOOMKill(OOMParams{Window: time.Minute})
	n := 0
	for i, ev := range open {
		n += len(r.Evaluate(ev, t0.Add(time.Duration(i)*time.Millisecond)))
	}
	n += len(r.Evaluate(killedEv("sleep", 103), t0.Add(time.Hour)))
	if n != 1 {
		t.Errorf("late Killed line inside an open episode: %d signals, want 1", n)
	}
	if s := r.Evaluate(invokedEv("node"), t0.Add(time.Hour)); len(s) != 0 {
		t.Errorf("invoked line gave a signal: %+v", s)
	}
	if s := r.Evaluate(killedEv("node", 300), t0.Add(time.Hour)); len(s) != 1 {
		t.Errorf("Killed line after the episode ended: %+v", s)
	}
}

// Only the kernel's own "Tasks in" line opens an episode.
func TestOOMGroupLineShapes(t *testing.T) {
	const ok = "Tasks in /system.slice/hoggroup.service are going to be killed due to memory.oom.group set"
	opens := func(ev event.Event, now time.Time) bool {
		r, _ := NewOOMKill(OOMParams{Window: time.Hour})
		if s := r.Evaluate(ev, now); len(s) != 0 {
			t.Errorf("%q gave a signal", ev.Message)
		}
		return len(r.Evaluate(killedEv("sleep", 101), t0)) == 0
	}
	for _, m := range []string{
		ok,
		"Tasks in / are going to be killed due to memory.oom.group set",
		"Tasks in /user.slice/user-1000.slice/user@1000.service/a b, c are going to be killed due to memory.oom.group set",
		"Tasks in /docker/" + containerID + " are going to be killed due to memory.oom.group set",
	} {
		if !opens(kernEv(m), t0) {
			t.Errorf("%q did not open an episode", m)
		}
	}
	for _, m := range []string{
		"x " + ok,
		"x\n" + ok,
		ok + " x",
		ok + "\nx",
		ok + ".",
		"Tasks in system.slice/hoggroup.service are going to be killed due to memory.oom.group set",
		"Tasks in  are going to be killed due to memory.oom.group set",
		"Tasks in /a\nb are going to be killed due to memory.oom.group set",
		"Tasks in /system.slice/hoggroup.service are going to be killed due to memoryXoomXgroup set",
		"Tasks in /system.slice/hoggroup.service are going to be killed",
		"tasks in /system.slice/hoggroup.service are going to be killed due to memory.oom.group set",
		// A command name is the start of this kernel line; it cannot make it the group line.
		"Tasks in /x invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=0",
		"",
	} {
		if opens(kernEv(m), t0) {
			t.Errorf("%q opened an episode", m)
		}
	}
	// The same text from another transport, from a posture event or without a clock value opens nothing.
	user := kernEv(ok)
	user.Transport, user.UID, user.PID = "syslog", 1000, 4000
	if opens(user, t0) {
		t.Error("a user's line opened an episode")
	}
	pid1 := sysdEv(ok)
	if opens(pid1, t0) {
		t.Error("a line of PID 1 opened an episode")
	}
	posture := kernEv(ok)
	posture.Kind = event.KindPosture
	if opens(posture, t0) {
		t.Error("a posture event opened an episode")
	}
	if opens(kernEv(ok), time.Time{}) {
		t.Error("a line without a clock value opened an episode")
	}
}

// A zero clock value changes no state: it neither opens nor ends an episode.
func TestOOMGroupEpisodeZeroNow(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	r.Evaluate(groupLine("/system.slice/hoggroup.service"), t0)
	r.Evaluate(invokedEv("node"), time.Time{})
	posture := invokedEv("node")
	posture.Kind = event.KindPosture
	r.Evaluate(posture, t0)
	if s := r.Evaluate(killedEv("sleep", 101), t0); len(s) != 0 {
		t.Fatalf("a line without a clock value, or a posture event, ended the episode: %+v", s)
	}
}

// The kernel prints at most ten kill summaries per five seconds. This is the
// storm captured on 22.04: sixteen processes, each in its own cgroup, killed
// within 45 ms; the last six have a Killed line only. Every victim is
// reported.
func TestOOMStormReportsEveryVictim(t *testing.T) {
	order := []struct {
		n, pid  int
		summary bool
	}{
		{1, 352101, true}, {2, 352104, true}, {3, 352107, true}, {4, 352110, true}, {5, 352113, true},
		{7, 352119, true}, {6, 352116, true}, {9, 352125, true}, {8, 352122, true}, {10, 352128, true},
		{11, 352131, false}, {12, 352134, false}, {13, 352137, false}, {14, 352140, false}, {15, 352143, false}, {16, 352146, false},
	}
	var evs []event.Event
	var want []string
	summaries := 0
	for _, v := range order {
		comm := fmt.Sprintf("st%d", v.n)
		if v.summary {
			summaries++
			evs = append(evs, invokedEv(comm), summaryEv("/docker/"+containerID+"/kwc/"+comm, comm, v.pid))
		}
		evs = append(evs, killedEv(comm, v.pid))
		want = append(want, comm)
	}
	if summaries != 10 || len(want) != 16 {
		t.Fatalf("fixture: %d summaries, %d victims", summaries, len(want))
	}
	wantSubjects(t, "storm", subjects(t, evs...), want...)
}

// Captured on 22.04 and 24.04: a user without privileges has fourteen of
// their own units killed at once (ten with a kill summary, four without),
// and one second later a process outside any unit is killed, again without a
// summary. The foreign kill is reported. Paths are in the form a host
// prints.
func TestOOMForeignKillAfterUserKills(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	var got []string
	eval := func(ev event.Event, at time.Time) {
		for _, s := range r.Evaluate(ev, at) {
			got = append(got, s.Subject)
		}
	}
	withSummary := []int{352179, 352180, 352178, 352181, 352185, 352183, 352186, 352182, 352184, 352188}
	for i, pid := range withSummary {
		at := t0.Add(time.Duration(i) * time.Millisecond)
		unit := fmt.Sprintf("/user.slice/user-1000.slice/user@1000.service/app.slice/run-r%02d.service", i)
		eval(invokedEv("tail"), at)
		eval(kernEv(oomSummary("/", "oom_memcg="+unit, unit, "tail", pid, 1000)), at)
		eval(killedEv("tail", pid), at)
		if i == 3 {
			// PID 1 and the user manager report in between.
			eval(sysdEv("user@1000.service: A process of this unit has been killed by the OOM killer."), at)
			um := sysdEv("run-r00.service: A process of this unit has been killed by the OOM killer.")
			um.UID, um.PID, um.SystemdUnit = 1000, 347, "user@1000.service"
			eval(um, at)
		}
	}
	for i, pid := range []int{352190, 352187, 352189, 352191} {
		eval(killedEv("tail", pid), t0.Add(time.Duration(20+i)*time.Millisecond))
	}
	eval(kernEv("Memory cgroup out of memory: Killed process 352194 (foreign) total-vm:26652kB, anon-rss:24448kB, file-rss:768kB, shmem-rss:0kB, UID:0 pgtables:92kB oom_score_adj:0"), t0.Add(time.Second))
	wantSubjects(t, "user kills, then a foreign kill", got, "user@1000.service", "tail", "tail", "tail", "tail", "foreign")
}

// A group kill whose kill summary was rate limited: the victim's Killed line
// reports the kill by command name, and the group's lines add nothing.
func TestOOMGroupKillWithoutSummary(t *testing.T) {
	const memcg = "/system.slice/hoggroup.service"
	wantSubjects(t, "rate limited group kill", subjects(t,
		killedEv("tail", 100), groupLine(memcg), killedEv("tail", 100), killedEv("sleep", 101), killedEv("sleep", 102)), "tail")
}

func killedUID(comm string, pid, uid int) event.Event {
	return kernEv(fmt.Sprintf("Memory cgroup out of memory: Killed process %d (%s) total-vm:26652kB, anon-rss:24448kB, file-rss:768kB, shmem-rss:0kB, UID:%d pgtables:92kB oom_score_adj:0", pid, comm, uid))
}

// A user may set memory.oom.group on cgroups of their own. The episode such
// a group kill opens covers only Killed lines with that user's uid, so it
// never covers the kill of somebody else's process.
func TestOOMGroupKillOfAUserCoversOnlyThatUser(t *testing.T) {
	const own = "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.service"
	open := []event.Event{
		kernEv(oomSummary("/", "oom_memcg="+own, own, "tail", 100, 1000)),
		killedUID("tail", 100, 1000),
		groupLine(own),
		killedUID("tail", 100, 1000),
		killedUID("sleep", 101, 1000),
	}
	with := func(more ...event.Event) []event.Event { return append(append([]event.Event{}, open...), more...) }

	wantSubjects(t, "the user's own group", subjects(t, with(killedUID("sleep", 102, 1000))...), "user@1000.service")
	wantSubjects(t, "root's process right after the group", subjects(t, with(killedUID("mysqld", 555, 0))...), "user@1000.service", "mysqld")
	wantSubjects(t, "another user's process", subjects(t, with(killedUID("node", 556, 1001))...), "user@1000.service", "node")
	wantSubjects(t, "a uid that only starts with the same digits", subjects(t, with(killedUID("node", 556, 10000))...), "user@1000.service", "node")
	wantSubjects(t, "a uid that is a prefix of the user's", subjects(t, with(killedUID("node", 556, 100))...), "user@1000.service", "node")
	// The foreign line does not end the episode: the group's later lines still add nothing.
	wantSubjects(t, "group lines after a foreign line", subjects(t, with(killedUID("mysqld", 555, 0), killedUID("sleep", 102, 1000))...), "user@1000.service", "mysqld")
	// A line without a uid (an older kernel), or with other text after the command name, is judged on its own.
	wantSubjects(t, "no uid in the line", subjects(t, with(
		kernEv("Memory cgroup out of memory: Killed process 555 (mysqld) total-vm:26652kB, anon-rss:24448kB, file-rss:768kB, shmem-rss:0kB"))...), "user@1000.service", "mysqld")
	wantSubjects(t, "uid after other text", subjects(t, with(
		kernEv("Memory cgroup out of memory: Killed process 555 (mysqld) total-vm:1kB, UID:1000 pgtables:92kB"))...), "user@1000.service", "mysqld")
	wantSubjects(t, "uid text not at the kernel's place", subjects(t, with(
		kernEv("Memory cgroup out of memory: Killed process 555 (mysqld) total-vm:x 1kB, anon-rss:1kB, file-rss:1kB, shmem-rss:1kB, UID:1000 pgtables:92kB"))...), "user@1000.service", "mysqld")
	// The command name is in front of the last ") total-vm:"; uid text in it is not the kernel's uid.
	wantSubjects(t, "uid text in the command name", subjects(t, with(
		killedUID("x) total-vm:1kB, anon-rss:1kB, file-rss:1kB, shmem-rss:1kB, UID:1000 y", 555, 0))...),
		"user@1000.service", "x) total-vm:1kB, anon-rss:1kB, file-rss:1kB, shmem-rss:1kB, UID:1000 y")

	// Every cgroup at or below the user's slice is limited to the user.
	for _, memcg := range []string{
		"/user.slice/user-1000.slice",
		"/user.slice/user-1000.slice/session-3.scope",
		"/user.slice/user-1000.slice/user@1000.service",
		"/user.slice/user-1000.slice/user@1000.service/a,task_memcg=/system.slice/x.service are going to be killed due to memory.oom.group set",
	} {
		wantSubjects(t, memcg, subjects(t, groupLine(memcg), killedUID("sleep", 101, 1000), killedUID("mysqld", 555, 0)), "mysqld")
	}
	// A group anywhere else is not limited to a uid: a system unit runs
	// processes of several users, and a container's kernel paths name no user.
	for _, memcg := range []string{
		"/system.slice/web.service",
		"/user.slice",
		"/machine.slice/user-1000.slice/x",
		"/system.slice/x.service/user.slice/user-1000.slice/y",
		"/docker/" + containerID + "/user.slice/user-1000.slice/user@1000.service/app.slice/run-r1.service",
	} {
		wantSubjects(t, memcg, subjects(t, groupLine(memcg), killedUID("nginx", 101, 0), killedUID("nginx", 102, 33)))
	}
}

// The scenario of TestOOMForeignKillAfterUserKills with memory.oom.group set
// on the user's units (built from the captured line shapes, not captured as
// a whole): fourteen group kills of one user, ten with a kill summary, then
// a foreign kill without a summary one second later. It is reported.
func TestOOMForeignKillAfterUserGroupKills(t *testing.T) {
	r, _ := NewOOMKill(OOMParams{Window: time.Hour})
	var got []string
	eval := func(ev event.Event, at time.Time) {
		for _, s := range r.Evaluate(ev, at) {
			got = append(got, s.Subject)
		}
	}
	for i := 0; i < 14; i++ {
		at := t0.Add(time.Duration(i) * time.Millisecond)
		unit := fmt.Sprintf("/user.slice/user-1000.slice/user@1000.service/app.slice/run-r%02d.service", i)
		pid := 352179 + 2*i
		if i < 10 {
			eval(invokedEv("tail"), at)
			eval(kernEv(oomSummary("/", "oom_memcg="+unit, unit, "tail", pid, 1000)), at)
		}
		eval(killedUID("tail", pid, 1000), at)
		eval(groupLine(unit), at)
		eval(killedUID("tail", pid, 1000), at)
		eval(killedUID("sleep", pid+1, 1000), at)
	}
	eval(killedUID("foreign", 352300, 0), t0.Add(time.Second))
	wantSubjects(t, "user group kills, then a foreign kill", got, "user@1000.service", "foreign")
}
