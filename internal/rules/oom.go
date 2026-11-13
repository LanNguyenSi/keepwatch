package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// Kernel and systemd OOM line shapes.
//
// The kernel's kill summary ("oom-kill:...") mixes parts only the kernel
// writes (the head up to cpuset=, and the numeric pid and uid at the end)
// with names chosen by users: the cpuset cgroup name, the cgroup paths after
// oom_memcg= and task_memcg=, and the command name after task=. The kernel
// prints those names raw, and a cgroup name may hold commas and the text
// ",task_memcg=" or ",task=". oomKillRE therefore fixes only the kernel's own
// parts and takes the command name after the last ",task="; the text before
// it is read by oomCgroupsRE and unitOfKill, which accept a cgroup path only
// when it cannot have been steered by such a name.
var (
	oomKillRE    = regexp.MustCompile(`(?s)\Aoom-kill:constraint=[A-Z_]+,nodemask=(?:\(null\)|[0-9,-]*),cpuset=(.*),task=(.*),pid=([0-9]+),uid=[0-9]+\z`)
	oomCgroupsRE = regexp.MustCompile(`\A[^,]*,mems_allowed=[0-9,-]*,(?:global_oom|oom_memcg=([^,]*)),task_memcg=([^,]*)\z`)
	oomKilledRE  = regexp.MustCompile(`(?s)\A(?:Memory cgroup out of memory|Out of memory): Killed process ([0-9]+) \((.*)\) total-vm:`)
	oomGroupRE   = regexp.MustCompile(`\ATasks in (/.*) are going to be killed due to memory\.oom\.group set\z`)
	oomUnitRE    = regexp.MustCompile(`\A(` + unitPattern + `): (?:A process of this unit has been killed by the OOM killer\.|Failed with result 'oom-kill'\.)\z`)
)

// What follows the command name in a Killed process line is written by the
// kernel alone; current kernels put the victim's uid there. oomKilledRE ends
// at the last ") total-vm:", so killedUIDRE reads the kernel's own text.
var killedUIDRE = regexp.MustCompile(`\A[0-9]+kB, anon-rss:[0-9]+kB, file-rss:[0-9]+kB, shmem-rss:[0-9]+kB, UID:([0-9]+)`)

// userSliceRE matches a user's slice and every cgroup below it. PID 1 creates
// the slice for the uid in its name; the user's sessions and service manager,
// and every cgroup that user may create, lie below it.
var userSliceRE = regexp.MustCompile(`\A/user\.slice/user-([0-9]+)\.slice`)

// taskMemcgMark starts the victim's cgroup path in the kernel's kill summary.
const taskMemcgMark = ",task_memcg="

// OOMKill fires once per kill when the kernel kills a process for lack of
// memory, or systemd reports that a unit was killed by the OOM killer. Kernel
// lines count only with Transport kernel, systemd lines only from PID 1 as
// root. One kill is written as several lines (kernel oom-kill and Killed
// process, then two systemd lines); they share victim keys (pid and command
// name for the kernel lines, the unit for the systemd lines, and a kernel
// line that names a unit marks that unit's systemd key too) and so give one
// signal per OOMParams.Window.
//
// The signal is about a unit when one is known: the unit systemd names, or
// the unit of the victim's cgroup in the kernel's kill summary (see
// unitOfKill). Otherwise it is about the command name parsed from the
// message. A command name is chosen by the process itself, so the summary
// says "process" for it and "unit" for a unit, and the two never share a
// fingerprint: a process that calls itself "cron.service" is not reported as
// the unit.
//
// Group kills: with memory.oom.group (OOMPolicy=kill) the kernel kills the
// victim, writes "Tasks in <cgroup> are going to be killed due to
// memory.oom.group set" and then one "Killed process" line per process of
// that cgroup. Those lines carry no cgroup, so the rule tells them by their
// place: the "Tasks in" line opens an episode, the "Killed process" lines
// that follow it are taken as that group's and give no signal, and the
// episode ends at the next kernel line of any other shape (the kernel writes
// the group's lines back to back). Lines of other transports do not end it,
// because the journal interleaves them. There is no time window: a "Killed
// process" line outside an episode is always judged on its own key, also when
// the kernel has rate limited the kill summary (it prints at most ten per
// five seconds) and the line stands alone.
//
// A user may set memory.oom.group on cgroups of their own, so a user can open
// episodes. When the group's cgroup lies below a user's slice
// (/user.slice/user-<uid>.slice/), the episode therefore covers only Killed
// lines that name this uid: the group kills of a user never cover the kill
// of somebody else's process. A line with another uid, or without a uid (an
// older kernel), is judged on its own key.
//
// Limits: the rule must see every kernel line in journal order, or an
// episode ends late. For a group outside the user slices (a system unit, a
// container), a "Killed process" line of another victim that follows the
// group's lines directly, without its own kill summary (so only while the
// kernel's rate limit is used up), is taken as part of the group; whoever may
// set memory.oom.group there (root, root in a container with a writable
// cgroup tree, the user of a delegated unit) can use that. systemd's line
// for a unit is never part of an episode, so a unit's kill is still reported
// then.
type OOMKill struct {
	s *seenSet

	mu sync.Mutex
	// groupKill: a "Tasks in" line opened an episode that no other kernel
	// line has ended. groupUID is the uid the episode is limited to, or ""
	// when the group's cgroup is not below a user's slice.
	groupKill bool
	groupUID  string
}

// NewOOMKill returns the rule, or an error for invalid params.
func NewOOMKill(p OOMParams) (*OOMKill, error) {
	if p.Window <= 0 {
		return nil, errWindow
	}
	return &OOMKill{s: newSeenSet(p.Window, p.MaxKeys)}, nil
}

// ID implements Rule.
func (r *OOMKill) ID() string { return IDOOMKill }

// serviceOfCgroup returns the unit a cgroup path belongs to, or "". A unit is
// derived only from a chain of *.slice elements followed by one *.service
// element: /system.slice/x.service gives x.service, and
// /user.slice/user-1000.slice/user@1000.service/... gives user@1000.service.
// Anything below the service element is ignored, because its names are
// chosen by the user who runs the service manager. Container paths
// (/docker/...), scopes and any other shape give no unit; the rule then
// falls back to the command name.
func serviceOfCgroup(path string) string {
	for _, el := range strings.Split(path, "/") {
		switch {
		case el == "":
		case strings.HasSuffix(el, ".slice") && len(el) > len(".slice"):
		case strings.HasSuffix(el, ".service") && len(el) > len(".service"):
			return el
		default:
			return ""
		}
	}
	return ""
}

// inCgroup reports whether path is the cgroup root or lies below it. The
// root "/" (and the empty root of a kill that is not scoped to a cgroup)
// holds every absolute path.
func inCgroup(path, root string) bool {
	root = strings.TrimSuffix(root, "/")
	return path == root || strings.HasPrefix(path, root+"/")
}

// unitOfKill returns the unit of the victim named by the kernel's kill
// summary msg, or "" when the summary gives no unit that can be trusted.
// cgroups is the part of msg between "cpuset=" and the last ",task=".
//
// The kernel prints cgroup names raw, so a user who may create cgroups (below
// a user manager, or as root in a container) can put commas and field names
// into the summary. A unit is derived only when all of this holds:
//   - ",task_memcg=" occurs exactly once in the whole summary, so the one
//     occurrence is the kernel's own and the path after it is the victim's;
//   - the cpuset name and both cgroup paths are free of commas, so no field
//     ends early or swallows the next one;
//   - for a kill scoped to a cgroup, the victim's path is that cgroup or lies
//     below it, as it does in every summary the kernel writes;
//   - the victim's path is rooted in slices (see serviceOfCgroup).
//
// In every other case the kill is reported by command name.
func unitOfKill(msg, cgroups string) string {
	if strings.Count(msg, taskMemcgMark) != 1 {
		return ""
	}
	m := oomCgroupsRE.FindStringSubmatch(cgroups)
	if m == nil {
		return ""
	}
	oomMemcg, taskMemcg := m[1], m[2]
	if !inCgroup(taskMemcg, oomMemcg) {
		return ""
	}
	return serviceOfCgroup(taskMemcg)
}

// setGroupKill ends the group kill episode, or opens one when line is the
// kernel's "Tasks in" line.
func (r *OOMKill) setGroupKill(line string) {
	m := oomGroupRE.FindStringSubmatch(line)
	uid := ""
	if m != nil {
		if u := userSliceRE.FindStringSubmatch(m[1]); u != nil {
			uid = u[1]
		}
	}
	r.mu.Lock()
	r.groupKill, r.groupUID = m != nil, uid
	r.mu.Unlock()
}

// inGroupKill reports whether a Killed process line belongs to the open
// group kill episode. rest is the text after the command name.
func (r *OOMKill) inGroupKill(rest string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.groupKill {
		return false
	}
	if r.groupUID == "" {
		return true
	}
	m := killedUIDRE.FindStringSubmatch(rest)
	return m != nil && m[1] == r.groupUID
}

// Evaluate implements Rule.
func (r *OOMKill) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if now.IsZero() || ev.Kind != event.KindJournal {
		return nil
	}
	var victimKeys []string
	var unit, comm string
	switch {
	case ev.Transport == "kernel":
		if m := oomKilledRE.FindStringSubmatch(ev.Message); m != nil {
			if r.inGroupKill(ev.Message[len(m[0]):]) {
				return nil
			}
			comm = m[2]
			victimKeys = []string{"kernel/" + m[1] + "/" + comm}
			break
		}
		// Any other kernel line ends an episode; the "Tasks in" line opens one.
		r.setGroupKill(ev.Message)
		m := oomKillRE.FindStringSubmatch(ev.Message)
		if m == nil {
			return nil
		}
		unit, comm = unitOfKill(ev.Message, m[1]), m[2]
		victimKeys = []string{"kernel/" + m[3] + "/" + comm}
		if unit != "" {
			victimKeys = append(victimKeys, "systemd/"+unit)
		}
	case fromSystemd(ev):
		m := oomUnitRE.FindStringSubmatch(ev.Message)
		if m == nil {
			return nil
		}
		unit = m[1]
		victimKeys = []string{"systemd/" + unit}
	default:
		return nil
	}
	if len(unit) > maxKeyLen || len(comm) > maxKeyLen {
		return nil
	}
	fp := event.FingerprintOf(IDOOMKill, "comm", comm)
	subject := comm
	summary := fmt.Sprintf("out of memory: process %s was killed by the OOM killer", comm)
	if unit != "" {
		fp = event.FingerprintOf(IDOOMKill, "unit", unit)
		subject = unit
		summary = fmt.Sprintf("out of memory: a process of unit %s was killed by the OOM killer", unit)
	}
	at, isNew := r.s.add(now, victimKeys...)
	if !isNew {
		return nil
	}
	return []event.Signal{{
		RuleID:      IDOOMKill,
		Fingerprint: fp,
		Severity:    SeverityOOMKill,
		Time:        at,
		Notify:      true,
		Subject:     subject,
		Summary:     summary,
	}}
}
