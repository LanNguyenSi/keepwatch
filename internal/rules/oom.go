package rules

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// Kernel and systemd OOM line shapes. The command name is chosen by the
// victim process, so the patterns are anchored and the numeric suffix the
// kernel appends is matched from the end.
var (
	oomKillRE   = regexp.MustCompile(`(?s)\Aoom-kill:constraint=[A-Z_]+,nodemask=(?:\(null\)|[0-9,-]*),cpuset=[^,]*,mems_allowed=[0-9,-]*,(?:global_oom|oom_memcg=[^,]*),task_memcg=([^,]*),task=(.*),pid=([0-9]+),uid=[0-9]+\z`)
	oomKilledRE = regexp.MustCompile(`(?s)\A(?:Memory cgroup out of memory|Out of memory): Killed process ([0-9]+) \((.*)\) total-vm:`)
	oomUnitRE   = regexp.MustCompile(`(?s)\A(` + unitPattern + `): (?:A process of this unit has been killed by the OOM killer\.|Failed with result 'oom-kill'\.)\z`)
)

// OOMKill fires once per kill when the kernel kills a process for lack of
// memory, or systemd reports that a unit was killed by the OOM killer. Kernel
// lines count only with Transport kernel, systemd lines only from PID 1 as
// root. One kill is written as several lines (kernel oom-kill and Killed
// process, then two systemd lines); they share victim keys (pid and command
// name for the kernel lines, the unit for the systemd lines, and a kernel
// line that names a unit marks that unit's systemd key too) and so give one
// signal per OOMParams.Window. The fingerprint comes from the unit when known
// (see serviceOfCgroup, or the unit systemd names), otherwise from the
// command name parsed from the message.
//
// With memory.oom.group (OOMPolicy=kill) the kernel writes one oom-kill line
// and then one "Killed process" line per process of the group, and those
// carry no cgroup. A "Killed process" line within killedGrace after an
// oom-kill line is therefore taken to belong to that kill and is ignored. On
// kernels that write no oom-kill line, or for a "Killed process" line more
// than killedGrace later, the line alone is reported (by command name).
type OOMKill struct {
	s *seenSet

	mu        sync.Mutex
	episodeAt time.Time // time of the latest matched oom-kill line
}

// killedGrace is how long after an oom-kill line the "Killed process" lines
// of the same kill are attributed to it.
const killedGrace = 5 * time.Second

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

// inEpisode reports whether now lies within killedGrace after the latest
// oom-kill line.
func (r *OOMKill) inEpisode(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	// With no episode yet episodeAt is the zero time, and the difference
	// saturates far above killedGrace.
	d := now.Sub(r.episodeAt)
	return d >= 0 && d < killedGrace
}

// Evaluate implements Rule.
func (r *OOMKill) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if now.IsZero() || ev.Kind != event.KindJournal {
		return nil
	}
	isKillLine := false
	var victimKeys []string
	var unit, comm string
	switch {
	case ev.Transport == "kernel":
		if m := oomKillRE.FindStringSubmatch(ev.Message); m != nil {
			isKillLine = true
			unit, comm = serviceOfCgroup(m[1]), m[2]
			victimKeys = []string{"kernel/" + m[3] + "/" + comm}
			if unit != "" {
				victimKeys = append(victimKeys, "systemd/"+unit)
			}
		} else if m := oomKilledRE.FindStringSubmatch(ev.Message); m != nil {
			if r.inEpisode(now) {
				return nil
			}
			comm = m[2]
			victimKeys = []string{"kernel/" + m[1] + "/" + comm}
		} else {
			return nil
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
	var fp event.Fingerprint
	subject := unit
	if unit != "" {
		fp = event.FingerprintOf(IDOOMKill, "unit", unit)
	} else {
		fp = event.FingerprintOf(IDOOMKill, "comm", comm)
		subject = comm
	}
	at, isNew := r.s.add(now, victimKeys...)
	if isKillLine {
		r.mu.Lock()
		r.episodeAt = now
		r.mu.Unlock()
	}
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
		Summary:     fmt.Sprintf("out of memory: %s was killed by the OOM killer", subject),
	}}
}
