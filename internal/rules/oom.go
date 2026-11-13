package rules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

// Kernel and systemd OOM line shapes. The command name is chosen by the
// victim process, so the patterns are anchored and the numeric suffix the
// kernel appends is matched from the end.
var (
	oomKillRE   = regexp.MustCompile(`(?s)\Aoom-kill:constraint=[A-Z_]+,nodemask=[^,]*,cpuset=[^,]*,mems_allowed=[^,]*,(?:global_oom|oom_memcg=[^,]*),task_memcg=([^,]*),task=(.*),pid=([0-9]+),uid=[0-9]+\z`)
	oomKilledRE = regexp.MustCompile(`(?s)\A(?:Memory cgroup out of memory|Out of memory): Killed process ([0-9]+) \((.*)\) total-vm:`)
	oomUnitRE   = regexp.MustCompile(`(?s)\A(` + unitPattern + `): (?:A process of this unit has been killed by the OOM killer\.|Failed with result 'oom-kill'\.)\z`)
)

// OOMKill fires once per victim when the kernel kills a process for lack of
// memory, or systemd reports that a unit was killed by the OOM killer. Kernel
// lines count only with Transport kernel, systemd lines only from PID 1 as
// root. The kernel writes several lines per kill; they share a victim key
// (pid and command name) and so give one signal. The fingerprint comes from
// the unit when known (the .service element of the victim's cgroup, or the
// unit systemd names), otherwise from the command name parsed from the
// message.
type OOMKill struct {
	s *seenSet
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

// serviceOfCgroup returns the innermost .service element of a cgroup path.
func serviceOfCgroup(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if strings.HasSuffix(parts[i], ".service") && len(parts[i]) > len(".service") {
			return parts[i]
		}
	}
	return ""
}

// Evaluate implements Rule.
func (r *OOMKill) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if ev.Kind != event.KindJournal {
		return nil
	}
	var victimKey, unit, comm string
	switch {
	case ev.Transport == "kernel":
		if m := oomKillRE.FindStringSubmatch(ev.Message); m != nil {
			unit, comm = serviceOfCgroup(m[1]), m[2]
			victimKey = "kernel/" + m[3] + "/" + comm
		} else if m := oomKilledRE.FindStringSubmatch(ev.Message); m != nil {
			comm = m[2]
			victimKey = "kernel/" + m[1] + "/" + comm
		} else {
			return nil
		}
	case fromSystemd(ev):
		m := oomUnitRE.FindStringSubmatch(ev.Message)
		if m == nil {
			return nil
		}
		unit = m[1]
		victimKey = "systemd/" + unit
	default:
		return nil
	}
	if len(unit) > maxKeyLen || len(comm) > maxKeyLen || len(victimKey) > 2*maxKeyLen {
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
	at, isNew := r.s.add(victimKey, now)
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
