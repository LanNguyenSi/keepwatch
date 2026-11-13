package rules

import (
	"fmt"
	"regexp"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/event"
)

const unitPattern = `[A-Za-z0-9:_.\\@-]+\.(?:service|socket|timer|mount|path)`

var scheduledRE = regexp.MustCompile(`\A(` + unitPattern + `): Scheduled restart job, restart counter is at [0-9]+\.\z`)

// RestartLoop fires when systemd schedules Threshold automatic restarts of
// one unit within Window. Only the "<unit>: Scheduled restart job, restart
// counter is at N." line counts: it is written once per automatic restart,
// reads the same on systemd 249 and 255, and not for logins, timers or manual
// restarts. Only lines logged by PID 1 as root are counted, and the unit name
// is taken from the message, never from the sender-set UNIT field.
type RestartLoop struct {
	c *windowCounter
	w time.Duration
	n int
}

// NewRestartLoop returns the rule, or an error for invalid params.
func NewRestartLoop(p Params) (*RestartLoop, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &RestartLoop{c: newWindowCounter(p), w: p.Window, n: p.Threshold}, nil
}

// ID implements Rule.
func (r *RestartLoop) ID() string { return IDRestartLoop }

func parseUnitRestart(msg string) (string, bool) {
	m := scheduledRE.FindStringSubmatch(msg)
	if m == nil || len(m[1]) > maxKeyLen {
		return "", false
	}
	return m[1], true
}

// Evaluate implements Rule.
func (r *RestartLoop) Evaluate(ev event.Event, now time.Time) []event.Signal {
	if now.IsZero() {
		return nil
	}
	if ev.Kind != event.KindJournal || !fromSystemd(ev) {
		return nil
	}
	unit, ok := parseUnitRestart(ev.Message)
	if !ok {
		return nil
	}
	at, crossed := r.c.hit(unit, now)
	if !crossed {
		return nil
	}
	return []event.Signal{{
		RuleID:      IDRestartLoop,
		Fingerprint: event.FingerprintOf(IDRestartLoop, unit),
		Severity:    SeverityRestartLoop,
		Time:        at,
		Notify:      true,
		Subject:     unit,
		Summary:     fmt.Sprintf("%s restarted %d times within %s", unit, r.n, r.w),
	}}
}
