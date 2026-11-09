package config

import (
	"time"
)

// parseDate parses a strict YYYY-MM-DD date (time.Parse enforces the
// two-digit fields and the calendar) and returns midnight of that day
// in the host's local zone.
func parseDate(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local), nil
}

// dayStart returns midnight, local zone, of the day now falls in.
func dayStart(now time.Time) time.Time {
	lt := now.In(time.Local)
	return time.Date(lt.Year(), lt.Month(), lt.Day(), 0, 0, 0, 0, time.Local)
}

// ActiveExceptions returns the exceptions that are still active on the
// day now falls in: an exception is active through its expiry date and
// expired from the day after. now is injected; the package never calls
// time.Now itself.
func (c *Config) ActiveExceptions(now time.Time) []Exception {
	start := dayStart(now)
	var out []Exception
	for _, e := range c.Exceptions {
		if !e.Expires.Before(start) {
			out = append(out, e)
		}
	}
	return out
}

// ExpiredExceptions returns the exceptions that expired before today,
// so that the engine can report an exception_expired finding for each.
func (c *Config) ExpiredExceptions(now time.Time) []Exception {
	start := dayStart(now)
	var out []Exception
	for _, e := range c.Exceptions {
		if e.Expires.Before(start) {
			out = append(out, e)
		}
	}
	return out
}
