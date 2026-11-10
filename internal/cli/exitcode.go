package cli

import "github.com/LanNguyenSi/keepwatch/internal/result"

// Exit codes of `keepwatch check`.
const (
	// ExitInternal: keepwatch could not do its job (invalid configuration,
	// a state directory that cannot be trusted or a state that cannot be
	// written, an interrupted run, a failed write of the report).
	ExitInternal = 3
)

// authorizedKeysKind is the probe kind whose warn results count like
// failures: a warn of that check can stand for keys that were not checked.
const authorizedKeysKind = "authorized_keys"

// Counts reports whether a result makes `check` exit 1 at the --fail-on
// severity. The rule, which the README repeats:
//
//   - fail counts when its severity is at least failOn;
//   - error counts the same way, because an unknown state must not look
//     green: a check that could not be evaluated is treated like one that
//     failed, at its own severity;
//   - warn counts only for the authorized_keys check (same severity rule),
//     since a warn there can hide keys that were never examined; every other
//     warn is a soft deviation and leaves the exit code at 0;
//   - pass, skipped and excepted never count (an excepted failure is covered
//     by a dated, reasoned exception; the exception_expired result is a fail
//     and counts at its low severity).
//
// The exit code depends on the current results only. Whether anything
// changed since the last run (the diff) never changes it: a scheduler that
// runs `check` every few hours sees exit 1 for as long as the host stays
// bad, and the diff decides what is worth a notification.
func Counts(r result.Result, failOn result.Severity) bool {
	if severityRank(r.Severity) < severityRank(failOn) {
		return false
	}
	switch r.Status {
	case result.Fail, result.Error:
		return true
	case result.Warn:
		return r.Kind == authorizedKeysKind
	}
	return false
}

// ExitCode returns 1 when any result counts at failOn, else 0.
func ExitCode(rs []result.Result, failOn result.Severity) int {
	for _, r := range rs {
		if Counts(r, failOn) {
			return ExitError
		}
	}
	return ExitOK
}

func severityRank(s result.Severity) int {
	for i, v := range result.Severities {
		if v == s {
			return i
		}
	}
	return -1
}
