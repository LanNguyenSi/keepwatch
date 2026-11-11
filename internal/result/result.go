// Package result holds the check result model shared by the probes, the
// engine and (later) state, diff and rendering. It has no dependencies, so
// every other package can import it without a cycle.
package result

import "fmt"

// Status is the outcome of one check.
type Status string

// The statuses a check can end in.
const (
	// Pass: the check ran and the host is as expected.
	Pass Status = "pass"
	// Fail: the check ran and found a deviation.
	Fail Status = "fail"
	// Warn: reserved for checks that report a soft deviation.
	Warn Status = "warn"
	// Error: the check could not be evaluated (a program failed, timed
	// out, or printed something unparseable). An error is never a pass.
	Error Status = "error"
	// Skipped: the check did not run (disabled, or a program it needs is
	// not installed).
	Skipped Status = "skipped"
	// Excepted: the check failed, and an active exception covers it.
	Excepted Status = "excepted"
)

// Severity ranks a finding.
type Severity string

// The severities, lowest first.
const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Severities lists the valid severities, lowest first.
var Severities = []Severity{Info, Low, Medium, High, Critical}

// ParseSeverity returns the severity named s, or an error when s is not one
// of the valid values.
func ParseSeverity(s string) (Severity, error) {
	for _, v := range Severities {
		if string(v) == s {
			return v, nil
		}
	}
	return "", fmt.Errorf("severity %q is not one of info, low, medium, high, critical", s)
}

// Evidence is one examined item of a check.
//
// Subject is a stable identifier of what was examined (for example
// "tcp/0.0.0.0:8080", "passwordauthentication" or "fail2ban.service"). It
// is what an exception's match compares against, exactly, and what the key of
// the item is made from (SubjectKey), so it is the raw identifier and is never
// changed by a probe (not cleaned, not cut, not quoted): two items that differ
// only in a control character, or only past the length a report shows, are two
// items. The probes cert_expiry, disk_usage, docker_exposure and
// authorized_keys also put the text of the host into Detail and into the
// Summary of a Result as it is (the other probes still clean some of their
// texts, which the report cleans again). The one change is made where the
// text leaves the program or is stored (report, notices, state, history), by
// redact.Redactor.Clean: redact, then escape, then cut. A change made before
// that can hide a secret from its pattern (a cut splits it, an escape takes
// away the word boundary in front of it). Detail is free text derived from
// host output and must be treated as untrusted.
type Evidence struct {
	Subject         string `json:"subject"`
	Detail          string `json:"detail"`
	Excepted        bool   `json:"excepted"`
	ExceptionReason string `json:"exception_reason,omitempty"`
}

// Result is the outcome of one check.
//
// For a failing check every evidence item is a failing item; findings that
// are only informational belong in Summary. An error result normally has no
// evidence. A check that reads several sources and could not read all of
// them keeps, as evidence, the failing items the other sources confirmed,
// and its Summary says the picture is partial; the status stays error.
type Result struct {
	CheckID  string     `json:"check_id"`
	Kind     string     `json:"kind"`
	Status   Status     `json:"status"`
	Severity Severity   `json:"severity"`
	Summary  string     `json:"summary"`
	Evidence []Evidence `json:"evidence"`
	// ExceptionReasons lists the reasons of the exceptions that were
	// applied to this check; it is empty unless one applied.
	ExceptionReasons []string `json:"exception_reasons,omitempty"`
	// Set describes the complete list that Evidence is a prefix of, and is
	// non-nil only when the probe cut that list (see EvidenceSet). When it is
	// non-nil the last item of Evidence is the marker that says how many items
	// are not shown, and the items before it are the ones that are listed.
	// This is how the marker is told from an item: by the set, which no host
	// output can produce, never by its text. It always describes the list
	// that is in Evidence: when the engine replaces the failing items by the
	// warnings, the set of the warnings replaces this one. It is not part of
	// any output.
	Set *EvidenceSet `json:"-"`
}

// Listed returns the evidence items without the marker of a cut list.
func (r Result) Listed() []Evidence {
	if r.Set != nil && len(r.Evidence) > 0 {
		return r.Evidence[:len(r.Evidence)-1]
	}
	return r.Evidence
}
