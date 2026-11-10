package cli

import (
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// The exit-code matrix of `keepwatch check`: which result makes the exit code
// 1 at which --fail-on severity. Everything not listed as counting exits 0.
func TestCountsMatrix(t *testing.T) {
	const (
		fail     = result.Fail
		errored  = result.Error
		warn     = result.Warn
		pass     = result.Pass
		skipped  = result.Skipped
		excepted = result.Excepted
	)
	tests := []struct {
		name     string
		status   result.Status
		kind     string
		severity result.Severity
		failOn   result.Severity
		want     bool
	}{
		// fail: counts from failOn upwards
		{"fail above", fail, "k", result.High, result.Medium, true},
		{"fail equal", fail, "k", result.Medium, result.Medium, true},
		{"fail below", fail, "k", result.Low, result.Medium, false},
		{"fail info at info", fail, "k", result.Info, result.Info, true},
		{"fail info at low", fail, "k", result.Info, result.Low, false},
		{"fail critical at critical", fail, "k", result.Critical, result.Critical, true},
		{"fail high at critical", fail, "k", result.High, result.Critical, false},
		{"fail low at info", fail, "k", result.Low, result.Info, true},
		// error: an unknown state must not look green; same severity rule
		{"error above", errored, "k", result.High, result.Medium, true},
		{"error equal", errored, "k", result.Medium, result.Medium, true},
		{"error below", errored, "k", result.Low, result.Medium, false},
		{"error critical at critical", errored, "k", result.Critical, result.Critical, true},
		{"error high at critical", errored, "k", result.High, result.Critical, false},
		// warn: soft deviation, 0, except for authorized_keys
		{"warn high", warn, "k", result.High, result.Medium, false},
		{"warn critical at info", warn, "k", result.Critical, result.Info, false},
		{"warn sshd", warn, "sshd_effective", result.High, result.Info, false},
		{"warn authorized_keys above", warn, "authorized_keys", result.High, result.Medium, true},
		{"warn authorized_keys equal", warn, "authorized_keys", result.Medium, result.Medium, true},
		{"warn authorized_keys below", warn, "authorized_keys", result.Low, result.Medium, false},
		// never counting statuses
		{"pass", pass, "k", result.Critical, result.Info, false},
		{"skipped", skipped, "k", result.Critical, result.Info, false},
		{"excepted", excepted, "k", result.Critical, result.Info, false},
		{"excepted authorized_keys", excepted, "authorized_keys", result.Critical, result.Info, false},
		{"pass authorized_keys", pass, "authorized_keys", result.Critical, result.Info, false},
		// the kind only matters for warn
		{"fail authorized_keys below", fail, "authorized_keys", result.Low, result.Medium, false},
		// unknown values never count
		{"unknown status", result.Status("bogus"), "k", result.Critical, result.Info, false},
		{"unknown severity", fail, "k", result.Severity("bogus"), result.Info, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := result.Result{CheckID: "x.y", Kind: tc.kind, Status: tc.status, Severity: tc.severity}
			if got := Counts(r, tc.failOn); got != tc.want {
				t.Errorf("Counts(%s %s/%s, fail-on %s) = %v, want %v", tc.kind, tc.status, tc.severity, tc.failOn, got, tc.want)
			}
			wantCode := ExitOK
			if tc.want {
				wantCode = ExitError
			}
			if got := ExitCode([]result.Result{r}, tc.failOn); got != wantCode {
				t.Errorf("ExitCode = %d, want %d", got, wantCode)
			}
		})
	}
}

func TestExitCodeOverSeveralResults(t *testing.T) {
	rs := func(statuses ...result.Status) []result.Result {
		var out []result.Result
		for _, s := range statuses {
			out = append(out, result.Result{CheckID: "a.b", Kind: "k", Status: s, Severity: result.High})
		}
		return out
	}
	cases := []struct {
		name string
		in   []result.Result
		want int
	}{
		{"none", nil, 0},
		{"all pass", rs(result.Pass, result.Pass), 0},
		{"pass and skipped and excepted and warn", rs(result.Pass, result.Skipped, result.Excepted, result.Warn), 0},
		{"one fail among passes", rs(result.Pass, result.Fail, result.Pass), 1},
		{"one error among passes", rs(result.Pass, result.Pass, result.Error), 1},
		{"fail and error", rs(result.Fail, result.Error), 1},
	}
	for _, c := range cases {
		if got := ExitCode(c.in, result.Medium); got != c.want {
			t.Errorf("%s: ExitCode = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestExitCodeValues(t *testing.T) {
	if ExitOK != 0 || ExitError != 1 || ExitUsage != 2 || ExitInternal != 3 {
		t.Errorf("exit codes: %d %d %d %d", ExitOK, ExitError, ExitUsage, ExitInternal)
	}
}
