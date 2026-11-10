package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// A state that contradicts itself (a listed item that its key set does not
// hold) must not give a diff. The command takes the path of a state it cannot
// handle: the report is printed without a comparison, a warning names the
// inconsistency, the stored state stays as it was and the exit code is 3.
//
// FromResults never builds such a state, so the test replaces the state
// builder of the command (env.buildState, the one seam for it) with one that
// breaks the output of the real builder after the fact.
func TestCheckWithAnInconsistentStateOfTheRunIsAnInternalError(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	if code, _, _ := f.check(); code != 0 {
		t.Fatalf("first run: exit %d", code)
	}
	before, err := os.ReadFile(f.statePath())
	if err != nil {
		t.Fatal(err)
	}

	// The service now fails, which a working comparison would report.
	f.env.runner = goodHost().AddResult(svcArgv, res("inactive\n", 3))
	f.clock = f.clock.Add(time.Hour)
	built := 0
	f.env.buildState = func(rs []result.Result, now time.Time, clean func(string) string) *state.State {
		built++
		st := state.FromResults(rs, now, clean)
		for i := range st.Checks {
			if st.Checks[i].Kind == "service_active" {
				// a set that holds a different item than the one listed
				other := result.SubjectKey("some other item")
				st.Checks[i].Items = []state.Item{{Key: result.SubjectKey("SECRET-SUBJECT"), Subject: "SECRET-SUBJECT"}}
				st.Checks[i].Total = 1
				st.Checks[i].Keys = []string{other}
				st.Checks[i].Digest = result.DigestOfKeys([]string{other})
			}
		}
		return st
	}
	code, out, errb := f.check("--format", "json")
	if built != 1 {
		t.Fatalf("the injected builder ran %d times, want 1", built)
	}
	if code != 3 {
		t.Errorf("exit = %d, want 3", code)
	}
	var v struct {
		Warnings []string `json:"warnings"`
		Changes  []any    `json:"changes"`
		Results  []any    `json:"results"`
		State    struct {
			Baseline bool `json:"baseline"`
		} `json:"state"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("the report was not printed as JSON: %v\n%q", err, out)
	}
	if len(v.Changes) != 0 {
		t.Errorf("a diff was computed: %v", v.Changes)
	}
	if !strings.Contains(out, "t.service") || strings.Contains(out, "SECRET-SUBJECT") {
		t.Errorf("the report does not show the results:\n%s", out)
	}
	for _, where := range []string{errb, strings.Join(v.Warnings, "\n")} {
		if !strings.Contains(where, "internal inconsistency") || !strings.Contains(where, "not in the key set") {
			t.Errorf("warning missing or without the rule: %q", where)
		}
		if strings.Contains(where, "SECRET-SUBJECT") {
			t.Errorf("warning names a subject: %q", where)
		}
	}
	after, err := os.ReadFile(f.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the state file changed:\n%s", after)
	}
	entries, _ := os.ReadDir(f.stateDir)
	if len(entries) != 1 {
		t.Errorf("state directory holds %d entries, want only state.json", len(entries))
	}

	// With --no-state the check is not reached.
	f.env.buildState = func([]result.Result, time.Time, func(string) string) *state.State {
		t.Error("the state was built with --no-state")
		return nil
	}
	if code, _, _ := f.check("--no-state"); code != 1 {
		t.Errorf("--no-state: exit %d, want 1", code)
	}
}
