package result

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		got, err := ParseSeverity(s)
		if err != nil || string(got) != s {
			t.Errorf("ParseSeverity(%q) = %q, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "High", "urgent", " low", "low "} {
		if got, err := ParseSeverity(s); err == nil || got != "" {
			t.Errorf("ParseSeverity(%q) = %q, %v; want an error", s, got, err)
		}
	}
}

func TestResultJSONShape(t *testing.T) {
	r := Result{
		CheckID: "a.b", Kind: "listeners", Status: Excepted, Severity: Low, Summary: "s",
		Evidence:         []Evidence{{Subject: "x", Detail: "d", Excepted: true, ExceptionReason: "why"}},
		ExceptionReasons: []string{"why"},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"check_id":"a.b"`, `"kind":"listeners"`, `"status":"excepted"`, `"severity":"low"`,
		`"summary":"s"`, `"subject":"x"`, `"detail":"d"`, `"excepted":true`, `"exception_reason":"why"`, `"exception_reasons":["why"]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %s", b, want)
		}
	}
	b, _ = json.Marshal(Result{Evidence: []Evidence{}})
	if !strings.Contains(string(b), `"evidence":[]`) || strings.Contains(string(b), "exception_reasons") {
		t.Errorf("empty result: %s", b)
	}
}

func TestEvidenceSetIsNotSerialized(t *testing.T) {
	r := Result{Evidence: []Evidence{{Subject: "a"}, {Subject: "(1 more not shown)"}}, Set: NewEvidenceSet([]Evidence{{Subject: "a"}, {Subject: "x"}})}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Set", "set", "Keys", "keys", "Digest", "digest", SubjectKey("x")} {
		if strings.Contains(string(b), leak) {
			t.Errorf("%s contains %q", b, leak)
		}
	}
}

func TestListedDropsTheMarkerOfACutListOnly(t *testing.T) {
	ev := []Evidence{{Subject: "a"}, {Subject: "(1 more not shown)"}}
	cut := Result{Evidence: ev, Set: NewEvidenceSet(ev)}
	if got := cut.Listed(); len(got) != 1 || got[0].Subject != "a" {
		t.Errorf("cut list: %+v", got)
	}
	// Without a set nothing is a marker, whatever the text says.
	if got := (Result{Evidence: ev}).Listed(); len(got) != 2 {
		t.Errorf("uncut list that looks cut: %+v", got)
	}
	if got := (Result{Set: cut.Set}).Listed(); len(got) != 0 {
		t.Errorf("set without evidence: %+v", got)
	}
	if ev[1].Subject != "(1 more not shown)" || len(cut.Evidence) != 2 {
		t.Error("Listed changed the evidence")
	}
}
