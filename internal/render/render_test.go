package render

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var genTime = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// hostile is text a local user could put into a container name, a path or a
// process name: Markdown that would open a link, an image or HTML, a heading,
// a table cell, terminal escape sequences, a bidirectional override, a fake
// line and a secret.
const hostile = "evil[click](http://evil.example/)![i](http://evil.example/p.png)<script>alert(1)</script> `tick` ``two`` | cell\n# fake heading\n- fake item\x1b[2J\x1b]0;title\x07\u202e reversed \u0085 password=hunter2"

func fullInput() Input {
	return Input{
		GeneratedAt: genTime,
		Host:        "web-01",
		FailOn:      result.Medium,
		ExitCode:    1,
		State:       StateInfo{Used: true, PrevRunAt: genTime.Add(-6 * time.Hour)},
		Warnings:    []string{"state file /var/lib/keepwatch/state.json was not used: " + hostile},
		Results: []result.Result{
			{CheckID: "services.fail2ban_active", Kind: "service_active", Status: result.Pass, Severity: result.High, Summary: "fail2ban.service is active", Evidence: []result.Evidence{}},
			{CheckID: "ssh.password_authentication", Kind: "sshd_effective", Status: result.Fail, Severity: result.High, Summary: "passwordauthentication is yes",
				Evidence: []result.Evidence{{Subject: "passwordauthentication", Detail: "effective value: yes; allowed: no"}}},
			{CheckID: "network.listeners", Kind: "listeners", Status: result.Fail, Severity: result.Medium, Summary: "2 listeners are not allowed",
				Evidence: []result.Evidence{
					{Subject: "tcp/0.0.0.0:9000", Detail: "process: " + hostile},
					{Subject: hostile, Detail: "token=abc123 was passed on the command line"},
					{Subject: "tcp/0.0.0.0:8080", Detail: "process: web", Excepted: true, ExceptionReason: "jump host until 2099"},
				}},
			{CheckID: "ssh.authorized_keys", Kind: "authorized_keys", Status: result.Warn, Severity: result.High, Summary: "1 authorized_keys file could not be read",
				Evidence: []result.Evidence{{Subject: "deploy:/home/deploy/.ssh/authorized_keys", Detail: "not read: permission denied"}}},
			{CheckID: "updates.security_pending", Kind: "security_updates", Status: result.Error, Severity: result.High, Summary: "apt-cache policy exited with status 100", Evidence: []result.Evidence{}},
			{CheckID: "docker.exposure", Kind: "docker_exposure", Status: result.Excepted, Severity: result.High, Summary: "1 container is privileged (excepted: build host)",
				Evidence: []result.Evidence{{Subject: "builder", Detail: "privileged", Excepted: true, ExceptionReason: "build host"}}, ExceptionReasons: []string{"build host"}},
			{CheckID: "certs.expiry", Kind: "cert_expiry", Status: result.Skipped, Severity: result.Medium, Summary: "disabled in the configuration", Evidence: []result.Evidence{}},
		},
		Diff: diff.Report{
			Changes: []diff.Change{
				{Kind: diff.NewFailure, CheckID: "ssh.password_authentication", CheckKind: "sshd_effective", Severity: result.High, From: result.Pass, To: result.Fail, Alert: true},
				{Kind: diff.SubjectNew, CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium, From: result.Fail, To: result.Fail, Subject: hostile, Alert: true},
				{Kind: diff.SubjectGone, CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium, From: result.Fail, To: result.Fail, Subject: "tcp/0.0.0.0:7000"},
				{Kind: diff.StatusChange, CheckID: "updates.security_pending", CheckKind: "security_updates", Severity: result.High, From: result.Pass, To: result.Error, Alert: true},
				{Kind: diff.StatusChange, CheckID: "ssh.authorized_keys", CheckKind: "authorized_keys", Severity: result.High, From: result.Pass, To: result.Warn, Alert: true},
				{Kind: diff.Fixed, CheckID: "disk.usage", CheckKind: "disk_usage", Severity: result.Medium, From: result.Fail, To: result.Pass},
				{Kind: diff.CountChange, CheckID: "docker.exposure", CheckKind: "docker_exposure", Severity: result.High, From: result.Fail, To: result.Fail, OldTotal: 104, NewTotal: 108, Alert: true},
				{Kind: diff.SeverityChange, CheckID: "disk.usage", CheckKind: "disk_usage", Severity: result.High, From: result.Fail, To: result.Fail, FromSeverity: result.Medium, ToSeverity: result.High, Alert: true},
				{Kind: diff.CheckAdded, CheckID: "fail2ban.sshd_jail", CheckKind: "fail2ban_jail", Severity: result.High, To: result.Pass},
				{Kind: diff.CheckRemoved, CheckID: "old.check", CheckKind: "k", Severity: result.Low, From: result.Fail},
			},
			StillFailing: []diff.Ref{{CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium}},
			StillWarning: []diff.Ref{{CheckID: "ssh.authorized_keys", CheckKind: "authorized_keys", Severity: result.High}},
		},
	}
}

func baselineInput() Input {
	in := fullInput()
	in.State = StateInfo{Used: true, Baseline: true, Reason: "no previous state (first run)"}
	in.Warnings = nil
	in.Diff = diff.Report{Baseline: true}
	return in
}

func noStateInput() Input {
	in := fullInput()
	in.State = StateInfo{}
	in.Warnings = nil
	in.Diff = diff.Report{}
	return in
}

func cleanInput() Input {
	return Input{
		GeneratedAt: genTime, Host: "web-01", FailOn: result.Medium, ExitCode: 0,
		State: StateInfo{Used: true, PrevRunAt: genTime.Add(-time.Hour)},
		Results: []result.Result{
			{CheckID: "a.one", Kind: "k", Status: result.Pass, Severity: result.Low, Summary: "fine", Evidence: []result.Evidence{}},
		},
		Diff: diff.Report{},
	}
}

func render(t *testing.T, f Format, in Input) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, f, in, nil); err != nil {
		t.Fatalf("Render(%s): %v", f, err)
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	inputs := map[string]Input{"full": fullInput(), "baseline": baselineInput(), "nostate": noStateInput(), "clean": cleanInput()}
	exts := map[Format]string{Text: "txt", JSON: "json", Markdown: "md"}
	for name, in := range inputs {
		for f, ext := range exts {
			t.Run(name+"/"+string(f), func(t *testing.T) {
				got := render(t, f, in)
				path := filepath.Join("testdata", name+"."+ext+".golden")
				if *update {
					if err := os.MkdirAll("testdata", 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("%v (run go test ./internal/render -update)", err)
				}
				if got != string(want) {
					t.Errorf("%s differs from the golden file:\n--- got\n%s\n--- want\n%s", path, got, want)
				}
			})
		}
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "json", "markdown"} {
		if f, err := ParseFormat(s); err != nil || string(f) != s {
			t.Errorf("ParseFormat(%q) = %q, %v", s, f, err)
		}
	}
	for _, s := range []string{"", "md", "TEXT", "xml", "json "} {
		if _, err := ParseFormat(s); err == nil {
			t.Errorf("ParseFormat(%q) accepted", s)
		}
	}
	if err := Render(&bytes.Buffer{}, Format("xml"), cleanInput(), nil); err == nil {
		t.Error("Render accepted an unknown format")
	}
}

// hostileInput puts the token HOSTILE and the hostile text into every field
// a report prints.
func hostileInput() Input {
	h := "HOSTILE" + hostile
	in := fullInput()
	in.Host = h
	in.Warnings = []string{h}
	in.State.Reason = h
	for i := range in.Results {
		r := &in.Results[i]
		r.CheckID, r.Kind, r.Summary = r.CheckID+h, r.Kind+h, h
		r.ExceptionReasons = []string{h}
		r.Evidence = []result.Evidence{{Subject: h, Detail: h, Excepted: true, ExceptionReason: h}, {Subject: h + "2", Detail: h}}
	}
	for i := range in.Diff.Changes {
		c := &in.Diff.Changes[i]
		c.CheckID, c.CheckKind, c.Subject = c.CheckID+h, c.CheckKind+h, h
	}
	for i := range in.Diff.StillFailing {
		in.Diff.StillFailing[i].CheckID += h
	}
	for i := range in.Diff.StillWarning {
		in.Diff.StillWarning[i].CheckID += h
	}
	return in
}

func isSafe(r rune) bool {
	return r == '\n' || (r >= 0x20 && r != 0x7f && !unicode.IsControl(r) && !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp))
}

func TestHostileTextNeverReachesAnyFormatRaw(t *testing.T) {
	in := hostileInput()
	for _, f := range []Format{Text, JSON, Markdown} {
		t.Run(string(f), func(t *testing.T) {
			out := render(t, f, in)
			if !utf8.ValidString(out) {
				t.Error("output is not valid UTF-8")
			}
			for _, r := range out {
				if !isSafe(r) {
					t.Fatalf("output holds U+%04X", r)
				}
			}
			for _, secret := range []string{"hunter2", "abc123"} {
				if strings.Contains(out, secret) {
					t.Errorf("secret %q is in the output", secret)
				}
			}
			if !strings.Contains(out, "HOSTILE") || !strings.Contains(out, "[REDACTED]") {
				t.Errorf("the hostile fields are missing from the output (a vacuous test):\n%s", out)
			}
		})
	}
}

func TestTextHostileFieldsCannotStartALine(t *testing.T) {
	out := render(t, Text, hostileInput())
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "# fake") || strings.HasPrefix(line, "- fake") {
			t.Errorf("a field started a line: %q", line)
		}
	}
}

func TestJSONIsValidAndCarriesTheCleanedText(t *testing.T) {
	out := render(t, JSON, hostileInput())
	var back view
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if back.SchemaVersion != SchemaVersion || len(back.Results) != 7 || len(back.Changes) != 10 {
		t.Errorf("round trip: %+v", back)
	}
	if strings.Contains(out, "<script>") || strings.Contains(out, "<script") && false {
		t.Errorf("raw tag in JSON")
	}
	// The cleaned subject is the escaped, redacted one.
	want := redact.Default().Clean("HOSTILE" + hostile)
	if back.Results[1].Evidence[0].Subject != want {
		t.Errorf("subject = %q, want %q", back.Results[1].Evidence[0].Subject, want)
	}
}

func TestJSONHasNoNullLists(t *testing.T) {
	out := render(t, JSON, Input{GeneratedAt: genTime, State: StateInfo{Used: true, Baseline: true, Reason: "x"}})
	for _, f := range []string{`"warnings": []`, `"changes": []`, `"still_failing": []`, `"still_warning": []`, `"results": []`} {
		if !strings.Contains(out, f) {
			t.Errorf("missing %s in:\n%s", f, out)
		}
	}
	if strings.Contains(out, "null") {
		t.Errorf("null in:\n%s", out)
	}
}

// stripCodeSpans removes the Markdown code spans from s the way CommonMark
// reads them: a run of N backticks opens a span that the next run of exactly
// N backticks closes.
func stripCodeSpans(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '`' {
			out.WriteByte(s[i])
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] == '`' {
			j++
		}
		n := j - i
		closed := false
		for k := j; k < len(s); {
			if s[k] != '`' {
				k++
				continue
			}
			m := k
			for m < len(s) && s[m] == '`' {
				m++
			}
			if m-k == n {
				i, closed = m, true
				break
			}
			k = m
		}
		if !closed {
			out.WriteString(s[i:j])
			i = j
		}
	}
	return out.String()
}

func TestMarkdownUntrustedTextOnlyInsideCodeSpans(t *testing.T) {
	out := render(t, Markdown, hostileInput())
	outside := stripCodeSpans(out)
	for _, bad := range []string{"HOSTILE", "evil", "click", "script", "http", "reversed", "fake", "hunter2", "<", "](", "!["} {
		if strings.Contains(outside, bad) {
			t.Errorf("%q appears outside a code span:\n%s", bad, outside)
		}
	}
	// A pipe of the data never splits a table row: every row of the table
	// has exactly four unescaped pipes.
	inTable := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| Check") {
			inTable = true
		}
		if inTable && strings.HasPrefix(line, "|") {
			if n := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); n != 4 {
				t.Errorf("table row has %d separators: %q", n, line)
			}
		}
	}
}

func TestMdCode(t *testing.T) {
	cases := map[string]string{
		"plain":      "` plain `",
		"":           "_(empty)_",
		"a`b":        "`` a`b ``",
		"a``b`c":     "``` a``b`c ```",
		"`lead":      "`` `lead ``",
		"trail`":     "`` trail` ``",
		"a|b":        "` a|b `",
		" spaced ":   "`  spaced  `",
		"[x](y)":     "` [x](y) `",
		"<b>x</b>":   "` <b>x</b> `",
		"x\\":        "` x\\ `",
		"```":        "```` ``` ````",
		"a ` b `` c": "``` a ` b `` c ```",
	}
	for in, want := range cases {
		if got := mdCode(in); got != want {
			t.Errorf("mdCode(%q) = %q, want %q", in, got, want)
		}
		// The span must read back as the input (less the pipe escaping).
		if in != "" {
			inner := stripCodeSpans(mdCode(in))
			if inner != "" {
				t.Errorf("mdCode(%q) is not one code span: %q is left over", in, inner)
			}
		}
	}
}

func TestMdCellEscapesPipes(t *testing.T) {
	if got := mdCell("a|b"); got != "` a\\|b `" {
		t.Errorf("mdCell = %q", got)
	}
	if got := mdCell("a`|b"); got != "`` a`\\|b ``" {
		t.Errorf("mdCell = %q", got)
	}
}

func TestRedactorFromTheConfigurationIsUsed(t *testing.T) {
	red, err := redact.New([]string{`corp-[0-9]{4}`})
	if err != nil {
		t.Fatal(err)
	}
	in := cleanInput()
	in.Results[0].Summary = "customer corp-1234 is fine"
	var b bytes.Buffer
	if err := Render(&b, Text, in, red); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); strings.Contains(out, "corp-1234") {
		t.Errorf("the configured pattern was not applied:\n%s", out)
	}
	in.Results[0].Status = result.Fail
	in.Results[0].Evidence = []result.Evidence{{Subject: "corp-1234"}}
	b.Reset()
	if err := Render(&b, Markdown, in, red); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "corp-1234") {
		t.Errorf("the configured pattern was not applied in Markdown:\n%s", b.String())
	}
}

func TestUnknownStatusIsShownAsUnknown(t *testing.T) {
	in := cleanInput()
	in.Results[0].Status = "[x](http://evil.example/)"
	for _, f := range []Format{Text, Markdown} {
		out := render(t, f, in)
		if !strings.Contains(out, "UNKNOWN") {
			t.Errorf("%s: %s", f, out)
		}
		if f == Markdown && strings.Contains(stripCodeSpans(out), "evil") {
			t.Errorf("status text outside a code span: %s", out)
		}
	}
}

func TestRenderWritesNothingOnFailure(t *testing.T) {
	var b bytes.Buffer
	_ = Render(&b, Format("bogus"), cleanInput(), nil)
	if b.Len() != 0 {
		t.Errorf("wrote %q", b.String())
	}
}

func TestTimesAreUTC(t *testing.T) {
	in := cleanInput()
	in.GeneratedAt = time.Date(2026, 11, 10, 14, 0, 0, 0, time.FixedZone("x", 2*3600))
	if out := render(t, JSON, in); !strings.Contains(out, `"generated_at": "2026-11-10T12:00:00Z"`) {
		t.Errorf("generated_at not in UTC:\n%s", out)
	}
}

func TestStateLines(t *testing.T) {
	cases := []struct {
		in   Input
		want string
	}{
		{noStateInput(), "state not used (--no-state)"},
		{baselineInput(), "baseline run, no changes are reported: no previous state (first run)"},
		{fullInput(), "changes since the previous run at 2026-11-10T06:00:00Z"},
	}
	for _, c := range cases {
		if out := render(t, Text, c.in); !strings.Contains(out, c.want) {
			t.Errorf("want %q in:\n%s", c.want, out)
		}
	}
	// The changes section is only printed when there is a comparison.
	if out := render(t, Text, noStateInput()); strings.Contains(out, "changes (") {
		t.Errorf("changes section without state:\n%s", out)
	}
	if out := render(t, Text, baselineInput()); strings.Contains(out, "changes (") {
		t.Errorf("changes section on a baseline:\n%s", out)
	}
	if out := render(t, JSON, baselineInput()); strings.Contains(out, `"kind": "new_failure"`) {
		t.Errorf("a baseline carries changes:\n%s", out)
	}
}

func TestStateFieldsOfAnUnusedStateAreIgnored(t *testing.T) {
	// A caller that did not use state may still hold a reason, a time and a
	// diff; none of them reach the report.
	for _, baseline := range []bool{true, false} {
		in := fullInput()
		in.Warnings = nil
		in.State = StateInfo{Used: false, Baseline: baseline, Reason: "LEFTOVER-REASON", PrevRunAt: genTime.Add(-time.Hour)}
		for _, f := range []Format{Text, JSON, Markdown} {
			out := render(t, f, in)
			for _, bad := range []string{"LEFTOVER-REASON", "2026-11-10T11:00:00Z", "new_failure", "now failing", "Changes", "changes ("} {
				if strings.Contains(out, bad) {
					t.Errorf("baseline=%v %s: %q in the report of a run without state:\n%s", baseline, f, bad, out)
				}
			}
		}
		if out := render(t, JSON, in); !strings.Contains(out, `"used": false`) || !strings.Contains(out, `"baseline": false`) {
			t.Errorf("state block:\n%s", out)
		}
	}
}

func TestChangesOfABaselineAreIgnored(t *testing.T) {
	in := fullInput()
	in.State = StateInfo{Used: true, Baseline: true, Reason: "first run"}
	for _, f := range []Format{Text, JSON, Markdown} {
		out := render(t, f, in)
		for _, bad := range []string{"new_failure", "now failing", "item gone", "still failing", "Still failing"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: %q in a baseline report:\n%s", f, bad, out)
			}
		}
	}
}
