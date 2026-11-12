package probes_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/render"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// The probes put the text of the host into subjects, summaries, causes and
// details exactly as they got it. The only change made to it is the one of
// redact.Redactor.Clean at the point where it leaves the program (report,
// notices, weekly report) or is stored (state, history): redact, then escape,
// then cut. These tests follow the text to those outputs.

// secretKind is one shape of secret the built-in patterns know.
type secretKind struct {
	name string
	// text is the secret with what the pattern needs around it.
	text string
	// probe is the part that must not be in any output (8 characters of it,
	// so no prefix of 8 or more characters of the secret can be).
	probe string
	// ws: the text holds white space
	ws bool
}

func secretKinds() []secretKind {
	return []secretKind{
		{"github token", "ghp_" + strings.Repeat("Z", 36), "ghp_ZZZZ", false},
		{"aws key id", "AKIA" + strings.Repeat("Q", 16), "AKIAQQQQ", false},
		{"bearer token", "bearer " + strings.Repeat("B", 20), "BBBBBBBB", true},
		{"password flag", "--password hunter2flag", "hunter2f", true},
		{"pass assignment", "pass=hunter2pass", "hunter2p", false},
		{"url user info", "", "hunter2u", false}, // text depends on the place
		{"operator pattern", "INT-1234567890", "INT-1234", false},
	}
}

// what stands in front of the secret, directly: nothing, white space, a
// punctuation mark, control characters, a character that makes the secret
// part of a longer word, and a terminal color sequence.
var corpusSeparators = []string{"", " ", "-", "\t", "\n", "\x01", "\x1b", "?", ",", "a", "\x1b[31m"}

// foundAfter says whether the built-in patterns find a secret of kind k right
// behind sep. Most separators end a word; the ones that glue the secret to the
// text before it hide only the shapes whose pattern needs a word boundary:
// the long, specific token prefixes and the scheme of a URL do not, and every
// built-in shape is found behind a terminal CSI (color) sequence. The rest is
// a stated limit (docs/okf/limit-known-limits.md).
func foundAfter(k secretKind, sep string) bool {
	switch sep {
	case "a":
		return k.name == "github token" || k.name == "url user info"
	case "\x1b[31m":
		return k.name != "operator pattern" // a pattern of the operator has its own boundary
	}
	return true
}

func hasCtl(s string) bool { return strings.ContainsAny(s, "\x00\x01\x1b\t\n") }
func hasWS(s string) bool  { return strings.ContainsAny(s, " \t\n") }

// fragFor builds the text a role gets: padding, a dot, the separator and the
// secret. ok is false when the role cannot hold that combination.
func fragFor(r corpusRole, k secretKind, sep string, pad int) (string, bool) {
	text := k.text
	if k.name == "url user info" {
		switch r.url {
		case "full":
			text = "https://user:hunter2urls@host.example"
		case "host":
			// the place supplies the scheme: the user info runs from there to
			// the "@". A comma, a space or a tab in front of it is covered (the
			// user info must then have the form user:password); a newline or a
			// "?" ends the URL for the pattern whatever the probe does
			if strings.Contains(sep, "\n") || sep == "?" {
				return "", false
			}
			text = "user:hunter2urls@host.example"
		default:
			return "", false
		}
	}
	if !foundAfter(k, sep) {
		return "", false
	}
	if (r.noCtl && hasCtl(sep)) || (r.noWS && (hasWS(sep) || hasWS(text))) || (r.noNL && strings.Contains(sep+text, "\n")) {
		return "", false
	}
	if r.maxPad > 0 && pad > r.maxPad {
		pad = r.maxPad
	}
	return strings.Repeat("a", pad) + "." + sep + text, true
}

// outputsOf puts one outcome through every place text leaves the program.
func outputsOf(t *testing.T, role corpusRole, o probes.Outcome, red *redact.Redactor) map[string][]byte {
	t.Helper()
	now := time.Unix(1700000000, 0)
	res := result.Result{CheckID: "c.x", Kind: role.kind, Status: o.Status, Severity: result.High, Summary: o.Summary, Evidence: o.Evidence, Set: o.Set}
	other := result.Result{CheckID: "c.x", Kind: role.kind, Status: result.Fail, Severity: result.High, Summary: "other", Evidence: []result.Evidence{{Subject: "other", Detail: "other"}}}
	cur := state.FromResults([]result.Result{res}, now, red.Clean)
	prev := state.FromResults([]result.Result{other}, now.Add(-time.Hour), red.Clean)
	rep := diff.Compute(prev, cur)
	out := map[string][]byte{}

	baseline := render.Input{GeneratedAt: now, Host: "host", FailOn: result.Medium, State: render.StateInfo{Used: true, Baseline: true, Reason: "first run"}, Results: []result.Result{res}}
	changed := render.Input{GeneratedAt: now, Host: "host", FailOn: result.Medium, State: render.StateInfo{Used: true, PrevRunAt: now.Add(-time.Hour)}, Results: []result.Result{res}, Diff: rep}
	for name, in := range map[string]render.Input{"baseline": baseline, "changed": changed} {
		for _, f := range []render.Format{render.Text, render.JSON, render.Markdown} {
			var b bytes.Buffer
			if err := render.Render(&b, f, in, red); err != nil {
				t.Fatal(err)
			}
			out[name+" "+string(f)] = b.Bytes()
		}
		if n, ok := render.BuildNotice(in, nil, red); ok {
			out[name+" notice"] = []byte(n.Title + "\n" + n.Body)
		}
	}
	run := history.FromReport(now, rep, red.Clean)
	runs := []history.Run{run}
	for _, md := range []bool{true, false} {
		n := render.BuildDigest(render.DigestInput{GeneratedAt: now, Host: "host", Days: 7, State: cur, Runs: runs}, md, red)
		out[fmt.Sprintf("digest markdown=%v", md)] = []byte(n.Title + "\n" + n.Body)
	}
	b, err := state.Marshal(cur)
	if err != nil {
		t.Fatal(err)
	}
	out["state"] = b
	hb, err := json.Marshal(runs)
	if err != nil {
		t.Fatal(err)
	}
	out["history"] = hb
	return out
}

// Every secret, whatever stands in front of it and wherever the cut of the
// report falls, is gone from every output, and no output holds a raw control
// character. The probes keep the host text as it is, so a pattern that wants a
// word boundary sees the same boundary the host text has.
func TestEverySecretIsGoneFromEveryOutput(t *testing.T) {
	red, err := redact.New([]string{`\bINT-[0-9]{10}\b`})
	if err != nil {
		t.Fatal(err)
	}
	// The secret straddles the 30 to 300 runes a probe used to cut at, the 200
	// runes the state shows of a subject, or the 2000 runes the report keeps of
	// a field.
	pads := []int{0, 5, 20, 190, 1990}
	switch {
	case raceEnabled:
		pads = []int{190}
	case testing.Short():
		pads = []int{0, 5, 20, 190}
	}
	seps := corpusSeparators
	if raceEnabled {
		// the race detector adds nothing to a pure function and costs minutes
		// here: a reduced list that still has nothing, white space (a space,
		// a tab, a newline), a control character, a comma, a letter that glues
		// the secret to the text before it and a color sequence
		seps = []string{"", " ", "\t", "\n", "\x01", ",", "a", "\x1b[31m"}
	}
	for _, role := range corpusRoles() {
		t.Run(role.name, func(t *testing.T) {
			ran := 0
			for _, k := range secretKinds() {
				for _, sep := range seps {
					for _, pad := range pads {
						frag, ok := fragFor(role, k, sep, pad)
						if !ok {
							continue
						}
						ran++
						checkCorpusCase(t, role, k, sep, pad, frag, red)
					}
				}
			}
			if ran == 0 {
				t.Fatal("no case ran")
			}
		})
	}
}

// checkCorpusCase runs one role with one text and follows it to every output.
func checkCorpusCase(t *testing.T, role corpusRole, k secretKind, sep string, pad int, frag string, red *redact.Redactor) {
	t.Helper()
	o := role.run(t, frag)
	if o.Status != role.status {
		t.Fatalf("%s sep %q pad %d: status %s (%s), want %s", k.name, sep, pad, o.Status, o.Summary, role.status)
	}
	// the probe kept the text: the secret is still there
	texts := []string{o.Summary}
	for _, e := range o.Evidence {
		texts = append(texts, e.Subject, e.Detail)
	}
	if all := strings.Join(texts, "\x00"); !strings.Contains(all, k.probe) {
		t.Fatalf("%s sep %q pad %d: the probe did not keep the secret in %q", k.name, sep, pad, texts)
	}
	sawRedacted := false
	for name, b := range outputsOf(t, role, o, red) {
		if leak := leakIn(b, k.probe); leak != "" {
			t.Fatalf("%s sep %q pad %d: %s holds the secret (%s): %.300q", k.name, sep, pad, name, leak, b)
		}
		for i, c := range b {
			if (c < 0x20 && c != '\n') || c == 0x7f {
				t.Fatalf("%s sep %q pad %d: %s holds the control byte %#x at %d", k.name, sep, pad, name, c, i)
			}
		}
		if bytes.Contains(b, []byte("[REDACTED]")) {
			sawRedacted = true
		}
	}
	// a secret that starts close to the cut of the report may be cut away
	// with its replacement
	if !sawRedacted && pad < 1990 {
		t.Fatalf("%s sep %q pad %d: nothing was redacted in any output, the case does not reach the report", k.name, sep, pad)
	}
}

// leakIn says where probe (a part of a secret) is in an output: "" when it is
// nowhere. JSON outputs are searched as written and decoded, since a JSON
// string escapes characters of the secret's surroundings (a probe that is in
// the decoded text is in the output whatever the escaping).
func leakIn(b []byte, probe string) string {
	if bytes.Contains(b, []byte(probe)) {
		return "as written"
	}
	var v any
	if json.Unmarshal(b, &v) == nil {
		var strs []string
		var walk func(any)
		walk = func(x any) {
			switch x := x.(type) {
			case string:
				strs = append(strs, x)
			case []any:
				for _, e := range x {
					walk(e)
				}
			case map[string]any:
				for k, e := range x {
					strs = append(strs, k)
					walk(e)
				}
			}
		}
		walk(v)
		if strings.Contains(strings.Join(strs, "\n"), probe) {
			return "after decoding the JSON"
		}
	}
	return ""
}

// The old cuts of the probes were at 30 to 300 runes of a subject, a summary
// or a detail. For every text of a role that names the host's text, the secret
// is put so that it starts 16 and 24 runes before each of those cut points
// (the probe of every kind is within its first 24 runes), and no output may
// hold a part of it: a probe that cut the text before the report redacted it
// would leave one.
func TestNoProbeCutsATextBeforeItIsRedacted(t *testing.T) {
	red, err := redact.New([]string{`\bINT-[0-9]{10}\b`})
	if err != nil {
		t.Fatal(err)
	}
	cuts := []int{30, 60, 80, 100, 120, 200, 300}
	before := []int{16, 24}
	seps := []string{"", "\t"}
	switch {
	case raceEnabled:
		cuts, before, seps = []int{200}, []int{16}, []string{""}
	case testing.Short():
		cuts = []int{30, 80, 200}
	}
	const marker = "MARKERMARKER"
	for _, role := range corpusRoles() {
		t.Run(role.name, func(t *testing.T) {
			// where the text of the host stands in each text of the outcome
			base := role.run(t, marker)
			at := map[string]int{}
			for key, tx := range textsOf(base) {
				if i := strings.Index(tx, marker); i >= 0 {
					at[key] = utf8.RuneCountInString(tx[:i])
				}
			}
			if len(at) == 0 {
				t.Fatalf("the text of the host is in no text of the outcome %+v", base)
			}
			ran := 0
			for _, k := range secretKinds() {
				for _, sep := range seps {
					done := map[int]bool{}
					for _, q := range at {
						for _, c := range cuts {
							for _, b := range before {
								pad := c - b - q - 1 - utf8.RuneCountInString(sep)
								if pad < 0 || done[pad] {
									continue
								}
								frag, ok := fragFor(role, k, sep, pad)
								if !ok {
									continue
								}
								done[pad] = true
								ran++
								checkCorpusCase(t, role, k, sep, pad, frag, red)
							}
						}
					}
				}
			}
			if ran == 0 {
				t.Fatal("no case ran")
			}
		})
	}
}

// textsOf names the texts of an outcome that the report shows.
func textsOf(o probes.Outcome) map[string]string {
	m := map[string]string{"summary": o.Summary}
	for i, e := range o.Evidence {
		m[fmt.Sprintf("subject %d", i)] = e.Subject
		m[fmt.Sprintf("detail %d", i)] = e.Detail
	}
	return m
}

// The probes do not change what the host gave them: no cut, no escape, no
// quoting. The first place the text is changed is the one that also redacts.
// Each text of the outcome that names the host's text (the summary, a subject,
// a detail) is checked on its own: one that is intact does not vouch for
// another.
func TestProbesKeepTheHostTextAsItIs(t *testing.T) {
	token := secretKinds()[0]
	const marker = "MARKERMARKER"
	for _, role := range corpusRoles() {
		t.Run(role.name, func(t *testing.T) {
			named := []string{}
			for key, tx := range textsOf(role.run(t, marker)) {
				if strings.Contains(tx, marker) {
					named = append(named, key)
				}
			}
			if len(named) == 0 {
				t.Fatal("the text of the host is in no text of the outcome")
			}
			for _, sep := range []string{"-", "\t", "\n", "\x01", "\x1b"} {
				for _, pad := range []int{5, 60, 250, 2100} {
					frag, ok := fragFor(role, token, sep, pad)
					if !ok {
						continue
					}
					got := textsOf(role.run(t, frag))
					for _, key := range named {
						if !strings.Contains(got[key], frag) {
							t.Fatalf("sep %q pad %d: the %s was changed: %q does not hold %q", sep, pad, key, got[key], frag)
						}
					}
				}
			}
		})
	}
}

// Each place that shows a subject applies the clean itself, whatever it was
// handed: the change lists of the report, the notices, the weekly report and
// the history take a subject from the state, which cleaned it already, and
// must not depend on that.
func TestEveryConsumerCleansWhatItShows(t *testing.T) {
	red, err := redact.New([]string{`\bINT-[0-9]{10}\b`})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	for _, k := range secretKinds() {
		text := k.text
		if k.name == "url user info" {
			text = "https://user:hunter2urls@host.example"
		}
		for _, sep := range corpusSeparators {
			if !foundAfter(k, sep) {
				continue
			}
			raw := "x." + sep + text
			ch := diff.Change{Kind: diff.SubjectNew, CheckID: "c.x", CheckKind: "cert_expiry", Severity: result.High, From: result.Fail, To: result.Fail, Subject: raw, Alert: true}
			rep := diff.Report{Changes: []diff.Change{ch}}
			in := render.Input{GeneratedAt: now, Host: "host", FailOn: result.Medium, State: render.StateInfo{Used: true, PrevRunAt: now}, Diff: rep}
			st := &state.State{SchemaVersion: state.SchemaVersion, RunAt: now, Checks: []state.Check{{ID: "c.x", Kind: "cert_expiry", Status: result.Fail, Severity: result.High, Items: []state.Item{{Key: result.SubjectKey(raw), Subject: raw}}}}}
			outs := map[string][]byte{}
			for _, f := range []render.Format{render.Text, render.JSON, render.Markdown} {
				var b bytes.Buffer
				if err := render.Render(&b, f, in, red); err != nil {
					t.Fatal(err)
				}
				outs["report "+string(f)] = b.Bytes()
			}
			if n, ok := render.BuildNotice(in, nil, red); ok {
				outs["notice"] = []byte(n.Title + "\n" + n.Body)
			}
			run := history.FromReport(now, rep, red.Clean)
			hb, err := json.Marshal(run)
			if err != nil {
				t.Fatal(err)
			}
			outs["history"] = hb
			for _, md := range []bool{true, false} {
				n := render.BuildDigest(render.DigestInput{GeneratedAt: now, Host: "host", Days: 7, State: st, Runs: []history.Run{run}}, md, red)
				outs[fmt.Sprintf("digest markdown=%v", md)] = []byte(n.Title + "\n" + n.Body)
			}
			for name, b := range outs {
				if leak := leakIn(b, k.probe); leak != "" {
					t.Fatalf("%s sep %q: %s holds the secret (%s): %.300q", k.name, sep, name, leak, b)
				}
				for i, c := range b {
					if (c < 0x20 && c != '\n') || c == 0x7f {
						t.Fatalf("%s sep %q: %s holds the control byte %#x at %d", k.name, sep, name, c, i)
					}
				}
			}
		}
	}
}
