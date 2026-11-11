package probes_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
// punctuation mark, and control characters.
var corpusSeparators = []string{"", " ", "-", "\t", "\n", "\x01", "\x1b", "?"}

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
			// the "@", and white space or a "?" in it ends the URL for the
			// pattern whatever the probe does
			if hasWS(sep) || sep == "?" {
				return "", false
			}
			text = "user:hunter2urls@host.example"
		default:
			return "", false
		}
	}
	if (r.noCtl && hasCtl(sep)) || (r.noWS && (hasWS(sep) || hasWS(text))) {
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
	pads := []int{20, 190, 1990}
	switch {
	case raceEnabled:
		pads = []int{190}
	case testing.Short():
		pads = []int{20, 190}
	}
	for _, role := range corpusRoles() {
		t.Run(role.name, func(t *testing.T) {
			ran := 0
			for _, k := range secretKinds() {
				for _, sep := range corpusSeparators {
					for _, pad := range pads {
						frag, ok := fragFor(role, k, sep, pad)
						if !ok {
							continue
						}
						ran++
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
						outs := outputsOf(t, role, o, red)
						sawRedacted := false
						for name, b := range outs {
							if bytes.Contains(b, []byte(k.probe)) {
								t.Fatalf("%s sep %q pad %d: %s holds the secret: %.300q", k.name, sep, pad, name, b)
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
						// a secret that starts close to the cut of the report may be
						// cut away with its replacement
						if !sawRedacted && pad < 1990 {
							t.Fatalf("%s sep %q pad %d: nothing was redacted in any output, the case does not reach the report", k.name, sep, pad)
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

// The probes do not change what the host gave them: no cut, no escape, no
// quoting. The first place the text is changed is the one that also redacts.
func TestProbesKeepTheHostTextAsItIs(t *testing.T) {
	token := secretKinds()[0]
	for _, role := range corpusRoles() {
		t.Run(role.name, func(t *testing.T) {
			for _, sep := range []string{"-", "\t", "\n", "\x01", "\x1b"} {
				for _, pad := range []int{5, 60, 250} {
					frag, ok := fragFor(role, token, sep, pad)
					if !ok {
						continue
					}
					o := role.run(t, frag)
					texts := []string{o.Summary}
					for _, e := range o.Evidence {
						texts = append(texts, e.Subject, e.Detail)
					}
					if !strings.Contains(strings.Join(texts, "\x00"), frag) {
						t.Fatalf("sep %q pad %d: the text %q was changed in %q", sep, pad, frag, texts)
					}
				}
			}
		})
	}
}
