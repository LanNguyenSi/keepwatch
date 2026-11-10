package render

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
	"github.com/LanNguyenSi/keepwatch/internal/result"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

func changeInput(changes ...diff.Change) Input {
	return Input{
		GeneratedAt: genTime, Host: "web-01", FailOn: result.Medium,
		State:   StateInfo{Used: true, PrevRunAt: genTime.Add(-6 * time.Hour)},
		Results: []result.Result{{CheckID: "a.b", Kind: "k", Status: result.Pass, Severity: result.Low, Evidence: []result.Evidence{}}},
		Diff:    diff.Report{Changes: changes},
	}
}

func alertChange(sev result.Severity) diff.Change {
	return diff.Change{Kind: diff.NewFailure, CheckID: "ssh.password_authentication", CheckKind: "sshd_effective", Severity: sev, From: result.Pass, To: result.Fail, Alert: true}
}

func fixedChange() diff.Change {
	return diff.Change{Kind: diff.Fixed, CheckID: "disk.usage", CheckKind: "disk_usage", Severity: result.Medium, From: result.Fail, To: result.Pass}
}

func TestBuildNoticeDecidesFromTheComparisonAndNotTheExitCode(t *testing.T) {
	prev := &DeliveryNote{At: genTime, Failures: 1, Kind: "check", Reason: "HTTP 503"}
	cases := []struct {
		name string
		in   Input
		prev *DeliveryNote
		want bool
	}{
		{"no state used", func() Input { in := changeInput(alertChange(result.High)); in.State.Used = false; return in }(), nil, false},
		{"no state used, pending delivery", func() Input { in := changeInput(alertChange(result.High)); in.State.Used = false; return in }(), prev, false},
		{"no changes", changeInput(), nil, false},
		{"no changes, exit code 1", func() Input { in := changeInput(); in.ExitCode = 1; return in }(), nil, false},
		{"only a fix", changeInput(fixedChange()), nil, false},
		{"an alert, exit code 0", changeInput(alertChange(result.Low)), nil, true},
		{"an alert", changeInput(alertChange(result.High)), nil, true},
		{"a fix and an alert", changeInput(fixedChange(), alertChange(result.High)), nil, true},
		{"no changes, delivery pending", changeInput(), prev, true},
		{"a fix, delivery pending", changeInput(fixedChange()), prev, true},
		{"baseline", func() Input { in := changeInput(); in.State.Baseline = true; return in }(), nil, true},
		{"baseline, delivery pending", func() Input { in := changeInput(); in.State.Baseline = true; return in }(), prev, true},
		{"alert in a baseline is not read", func() Input {
			in := changeInput(alertChange(result.High))
			in.State.Baseline = true
			return in
		}(), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, ok := BuildNotice(c.in, c.prev, nil)
			if ok != c.want {
				t.Fatalf("ok = %v, want %v\n%s", ok, c.want, n.Body)
			}
			if !ok && (n.Title != "" || n.Body != "") {
				t.Errorf("a notice that is not sent is not empty: %+v", n)
			}
		})
	}
}

func TestChangeNoticeContent(t *testing.T) {
	in := changeInput(
		alertChange(result.High),
		diff.Change{Kind: diff.SubjectNew, CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium, From: result.Fail, To: result.Fail, Subject: "tcp/0.0.0.0:9000", Alert: true},
		fixedChange(),
	)
	in.Diff.StillFailing = []diff.Ref{{CheckID: "network.listeners"}, {CheckID: "x.y"}}
	n, ok := BuildNotice(in, nil, nil)
	if !ok {
		t.Fatal("no notice")
	}
	if n.Title != "keepwatch web-01: 2 alerts" || n.Severity != result.High {
		t.Errorf("title %q severity %q", n.Title, n.Severity)
	}
	if got := strings.Join(n.Tags, ","); got != "keepwatch,rotating_light" {
		t.Errorf("tags %q", got)
	}
	want := "**2 alerts** since the previous run at ` 2026-11-10T06:00:00Z `.\n" +
		"\n**Alerts**\n\n" +
		"- ` ssh.password_authentication ` (` high `): ` now failing (was pass) `\n" +
		"- ` network.listeners ` (` medium `): ` new item `: ` tcp/0.0.0.0:9000 `\n" +
		"\n**Other changes**\n\n" +
		"- ` disk.usage ` (` medium `): ` fixed (was failing) `\n" +
		"\nStill failing (2): ` network.listeners `, ` x.y `.\n"
	if n.Body != want {
		t.Errorf("body:\n%s\nwant:\n%s", n.Body, want)
	}
	// One alert: the singular, and a lower severity is a different tag.
	n, _ = BuildNotice(changeInput(alertChange(result.Medium)), nil, nil)
	if n.Title != "keepwatch web-01: 1 alert" || strings.Join(n.Tags, ",") != "keepwatch,warning" || n.Severity != result.Medium {
		t.Errorf("%+v", n)
	}
}

func TestNoticeSeverityIsTheHighestAlertAndIgnoresOtherChanges(t *testing.T) {
	fixedCritical := fixedChange()
	fixedCritical.Severity = result.Critical
	in := changeInput(alertChange(result.Low), alertChange(result.High), alertChange(result.Medium), fixedCritical)
	n, _ := BuildNotice(in, nil, nil)
	if n.Severity != result.High {
		t.Errorf("severity %q", n.Severity)
	}
	n, _ = BuildNotice(changeInput(fixedCritical), &DeliveryNote{At: genTime, Failures: 1, Kind: "check"}, nil)
	if n.Severity != "" {
		t.Errorf("a notice without alerts has severity %q", n.Severity)
	}
}

func TestNoticeForAnEarlierFailedDelivery(t *testing.T) {
	prev := &DeliveryNote{At: genTime.Add(-time.Hour), Failures: 3, Kind: "check", Reason: "ntfy: HTTP 503 (after 2 attempts)"}
	n, ok := BuildNotice(changeInput(), prev, nil)
	if !ok || n.Title != "keepwatch web-01: earlier notification was not delivered" {
		t.Fatalf("%v %+v", ok, n)
	}
	for _, want := range []string{"**0 alerts**", "**Last delivery failed:** the notification of an earlier run could not be delivered at ` 2026-11-10T11:00:00Z ` (3 runs in a row): ` ntfy: HTTP 503 (after 2 attempts) `.", "everything since the last report that was delivered"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, n.Body)
		}
	}
	weekly := &DeliveryNote{At: genTime, Failures: 1, Kind: "weekly", Reason: ""}
	n, _ = BuildNotice(changeInput(alertChange(result.High)), weekly, nil)
	if !strings.Contains(n.Body, "the weekly report could not be delivered") || !strings.Contains(n.Body, "(1 run in a row): ` no reason recorded `") || strings.Contains(n.Body, "everything since") {
		t.Errorf("weekly record:\n%s", n.Body)
	}
}

func TestNoticeReasonIsRedacted(t *testing.T) {
	prev := &DeliveryNote{At: genTime, Failures: 1, Kind: "check", Reason: "token=hunter2 \x1b[2J"}
	n, _ := BuildNotice(changeInput(), prev, nil)
	if strings.Contains(n.Body, "hunter2") || strings.Contains(n.Body, "\x1b") || !strings.Contains(n.Body, "[REDACTED]") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func baselineNoticeInput() Input {
	in := changeInput()
	in.State = StateInfo{Used: true, Baseline: true, Reason: "no previous state (first run)"}
	in.Results = []result.Result{
		{CheckID: "ssh.pw", Kind: "sshd_effective", Status: result.Fail, Severity: result.High, Evidence: []result.Evidence{{Subject: "passwordauthentication"}}},
		{CheckID: "net.listeners", Kind: "listeners", Status: result.Fail, Severity: result.Medium, Evidence: []result.Evidence{
			{Subject: "tcp/0.0.0.0:1"}, {Subject: "tcp/0.0.0.0:2"}, {Subject: "tcp/0.0.0.0:3"}, {Subject: "tcp/0.0.0.0:4"}, {Subject: "tcp/0.0.0.0:5"},
			{Subject: "tcp/0.0.0.0:6", Excepted: true, ExceptionReason: "ok"}}},
		{CheckID: "upd.pending", Kind: "security_updates", Status: result.Error, Severity: result.Critical, Summary: "apt failed", Evidence: []result.Evidence{{Subject: "partial-a"}, {Subject: "partial-b"}}},
		{CheckID: "keys.auth", Kind: "authorized_keys", Status: result.Warn, Severity: result.Critical, Evidence: []result.Evidence{{Subject: "line 3"}}},
		{CheckID: "ok.one", Kind: "k", Status: result.Pass, Severity: result.Low, Evidence: []result.Evidence{}},
		{CheckID: "skip.one", Kind: "k", Status: result.Skipped, Severity: result.Low, Evidence: []result.Evidence{}},
		{CheckID: "exc.one", Kind: "k", Status: result.Excepted, Severity: result.Low, Evidence: []result.Evidence{{Subject: "x", Excepted: true}}},
	}
	return in
}

func TestBaselineNoticeListsTheOpenFindings(t *testing.T) {
	n, ok := BuildNotice(baselineNoticeInput(), nil, nil)
	if !ok {
		t.Fatal("no notice")
	}
	if n.Title != "keepwatch web-01: first run, 4 open findings" || n.Severity != result.Critical {
		t.Errorf("title %q, severity %q", n.Title, n.Severity)
	}
	want := "**First run:** there is no previous run to compare with, so no changes are reported. ` no previous state (first run) `\n" +
		"\n` 7 checks: 0 pass, 0 fail, 0 warn, 0 error, 0 skipped, 0 excepted `\n" +
		"\n**Open findings**\n\n" +
		"- FAIL ` ssh.pw ` (` high `): ` passwordauthentication `\n" +
		"- FAIL ` net.listeners ` (` medium `): ` tcp/0.0.0.0:1 `, ` tcp/0.0.0.0:2 `, ` tcp/0.0.0.0:3 ` and 2 more\n" +
		"- ERROR ` upd.pending ` (` critical `)\n" +
		"- WARN ` keys.auth ` (` critical `): ` line 3 `\n"
	// The counts line is computed from the results by the view; compare
	// everything else exactly.
	got := regexp.MustCompile("` 7 checks[^`]*`").ReplaceAllString(n.Body, "` 7 checks: 0 pass, 0 fail, 0 warn, 0 error, 0 skipped, 0 excepted `")
	if got != want {
		t.Errorf("body:\n%s\nwant:\n%s", got, want)
	}
	// An error lists no evidence, an excepted item is not listed.
	if strings.Contains(n.Body, "partial-") || strings.Contains(n.Body, "tcp/0.0.0.0:6") {
		t.Errorf("body lists evidence it must not:\n%s", n.Body)
	}
}

func TestBaselineNoticeSeverityIgnoresWarnings(t *testing.T) {
	in := baselineNoticeInput()
	in.Results = in.Results[3:4] // only the critical warn
	n, _ := BuildNotice(in, nil, nil)
	if n.Severity != "" || !strings.Contains(n.Title, "1 open finding") || strings.Contains(n.Title, "findings") {
		t.Errorf("title %q severity %q", n.Title, n.Severity)
	}
	in.Results = nil
	n, _ = BuildNotice(in, nil, nil)
	if !strings.Contains(n.Body, "No open findings.") || !strings.Contains(n.Title, "0 open findings") || strings.Join(n.Tags, ",") != "keepwatch,information_source" {
		t.Errorf("%+v", n)
	}
	n, _ = BuildNotice(baselineNoticeInput(), nil, nil)
	if strings.Join(n.Tags, ",") != "keepwatch,rotating_light" {
		t.Errorf("tags %v", n.Tags)
	}
}

func TestBaselineNoticeDoesNotListTheMarkerOfACutList(t *testing.T) {
	in := baselineNoticeInput()
	in.Results = []result.Result{{
		CheckID: "net.listeners", Kind: "listeners", Status: result.Fail, Severity: result.Medium,
		Evidence: []result.Evidence{{Subject: "tcp/0.0.0.0:1"}, {Subject: "(5000 more not shown)"}},
		Set:      result.NewEvidenceSet([]result.Evidence{{Subject: "tcp/0.0.0.0:1"}}),
	}}
	n, _ := BuildNotice(in, nil, nil)
	if strings.Contains(n.Body, "more not shown") || !strings.Contains(n.Body, "` tcp/0.0.0.0:1 `\n") || strings.Contains(n.Body, " and ") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func TestBaselineNoticeWithAnEarlierFailure(t *testing.T) {
	prev := &DeliveryNote{At: genTime, Failures: 2, Kind: "weekly", Reason: "HTTP 401"}
	n, _ := BuildNotice(baselineNoticeInput(), prev, nil)
	if !strings.Contains(n.Body, "the weekly report could not be delivered") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func TestNoticeUsesTheRedactorOfTheConfiguration(t *testing.T) {
	red, err := redact.New([]string{`corp-[0-9]{4}`})
	if err != nil {
		t.Fatal(err)
	}
	in := changeInput(diff.Change{Kind: diff.SubjectNew, CheckID: "a.b", Severity: result.High, Subject: "host corp-1234 password=hunter2", Alert: true})
	in.Host = "corp-9999"
	n, _ := BuildNotice(in, nil, red)
	if strings.Contains(n.Body, "corp-1234") || strings.Contains(n.Body, "hunter2") || strings.Contains(n.Title, "corp-9999") {
		t.Errorf("%q\n%s", n.Title, n.Body)
	}
}

func TestNoticeAnErrorStatusChangeIsOneLine(t *testing.T) {
	in := changeInput(diff.Change{Kind: diff.StatusChange, CheckID: "upd.pending", CheckKind: "security_updates", Severity: result.High, From: result.Pass, To: result.Error, Alert: true})
	in.Results = []result.Result{{CheckID: "upd.pending", Kind: "security_updates", Status: result.Error, Severity: result.High, Summary: "apt failed",
		Evidence: []result.Evidence{{Subject: "a"}, {Subject: "b"}, {Subject: "c"}}}}
	n, _ := BuildNotice(in, nil, nil)
	if strings.Count(n.Body, "upd.pending") != 1 || strings.Contains(n.Body, "` a `") || !strings.Contains(n.Body, "pass -> error") {
		t.Errorf("body:\n%s", n.Body)
	}
}

// outsideOK is the form of a line once the code spans are taken out: only
// words and punctuation keepwatch writes itself.
var outsideOK = regexp.MustCompile(`^(- |\*\*)?[A-Za-z0-9 .,:()*-]*$`)

type errorfer interface {
	Errorf(format string, args ...any)
}

// assertSafeMarkdown checks that untrusted text can only be inside code spans:
// nothing but keepwatch's own words is left once the spans are removed, every
// fence is closed, and no line can start a block element of its own.
func assertSafeMarkdown(t errorfer, body string) {
	outside := stripCodeSpans(body)
	if strings.Contains(outside, "`") {
		t.Errorf("a code span is not closed:\n%s", outside)
	}
	for _, bad := range []string{"HOSTILE", "evil", "click", "script", "http", "<", ">", "](", "![", "[", "]", "#", "@", "\\", "|", "_", "~", "\t", "\r", "\x1b"} {
		if strings.Contains(outside, bad) {
			t.Errorf("%q appears outside a code span:\n%s", bad, outside)
		}
	}
	for _, line := range strings.Split(outside, "\n") {
		if !outsideOK.MatchString(line) || strings.HasPrefix(line, " ") {
			t.Errorf("line %q has more than keepwatch's own words outside a code span", line)
		}
	}
}

func TestNoticeHostileTextIsOnlyEverInsideCodeSpans(t *testing.T) {
	h := "HOSTILE" + hostile
	cases := map[string]Input{}
	chg := changeInput()
	chg.Host = h
	chg.State.Reason = h
	for i, k := range []diff.Kind{diff.NewFailure, diff.SubjectNew, diff.SubjectGone, diff.HiddenNew, diff.SetChanged, diff.SeverityChange, diff.CheckAdded, diff.Fixed} {
		chg.Diff.Changes = append(chg.Diff.Changes, diff.Change{
			Kind: k, CheckID: fmt.Sprintf("%s%d", h, i), CheckKind: h, Severity: result.High, From: result.Status(h), To: result.Status(h), Subject: h,
			FromSeverity: result.Severity(h), ToSeverity: result.Severity(h), Alert: i%2 == 0, HiddenNew: 2, OldTotal: 1, NewTotal: 2,
		})
	}
	chg.Diff.StillFailing = []diff.Ref{{CheckID: h}, {CheckID: h + "2"}}
	cases["changes"] = chg
	base := baselineNoticeInput()
	base.Host = h
	base.State.Reason = h
	for i := range base.Results {
		r := &base.Results[i]
		r.CheckID = h + r.CheckID
		for j := range r.Evidence {
			r.Evidence[j].Subject = h
		}
	}
	cases["baseline"] = base
	for name, in := range cases {
		for _, prev := range []*DeliveryNote{nil, {At: genTime, Failures: 2, Kind: "check", Reason: h}} {
			t.Run(fmt.Sprintf("%s prev=%v", name, prev != nil), func(t *testing.T) {
				n, ok := BuildNotice(in, prev, nil)
				if !ok {
					t.Fatal("no notice")
				}
				assertSafeMarkdown(t, n.Body)
				if !strings.Contains(n.Body, "HOSTILE") {
					t.Errorf("the hostile fields are missing (a vacuous test):\n%s", n.Body)
				}
				if strings.Contains(n.Body, "hunter2") {
					t.Error("secret in the body")
				}
				for _, r := range n.Body {
					if !isSafe(r) {
						t.Fatalf("body holds U+%04X", r)
					}
				}
				// The title is a line of its own: no control characters, and
				// the secret is gone from it too.
				if strings.ContainsAny(n.Title, "\r\n\x00\x1b") || strings.Contains(n.Title, "hunter2") {
					t.Errorf("title %q", n.Title)
				}
				if !strings.HasPrefix(n.Title, "keepwatch HOSTILE") {
					t.Errorf("title %q", n.Title)
				}
			})
		}
	}
}

// The assertion above must be able to fail: a body in which untrusted text
// is not in a code span is refused by it.
func TestAssertSafeMarkdownDetectsUnsafeBodies(t *testing.T) {
	for _, body := range []string{
		"- ` ok `: [click](http://evil.example)\n",
		"- ` ok `: ![i](x)\n",
		"# heading\n",
		"- ` unclosed \n",
		"- <b>bold</b>\n",
		"    indented\n",
		"> quote\n",
		"@all\n",
	} {
		ft := &fakeT{}
		assertSafeMarkdown(ft, body)
		if !ft.failed {
			t.Errorf("not detected: %q", body)
		}
	}
}

type fakeT struct{ failed bool }

func (f *fakeT) Errorf(string, ...any) { f.failed = true }

func TestNoticeBodyIsBoundedAndSaysWhatWasLeftOut(t *testing.T) {
	var changes []diff.Change
	for i := 0; i < 400; i++ {
		changes = append(changes, diff.Change{Kind: diff.SubjectNew, CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium,
			Subject: fmt.Sprintf("tcp/0.0.0.0:%d %s", i, strings.Repeat("x", 150)), Alert: true})
	}
	in := changeInput(changes...)
	for _, prev := range []*DeliveryNote{nil, {At: genTime, Failures: 1, Kind: "check", Reason: strings.Repeat("r", 2000)}} {
		n, ok := BuildNotice(in, prev, nil)
		if !ok {
			t.Fatal("no notice")
		}
		if len(n.Body) > MaxNoticeBytes {
			t.Errorf("body of %d bytes, limit %d", len(n.Body), MaxNoticeBytes)
		}
		if !regexp.MustCompile(`\n\d+ more lines not shown\.\n$`).MatchString(n.Body) {
			t.Errorf("no mark of the dropped lines:\n...%s", n.Body[len(n.Body)-200:])
		}
		if !strings.HasPrefix(n.Body, "**400 alerts**") || !strings.Contains(n.Title, "400 alerts") {
			t.Errorf("the count must be the real one: %q %q", n.Title, n.Body[:30])
		}
		assertSafeMarkdown(t, n.Body)
	}
	// The same for a baseline with many findings.
	base := baselineNoticeInput()
	base.Results = nil
	for i := 0; i < 300; i++ {
		base.Results = append(base.Results, result.Result{CheckID: fmt.Sprintf("check.%d", i), Kind: "k", Status: result.Fail, Severity: result.Low, Evidence: []result.Evidence{{Subject: strings.Repeat("s", 100)}}})
	}
	n, _ := BuildNotice(base, nil, nil)
	if len(n.Body) > MaxNoticeBytes || !strings.Contains(n.Body, "more lines not shown.") || !strings.Contains(n.Title, "300 open findings") {
		t.Errorf("baseline: %d bytes\n%q", len(n.Body), n.Title)
	}
}

func TestNoticeBodyOfAnOrdinaryRunIsNotCut(t *testing.T) {
	n, _ := BuildNotice(changeInput(alertChange(result.High), fixedChange()), nil, nil)
	if strings.Contains(n.Body, "not shown") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func TestLongHostIsCutInTheTitle(t *testing.T) {
	in := changeInput(alertChange(result.High))
	in.Host = strings.Repeat("h", 500)
	n, _ := BuildNotice(in, nil, nil)
	if want := "keepwatch " + strings.Repeat("h", 60) + "...: 1 alert"; n.Title != want {
		t.Errorf("title %q", n.Title)
	}
}

// ---- weekly digest ----

func digestState() *state.State {
	return &state.State{SchemaVersion: state.SchemaVersion, RunAt: genTime.Add(-time.Hour), Checks: []state.Check{
		{ID: "ok.one", Kind: "k", Status: result.Pass, Severity: result.Low},
		{ID: "low.fail", Kind: "k", Status: result.Fail, Severity: result.Low, Items: []state.Item{{Key: strings.Repeat("a", 64), Subject: "tcp/0.0.0.0:1"}}},
		{ID: "high.fail", Kind: "k", Status: result.Fail, Severity: result.High, Items: []state.Item{
			{Key: strings.Repeat("1", 64), Subject: "s1"}, {Key: strings.Repeat("2", 64), Subject: "s2"}, {Key: strings.Repeat("3", 64), Subject: "s3"},
			{Key: strings.Repeat("4", 64), Subject: "s4"}, {Key: strings.Repeat("5", 64), Subject: "s5", Excepted: true}}},
		{ID: "crit.err", Kind: "k", Status: result.Error, Severity: result.Critical, Items: []state.Item{{Key: strings.Repeat("b", 64), Subject: "partial"}}},
		{ID: "mid.warn", Kind: "authorized_keys", Status: result.Warn, Severity: result.Medium, Items: []state.Item{{Key: strings.Repeat("c", 64), Subject: "line 4"}}},
		{ID: "exc.one", Kind: "k", Status: result.Excepted, Severity: result.High},
	}}
}

func digestInput() DigestInput {
	return DigestInput{
		GeneratedAt: genTime, Host: "web-01", Days: 7, State: digestState(),
		Runs: []history.Run{
			{RunAt: genTime.Add(-72 * time.Hour), Changes: []history.Change{{Kind: "new_failure", CheckID: "high.fail", Severity: "high", From: "pass", To: "fail", Alert: true}}},
			{RunAt: genTime.Add(-48 * time.Hour), Changes: []history.Change{{Kind: "fixed", CheckID: "disk.usage", Severity: "medium", From: "fail", To: "pass"}}},
			{RunAt: genTime.Add(-24 * time.Hour), Changes: []history.Change{}},
		},
	}
}

func TestDigestMarkdown(t *testing.T) {
	n := BuildDigest(digestInput(), true, nil)
	if n.Title != "keepwatch web-01: weekly report, 4 open findings" || n.Severity != result.Medium || strings.Join(n.Tags, ",") != "keepwatch,calendar" {
		t.Errorf("%q %q %v", n.Title, n.Severity, n.Tags)
	}
	want := "**keepwatch weekly report** for host ` web-01 `, ` 2026-11-10T12:00:00Z `, last 7 days.\n" +
		"\n**Open findings** (4 of 6 checks), state of ` 2026-11-10T11:00:00Z `:\n\n" +
		"- ERROR ` crit.err ` (` critical `)\n" +
		"- FAIL ` high.fail ` (` high `): ` s1 `, ` s2 `, ` s3 ` and 1 more\n" +
		"- WARN ` mid.warn ` (` medium `): ` line 4 `\n" +
		"- FAIL ` low.fail ` (` low `): ` tcp/0.0.0.0:1 `\n" +
		"\n**Changes in the last 7 days** (3 runs recorded, 2 changes, 1 alert, 1 fixed or gone):\n\n" +
		"- ` 2026-11-08T12:00:00Z ` ` disk.usage ` (` medium `): ` fixed (was failing) `\n" +
		"- **ALERT** ` 2026-11-07T12:00:00Z ` ` high.fail ` (` high `): ` now failing (was pass) `\n"
	if n.Body != want {
		t.Errorf("body:\n%s\nwant:\n%s", n.Body, want)
	}
	assertSafeMarkdown(t, n.Body)
}

func TestDigestText(t *testing.T) {
	in := digestInput()
	in.PrevDelivery = &DeliveryNote{At: genTime, Failures: 1, Kind: "weekly", Reason: "HTTP 401"}
	n := BuildDigest(in, false, nil)
	if strings.Contains(n.Body, "`") || strings.Contains(n.Body, "**") {
		t.Errorf("markup in the text format:\n%s", n.Body)
	}
	for _, want := range []string{"Keepwatch weekly report for host web-01", "Last delivery failed: the last weekly report could not be delivered at 2026-11-10T12:00:00Z (1 run in a row): HTTP 401.",
		"- FAIL high.fail (high): s1, s2, s3 and 1 more", "- ALERT 2026-11-07T12:00:00Z high.fail (high): now failing (was pass)"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("text lacks %q:\n%s", want, n.Body)
		}
	}
}

func TestDigestWithNothingToTell(t *testing.T) {
	in := DigestInput{GeneratedAt: genTime, Host: "h", State: &state.State{SchemaVersion: state.SchemaVersion, RunAt: genTime, Checks: []state.Check{{ID: "a", Kind: "k", Status: result.Pass, Severity: result.Low}}}}
	n := BuildDigest(in, true, nil)
	if n.Title != "keepwatch h: weekly report, 0 open findings" || n.Severity != result.Low {
		t.Errorf("%q %q", n.Title, n.Severity)
	}
	if !strings.Contains(n.Body, "(0 of 1 checks)") || strings.Count(n.Body, "None.") != 2 || !strings.Contains(n.Body, "last 7 days") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func TestDigestWithoutAUsableStateOrHistory(t *testing.T) {
	in := DigestInput{GeneratedAt: genTime, Host: "h", StateNote: "token=hunter2 no state", HistoryNote: "history.json is a symlink"}
	n := BuildDigest(in, true, nil)
	if strings.Contains(n.Body, "hunter2") || !strings.Contains(n.Body, "**Open findings** are unknown: ` token=[REDACTED] no state `.") ||
		!strings.Contains(n.Body, "The history is incomplete: ` history.json is a symlink `.") || !strings.Contains(n.Title, "0 open findings") {
		t.Errorf("%q\n%s", n.Title, n.Body)
	}
	assertSafeMarkdown(t, n.Body)
}

func TestDigestIsBoundedAndNewestChangesComeFirst(t *testing.T) {
	in := digestInput()
	in.State.Checks = nil
	for i := 0; i < 80; i++ {
		in.State.Checks = append(in.State.Checks, state.Check{ID: fmt.Sprintf("c.%02d", i), Kind: "k", Status: result.Fail, Severity: result.Low})
	}
	in.Runs = nil
	for i := 0; i < 40; i++ {
		r := history.Run{RunAt: genTime.Add(-time.Duration(i+1) * time.Hour), Dropped: 2}
		for j := 0; j < 5; j++ {
			r.Changes = append(r.Changes, history.Change{Kind: "new_failure", CheckID: fmt.Sprintf("run%d.%d", i, j), Severity: "low", From: "pass", To: "fail", Alert: true, Subject: strings.Repeat("s", 150)})
		}
		in.Runs = append(in.Runs, r)
	}
	n := BuildDigest(in, true, nil)
	if len(n.Body) > MaxNoticeBytes {
		t.Errorf("%d bytes", len(n.Body))
	}
	if !strings.Contains(n.Body, "and 60 more.") || !strings.Contains(n.Body, "more lines not shown.") || !strings.Contains(n.Body, "more (older).") {
		t.Errorf("limits are not shown:\n%s", n.Body[len(n.Body)-600:])
	}
	i0 := strings.Index(n.Body, "run0.0")
	i1 := strings.Index(n.Body, "run1.0")
	if i0 < 0 || i1 < 0 || i0 > i1 {
		t.Errorf("newest first: %d %d", i0, i1)
	}
	assertSafeMarkdown(t, n.Body)
}

func TestDigestHostileTextIsOnlyEverInsideCodeSpans(t *testing.T) {
	h := "HOSTILE" + hostile
	in := digestInput()
	in.Host = h
	in.StateNote = h
	in.HistoryNote = h
	in.PrevDelivery = &DeliveryNote{At: genTime, Failures: 1, Kind: "check", Reason: h}
	for i := range in.State.Checks {
		c := &in.State.Checks[i]
		c.ID = h + c.ID
		for j := range c.Items {
			c.Items[j].Subject = h
		}
	}
	for i := range in.Runs {
		for j := range in.Runs[i].Changes {
			ch := &in.Runs[i].Changes[j]
			ch.CheckID, ch.Subject, ch.CheckKind, ch.Severity, ch.From, ch.To = h, h, h, h, h, h
		}
	}
	for _, withState := range []bool{true, false} {
		in := in
		if !withState {
			in.State = nil
		}
		for _, md := range []bool{true, false} {
			n := BuildDigest(in, md, nil)
			if strings.Contains(n.Body, "hunter2") || strings.ContainsAny(n.Title, "\r\n\x1b") || !strings.Contains(n.Body, "HOSTILE") {
				t.Errorf("md=%v state=%v: title %q\n%s", md, withState, n.Title, n.Body)
			}
			for _, r := range n.Body {
				if !isSafe(r) {
					t.Fatalf("body holds U+%04X", r)
				}
			}
			if md {
				assertSafeMarkdown(t, n.Body)
			}
		}
	}
}

func TestDigestCappedCheckCountsTheWholeSet(t *testing.T) {
	st := digestState()
	st.Checks = []state.Check{{ID: "big", Kind: "k", Status: result.Fail, Severity: result.High, Total: 500, Digest: strings.Repeat("d", 64),
		Items: []state.Item{{Key: strings.Repeat("1", 64), Subject: "s1"}, {Key: strings.Repeat("2", 64), Subject: "s2"}}}}
	n := BuildDigest(DigestInput{GeneratedAt: genTime, Host: "h", State: st}, true, nil)
	if !strings.Contains(n.Body, "` s1 `, ` s2 ` and 498 more") {
		t.Errorf("body:\n%s", n.Body)
	}
}

func TestDigestListsAtMostTwentyFiveChangesAndTwentyFindings(t *testing.T) {
	in := digestInput()
	in.State.Checks = nil
	for i := 0; i < 30; i++ {
		in.State.Checks = append(in.State.Checks, state.Check{ID: fmt.Sprintf("c.%02d", i), Kind: "k", Status: result.Fail, Severity: result.Low})
	}
	in.Runs = nil
	for i := 0; i < 30; i++ {
		in.Runs = append(in.Runs, history.Run{RunAt: genTime.Add(-time.Duration(i+1) * time.Hour), Changes: []history.Change{
			{Kind: "fixed", CheckID: fmt.Sprintf("r%02d", i), Severity: "low", From: "fail", To: "pass"}}})
	}
	n := BuildDigest(in, true, nil)
	if got := strings.Count(n.Body, "fixed (was failing)"); got != maxDigestChanges {
		t.Errorf("%d change lines, want %d:\n%s", got, maxDigestChanges, n.Body)
	}
	if got := strings.Count(n.Body, "- FAIL "); got != maxDigestOpen {
		t.Errorf("%d findings, want %d", got, maxDigestOpen)
	}
	if !strings.Contains(n.Body, "and 10 more.") || !strings.Contains(n.Body, "and 5 more (older).") || strings.Contains(n.Body, "not shown") {
		t.Errorf("body:\n%s", n.Body)
	}
	// Newest first: r00 is the newest, r24 the last one listed.
	if !strings.Contains(n.Body, "` r24 `") || strings.Contains(n.Body, "` r25 `") {
		t.Errorf("the wrong end was cut:\n%s", n.Body)
	}
}

func TestDigestSortsEqualSeveritiesById(t *testing.T) {
	in := DigestInput{GeneratedAt: genTime, Host: "h", State: &state.State{SchemaVersion: state.SchemaVersion, RunAt: genTime, Checks: []state.Check{
		{ID: "b.check", Kind: "k", Status: result.Fail, Severity: result.High},
		{ID: "a.check", Kind: "k", Status: result.Fail, Severity: result.High},
		{ID: "z.check", Kind: "k", Status: result.Fail, Severity: result.Critical},
	}}}
	body := BuildDigest(in, false, nil).Body
	z, a, b := strings.Index(body, "z.check"), strings.Index(body, "a.check"), strings.Index(body, "b.check")
	if !(z < a && a < b) {
		t.Errorf("order z=%d a=%d b=%d:\n%s", z, a, b, body)
	}
}

func TestNoticeListsTheHighestSeverityFirstAndNeverLosesTheCriticalAlert(t *testing.T) {
	var changes []diff.Change
	for i := 0; i < 50; i++ {
		changes = append(changes, diff.Change{Kind: diff.SubjectNew, CheckID: "network.listeners", CheckKind: "listeners", Severity: result.Medium,
			Subject: fmt.Sprintf("tcp/0.0.0.0:%d", 1000+i), Alert: true})
	}
	changes = append(changes, diff.Change{Kind: diff.SubjectNew, CheckID: "ssh.authorized_keys", CheckKind: "authorized_keys", Severity: result.Critical,
		Subject: "SHA256:newkey", Alert: true})
	n, ok := BuildNotice(changeInput(changes...), nil, nil)
	if !ok {
		t.Fatal("no notice")
	}
	if n.Severity != result.Critical || !strings.HasPrefix(n.Body, "**51 alerts**") {
		t.Errorf("severity %q, body starts %q", n.Severity, n.Body[:20])
	}
	crit := strings.Index(n.Body, "ssh.authorized_keys")
	first := strings.Index(n.Body, "network.listeners")
	if crit < 0 || crit > first {
		t.Errorf("the critical alert is missing or not first (%d, %d):\n%s", crit, first, n.Body)
	}
	if !strings.Contains(n.Body, "more lines not shown.") {
		t.Errorf("the medium alerts did not need to be cut: the test is vacuous:\n%s", n.Body)
	}
	// Order among equal severities stays the order of the report.
	n, _ = BuildNotice(changeInput(alertChange(result.Low), alertChange(result.High), alertChange(result.Low), alertChange(result.High)), nil, nil)
	hi, lo := strings.Index(n.Body, "` high `"), strings.Index(n.Body, "` low `")
	if hi < 0 || lo < 0 || hi > lo {
		t.Errorf("order:\n%s", n.Body)
	}
}

func TestNoticeCutsEveryUntrustedStringAndStillShowsALine(t *testing.T) {
	long := strings.Repeat("\u4e16", 2000) // 3 bytes each
	in := changeInput(diff.Change{Kind: diff.SubjectNew, CheckID: "a.b", CheckKind: "k", Severity: result.High, Subject: long, Alert: true})
	in.Diff.StillFailing = []diff.Ref{{CheckID: long}}
	n, ok := BuildNotice(in, &DeliveryNote{At: genTime, Failures: 1, Kind: "check", Reason: long}, nil)
	if !ok {
		t.Fatal("no notice")
	}
	if !strings.Contains(n.Body, "**Alerts**\n\n- ` a.b `") || strings.Contains(n.Body, "not shown") {
		t.Errorf("the alert line is missing:\n%s", n.Body)
	}
	want := strings.Repeat("\u4e16", maxNoticeRunes) + "..."
	if got := strings.Count(n.Body, want); got != 3 { // subject, reason, still failing
		t.Errorf("%d cut strings, want 3:\n%s", got, n.Body)
	}
	if strings.Contains(n.Body, strings.Repeat("\u4e16", maxNoticeRunes+1)) || len(n.Body) > MaxNoticeBytes {
		t.Errorf("a string is longer than the cut, or the body is %d bytes", len(n.Body))
	}
	// A cut never splits a character.
	for _, r := range n.Body {
		if r == '\ufffd' {
			t.Fatal("a character was split")
		}
	}
	// Baseline and digest too.
	base := baselineNoticeInput()
	base.Results[0].CheckID = long
	base.Results[0].Evidence[0].Subject = long
	base.State.Reason = long
	nb, _ := BuildNotice(base, nil, nil)
	if strings.Contains(nb.Body, strings.Repeat("\u4e16", maxNoticeRunes+1)) || !strings.Contains(nb.Body, want) || len(nb.Body) > MaxNoticeBytes {
		t.Errorf("baseline body of %d bytes", len(nb.Body))
	}
	d := digestInput()
	d.State.Checks[2].ID = long
	d.Runs[0].Changes[0].Subject = long
	nd := BuildDigest(d, true, nil)
	if strings.Contains(nd.Body, strings.Repeat("\u4e16", maxNoticeRunes+1)) || !strings.Contains(nd.Body, want) {
		t.Errorf("digest:\n%s", nd.Body)
	}
}

func TestCutRunes(t *testing.T) {
	if got := cutRunes("abc", 3); got != "abc" {
		t.Errorf("%q", got)
	}
	if got := cutRunes("abcd", 3); got != "abc..." {
		t.Errorf("%q", got)
	}
	if got := cutRunes("\u4e16\u4e16\u4e16", 2); got != "\u4e16\u4e16..." {
		t.Errorf("%q", got)
	}
}

func TestNoticeAfterAFailedFirstRunSendsTheOpenFindingsAsAFirstReport(t *testing.T) {
	in := baselineNoticeInput()
	in.State = StateInfo{Used: true, PrevRunAt: genTime.Add(-time.Hour)} // not a baseline any more
	in.Diff = diff.Report{Changes: []diff.Change{alertChange(result.High)}}
	prev := &DeliveryNote{At: genTime, Failures: 2, Kind: "baseline", Reason: "HTTP 503"}
	n, ok := BuildNotice(in, prev, nil)
	if !ok {
		t.Fatal("no notice")
	}
	if n.Title != "keepwatch web-01: first report, 4 open findings" {
		t.Errorf("title %q", n.Title)
	}
	for _, want := range []string{"**First report:** the notification of the first run could not be delivered", "the first notification (the open findings) could not be delivered", "(2 runs in a row)", "**Open findings**", "- FAIL ` ssh.pw `"} {
		if !strings.Contains(n.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, n.Body)
		}
	}
	for _, bad := range []string{"everything since the last report", "**Alerts**", "no previous run"} {
		if strings.Contains(n.Body, bad) {
			t.Errorf("body holds %q:\n%s", bad, n.Body)
		}
	}
	// The same record in a digest.
	d := digestInput()
	d.PrevDelivery = prev
	if nd := BuildDigest(d, true, nil); !strings.Contains(nd.Body, "the first notification (the open findings) could not be delivered") {
		t.Errorf("digest:\n%s", nd.Body)
	}
}
