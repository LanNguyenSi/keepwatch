package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/state"
)

func (f *fixture) report(args ...string) (int, string, string) {
	f.t.Helper()
	var out, errb bytes.Buffer
	code := dispatch(f.env, append([]string{"report", "--config", f.cfgPath}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

// weekFixture runs `check` a few times over several days: a new failure on
// the second run and a fix on the third.
func weekFixture(t *testing.T, n *fakeNtfy) *fixture {
	t.Helper()
	f := notifyFixture(t, n, goodHost(), "")
	f.check()
	f.clock = f.clock.Add(24 * time.Hour)
	f.env.runner = goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)).AddResult(ssTCP, res("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n", 0))
	f.check()
	f.clock = f.clock.Add(24 * time.Hour)
	f.env.runner = goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0))
	f.check()
	f.clock = f.clock.Add(24 * time.Hour)
	return f
}

func TestReportWithoutWeeklyStaysAStub(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	code, _, errb := f.report()
	if code != 3 || !strings.Contains(errb, "not implemented without --weekly") {
		t.Errorf("exit %d stderr %q", code, errb)
	}
	if code, _, _ := f.report("--notify"); code != 3 {
		t.Errorf("exit %d", code)
	}
}

func TestReportWeeklyPrintsTheDigest(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	code, out, errb := f.report("--weekly")
	if code != 0 || errb != "" {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	for _, want := range []string{
		"Keepwatch weekly report for host testhost, 2026-11-13T12:00:00Z, last 7 days.",
		"Open findings (1 of 3 checks), state of 2026-11-12T12:00:00Z:",
		"- FAIL t.sshd (high): passwordauthentication",
		"Changes in the last 7 days (3 runs recorded, 3 changes, 2 alerts, 1 fixed or gone):",
		"- ALERT 2026-11-11T12:00:00Z t.sshd (high): now failing (was pass)",
		"- 2026-11-12T12:00:00Z t.listeners (low): fixed (was failing)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the digest lacks %q:\n%s", want, out)
		}
	}
	if n.count() != 0 {
		t.Errorf("%d requests without --notify", n.count())
	}
	// Markdown on request; json is not offered.
	_, md, _ := f.report("--weekly", "--format", "markdown")
	if !strings.Contains(md, "**keepwatch weekly report** for host ` testhost `") {
		t.Errorf("markdown:\n%s", md)
	}
	if code, _, errb := f.report("--weekly", "--format", "json"); code != 2 || !strings.Contains(errb, "text, markdown") {
		t.Errorf("exit %d stderr %q", code, errb)
	}
	if code, _, _ := f.report("--weekly", "--format", "xml"); code != 2 {
		t.Errorf("exit %d", code)
	}
}

func TestReportWeeklyListsOnlyTheLastSevenDays(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	f.clock = f.clock.Add(6 * 24 * time.Hour) // the runs of day 0 and 1 are older than 7 days, the one of day 2 is exactly 7
	_, out, _ := f.report("--weekly")
	if strings.Contains(out, "t.sshd (high): now failing") || !strings.Contains(out, "(1 run recorded, 1 change, 0 alerts") || !strings.Contains(out, "t.listeners (low): fixed") {
		t.Errorf("digest:\n%s", out)
	}
}

func TestReportWeeklyWithoutStateOrHistory(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	code, out, errb := f.report("--weekly")
	if code != 0 || errb != "" || !strings.Contains(out, "Open findings are unknown: no run has been recorded yet.") ||
		!strings.Contains(out, "(0 runs recorded, 0 changes") {
		t.Errorf("exit %d stderr %q\n%s", code, errb, out)
	}
}

func TestReportWeeklyWithABrokenHistoryWarnsAndGoesOn(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	if err := os.WriteFile(filepath.Join(f.stateDir, "history.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb := f.report("--weekly")
	if code != 0 || !strings.Contains(errb, "the history was not used") || !strings.Contains(out, "The history is incomplete:") ||
		!strings.Contains(out, "- FAIL t.sshd (high)") {
		t.Errorf("exit %d stderr %q\n%s", code, errb, out)
	}
	// And so does a state file that cannot be used.
	if err := os.WriteFile(f.statePath(), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errb = f.report("--weekly")
	if code != 0 || !strings.Contains(errb, "the state was not used") || !strings.Contains(out, "Open findings are unknown:") {
		t.Errorf("exit %d stderr %q\n%s", code, errb, out)
	}
}

func TestReportWeeklyWithAnUntrustedStateDirectoryExits3(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	if err := os.Mkdir(f.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := f.report("--weekly"); code != 3 || !strings.Contains(errb, "state is not usable") {
		t.Errorf("exit %d stderr %q", code, errb)
	}
}

func TestReportWeeklyNotifySendsTheDigestAndPrintsNothingElse(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	before, _ := os.ReadFile(f.statePath())
	code, out, errb := f.report("--weekly", "--notify")
	if code != 0 || errb != "" || out != "keepwatch report: the weekly report was sent\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errb)
	}
	if n.count() != 1 {
		t.Fatalf("%d requests", n.count())
	}
	r := n.last()
	if r.Path != "/alerts" || r.Header.Get("Markdown") != "yes" || r.Header.Get("Priority") != "3" || r.Header.Get("Tags") != "keepwatch,calendar" ||
		r.Header.Get("Title") != "keepwatch testhost: weekly report, 1 open finding" || r.Header.Get("Authorization") != "Bearer "+testToken {
		t.Errorf("headers %v", r.Header)
	}
	if !strings.Contains(r.Body, "**Open findings** (1 of 3 checks)") || !strings.Contains(r.Body, "- **ALERT** ` 2026-11-11T12:00:00Z ` ` t.sshd `") {
		t.Errorf("body:\n%s", r.Body)
	}
	if after, _ := os.ReadFile(f.statePath()); string(after) != string(before) {
		t.Error("a delivered report changed the state")
	}
}

func TestReportWeeklyNotifyFailureIsExit4AndRecordedAndTheNextCheckSaysSo(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	n.answer(503, 503)
	code, _, errb := f.report("--weekly", "--notify")
	if code != ExitDelivery || !strings.Contains(errb, "the weekly report was not delivered") || n.count() != 2 {
		t.Fatalf("exit %d stderr %q, %d requests", code, errb, n.count())
	}
	d := f.delivery()
	if d == nil || d.Kind != state.DeliveryWeekly || d.Failures != 1 {
		t.Fatalf("record %+v", d)
	}
	if c := f.loadState().Find("t.sshd"); c == nil || c.Status != "fail" {
		t.Error("the snapshot changed")
	}
	// The weekly record does not hold the snapshot back: a run without
	// --notify moves it and keeps the record.
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	if code, _, errb := f.check(); code != 1 || strings.Contains(errb, "not moved forward") {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	if d := f.delivery(); d == nil || d.Kind != state.DeliveryWeekly {
		t.Errorf("record after a run without --notify: %+v", d)
	}
	// The next run with --notify tells it, although nothing changed.
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, _, _ = f.check("--notify")
	if code != 1 || n.count() != 3 {
		t.Fatalf("exit %d, %d requests", code, n.count())
	}
	r := n.last()
	if !strings.Contains(r.Body, "the weekly report could not be delivered") || !strings.Contains(r.Header.Get("Title"), "earlier notification was not delivered") ||
		strings.Contains(r.Body, "everything since the last report") {
		t.Errorf("message %v\n%s", r.Header, r.Body)
	}
	if f.delivery() != nil {
		t.Error("record not cleared")
	}
}

func TestReportWeeklyNotifyFailureKeepsAnExistingRecord(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	// A check run whose notification fails leaves a record of kind check.
	n.answer(500, 500)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)).AddResult(svcArgv, res("inactive\n", 3)))
	if code, _, _ := f.check("--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	n.answer(500, 500)
	if code, _, _ := f.report("--weekly", "--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	if d := f.delivery(); d == nil || d.Kind != state.DeliveryCheck || d.Failures != 1 {
		t.Errorf("the record of the undelivered changes was overwritten: %+v", d)
	}
}

func TestReportWeeklyNotifyWithoutAStateStillExit4(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	n.answer(401)
	code, _, errb := f.report("--weekly", "--notify")
	if code != ExitDelivery || n.count() != 1 {
		t.Errorf("exit %d, %d requests, stderr %q", code, n.count(), errb)
	}
	if _, err := os.Stat(f.statePath()); err == nil {
		t.Error("a state file was created by the report")
	}
}

func TestReportWeeklyNotifyNeedsNtfyInTheConfiguration(t *testing.T) {
	f := newFixture(t, goodHost(), "")
	code, _, errb := f.report("--weekly", "--notify")
	if code != 3 || !strings.Contains(errb, "notify.ntfy is not configured") {
		t.Errorf("exit %d stderr %q", code, errb)
	}
}

func TestReportWeeklyShowsAPendingDeliveryFailure(t *testing.T) {
	n := newFakeNtfy(t)
	f := weekFixture(t, n)
	n.answer(500, 500)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)).AddResult(svcArgv, res("inactive\n", 3)))
	if code, _, _ := f.check("--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	_, out, _ := f.report("--weekly")
	if !strings.Contains(out, "Last delivery failed: the notification of an earlier run could not be delivered at") || !strings.Contains(out, "HTTP 500") {
		t.Errorf("digest:\n%s", out)
	}
}
