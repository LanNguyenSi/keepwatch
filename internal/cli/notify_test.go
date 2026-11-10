package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/notify"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

const testToken = "tk_0123456789abcdefghijklmnopqrs"

// recorded is one request the fake ntfy server received.
type recorded struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

// fakeNtfy is an ntfy server that records what it gets and answers with the
// statuses it is told to (200 once the list is used up).
type fakeNtfy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []recorded
	// answers are the statuses of the next requests, in order.
	answers []int
}

func newFakeNtfy(t *testing.T) *fakeNtfy {
	t.Helper()
	n := &fakeNtfy{}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		n.reqs = append(n.reqs, recorded{r.Method, r.URL.Path, r.Header.Clone(), string(b)})
		status := 200
		if len(n.answers) > 0 {
			status, n.answers = n.answers[0], n.answers[1:]
		}
		n.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"id":"x"}`)
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNtfy) answer(statuses ...int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.answers = append(n.answers, statuses...)
}

func (n *fakeNtfy) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.reqs)
}

func (n *fakeNtfy) last() recorded {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.reqs) == 0 {
		return recorded{}
	}
	return n.reqs[len(n.reqs)-1]
}

// notifyConfig is the configuration block for the fake server and a token
// file that satisfies the rules of the config package.
func notifyConfig(t *testing.T, n *fakeNtfy) string {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "ntfy.token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return "notify:\n  ntfy:\n    url: " + n.srv.URL + "\n    topic: alerts\n    token_file: " + tokenFile + "\n"
}

// notifyFixture is a fixture whose environment sends to the fake server
// without waiting between the two attempts.
func notifyFixture(t *testing.T, n *fakeNtfy, runner execx.Runner, extra string) *fixture {
	t.Helper()
	f := newFixture(t, runner, notifyConfig(t, n)+extra)
	f.env.notifyOpts = []notify.Option{
		notify.WithBackoff(0),
		notify.WithSleep(func(context.Context, time.Duration) error { return nil }),
	}
	return f
}

// next moves the clock one hour on and installs the runner of the next run.
func (f *fixture) next(r execx.Runner) {
	f.clock = f.clock.Add(time.Hour)
	f.env.runner = r
}

func (f *fixture) delivery() *state.Delivery {
	f.t.Helper()
	return f.loadState().Delivery
}

func (f *fixture) history() history.File {
	f.t.Helper()
	hs, err := history.Open(f.stateDir)
	if err != nil {
		f.t.Fatal(err)
	}
	lr, err := hs.Load()
	if err != nil || lr.Problem != "" {
		f.t.Fatalf("history: %v %q", err, lr.Problem)
	}
	return lr.File
}

func TestNotifyFirstRunSendsOneBaselineNotice(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	code, _, errb := f.check("--notify")
	if code != 1 || n.count() != 1 {
		t.Fatalf("exit %d, %d requests, stderr %q", code, n.count(), errb)
	}
	r := n.last()
	if r.Method != "POST" || r.Path != "/alerts" {
		t.Errorf("request %s %s", r.Method, r.Path)
	}
	h := r.Header
	if h.Get("Authorization") != "Bearer "+testToken || h.Get("Markdown") != "yes" ||
		!strings.Contains(h.Get("Title"), "first run, 3 open findings") || h.Get("Priority") != "4" ||
		!strings.Contains(h.Get("Tags"), "keepwatch") {
		t.Errorf("headers %v", h)
	}
	for _, want := range []string{"**First run:**", "**Open findings**", "- FAIL ` t.sshd ` (` high `)", "- FAIL ` t.service ` (` medium `)", "- FAIL ` t.listeners ` (` low `): ` tcp/0.0.0.0:8080 `"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, r.Body)
		}
	}
	if st := f.loadState(); st.Delivery != nil {
		t.Errorf("delivery record after a delivery: %+v", st.Delivery)
	}
	if h := f.history(); len(h.Runs) != 1 || !h.Runs[0].Baseline {
		t.Errorf("history %+v", h)
	}
}

func TestNotifyDoesNotSendWithoutTheFlag(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	f.check()
	f.next(goodHost())
	f.check()
	if n.count() != 0 {
		t.Errorf("%d requests without --notify", n.count())
	}
}

func TestNotifyEmptyDiffSendsNothing(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify") // the baseline notice
	if n.count() != 1 {
		t.Fatalf("baseline: %d requests", n.count())
	}
	for i := 0; i < 3; i++ {
		f.next(goodHost())
		if code, _, errb := f.check("--notify"); code != 0 {
			t.Fatalf("exit %d %s", code, errb)
		}
	}
	if n.count() != 1 {
		t.Errorf("%d requests, want only the baseline notice", n.count())
	}
}

func TestNotifyStillFailingAloneSendsNothing(t *testing.T) {
	// The exit code is 1 on every run while the host stays bad: it must not
	// decide whether there is something to tell.
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	f.check("--notify")
	f.next(badHost())
	if code, _, _ := f.check("--notify"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if n.count() != 1 {
		t.Errorf("%d requests, want only the baseline notice", n.count())
	}
}

func TestNotifySendsAnAlertForANewFailure(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, _, errb := f.check("--notify")
	if code != 1 || n.count() != 2 {
		t.Fatalf("exit %d, %d requests, stderr %q", code, n.count(), errb)
	}
	r := n.last()
	if r.Header.Get("Title") != "keepwatch testhost: 1 alert" || r.Header.Get("Priority") != "4" || r.Header.Get("Tags") != "keepwatch,rotating_light" {
		t.Errorf("headers %v", r.Header)
	}
	if !strings.Contains(r.Body, "- ` t.sshd ` (` high `): ` now failing (was pass) `") || !strings.Contains(r.Body, "**1 alert**") {
		t.Errorf("body:\n%s", r.Body)
	}
	if len(f.history().Runs) != 2 {
		t.Errorf("history %+v", f.history())
	}
}

func TestNotifyPriorityFollowsTheHighestAlert(t *testing.T) {
	// medium (service) and low (listener) alerts: priority 3.
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	f.next(goodHost().AddResult(svcArgv, res("inactive\n", 3)))
	f.check("--notify")
	if p := n.last().Header.Get("Priority"); p != "3" {
		t.Errorf("priority %q", p)
	}
	if tags := n.last().Header.Get("Tags"); tags != "keepwatch,warning" {
		t.Errorf("tags %q", tags)
	}
}

func TestNotifyAFixAloneSendsNothingButMovesTheState(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	f.check("--notify")
	f.next(goodHost())
	if code, _, _ := f.check("--notify"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n.count() != 1 {
		t.Errorf("%d requests: a fix is not an alert", n.count())
	}
	if c := f.loadState().Find("t.service"); c == nil || c.Status != "pass" {
		t.Errorf("the state did not move forward: %+v", c)
	}
}

func TestNotifyDeliveryFailureKeepsTheStateAndTheNextRunTellsAgain(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	before, _ := os.ReadFile(f.statePath())
	histBefore, _ := os.ReadFile(filepath.Join(f.stateDir, "history.json"))

	// The server is down for both attempts.
	n.answer(503, 503)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, _, errb := f.check("--notify")
	if code != ExitDelivery || !strings.Contains(errb, "the notification was not delivered") || !strings.Contains(errb, "HTTP 503") {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	if n.count() != 3 { // baseline + 2 attempts
		t.Errorf("%d requests", n.count())
	}
	st := f.loadState()
	if st.Delivery == nil || st.Delivery.Kind != state.DeliveryCheck || st.Delivery.Failures != 1 || !strings.Contains(st.Delivery.Reason, "HTTP 503") {
		t.Fatalf("delivery record %+v", st.Delivery)
	}
	if c := st.Find("t.sshd"); c == nil || c.Status != "pass" {
		t.Errorf("the failed change was committed as seen: %+v", c)
	}
	if !st.RunAt.Equal(f.loadStateRunAt(before)) {
		t.Errorf("run_at moved: %v", st.RunAt)
	}
	if after, _ := os.ReadFile(filepath.Join(f.stateDir, "history.json")); string(after) != string(histBefore) {
		t.Errorf("the history recorded a run that was not delivered")
	}

	// Still down: the failure count grows, the state still does not move.
	n.answer(500, 500)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	if code, _, _ := f.check("--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	if d := f.delivery(); d == nil || d.Failures != 2 {
		t.Errorf("delivery record %+v", d)
	}

	// The server is back: the change is told, together with the failure.
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, out, errb := f.check("--notify")
	if code != 1 {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	if !strings.Contains(out, "last delivery failed") || !strings.Contains(errb, "last delivery failed") {
		t.Errorf("the report does not mention the failure:\n%s\n%s", out, errb)
	}
	r := n.last()
	for _, want := range []string{"**Last delivery failed:**", "(2 runs in a row)", "- ` t.sshd ` (` high `): ` now failing (was pass) `", "everything since the last report that was delivered"} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, r.Body)
		}
	}
	if st := f.loadState(); st.Delivery != nil || st.Find("t.sshd").Status != "fail" {
		t.Errorf("state after the delivery: %+v", st)
	}
	if len(f.history().Runs) != 2 {
		t.Errorf("history has %d runs, want the baseline and the delivered run", len(f.history().Runs))
	}
	// And now it is quiet.
	before3 := n.count()
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	f.check("--notify")
	if n.count() != before3 {
		t.Errorf("sent again after the delivery")
	}
}

func (f *fixture) loadStateRunAt(raw []byte) time.Time {
	f.t.Helper()
	// run_at of the snapshot stored before the failed run.
	i := strings.Index(string(raw), `"run_at": "`)
	if i < 0 {
		f.t.Fatalf("no run_at in %s", raw)
	}
	s := string(raw)[i+len(`"run_at": "`):]
	ts, err := time.Parse(time.RFC3339, s[:strings.Index(s, `"`)])
	if err != nil {
		f.t.Fatal(err)
	}
	return ts
}

func TestNotifyRetriesOnceThenSucceeds(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	n.answer(502)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, _, _ := f.check("--notify")
	if code != 1 || n.count() != 3 {
		t.Errorf("exit %d, %d requests", code, n.count())
	}
	if f.loadState().Delivery != nil {
		t.Error("delivery record after a delivery on the second attempt")
	}
}

func TestNotifyAuthFailureIsExit4WithoutRetry(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			n := newFakeNtfy(t)
			f := notifyFixture(t, n, goodHost(), "")
			n.answer(status)
			code, _, errb := f.check("--notify")
			if code != ExitDelivery || n.count() != 1 {
				t.Fatalf("exit %d, %d requests, stderr %q", code, n.count(), errb)
			}
			if strings.Contains(errb, testToken) {
				t.Error("the token is in the output")
			}
		})
	}
}

func TestNotifyFailedBaselineIsStoredAsItsOwnKindAndTheOpenFindingsAreResent(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	n.answer(500, 500)
	if code, _, _ := f.check("--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	st := f.loadState()
	if st.Delivery == nil || st.Delivery.Kind != state.DeliveryBaseline || len(st.Checks) != 3 {
		t.Fatalf("state %+v", st)
	}
	if len(f.history().Runs) != 0 {
		t.Error("history written for an undelivered run")
	}
	// Still down: the kind stays, the count grows.
	n.answer(500, 500)
	f.next(badHost())
	if code, _, _ := f.check("--notify"); code != ExitDelivery {
		t.Fatalf("exit %d", code)
	}
	if d := f.delivery(); d == nil || d.Kind != state.DeliveryBaseline || d.Failures != 2 {
		t.Fatalf("record %+v", d)
	}
	// A run without --notify does not hold the snapshot (the open findings
	// are resent from the results of the run that delivers) and keeps the
	// record.
	f.next(badHost().AddResult(svcArgv, res("active\n", 0)))
	if code, _, errb := f.check(); code != 1 || strings.Contains(errb, "not moved forward") {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	if d := f.delivery(); d == nil || d.Kind != state.DeliveryBaseline {
		t.Fatalf("record after a run without --notify: %+v", d)
	}
	f.next(badHost().AddResult(svcArgv, res("active\n", 0)))
	code, _, _ := f.check("--notify")
	if code != 1 || n.count() != 5 {
		t.Fatalf("exit %d, %d requests", code, n.count())
	}
	r := n.last()
	if !strings.HasPrefix(r.Body, "**First report:**") || !strings.Contains(r.Header.Get("Title"), "first report, 2 open findings") ||
		!strings.Contains(r.Body, "**Last delivery failed:** the first notification (the open findings) could not be delivered") ||
		!strings.Contains(r.Body, "- FAIL ` t.sshd ` (` high `)") || strings.Contains(r.Body, "everything since the last report") ||
		strings.Contains(r.Body, "t.service") {
		t.Errorf("last message:\n%v\n%s", r.Header, r.Body)
	}
	if f.loadState().Delivery != nil {
		t.Error("record not cleared")
	}
	// And it is quiet afterwards.
	f.next(badHost().AddResult(svcArgv, res("active\n", 0)))
	f.check("--notify")
	if n.count() != 5 {
		t.Errorf("%d requests", n.count())
	}
}

func TestNotifyAfterAFailureWithNothingToTellStillTellsTheFailure(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	n.answer(500, 500)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	f.check("--notify")
	// The host is fine again: nothing to compare with the delivered state.
	f.next(goodHost())
	code, _, _ := f.check("--notify")
	if code != 0 || n.count() != 4 {
		t.Fatalf("exit %d, %d requests", code, n.count())
	}
	r := n.last()
	if !strings.Contains(r.Header.Get("Title"), "earlier notification was not delivered") || strings.Contains(r.Body, "**Alerts**") {
		t.Errorf("message %v\n%s", r.Header, r.Body)
	}
	if f.loadState().Delivery != nil {
		t.Error("record not cleared")
	}
}

func TestNotifyDeliveryFailureBeatsExit1AndInternalErrorBeatsDelivery(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	n.answer(500, 500)
	// The checks fail (exit 1) and the delivery fails: 4.
	if code, _, _ := f.check("--notify"); code != 4 {
		t.Errorf("exit %d, want 4", code)
	}
	// An unusable state directory (3) sends nothing and wins.
	f2 := notifyFixture(t, n, badHost(), "")
	if err := os.Mkdir(f2.stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f2.stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	before := n.count()
	code, _, errb := f2.check("--notify")
	if code != 3 || n.count() != before || !strings.Contains(errb, "no notification is sent") {
		t.Errorf("exit %d, %d new requests, stderr %q", code, n.count()-before, errb)
	}
}

func TestNotifyWithoutTheFlagDoesNotMoveThePendingState(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	n.answer(500, 500)
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	f.check("--notify")
	before, _ := os.ReadFile(f.statePath())

	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	code, out, errb := f.check()
	if code != 1 || !strings.Contains(errb, "the state is not moved forward") || !strings.Contains(out, "last delivery failed") {
		t.Errorf("exit %d\n%s\n%s", code, out, errb)
	}
	if after, _ := os.ReadFile(f.statePath()); string(after) != string(before) {
		t.Errorf("a run without --notify moved the state that holds undelivered changes:\n%s", after)
	}
	// The change is still told by the next run with --notify.
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	f.check("--notify")
	if !strings.Contains(n.last().Body, "` t.sshd `") {
		t.Errorf("last body:\n%s", n.last().Body)
	}
}

func TestNotifyConfigurationProblemsSendNothing(t *testing.T) {
	t.Run("not configured", func(t *testing.T) {
		f := newFixture(t, badHost(), "")
		code, _, errb := f.check("--notify")
		if code != 3 || !strings.Contains(errb, "notify.ntfy is not configured") {
			t.Errorf("exit %d stderr %q", code, errb)
		}
		if _, err := os.Stat(f.statePath()); err == nil {
			t.Error("checks ran and stored state")
		}
	})
	t.Run("no state", func(t *testing.T) {
		n := newFakeNtfy(t)
		f := notifyFixture(t, n, badHost(), "")
		if code, _, errb := f.check("--notify", "--no-state"); code != 2 || !strings.Contains(errb, "--no-state") {
			t.Errorf("exit %d stderr %q", code, errb)
		}
	})
	t.Run("token file missing", func(t *testing.T) {
		n := newFakeNtfy(t)
		f := notifyFixture(t, n, badHost(), "")
		cfg := "notify:\n  ntfy:\n    url: " + n.srv.URL + "\n    topic: alerts\n    token_file: " + filepath.Join(t.TempDir(), "nope") + "\n"
		f.writeConfig(cfg)
		code, _, errb := f.check("--notify")
		if code != 3 || n.count() != 0 || !strings.Contains(errb, "token_file") {
			t.Errorf("exit %d, %d requests, stderr %q", code, n.count(), errb)
		}
	})
	t.Run("token file too open", func(t *testing.T) {
		n := newFakeNtfy(t)
		f := notifyFixture(t, n, badHost(), "")
		tokenFile := filepath.Join(t.TempDir(), "ntfy.token")
		if err := os.WriteFile(tokenFile, []byte(testToken), 0o644); err != nil {
			t.Fatal(err)
		}
		f.writeConfig("notify:\n  ntfy:\n    url: " + n.srv.URL + "\n    topic: alerts\n    token_file: " + tokenFile + "\n")
		code, _, errb := f.check("--notify")
		if code != 3 || n.count() != 0 || !strings.Contains(errb, "token_file") {
			t.Errorf("exit %d, %d requests, stderr %q", code, n.count(), errb)
		}
		if strings.Contains(errb, testToken) {
			t.Error("the token is in the output")
		}
	})
	t.Run("bad topic", func(t *testing.T) {
		n := newFakeNtfy(t)
		f := notifyFixture(t, n, badHost(), "")
		f.writeConfig("notify:\n  ntfy:\n    url: " + n.srv.URL + "\n    topic: \"a/b\"\n")
		code, _, errb := f.check("--notify")
		if code != 3 || n.count() != 0 || !strings.Contains(errb, "topic") {
			t.Errorf("exit %d, %d requests, stderr %q", code, n.count(), errb)
		}
	})
}

func TestNotifySecretsAndHostileTextNeverReachTheServer(t *testing.T) {
	// An expired exception carries its match into a check subject; the
	// match holds a secret, a terminal escape, markdown and a configured
	// pattern. The host name is hostile too.
	n := newFakeNtfy(t)
	hostile := `password=hunter2 \e[2J [x](http://evil.example/a) ![i](http://evil.example/p.png) <img src=x> @all ` + "`` ```" + ` ghp_abcdefghijklmnopqrstuvwxyz0123456789 secret-host-7`
	extra := "redact:\n  patterns:\n    - 'secret-host-[0-9]+'\n"
	exc := func(match string) string {
		return "  - check: t.listeners\n    match: \"" + match + "\"\n    reason: old\n    expires: 2020-01-01\n"
	}
	f := notifyFixture(t, n, badHost(), extra)
	notifyCfg := notifyConfig(t, n)
	f.env.hostname = func() (string, error) { return "host\r\nX-Evil: 1 token=hostsecret99", nil }
	f.writeConfig(notifyCfg + extra + "exceptions:\n" + exc("first secret-host-1"))
	f.check("--notify") // baseline: the first expired exception is an open finding
	f.writeConfig(notifyCfg + extra + "exceptions:\n" + exc("first secret-host-1") + exc(hostile))
	f.next(badHost())
	code, _, errb := f.check("--notify")
	if code != 1 || n.count() != 2 {
		t.Fatalf("exit %d, %d requests, stderr %s", code, n.count(), errb)
	}
	for i := 0; i < n.count(); i++ {
		n.mu.Lock()
		r := n.reqs[i]
		n.mu.Unlock()
		all := r.Body + "\n" + r.Header.Get("Title")
		for _, bad := range []string{"hunter2", "ghp_abcdefgh", "secret-host-", "hostsecret99", "\x1b", "\r"} {
			if strings.Contains(all, bad) {
				t.Errorf("request %d: %q reached the server:\n%v\n%s", i, bad, r.Header, r.Body)
			}
		}
		if r.Header.Get("X-Evil") != "" || strings.ContainsAny(r.Header.Get("Title"), "\r\n") {
			t.Errorf("request %d: header injection: %v", i, r.Header)
		}
	}
	body := n.last().Body
	for _, want := range []string{"[REDACTED]", "[x](http://evil.example/a)", `\x1b[2J`} {
		if !strings.Contains(body, want) {
			t.Errorf("the body lacks %q:\n%s", want, body)
		}
	}
}

func TestNotifyAnErrorResultIsNotAnAlertPerEvidenceItem(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	// ss fails: the listeners check is in error, one change of status.
	f.next(goodHost().AddResult(ssTCP, res("", 1)))
	code, _, _ := f.check("--notify")
	if code != 0 || n.count() != 2 { // the listeners check is low: below --fail-on
		t.Fatalf("exit %d, %d requests", code, n.count())
	}
	b := n.last().Body
	if strings.Count(b, "t.listeners") != 1 || !strings.Contains(b, "**1 alert**") {
		t.Errorf("body:\n%s", b)
	}
}

func TestNotifyBaselineWithAnUnusableOldStateIsOneNotice(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, badHost(), "")
	if err := os.MkdirAll(f.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.statePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, _ := f.check("--notify")
	if code != 1 || n.count() != 1 || !strings.Contains(n.last().Header.Get("Title"), "first run") || !strings.Contains(n.last().Body, "not usable") {
		t.Errorf("exit %d, %d requests, last %v\n%s", code, n.count(), n.last().Header, n.last().Body)
	}
}

func TestNotifyTimeoutIsAFailureTooAndNeverLeaksTheTopic(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })
	tokenFile := filepath.Join(t.TempDir(), "t")
	_ = os.WriteFile(tokenFile, []byte(testToken), 0o600)
	f := newFixture(t, badHost(), "notify:\n  ntfy:\n    url: "+srv.URL+"\n    topic: secrettopic\n    token_file: "+tokenFile+"\n")
	f.env.notifyOpts = []notify.Option{notify.WithTimeout(50 * time.Millisecond), notify.WithBackoff(0)}
	code, _, errb := f.check("--notify")
	if code != ExitDelivery || !strings.Contains(errb, "timeout") || strings.Contains(errb, "secrettopic") || strings.Contains(errb, testToken) {
		t.Errorf("exit %d stderr %q", code, errb)
	}
	if d := f.delivery(); d == nil || strings.Contains(d.Reason, "secrettopic") {
		t.Errorf("delivery %+v", d)
	}
}

func TestNotifyRecordedReasonIsShortAndRedacted(t *testing.T) {
	// A server that answers with a long error text that holds a secret.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"code":40301,"http":403,"error":"password=hunter2 `+strings.Repeat("y", 400)+`"}`)
	}))
	t.Cleanup(srv.Close)
	f := newFixture(t, goodHost(), "notify:\n  ntfy:\n    url: "+srv.URL+"\n    topic: alerts\n")
	code, _, errb := f.check("--notify")
	if code != ExitDelivery || strings.Contains(errb, "hunter2") {
		t.Fatalf("exit %d stderr %q", code, errb)
	}
	d := f.delivery()
	if d == nil || strings.Contains(d.Reason, "hunter2") || !strings.HasSuffix(d.Reason, "...") || len([]rune(d.Reason)) != maxReasonRunes+3 {
		t.Errorf("reason %q (%d runes)", d.Reason, len([]rune(d.Reason)))
	}
}

func TestNotifyARunWithoutTheFlagWarnsWhenItConsumesAlerts(t *testing.T) {
	n := newFakeNtfy(t)
	f := notifyFixture(t, n, goodHost(), "")
	f.check("--notify")
	f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	_, _, errb := f.check()
	if !strings.Contains(errb, "did not use --notify and moved the state forward past 1 alert-worthy change that no notification will tell") {
		t.Errorf("stderr %q", errb)
	}
	// No alert, no warning; a fix is not an alert.
	f.next(goodHost())
	if _, _, errb := f.check(); strings.Contains(errb, "alert-worthy") {
		t.Errorf("stderr %q", errb)
	}
	// Without a configured channel there is nobody to tell: no warning.
	g := newFixture(t, goodHost(), "")
	g.check()
	g.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
	if _, _, errb := g.check(); strings.Contains(errb, "alert-worthy") {
		t.Errorf("stderr %q", errb)
	}
	// And a first run is a baseline, not a consumed alert.
	h := notifyFixture(t, n, badHost(), "")
	if _, _, errb := h.check(); strings.Contains(errb, "alert-worthy") {
		t.Errorf("stderr %q", errb)
	}
}

// cancelNotifier cancels the context of the run while it "sends".
type cancelNotifier struct {
	cancel context.CancelFunc
	err    error
}

func (c cancelNotifier) Send(context.Context, notify.Message) error {
	c.cancel()
	return c.err
}

func TestNotifyASignalDuringTheDeliveryIsAnInterruptedRun(t *testing.T) {
	for name, sendErr := range map[string]error{
		"delivery fails": &notify.Error{Class: notify.Transient, Msg: "no answer: context canceled"},
		"delivery works": nil,
	} {
		t.Run(name, func(t *testing.T) {
			n := newFakeNtfy(t)
			f := notifyFixture(t, n, goodHost(), "")
			f.check("--notify")
			stateBefore, _ := os.ReadFile(f.statePath())
			histBefore, _ := os.ReadFile(filepath.Join(f.stateDir, "history.json"))

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.env.ctx = ctx
			f.env.notifier = cancelNotifier{cancel, sendErr}
			f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
			code, _, errb := f.check("--notify")
			if code != ExitInternal || !strings.Contains(errb, "interrupted") {
				t.Fatalf("exit %d stderr %q", code, errb)
			}
			if after, _ := os.ReadFile(f.statePath()); string(after) != string(stateBefore) {
				t.Errorf("an interrupted run wrote the state:\n%s", after)
			}
			if after, _ := os.ReadFile(filepath.Join(f.stateDir, "history.json")); string(after) != string(histBefore) {
				t.Error("an interrupted run wrote the history")
			}
			// The next run reports and sends the change.
			f.env.ctx = context.Background()
			f.env.notifier = nil
			f.next(goodHost().AddResult(sshdArgv, res("port 22\npasswordauthentication yes\n", 0)))
			if code, _, _ := f.check("--notify"); code != 1 || !strings.Contains(n.last().Body, "` t.sshd `") {
				t.Errorf("exit %d\n%s", code, n.last().Body)
			}
		})
	}
}
