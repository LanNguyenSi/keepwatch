package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
)

// listenerHost is a host with n listening sockets on the ports from base up,
// none of them allowed.
func listenerHost(base, n int) (tcp, tcpP string) {
	var a, b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&a, "LISTEN 0 5 0.0.0.0:%d 0.0.0.0:*\n", base+i)
		fmt.Fprintf(&b, "LISTEN 0 5 0.0.0.0:%d 0.0.0.0:* users:((\"p\",pid=1,fd=3))\n", base+i)
	}
	return a.String(), b.String()
}

func hostWithListeners(tcp, tcpP string) *fake.FakeRunner {
	return goodHost().AddResult(ssTCP, res(tcp, 0)).AddResult(ssTCPp, res(tcpP, 0))
}

type changeJSON struct {
	Kind       string `json:"kind"`
	CheckID    string `json:"check_id"`
	Subject    string `json:"subject"`
	HiddenNew  int    `json:"hidden_new"`
	HiddenGone int    `json:"hidden_gone"`
	Alert      bool   `json:"alert"`
}

func changesOf(t *testing.T, out string) []changeJSON {
	t.Helper()
	var v struct {
		Changes []changeJSON `json:"changes"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	var out2 []changeJSON
	for _, c := range v.Changes {
		if c.CheckID == "t.listeners" {
			out2 = append(out2, c)
		}
	}
	return out2
}

// The whole chain, probe to report, for a flood of listeners: a listener below
// the cut stops and a new one starts above it.
func TestCheckSeesASwapAcrossTheCutOfAFloodOfListeners(t *testing.T) {
	f := newFixture(t, hostWithListeners(listenerHost(10000, 150)), "")
	f.check("--format", "json")
	if c := f.loadState().Find("t.listeners"); c == nil || !c.Capped() || c.Total != 150 || len(c.Keys) != 150 || len(c.Items) != 99 {
		t.Fatalf("saved check %+v", c)
	}

	// tcp/0.0.0.0:10005 (listed) stops; tcp/0.0.0.0:20000 (sorted after all the
	// others, so hidden) starts.
	tcp, tcpP := listenerHost(10000, 150)
	tcp = strings.Replace(tcp, "0.0.0.0:10005", "0.0.0.0:20000", 1)
	tcpP = strings.Replace(tcpP, "0.0.0.0:10005", "0.0.0.0:20000", 1)
	f.env.runner = hostWithListeners(tcp, tcpP)
	f.clock = f.clock.Add(time.Hour)
	_, out, _ := f.check("--format", "json")
	got := changesOf(t, out)
	want := []changeJSON{
		{Kind: "subject_gone", CheckID: "t.listeners", Subject: "tcp/0.0.0.0:10005"},
		{Kind: "hidden_new", CheckID: "t.listeners", HiddenNew: 1, Alert: true},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("changes:\n got %+v\nwant %+v", got, want)
	}
}

// An exception for a listed listener goes through the engine and the state:
// the excepted listener is not in the failing set, and the sets still compare.
func TestCheckKeepsTheSetsThroughExceptions(t *testing.T) {
	cfg := "exceptions:\n  - check: t.listeners\n    match: tcp/0.0.0.0:10003\n    reason: ok\n    expires: 2099-12-31\n"
	f := newFixture(t, hostWithListeners(listenerHost(10000, 150)), cfg)
	f.check("--format", "json")
	c := f.loadState().Find("t.listeners")
	if c == nil || c.Status != "fail" || c.Total != 150 || len(c.Keys) != 150 {
		t.Fatalf("saved check %+v", c)
	}
	excepted := 0
	for _, it := range c.Items {
		if it.Excepted {
			excepted++
		}
	}
	if excepted != 1 {
		t.Fatalf("%d excepted items", excepted)
	}

	// One more listener at the end: new, hidden, and the excepted one adds
	// nothing.
	f.env.runner = hostWithListeners(listenerHost(10000, 151))
	f.clock = f.clock.Add(time.Hour)
	_, out, _ := f.check("--format", "json")
	got := changesOf(t, out)
	if len(got) != 1 || got[0].Kind != "hidden_new" || got[0].HiddenNew != 1 || !got[0].Alert {
		t.Errorf("changes %+v", got)
	}
}

// The warnings next to a failure become the evidence when exceptions cover
// every failing item. They are capped on their own, and their set must reach
// the state through the engine's swap.
func TestCheckKeepsTheSetOfTheWarningsWhenExceptionsTurnAFailIntoAWarn(t *testing.T) {
	const disk = `
checks:
  - id: t.disk
    title: Disk
    kind: disk_usage
    params: {warn_percent: 80, fail_percent: 90}
    severity: medium
    rationale: r
    fix_hint: f
`
	cat, err := catalog.Parse([]byte(disk))
	if err != nil {
		t.Fatal(err)
	}
	var mounts strings.Builder
	st := map[string]probes.Statfs{}
	use := func(pct uint64) probes.Statfs {
		return probes.Statfs{BlockSize: 4096, Blocks: 1000, Bfree: 1000 - pct*10, Bavail: 1000 - pct*10, Files: 1000, Ffree: 1000 - pct*10}
	}
	add := func(point string, pct uint64) {
		fmt.Fprintf(&mounts, "%d 1 8:1 / %s rw - ext4 /dev/x rw\n", len(st)+1, point)
		st[point] = use(pct)
	}
	add("/full", 95)
	for i := 0; i < 130; i++ {
		add(fmt.Sprintf("/w%03d", i), 85)
	}
	f := newFixture(t, fake.New(nil), "exceptions:\n  - check: t.disk\n    match: /full\n    reason: ok\n    expires: 2099-12-31\n")
	f.env.catalog = cat
	f.env.fs = probestest.MemFS{"/proc/self/mountinfo": mounts.String()}
	f.env.statfs = func(p string) (probes.Statfs, error) { return st[p], nil }
	f.check("--format", "json")
	c := f.loadState().Find("t.disk")
	if c == nil || c.Status != "warn" || !c.Capped() || c.Total != 130 || len(c.Keys) != 130 || len(c.Items) != 99 {
		t.Fatalf("saved check %+v", c)
	}
}
