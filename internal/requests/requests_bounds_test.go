package requests

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

func setMaxExamined(t *testing.T, n int) {
	t.Helper()
	old := maxExamined
	maxExamined = n
	t.Cleanup(func() { maxExamined = old })
}

func names(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Name)
	}
	return out
}

func TestStrayNames(t *testing.T) {
	// An entry that is not named as Submit names it is a stray: reported with
	// ReasonName in its own list, never opened, never counted toward the window.
	cases := map[string]string{
		"wrong prefix":       "request-1",
		"json suffix":        fname(1) + ".json",
		"dotfile":            ".hidden",
		"short random part":  "req-00000000000000000001-ab",
		"uppercase hex":      fmt.Sprintf("req-%020d-%032X", 1, 0xabcdef),
		"text before":        "x" + fname(1),
		"text after":         fname(1) + "x",
		"19 digits":          fmt.Sprintf("req-%019d-%032x", 1, 1),
		"21 digits":          fmt.Sprintf("req-%021d-%032x", 1, 1),
		"31 random":          fmt.Sprintf("req-%020d-%031x", 1, 1),
		"33 random":          fmt.Sprintf("req-%020d-%033x", 1, 1),
		"non hex random":     fmt.Sprintf("req-%020d-%s", 1, strings.Repeat("g", 32)),
		"backslash":          `a\b`,
		"newline":            fname(1)[:10] + "\n",
		"two names in one":   fname(1) + fname(2),
		"empty-ish":          " ",
		"escape sequence":    "\x1b[31mred\x1b[0m",
		"max length (255 B)": strings.Repeat("a", 255),
	}
	for label, name := range cases {
		t.Run(label, func(t *testing.T) {
			state := newState(t)
			plant(t, state, name, goodBody, 0o600)
			valid := plant(t, state, fname(7), goodBody, 0o600)
			b := pending(t, state)
			if len(b.Items) != 1 || b.Items[0].Name != filepath.Base(valid) || !b.Items[0].Accepted() {
				t.Fatalf("items: %+v, want only the valid request", b.Items)
			}
			if len(b.Stray) != 1 || b.Stray[0].Name != name || b.Stray[0].Accepted() || b.Stray[0].Rejection.Reason != ReasonName {
				t.Fatalf("stray: %+v, want %q rejected with ReasonName", b.Stray, name)
			}
			if b.More || b.StrayMore || b.Overfull {
				t.Fatalf("flags set: %+v", b)
			}
			// The raw name goes to Remove as it is.
			if err := Remove(state, b.Stray[0].Name); err != nil {
				t.Fatal(err)
			}
			if b := pending(t, state); len(b.Stray) != 0 || len(b.Items) != 1 {
				t.Fatalf("after Remove: %+v", b)
			}
		})
	}
}

func TestStrayDoesNotCountTowardWindow(t *testing.T) {
	// 100 entries that sort before every request and that nothing ever removes
	// (names with a backslash, non-empty directories, plain junk): a valid
	// request behind them is returned by the first call, and every call after.
	state := newState(t)
	rd := reqDir(t, state)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("a%03d", i)
		switch i % 3 {
		case 0:
			plant(t, state, name+`\x`, "junk", 0o600)
		case 1:
			if err := os.MkdirAll(filepath.Join(rd, name, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rd, name, "sub", "f"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		default:
			plant(t, state, name, "junk", 0o600)
		}
	}
	plant(t, state, fname(1), goodBody, 0o600)
	for pass := 0; pass < 3; pass++ {
		b := pending(t, state)
		if len(b.Items) != 1 || b.Items[0].Name != fname(1) || !b.Items[0].Accepted() {
			t.Fatalf("pass %d: items %+v, want the valid request", pass, b.Items)
		}
		if len(b.Stray) != MaxStray || !b.StrayMore || b.More || b.Overfull {
			t.Fatalf("pass %d: %d stray, flags more=%v strayMore=%v overfull=%v; want %d stray and strayMore only",
				pass, len(b.Stray), b.More, b.StrayMore, b.Overfull, MaxStray)
		}
		for i, it := range b.Stray {
			if want := fmt.Sprintf("a%03d", i); !strings.HasPrefix(it.Name, want) {
				t.Fatalf("stray %d is %q, want name order starting %q", i, it.Name, want)
			}
		}
	}
	// Removing the valid request does not need the junk gone first.
	if err := Remove(state, fname(1)); err != nil {
		t.Fatal(err)
	}
	// Every junk entry can be removed, in capped passes, and nothing is left.
	for pass := 0; ; pass++ {
		b := pending(t, state)
		for _, it := range b.Stray {
			if err := Remove(state, it.Name); err != nil {
				t.Fatalf("Remove(%q): %v", it.Name, err)
			}
		}
		if !b.StrayMore {
			break
		}
		if pass > 10 {
			t.Fatal("junk does not drain")
		}
	}
	if ents, _ := os.ReadDir(rd); len(ents) != 0 {
		t.Fatalf("%d entries left", len(ents))
	}
}

func TestStrayCap(t *testing.T) {
	for _, n := range []int{MaxStray - 1, MaxStray, MaxStray + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			state := newState(t)
			for i := 0; i < n; i++ {
				plant(t, state, fmt.Sprintf("j%03d", i), "x", 0o600)
			}
			b := pending(t, state)
			wantLen := n
			if wantLen > MaxStray {
				wantLen = MaxStray
			}
			if len(b.Stray) != wantLen || b.StrayMore != (n > MaxStray) {
				t.Fatalf("%d entries: %d stray, strayMore=%v", n, len(b.Stray), b.StrayMore)
			}
			if !sort.StringsAreSorted(names(b.Stray)) {
				t.Fatalf("stray not in name order: %v", names(b.Stray))
			}
			if len(b.Items) != 0 || b.More {
				t.Fatalf("items %+v more=%v", b.Items, b.More)
			}
		})
	}
}

func TestWindowStopsAtMaxPendingExactly(t *testing.T) {
	for _, n := range []int{MaxPending - 1, MaxPending, MaxPending + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			state := newState(t)
			for i := 0; i < n; i++ {
				plant(t, state, fname(i), goodBody, 0o600)
			}
			b := pending(t, state)
			wantLen := n
			if wantLen > MaxPending {
				wantLen = MaxPending
			}
			if len(b.Items) != wantLen || b.More != (n > MaxPending) {
				t.Fatalf("%d files: %d items, more=%v", n, len(b.Items), b.More)
			}
		})
	}
}

func TestOverfull(t *testing.T) {
	// The directory is read in chunks of listChunk and at most maxExamined
	// entries are examined; one more than that sets Overfull.
	mk := func(t *testing.T, state string, requests, strays, temps int) {
		for i := 0; i < requests; i++ {
			plant(t, state, fname(i), goodBody, 0o600)
		}
		for i := 0; i < strays; i++ {
			plant(t, state, fmt.Sprintf("j%04d", i), "x", 0o600)
		}
		for i := 0; i < temps; i++ {
			plant(t, state, fmt.Sprintf("%s%04d", securefile.TempPrefix, i), "x", 0o600)
		}
	}
	cases := []struct {
		label                   string
		max                     int
		requests, strays, temps int
		overfull                bool
	}{
		{"under", 5, 2, 1, 1, false},
		{"exactly the limit", 5, 2, 2, 1, false},
		{"one over", 5, 3, 2, 1, true},
		{"far over", 5, 20, 20, 20, true},
		{"only temp files over", 3, 0, 0, 4, true},
		{"only requests at the limit", 4, 4, 0, 0, false},
		{"empty", 5, 0, 0, 0, false},
		{"limit of one, one entry", 1, 1, 0, 0, false},
		{"limit of one, two entries", 1, 1, 1, 0, true},
		{"across a chunk boundary, at the limit", listChunk + 44, listChunk + 44, 0, 0, false},
		{"across a chunk boundary, one over", listChunk + 44, listChunk + 45, 0, 0, true},
		{"exactly one chunk", listChunk, listChunk, 0, 0, false},
		{"one chunk and one", listChunk, listChunk + 1, 0, 0, true},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			state := newState(t)
			setMaxExamined(t, c.max)
			mk(t, state, c.requests, c.strays, c.temps)
			b := pending(t, state)
			if b.Overfull != c.overfull {
				t.Fatalf("overfull=%v, want %v (%d entries, limit %d)", b.Overfull, c.overfull, c.requests+c.strays+c.temps, c.max)
			}
			if got := len(b.Items) + len(b.Stray); got > c.max {
				t.Fatalf("%d entries reported, the limit is %d", got, c.max)
			}
			if !c.overfull {
				// Everything is seen, up to the window and the stray cap.
				wantItems, wantStray := c.requests, c.strays
				if wantItems > MaxPending {
					wantItems = MaxPending
				}
				if wantStray > MaxStray {
					wantStray = MaxStray
				}
				if len(b.Items) != wantItems || len(b.Stray) != wantStray {
					t.Fatalf("%d items and %d stray, want %d and %d", len(b.Items), len(b.Stray), wantItems, wantStray)
				}
			}
		})
	}
}

func TestOverfullDrainsByRemoving(t *testing.T) {
	// Entries beyond the examined ones are seen once the examined ones are
	// removed: nothing is lost, it takes more passes.
	state := newState(t)
	setMaxExamined(t, 5)
	const total = 12
	for i := 0; i < total; i++ {
		plant(t, state, fname(i), goodBody, 0o600)
	}
	seen := map[string]bool{}
	passes := 0
	for {
		b := pending(t, state)
		passes++
		for _, it := range b.Items {
			seen[it.Name] = true
			if err := Remove(state, it.Name); err != nil {
				t.Fatal(err)
			}
		}
		if !b.Overfull {
			break
		}
		if passes > total {
			t.Fatal("does not drain")
		}
	}
	if len(seen) != total || passes != 3 {
		t.Fatalf("saw %d of %d in %d passes, want all in 3", len(seen), total, passes)
	}
}

func TestOverfullSweepTemp(t *testing.T) {
	// SweepTemp examines at most maxExamined entries per call too.
	state := newState(t)
	rd := reqDir(t, state)
	old := time.Now().Add(-3 * time.Hour)
	for i := 0; i < 6; i++ {
		p := plant(t, state, fmt.Sprintf("%s%d", securefile.TempPrefix, i), "x", 0o600)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	setMaxExamined(t, 3)
	for i, want := range []int{3, 3, 0} {
		n, err := SweepTemp(state, time.Hour)
		if err != nil || n != want {
			t.Fatalf("call %d: removed %d, err %v; want %d", i, n, err, want)
		}
	}
	if ents, _ := os.ReadDir(rd); len(ents) != 0 {
		t.Fatalf("%d left", len(ents))
	}
}

func TestStrayNameIsRaw(t *testing.T) {
	state := newState(t)
	name := "\x1b[2Jred\nline2\t\x7f"
	plant(t, state, name, "x", 0o600)
	b := pending(t, state)
	if len(b.Stray) != 1 || b.Stray[0].Name != name {
		t.Fatalf("got %+v, want the raw name", b.Stray)
	}
	if err := Remove(state, b.Stray[0].Name); err != nil {
		t.Fatal(err)
	}
	if b := pending(t, state); len(b.Stray) != 0 {
		t.Fatalf("still there: %+v", b.Stray)
	}
}

func TestSubmitRefusesWhatPendingRefuses(t *testing.T) {
	state := newState(t)
	bad := strings.Repeat("\xff", 342)
	cases := []struct {
		label string
		req   Request
	}{
		{"342 invalid bytes", Request{Action: ActionAck, IncidentID: "a1", Note: bad}},
		{"341 invalid bytes", Request{Action: ActionAck, IncidentID: "a1", Note: bad[:341]}},
		{"one invalid byte", Request{Action: ActionAck, IncidentID: "a1", Note: "\xff"}},
		{"invalid byte inside text", Request{Action: ActionAck, IncidentID: "a1", Note: "ok\xffok"}},
		{"truncated sequence", Request{Action: ActionAck, IncidentID: "a1", Note: "caf\xc3"}},
		{"overlong encoding", Request{Action: ActionAck, IncidentID: "a1", Note: "\xc0\xaf"}},
		{"surrogate", Request{Action: ActionAck, IncidentID: "a1", Note: "\xed\xa0\x80"}},
		{"year 10000", Request{Action: ActionAck, IncidentID: "a1", RequestedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{"year -1", Request{Action: ActionAck, IncidentID: "a1", RequestedAt: time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC)}},
		{"year 10000 after the UTC conversion", Request{Action: ActionAck, IncidentID: "a1",
			RequestedAt: time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("west", -2*3600))}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			if _, err := Submit(state, c.req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v, want ErrInvalidRequest", err)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(state, DirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused request created the requests directory: %v", err)
	}
	// What Submit takes, Pending takes: valid multi-byte text up to the limit,
	// the replacement character itself, and the edges of the time range.
	ok := []Request{
		{Action: ActionAck, IncidentID: "a1", Note: strings.Repeat("�", MaxNoteBytes/3)},
		{Action: ActionAck, IncidentID: "a1", Note: strings.Repeat("é", MaxNoteBytes/2)},
		{Action: ActionAck, IncidentID: "a1", Note: strings.Repeat("<", MaxNoteBytes)},
		{Action: ActionAck, IncidentID: "a1", Note: strings.Repeat("\x00", MaxNoteBytes)},
		{Action: ActionAck, IncidentID: "a1", RequestedAt: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
		{Action: ActionAck, IncidentID: "a1", RequestedAt: time.Date(1, 1, 1, 0, 0, 1, 0, time.UTC)},
	}
	for i, req := range ok {
		if _, err := Submit(state, req); err != nil {
			t.Fatalf("request %d refused: %v", i, err)
		}
	}
	b := pending(t, state)
	if len(b.Items) != len(ok) {
		t.Fatalf("Pending saw %d, want %d", len(b.Items), len(ok))
	}
	for _, it := range b.Items {
		if !it.Accepted() {
			t.Fatalf("Submit wrote what Pending refuses: %+v", it.Rejection)
		}
	}
}

func TestKeysMustBeExactAndUnique(t *testing.T) {
	cases := map[string]string{
		"action twice":                `{"schema_version":1,"action":"ack","action":"close","incident_id":"a1"}`,
		"action twice, same value":    `{"schema_version":1,"action":"ack","action":"ack","incident_id":"a1"}`,
		"incident_id twice":           `{"schema_version":1,"action":"ack","incident_id":"a1","incident_id":"b2"}`,
		"note twice":                  `{"schema_version":1,"action":"ack","incident_id":"a1","note":"x","note":"y"}`,
		"requested_at twice":          `{"schema_version":1,"action":"ack","incident_id":"a1","requested_at":"2026-01-02T03:04:05Z","requested_at":"2027-01-02T03:04:05Z"}`,
		"schema_version twice":        `{"schema_version":1,"schema_version":1,"action":"ack","incident_id":"a1"}`,
		"action capitalised":          `{"schema_version":1,"Action":"ack","incident_id":"a1"}`,
		"action upper case":           `{"schema_version":1,"ACTION":"ack","incident_id":"a1"}`,
		"incident_id mixed case":      `{"schema_version":1,"action":"ack","Incident_ID":"a1"}`,
		"note capitalised":            `{"schema_version":1,"action":"ack","incident_id":"a1","Note":"x"}`,
		"requested_at capitalised":    `{"schema_version":1,"action":"ack","incident_id":"a1","Requested_At":"2026-01-02T03:04:05Z"}`,
		"schema_version capitalised":  `{"Schema_Version":1,"action":"ack","incident_id":"a1"}`,
		"exact and capitalised":       `{"schema_version":1,"action":"ack","Action":"close","incident_id":"a1"}`,
		"capitalised and exact":       `{"schema_version":1,"ACTION":"close","action":"ack","incident_id":"a1"}`,
		"unknown key between":         `{"schema_version":1,"action":"ack","zzz":{"a":1,"a":2},"incident_id":"a1"}`,
		"duplicate inside a nested":   `{"schema_version":1,"action":"ack","incident_id":"a1","note":{"a":1,"a":2}}`,
		"duplicate key after a value": `{"schema_version":1,"action":"ack","incident_id":"a1","note":"x","action":"close"}`,
	}
	for label, body := range cases {
		t.Run(label, func(t *testing.T) {
			state := newState(t)
			plant(t, state, fname(1), body, 0o600)
			wantReject(t, pending(t, state), fname(1), ReasonMalformed)
		})
	}
	// Order does not matter, and every key once is fine.
	state := newState(t)
	plant(t, state, fname(1), `{"requested_at":"2026-01-02T03:04:05Z","note":"n","incident_id":"a1","action":"close","schema_version":1}`, 0o600)
	b := pending(t, state)
	if len(b.Items) != 1 || !b.Items[0].Accepted() || b.Items[0].Request.Action != ActionClose {
		t.Fatalf("got %+v", b.Items)
	}
}

// ownerSequence answers the owner question for the directories below the state
// directory by call number: the state directory takes calls 1 and 2, then the
// requests directory is looked at by open (call 3), by securefile twice (4, 5)
// and by open again on the root (6). foreign names the calls that answer with a
// foreign uid.
func ownerSequence(t *testing.T, foreign ...int) *int {
	t.Helper()
	calls := new(int)
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		*calls++
		for _, n := range foreign {
			if *calls == n {
				return os.Getuid() + 4242, nil
			}
		}
		return securefile.DefaultOwnerOf(fi)
	})
	return calls
}

func TestRequestsDirIsJudgedAtEveryLook(t *testing.T) {
	ops := map[string]func(string) error{
		"Submit":    func(s string) error { _, err := Submit(s, Request{Action: ActionAck, IncidentID: "a1"}); return err },
		"Pending":   func(s string) error { _, err := Pending(s); return err },
		"Remove":    func(s string) error { return Remove(s, fname(1)) },
		"SweepTemp": func(s string) error { _, err := SweepTemp(s, time.Hour); return err },
	}
	sequences := map[string][]int{
		"untrusted at the first look (before securefile)": {3},
		"untrusted only for securefile's first look":      {4},
		"untrusted only for securefile's second look":     {5},
		"untrusted only on the root, after all others":    {6},
		"untrusted, trusted, trusted, untrusted":          {3, 6},
		"trusted, untrusted, untrusted, trusted":          {4, 5},
		"untrusted throughout":                            {3, 4, 5, 6},
	}
	for opName, op := range ops {
		for label, seq := range sequences {
			t.Run(opName+"/"+label, func(t *testing.T) {
				state := newState(t)
				plant(t, state, fname(1), goodBody, 0o600)
				calls := ownerSequence(t, seq...)
				if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
					t.Fatalf("got %v, want ErrUntrusted (owner asked %d times)", err, *calls)
				}
				if _, err := os.Lstat(filepath.Join(state, DirName, fname(1))); err != nil {
					t.Fatalf("request touched: %v", err)
				}
			})
		}
		t.Run(opName+"/trusted at every look", func(t *testing.T) {
			state := newState(t)
			plant(t, state, fname(1), goodBody, 0o600)
			calls := ownerSequence(t)
			if err := op(state); err != nil {
				t.Fatalf("got %v", err)
			}
			if *calls < 6 {
				t.Fatalf("owner asked %d times, want the six looks of the two directories", *calls)
			}
		})
	}
}

func TestRequestsDirModeChangedWhileOpening(t *testing.T) {
	// The same directory, opened as trusted, becomes group-writable before the
	// root is opened: the identity is the same, the rules are not.
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720, 0o702} {
		for name, op := range map[string]func(string) error{
			"Submit":  func(s string) error { _, err := Submit(s, Request{Action: ActionAck, IncidentID: "a1"}); return err },
			"Pending": func(s string) error { _, err := Pending(s); return err },
			"Remove":  func(s string) error { return Remove(s, fname(1)) },
		} {
			t.Run(fmt.Sprintf("%s/%o", name, mode), func(t *testing.T) {
				state := newState(t)
				rd := reqDir(t, state)
				plant(t, state, fname(1), goodBody, 0o600)
				old := afterDirOpen
				t.Cleanup(func() { afterDirOpen = old })
				afterDirOpen = func() {
					afterDirOpen = func() {}
					if err := os.Chmod(rd, mode); err != nil {
						t.Fatal(err)
					}
				}
				if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
					t.Fatalf("got %v, want ErrUntrusted", err)
				}
				if _, err := os.Stat(filepath.Join(rd, fname(1))); err != nil {
					t.Fatalf("request touched: %v", err)
				}
			})
		}
	}
}

func TestRequestsDirSwappedForUntrustedWhileOpening(t *testing.T) {
	// A trusted directory is swapped for a group-writable one after the
	// securefile directory was opened on the trusted one.
	state := newState(t)
	rd := reqDir(t, state)
	plant(t, state, fname(1), goodBody, 0o600)
	old := afterDirOpen
	t.Cleanup(func() { afterDirOpen = old })
	afterDirOpen = func() {
		afterDirOpen = func() {}
		if err := os.Rename(rd, rd+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(rd, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(rd, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Pending(state); !errors.Is(err, securefile.ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestRealForeignOwner(t *testing.T) {
	// The owner rule against a real chown, which needs root. (The other tests
	// inject the owner, because an unprivileged run cannot make a foreign file.)
	if os.Getuid() != 0 {
		t.Skip("chown to another user needs root")
	}
	const foreign = 4242
	t.Run("file", func(t *testing.T) {
		state := newState(t)
		p := plant(t, state, fname(1), goodBody, 0o600)
		plant(t, state, fname(2), goodBody, 0o600)
		if err := os.Chown(p, foreign, foreign); err != nil {
			t.Skipf("cannot chown: %v", err)
		}
		b := pending(t, state)
		if len(b.Items) != 2 || b.Items[0].Accepted() || b.Items[0].Rejection.Reason != ReasonOwner || !b.Items[1].Accepted() {
			t.Fatalf("got %+v", b.Items)
		}
	})
	t.Run("requests directory", func(t *testing.T) {
		state := newState(t)
		rd := reqDir(t, state)
		plant(t, state, fname(1), goodBody, 0o600)
		if err := os.Chown(rd, foreign, foreign); err != nil {
			t.Skipf("cannot chown: %v", err)
		}
		for name, op := range map[string]func() error{
			"Pending": func() error { _, err := Pending(state); return err },
			"Submit":  func() error { _, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1"}); return err },
			"Remove":  func() error { return Remove(state, fname(1)) },
		} {
			if err := op(); !errors.Is(err, securefile.ErrUntrusted) {
				t.Errorf("%s: got %v, want ErrUntrusted", name, err)
			}
		}
	})
	t.Run("file owned by the running user", func(t *testing.T) {
		state := newState(t)
		p := plant(t, state, fname(1), goodBody, 0o600)
		if err := os.Chown(p, 0, 0); err != nil {
			t.Skipf("cannot chown: %v", err)
		}
		if b := pending(t, state); len(b.Items) != 1 || !b.Items[0].Accepted() {
			t.Fatalf("got %+v", b.Items)
		}
	})
}

func setNowFixed(t *testing.T, at time.Time) {
	t.Helper()
	setNow(t, func() time.Time { return at })
}

func TestSweepTemp(t *testing.T) {
	state := newState(t)
	rd := reqDir(t, state)
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	setNowFixed(t, at)
	touch := func(name string, age time.Duration) {
		p := plant(t, state, name, "partial", 0o600)
		if err := os.Chtimes(p, at.Add(-age), at.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	touch(securefile.TempPrefix+"old1", 2*time.Hour)
	touch(securefile.TempPrefix+"old2", time.Hour+time.Second)
	touch(securefile.TempPrefix+"edge", time.Hour)
	touch(securefile.TempPrefix+"young", time.Minute)
	touch(securefile.TempPrefix+"fresh", 0)
	touch(securefile.TempPrefix+"future", -time.Hour)
	touch(fname(1), 5*time.Hour) // an old request is not a temp file
	touch("stray", 5*time.Hour)
	touch(securefile.TempPrefix[:len(securefile.TempPrefix)-1], 5*time.Hour) // one byte short of the prefix

	n, err := SweepTemp(state, time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("removed %d, err %v; want 2", n, err)
	}
	var left []string
	ents, _ := os.ReadDir(rd)
	for _, e := range ents {
		left = append(left, e.Name())
	}
	want := []string{
		securefile.TempPrefix[:len(securefile.TempPrefix)-1], securefile.TempPrefix + "edge", securefile.TempPrefix + "fresh",
		securefile.TempPrefix + "future", securefile.TempPrefix + "young", fname(1), "stray",
	}
	sort.Strings(want)
	if strings.Join(left, "|") != strings.Join(want, "|") {
		t.Fatalf("left %q, want %q", left, want)
	}
	// A second call finds nothing; a shorter age takes the rest.
	if n, err := SweepTemp(state, time.Hour); err != nil || n != 0 {
		t.Fatalf("second call removed %d, err %v", n, err)
	}
	if n, err := SweepTemp(state, 30*time.Second); err != nil || n != 2 {
		t.Fatalf("shorter age removed %d, err %v; want 2 (edge, young)", n, err)
	}
	// Pending never saw the temp files, and still sees the request.
	if b := pending(t, state); len(b.Items) != 1 || len(b.Stray) != 2 {
		t.Fatalf("got %+v", b)
	}
}

func TestSweepTempKindsAndEdges(t *testing.T) {
	t.Run("age must be positive", func(t *testing.T) {
		state := newState(t)
		plant(t, state, securefile.TempPrefix+"x", "x", 0o600)
		for _, d := range []time.Duration{0, -time.Hour} {
			if n, err := SweepTemp(state, d); err == nil || n != 0 {
				t.Fatalf("SweepTemp(%v) = %d, %v; want an error and nothing removed", d, n, err)
			}
		}
		if _, err := os.Lstat(filepath.Join(state, DirName, securefile.TempPrefix+"x")); err != nil {
			t.Fatalf("file removed: %v", err)
		}
		if n, err := SweepTemp(state, time.Nanosecond); err != nil || n != 1 {
			t.Fatalf("smallest age: %d, %v; want 1", n, err)
		}
	})
	t.Run("missing directories", func(t *testing.T) {
		if n, err := SweepTemp(newState(t), time.Hour); err != nil || n != 0 {
			t.Fatalf("no requests dir: %d, %v", n, err)
		}
		if _, err := SweepTemp(filepath.Join(t.TempDir(), "nope"), time.Hour); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("no state dir: %v, want ErrNotExist", err)
		}
	})
	t.Run("symlink, directory and fifo", func(t *testing.T) {
		state := newState(t)
		rd := reqDir(t, state)
		outside := filepath.Join(t.TempDir(), "outside")
		if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(rd, securefile.TempPrefix+"link")); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(rd, securefile.TempPrefix+"dir")
		if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "sub", "link")); err != nil {
			t.Fatal(err)
		}
		setNowFixed(t, time.Now().Add(48*time.Hour))
		n, err := SweepTemp(state, time.Hour)
		if err != nil || n != 2 {
			t.Fatalf("removed %d, err %v; want 2", n, err)
		}
		if got, err := os.ReadFile(outside); err != nil || string(got) != "keep" {
			t.Fatalf("a link was followed: %q %v", got, err)
		}
	})
	t.Run("untrusted directory", func(t *testing.T) {
		state := newState(t)
		real := filepath.Join(t.TempDir(), "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(real, securefile.TempPrefix+"x")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(state, DirName)); err != nil {
			t.Fatal(err)
		}
		setNowFixed(t, time.Now().Add(48*time.Hour))
		if _, err := SweepTemp(state, time.Hour); !errors.Is(err, securefile.ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("file removed through a symlinked directory: %v", err)
		}
	})
	t.Run("a failure does not stop the rest", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root can remove anything")
		}
		state := newState(t)
		rd := reqDir(t, state)
		stuck := filepath.Join(rd, securefile.TempPrefix+"a-stuck")
		if err := os.MkdirAll(stuck, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stuck, "f"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stuck, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })
		plant(t, state, securefile.TempPrefix+"b-plain", "x", 0o600)
		setNowFixed(t, time.Now().Add(48*time.Hour))
		n, err := SweepTemp(state, time.Hour)
		if n != 1 || err == nil {
			t.Fatalf("removed %d, err %v; want 1 and an error", n, err)
		}
		if _, err := os.Lstat(filepath.Join(rd, securefile.TempPrefix+"b-plain")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the plain file was not removed: %v", err)
		}
	})
}
