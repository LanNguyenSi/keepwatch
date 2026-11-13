package requests

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// The tests replace package variables, so none of them runs in parallel.

func newState(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func reqDir(t *testing.T, state string) string {
	t.Helper()
	p := filepath.Join(state, DirName)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func fname(i int) string { return fmt.Sprintf("req-%020d-%032x", i, i) }

const goodBody = `{"schema_version":1,"action":"ack","incident_id":"ab12cd34","note":"n","requested_at":"2026-01-02T03:04:05Z"}`

// plant writes a request file with an exact mode.
func plant(t *testing.T, state, name, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(reqDir(t, state), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func pending(t *testing.T, state string) Batch {
	t.Helper()
	b, err := Pending(state)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func setOwner(t *testing.T, f securefile.OwnerOf) {
	t.Helper()
	old := ownerOf
	ownerOf = f
	t.Cleanup(func() { ownerOf = old })
}

func foreignFor(names ...string) securefile.OwnerOf {
	return func(fi fs.FileInfo) (int, error) {
		for _, n := range names {
			if fi.Name() == n {
				return os.Getuid() + 4242, nil
			}
		}
		return securefile.DefaultOwnerOf(fi)
	}
}

func setNow(t *testing.T, f func() time.Time) {
	t.Helper()
	old := now
	now = f
	t.Cleanup(func() { now = old })
}

func wantReject(t *testing.T, b Batch, name string, r Reason) {
	t.Helper()
	if len(b.Items) != 1 {
		t.Fatalf("got %d items, want 1: %+v", len(b.Items), b.Items)
	}
	it := b.Items[0]
	if it.Name != name {
		t.Fatalf("name %q, want %q", it.Name, name)
	}
	if it.Accepted() || it.Rejection.Reason != r {
		t.Fatalf("got %+v (rejection %+v), want rejection %q", it, it.Rejection, r)
	}
}

func TestSubmitPendingRoundTrip(t *testing.T) {
	state := newState(t)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name, err := Submit(state, Request{Action: ActionClose, IncidentID: "abc-7", Note: "done", RequestedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	if !nameRE.MatchString(name) {
		t.Fatalf("name %q does not have the documented shape", name)
	}
	rd := filepath.Join(state, DirName)
	if fi, err := os.Stat(rd); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("requests dir: %v %v, want mode 0700", fi, err)
	}
	fi, err := os.Lstat(filepath.Join(rd, name))
	if err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("request file: %v %v, want a regular 0600 file", fi, err)
	}
	raw, _ := os.ReadFile(filepath.Join(rd, name))
	if !strings.Contains(string(raw), `"schema_version":1`) {
		t.Fatalf("file lacks schema_version: %s", raw)
	}
	b := pending(t, state)
	if b.More || len(b.Items) != 1 || !b.Items[0].Accepted() {
		t.Fatalf("got %+v", b)
	}
	want := Request{Action: ActionClose, IncidentID: "abc-7", Note: "done", RequestedAt: at}
	got := b.Items[0].Request
	if got.Action != want.Action || got.IncidentID != want.IncidentID || got.Note != want.Note || !got.RequestedAt.Equal(at) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if b.Items[0].Name != name {
		t.Fatalf("name %q, want %q", b.Items[0].Name, name)
	}
	// Pending consumes nothing.
	if b2 := pending(t, state); len(b2.Items) != 1 {
		t.Fatalf("second Pending saw %d items, want 1", len(b2.Items))
	}
	ents, _ := os.ReadDir(rd)
	if len(ents) != 1 {
		t.Fatalf("directory holds %d entries, want exactly the request", len(ents))
	}
}

func TestSubmitNoteIsRaw(t *testing.T) {
	state := newState(t)
	note := "a\x1b[31mred\x1b[0m\nline2\x00nul \u202e bidi"
	if _, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1", Note: note}); err != nil {
		t.Fatal(err)
	}
	b := pending(t, state)
	if len(b.Items) != 1 || !b.Items[0].Accepted() || b.Items[0].Request.Note != note {
		t.Fatalf("note not preserved verbatim: %+v", b.Items)
	}
}

func TestSubmitFillsZeroTime(t *testing.T) {
	state := newState(t)
	at := time.Date(2030, 5, 6, 7, 8, 9, 0, time.UTC)
	setNow(t, func() time.Time { return at })
	if _, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1"}); err != nil {
		t.Fatal(err)
	}
	b := pending(t, state)
	if !b.Items[0].Request.RequestedAt.Equal(at) {
		t.Fatalf("RequestedAt %v, want %v", b.Items[0].Request.RequestedAt, at)
	}
	// A given time wins over the clock.
	given := at.Add(-time.Hour)
	if _, err := Submit(state, Request{Action: ActionAck, IncidentID: "b2", RequestedAt: given}); err != nil {
		t.Fatal(err)
	}
	for _, it := range pending(t, state).Items {
		if it.Request.IncidentID == "b2" && !it.Request.RequestedAt.Equal(given) {
			t.Fatalf("RequestedAt %v, want the given %v", it.Request.RequestedAt, given)
		}
	}
}

func TestSubmitRejectsInvalid(t *testing.T) {
	state := newState(t)
	cases := []struct {
		name string
		req  Request
	}{
		{"action empty", Request{IncidentID: "a1"}},
		{"action unknown", Request{Action: "delete", IncidentID: "a1"}},
		{"action upper", Request{Action: "ACK", IncidentID: "a1"}},
		{"id empty", Request{Action: ActionAck}},
		{"id slash", Request{Action: ActionAck, IncidentID: "a/b"}},
		{"id long", Request{Action: ActionAck, IncidentID: strings.Repeat("a", MaxIncidentIDBytes+1)}},
		{"note long", Request{Action: ActionAck, IncidentID: "a1", Note: strings.Repeat("n", MaxNoteBytes+1)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Submit(state, c.req); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v, want ErrInvalidRequest", err)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(state, DirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused request created the requests directory: %v", err)
	}
	// The limits themselves are fine.
	ok := Request{Action: ActionClose, IncidentID: strings.Repeat("a", MaxIncidentIDBytes), Note: strings.Repeat("n", MaxNoteBytes)}
	if _, err := Submit(state, ok); err != nil {
		t.Fatalf("request at the limits refused: %v", err)
	}
	if b := pending(t, state); len(b.Items) != 1 || !b.Items[0].Accepted() {
		t.Fatalf("request at the limits not accepted by Pending: %+v", b.Items)
	}
}

func TestValidIncidentID(t *testing.T) {
	hex64 := strings.Repeat("0123456789abcdef", 4)
	good := []string{
		"a", "f", "0", "9", "ab12cd34", hex64, hex64 + "-2", hex64 + "-12", "a-", "a--b",
		strings.Repeat("a", MaxIncidentIDBytes), "a" + strings.Repeat("-", MaxIncidentIDBytes-1),
	}
	bad := []string{
		"", "-", "-a", "--", "-" + hex64, "A", "ABCDEF12", "abcdefG", "abCdef", "g", "z", "inc-1", "a_b", "_a",
		" ", "a b", "a.b", "a/b", "../x", "a\n", "a\x00", "é", "a:b", "@", "[", "`", "{", "/", ":", "~", "a\x7f",
		strings.Repeat("a", MaxIncidentIDBytes+1), hex64 + "-" + strings.Repeat("1", MaxIncidentIDBytes),
	}
	for _, id := range good {
		if !ValidIncidentID(id) {
			t.Errorf("%q should be valid", id)
		}
	}
	for _, id := range bad {
		if ValidIncidentID(id) {
			t.Errorf("%q should be invalid", id)
		}
	}
}

func TestLimitsArePinned(t *testing.T) {
	// The documented values, as literals: changing one is a decision, not an
	// accident.
	for name, c := range map[string][2]int{
		"MaxPending":         {MaxPending, 100},
		"MaxStray":           {MaxStray, 20},
		"MaxExamined":        {MaxExamined, 10000},
		"MaxFileSize":        {MaxFileSize, 16384},
		"MaxNoteBytes":       {MaxNoteBytes, 1024},
		"MaxIncidentIDBytes": {MaxIncidentIDBytes, 80},
		"SchemaVersion":      {SchemaVersion, 1},
	} {
		if c[0] != c[1] {
			t.Errorf("%s = %d, documented %d", name, c[0], c[1])
		}
	}
}

func TestActionValid(t *testing.T) {
	if !ActionAck.Valid() || !ActionClose.Valid() || Action("").Valid() || Action("open").Valid() {
		t.Fatal("Action.Valid is wrong")
	}
}

func TestSubmitNeedsExistingStateDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, err := Submit(missing, Request{Action: ActionAck, IncidentID: "a1"})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want ErrNotExist", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Submit created the state directory: %v", err)
	}
}

func TestDirectoryTrust(t *testing.T) {
	submit := func(state string) error {
		_, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1"})
		return err
	}
	pend := func(state string) error { _, err := Pending(state); return err }
	remove := func(state string) error { return Remove(state, fname(1)) }
	ops := map[string]func(string) error{"Submit": submit, "Pending": pend, "Remove": remove}

	for opName, op := range ops {
		t.Run(opName+"/requests dir is a symlink", func(t *testing.T) {
			state := newState(t)
			real := filepath.Join(t.TempDir(), "real")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, filepath.Join(state, DirName)); err != nil {
				t.Fatal(err)
			}
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
			if ents, _ := os.ReadDir(real); len(ents) != 0 {
				t.Fatalf("something was written through the symlink: %v", ents)
			}
		})
		t.Run(opName+"/requests dir group-writable", func(t *testing.T) {
			state := newState(t)
			rd := reqDir(t, state)
			if err := os.Chmod(rd, 0o770); err != nil {
				t.Fatal(err)
			}
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
		t.Run(opName+"/requests dir other-writable", func(t *testing.T) {
			state := newState(t)
			rd := reqDir(t, state)
			if err := os.Chmod(rd, 0o702); err != nil {
				t.Fatal(err)
			}
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
		t.Run(opName+"/requests dir foreign owner", func(t *testing.T) {
			state := newState(t)
			reqDir(t, state)
			setOwner(t, foreignFor(DirName))
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
		t.Run(opName+"/state dir group-writable", func(t *testing.T) {
			state := newState(t)
			reqDir(t, state)
			if err := os.Chmod(state, 0o770); err != nil {
				t.Fatal(err)
			}
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
		t.Run(opName+"/state dir is a symlink", func(t *testing.T) {
			state := newState(t)
			reqDir(t, state)
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(state, link); err != nil {
				t.Fatal(err)
			}
			if err := op(link); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
	}
}

func TestPendingMissingDirs(t *testing.T) {
	state := newState(t)
	b, err := Pending(state)
	if err != nil || len(b.Items) != 0 || b.More {
		t.Fatalf("no requests dir: got %+v, %v; want empty and no error", b, err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Pending created the requests directory: %v", err)
	}
	if _, err := Pending(filepath.Join(t.TempDir(), "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing state dir: got %v, want ErrNotExist", err)
	}
	reqDir(t, state)
	if b := pending(t, state); len(b.Items) != 0 {
		t.Fatalf("empty dir: got %+v", b)
	}
}

func TestRejections(t *testing.T) {
	type tc struct {
		name   string
		file   string
		body   string
		mode   os.FileMode
		reason Reason
		owner  bool // plant as a foreign-owned file
	}
	cases := []tc{
		{name: "owner foreign", file: fname(1), body: goodBody, mode: 0o600, reason: ReasonOwner, owner: true},
		{name: "mode 0644", file: fname(1), body: goodBody, mode: 0o644, reason: ReasonMode},
		{name: "mode 0640", file: fname(1), body: goodBody, mode: 0o640, reason: ReasonMode},
		{name: "mode 0604", file: fname(1), body: goodBody, mode: 0o604, reason: ReasonMode},
		{name: "mode 0620", file: fname(1), body: goodBody, mode: 0o620, reason: ReasonMode},
		{name: "mode 0602", file: fname(1), body: goodBody, mode: 0o602, reason: ReasonMode},
		{name: "mode 0700", file: fname(1), body: goodBody, mode: 0o700, reason: ReasonMode},
		{name: "mode setuid", file: fname(1), body: goodBody, mode: 0o600 | os.ModeSetuid, reason: ReasonMode},
		{name: "mode sticky", file: fname(1), body: goodBody, mode: 0o600 | os.ModeSticky, reason: ReasonMode},
		{name: "mode setgid", file: fname(1), body: goodBody, mode: 0o600 | os.ModeSetgid, reason: ReasonMode},
		{name: "oversize", file: fname(1), body: goodBody + strings.Repeat(" ", MaxFileSize), mode: 0o600, reason: ReasonOversize},
		{name: "malformed: empty", file: fname(1), body: "", mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: not json", file: fname(1), body: "ack inc-1", mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: array", file: fname(1), body: "[]", mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: truncated", file: fname(1), body: goodBody[:40], mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: unknown field", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"a1","extra":1}`, mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: wrong type", file: fname(1), body: `{"schema_version":1,"action":1,"incident_id":"a1"}`, mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: bad time", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"a1","requested_at":"yesterday"}`, mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: trailing object", file: fname(1), body: goodBody + `{"schema_version":1}`, mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: trailing garbage", file: fname(1), body: goodBody + "x", mode: 0o600, reason: ReasonMalformed},
		{name: "malformed: note too long", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"a1","note":"` + strings.Repeat("n", MaxNoteBytes+1) + `"}`, mode: 0o600, reason: ReasonMalformed},
		{name: "schema: missing", file: fname(1), body: `{"action":"ack","incident_id":"a1"}`, mode: 0o600, reason: ReasonSchema},
		{name: "schema: zero", file: fname(1), body: `{"schema_version":0,"action":"ack","incident_id":"a1"}`, mode: 0o600, reason: ReasonSchema},
		{name: "schema: future with unknown fields", file: fname(1), body: `{"schema_version":2,"action":"ack","incident_id":"a1","extra":true}`, mode: 0o600, reason: ReasonSchema},
		{name: "schema: string", file: fname(1), body: `{"schema_version":"1","action":"ack","incident_id":"a1"}`, mode: 0o600, reason: ReasonMalformed},
		{name: "action: unknown", file: fname(1), body: `{"schema_version":1,"action":"reopen","incident_id":"a1"}`, mode: 0o600, reason: ReasonAction},
		{name: "action: empty", file: fname(1), body: `{"schema_version":1,"action":"","incident_id":"a1"}`, mode: 0o600, reason: ReasonAction},
		{name: "action: missing", file: fname(1), body: `{"schema_version":1,"incident_id":"a1"}`, mode: 0o600, reason: ReasonAction},
		{name: "action: case", file: fname(1), body: `{"schema_version":1,"action":"Ack","incident_id":"a1"}`, mode: 0o600, reason: ReasonAction},
		{name: "incident id: missing", file: fname(1), body: `{"schema_version":1,"action":"ack"}`, mode: 0o600, reason: ReasonIncidentID},
		{name: "incident id: empty", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":""}`, mode: 0o600, reason: ReasonIncidentID},
		{name: "incident id: path", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"../../etc/passwd"}`, mode: 0o600, reason: ReasonIncidentID},
		{name: "incident id: newline", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"a\nb"}`, mode: 0o600, reason: ReasonIncidentID},
		{name: "incident id: too long", file: fname(1), body: `{"schema_version":1,"action":"ack","incident_id":"` + strings.Repeat("a", MaxIncidentIDBytes+1) + `"}`, mode: 0o600, reason: ReasonIncidentID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := newState(t)
			plant(t, state, c.file, c.body, c.mode)
			if fi, err := os.Lstat(filepath.Join(state, DirName, c.file)); err != nil || fi.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != c.mode {
				t.Skipf("this system does not keep mode %v on a file", c.mode)
			}
			if c.owner {
				setOwner(t, foreignFor(c.file))
			}
			wantReject(t, pending(t, state), c.file, c.reason)
		})
	}
}

func TestAcceptedModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		state := newState(t)
		plant(t, state, fname(1), goodBody, mode)
		b := pending(t, state)
		if len(b.Items) != 1 || !b.Items[0].Accepted() {
			t.Fatalf("mode %o: got %+v, want accepted", mode, b.Items)
		}
	}
}

func TestSchemaJudgedBeforeShape(t *testing.T) {
	// A future schema is reported as such even when everything else is off.
	state := newState(t)
	plant(t, state, fname(1), `{"schema_version":3,"action":"nope","incident_id":"","zzz":[1]}`, 0o600)
	wantReject(t, pending(t, state), fname(1), ReasonSchema)
}

func TestRejectsSymlinkAndLeavesTarget(t *testing.T) {
	state := newState(t)
	good := plant(t, state, fname(1), goodBody, 0o600)
	link := filepath.Join(filepath.Dir(good), fname(2))
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	b := pending(t, state)
	if len(b.Items) != 2 || !b.Items[0].Accepted() {
		t.Fatalf("got %+v", b.Items)
	}
	if it := b.Items[1]; it.Name != fname(2) || it.Accepted() || it.Rejection.Reason != ReasonSymlink {
		t.Fatalf("symlink item: %+v", it)
	}
	// Dangling and out-of-directory links are refused the same way.
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(goodBody), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, target := range []string{outside, filepath.Join(t.TempDir(), "missing")} {
		if err := os.Symlink(target, filepath.Join(filepath.Dir(good), fname(10+i))); err != nil {
			t.Fatal(err)
		}
	}
	for _, it := range pending(t, state).Items[2:] {
		if it.Accepted() || it.Rejection.Reason != ReasonSymlink {
			t.Fatalf("link item: %+v", it)
		}
	}
	// Removing the rejected link leaves its target alone.
	if err := Remove(state, fname(10)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("target of a removed symlink is gone: %v", err)
	}
}

func TestRejectsNonRegular(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		state := newState(t)
		if err := os.Mkdir(filepath.Join(reqDir(t, state), fname(1)), 0o700); err != nil {
			t.Fatal(err)
		}
		wantReject(t, pending(t, state), fname(1), ReasonNotRegular)
	})
	t.Run("fifo", func(t *testing.T) {
		state := newState(t)
		if err := syscall.Mkfifo(filepath.Join(reqDir(t, state), fname(1)), 0o600); err != nil {
			t.Skipf("no fifo: %v", err)
		}
		wantReject(t, pending(t, state), fname(1), ReasonNotRegular)
	})
}

func TestOwnerErrorIsUnreadable(t *testing.T) {
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		if fi.Name() == fname(1) {
			return 0, errors.New("no owner")
		}
		return securefile.DefaultOwnerOf(fi)
	})
	b := pending(t, state)
	wantReject(t, b, fname(1), ReasonUnreadable)
	// Judged at the first look, not left to the read that follows it.
	if d := b.Items[0].Rejection.Detail; !strings.HasPrefix(d, "cannot tell who owns") {
		t.Fatalf("detail %q, want the owner lookup at the first look to be the cause", d)
	}
}

func TestSwappedBetweenLookAndOpen(t *testing.T) {
	// The first look finds a trusted file; by the time it is opened the owner
	// answer has changed (the file was swapped): the open-time check wins.
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	calls := 0
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		if fi.Name() == fname(1) {
			calls++
			if calls > 1 {
				return os.Getuid() + 4242, nil
			}
		}
		return securefile.DefaultOwnerOf(fi)
	})
	wantReject(t, pending(t, state), fname(1), ReasonUntrusted)
	if calls < 2 {
		t.Fatalf("owner asked %d times, want the look and the open", calls)
	}
}

func TestUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read a mode 0000 file")
	}
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o000)
	wantReject(t, pending(t, state), fname(1), ReasonUnreadable)
}

func TestVanishedFileIsSkipped(t *testing.T) {
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	plant(t, state, fname(2), goodBody, 0o600)
	old := afterList
	afterList = func() { _ = os.Remove(filepath.Join(state, DirName, fname(1))) }
	t.Cleanup(func() { afterList = old })
	b := pending(t, state)
	if len(b.Items) != 1 || b.Items[0].Name != fname(2) {
		t.Fatalf("got %+v, want only the second file", b.Items)
	}
	// Vanishing between the first look and the open is skipped as well.
	plant(t, state, fname(3), goodBody, 0o600)
	afterList = func() {}
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		if fi.Name() == fname(3) {
			_ = os.Remove(filepath.Join(state, DirName, fname(3)))
		}
		return securefile.DefaultOwnerOf(fi)
	})
	for _, it := range pending(t, state).Items {
		if it.Name == fname(3) {
			t.Fatalf("vanished file reported: %+v", it)
		}
	}
}

func TestTempFilesIgnored(t *testing.T) {
	state := newState(t)
	plant(t, state, securefile.TempPrefix+"abcdef", "partial", 0o644)
	plant(t, state, securefile.TempPrefix+"x", goodBody, 0o600)
	if b := pending(t, state); len(b.Items) != 0 || b.More {
		t.Fatalf("temp files listed: %+v", b)
	}
	// They do not count against the bound either.
	for i := 0; i < MaxPending; i++ {
		plant(t, state, fname(i), goodBody, 0o600)
	}
	if b := pending(t, state); len(b.Items) != MaxPending || b.More {
		t.Fatalf("got %d items, more=%v; want %d and no more", len(b.Items), b.More, MaxPending)
	}
	// Remove never touches a temp file.
	if err := Remove(state, securefile.TempPrefix+"abcdef"); !errors.Is(err, securefile.ErrInvalidName) {
		t.Fatalf("got %v, want ErrInvalidName", err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName, securefile.TempPrefix+"abcdef")); err != nil {
		t.Fatalf("temp file removed: %v", err)
	}
}

func TestNameOrder(t *testing.T) {
	state := newState(t)
	tick := time.Unix(1_800_000_000, 0)
	setNow(t, func() time.Time { tick = tick.Add(time.Second); return tick })
	var want []string
	for i := 0; i < 20; i++ {
		n, err := Submit(state, Request{Action: ActionAck, IncidentID: fmt.Sprintf("a%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, n)
	}
	var got []string
	for _, it := range pending(t, state).Items {
		got = append(got, it.Name)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order differs from submission order:\n got %v\nwant %v", got, want)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatal("names are not in name order")
	}
}

func TestNegativeClockDoesNotBreakName(t *testing.T) {
	state := newState(t)
	setNow(t, func() time.Time { return time.Unix(-5, 0) })
	n, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1", RequestedAt: time.Unix(1, 0)})
	if err != nil || !nameRE.MatchString(n) {
		t.Fatalf("name %q, err %v", n, err)
	}
	if b := pending(t, state); len(b.Items) != 1 || !b.Items[0].Accepted() {
		t.Fatalf("got %+v", b.Items)
	}
}

func TestConcurrentSubmit(t *testing.T) {
	state := newState(t)
	const workers, each = 16, 4
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		names = map[string]bool{}
		errs  []error
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				n, err := Submit(state, Request{Action: ActionAck, IncidentID: fmt.Sprintf("a%d-%d", w, i)})
				mu.Lock()
				if err != nil {
					errs = append(errs, err)
				} else {
					names[n] = true
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(names) != workers*each {
		t.Fatalf("%d distinct names, want %d", len(names), workers*each)
	}
	b := pending(t, state)
	if len(b.Items) != workers*each {
		t.Fatalf("Pending saw %d, want %d", len(b.Items), workers*each)
	}
	ids := map[string]bool{}
	for _, it := range b.Items {
		if !it.Accepted() || !names[it.Name] {
			t.Fatalf("bad item %+v", it)
		}
		ids[it.Request.IncidentID] = true
	}
	if len(ids) != workers*each {
		t.Fatalf("%d distinct requests read, want %d (a file was overwritten)", len(ids), workers*each)
	}
	ents, _ := os.ReadDir(filepath.Join(state, DirName))
	if len(ents) != workers*each {
		t.Fatalf("directory holds %d entries, want %d (leftover temp files?)", len(ents), workers*each)
	}
}

func TestSubmitWhilePending(t *testing.T) {
	// A reader never sees a half-written file: every file it lists parses.
	state := newState(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			if _, err := Submit(state, Request{Action: ActionClose, IncidentID: fmt.Sprintf("a%d", i), Note: strings.Repeat("n", 500)}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for {
		b, err := Pending(state)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range b.Items {
			if !it.Accepted() {
				t.Fatalf("reader saw a bad file: %+v", it.Rejection)
			}
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestFloodIsBoundedPerCall(t *testing.T) {
	state := newState(t)
	const total = 1000
	for i := 0; i < total; i++ {
		plant(t, state, fname(i), goodBody, 0o600)
	}
	seen := map[string]int{}
	calls := 0
	for {
		b := pending(t, state)
		calls++
		if len(b.Items) > MaxPending {
			t.Fatalf("call %d returned %d items, the bound is %d", calls, len(b.Items), MaxPending)
		}
		if calls == 1 {
			if len(b.Items) != MaxPending || !b.More {
				t.Fatalf("first call: %d items, more=%v; want %d and more", len(b.Items), b.More, MaxPending)
			}
			// Name order: the first call returns the lowest names.
			for i, it := range b.Items {
				if it.Name != fname(i) {
					t.Fatalf("item %d is %q, want %q", i, it.Name, fname(i))
				}
			}
		}
		for _, it := range b.Items {
			seen[it.Name]++
			if err := Remove(state, it.Name); err != nil {
				t.Fatal(err)
			}
		}
		if !b.More {
			break
		}
		if calls > total {
			t.Fatal("does not drain")
		}
	}
	if len(seen) != total || calls != total/MaxPending {
		t.Fatalf("saw %d distinct requests in %d calls, want %d in %d", len(seen), calls, total, total/MaxPending)
	}
	for n, c := range seen {
		if c != 1 {
			t.Fatalf("%s seen %d times", n, c)
		}
	}
}

func TestFloodOfRejectedFilesIsBounded(t *testing.T) {
	// Junk counts against the bound, so it cannot make one call do unbounded
	// work, and a valid request behind it is reached once the junk is removed.
	state := newState(t)
	for i := 0; i < 3*MaxPending; i++ {
		plant(t, state, fname(i), "junk", 0o600)
	}
	plant(t, state, fname(9999), goodBody, 0o600)
	b := pending(t, state)
	if len(b.Items) != MaxPending || !b.More {
		t.Fatalf("got %d items, more=%v", len(b.Items), b.More)
	}
	for _, it := range b.Items {
		if it.Accepted() {
			t.Fatalf("junk accepted: %+v", it)
		}
		if err := Remove(state, it.Name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemove(t *testing.T) {
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	plant(t, state, fname(2), goodBody, 0o600)
	if err := Remove(state, fname(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName, fname(1))); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("file still there: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName, fname(2))); err != nil {
		t.Fatalf("other file gone: %v", err)
	}
	// Removing again is harmless.
	if err := Remove(state, fname(1)); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
	// So is removing from a state directory that never had requests.
	if err := Remove(newState(t), fname(1)); err != nil {
		t.Fatalf("Remove without requests dir: %v", err)
	}
	if err := Remove(filepath.Join(t.TempDir(), "nope"), fname(1)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing state dir: got %v, want ErrNotExist", err)
	}
}

func TestRemoveRejectsBadNames(t *testing.T) {
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	outside := filepath.Join(state, "incidents.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "/", "../incidents.json", "a/b", "/a", "a/", "a\x00b", securefile.TempPrefix + "x", securefile.TempPrefix} {
		if err := Remove(state, name); !errors.Is(err, securefile.ErrInvalidName) {
			t.Errorf("Remove(%q) = %v, want ErrInvalidName", name, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("file outside the requests directory was touched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, DirName, fname(1))); err != nil {
		t.Fatalf("request removed by a bad name: %v", err)
	}
}

func TestRemoveRejectedFilesOfEveryKind(t *testing.T) {
	// A rejected entry of any kind can be removed, so the daemon is not stuck
	// with it: a bad name, a backslash name, a symlink, a directory, and a
	// directory with content (with a link to a file outside inside it).
	state := newState(t)
	rd := reqDir(t, state)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	plant(t, state, ".hidden", "x", 0o600)
	plant(t, state, `a\b`, "x", 0o600)
	plant(t, state, `\`, "x", 0o600)
	if err := os.Symlink("/nonexistent", filepath.Join(rd, fname(1))); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(rd, fname(2)), 0o700); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(rd, "a000")
	if err := os.MkdirAll(filepath.Join(full, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "sub", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(full, "link")); err != nil {
		t.Fatal(err)
	}
	b := pending(t, state)
	if len(b.Items) != 2 || len(b.Stray) != 4 {
		t.Fatalf("got %d items and %d stray, want 2 and 4: %+v", len(b.Items), len(b.Stray), b)
	}
	for _, it := range append(append([]Item{}, b.Stray...), b.Items...) {
		if it.Accepted() {
			t.Fatalf("accepted: %+v", it)
		}
		if err := Remove(state, it.Name); err != nil {
			t.Fatalf("Remove(%q): %v", it.Name, err)
		}
	}
	if b := pending(t, state); len(b.Items) != 0 || len(b.Stray) != 0 {
		t.Fatalf("still pending: %+v", b)
	}
	if ents, _ := os.ReadDir(rd); len(ents) != 0 {
		t.Fatalf("directory not empty: %v", ents)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "keep" {
		t.Fatalf("a link inside a removed directory was followed: %q %v", got, err)
	}
}

func TestRemoveBackslashName(t *testing.T) {
	// A backslash is an ordinary byte of a file name here: Remove must delete
	// such an entry and nothing else.
	state := newState(t)
	plant(t, state, `a\b`, "x", 0o600)
	plant(t, state, "ab", "x", 0o600)
	b := pending(t, state)
	if len(b.Stray) != 2 {
		t.Fatalf("got %+v", b)
	}
	if err := Remove(state, `a\b`); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName, `a\b`)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("entry still there: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(state, DirName, "ab")); err != nil {
		t.Fatalf("other entry gone: %v", err)
	}
}

func TestRequestsDirSwappedWhileOpening(t *testing.T) {
	// The directory is replaced by another one after it passed the trust
	// check: the second look notices and nothing is read or written.
	for name, op := range map[string]func(string) error{
		"Submit":  func(s string) error { _, err := Submit(s, Request{Action: ActionAck, IncidentID: "a1"}); return err },
		"Pending": func(s string) error { _, err := Pending(s); return err },
		"Remove":  func(s string) error { return Remove(s, fname(1)) },
	} {
		t.Run(name, func(t *testing.T) {
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
			}
			if err := op(state); !errors.Is(err, securefile.ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
			if ents, _ := os.ReadDir(rd); len(ents) != 0 {
				t.Fatalf("the swapped-in directory was written to: %v", ents)
			}
			if _, err := os.Stat(filepath.Join(rd+".old", fname(1))); err != nil {
				t.Fatalf("the original request was touched: %v", err)
			}
		})
	}
}

func TestGrowsWhileBeingRead(t *testing.T) {
	// The file passes the size check and then grows past the limit while it
	// is read; the read stays bounded and the file is rejected as oversize.
	state := newState(t)
	p := plant(t, state, fname(1), goodBody, 0o600)
	calls := 0
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		if fi.Name() == fname(1) {
			calls++
			if calls == 2 {
				if err := os.WriteFile(p, []byte(goodBody+strings.Repeat(" ", MaxFileSize)), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return securefile.DefaultOwnerOf(fi)
	})
	wantReject(t, pending(t, state), fname(1), ReasonOversize)
}

func TestTrustedOwner(t *testing.T) {
	old := getuid
	t.Cleanup(func() { getuid = old })
	cases := []struct {
		uid, self int
		want      bool
	}{
		{0, 1000, true},
		{1000, 1000, true},
		{1001, 1000, false},
		{0, 0, true},
		{1000, 0, false},
	}
	for _, c := range cases {
		getuid = func() int { return c.self }
		if got := trustedOwner(c.uid); got != c.want {
			t.Errorf("trustedOwner(%d) as %d = %v, want %v", c.uid, c.self, got, c.want)
		}
	}
}

func TestOwnerUsesInjectedFunction(t *testing.T) {
	state := newState(t)
	plant(t, state, fname(1), goodBody, 0o600)
	// uid 0 is trusted whoever runs the daemon.
	setOwner(t, func(fi fs.FileInfo) (int, error) {
		if fi.Name() == fname(1) {
			return 0, nil
		}
		return securefile.DefaultOwnerOf(fi)
	})
	if b := pending(t, state); len(b.Items) != 1 || !b.Items[0].Accepted() {
		t.Fatalf("root-owned file not accepted: %+v", b.Items)
	}
}

func TestNamesDifferWithFrozenClock(t *testing.T) {
	state := newState(t)
	at := time.Unix(1_800_000_000, 0)
	setNow(t, func() time.Time { return at })
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		n, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1", RequestedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("name %q repeated", n)
		}
		seen[n] = true
		if suffix := n[len("req-")+20+1:]; suffix == strings.Repeat("0", 32) {
			t.Fatalf("random part of %q is all zero", n)
		}
	}
	if b := pending(t, state); len(b.Items) != 20 {
		t.Fatalf("got %d items, want 20", len(b.Items))
	}
}

func TestSubmitTwiceReusesRequestsDir(t *testing.T) {
	state := newState(t)
	for i := 0; i < 2; i++ {
		if _, err := Submit(state, Request{Action: ActionAck, IncidentID: "a1"}); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}
}

func TestReadErrorsAreMapped(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		reason Reason
		skip   bool
	}{
		{"changed", fmt.Errorf("x: %w", securefile.ErrChanged), ReasonUntrusted, false},
		{"untrusted", fmt.Errorf("x: %w", securefile.ErrUntrusted), ReasonUntrusted, false},
		{"too large", fmt.Errorf("x: %w", securefile.ErrTooLarge), ReasonOversize, false},
		{"io error", syscall.EIO, ReasonUnreadable, false},
		{"gone", fmt.Errorf("x: %w", fs.ErrNotExist), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := newState(t)
			plant(t, state, fname(1), goodBody, 0o600)
			old := readCapped
			readCapped = func(*securefile.Dir, string) ([]byte, error) { return []byte(goodBody), c.err }
			t.Cleanup(func() { readCapped = old })
			b := pending(t, state)
			if c.skip {
				if len(b.Items) != 0 {
					t.Fatalf("got %+v, want nothing", b.Items)
				}
				return
			}
			wantReject(t, b, fname(1), c.reason)
		})
	}
}
