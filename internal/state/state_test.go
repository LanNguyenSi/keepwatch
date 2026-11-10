package state

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func sample() *State {
	return FromResults([]result.Result{
		{CheckID: "ssh.password_authentication", Kind: "sshd_effective", Status: result.Fail, Severity: result.High,
			Evidence: []result.Evidence{{Subject: "passwordauthentication", Detail: "secret detail password=hunter2"}}},
		{CheckID: "services.fail2ban_active", Kind: "service_active", Status: result.Pass, Severity: result.High, Evidence: []result.Evidence{}},
	}, t0, nil)
}

func newStore(t *testing.T, opts ...Option) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func mustSave(t *testing.T, s *Store, st *State) {
	t.Helper()
	if err := s.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

func TestOpenCleansAndRequiresAbsolute(t *testing.T) {
	for _, bad := range []string{"", "relative/dir", ".", "..", "a/../..", "/", "/.."} {
		if _, err := Open(bad); err == nil {
			t.Errorf("Open(%q) accepted a path that is not an absolute directory", bad)
		}
	}
	s, err := Open("/var/lib/../lib//keepwatch/./")
	if err != nil {
		t.Fatal(err)
	}
	if s.Dir() != "/var/lib/keepwatch" || s.Path() != "/var/lib/keepwatch/state.json" {
		t.Errorf("Dir = %q, Path = %q", s.Dir(), s.Path())
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s, dir := newStore(t)
	st := sample()
	mustSave(t, s, st)

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("created directory mode = %o, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o, want 0600", fi.Mode().Perm())
	}
	if got := listDir(t, dir); len(got) != 1 || got[0] != FileName {
		t.Errorf("directory holds %v, want only %s", got, FileName)
	}

	lr, err := s.Load()
	if err != nil || lr.Problem != "" || lr.Missing || lr.State == nil {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
	if lr.State.SchemaVersion != SchemaVersion || !lr.State.RunAt.Equal(t0) || len(lr.State.Checks) != 2 {
		t.Errorf("loaded %+v", lr.State)
	}
	c := lr.State.Find("ssh.password_authentication")
	if c == nil || c.Status != result.Fail || c.Severity != result.High || len(c.Items) != 1 ||
		c.Items[0].Key != result.SubjectKey("passwordauthentication") || c.Items[0].Subject != "passwordauthentication" {
		t.Errorf("loaded check %+v", c)
	}
	// Evidence detail text is not part of the state.
	b, _ := os.ReadFile(s.Path())
	if !strings.HasSuffix(string(b), "}\n") {
		t.Errorf("the state file should end with a newline: %q", b[len(b)-3:])
	}
	if strings.Contains(string(b), "hunter2") || strings.Contains(string(b), "secret detail") {
		t.Errorf("state file holds evidence detail text:\n%s", b)
	}
}

func TestSaveIsMode0600UnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	s, _ := newStore(t)
	mustSave(t, s, sample())
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o under umask 0, want 0600", fi.Mode().Perm())
	}
}

func TestLoadMissing(t *testing.T) {
	s, dir := newStore(t)
	if lr, err := s.Load(); err != nil || !lr.Missing || lr.State != nil || lr.Problem != "" {
		t.Errorf("no directory: %+v, %v", lr, err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if lr, err := s.Load(); err != nil || !lr.Missing || lr.State != nil || lr.Problem != "" {
		t.Errorf("empty directory: %+v, %v", lr, err)
	}
}

func TestLoadingSomethingUnusableIsAProblemNotAnError(t *testing.T) {
	good, err := Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	g := string(good)
	cases := map[string]string{
		"empty file":          "",
		"truncated":           g[:len(g)/2],
		"garbage":             "\x00\x01 not json",
		"not an object":       "[1,2,3]",
		"data after json":     g + "{}",
		"unknown field":       strings.Replace(g, `"run_at"`, `"extra": 1, "run_at"`, 1),
		"version 1":           strings.Replace(g, `"schema_version": 3`, `"schema_version": 1`, 1),
		"version 2":           strings.Replace(g, `"schema_version": 3`, `"schema_version": 2`, 1),
		"version 4":           strings.Replace(g, `"schema_version": 3`, `"schema_version": 4`, 1),
		"schema zero":         strings.Replace(g, `"schema_version": 3`, `"schema_version": 0`, 1),
		"no schema":           strings.Replace(g, `"schema_version": 3,`, ``, 1),
		"cutoff of version 2": strings.Replace(g, `"items": [`, `"cutoff": "a", "items": [`, 1),
		"hidden of version 2": strings.Replace(g, `"items": [`, `"hidden": 3, "items": [`, 1),
		"exact of version 2":  strings.Replace(g, `"subject": "passwordauthentication"`, `"subject": "passwordauthentication", "exact": true`, 1),
		"bad status":          strings.Replace(g, `"status": "fail"`, `"status": "bogus"`, 1),
		"bad severity":        strings.Replace(g, `"severity": "high"`, `"severity": "extreme"`, 1),
		"empty id":            strings.Replace(g, `"id": "ssh.password_authentication"`, `"id": ""`, 1),
		"duplicate id":        strings.Replace(g, `"id": "services.fail2ban_active"`, `"id": "ssh.password_authentication"`, 1),
		"bad key":             strings.Replace(g, result.SubjectKey("passwordauthentication"), "xyz", 1),
		"no checks":           `{"schema_version": 3, "run_at": "2026-11-10T12:00:00Z", "checks": []}`,
		"null checks":         `{"schema_version": 3, "run_at": "2026-11-10T12:00:00Z", "checks": null}`,
		"wrong type":          strings.Replace(g, `"status": "fail"`, `"status": 7`, 1),
		"huge item count":     hugeItems(),
		"too many checks":     manyChecks(maxChecks + 1),
		"id too long":         strings.Replace(g, `"id": "services.fail2ban_active"`, `"id": "`+strings.Repeat("a", maxIDLen+1)+`"`, 1),
		"kind too long":       strings.Replace(g, `"kind": "service_active"`, `"kind": "`+strings.Repeat("k", maxIDLen+1)+`"`, 1),
		"duplicate key":       strings.Replace(g, `"items": []`, fmt.Sprintf(`"items": [{"key":"%[1]s","subject":"a"},{"key":"%[1]s","subject":"b"}]`, result.SubjectKey("a")), 1),
		"subject too long":    strings.Replace(g, `"subject": "passwordauthentication"`, `"subject": "`+strings.Repeat("s", maxSubjectLen+1)+`"`, 1),
		"oversize":            strings.Repeat(" ", MaxFileSize+1),
		"valid then spaces":   g + strings.Repeat(" ", MaxFileSize),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.Path(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			lr, err := s.Load()
			if err != nil {
				t.Fatalf("Load returned an error for an unusable file: %v", err)
			}
			if lr.State != nil || lr.Missing || lr.Problem == "" {
				t.Fatalf("Load = %+v, want a problem and no state", lr)
			}
		})
	}
}

func manyChecks(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"schema_version":3,"run_at":"2026-11-10T12:00:00Z","checks":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"id":"c.%d","kind":"k","status":"pass","severity":"low","items":[]}`, i)
	}
	sb.WriteString(`]}`)
	return sb.String()
}

func hugeItems() string {
	var sb strings.Builder
	sb.WriteString(`{"schema_version":3,"run_at":"2026-11-10T12:00:00Z","checks":[{"id":"a.b","kind":"k","status":"fail","severity":"low","items":[`)
	for i := 0; i < maxItems+1; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"key":"%064x","subject":"s"}`, i)
	}
	sb.WriteString(`]}]}`)
	return sb.String()
}

func TestLoadDoesNotFollowASymlinkedStateFile(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	other := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Rename(s.Path(), other); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, s.Path()); err != nil {
		t.Fatal(err)
	}
	lr, err := s.Load()
	if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "symlink") {
		t.Fatalf("Load = %+v, %v; want a symlink problem", lr, err)
	}
	_ = dir
}

func TestLoadRefusesNonRegularFiles(t *testing.T) {
	s, _ := newStore(t)
	if err := os.MkdirAll(s.Path(), 0o700); err != nil { // a directory named state.json
		t.Fatal(err)
	}
	lr, err := s.Load()
	if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "not a regular file") {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
}

func TestLoadRefusesAFileGroupOrOtherCanWrite(t *testing.T) {
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		s, _ := newStore(t)
		mustSave(t, s, sample())
		if err := os.Chmod(s.Path(), mode); err != nil {
			t.Fatal(err)
		}
		lr, err := s.Load()
		if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "permissions") {
			t.Errorf("mode %o: Load = %+v, %v", mode, lr, err)
		}
	}
	// Read access for others is not a problem.
	s, _ := newStore(t)
	mustSave(t, s, sample())
	if err := os.Chmod(s.Path(), 0o644); err != nil {
		t.Fatal(err)
	}
	if lr, err := s.Load(); err != nil || lr.State == nil {
		t.Errorf("mode 0644: Load = %+v, %v", lr, err)
	}
}

func TestLoadRefusesAForeignOwnedFile(t *testing.T) {
	var foreignFile bool
	of := func(fi fs.FileInfo) (int, error) {
		if foreignFile && !fi.IsDir() {
			return os.Getuid() + 4242, nil
		}
		return defaultOwnerOf(fi)
	}
	s, _ := newStore(t, WithOwnerOf(of))
	mustSave(t, s, sample())
	foreignFile = true
	lr, err := s.Load()
	if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "owned by uid") {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
	if want := "want " + wantOwner(os.Getuid()); !strings.HasSuffix(lr.Problem, want) {
		t.Errorf("Problem = %q, want it to end in %q", lr.Problem, want)
	}
	// An owner lookup that fails is a problem too.
	failing := func(fi fs.FileInfo) (int, error) {
		if !fi.IsDir() {
			return 0, errors.New("no owner")
		}
		return defaultOwnerOf(fi)
	}
	s2, _ := newStore(t, WithOwnerOf(failing))
	mustSave(t, s2, sample())
	if lr, err := s2.Load(); err != nil || lr.State != nil || lr.Problem == "" {
		t.Fatalf("failing owner lookup: Load = %+v, %v", lr, err)
	}
}

func TestRootOwnedIsAccepted(t *testing.T) {
	// A root-owned file in a root-owned directory is the production case.
	root := func(fi fs.FileInfo) (int, error) { return 0, nil }
	s, _ := newStore(t, WithOwnerOf(root))
	mustSave(t, s, sample())
	if lr, err := s.Load(); err != nil || lr.State == nil {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
}

func TestDirectoryRules(t *testing.T) {
	mk := func(t *testing.T) (*Store, string) {
		s, dir := newStore(t)
		mustSave(t, s, sample())
		return s, dir
	}
	check := func(t *testing.T, s *Store, want string) {
		t.Helper()
		lr, err := s.Load()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Load error = %v (result %+v), want %q", err, lr, want)
		}
		if lr.State != nil {
			t.Errorf("Load returned a state from an untrusted directory")
		}
		err = s.Save(sample())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Save error = %v, want %q", err, want)
		}
	}
	t.Run("group writable", func(t *testing.T) {
		s, dir := mk(t)
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		check(t, s, "allow group or other writes")
	})
	t.Run("other writable", func(t *testing.T) {
		s, dir := mk(t)
		if err := os.Chmod(dir, 0o703); err != nil {
			t.Fatal(err)
		}
		check(t, s, "allow group or other writes")
	})
	t.Run("symlink to a good directory", func(t *testing.T) {
		s, dir := mk(t)
		real := dir + ".real"
		if err := os.Rename(dir, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, dir); err != nil {
			t.Fatal(err)
		}
		check(t, s, "it is a symlink")
		if _, err := os.Stat(filepath.Join(real, FileName)); err != nil {
			t.Errorf("the linked directory lost its state: %v", err)
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		s, dir := newStore(t)
		if err := os.Symlink(filepath.Join(filepath.Dir(dir), "nowhere"), dir); err != nil {
			t.Fatal(err)
		}
		check(t, s, "it is a symlink")
		if _, err := os.Lstat(filepath.Join(filepath.Dir(dir), "nowhere")); err == nil {
			t.Errorf("Save created the target of a dangling symlink")
		}
	})
	t.Run("a file", func(t *testing.T) {
		s, dir := newStore(t)
		if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		check(t, s, "must be a directory")
	})
	t.Run("foreign owner", func(t *testing.T) {
		foreign := func(fi fs.FileInfo) (int, error) { return os.Getuid() + 4242, nil }
		s, _ := newStore(t, WithOwnerOf(foreign))
		// The directory does not exist yet: Save creates it, and then
		// refuses it because it is not owned by root or the running user.
		if err := s.Save(sample()); err == nil || !strings.HasSuffix(err.Error(), "want "+wantOwner(os.Getuid())) {
			t.Errorf("Save error = %v", err)
		}
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Errorf("Load error = %v", err)
		}
	})
	t.Run("owner lookup fails", func(t *testing.T) {
		s, _ := newStore(t, WithOwnerOf(func(fs.FileInfo) (int, error) { return 0, errors.New("boom") }))
		if err := s.Save(sample()); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("Save error = %v", err)
		}
	})
}

func TestSaveReplacesASymlinkAtTheStatePathWithoutFollowingIt(t *testing.T) {
	s, dir := newStore(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, s.Path()); err != nil {
		t.Fatal(err)
	}
	mustSave(t, s, sample())
	if b, _ := os.ReadFile(victim); string(b) != "keep me" {
		t.Errorf("Save wrote through the symlink: %q", b)
	}
	fi, err := os.Lstat(s.Path())
	if err != nil || !fi.Mode().IsRegular() {
		t.Errorf("state path is not a regular file after Save: %v %v", fi, err)
	}
	if lr, err := s.Load(); err != nil || lr.State == nil {
		t.Errorf("Load = %+v, %v", lr, err)
	}
}

func TestSaveFailureKeepsThePreviousStateAndLeavesNoTempFile(t *testing.T) {
	boom := errors.New("injected failure")
	steps := map[string]func(*Store){
		"write": func(s *Store) { s.hooks.write = func(*os.File, []byte) (int, error) { return 0, boom } },
		"short write": func(s *Store) {
			s.hooks.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:len(b)/2]) }
		},
		"sync":   func(s *Store) { s.hooks.sync = func(*os.File) error { return boom } },
		"rename": func(s *Store) { s.hooks.rename = func(*os.Root, string, string) error { return boom } },
	}
	for name, inject := range steps {
		t.Run(name, func(t *testing.T) {
			s, dir := newStore(t)
			old := sample()
			mustSave(t, s, old)
			before, _ := os.ReadFile(s.Path())

			next := FromResults([]result.Result{{CheckID: "x.y", Kind: "k", Status: result.Fail, Severity: result.Low}}, t0.Add(time.Hour), nil)
			inject(s)
			if err := s.Save(next); err == nil {
				t.Fatal("Save succeeded although a step failed")
			} else if name != "short write" && !errors.Is(err, boom) {
				t.Fatalf("Save error = %v, want the injected one", err)
			} else if name == "short write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatalf("Save error = %v, want a short write", err)
			}
			after, _ := os.ReadFile(s.Path())
			if string(before) != string(after) {
				t.Errorf("the previous state file changed")
			}
			if got := listDir(t, dir); len(got) != 1 || got[0] != FileName {
				t.Errorf("directory holds %v after the failure, want only %s", got, FileName)
			}
		})
	}
	t.Run("sync of the directory", func(t *testing.T) {
		s, dir := newStore(t)
		s.hooks.syncDir = func(*os.File) error { return boom }
		if err := s.Save(sample()); !errors.Is(err, boom) {
			t.Fatalf("Save error = %v", err)
		}
		if got := listDir(t, dir); len(got) != 1 {
			t.Errorf("directory holds %v", got)
		}
	})
	t.Run("first write fails and nothing exists", func(t *testing.T) {
		s, dir := newStore(t)
		s.hooks.rename = func(*os.Root, string, string) error { return boom }
		if err := s.Save(sample()); err == nil {
			t.Fatal("Save succeeded")
		}
		if got := listDir(t, dir); len(got) != 0 {
			t.Errorf("directory holds %v, want empty", got)
		}
		if lr, err := s.Load(); err != nil || !lr.Missing {
			t.Errorf("Load = %+v, %v", lr, err)
		}
	})
}

func TestSaveRefusesAStateTooLargeToReadBack(t *testing.T) {
	s, dir := newStore(t)
	big := &State{SchemaVersion: SchemaVersion, RunAt: t0, Checks: []Check{{ID: "a.b", Kind: "k", Status: result.Fail, Severity: result.Low}}}
	for i := 0; i < 60000; i++ {
		big.Checks[0].Items = append(big.Checks[0].Items, Item{Key: result.SubjectKey(fmt.Sprint(i)), Subject: strings.Repeat("x", 200)})
	}
	if err := s.Save(big); err == nil || !strings.Contains(err.Error(), "larger than the limit") {
		t.Fatalf("Save error = %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		if got := listDir(t, dir); len(got) != 0 {
			t.Errorf("directory holds %v", got)
		}
	}
}

func TestLeftoverTempFileIsHarmless(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	if err := os.WriteFile(filepath.Join(dir, tempPrefix+"0000000000000000"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if lr, err := s.Load(); err != nil || lr.State == nil {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
	mustSave(t, s, sample())
}

func TestFromResults(t *testing.T) {
	hostile := "evil\x1b[31m password=hunter2"
	clean := func(s string) string { return strings.NewReplacer("\x1b", `\x1b`, "hunter2", "[REDACTED]").Replace(s) }
	st := FromResults([]result.Result{
		{CheckID: "a.one", Kind: "k", Status: result.Fail, Severity: result.High, Evidence: []result.Evidence{
			{Subject: hostile}, {Subject: "plain", Excepted: true}, {Subject: "plain", Excepted: false},
		}},
	}, t0.Add(500*time.Millisecond), clean)
	c := st.Find("a.one")
	if c == nil || len(c.Items) != 2 {
		t.Fatalf("check %+v", c)
	}
	if c.Items[0].Key != result.SubjectKey(hostile) {
		t.Errorf("the key must come from the raw subject")
	}
	if strings.Contains(c.Items[0].Subject, "hunter2") || strings.Contains(c.Items[0].Subject, "\x1b") {
		t.Errorf("display subject not cleaned: %q", c.Items[0].Subject)
	}
	// A repeated subject is one item, and counts as excepted only if every
	// occurrence is excepted.
	if c.Items[1].Subject != "plain" || c.Items[1].Excepted {
		t.Errorf("duplicate fold: %+v", c.Items[1])
	}
	if !st.RunAt.Equal(t0) {
		t.Errorf("RunAt = %v, want %v truncated to the second", st.RunAt, t0)
	}
	// Distinct raw subjects with the same cleaned text stay distinct.
	same := FromResults([]result.Result{{CheckID: "a.one", Status: result.Fail, Severity: result.Low, Evidence: []result.Evidence{
		{Subject: "web"}, {Subject: "web\x01"},
	}}}, t0, func(s string) string { return strings.ReplaceAll(s, "\x01", "") })
	if got := same.Find("a.one"); len(got.Items) != 2 || got.Items[0].Key == got.Items[1].Key {
		t.Errorf("subjects that clean to the same text were merged: %+v", got)
	}
}

func TestFromResultsDisplaySubjectIsBounded(t *testing.T) {
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low,
		Evidence: []result.Evidence{{Subject: strings.Repeat("é", 5000)}}}}, t0, nil)
	if got := len([]rune(st.Checks[0].Items[0].Subject)); got > displayRunes+3 {
		t.Errorf("display subject has %d runes", got)
	}
	if err := validate(st); err != nil {
		t.Errorf("a bounded subject must pass validation: %v", err)
	}
}

func TestFromResultsMergesResultsThatShareAnID(t *testing.T) {
	// The engine reports one exception_expired result per expired exception.
	st := FromResults([]result.Result{
		{CheckID: "exception_expired", Kind: "exception", Status: result.Excepted, Severity: result.Low,
			Evidence: []result.Evidence{{Subject: "a", Excepted: true}}},
		{CheckID: "exception_expired", Kind: "exception", Status: result.Fail, Severity: result.Low,
			Evidence: []result.Evidence{{Subject: "b"}}},
		{CheckID: "exception_expired", Kind: "exception", Status: result.Excepted, Severity: result.Medium,
			Evidence: []result.Evidence{{Subject: "c", Excepted: true}}},
	}, t0, nil)
	if len(st.Checks) != 1 {
		t.Fatalf("checks = %+v", st.Checks)
	}
	c := st.Checks[0]
	if c.Status != result.Fail || c.Severity != result.Medium || len(c.Items) != 3 {
		t.Errorf("merged check %+v", c)
	}
	if err := validate(st); err != nil {
		t.Errorf("merged state invalid: %v", err)
	}
}

// capped returns what the engine hands over for a list of total distinct
// subjects that a probe cut: the first 99 sorted and the marker, with the set
// of all of them.
func capped(total int) result.Result {
	all := make([]result.Evidence, total)
	for i := range all {
		all[i] = result.Evidence{Subject: fmt.Sprintf("item-%05d", i), Detail: "d"}
	}
	ev := append([]result.Evidence(nil), all[:99]...)
	ev = append(ev, result.Evidence{
		Subject: fmt.Sprintf("(%d more not shown)", total-99),
		Detail:  fmt.Sprintf("%d further items are not listed, the limit is 100 items", total-99),
	})
	return result.Result{CheckID: "a.b", Kind: "k", Status: result.Fail, Severity: result.Low, Evidence: ev, Set: result.NewEvidenceSet(all)}
}

func items(n int) []result.Evidence {
	var out []result.Evidence
	for i := 0; i < n; i++ {
		out = append(out, result.Evidence{Subject: fmt.Sprintf("item-%03d", i), Detail: "d"})
	}
	return out
}

func TestMarkerIsRecognisedByTheSetOnly(t *testing.T) {
	look := result.Evidence{Subject: "(7 more not shown)", Detail: "7 further items are not listed, the limit is 100 items"}
	res := func(ev []result.Evidence, set *result.EvidenceSet) result.Result {
		return result.Result{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: ev, Set: set}
	}
	cases := []struct {
		name      string
		r         result.Result
		wantItems int
	}{
		{"a cut list: the last item is the marker", capped(106), 99},
		{"no set: nothing is a marker", res(items(10), nil), 10},
		{"empty", res(nil, nil), 0},
		{"a text that looks exactly like the marker is an item without a set", res(append(items(99), look), nil), 100},
		{"an excepted marker is still the marker", func() result.Result {
			r := capped(106)
			r.Evidence[99].Excepted = true
			return r
		}(), 99},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := FromResults([]result.Result{c.r}, t0, nil)
			if got := len(st.Checks[0].Items); got != c.wantItems {
				t.Errorf("%d items stored, want %d", got, c.wantItems)
			}
			for _, it := range st.Checks[0].Items {
				if strings.Contains(it.Subject, "more not shown") && c.r.Set != nil {
					t.Errorf("the marker is stored as an item")
				}
			}
		})
	}
}

func TestMarkerBecomesTheKeySet(t *testing.T) {
	st := FromResults([]result.Result{capped(106)}, t0, nil)
	c := st.Checks[0]
	if len(c.Items) != 99 || !c.Capped() || c.Total != 106 || len(c.Keys) != 106 || c.SetTotal() != 106 {
		t.Fatalf("check: %d items, total %d, %d keys", len(c.Items), c.Total, len(c.Keys))
	}
	if c.Digest != result.DigestOfKeys(c.Keys) || c.SetDigest() != c.Digest {
		t.Errorf("digest %s", c.Digest)
	}
	for _, it := range c.Items {
		if strings.Contains(it.Subject, "more not shown") {
			t.Errorf("the marker is stored as an item")
		}
	}
	b, _ := Marshal(st)
	if strings.Contains(string(b), "item-00105") || strings.Contains(string(b), "item-00099") {
		t.Errorf("a subject that was cut is stored:\n%s", b)
	}
	// A list that was not cut has no set in the file, and the set methods
	// derive it from the items.
	un := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: items(3)}}, t0, nil).Checks[0]
	if un.Capped() || un.Total != 0 || un.Keys != nil || un.Digest != "" || un.SetTotal() != 3 {
		t.Errorf("uncapped check: %+v", un)
	}
	keys, ok := un.SetKeys()
	if !ok || len(keys) != 3 || un.SetDigest() != result.DigestOfKeys(keys) {
		t.Errorf("keys %v %v", keys, ok)
	}
}

func TestValidateAcceptsWhatFromResultsProduces(t *testing.T) {
	st := FromResults([]result.Result{
		capped(106),
		{CheckID: "c.d", Kind: "k", Status: result.Skipped, Severity: result.Info},
	}, t0, nil)
	b, err := Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(b); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestReadCappedReportsWhatExceedsTheCap(t *testing.T) {
	if b, err := readCapped(strings.NewReader("12345"), 5); err != nil || string(b) != "12345" {
		t.Errorf("at the cap: %q, %v", b, err)
	}
	if _, err := readCapped(strings.NewReader("123456"), 5); err == nil {
		t.Error("one byte over the cap was accepted")
	}
	if _, err := readCapped(strings.NewReader(strings.Repeat("x", 100)), 5); err == nil {
		t.Error("far over the cap was accepted")
	}
}

func TestLoadSizeLimitIsCheckedBeforeReading(t *testing.T) {
	s, dir := newStore(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), []byte(strings.Repeat(" ", MaxFileSize+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	lr, err := s.Load()
	if err != nil || !strings.Contains(lr.Problem, "bytes, larger than the limit") {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
}

func TestDirectorySwappedAfterTheCheckIsRefused(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	// Between the check of the path and the open, replace the directory by
	// another one (a different inode at the same path).
	s.hooks.dirChecked = func() {
		if err := os.Rename(dir, dir+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestTempFileIsNeverReusedOrFollowed(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	s.hooks.tempName = func() (string, error) { return ".fixed-temp-name", nil }

	// An existing regular file under the temporary name is not overwritten.
	existing := filepath.Join(dir, ".fixed-temp-name")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Path())
	if err := s.Save(sample()); err == nil {
		t.Fatal("Save reused an existing temporary file")
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Errorf("existing file was written: %q", b)
	}
	if b, _ := os.ReadFile(s.Path()); string(b) != string(before) {
		t.Error("state file changed")
	}

	// A symlink under the temporary name is not written through.
	if err := os.Remove(existing); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, existing); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(sample()); err == nil {
		t.Fatal("Save wrote through a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("victim was written: %q", b)
	}
	// A failing name source is an error, not a panic.
	s.hooks.tempName = func() (string, error) { return "", errors.New("no randomness") }
	if err := s.Save(sample()); err == nil {
		t.Fatal("Save ignored the error of the name source")
	}
}

func TestDirectoryChangedAfterTheCheckIsCheckedAgain(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	s.hooks.dirChecked = func() {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "allow group or other writes") {
		t.Fatalf("Load error = %v", err)
	}
}

func TestFileSwappedForALinkAfterTheCheckIsNotFollowed(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	// A link that stays inside the directory is one os.Root would follow;
	// the open itself must refuse it.
	good, _ := os.ReadFile(s.Path())
	other := filepath.Join(dir, "other.json")
	if err := os.WriteFile(other, good, 0o600); err != nil {
		t.Fatal(err)
	}
	s.hooks.beforeOpen = func() {
		if err := os.Remove(s.Path()); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("other.json", s.Path()); err != nil {
			t.Fatal(err)
		}
	}
	lr, err := s.Load()
	if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "changed while") {
		t.Fatalf("Load = %+v, %v; the swapped link was followed", lr, err)
	}
}

func TestSaveCloseFailure(t *testing.T) {
	s, dir := newStore(t)
	mustSave(t, s, sample())
	before, _ := os.ReadFile(s.Path())
	boom := errors.New("close failed")
	s.hooks.closeFile = func(f *os.File) error { f.Close(); return boom }
	if err := s.Save(sample()); !errors.Is(err, boom) {
		t.Fatalf("Save error = %v", err)
	}
	if after, _ := os.ReadFile(s.Path()); string(after) != string(before) {
		t.Error("state file changed")
	}
	if got := listDir(t, dir); len(got) != 1 {
		t.Errorf("directory holds %v", got)
	}
}

func TestRunAtIsStoredInUTC(t *testing.T) {
	zone := time.FixedZone("x", 5*3600+1800)
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Pass, Severity: result.Low}}, time.Date(2026, 11, 10, 17, 30, 15, 999, zone), nil)
	b, err := Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"run_at": "2026-11-10T12:00:15Z"`) {
		t.Errorf("run_at not in UTC at second precision:\n%s", b)
	}
}

func TestMergedResultsUniteTheirSets(t *testing.T) {
	one := capped(130)
	two := capped(150)
	st := FromResults([]result.Result{
		one,
		two,
		{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: []result.Evidence{{Subject: "extra"}}},
	}, t0, nil)
	c := st.Checks[0]
	// item-00000..item-00149 and "extra": the first list is a subset of the second.
	if c.Total != 151 || len(c.Keys) != 151 || c.Digest != result.DigestOfKeys(c.Keys) {
		t.Fatalf("total %d, %d keys", c.Total, len(c.Keys))
	}
	if err := validate(st); err != nil {
		t.Errorf("merged state invalid: %v", err)
	}
}

func TestMergedResultsOfSetsTooLargeToListKeepADigest(t *testing.T) {
	big := func(prefix string, n int) result.Result {
		all := make([]result.Evidence, n)
		for i := range all {
			all[i] = result.Evidence{Subject: fmt.Sprintf("%s%06d", prefix, i)}
		}
		ev := append(append([]result.Evidence(nil), all[:99]...), result.Evidence{Subject: "(m)"})
		return result.Result{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: ev, Set: result.NewEvidenceSet(all)}
	}
	build := func(second result.Result) Check {
		st := FromResults([]result.Result{big("x", result.MaxKeys+10), second}, t0, nil)
		if err := validate(st); err != nil {
			t.Fatalf("invalid: %v", err)
		}
		return st.Checks[0]
	}
	a := build(big("y", 150))
	if a.Total != result.MaxKeys+10+150 || a.Keys != nil || len(a.Digest) != 64 {
		t.Fatalf("%+v", a)
	}
	if again := build(big("y", 150)); again.Digest != a.Digest {
		t.Error("the digest of the same input changed")
	}
	if other := build(big("z", 150)); other.Digest == a.Digest {
		t.Error("a different second list gives the same digest")
	}
}

func TestAListThatWasNotCutByTheProbeIsCutHere(t *testing.T) {
	n := maxItems + 500
	ev := make([]result.Evidence, n)
	for i := range ev {
		ev[i] = result.Evidence{Subject: fmt.Sprintf("s%05d", n-i)} // unsorted
	}
	st := FromResults([]result.Result{{CheckID: "a.b", Status: result.Fail, Severity: result.Low, Evidence: ev}}, t0, nil)
	c := st.Checks[0]
	if len(c.Items) != displayItems || c.Total != n || len(c.Keys) != n || c.Items[0].Subject != "s00001" {
		t.Fatalf("%d items, total %d, %d keys, first %q", len(c.Items), c.Total, len(c.Keys), c.Items[0].Subject)
	}
	if ev[0].Subject != fmt.Sprintf("s%05d", n) {
		t.Error("the caller's slice was reordered")
	}
	if err := validate(st); err != nil {
		t.Errorf("invalid: %v", err)
	}
}

func TestFileRemovedBeforeTheOpen(t *testing.T) {
	s, _ := newStore(t)
	mustSave(t, s, sample())
	s.hooks.beforeOpen = func() {
		if err := os.Remove(s.Path()); err != nil {
			t.Fatal(err)
		}
	}
	lr, err := s.Load()
	if err != nil || lr.Missing || lr.State != nil || !strings.Contains(lr.Problem, "disappeared") {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
}

func TestFileThatGrowsAfterTheSizeCheckIsStillCapped(t *testing.T) {
	s, _ := newStore(t)
	mustSave(t, s, sample())
	s.hooks.afterStat = func() {
		f, err := os.OpenFile(s.Path(), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write([]byte(strings.Repeat(" ", MaxFileSize))); err != nil {
			t.Fatal(err)
		}
	}
	lr, err := s.Load()
	if err != nil || lr.State != nil || !strings.Contains(lr.Problem, "cannot read") {
		t.Fatalf("Load = %+v, %v", lr, err)
	}
}

// The message names the owners that would have been accepted: as root only
// uid 0, otherwise uid 0 and the running user.
func TestOwnerMessagesNameTheAcceptedUIDs(t *testing.T) {
	old := getuid
	defer func() { getuid = old }()
	for _, running := range []int{0, 1000} {
		getuid = func() int { return running }
		foreign := func(fi fs.FileInfo) (int, error) { return 4242, nil }
		want := "want " + wantOwner(running)

		s, _ := newStore(t, WithOwnerOf(foreign))
		if err := s.Save(sample()); err == nil || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("running as %d: directory message %v, want it to end in %q", running, err, want)
		}
		// A foreign-owned file in a directory that is accepted.
		s2, _ := newStore(t, WithOwnerOf(func(fi fs.FileInfo) (int, error) { return 0, nil }))
		mustSave(t, s2, sample())
		s3, err := Open(filepath.Dir(s2.Path()), WithOwnerOf(func(fi fs.FileInfo) (int, error) {
			if fi.IsDir() {
				return 0, nil
			}
			return 4242, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		lr, err := s3.Load()
		if err != nil || !strings.HasSuffix(lr.Problem, want) {
			t.Errorf("running as %d: file message %q (%v), want it to end in %q", running, lr.Problem, err, want)
		}
	}
}

func TestWantOwnerNamesTheAcceptedUIDs(t *testing.T) {
	for running, want := range map[int]string{0: "uid 0", 1000: "uid 0 or 1000", 501: "uid 0 or 501"} {
		if got := wantOwner(running); got != want {
			t.Errorf("wantOwner(%d) = %q, want %q", running, got, want)
		}
	}
}
