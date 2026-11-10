package history

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var t0 = time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC)

func newStore(t *testing.T, opts ...Option) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func run(i int, n int) Run {
	r := Run{RunAt: t0.Add(time.Duration(i) * time.Hour), Changes: []Change{}}
	for j := 0; j < n; j++ {
		r.Changes = append(r.Changes, Change{Kind: "new_failure", CheckID: "a.b", CheckKind: "k", Severity: "high", From: "pass", To: "fail", Alert: true})
	}
	return r
}

func TestMissingHistoryIsEmpty(t *testing.T) {
	s, _ := newStore(t)
	lr, err := s.Load()
	if err != nil || !lr.Missing || lr.Problem != "" || len(lr.File.Runs) != 0 {
		t.Errorf("%+v, %v", lr, err)
	}
	// A missing state directory is a missing history too.
	s2, _ := Open(filepath.Join(t.TempDir(), "nope"))
	if lr, err := s2.Load(); err != nil || !lr.Missing {
		t.Errorf("%+v, %v", lr, err)
	}
}

func TestAppendRoundTripsAndKeepsTheLastSixtyRuns(t *testing.T) {
	s, dir := newStore(t)
	for i := 0; i < MaxRuns+5; i++ {
		if problem, err := s.Append(run(i, 1)); err != nil || problem != "" {
			t.Fatalf("append %d: %q %v", i, problem, err)
		}
	}
	lr, err := s.Load()
	if err != nil || lr.Problem != "" {
		t.Fatalf("%+v %v", lr, err)
	}
	if len(lr.File.Runs) != MaxRuns {
		t.Fatalf("%d runs", len(lr.File.Runs))
	}
	if first := lr.File.Runs[0]; !first.RunAt.Equal(t0.Add(5 * time.Hour)) {
		t.Errorf("oldest run kept: %v", first.RunAt)
	}
	if last := lr.File.Runs[MaxRuns-1]; !last.RunAt.Equal(t0.Add(time.Duration(MaxRuns+4) * time.Hour)) {
		t.Errorf("newest run: %v", last.RunAt)
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v, %v", fi.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("%d entries in the state directory (leftover temporary file?)", len(entries))
	}
}

func TestSince(t *testing.T) {
	f := File{Runs: []Run{run(0, 0), run(24, 0), run(48, 0)}}
	got := f.Since(t0.Add(24 * time.Hour))
	if len(got) != 2 || !got[0].RunAt.Equal(t0.Add(24*time.Hour)) {
		t.Errorf("%+v", got)
	}
	if len(f.Since(t0.Add(100*time.Hour))) != 0 {
		t.Error("runs after the end")
	}
}

func TestUnusableHistoryIsAProblemAndIsReplaced(t *testing.T) {
	s, dir := newStore(t)
	good, _ := marshal(&File{SchemaVersion: SchemaVersion, Runs: []Run{run(0, 1)}})
	cases := map[string]string{
		"empty":           "",
		"garbage":         "\x00\x01",
		"truncated":       string(good[:len(good)/2]),
		"wrong schema":    strings.Replace(string(good), `"schema_version": 1`, `"schema_version": 7`, 1),
		"unknown field":   strings.Replace(string(good), `"runs"`, `"extra": 1, "runs"`, 1),
		"data after":      string(good) + "{}",
		"too many runs":   manyRuns(MaxRuns + 1),
		"too many chg":    `{"schema_version":1,"runs":[{"run_at":"2026-11-01T06:00:00Z","changes":[` + strings.Repeat(`{"kind":"k","check_id":"a","check_kind":"k","severity":"low","alert":false},`, MaxChangesPerRun) + `{"kind":"k","check_id":"a","check_kind":"k","severity":"low","alert":false}]}]}`,
		"no time":         `{"schema_version":1,"runs":[{"changes":[]}]}`,
		"negative drop":   `{"schema_version":1,"runs":[{"run_at":"2026-11-01T06:00:00Z","changes":[],"dropped":-1}]}`,
		"a huge string":   `{"schema_version":1,"runs":[{"run_at":"2026-11-01T06:00:00Z","changes":[{"kind":"` + strings.Repeat("x", 5000) + `","check_id":"a","check_kind":"k","severity":"low","alert":false}]}]}`,
		"a number string": `{"schema_version":1,"runs":[{"run_at":"2026-11-01T06:00:00Z","changes":[{"kind":7}]}]}`,
	}
	for name, doc := range cases {
		if err := os.WriteFile(filepath.Join(dir, FileName), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		lr, err := s.Load()
		if err != nil || lr.Problem == "" || lr.Missing || len(lr.File.Runs) != 0 {
			t.Errorf("%s: %+v %v", name, lr, err)
		}
		problem, err := s.Append(run(1, 1))
		if err != nil || problem == "" {
			t.Errorf("%s: append: %q %v", name, problem, err)
		}
		if lr, _ := s.Load(); lr.Problem != "" || len(lr.File.Runs) != 1 {
			t.Errorf("%s: after the append %+v", name, lr)
		}
	}
}

func manyRuns(n int) string {
	var sb strings.Builder
	sb.WriteString(`{"schema_version":1,"runs":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"run_at":"2026-11-01T06:00:00Z","changes":[]}`)
	}
	sb.WriteString("]}")
	return sb.String()
}

func TestFileRulesAreThoseOfTheStateFile(t *testing.T) {
	good, _ := marshal(&File{SchemaVersion: SchemaVersion, Runs: []Run{run(0, 1)}})
	t.Run("symlink", func(t *testing.T) {
		s, dir := newStore(t)
		target := filepath.Join(dir, "real")
		os.WriteFile(target, good, 0o600)
		os.Symlink(target, filepath.Join(dir, FileName))
		lr, err := s.Load()
		if err != nil || !strings.Contains(lr.Problem, "symlink") || len(lr.File.Runs) != 0 {
			t.Errorf("%+v %v", lr, err)
		}
		// The write replaces the link, it does not write through it.
		if _, err := s.Append(run(1, 1)); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(target); string(b) != string(good) {
			t.Error("the append wrote through the symlink")
		}
		if fi, _ := os.Lstat(filepath.Join(dir, FileName)); fi.Mode()&fs.ModeSymlink != 0 {
			t.Error("still a symlink")
		}
	})
	t.Run("group writable", func(t *testing.T) {
		s, dir := newStore(t)
		p := filepath.Join(dir, FileName)
		os.WriteFile(p, good, 0o600)
		os.Chmod(p, 0o660)
		if lr, err := s.Load(); err != nil || !strings.Contains(lr.Problem, "permissions") {
			t.Errorf("%+v %v", lr, err)
		}
	})
	t.Run("foreign owner", func(t *testing.T) {
		s, dir := newStore(t, WithOwnerOf(func(fi fs.FileInfo) (int, error) {
			if fi.IsDir() {
				return os.Getuid(), nil
			}
			return os.Getuid() + 4242, nil
		}))
		os.WriteFile(filepath.Join(dir, FileName), good, 0o600)
		if lr, err := s.Load(); err != nil || !strings.Contains(lr.Problem, "owned by uid") {
			t.Errorf("%+v %v", lr, err)
		}
	})
	t.Run("owner root is fine", func(t *testing.T) {
		s, dir := newStore(t, WithOwnerOf(func(fs.FileInfo) (int, error) { return 0, nil }))
		os.WriteFile(filepath.Join(dir, FileName), good, 0o600)
		if lr, err := s.Load(); err != nil || lr.Problem != "" || len(lr.File.Runs) != 1 {
			t.Errorf("%+v %v", lr, err)
		}
	})
	t.Run("not a regular file", func(t *testing.T) {
		s, dir := newStore(t)
		os.Mkdir(filepath.Join(dir, FileName), 0o700)
		if lr, err := s.Load(); err != nil || lr.Problem == "" {
			t.Errorf("%+v %v", lr, err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		s, dir := newStore(t)
		f, _ := os.Create(filepath.Join(dir, FileName))
		f.Truncate(MaxFileSize + 1)
		f.Close()
		os.Chmod(filepath.Join(dir, FileName), 0o600)
		if lr, err := s.Load(); err != nil || !strings.Contains(lr.Problem, "larger than the limit") {
			t.Errorf("%+v %v", lr, err)
		}
	})
	t.Run("directory is a symlink", func(t *testing.T) {
		real := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		os.Symlink(real, link)
		s, _ := Open(link)
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("load: %v", err)
		}
		if _, err := s.Append(run(0, 0)); err == nil {
			t.Error("append through a symlinked directory")
		}
	})
	t.Run("directory writable by others", func(t *testing.T) {
		s, dir := newStore(t)
		os.Chmod(dir, 0o777)
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Errorf("load: %v", err)
		}
		if _, err := s.Append(run(0, 0)); err == nil {
			t.Error("append into a writable directory")
		}
	})
	t.Run("directory of a foreign owner", func(t *testing.T) {
		s, _ := newStore(t, WithOwnerOf(func(fs.FileInfo) (int, error) { return os.Getuid() + 4242, nil }))
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Errorf("load: %v", err)
		}
	})
}

func TestOpenRejectsRelativeAndRootPaths(t *testing.T) {
	for _, d := range []string{"", "state", "./state", "/"} {
		if _, err := Open(d); err == nil {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestAWriteThatFailsLeavesThePreviousFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a read-only directory does not stop root")
	}
	s, dir := newStore(t)
	if _, err := s.Append(run(0, 1)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, FileName))
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if _, err := s.Append(run(1, 1)); err == nil {
		t.Fatal("append into a read-only directory")
	}
	os.Chmod(dir, 0o700)
	after, _ := os.ReadFile(filepath.Join(dir, FileName))
	if string(before) != string(after) {
		t.Error("the file changed")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("%d entries", len(entries))
	}
}

func TestFromReportCleansAndCaps(t *testing.T) {
	rep := diff.Report{}
	long := strings.Repeat("x", 500)
	for i := 0; i < MaxChangesPerRun+7; i++ {
		rep.Changes = append(rep.Changes, diff.Change{
			Kind: diff.SubjectNew, CheckID: "a.b", CheckKind: "k", Severity: result.High, From: result.Fail, To: result.Fail,
			Subject: "password=hunter2 " + long, Alert: true, HiddenNew: 2, OldTotal: 3, NewTotal: 4,
			FromSeverity: result.Low, ToSeverity: result.High,
		})
	}
	clean := func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
	r := FromReport(t0.Add(500*time.Millisecond), rep, clean)
	if len(r.Changes) != MaxChangesPerRun || r.Dropped != 7 || r.Baseline {
		t.Fatalf("%d changes, %d dropped", len(r.Changes), r.Dropped)
	}
	if !r.RunAt.Equal(t0) {
		t.Errorf("run_at %v", r.RunAt)
	}
	c := r.Changes[0]
	if strings.Contains(c.Subject, "hunter2") || !strings.Contains(c.Subject, "[REDACTED]") || len(c.Subject) != len("password=[REDACTED] ")+MaxStringRunes-len("password=[REDACTED] ")+3 {
		t.Errorf("subject %q", c.Subject)
	}
	if !c.Alert || c.HiddenNew != 2 || c.OldTotal != 3 || c.NewTotal != 4 || c.FromSeverity != "low" || c.ToSeverity != "high" || c.Kind != "subject_new" || c.From != "fail" {
		t.Errorf("change %+v", c)
	}
	base := FromReport(t0, diff.Report{Baseline: true}, nil)
	if !base.Baseline || base.Changes == nil || len(base.Changes) != 0 {
		t.Errorf("baseline run %+v", base)
	}
}

// The size limit is a bound, not a promise to keep 60 full runs: a run of 100
// changes whose strings are as long as they can be, in characters that JSON
// writes as six bytes, is about a megabyte. Append then drops the oldest runs
// until the file fits, and the newest run is always kept.
func TestTheSizeLimitDropsTheOldestRunsFirst(t *testing.T) {
	long := strings.Repeat("<", MaxStringRunes) // six bytes each in JSON
	big := func(i int) Run {
		r := Run{RunAt: t0.Add(time.Duration(i) * time.Hour), Changes: []Change{}}
		for j := 0; j < MaxChangesPerRun; j++ {
			r.Changes = append(r.Changes, Change{Kind: long, CheckID: long, CheckKind: long, Severity: long, From: long, To: long, Subject: long,
				FromSeverity: long, ToSeverity: long, Alert: true})
		}
		return r
	}
	s, dir := newStore(t)
	const n = 10
	for i := 0; i < n; i++ {
		if _, err := s.Append(big(i)); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	lr, err := s.Load()
	if err != nil || lr.Problem != "" {
		t.Fatalf("the file is not readable: %+v %v", lr, err)
	}
	t.Logf("%d bytes for %d runs of the worst case (limit %d)", fi.Size(), len(lr.File.Runs), MaxFileSize)
	if fi.Size() > MaxFileSize || len(lr.File.Runs) >= n || len(lr.File.Runs) == 0 {
		t.Fatalf("file of %d bytes with %d runs", fi.Size(), len(lr.File.Runs))
	}
	if last := lr.File.Runs[len(lr.File.Runs)-1]; !last.RunAt.Equal(t0.Add((n - 1) * time.Hour)) {
		t.Errorf("the newest run was not kept: %v", last.RunAt)
	}
	if first := lr.File.Runs[0]; !first.RunAt.Equal(t0.Add(time.Duration(n-len(lr.File.Runs)) * time.Hour)) {
		t.Errorf("not the oldest runs were dropped: first kept %v of %d", first.RunAt, len(lr.File.Runs))
	}
}

// What a run costs in the ordinary case, to justify the limit: a change of a
// check with a long id and a long subject.
func TestAnOrdinaryFullHistoryIsFarBelowTheLimit(t *testing.T) {
	var runs []Run
	for i := 0; i < MaxRuns; i++ {
		r := Run{RunAt: t0.Add(time.Duration(i) * time.Hour), Changes: []Change{}}
		for j := 0; j < MaxChangesPerRun; j++ {
			r.Changes = append(r.Changes, Change{Kind: "subject_new", CheckID: "ssh.password_authentication", CheckKind: "sshd_effective", Severity: "high",
				From: "fail", To: "fail", Subject: strings.Repeat("a", 60), Alert: true})
		}
		runs = append(runs, r)
	}
	b, err := marshal(&File{SchemaVersion: SchemaVersion, Runs: runs})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d bytes for %d runs of %d ordinary changes", len(b), MaxRuns, MaxChangesPerRun)
	if len(b) > MaxFileSize/2 {
		t.Errorf("%d bytes", len(b))
	}
}

func TestARunThatAloneIsTooLargeIsAnError(t *testing.T) {
	s, _ := newStore(t)
	long := strings.Repeat(" ", 400)
	r := Run{RunAt: t0, Changes: []Change{}}
	for j := 0; j < 5000; j++ {
		r.Changes = append(r.Changes, Change{Kind: long, CheckID: long, Subject: long})
	}
	if _, err := s.Append(r); err == nil || !strings.Contains(err.Error(), "larger than the limit") {
		t.Errorf("error %v", err)
	}
}
