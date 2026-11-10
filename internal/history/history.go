// Package history keeps a bounded record of what changed between the runs of
// keepwatch, for the weekly report.
//
// The record is one JSON file, history.json, next to the state file in the
// state directory. It holds the last MaxRuns runs, and per run the changes
// the comparison found (the cleaned, redacted text the report showed, never
// evidence detail), at most MaxChangesPerRun of them; the number that did not
// fit is kept. A run is added when the state moves forward, so a change that
// could not be delivered is recorded once, by the run that finally delivered
// it, and not once per attempt.
//
// The file gets the rules of the state file (see the state package): the
// directory must be a real directory owned by root or the running user and
// not writable by others, the file is opened without following links and
// must be a regular file of the right owner and mode and at most MaxFileSize
// bytes, and a write goes to a temporary file that is renamed over the old
// one. The history is a convenience, not a source of truth: a file that is
// not usable is reported as a problem and replaced by the next write, it never
// stops a run.
package history

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/diff"
)

// FileName is the name of the history file inside the state directory.
const FileName = "history.json"

// SchemaVersion is the version of the file format.
const SchemaVersion = 1

// Limits.
const (
	// MaxRuns is how many runs are kept.
	MaxRuns = 60
	// MaxChangesPerRun is how many changes of a run are kept.
	MaxChangesPerRun = 100
	// MaxFileSize bounds the file that is read and written. An ordinary
	// change costs about 290 bytes in the indented file, so 60 full runs are
	// about 1.7 MB. Strings are cut at MaxStringRunes, but a hostile one in
	// characters that JSON writes as six bytes makes a change cost 10 KB: when
	// the file would pass this limit Append drops the oldest runs (tests
	// build both cases).
	MaxFileSize = 8 << 20
	// MaxStringRunes cuts every string of a change.
	MaxStringRunes = 200
)

// Change is one change of a run, as the report showed it.
type Change struct {
	Kind         string `json:"kind"`
	CheckID      string `json:"check_id"`
	CheckKind    string `json:"check_kind"`
	Severity     string `json:"severity"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	Subject      string `json:"subject,omitempty"`
	OldTotal     int    `json:"old_total,omitempty"`
	NewTotal     int    `json:"new_total,omitempty"`
	HiddenNew    int    `json:"hidden_new,omitempty"`
	HiddenGone   int    `json:"hidden_gone,omitempty"`
	FromSeverity string `json:"from_severity,omitempty"`
	ToSeverity   string `json:"to_severity,omitempty"`
	Alert        bool   `json:"alert"`
}

// Run is one run of `check` that moved the state forward.
type Run struct {
	RunAt time.Time `json:"run_at"`
	// Baseline is true for a run without a previous state to compare with:
	// it recorded no changes.
	Baseline bool     `json:"baseline,omitempty"`
	Changes  []Change `json:"changes"`
	// Dropped is the number of changes that were not kept.
	Dropped int `json:"dropped,omitempty"`
}

// File is the content of the history file.
type File struct {
	SchemaVersion int   `json:"schema_version"`
	Runs          []Run `json:"runs"`
}

// FromReport builds the record of a run from the comparison. clean turns an
// untrusted string into text that may be stored (the redactor's Clean); a nil
// clean stores strings unchanged. Every string is cut at MaxStringRunes.
func FromReport(at time.Time, rep diff.Report, clean func(string) string) Run {
	if clean == nil {
		clean = func(s string) string { return s }
	}
	c := func(s string) string { return cut(clean(s), MaxStringRunes) }
	r := Run{RunAt: at.UTC().Truncate(time.Second), Baseline: rep.Baseline, Changes: []Change{}}
	for i, ch := range rep.Changes {
		if i == MaxChangesPerRun {
			r.Dropped = len(rep.Changes) - MaxChangesPerRun
			break
		}
		r.Changes = append(r.Changes, Change{
			Kind: c(string(ch.Kind)), CheckID: c(ch.CheckID), CheckKind: c(ch.CheckKind), Severity: c(string(ch.Severity)),
			From: c(string(ch.From)), To: c(string(ch.To)), Subject: c(ch.Subject),
			OldTotal: ch.OldTotal, NewTotal: ch.NewTotal, HiddenNew: ch.HiddenNew, HiddenGone: ch.HiddenGone,
			FromSeverity: c(string(ch.FromSeverity)), ToSeverity: c(string(ch.ToSeverity)), Alert: ch.Alert,
		})
	}
	return r
}

func cut(s string, runes int) string {
	if utf8.RuneCountInString(s) <= runes {
		return s
	}
	return string([]rune(s)[:runes]) + "..."
}

// Since returns the runs at or after t, oldest first.
func (f *File) Since(t time.Time) []Run {
	var out []Run
	for _, r := range f.Runs {
		if !r.RunAt.Before(t) {
			out = append(out, r)
		}
	}
	return out
}

// Store reads and writes the history file in one state directory.
type Store struct {
	dir     string
	ownerOf func(fs.FileInfo) (int, error)
	getuid  func() int
	// dirChecked runs after the directory was examined and before it is
	// opened; tests swap the directory there.
	dirChecked func()
}

// Option customises a Store; production callers use none.
type Option func(*Store)

// WithOwnerOf replaces the owner lookup (tests simulate foreign owners).
func WithOwnerOf(fn func(fs.FileInfo) (int, error)) Option { return func(s *Store) { s.ownerOf = fn } }

// Open returns a Store for dir, which must be an absolute path other than /.
// Nothing on disk is touched.
func Open(dir string, opts ...Option) (*Store, error) {
	c := filepath.Clean(dir)
	if !filepath.IsAbs(c) || c == string(filepath.Separator) {
		return nil, fmt.Errorf("state_dir %q: must be an absolute path other than /", dir)
	}
	s := &Store{dir: c, ownerOf: defaultOwnerOf, getuid: os.Getuid, dirChecked: func() {}}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Path returns the path of the history file.
func (s *Store) Path() string { return filepath.Join(s.dir, FileName) }

func defaultOwnerOf(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine the owner of %s", fi.Name())
	}
	return int(st.Uid), nil
}

func (s *Store) trusted(uid int) bool { return uid == 0 || uid == s.getuid() }

func (s *Store) checkDirInfo(fi fs.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: must be a real directory, it is a symlink", s.dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: must be a directory", s.dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes", s.dir, fi.Mode().Perm())
	}
	uid, err := s.ownerOf(fi)
	if err != nil {
		return err
	}
	if !s.trusted(uid) {
		return fmt.Errorf("%s: owned by uid %d", s.dir, uid)
	}
	return nil
}

// openDir checks the directory and opens it as an os.Root, which every file
// operation goes through; the opened directory must be the one that was
// checked.
func (s *Store) openDir() (*os.Root, error) {
	fi, err := os.Lstat(s.dir)
	if err != nil {
		return nil, err
	}
	if err := s.checkDirInfo(fi); err != nil {
		return nil, err
	}
	s.dirChecked()
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, err
	}
	rfi, err := root.Lstat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	if !os.SameFile(fi, rfi) {
		root.Close()
		return nil, fmt.Errorf("%s: changed while it was being opened", s.dir)
	}
	if err := s.checkDirInfo(rfi); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// LoadResult is the outcome of reading the history.
type LoadResult struct {
	// File is the history; empty (but valid) when there is none or it was
	// not usable.
	File File
	// Missing is true when there is no history file.
	Missing bool
	// Problem says why an existing file was not used; empty otherwise.
	Problem string
}

// Load reads the history. A file that cannot be used yields a Problem and an
// empty history. The error is non-nil only when the directory cannot be
// trusted; then nothing was read.
func (s *Store) Load() (LoadResult, error) {
	empty := File{SchemaVersion: SchemaVersion, Runs: []Run{}}
	root, err := s.openDir()
	if errors.Is(err, fs.ErrNotExist) {
		return LoadResult{File: empty, Missing: true}, nil
	}
	if err != nil {
		return LoadResult{File: empty}, err
	}
	defer root.Close()
	problem := func(format string, a ...any) (LoadResult, error) {
		return LoadResult{File: empty, Problem: fmt.Sprintf(format, a...)}, nil
	}
	li, err := root.Lstat(FileName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return LoadResult{File: empty, Missing: true}, nil
	case err != nil:
		return problem("cannot stat %s: %v", s.Path(), err)
	case li.Mode()&os.ModeSymlink != 0:
		return problem("%s is a symlink, it is not followed", s.Path())
	}
	f, err := root.OpenFile(FileName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return problem("cannot open %s: %v", s.Path(), err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return problem("cannot stat %s: %v", s.Path(), err)
	}
	switch {
	case !os.SameFile(li, fi):
		return problem("%s changed while it was being opened", s.Path())
	case !fi.Mode().IsRegular():
		return problem("%s is not a regular file (%s)", s.Path(), fi.Mode().Type())
	case fi.Size() > MaxFileSize:
		return problem("%s is %d bytes, larger than the limit %d", s.Path(), fi.Size(), MaxFileSize)
	case fi.Mode().Perm()&0o022 != 0:
		return problem("%s has permissions 0%03o that allow group or other writes", s.Path(), fi.Mode().Perm())
	}
	uid, err := s.ownerOf(fi)
	if err != nil {
		return problem("cannot tell who owns %s: %v", s.Path(), err)
	}
	if !s.trusted(uid) {
		return problem("%s is owned by uid %d", s.Path(), uid)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return problem("cannot read %s: %v", s.Path(), err)
	}
	if len(b) > MaxFileSize {
		return problem("%s is larger than the limit %d", s.Path(), MaxFileSize)
	}
	file, err := parse(b)
	if err != nil {
		return problem("%s: %v", s.Path(), err)
	}
	return LoadResult{File: *file}, nil
}

func parse(b []byte) (*File, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("not a valid history file: %v", err)
	}
	if dec.More() {
		return nil, errors.New("not a valid history file: data after the document")
	}
	if f.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("schema version %d, this keepwatch reads version %d only", f.SchemaVersion, SchemaVersion)
	}
	if len(f.Runs) > MaxRuns {
		return nil, fmt.Errorf("%d runs, at most %d are accepted", len(f.Runs), MaxRuns)
	}
	for i, r := range f.Runs {
		if r.RunAt.IsZero() {
			return nil, fmt.Errorf("runs[%d]: no time", i)
		}
		if len(r.Changes) > MaxChangesPerRun || r.Dropped < 0 {
			return nil, fmt.Errorf("runs[%d]: invalid number of changes", i)
		}
		for j, c := range r.Changes {
			for _, s := range []string{c.Kind, c.CheckID, c.CheckKind, c.Severity, c.From, c.To, c.Subject, c.FromSeverity, c.ToSeverity} {
				if len(s) > 4*(MaxStringRunes+3) {
					return nil, fmt.Errorf("runs[%d].changes[%d]: a string is too long", i, j)
				}
			}
		}
	}
	if f.Runs == nil {
		f.Runs = []Run{}
	}
	return &f, nil
}

// Append adds run to the history and writes it. The history is trimmed to
// MaxRuns, and further (oldest first) until the file fits MaxFileSize. A
// history that cannot be used is replaced; the problem is returned so the
// caller can say so. err is a failure to write (the previous file is then
// untouched) or a directory that cannot be trusted.
func (s *Store) Append(run Run) (problem string, err error) {
	lr, err := s.Load()
	if err != nil {
		return "", err
	}
	f := lr.File
	f.SchemaVersion = SchemaVersion
	f.Runs = append(f.Runs, run)
	if len(f.Runs) > MaxRuns {
		f.Runs = f.Runs[len(f.Runs)-MaxRuns:]
	}
	b, err := marshal(&f)
	for err == nil && len(b) > MaxFileSize && len(f.Runs) > 1 {
		f.Runs = f.Runs[1:]
		b, err = marshal(&f)
	}
	if err != nil {
		return lr.Problem, err
	}
	if len(b) > MaxFileSize {
		return lr.Problem, fmt.Errorf("a single run is %d bytes, larger than the limit %d", len(b), MaxFileSize)
	}
	return lr.Problem, s.write(b)
}

func marshal(f *File) ([]byte, error) {
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// write replaces the history file atomically.
func (s *Store) write(b []byte) (err error) {
	root, err := s.openDir()
	if err != nil {
		return err
	}
	defer root.Close()
	var rnd [8]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".history.json.tmp-" + hex.EncodeToString(rnd[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		_ = root.Remove(tmp)
	}()
	n, err := f.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = root.Rename(tmp, FileName); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
