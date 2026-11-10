package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// OwnerOf reports the uid that owns the file described by fi. The default
// reads it from the Stat_t of fi; tests replace it (WithOwnerOf) to simulate
// foreign owners without privileges.
type OwnerOf func(fi fs.FileInfo) (int, error)

func defaultOwnerOf(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine the owner of %s", fi.Name())
	}
	return int(st.Uid), nil
}

// Option customises a Store; production callers use none.
type Option func(*Store)

// WithOwnerOf replaces the owner lookup.
func WithOwnerOf(fn OwnerOf) Option { return func(s *Store) { s.ownerOf = fn } }

// hooks are the steps of a write that tests make fail.
type hooks struct {
	write   func(f *os.File, b []byte) (int, error)
	sync    func(f *os.File) error
	rename  func(r *os.Root, oldname, newname string) error
	syncDir func(d *os.File) error
	// dirChecked runs after the state directory was examined and before it
	// is opened; tests swap the directory there.
	dirChecked func()
	// beforeOpen runs after the state file was looked at and before it is
	// opened; tests swap the file there.
	beforeOpen func()
	// afterStat runs after the size of the state file was checked and before
	// it is read; tests grow the file there.
	afterStat func()
	// closeFile closes the temporary file.
	closeFile func(f *os.File) error
	// tempName returns the name of the temporary file.
	tempName func() (string, error)
}

// Store reads and writes the state file in one state directory.
type Store struct {
	dir     string
	ownerOf OwnerOf
	hooks   hooks
}

// Open returns a Store for dir. The path is cleaned with filepath.Clean and
// must be absolute after cleaning (and not the root directory); nothing on
// disk is touched yet.
func Open(dir string, opts ...Option) (*Store, error) {
	c := filepath.Clean(dir)
	if !filepath.IsAbs(c) || c == string(filepath.Separator) {
		return nil, fmt.Errorf("state_dir %q: must be an absolute path other than /", dir)
	}
	s := &Store{dir: c, ownerOf: defaultOwnerOf}
	for _, o := range opts {
		o(s)
	}
	s.hooks = hooks{
		write:   func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		sync:    func(f *os.File) error { return f.Sync() },
		rename:  func(r *os.Root, o, n string) error { return r.Rename(o, n) },
		syncDir: func(d *os.File) error { return d.Sync() },

		dirChecked: func() {},
		beforeOpen: func() {},
		afterStat:  func() {},
		closeFile:  func(f *os.File) error { return f.Close() },
		tempName:   tempName,
	}
	return s, nil
}

// Dir returns the cleaned state directory.
func (s *Store) Dir() string { return s.dir }

// Path returns the path of the state file.
func (s *Store) Path() string { return filepath.Join(s.dir, FileName) }

// trustedOwner reports whether uid may own the state directory and file: root
// or the user keepwatch runs as.
func trustedOwner(uid int) bool { return uid == 0 || uid == os.Getuid() }

// checkDirInfo applies the directory rules to fi.
func (s *Store) checkDirInfo(fi fs.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: must be a real directory, it is a symlink", s.dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: must be a directory", s.dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes, want 0755 or stricter", s.dir, fi.Mode().Perm())
	}
	uid, err := s.ownerOf(fi)
	if err != nil {
		return err
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s: owned by uid %d, want uid 0 or %d", s.dir, uid, os.Getuid())
	}
	return nil
}

// openDir checks the state directory and opens it as an os.Root, which every
// later file operation goes through. With create the directory is made (mode
// 0700) when absent; without it an absent directory is fs.ErrNotExist.
//
// The check is made on the path (Lstat, so a symlink is seen) and the opened
// directory must be the very directory that was checked, so a swap between
// the two is caught. Ancestors above state_dir are not examined: like the
// configuration directories, they must be root-owned (known limit).
func (s *Store) openDir(create bool) (*os.Root, error) {
	fi, err := os.Lstat(s.dir)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err = os.MkdirAll(s.dir, 0o700); err != nil {
			return nil, err
		}
		fi, err = os.Lstat(s.dir)
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkDirInfo(fi); err != nil {
		return nil, err
	}
	s.hooks.dirChecked()
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

// LoadResult is the outcome of reading the previous state.
type LoadResult struct {
	// State is the previous state, nil unless the file was usable.
	State *State
	// Missing is true when there is no state file (a first run).
	Missing bool
	// Problem says why an existing state file was not used; empty otherwise.
	Problem string
}

// Load reads the previous state. A missing file or directory is Missing. A
// file that exists but cannot be used (a symlink, foreign-owned or writable
// by others, too large, truncated, invalid, of another schema version) yields
// a Problem and no State: the caller reports it and runs as a new baseline.
// The error is non-nil only when the state directory itself cannot be
// trusted (a symlink, foreign-owned, writable by others, not a directory);
// then nothing was read.
func (s *Store) Load() (LoadResult, error) {
	root, err := s.openDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return LoadResult{Missing: true}, nil
	}
	if err != nil {
		return LoadResult{}, err
	}
	defer root.Close()

	// Look at the path first so that a symlink is named as such (root.OpenFile
	// would report an escaping link as a path error), and remember what is
	// there: os.Root follows a link whose target stays inside the directory
	// even when O_NOFOLLOW is set, so a file that was swapped in after this
	// look is caught by comparing the opened file with this one.
	li, err := root.Lstat(FileName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return LoadResult{Missing: true}, nil
	case err != nil:
		return LoadResult{Problem: fmt.Sprintf("cannot stat %s: %v", s.Path(), err)}, nil
	case li.Mode()&os.ModeSymlink != 0:
		return LoadResult{Problem: s.Path() + " is a symlink, it is not followed"}, nil
	}
	s.hooks.beforeOpen()
	f, err := root.OpenFile(FileName, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return LoadResult{Problem: s.Path() + " disappeared while it was being opened"}, nil
	case errors.Is(err, syscall.ELOOP):
		return LoadResult{Problem: s.Path() + " is a symlink, it is not followed"}, nil
	case err != nil:
		return LoadResult{Problem: fmt.Sprintf("cannot open %s: %v", s.Path(), err)}, nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return LoadResult{Problem: fmt.Sprintf("cannot stat %s: %v", s.Path(), err)}, nil
	}
	switch {
	case !os.SameFile(li, fi):
		return LoadResult{Problem: s.Path() + " changed while it was being opened"}, nil
	case !fi.Mode().IsRegular():
		return LoadResult{Problem: fmt.Sprintf("%s is not a regular file (%s)", s.Path(), fi.Mode().Type())}, nil
	case fi.Size() > MaxFileSize:
		return LoadResult{Problem: fmt.Sprintf("%s is %d bytes, larger than the limit %d", s.Path(), fi.Size(), MaxFileSize)}, nil
	case fi.Mode().Perm()&0o022 != 0:
		return LoadResult{Problem: fmt.Sprintf("%s has permissions 0%03o that allow group or other writes", s.Path(), fi.Mode().Perm())}, nil
	}
	uid, err := s.ownerOf(fi)
	if err != nil {
		return LoadResult{Problem: fmt.Sprintf("cannot tell who owns %s: %v", s.Path(), err)}, nil
	}
	if !trustedOwner(uid) {
		return LoadResult{Problem: fmt.Sprintf("%s is owned by uid %d, want uid 0 or %d", s.Path(), uid, os.Getuid())}, nil
	}
	s.hooks.afterStat()
	b, err := readCapped(f, MaxFileSize)
	if err != nil {
		return LoadResult{Problem: fmt.Sprintf("cannot read %s: %v", s.Path(), err)}, nil
	}
	st, err := parse(b)
	if err != nil {
		return LoadResult{Problem: s.Path() + ": " + err.Error()}, nil
	}
	return LoadResult{State: st}, nil
}

// Save writes st as the state file, atomically: a temporary file in the same
// directory (mode 0600, created exclusively without following links) is
// written and flushed, renamed over the state file, and the directory is
// flushed. Whatever fails, the previous state file stays as it was and the
// temporary file is removed. The state directory is created (0700) if absent.
func (s *Store) Save(st *State) (err error) {
	b, err := Marshal(st)
	if err != nil {
		return err
	}
	if len(b) > MaxFileSize {
		return fmt.Errorf("the state is %d bytes, larger than the limit %d", len(b), MaxFileSize)
	}
	root, err := s.openDir(true)
	if err != nil {
		return err
	}
	defer root.Close()

	tmpName, err := s.hooks.tempName()
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	// After a successful rename the temporary name no longer exists and the
	// removal is a no-op; after any failure it removes the leftover.
	defer func() {
		f.Close()
		_ = root.Remove(tmpName)
	}()
	n, werr := s.hooks.write(f, b)
	if werr != nil {
		return werr
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if err = s.hooks.sync(f); err != nil {
		return err
	}
	if err = s.hooks.closeFile(f); err != nil {
		return err
	}
	if err = s.hooks.rename(root, tmpName, FileName); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return s.hooks.syncDir(d)
}

// readCapped reads at most max bytes from r. It takes max+1 so that a reader
// that delivers more is reported, not silently cut: a file that grows between
// the size check and the read cannot make the read unbounded.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than the limit %d", max)
	}
	return b, nil
}

// tempPrefix starts the name of the temporary file; a leftover one (after a
// crash) is harmless and never read.
const tempPrefix = ".state.json.tmp-"

func tempName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return tempPrefix + hex.EncodeToString(b[:]), nil
}
