// Package securefile holds the trust checks and the atomic write dance for the
// files keepwatch keeps in its state directory (incidents, audit log, cursor,
// baseline, requests, lock), so that they exist once for new code.
//
// The rules follow the state package, which stays as it is: the directory must
// be a real directory (not a symlink), owned by uid 0 or the running user and
// not writable by group or other; every file is opened relative to an os.Root
// of that directory, without following links, must be a regular file with the
// same owner rule and no group/other write bit, and is read or written within
// a size cap. Permissions are mode bits and owner only (known limit).
package securefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

var (
	// ErrInvalidName is returned for a name that is not a single plain path
	// component.
	ErrInvalidName = errors.New("invalid file name")
	// ErrTooLarge is returned when data or a file exceeds the size cap.
	ErrTooLarge = errors.New("larger than the size limit")
	// ErrUntrusted is returned when a directory or file fails a trust check
	// (symlink, wrong type, foreign owner, group/other writable, swapped).
	ErrUntrusted = errors.New("not trusted")
)

// OwnerOf reports the uid that owns the file described by fi. Tests inject one
// to simulate foreign owners without privileges.
type OwnerOf func(fi fs.FileInfo) (int, error)

// DefaultOwnerOf reads the owner from the Stat_t of fi.
func DefaultOwnerOf(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine the owner of %s", fi.Name())
	}
	return int(st.Uid), nil
}

// getuid is the user keepwatch runs as; tests replace it.
var getuid = os.Getuid

func trustedOwner(uid int) bool { return uid == 0 || uid == getuid() }

func wantOwner() string {
	if u := getuid(); u != 0 {
		return fmt.Sprintf("uid 0 or %d", u)
	}
	return "uid 0"
}

// tempPrefix starts every temporary name. A valid name never starts with a
// dot, so a temporary name cannot be the name of a real file.
const tempPrefix = ".kwtmp-"

// hooks are the steps of a write that tests make fail or interleave.
type hooks struct {
	write      func(f *os.File, b []byte) (int, error)
	sync       func(f *os.File) error
	rename     func(r *os.Root, oldname, newname string) error
	syncDir    func(d *os.File) error
	dirChecked func()
	beforeOpen func()
	afterStat  func()
	tempName   func() (string, error)
}

func defaultHooks() hooks {
	return hooks{
		write:      func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		sync:       func(f *os.File) error { return f.Sync() },
		rename:     func(r *os.Root, o, n string) error { return r.Rename(o, n) },
		syncDir:    func(d *os.File) error { return d.Sync() },
		dirChecked: func() {},
		beforeOpen: func() {},
		afterStat:  func() {},
		tempName:   randomTempName,
	}
}

func randomTempName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return tempPrefix + hex.EncodeToString(b[:]), nil
}

// Dir is a trusted directory, opened as an os.Root.
type Dir struct {
	path    string
	root    *os.Root
	ownerOf OwnerOf
	hooks   hooks
}

// Close releases the directory.
func (d *Dir) Close() error { return d.root.Close() }

// Path returns the path the directory was opened with.
func (d *Dir) Path() string { return d.path }

func checkDirInfo(path string, fi fs.FileInfo, ownerOf OwnerOf) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: must be a real directory, it is a symlink: %w", path, ErrUntrusted)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: must be a directory: %w", path, ErrUntrusted)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes: %w", path, fi.Mode().Perm(), ErrUntrusted)
	}
	uid, err := ownerOf(fi)
	if err != nil {
		return err
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s: owned by uid %d, want %s: %w", path, uid, wantOwner(), ErrUntrusted)
	}
	return nil
}

// OpenDir checks path and opens it. With create the directory is made (mode
// 0700) when absent; without it an absent directory is fs.ErrNotExist. A nil
// ownerOf means DefaultOwnerOf.
//
// The check is made on the path (Lstat, so a symlink is seen) and the opened
// directory must be the very directory that was checked, so a swap between
// the two is caught. Ancestors of path are not examined (known limit).
func OpenDir(path string, create bool, ownerOf OwnerOf) (*Dir, error) {
	return openDir(path, create, ownerOf, defaultHooks())
}

func openDir(path string, create bool, ownerOf OwnerOf, h hooks) (*Dir, error) {
	if ownerOf == nil {
		ownerOf = DefaultOwnerOf
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err = os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		fi, err = os.Lstat(path)
	}
	if err != nil {
		return nil, err
	}
	if err := checkDirInfo(path, fi, ownerOf); err != nil {
		return nil, err
	}
	h.dirChecked()
	root, err := os.OpenRoot(path)
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
		return nil, fmt.Errorf("%s: changed while it was being opened: %w", path, ErrUntrusted)
	}
	if err := checkDirInfo(path, rfi, ownerOf); err != nil {
		root.Close()
		return nil, err
	}
	return &Dir{path: path, root: root, ownerOf: ownerOf, hooks: h}, nil
}

// validName accepts a single plain path component: not empty, no separator,
// no NUL, and no leading dot (which also rules out "." and ".." and keeps
// temporary names, which start with a dot, apart from real names).
func validName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty", ErrInvalidName)
	case strings.HasPrefix(name, "."):
		return fmt.Errorf("%w: %q starts with a dot", ErrInvalidName, name)
	case strings.ContainsAny(name, "/\\\x00"):
		return fmt.Errorf("%w: %q is not a single path component", ErrInvalidName, name)
	}
	return nil
}

func (d *Dir) filePath(name string) string { return d.path + string(os.PathSeparator) + name }

// checkFile applies the file rules to an opened file's info.
func (d *Dir) checkFile(name string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file (%s): %w", d.filePath(name), fi.Mode().Type(), ErrUntrusted)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s has permissions 0%03o that allow group or other writes: %w", d.filePath(name), fi.Mode().Perm(), ErrUntrusted)
	}
	uid, err := d.ownerOf(fi)
	if err != nil {
		return fmt.Errorf("cannot tell who owns %s: %w", d.filePath(name), err)
	}
	if !trustedOwner(uid) {
		return fmt.Errorf("%s is owned by uid %d, want %s: %w", d.filePath(name), uid, wantOwner(), ErrUntrusted)
	}
	return nil
}

// WriteAtomic replaces the file name with data: a temporary file in the same
// directory (mode 0600, created exclusively without following links) is
// written and flushed, renamed over name, and the directory is flushed.
// Whatever fails, the previous file stays as it was and the temporary file is
// removed. data above maxSize is refused before anything is written.
func (d *Dir) WriteAtomic(name string, data []byte, maxSize int64) (err error) {
	if err := validName(name); err != nil {
		return err
	}
	if int64(len(data)) > maxSize {
		return fmt.Errorf("%s: %d bytes, larger than the limit %d: %w", d.filePath(name), len(data), maxSize, ErrTooLarge)
	}
	tmp, err := d.hooks.tempName()
	if err != nil {
		return err
	}
	f, err := d.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	// After a successful rename the temporary name is gone and the removal is
	// a no-op; after any failure it removes the leftover.
	defer func() {
		f.Close()
		_ = d.root.Remove(tmp)
	}()
	n, werr := d.hooks.write(f, data)
	if werr != nil {
		return werr
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err = d.hooks.sync(f); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = d.hooks.rename(d.root, tmp, name); err != nil {
		return err
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return d.hooks.syncDir(dir)
}

// openChecked looks at name, opens it without following links and checks that
// the opened file is the one looked at, before and after the open.
func (d *Dir) openChecked(name string, flag int, perm os.FileMode) (f *os.File, fi fs.FileInfo, err error) {
	// Look at the path first so a symlink is named as such, and remember what
	// is there: os.Root follows a link whose target stays inside the directory
	// even with O_NOFOLLOW (so that flag alone is not relied on), so a file swapped in after this look is caught by
	// comparing the opened file with this one.
	li, lerr := d.root.Lstat(name)
	switch {
	case lerr == nil && li.Mode()&os.ModeSymlink != 0:
		return nil, nil, fmt.Errorf("%s is a symlink, it is not followed: %w", d.filePath(name), ErrUntrusted)
	case lerr != nil && !errors.Is(lerr, fs.ErrNotExist):
		return nil, nil, lerr
	}
	d.hooks.beforeOpen()
	f, err = d.root.OpenFile(name, flag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, perm)
	switch {
	case errors.Is(err, syscall.ELOOP):
		return nil, nil, fmt.Errorf("%s is a symlink, it is not followed: %w", d.filePath(name), ErrUntrusted)
	case err != nil:
		return nil, nil, err
	}
	fi, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if lerr == nil && !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened: %w", d.filePath(name), ErrUntrusted)
	}
	// The path must still name the opened file: this is what catches a link
	// planted after the first look when the file was absent then.
	if pi, perr := d.root.Lstat(name); perr != nil || !os.SameFile(pi, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("%s changed while it was being opened: %w", d.filePath(name), ErrUntrusted)
	}
	if err := d.checkFile(name, fi); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, fi, nil
}

// ReadCapped reads the file name. A missing file is an error for which
// errors.Is(err, fs.ErrNotExist) holds. The file must be a regular file with
// a trusted owner and no group/other write bit; a size above maxSize is
// refused before reading, and the read itself stops at maxSize+1 bytes so a
// file that grows meanwhile cannot make it unbounded.
func (d *Dir) ReadCapped(name string, maxSize int64) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	f, fi, err := d.openChecked(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi.Size() > maxSize {
		return nil, fmt.Errorf("%s is %d bytes, larger than the limit %d: %w", d.filePath(name), fi.Size(), maxSize, ErrTooLarge)
	}
	d.hooks.afterStat()
	b, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", d.filePath(name), err)
	}
	if int64(len(b)) > maxSize {
		return nil, fmt.Errorf("%s grew beyond the limit %d while being read: %w", d.filePath(name), maxSize, ErrTooLarge)
	}
	return b, nil
}

// OpenAppend opens name for appending (O_APPEND|O_CREATE, mode 0600, links
// not followed) and returns the file with its current size. An existing file
// gets the same owner and mode checks as in ReadCapped. A file already larger
// than maxSize is refused with ErrTooLarge, so the caller can rotate it. The
// caller closes the file.
func (d *Dir) OpenAppend(name string, maxSize int64) (*os.File, int64, error) {
	if err := validName(name); err != nil {
		return nil, 0, err
	}
	f, fi, err := d.openChecked(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, 0, err
	}
	if fi.Size() > maxSize {
		f.Close()
		return nil, 0, fmt.Errorf("%s is %d bytes, larger than the limit %d: %w", d.filePath(name), fi.Size(), maxSize, ErrTooLarge)
	}
	return f, fi.Size(), nil
}
