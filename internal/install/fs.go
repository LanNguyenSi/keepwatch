package install

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// Info is what install needs to know about a file system entry. It is
// returned by Lstat, so a symbolic link is described as a link.
type Info struct {
	Mode fs.FileMode
	UID  int
	Size int64
}

// IsDir reports whether the entry is a directory (not a link to one).
func (i Info) IsDir() bool { return i.Mode.IsDir() }

// IsRegular reports whether the entry is a regular file.
func (i Info) IsRegular() bool { return i.Mode.IsRegular() }

// IsSymlink reports whether the entry is a symbolic link.
func (i Info) IsSymlink() bool { return i.Mode&fs.ModeSymlink != 0 }

// FS is the file system access of install, uninstall and doctor. keepwatch
// writes here as root, so the interface offers no way to follow a link: every
// write and removal goes through a Dir, which is an opened and checked
// directory.
type FS interface {
	// Lstat describes path without following a link in its last component.
	Lstat(path string) (Info, error)
	// Mkdir creates one directory with exactly mode perm (the umask does not
	// apply). The parent must exist; an existing path is fs.ErrExist.
	Mkdir(path string, perm fs.FileMode) error
	// Rmdir removes an empty directory. It refuses a link.
	Rmdir(path string) error
	// OpenDir opens a directory for work in it. It refuses a symbolic link,
	// a path that is not a directory, a directory that group or other can
	// write to and one that neither root nor the running user owns.
	OpenDir(path string) (Dir, error)
}

// Dir is an opened directory. Names are plain file names, never paths.
type Dir interface {
	// Lstat describes the entry called name without following a link.
	Lstat(name string) (Info, error)
	// ReadFile reads the regular file called name, at most max bytes (more is
	// an error). A link, a non-regular file or a file swapped while it was
	// opened is an error.
	ReadFile(name string, max int64) ([]byte, error)
	// WriteFile replaces or creates the file called name atomically: a
	// temporary file in the same directory, created exclusively without
	// following links, is written, flushed, given mode perm and renamed over
	// the name, and the directory is flushed. Whatever fails, the previous
	// file stays and the temporary file is removed.
	WriteFile(name string, data []byte, perm fs.FileMode) error
	// Remove removes the entry called name (a link is removed, not followed).
	Remove(name string) error
	// Names lists the entries, sorted.
	Names() ([]string, error)
	// Close releases the directory.
	Close() error
}

// OSFS is the file system of the host.
type OSFS struct {
	// OwnerOK reports whether uid may own a directory install works in. Nil
	// means root or the running user.
	OwnerOK func(uid int) bool

	afterMkdir  func(path string) // tests swap the new directory here
	beforeChmod func(path string) // tests swap it between the look and the open
	afterLstat  func(path string) // tests change the directory between OpenDir's look and its open
	tempName    func() string     // tests fix the name of the temporary file
}

func infoOf(fi fs.FileInfo) Info {
	i := Info{Mode: fi.Mode(), Size: fi.Size(), UID: -1}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		i.UID = int(st.Uid)
	}
	return i
}

// Lstat implements FS.
func (OSFS) Lstat(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

// Mkdir implements FS. The directory is created through an os.Root of its
// parent and its mode is set with fchmod on a descriptor, not with a path-based
// chmod that would follow a link. os.Root follows a link whose target stays
// inside the parent even with O_NOFOLLOW, so the descriptor must be the very
// directory that was looked at: a name swapped for a link or another directory
// between the look and the open is refused.
func (o OSFS) Mkdir(path string, perm fs.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if err := root.Mkdir(name, perm); err != nil {
		return err
	}
	if o.afterMkdir != nil {
		o.afterMkdir(path)
	}
	li, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if infoOf(li).UID != os.Geteuid() {
		return fmt.Errorf("%s: is not the directory that was just created", path)
	}
	if o.beforeChmod != nil {
		o.beforeChmod(path)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: cannot be opened after it was created: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(li, fi) {
		return fmt.Errorf("%s: changed while it was being opened", path)
	}
	return f.Chmod(perm) // defeats the umask
}

// Rmdir implements FS.
func (OSFS) Rmdir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory (a link or file is never removed as a directory)", path)
	}
	return syscall.Rmdir(path)
}

func (o OSFS) ownerOK(uid int) bool {
	if o.OwnerOK != nil {
		return o.OwnerOK(uid)
	}
	return uid == 0 || uid == os.Getuid()
}

// CheckDir applies the directory rules of OpenDir to info: a real directory
// that group and other cannot write and that a trusted user owns. ownerOK
// decides which owners are trusted.
func CheckDir(path string, i Info, ownerOK func(int) bool) error {
	switch {
	case i.IsSymlink():
		return fmt.Errorf("%s: must be a real directory, it is a symlink", path)
	case !i.IsDir():
		return fmt.Errorf("%s: must be a directory", path)
	case i.Mode.Perm()&0o022 != 0:
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes", path, i.Mode.Perm())
	case !ownerOK(i.UID):
		return fmt.Errorf("%s: owned by uid %d, want uid 0 or the running user", path, i.UID)
	}
	return nil
}

// OpenDir implements FS. The directory is checked with Lstat, opened as an
// os.Root, and the opened directory must be the one that was checked.
// Ancestors of path are not examined (known limit): they must be root-owned.
func (o OSFS) OpenDir(path string) (Dir, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := CheckDir(path, infoOf(fi), o.ownerOK); err != nil {
		return nil, err
	}
	if o.afterLstat != nil {
		o.afterLstat(path)
	}
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
		return nil, fmt.Errorf("%s: changed while it was being opened", path)
	}
	if err := CheckDir(path, infoOf(rfi), o.ownerOK); err != nil {
		root.Close()
		return nil, err
	}
	return &osDir{path: path, root: root, tempName: o.tempName}, nil
}

type osDir struct {
	path string
	root *os.Root
	// beforeOpen runs after a file was looked at and before it is opened;
	// tests swap the file there.
	beforeOpen func()
	tempName   func() string
}

func (d *osDir) Close() error { return d.root.Close() }

func (d *osDir) Lstat(name string) (Info, error) {
	fi, err := d.root.Lstat(name)
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

func (d *osDir) ReadFile(name string, max int64) ([]byte, error) {
	li, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if li.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s/%s is a symlink, it is not followed", d.path, name)
	}
	if d.beforeOpen != nil {
		d.beforeOpen()
	}
	f, err := d.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s/%s is a symlink, it is not followed", d.path, name)
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !os.SameFile(li, fi):
		return nil, fmt.Errorf("%s/%s changed while it was being opened", d.path, name)
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%s/%s is not a regular file (%s)", d.path, name, fi.Mode().Type())
	case fi.Size() > max:
		return nil, fmt.Errorf("%s/%s is %d bytes, larger than the limit %d", d.path, name, fi.Size(), max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s/%s is larger than the limit %d", d.path, name, max)
	}
	return b, nil
}

func (d *osDir) WriteFile(name string, data []byte, perm fs.FileMode) (err error) {
	var rnd [8]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := tmpWritePrefix + hex.EncodeToString(rnd[:])
	if d.tempName != nil {
		tmp = d.tempName()
	}
	f, err := d.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		_ = d.root.Remove(tmp) // a no-op after a successful rename
	}()
	if n, werr := f.Write(data); werr != nil {
		return werr
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = d.root.Rename(tmp, name); err != nil {
		return err
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (d *osDir) Remove(name string) error { return d.root.Remove(name) }

func (d *osDir) Names() ([]string, error) {
	dir, err := d.root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}
