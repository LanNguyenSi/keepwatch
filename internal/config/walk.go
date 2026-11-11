package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// dirErrKind says why a directory of the path walk was refused.
type dirErrKind int

const (
	dirLookup  dirErrKind = iota // the component cannot be looked at (missing, not searchable)
	dirSymlink                   // the component is a symbolic link
	dirNotDir                    // the component is not a directory
	dirPerm                      // group or other can write the component
	dirOwner                     // the component has an owner nobody trusts
	dirSwapped                   // the component changed while it was being opened
)

// dirError is a refusal of openCheckedDir. It names the directory that
// was asked for and the component of its path that failed, which is the
// directory itself or one of its ancestors.
type dirError struct {
	dir  string // the directory openCheckedDir was asked for
	comp string // the component that failed
	kind dirErrKind
	msg  string // the reason, without any path
	err  error  // the cause of a dirLookup, for errors.Is
}

func (e *dirError) final() bool { return e.comp == e.dir }

func (e *dirError) Error() string {
	if e.final() {
		return e.dir + ": " + e.msg
	}
	return e.dir + ": ancestor " + e.comp + ": " + e.msg
}

func (e *dirError) Unwrap() error { return e.err }

// namedInfo reports name from Name() instead of whatever the file system
// answered, so that an injected OwnerOf sees the same name for the
// directory that a Lstat on its parent would show.
type namedInfo struct {
	fs.FileInfo
	name string
}

func (n namedInfo) Name() string { return n.name }

// openCheckedDir opens dir for the loader and checks every component of
// its path on the way, from "/" down, and returns a handle on the
// directory itself. Every component must be a real directory (never a
// symbolic link), owned by root or the running user, and not writable by
// group or other. The directory itself must satisfy this strictly; an
// ancestor with the sticky bit set (such as /tmp) is also accepted
// although group or other can write it, because they cannot rename or
// remove an entry they do not own, and the next component is checked to
// be owned by root or the running user.
//
// Each step is an openat on the descriptor of the parent that was just
// checked, and the descriptor of the child is compared with what the
// Lstat on the parent showed, so a component swapped between the look and
// the open is reported instead of followed. Callers open the files they
// read relative to the returned handle, never by path again. With create
// set, missing components are created with mode 0750 and then checked
// like the others (keepwatch init).
//
// A relative dir is made absolute with the physical working directory
// first. The caller closes the handle.
//
// Known limit: POSIX ACLs and file capabilities are not examined, nor is
// the mount (a writable bind mount over a checked directory).
func openCheckedDir(dir string, of OwnerOf, create bool) (*os.Root, error) {
	abs := dir
	if !filepath.IsAbs(abs) {
		wd, err := syscall.Getwd()
		if err != nil {
			return nil, &dirError{dir: dir, comp: dir, kind: dirLookup, msg: "cannot resolve the working directory: " + err.Error(), err: err}
		}
		abs = filepath.Join(wd, abs)
	}
	abs = filepath.Clean(abs)

	cur, err := os.OpenRoot("/")
	if err != nil {
		return nil, &dirError{dir: dir, comp: "/", kind: dirLookup, msg: lookupReason(err), err: err}
	}
	fail := func(e *dirError) (*os.Root, error) {
		cur.Close()
		return nil, e
	}
	rootInfo, err := cur.Stat(".")
	if err != nil {
		return fail(&dirError{dir: dir, comp: "/", kind: dirLookup, msg: lookupReason(err), err: err})
	}
	if e := checkDirInfo(namedInfo{rootInfo, "/"}, of, abs != "/"); e != nil {
		e.dir, e.comp = dir, "/"
		return fail(e)
	}
	if abs == "/" {
		return cur, nil
	}
	comp := ""
	for _, name := range strings.Split(abs[1:], "/") {
		comp += "/" + name
		next, e := descend(cur, name, comp, create, of, comp != abs)
		if e != nil {
			e.dir = dir
			return fail(e)
		}
		cur.Close()
		cur = next
	}
	return cur, nil
}

// afterLstat, when set, runs after a component has been looked at and
// before it is opened, with the absolute path of the component. Tests
// use it to swap the component in that window; it is nil in production.
var afterLstat func(path string)

// descend opens the directory name below cur, which was checked before.
// comp is the absolute path of the result and ancestor says whether it is
// a directory on the way to the one asked for.
func descend(cur *os.Root, name, comp string, create bool, of OwnerOf, ancestor bool) (*os.Root, *dirError) {
	fail := func(kind dirErrKind, msg string, err error) *dirError {
		return &dirError{comp: comp, kind: kind, msg: msg, err: err}
	}
	li, err := cur.Lstat(name)
	created := false
	if err != nil && create && errors.Is(err, fs.ErrNotExist) {
		if merr := cur.Mkdir(name, 0o750); merr != nil {
			return nil, fail(dirLookup, "cannot create: "+lookupReason(merr), merr)
		}
		created = true
		li, err = cur.Lstat(name)
	}
	if err != nil {
		return nil, fail(dirLookup, lookupReason(err), rootCause(err))
	}
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		if ancestor {
			return nil, fail(dirSymlink, "is a symlink, whoever can change it can redirect the path", nil)
		}
		return nil, fail(dirSymlink, "must not be a symlink", nil)
	case !li.IsDir():
		if ancestor {
			return nil, fail(dirNotDir, "is not a directory", nil)
		}
		return nil, fail(dirNotDir, "must be a directory", nil)
	}
	if afterLstat != nil {
		afterLstat(comp)
	}
	next, err := cur.OpenRoot(name)
	if err != nil {
		return nil, fail(dirLookup, "open: "+lookupReason(err), rootCause(err))
	}
	ni, err := next.Stat(".")
	if err != nil {
		next.Close()
		return nil, fail(dirLookup, lookupReason(err), rootCause(err))
	}
	if !os.SameFile(li, ni) {
		next.Close()
		return nil, fail(dirSwapped, "changed while it was being opened", nil)
	}
	if created {
		// The mode of a new directory is 0750 whatever the umask says. The
		// descriptor is the one that was just compared, so the chmod cannot
		// land on something else.
		d, oerr := next.Open(".")
		if oerr == nil {
			oerr = d.Chmod(0o750)
			d.Close()
		}
		if oerr != nil {
			next.Close()
			return nil, fail(dirLookup, "cannot set the mode: "+lookupReason(oerr), rootCause(oerr))
		}
		if ni, err = next.Stat("."); err != nil {
			next.Close()
			return nil, fail(dirLookup, lookupReason(err), rootCause(err))
		}
	}
	if e := checkDirInfo(namedInfo{ni, name}, of, ancestor); e != nil {
		next.Close()
		e.comp = comp
		return nil, e
	}
	return next, nil
}

// checkDirInfo applies the owner and permission rule of the loader to one
// directory, as the open descriptor reports it. A sticky directory may be
// writable by group or other when it is an ancestor.
func checkDirInfo(fi fs.FileInfo, of OwnerOf, ancestor bool) *dirError {
	perm := fi.Mode().Perm()
	if perm&0o022 != 0 && !(ancestor && fi.Mode()&os.ModeSticky != 0) {
		return &dirError{kind: dirPerm, msg: fmt.Sprintf("permissions 0%03o allow group or other writes", perm)}
	}
	uid, err := of(fi)
	if err != nil {
		return &dirError{kind: dirOwner, msg: err.Error()}
	}
	if uid != 0 && uid != os.Getuid() {
		return &dirError{kind: dirOwner, msg: fmt.Sprintf("owned by uid %d, want uid 0 or %d", uid, os.Getuid())}
	}
	return nil
}

// rootCause is the syscall error below a *fs.PathError.
func rootCause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// lookupReason is the reason of a failed file system call without the
// operation and the path.
func lookupReason(err error) string { return rootCause(err).Error() }
