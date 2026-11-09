package probes

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrTooLarge is returned by FS.ReadFile when a file is larger than max.
var ErrTooLarge = errors.New("file too large")

// ErrUnsafe is wrapped by the errors of the readers below when a path was
// refused for what it is or where it lies: a symbolic link that leaves the
// directory it must stay in, a file of the wrong type or owner, a directory
// anybody else can write to. The message says which.
var ErrUnsafe = errors.New("unsafe path")

// FS is the read-only file access probes get. ReadFile returns the whole
// file, or ErrTooLarge when it holds more than max bytes. A missing file
// is reported as an error for which errors.Is(err, fs.ErrNotExist) holds.
//
// A file system may offer more than ReadFile. The optional interfaces below
// are what the kinds that need them look for; OSFS implements all of them and
// the kinds report an internal error when their file system does not.
type FS interface {
	ReadFile(path string, max int64) ([]byte, error)
}

// Globber is an FS that can expand an absolute glob pattern, sorted.
type Globber interface {
	Glob(pattern string) ([]string, error)
}

// ModTimer is an FS that can tell the modification time of a regular file.
type ModTimer interface {
	ModTime(path string) (time.Time, error)
}

// TrustedReader is an FS that can read a file the caller may not own, by
// following symbolic links, as long as nobody but the trusted owners can
// change anything on the way. It returns the content and the resolved path.
type TrustedReader interface {
	ReadTrusted(path string, max int64) ([]byte, string, error)
}

// OwnerReader is an FS that can tell which user owns a path (without following
// a symbolic link in its last component).
type OwnerReader interface {
	Owner(path string) (uint32, error)
}

// HomeReader is an FS that can read a file below a home directory without
// ever leaving it. The user owns the files and every directory below the home,
// so a path inside it cannot be trusted. rel is relative to home.
type HomeReader interface {
	ReadHomeFile(home string, uid uint32, rel string, max int64) ([]byte, error)
}

var errNoCapability = errors.New("internal error: the file system does not offer this operation")

func (e *Env) glob(pattern string) ([]string, error) {
	if g, ok := e.FS.(Globber); ok {
		return g.Glob(pattern)
	}
	return nil, errNoCapability
}

func (e *Env) modTime(path string) (time.Time, error) {
	if m, ok := e.FS.(ModTimer); ok {
		return m.ModTime(path)
	}
	return time.Time{}, errNoCapability
}

func (e *Env) owner(path string) (uint32, error) {
	if o, ok := e.FS.(OwnerReader); ok {
		return o.Owner(path)
	}
	return 0, errNoCapability
}

func (e *Env) readTrusted(path string, max int64) ([]byte, string, error) {
	if r, ok := e.FS.(TrustedReader); ok {
		return r.ReadTrusted(path, max)
	}
	return nil, "", errNoCapability
}

func (e *Env) readHome(home string, uid uint32, rel string, max int64) ([]byte, error) {
	if r, ok := e.FS.(HomeReader); ok {
		return r.ReadHomeFile(home, uid, rel, max)
	}
	return nil, errNoCapability
}

// OSFS reads regular files from the host, read-only. keepwatch runs as
// root and some files it reads sit in places other users can write to, so
// every reader refuses anything that is not a regular file and none of them
// opens a path before it has looked at what it is: the path is examined with
// lstat first, so a device node or a socket is never opened, and the open
// that follows is non-blocking (a FIFO that appears in between does not
// stall the run) and checked again on the open descriptor.
//
// ReadFile does not follow a symbolic link in the last component, but follows
// directories on the way, which keeps the standard paths working (on Ubuntu
// /var/run is a symbolic link to /run, and a path like
// /var/run/reboot-required is opened as such). A caller therefore passes a
// path whose directories are root-owned, and the file itself must not be a
// link.
//
// ReadTrusted, ReadHomeFile, Glob and ModTime are described at their methods.
type OSFS struct {
	// TrustedOwners are the user ids ReadTrusted accepts as owners of a file
	// and of every directory above it. Nil means root (0) only. Tests use it
	// to stand in for root.
	TrustedOwners []uint32
	// CheckFrom is the directory from which ReadTrusted starts checking the
	// directories on the way; the ones above it are not examined. Empty means
	// "/", every directory. Tests use it to keep a world-writable /tmp out of
	// the chain.
	CheckFrom string
}

// ReadFile implements FS.
func (OSFS) ReadFile(path string, max int64) ([]byte, error) {
	if fi, err := os.Lstat(path); err != nil {
		return nil, err
	} else if fi.Mode()&os.ModeSymlink == 0 && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	f, err := os.OpenFile(path, openFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return readCapped(f, max)
}

func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Glob returns the files that match the absolute pattern, sorted. A pattern
// that is not absolute or not well formed is an error; filepath.Glob ignores
// directories it cannot read, so an unreadable directory looks like no match.
func (OSFS) Glob(pattern string) ([]string, error) {
	if !filepath.IsAbs(pattern) {
		return nil, fmt.Errorf("glob pattern %q is not absolute", pattern)
	}
	return filepath.Glob(pattern)
}

// ModTime returns the modification time of a regular file. It does not open
// the file and does not follow a symbolic link.
func (OSFS) ModTime(path string) (time.Time, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return time.Time{}, err
	}
	if !fi.Mode().IsRegular() {
		return time.Time{}, fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, path)
	}
	return fi.ModTime(), nil
}

// Owner implements OwnerReader. It does not open the path.
func (OSFS) Owner(path string) (uint32, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	uid, ok := ownerUID(fi)
	if !ok {
		return 0, fmt.Errorf("%w: cannot tell who owns %s", ErrUnsafe, path)
	}
	return uid, nil
}

func (o OSFS) trusted(uid uint32) bool {
	owners := o.TrustedOwners
	if owners == nil {
		owners = []uint32{0}
	}
	for _, t := range owners {
		if t == uid {
			return true
		}
	}
	return false
}

// checkNode refuses a node that is not owned by a trusted owner or that group
// or others can write to. what is "file" or "directory" for the message.
func (o OSFS) checkNode(path string, fi os.FileInfo, what string) error {
	uid, ok := ownerUID(fi)
	if !ok {
		return fmt.Errorf("%w: cannot tell who owns %s %s", ErrUnsafe, what, path)
	}
	if !o.trusted(uid) {
		return fmt.Errorf("%w: %s %s is owned by uid %d", ErrUnsafe, what, path, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s %s is writable by group or others (mode %04o)", ErrUnsafe, what, path, fi.Mode().Perm())
	}
	return nil
}

// maxTrustedLinks bounds the symbolic links ReadTrusted follows; the kernel
// allows 40.
const maxTrustedLinks = 40

// ReadTrusted reads the file at path and returns its content and the path it
// resolved to. Symbolic links are followed (Let's Encrypt keeps its current
// certificate as a link into an archive directory), but only when nothing on
// the way can be changed by anyone but the trusted owners.
//
// The path is resolved here, one component at a time (Lstat, Readlink), not by
// the kernel and not by filepath.EvalSymlinks, because the directories that
// matter are all the directories the walk goes through, including the one that
// holds a link and the ones the links lead into. Every directory the walk
// enters, from CheckFrom down, must be owned by a trusted owner (root) and not
// writable by group or others; every link must be owned by a trusted owner;
// and the file at the end must be a regular file with the same property. Otherwise the
// owner of a directory on the way could repoint a link at any other file that
// the trusted directories hold, and the check would read that file instead
// of the one it was asked for. At most 40 links are followed. A violation is an
// error that wraps ErrUnsafe and names the offender; a path that does not exist
// is an error for which errors.Is(err, fs.ErrNotExist) holds.
//
// The file is then opened by its resolved path, without following a link
// (O_NOFOLLOW) and without blocking, and checked again on the descriptor: a
// regular file, trusted owner, not group- or world-writable. Because the
// directories can only be changed by the trusted owners, nobody else can swap
// the path for something else between the check and the open; a link that
// shows up anyway makes the open fail.
func (o OSFS) ReadTrusted(path string, max int64) ([]byte, string, error) {
	if !filepath.IsAbs(path) {
		return nil, "", fmt.Errorf("%w: %q is not absolute", ErrUnsafe, path)
	}
	resolved, err := o.resolveTrusted(path)
	if err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(resolved, openFlags, 0)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !fi.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, resolved)
	}
	if err := o.checkNode(resolved, fi, "file"); err != nil {
		return nil, "", err
	}
	b, err := readCapped(f, max)
	return b, resolved, err
}

// resolveTrusted walks the absolute path component by component and returns
// the path of the regular file it ends at, without a link in it.
func (o OSFS) resolveTrusted(path string) (string, error) {
	from := o.CheckFrom
	if from == "" {
		from = "/"
	}
	from = filepath.Clean(from)
	// above reports whether dir lies strictly above the point from which the
	// walk checks (tests start below a world-writable /tmp).
	above := func(dir string) bool {
		return dir != from && (dir == "/" || strings.HasPrefix(from, dir+"/"))
	}
	checked := map[string]bool{}
	enter := func(dir string) error {
		if checked[dir] || above(dir) {
			return nil
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrUnsafe, dir)
		}
		if err := o.checkNode(dir, fi, "directory"); err != nil {
			return err
		}
		checked[dir] = true
		return nil
	}
	pending := splitPathComponents(path)
	cur := "/"
	if err := enter(cur); err != nil {
		return "", err
	}
	links := 0
	for len(pending) > 0 {
		comp := pending[0]
		pending = pending[1:]
		switch comp {
		case ".":
			continue
		case "..":
			// cur never contains a link, so its lexical parent is its real parent
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", err
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			links++
			if links > maxTrustedLinks {
				return "", fmt.Errorf("%w: more than %d symbolic links on the way to %s", ErrUnsafe, maxTrustedLinks, path)
			}
			if !above(cur) {
				uid, ok := ownerUID(fi)
				if !ok || !o.trusted(uid) {
					return "", fmt.Errorf("%w: link %s is owned by uid %d", ErrUnsafe, next, uid)
				}
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			pending = append(splitPathComponents(target), pending...)
		case len(pending) == 0:
			if !fi.Mode().IsRegular() {
				return "", fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, next)
			}
			if err := o.checkNode(next, fi, "file"); err != nil {
				return "", err
			}
			return next, nil
		default:
			if !fi.IsDir() {
				return "", fmt.Errorf("%w: %s is not a directory", ErrUnsafe, next)
			}
			if err := enter(next); err != nil {
				return "", err
			}
			cur = next
		}
	}
	return "", fmt.Errorf("%w: %s does not end in a regular file", ErrUnsafe, path)
}

// splitPathComponents splits a path at "/" and drops the empty parts.
func splitPathComponents(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ReadHomeFile reads the file rel (a relative path) below the directory home
// without leaving home. The user owns the file and every directory below the
// home and can replace any of them with a symbolic link at any moment, so the
// path is resolved by the kernel inside a root opened on home (os.Root): a
// link that leads out of home, an absolute link, ".." out of home, all fail
// with an error that says the path escapes, and that is the only protection
// the reader relies on.
//
// What the open can and cannot do. The target is examined with stat first and
// opened only if it is a regular file, so a device node or socket that is
// already there is never opened. A FIFO (anybody can create one) that
// replaces the file between the stat and the open does not block the open,
// because it is non-blocking, and the descriptor is checked again with fstat
// and refused. A device node can be put there only by root, so the window
// between stat and open cannot be exploited by an unprivileged user. The file
// must be owned by uid or by root (the rule sshd applies with StrictModes),
// at most max bytes, and ErrTooLarge is returned beyond that; every refusal
// wraps ErrUnsafe except a missing file or directory, which is an error for
// which errors.Is(err, fs.ErrNotExist) holds, and the escape of a link, whose
// text says "escapes".
func (OSFS) ReadHomeFile(home string, uid uint32, rel string, max int64) ([]byte, error) {
	if !filepath.IsAbs(home) || rel == "" || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("%w: home %q and path %q must be an absolute directory and a relative path", ErrUnsafe, home, rel)
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fi, err := root.Stat(rel)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, rel)
	}
	f, err := root.OpenFile(rel, nonblockRead, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err = f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafe, rel)
	}
	owner, ok := ownerUID(fi)
	if !ok || (owner != 0 && owner != uid) {
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not by the user or root", ErrUnsafe, rel, owner)
	}
	return readCapped(f, max)
}
