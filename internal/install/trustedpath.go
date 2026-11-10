package install

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// PathKind says what the last component of a trusted path must be.
type PathKind int

// The kinds of trusted path.
const (
	// KindFile: a regular file (the keepwatch binary).
	KindFile PathKind = iota
	// KindDir: a directory.
	KindDir
)

// RootOnly is the owner rule of TrustedPath: only uid 0.
func RootOnly(uid int) bool { return uid == 0 }

// TrustedPath checks that nothing but root can change what p names, for a
// path that root will execute or read as a trusted input: it walks p from "/"
// and looks at every component with Lstat, and each one must not be a symbolic
// link, must be owned by root and must not be writable by group or other. The
// last component must be a regular file (KindFile) or a directory (KindDir).
//
// The walk needs no openat-style descent: a component that only root can
// change cannot be swapped by anybody else between the look and the use, so
// if every component passes, the path means what it meant when it was checked.
// A component that fails is exactly one somebody else could swap.
//
// Known limit: POSIX ACLs and file capabilities are not examined, and neither
// is the mount (a writable bind mount over a checked directory).
func TrustedPath(fsys FS, p string, kind PathKind) error {
	return trustedPathFrom(fsys, "", p, kind, RootOnly)
}

// trustedPathFrom is TrustedPath with the owner rule given and with the
// components at and above trusted left unexamined (tests work below a
// temporary directory they own). An empty trusted examines everything.
func trustedPathFrom(fsys FS, trusted, p string, kind PathKind, owner func(uid int) bool) error {
	if p == "" || p[0] != '/' || path.Clean(p) != p {
		return fmt.Errorf("%q is not a clean absolute path", p)
	}
	if trusted != "" && p != trusted && !strings.HasPrefix(p, strings.TrimSuffix(trusted, "/")+"/") {
		return fmt.Errorf("%s is not below %s", p, trusted)
	}
	prefixes := []string{"/"}
	if p != "/" {
		cur := ""
		for _, c := range strings.Split(p[1:], "/") {
			cur += "/" + c
			prefixes = append(prefixes, cur)
		}
	}
	for i, q := range prefixes {
		if trusted != "" && len(q) <= len(trusted) {
			continue
		}
		info, err := fsys.Lstat(q)
		if err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
		last := i == len(prefixes)-1
		switch {
		case info.IsSymlink():
			return &linkError{path: q}
		case !last && !info.IsDir():
			return fmt.Errorf("%s is not a directory", q)
		case last && kind == KindFile && !info.IsRegular():
			return fmt.Errorf("%s is not a regular file", q)
		case last && kind == KindDir && !info.IsDir():
			return fmt.Errorf("%s is not a directory", q)
		case !owner(info.UID):
			return fmt.Errorf("%s is owned by uid %d, not by root", q, info.UID)
		case info.Mode.Perm()&0o022 != 0:
			return fmt.Errorf("%s has permissions %04o, writable by group or other", q, info.Mode.Perm())
		}
	}
	return nil
}

// IsMissing reports whether err from TrustedPath is a missing component.
func IsMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// linkError is the error of TrustedPath for a component that is a symbolic
// link.
type linkError struct{ path string }

func (e *linkError) Error() string {
	return e.path + " is a symbolic link, somebody who can change it can redirect the path"
}

// IsSymlink reports whether err from TrustedPath is a component that is a
// symbolic link.
func IsSymlink(err error) bool {
	var l *linkError
	return errors.As(err, &l)
}
