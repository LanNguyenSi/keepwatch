package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

// Size caps for files read through the secure-open path.
const (
	maxTokenSize  = 4096
	maxConfigSize = 1 << 20
)

// OwnerOf reports the uid that owns the file described by fi, taken
// from the fd's fstat result (fs.FileInfo from File.Stat). The default
// is injectable via WithOwnerOf so ownership checks run unprivileged.
type OwnerOf func(fi fs.FileInfo) (int, error)

func ownerOf(fi fs.FileInfo) (int, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine the owner of %s", fi.Name())
	}
	return int(st.Uid), nil
}

// securePolicy is the rule set openSecure enforces on the opened fd.
type securePolicy struct {
	maxSize    int64
	permMask   os.FileMode // permission bits that must all be zero
	permMsg    string      // full message: path, perm
	ownerOf    OwnerOf
	ownerMsg   string // full message: path, uid
	isExpected func(uid int) bool
}

// tokenPolicy is the rule for notify.ntfy.token_file: a regular file
// of at most maxTokenSize bytes, readable and writable only by its
// owner, owned by the running user.
func tokenPolicy(of OwnerOf) securePolicy {
	uid := os.Getuid()
	s := strconv.Itoa(uid)
	return securePolicy{
		maxSize:    maxTokenSize,
		permMask:   0o077,
		permMsg:    "%s: permissions 0%03o grant access to group or other, want 0600 or stricter",
		ownerOf:    of,
		ownerMsg:   "%s: owned by uid %d, expected uid " + s,
		isExpected: func(u int) bool { return u == uid },
	}
}

// configPolicy is the rule for every loaded configuration file: a
// regular file of at most maxConfigSize bytes, not writable by group
// or other, owned by root or the running user.
func configPolicy(of OwnerOf) securePolicy {
	uid := os.Getuid()
	s := strconv.Itoa(uid)
	return securePolicy{
		maxSize:  maxConfigSize,
		permMask: 0o022,
		permMsg:  "%s: permissions 0%03o allow group or other writes, want 0644 or stricter",
		ownerOf:  of,
		ownerMsg: "%s: owned by uid %d, want uid 0 or " + s,
		isExpected: func(u int) bool {
			return u == 0 || u == uid
		},
	}
}

// openSecure opens path and enforces the policy on the file the fd
// refers to: it never follows a symlink (O_NOFOLLOW), never blocks on
// a FIFO (O_NONBLOCK), fstats the fd, and requires a regular file no
// larger than maxSize with no permMask permission bits and an
// acceptable owner. Existence, type, size, permissions and ownership
// are all checked on the one open fd, so swapping the path between
// validation and a later read cannot substitute a different file: the
// next openSecure call sees the swap, and the already-open fd keeps
// pointing at the original inode. The caller must close the file.
func openSecure(path string, p securePolicy) (*os.File, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("%s: must be a regular file, it is a symlink", path)
		}
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: must be a regular file, found %s", path, fi.Mode().Type().String())
	}
	if fi.Size() > p.maxSize {
		f.Close()
		return nil, nil, fmt.Errorf("%s: size %d is larger than the limit %d", path, fi.Size(), p.maxSize)
	}
	if fi.Mode().Perm()&p.permMask != 0 {
		f.Close()
		return nil, nil, fmt.Errorf(p.permMsg, path, fi.Mode().Perm())
	}
	uid, err := p.ownerOf(fi)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !p.isExpected(uid) {
		f.Close()
		return nil, nil, fmt.Errorf(p.ownerMsg, path, uid)
	}
	return f, fi, nil
}

// checkConfigDir enforces the configuration directory rules on dir:
// it must exist as a real directory (not a symlink), must not be
// writable by group or other, and must be owned by root or the
// running user. The running-as-root case is why: a group-writable
// conf.d lets another user suppress findings or redirect the token.
func checkConfigDir(dir string, of OwnerOf) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: must not be a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: must be a directory", dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: permissions 0%03o allow group or other writes", dir, fi.Mode().Perm())
	}
	uid, err := of(fi)
	if err != nil {
		return err
	}
	if uid != 0 && uid != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, want uid 0 or %d", dir, uid, os.Getuid())
	}
	return nil
}
