package config

import (
	"errors"
	"fmt"
	"io"
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

// securePolicy is the rule set openSecureIn enforces on the opened fd.
type securePolicy struct {
	maxSize    int64
	permMask   os.FileMode // permission bits that must all be zero
	permMsg    string      // full message: path, perm
	ownerOf    OwnerOf
	ownerMsg   string // full message: path, uid
	isExpected func(uid int) bool
	nlink1     bool // require exactly one hard link (secrets only)
}

// tokenPolicy is the rule for notify.ntfy.token_file: a regular file
// of at most maxTokenSize bytes with exactly one hard link, readable
// and writable only by its owner, owned by the running user.
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
		nlink1:     true,
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

// readCapped reads at most max bytes from r: it takes max+1 bytes at
// most so a reader that delivers more than max is reported instead of
// silently truncated.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	return b, nil
}

// openSecureIn opens the file name in the checked directory root and
// enforces the policy on the file the fd refers to. display is the full
// path of the file, which the messages name. The open goes through the
// descriptor of the directory (openat), never through the path again:
// root comes from openCheckedDir, which has checked every ancestor, so
// the directory component cannot be swapped between the check and the
// open. The final component is never followed: a symlink is refused, a
// FIFO never blocks (O_NONBLOCK), and the descriptor must be the very
// file the Lstat on the directory showed. The fd's fstat result must be a
// regular file no larger than maxSize (exactly one hard link when nlink1)
// with no permMask permission bits and an acceptable owner. Because
// every check runs on the one open fd, a later call sees a swap of the
// path and the already-open fd keeps pointing at the original inode. The
// caller must close the file.
func openSecureIn(root *os.Root, name, display string, p securePolicy) (*os.File, fs.FileInfo, error) {
	li, err := root.Lstat(name)
	if err != nil {
		return nil, nil, &fs.PathError{Op: "open", Path: display, Err: rootCause(err)}
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: must be a regular file, it is a symlink", display)
	}
	if afterLstat != nil {
		afterLstat(display)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("%s: must be a regular file, it is a symlink", display)
		}
		return nil, nil, &fs.PathError{Op: "open", Path: display, Err: rootCause(err)}
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !os.SameFile(li, fi) {
		f.Close()
		return nil, nil, fmt.Errorf("%s: changed while it was being opened", display)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, nil, fmt.Errorf("%s: must be a regular file, found %s", display, fi.Mode().Type().String())
	}
	if fi.Size() > p.maxSize {
		f.Close()
		return nil, nil, fmt.Errorf("%s: size %d is larger than the limit %d", display, fi.Size(), p.maxSize)
	}
	if fi.Mode().Perm()&p.permMask != 0 {
		f.Close()
		return nil, nil, fmt.Errorf(p.permMsg, display, fi.Mode().Perm())
	}
	if p.nlink1 {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			f.Close()
			return nil, nil, fmt.Errorf("%s: cannot determine the link count of the open file", display)
		}
		if st.Nlink != 1 {
			f.Close()
			return nil, nil, fmt.Errorf("%s: has %d hard links, want exactly 1", display, st.Nlink)
		}
	}
	uid, err := p.ownerOf(fi)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !p.isExpected(uid) {
		f.Close()
		return nil, nil, fmt.Errorf(p.ownerMsg, display, uid)
	}
	return f, fi, nil
}
