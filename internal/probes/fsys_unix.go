//go:build unix

package probes

import (
	"os"
	"syscall"
)

// openFlags: read-only; O_NOFOLLOW makes opening a symbolic link in the last
// path component fail (ELOOP); O_NONBLOCK keeps open from waiting on a FIFO
// that has no writer.
const openFlags = syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW

// nonblockRead: read-only and non-blocking, for a path that os.Root has
// already confined (the root does not follow a link out of its directory).
const nonblockRead = syscall.O_RDONLY | syscall.O_NONBLOCK

// ownerUID returns the owning user id of fi.
func ownerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
