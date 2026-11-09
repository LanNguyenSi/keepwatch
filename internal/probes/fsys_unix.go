//go:build unix

package probes

import "syscall"

// openFlags: read-only; O_NOFOLLOW makes opening a symbolic link in the last
// path component fail (ELOOP); O_NONBLOCK keeps open from waiting on a FIFO
// that has no writer.
const openFlags = syscall.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
