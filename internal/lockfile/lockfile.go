// Package lockfile keeps one keepwatch watch per state directory.
//
// Acquire opens watch.lock in the state directory under the securefile
// rules (a regular file, links not followed, mode 0600 when created, a
// trusted owner) and takes a non-blocking exclusive flock on it. While the
// lock is held, any other Acquire on the same directory, in this process or
// in another, fails with an error for which errors.Is(err, ErrLocked)
// holds and whose message names the lock file. Release drops the lock and
// closes the file; the lock file itself is never removed, because deleting
// it would let a second acquirer lock a different file and both would
// believe they were the watch.
//
// Only watch takes this lock; check and the timer stay unlocked (a known
// limit). On platforms other than linux and darwin, Acquire fails with an
// error for which errors.Is(err, ErrUnsupported) holds.
package lockfile

import "errors"

var (
	// ErrLocked is returned when another watch holds the lock. The error
	// message names the lock file.
	ErrLocked = errors.New("lock is held by another keepwatch watch")
	// ErrUnsupported is returned by Acquire on platforms without flock.
	ErrUnsupported = errors.New("locking the state directory is not supported on this platform")
)

// lockFileName is the name of the lock file inside the state directory.
const lockFileName = "watch.lock"
