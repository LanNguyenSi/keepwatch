//go:build linux || darwin

package lockfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/LanNguyenSi/keepwatch/internal/securefile"
)

// maxLockSize bounds the lock file, which keepwatch itself never fills: the
// lock is a lock, not a log.
const maxLockSize = 4096

// Lock is a held lock on the lock file of one state directory. The lock is
// held only while the Lock stays reachable: an *os.File closes its
// descriptor when it is garbage collected, which drops the flock, so keep
// the Lock reachable until Release (a deferred l.Release() does).
type Lock struct {
	path string
	dir  *securefile.Dir
	f    *os.File
}

// Path returns the path of the lock file.
func (l *Lock) Path() string { return l.path }

// Acquire opens dir/watch.lock and locks it. dir must be an absolute path
// to an existing state directory that passes the securefile checks; a
// missing directory is an error for which errors.Is(err, fs.ErrNotExist)
// holds. The file is opened under the securefile rules (links not followed,
// mode 0600 when created, a trusted owner) and locked with a non-blocking
// exclusive flock. Another watch holds it when the returned error satisfies
// errors.Is(err, ErrLocked). A new Lock must be released with Release, once.
// Keep the returned Lock reachable until Release: an *os.File closes its
// descriptor when it is garbage collected, which drops the flock.
//
// Any error other than one for which errors.Is(err, ErrLocked) holds means
// the lock state is unknown. A securefile.ErrChanged (the name was replaced
// while it was being opened) is retryable. A securefile.ErrTooLarge means
// watch.lock is not keepwatch's own lock file: Acquire wraps it with that
// hint, and no retry succeeds until that file is dealt with.
//
// A known limit: renaming or removing watch.lock while a watch holds it
// lets a second watch start, because the next Acquire then creates a fresh
// file and flocks that. state_dir is trusted (root-owned or owned by the
// running user, not writable by group or other), so doing that takes the
// rights of whoever could stop the watch anyway, given trusted ancestors:
// securefile does not examine the ancestors of state_dir or ACLs, and
// whoever can write a parent of state_dir can rename state_dir itself away.
func Acquire(dir string) (*Lock, error) {
	d, err := securefile.OpenDir(dir, false, nil)
	if err != nil {
		return nil, err
	}
	f, _, err := d.OpenAppend(lockFileName, maxLockSize)
	if err != nil {
		d.Close()
		if errors.Is(err, securefile.ErrTooLarge) {
			return nil, fmt.Errorf("%w: watch.lock is not keepwatch's own lock file", err)
		}
		return nil, err
	}
	l := &Lock{path: filepath.Join(d.Path(), lockFileName), dir: d, f: f}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		d.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", l.path, ErrLocked)
		}
		return nil, fmt.Errorf("cannot lock %s: %w", l.path, err)
	}
	return l, nil
}

// Release drops the lock and closes the file and the directory. The lock
// file is kept: removing it would let an acquirer that looked at the name
// just before the removal and one that comes after it each lock a different
// file. Release must be called once; a second call reports an error.
func (l *Lock) Release() error {
	var uerr error
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN); err != nil {
		uerr = fmt.Errorf("cannot unlock %s: %w", l.path, err)
	}
	return errors.Join(uerr, l.f.Close(), l.dir.Close())
}
