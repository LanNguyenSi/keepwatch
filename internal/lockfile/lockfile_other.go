//go:build !linux && !darwin

package lockfile

import "fmt"

// Lock is a held lock on the lock file. On this platform no Lock can
// exist, because Acquire always fails.
type Lock struct {
	path string
}

// Path returns the path of the lock file.
func (l *Lock) Path() string { return l.path }

// Acquire fails: this platform has no flock, so keepwatch cannot tell
// whether another watch holds the state directory.
func Acquire(dir string) (*Lock, error) {
	return nil, fmt.Errorf("%s: %w", dir, ErrUnsupported)
}

// Release fails: no lock can be held on this platform.
func (l *Lock) Release() error {
	return fmt.Errorf("%s: %w", l.path, ErrUnsupported)
}
