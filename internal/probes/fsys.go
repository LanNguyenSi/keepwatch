package probes

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrTooLarge is returned by FS.ReadFile when a file is larger than max.
var ErrTooLarge = errors.New("file too large")

// FS is the read-only file access probes get. ReadFile returns the whole
// file, or ErrTooLarge when it holds more than max bytes. A missing file
// is reported as an error for which errors.Is(err, fs.ErrNotExist) holds.
type FS interface {
	ReadFile(path string, max int64) ([]byte, error)
}

// OSFS reads regular files from the host, read-only. keepwatch runs as
// root and some files it reads sit in places other users can write to, so
// ReadFile opens the path without following a symbolic link in its last
// component, without blocking on a FIFO or device, and refuses anything that
// is not a regular file. It reads at most max bytes.
//
// Only the last component is checked: directories on the way are followed,
// which keeps the standard paths working (on Ubuntu /var/run is a symbolic
// link to /run, and a path like /var/run/reboot-required is opened as such).
// A caller therefore passes a path whose directories are root-owned, and the
// file itself must not be a link.
type OSFS struct{}

// ReadFile implements FS.
func (OSFS) ReadFile(path string, max int64) ([]byte, error) {
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
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}
