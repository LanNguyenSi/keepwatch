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

// OSFS reads regular files from the host. It follows no policy beyond
// being read-only: it opens the path, requires a regular file and reads at
// most max bytes.
type OSFS struct{}

// ReadFile implements FS.
func (OSFS) ReadFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
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
