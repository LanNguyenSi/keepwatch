// Package probestest holds test helpers for packages that use probes.
package probestest

import (
	"fmt"
	"io/fs"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
)

// MemFS is an in-memory probes.FS keyed by absolute path. A path that maps
// to nothing is missing. It applies the size cap the way the real FS does.
type MemFS map[string]string

var _ probes.FS = MemFS(nil)

// ReadFile implements probes.FS.
func (m MemFS) ReadFile(path string, max int64) ([]byte, error) {
	s, ok := m[path]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	if int64(len(s)) > max {
		return nil, probes.ErrTooLarge
	}
	return []byte(s), nil
}

// ErrFS is a probes.FS whose every read fails with Err.
type ErrFS struct{ Err error }

var _ probes.FS = ErrFS{}

// ReadFile implements probes.FS.
func (e ErrFS) ReadFile(path string, _ int64) ([]byte, error) {
	return nil, fmt.Errorf("open %s: %w", path, e.Err)
}
