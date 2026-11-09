// Package probestest holds test helpers for packages that use probes.
package probestest

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"time"

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

// FakeFS is an in-memory probes.FS that also offers the optional operations
// of OSFS (Glob, ModTime, ReadTrusted, ReadHomeFile). All of them are looked
// up in plain maps; none reads the host.
type FakeFS struct {
	// Files maps an absolute path to its content; ReadFile, ReadTrusted and
	// Glob use it.
	Files map[string]string
	// Times maps a path to its modification time; ModTime and Glob use it.
	Times map[string]time.Time
	// Homes maps home + "\x00" + rel to a file's content for ReadHomeFile.
	Homes map[string]string
	// Errs maps a path (or home + "\x00" + rel) to the error every read of it
	// returns, before the maps above are consulted.
	Errs map[string]error
	// GlobErr, when set, is returned by every Glob.
	GlobErr error
}

var (
	_ probes.FS            = FakeFS{}
	_ probes.Globber       = FakeFS{}
	_ probes.ModTimer      = FakeFS{}
	_ probes.TrustedReader = FakeFS{}
	_ probes.HomeReader    = FakeFS{}
)

// HomeKey builds the key of a Homes or Errs entry for ReadHomeFile.
func HomeKey(home, rel string) string { return home + "\x00" + rel }

func notExist(p string) error { return &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist} }

// ReadFile implements probes.FS.
func (f FakeFS) ReadFile(path string, max int64) ([]byte, error) {
	if err, ok := f.Errs[path]; ok {
		return nil, err
	}
	s, ok := f.Files[path]
	if !ok {
		return nil, notExist(path)
	}
	if int64(len(s)) > max {
		return nil, probes.ErrTooLarge
	}
	return []byte(s), nil
}

// Glob implements probes.Globber over the keys of Files and Times.
func (f FakeFS) Glob(pattern string) ([]string, error) {
	if f.GlobErr != nil {
		return nil, f.GlobErr
	}
	seen := map[string]bool{}
	var out []string
	for p := range f.Files {
		if ok, _ := path.Match(pattern, p); ok && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for p := range f.Times {
		if ok, _ := path.Match(pattern, p); ok && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ModTime implements probes.ModTimer.
func (f FakeFS) ModTime(p string) (time.Time, error) {
	if err, ok := f.Errs[p]; ok {
		return time.Time{}, err
	}
	t, ok := f.Times[p]
	if !ok {
		return time.Time{}, notExist(p)
	}
	return t, nil
}

// ReadTrusted implements probes.TrustedReader; the resolved path is the path.
func (f FakeFS) ReadTrusted(p string, max int64) ([]byte, string, error) {
	b, err := f.ReadFile(p, max)
	return b, p, err
}

// ReadHomeFile implements probes.HomeReader.
func (f FakeFS) ReadHomeFile(home string, _ uint32, rel string, max int64) ([]byte, error) {
	key := HomeKey(home, rel)
	if err, ok := f.Errs[key]; ok {
		return nil, err
	}
	s, ok := f.Homes[key]
	if !ok {
		return nil, notExist(home + "/" + rel)
	}
	if int64(len(s)) > max {
		return nil, probes.ErrTooLarge
	}
	return []byte(s), nil
}
