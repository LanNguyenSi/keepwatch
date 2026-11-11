package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// ReadToken reads the ntfy token lazily, after Load has validated the
// file's existence, type, ownership and permissions without reading
// it. It re-opens through the same secure path (no symlink following,
// checks on the fd itself, size cap) so a swap of the path after Load
// is rejected rather than read; the directory holding the token is
// checked again as well, so a directory made group- or other-writable
// after Load is refused. A trailing newline is trimmed; a token
// that is empty after trimming is an error.
func (c *Config) ReadToken() ([]byte, error) {
	if c.Notify.Ntfy == nil || c.Notify.Ntfy.TokenFile == "" {
		return nil, errors.New("config: notify.ntfy.token_file is not set")
	}
	path := c.Notify.Ntfy.TokenFile
	of := c.ownerOf
	if of == nil {
		of = ownerOf
	}
	root, err := openCheckedDir(filepath.Dir(path), of, false)
	if err != nil {
		return nil, fmt.Errorf("notify.ntfy.token_file: %v", err)
	}
	defer root.Close()
	f, _, err := openSecureIn(root, filepath.Base(path), path, tokenPolicy(of))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := readCapped(f, maxTokenSize)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s: the token is empty", path)
	}
	return b, nil
}

// WriteExample writes the embedded example configuration to path with
// mode 0640, creating its directory with 0750 when missing. It never
// follows a symlink at the path or at the directory or any directory
// above it: an existing entry (including a dangling symlink) is refused
// without --force, and with --force only a regular file is replaced.
// The directory and every directory above it must also be non-writable
// by group or other and owned by uid 0 or the running user, like every
// other configuration path (see openCheckedDir), and the file is written
// through the checked directory. The write is atomic: a temp file in the
// same directory, chmod 0640, fsync, then rename, with the temp file
// removed on any error.
func WriteExample(path string, force bool, opts ...Option) error {
	opt := options{ownerOf: ownerOf}
	for _, fn := range opts {
		fn(&opt)
	}
	dir := filepath.Dir(path)
	root, err := openCheckedDir(dir, opt.ownerOf, true)
	if err != nil {
		var de *dirError
		if errors.As(err, &de) {
			switch de.kind {
			case dirSymlink:
				if de.final() {
					return fmt.Errorf("%s: the directory is a symlink, refusing to write through it", dir)
				}
			case dirNotDir:
				if de.final() {
					return fmt.Errorf("%s: not a directory", dir)
				}
			case dirPerm, dirOwner:
				return fmt.Errorf("%v, refusing to write", err)
			}
		}
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	if fi, err := root.Lstat(name); err == nil {
		if !force {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file, refusing to replace it", path)
		}
	} else if !isNotExist(err) {
		return fmt.Errorf("%s: %v", path, rootCause(err))
	}
	tmpName, tmp, err := createTemp(root)
	if err != nil {
		return fmt.Errorf("%s: %v", dir, rootCause(err))
	}
	var errw error
	if errw = tmp.Chmod(0o640); errw == nil {
		_, errw = tmp.Write(example)
	}
	if errw == nil {
		errw = tmp.Sync()
	}
	if cerr := tmp.Close(); errw == nil {
		errw = cerr
	}
	if errw != nil {
		root.Remove(tmpName)
		return errw
	}
	if err := root.Rename(tmpName, name); err != nil {
		root.Remove(tmpName)
		return fmt.Errorf("%s: %v", path, rootCause(err))
	}
	return nil
}

// createTemp creates a new file with a name like .keepwatch-<random>.yaml
// in the checked directory, mode 0600, never replacing an existing one.
func createTemp(root *os.Root) (string, *os.File, error) {
	for try := 0; ; try++ {
		name := fmt.Sprintf(".keepwatch-%016x.yaml", rand.Uint64())
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, f, nil
		}
		if !errors.Is(err, fs.ErrExist) || try >= 100 {
			return "", nil, err
		}
	}
}
