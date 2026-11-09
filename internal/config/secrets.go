package config

import (
	"errors"
	"fmt"
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
	if err := checkConfigDir(filepath.Dir(path), of); err != nil {
		return nil, fmt.Errorf("notify.ntfy.token_file: %v", err)
	}
	f, _, err := openSecure(path, tokenPolicy(of))
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
// follows a symlink at the path or at the directory: an existing
// entry (including a dangling symlink) is refused without --force,
// and with --force only a regular file is replaced. An existing
// directory must also be non-writable by group or other and owned by
// uid 0 or the running user, like every other configuration path. The
// write is atomic: a temp file in the same directory, chmod 0640,
// fsync, then rename, with the temp file removed on any error.
func WriteExample(path string, force bool, opts ...Option) error {
	opt := options{ownerOf: ownerOf}
	for _, fn := range opts {
		fn(&opt)
	}
	dir := filepath.Dir(path)
	if fi, err := os.Lstat(dir); err != nil {
		if !isNotExist(err) {
			return err
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil { // defeat the umask
			return err
		}
	} else {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: the directory is a symlink, refusing to write through it", dir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: not a directory", dir)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: permissions 0%03o allow group or other writes, refusing to write", dir, fi.Mode().Perm())
		}
		uid, err := opt.ownerOf(fi)
		if err != nil {
			return err
		}
		if uid != 0 && uid != os.Getuid() {
			return fmt.Errorf("%s: owned by uid %d, want uid 0 or %d, refusing to write", dir, uid, os.Getuid())
		}
	}
	if fi, err := os.Lstat(path); err == nil {
		if !force {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s exists and is not a regular file, refusing to replace it", path)
		}
	} else if !isNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".keepwatch-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
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
		os.Remove(tmpName)
		return errw
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
