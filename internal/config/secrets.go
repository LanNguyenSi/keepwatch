package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ownerOf reports the uid that owns path. It is the default, injectable
// via WithOwnerOf so that ownership rejection can be tested unprivileged.
func ownerOf(path string) (int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot determine the owner of %s", path)
	}
	return int(st.Uid), nil
}

// ReadToken reads the ntfy token lazily, after Load has validated the
// file's existence, type, ownership and permissions without reading it.
// A trailing newline is trimmed.
func (c *Config) ReadToken() ([]byte, error) {
	if c.Notify.Ntfy == nil || c.Notify.Ntfy.TokenFile == "" {
		return nil, errors.New("config: notify.ntfy.token_file is not set")
	}
	b, err := os.ReadFile(c.Notify.Ntfy.TokenFile)
	if err != nil {
		return nil, err
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b, nil
}

// WriteExample writes the embedded example configuration to path with
// mode 0640, creating its directory with 0750 when missing. Without
// force it refuses to overwrite an existing file.
func WriteExample(path string, force bool) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); err != nil {
		if !isNotExist(err) {
			return err
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return err
		}
	}
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}
	if err := os.WriteFile(path, example, 0o640); err != nil {
		return err
	}
	return os.Chmod(path, 0o640)
}
