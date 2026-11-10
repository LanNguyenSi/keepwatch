package doctor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// OSStateProber examines dir the way `check` will use it and proves it is
// writable. The directory is judged by the state package itself (a symlink, a
// foreign owner or a directory others can write is refused exactly as check
// refuses it); then one probe file is created exclusively inside the opened
// directory and removed again. Nothing outside the directory is touched, and
// a directory that does not exist is not created.
func OSStateProber(dir string) StateStatus {
	var st StateStatus
	store, err := state.Open(dir)
	if err != nil {
		st.Err = err
		return st
	}
	if _, err := os.Lstat(store.Dir()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st
		}
		st.Err = err
		return st
	}
	st.Exists = true
	lr, err := store.Load()
	if err != nil {
		st.Err = err
		return st
	}
	st.FileProblem = lr.Problem
	if err := writeProbe(store.Dir()); err != nil {
		st.Err = fmt.Errorf("not writable: %w", err)
	}
	return st
}

// writeProbe creates and removes a file inside dir. It goes through a
// directory that install.OSFS opened and checked (a real directory, not
// writable by others, trusted owner, the very directory that was checked), so
// the file cannot land anywhere else. A crash between the two steps leaves a
// file named with install.ProbePrefix, which `uninstall --purge` removes.
func writeProbe(dir string) error {
	d, err := (install.OSFS{}).OpenDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	name := install.ProbePrefix + hex.EncodeToString(b[:])
	if err := d.WriteFile(name, []byte("x"), 0o600); err != nil {
		return err
	}
	return d.Remove(name)
}
