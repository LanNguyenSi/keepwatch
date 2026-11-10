package doctor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

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

// writeProbe creates and removes a file inside dir without following links.
func writeProbe(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	name := ".keepwatch-doctor-probe-" + hex.EncodeToString(b[:])
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write([]byte("x"))
	cerr := f.Close()
	rerr := root.Remove(name)
	for _, e := range []error{werr, cerr, rerr} {
		if e != nil {
			return e
		}
	}
	return nil
}
