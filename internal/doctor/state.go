package doctor

import (
	"errors"
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
	if err := install.WriteProbe(install.OSFS{}, store.Dir()); err != nil {
		st.Err = err
	}
	return st
}
