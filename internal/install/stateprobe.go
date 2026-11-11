package install

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// WriteProbe proves that dir can be written to, the way a scheduled run needs
// it: one file is created and removed again inside it. `install` runs it
// before it writes a unit, and `doctor` runs it on the state directory, so the
// two cannot disagree about a directory on a read-only file system.
//
// The file goes through a directory that fsys opened and checked (a real
// directory, not writable by others, trusted owner, the very directory that
// was checked), so it cannot land anywhere else. A crash between the two steps
// leaves a file named with ProbePrefix, which `uninstall --purge` removes.
// Every failure, opening the directory included, is reported as "not
// writable: ...", the text both commands print.
func WriteProbe(fsys FS, dir string) error {
	if err := writeProbe(fsys, dir); err != nil {
		return fmt.Errorf("not writable: %w", err)
	}
	return nil
}

func writeProbe(fsys FS, dir string) error {
	d, err := fsys.OpenDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	name := ProbePrefix + hex.EncodeToString(b[:])
	if err := d.WriteFile(name, []byte("x"), 0o600); err != nil {
		return err
	}
	return d.Remove(name)
}

// StateDirUnusable is the sentence for a state_dir that checks cannot use.
// `install` refuses with it and `doctor` reports it as a problem.
func StateDirUnusable(dir string, err error) string {
	return fmt.Sprintf("state_dir %s is not usable, checks would exit 3: %v", dir, err)
}
