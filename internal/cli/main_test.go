package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain makes the temporary directories of the tests real paths. The
// configuration loader refuses a symbolic link anywhere on the path of a
// configuration file, and the default temporary directory of macOS lies
// below /var, which is one.
func TestMain(m *testing.M) {
	if real, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		os.Setenv("TMPDIR", real)
	}
	os.Exit(m.Run())
}
