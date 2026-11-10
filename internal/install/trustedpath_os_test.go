package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On the real file system, below a temporary directory that the test owns.
func TestTrustedPathOnTheRealFileSystem(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	mine := func(uid int) bool { return uid == me }
	nobody := func(int) bool { return false }
	mk := func(rel string, mode os.FileMode, dir bool) string {
		p := filepath.Join(base, rel)
		var err error
		if dir {
			err = os.MkdirAll(p, 0o755)
		} else {
			err = os.WriteFile(p, []byte("x"), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := mk("bin", 0o755, true)
	bin := filepath.Join(good, "keepwatch")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathFrom(OSFS{}, base, bin, KindFile, mine); err != nil {
		t.Fatalf("a good path: %v", err)
	}
	if err := trustedPathFrom(OSFS{}, base, bin, KindFile, nobody); err == nil || !strings.Contains(err.Error(), "not by root") {
		t.Errorf("owner rule not applied: %v", err)
	}
	if err := trustedPathFrom(OSFS{}, base, good, KindDir, mine); err != nil {
		t.Errorf("a good directory: %v", err)
	}

	// A symbolic link as a middle component or as the file.
	if err := os.Symlink(good, filepath.Join(base, "linkdir")); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathFrom(OSFS{}, base, filepath.Join(base, "linkdir", "keepwatch"), KindFile, mine); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("link in the middle: %v", err)
	}
	if err := os.Symlink(bin, filepath.Join(good, "linkfile")); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathFrom(OSFS{}, base, filepath.Join(good, "linkfile"), KindFile, mine); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("link as the file: %v", err)
	}
	if err := os.Symlink(filepath.Join(base, "nowhere"), filepath.Join(good, "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathFrom(OSFS{}, base, filepath.Join(good, "dangling"), KindFile, mine); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("dangling link: %v", err)
	}

	// Somebody else can write: the only way to swap a component.
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		d := mk("w"+mode.String(), mode, true)
		f := filepath.Join(d, "keepwatch")
		if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := trustedPathFrom(OSFS{}, base, f, KindFile, mine); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
			t.Errorf("directory %v: %v", mode, err)
		}
	}
	loose := filepath.Join(good, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := trustedPathFrom(OSFS{}, base, loose, KindFile, mine); err == nil || !strings.Contains(err.Error(), "writable by group or other") {
		t.Errorf("file 0666: %v", err)
	}
	// Kind and presence.
	if err := trustedPathFrom(OSFS{}, base, good, KindFile, mine); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory as file: %v", err)
	}
	if err := trustedPathFrom(OSFS{}, base, bin, KindDir, mine); err == nil {
		t.Error("file as directory")
	}
	if err := trustedPathFrom(OSFS{}, base, filepath.Join(good, "absent"), KindFile, mine); !IsMissing(err) {
		t.Errorf("missing: %v", err)
	}
	// A path outside the part the test trusts is a mistake of the test.
	if err := trustedPathFrom(OSFS{}, base, "/etc/hostname", KindFile, mine); err == nil || !strings.Contains(err.Error(), "not below") {
		t.Errorf("outside: %v", err)
	}
	// The public function starts at "/": the system temporary directory is
	// writable by others, so nothing below it is trusted.
	if err := TrustedPath(OSFS{}, bin, KindFile); err == nil {
		t.Error("TrustedPath accepted a file below a temporary directory")
	}
}

// Mkdir sets the mode with fchmod on a descriptor opened without following a
// link: a name swapped for a link after the creation is not chmod-ed through.
func TestOSFSMkdirDoesNotChmodThroughASwappedLink(t *testing.T) {
	base := tempDir(t)
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "new")
	o := OSFS{afterMkdir: func(p string) {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		// a relative target stays inside the parent, where os.Root follows it
		if err := os.Symlink(filepath.Base(victim), p); err != nil {
			t.Fatal(err)
		}
	}}
	if err := o.Mkdir(target, 0o700); err == nil {
		t.Error("Mkdir succeeded although the new directory was replaced by a link")
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o755 {
		t.Errorf("the link target was chmod-ed to %v", fi.Mode().Perm())
	}
}

// The directory is looked at, then opened: a swap in between (a link to
// another directory) is caught because the opened directory is not the one
// that was looked at.
func TestOSFSMkdirDetectsASwapBetweenTheLookAndTheOpen(t *testing.T) {
	base := tempDir(t)
	victim := filepath.Join(base, "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	o := OSFS{beforeChmod: func(p string) {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(victim), p); err != nil {
			t.Fatal(err)
		}
	}}
	if err := o.Mkdir(filepath.Join(base, "new"), 0o700); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Errorf("err = %v, want the swap to be detected", err)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm() != 0o755 {
		t.Errorf("the link target was chmod-ed to %v", fi.Mode().Perm())
	}
}

// A directory of another owner in the place of the new one is not chmod-ed.
// Needs root to give a directory away.
func TestOSFSMkdirRefusesADirectoryOfAnotherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a directory to another user needs root")
	}
	base := tempDir(t)
	o := OSFS{afterMkdir: func(p string) {
		if err := os.Chown(p, 12345, 12345); err != nil {
			t.Fatal(err)
		}
	}}
	if err := o.Mkdir(filepath.Join(base, "new"), 0o700); err == nil || !strings.Contains(err.Error(), "not the directory that was just created") {
		t.Errorf("err = %v", err)
	}
}
