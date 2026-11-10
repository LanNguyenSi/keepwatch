package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func tempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOSFSOpenDirRefusals(t *testing.T) {
	base := tempDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o775); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	foreign := OSFS{OwnerOK: func(int) bool { return false }}

	if d, err := (OSFS{}).OpenDir(real); err != nil {
		t.Fatalf("OpenDir(real): %v", err)
	} else {
		d.Close()
	}
	for name, c := range map[string]struct {
		fsys OSFS
		path string
		want string
	}{
		"symlink":        {OSFS{}, link, "symlink"},
		"group writable": {OSFS{}, loose, "allow group or other writes"},
		"not a dir":      {OSFS{}, file, "must be a directory"},
		"foreign owner":  {foreign, real, "owned by uid"},
	} {
		d, err := c.fsys.OpenDir(c.path)
		if err == nil {
			d.Close()
			t.Errorf("%s: OpenDir succeeded", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
		}
	}
	if _, err := (OSFS{}).OpenDir(filepath.Join(base, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: err = %v, want ErrNotExist", err)
	}
}

func TestOSFSWriteFileIsAtomicAndLeavesNoTemporaryFile(t *testing.T) {
	base := tempDir(t)
	d, err := (OSFS{}).OpenDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.WriteFile("a.service", []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile("a.service", []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := d.ReadFile("a.service", 100)
	if err != nil || string(got) != "two" {
		t.Fatalf("ReadFile = %q, %v", got, err)
	}
	fi, _ := os.Stat(filepath.Join(base, "a.service"))
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644 whatever the umask", fi.Mode().Perm())
	}
	names, _ := d.Names()
	if len(names) != 1 || names[0] != "a.service" {
		t.Errorf("directory holds %v, want only a.service", names)
	}

	// A failing rename (the name is a non-empty directory) keeps the old
	// state and removes the temporary file.
	if err := os.MkdirAll(filepath.Join(base, "dir", "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteFile("dir", []byte("z"), 0o644); err == nil {
		t.Fatal("WriteFile over a non-empty directory succeeded")
	}
	names, _ = d.Names()
	for _, n := range names {
		if strings.HasPrefix(n, ".keepwatch-tmp-") {
			t.Errorf("temporary file %s left behind", n)
		}
	}
}

// A symbolic link at the target name is replaced, never written through: the
// file it points to keeps its content.
func TestOSFSWriteFileNeverWritesThroughALink(t *testing.T) {
	base := tempDir(t)
	victim := filepath.Join(base, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(base, "unit")); err != nil {
		t.Fatal(err)
	}
	d, _ := (OSFS{}).OpenDir(base)
	defer d.Close()
	if err := d.WriteFile("unit", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("the link target was written: %q", b)
	}
	if fi, _ := os.Lstat(filepath.Join(base, "unit")); fi.Mode()&os.ModeSymlink != 0 {
		t.Error("the link is still a link")
	}
}

func TestOSFSReadFileRefusals(t *testing.T) {
	base := tempDir(t)
	if err := os.WriteFile(filepath.Join(base, "f"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "f"), filepath.Join(base, "l")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(base, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, _ := (OSFS{}).OpenDir(base)
	defer d.Close()
	if b, err := d.ReadFile("f", 10); err != nil || string(b) != "0123456789" {
		t.Errorf("ReadFile at the limit: %q, %v", b, err)
	}
	for name, c := range map[string]struct{ file, want string }{
		"too large": {"f", "larger than"}, "symlink": {"l", "symlink"}, "directory": {"sub", "not a regular file"}, "fifo": {"fifo", "not a regular file"},
	} {
		max := int64(10)
		if name == "too large" {
			max = 9
		}
		if _, err := d.ReadFile(c.file, max); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if _, err := d.ReadFile("missing", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	// Names are plain names: a path cannot leave the directory.
	if _, err := d.ReadFile("../f", 10); err == nil {
		t.Error("ReadFile accepted a path that leaves the directory")
	}
	if _, err := d.Lstat("sub/../../f"); err == nil {
		t.Error("Lstat accepted a path that leaves the directory")
	}
}

func TestOSFSMkdirSetsTheExactModeAndRmdirIsCareful(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	base := tempDir(t)
	p := filepath.Join(base, "cfg")
	if err := (OSFS{}).Mkdir(p, 0o750); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o750 {
		t.Errorf("mode = %v, want 0750 although the umask is 077", fi.Mode().Perm())
	}
	if err := (OSFS{}).Mkdir(p, 0o750); !errors.Is(err, fs.ErrExist) {
		t.Errorf("Mkdir of an existing path: %v", err)
	}
	if err := (OSFS{}).Mkdir(filepath.Join(base, "no", "parent"), 0o700); err == nil {
		t.Error("Mkdir created a missing parent")
	}
	// Rmdir: refuses links and files, and a directory with content.
	if err := os.WriteFile(filepath.Join(p, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (OSFS{}).Rmdir(p); err == nil {
		t.Error("Rmdir removed a directory with content")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if err := (OSFS{}).Rmdir(link); err == nil {
		t.Error("Rmdir removed a symlink")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Error("the symlink is gone")
	}
	if err := os.Remove(filepath.Join(p, "x")); err != nil {
		t.Fatal(err)
	}
	if err := (OSFS{}).Rmdir(p); err != nil {
		t.Errorf("Rmdir of an empty directory: %v", err)
	}
}

func TestOSFSRemoveRemovesTheLinkNotTheTarget(t *testing.T) {
	base := tempDir(t)
	target := filepath.Join(base, "target")
	os.WriteFile(target, []byte("x"), 0o644)
	os.Symlink(target, filepath.Join(base, "link"))
	d, _ := (OSFS{}).OpenDir(base)
	defer d.Close()
	if err := d.Remove("link"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Errorf("the target is gone: %v", err)
	}
}

// A file swapped for another between the look and the open is not read.
func TestOSFSReadFileDetectsASwap(t *testing.T) {
	base := tempDir(t)
	name := filepath.Join(base, "unit")
	if err := os.WriteFile(name, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := (OSFS{}).OpenDir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.(*osDir).beforeOpen = func() {
		other := filepath.Join(base, "other")
		if err := os.WriteFile(other, []byte("second"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(other, name); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := d.ReadFile("unit", 100); err == nil || !strings.Contains(err.Error(), "changed while") {
		t.Errorf("ReadFile = %q, %v, want the swap to be detected", b, err)
	}
}
