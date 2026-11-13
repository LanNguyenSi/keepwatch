package securefile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newDir(t *testing.T) (*Dir, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "state")
	d, err := OpenDir(p, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, p
}

func foreign(fs.FileInfo) (int, error) { return os.Getuid() + 4242, nil }

func entries(t *testing.T, p string) []string {
	t.Helper()
	es, err := os.ReadDir(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestOpenDirCreatesPrivate(t *testing.T) {
	_, p := newDir(t)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o, want 0700", fi.Mode().Perm())
	}
}

func TestOpenDirMissingWithoutCreate(t *testing.T) {
	_, err := OpenDir(filepath.Join(t.TempDir(), "nope"), false, nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want ErrNotExist", err)
	}
}

func TestOpenDirRefusesSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for _, create := range []bool{false, true} {
		if _, err := OpenDir(link, create, nil); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("create=%v: got %v, want ErrUntrusted", create, err)
		}
	}
}

func TestOpenDirRefusesFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(f, false, nil); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestOpenDirRefusesGroupOrOtherWritable(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		p := filepath.Join(t.TempDir(), "d")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenDir(p, false, nil); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("mode %o: got %v, want ErrUntrusted", mode, err)
		}
	}
	// Group/other read and execute are fine.
	p := filepath.Join(t.TempDir(), "ok")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDir(p, false, nil)
	if err != nil {
		t.Fatalf("0755: %v", err)
	}
	d.Close()
}

func TestOpenDirForeignOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "d")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDir(p, false, foreign); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	// uid 0 is trusted, and so is the running user.
	for _, uid := range []int{0, os.Getuid()} {
		d, err := OpenDir(p, false, func(fs.FileInfo) (int, error) { return uid, nil })
		if err != nil {
			t.Fatalf("uid %d: %v", uid, err)
		}
		d.Close()
	}
	boom := errors.New("boom")
	if _, err := OpenDir(p, false, func(fs.FileInfo) (int, error) { return 0, boom }); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the owner lookup error", err)
	}
}

func TestOpenDirSwapBetweenCheckAndOpen(t *testing.T) {
	base := t.TempDir()
	p := filepath.Join(base, "d")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	h := defaultHooks()
	h.dirChecked = func() {
		if err := os.Rename(p, p+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openDir(p, false, nil, h); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestNameValidation(t *testing.T) {
	d, p := newDir(t)
	bad := []string{"", ".", "..", "a/b", "/abs", "../x", "a/../b", ".hidden", ".kwtmp-1", `a\b`, "a\x00b"}
	for _, n := range bad {
		if err := d.WriteAtomic(n, []byte("x"), 10); !errors.Is(err, ErrInvalidName) {
			t.Errorf("WriteAtomic(%q): got %v", n, err)
		}
		if _, err := d.ReadCapped(n, 10); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ReadCapped(%q): got %v", n, err)
		}
		if f, _, err := d.OpenAppend(n, 10); !errors.Is(err, ErrInvalidName) {
			if f != nil {
				f.Close()
			}
			t.Errorf("OpenAppend(%q): got %v", n, err)
		}
	}
	if got := entries(t, p); len(got) != 0 {
		t.Fatalf("directory not empty after refused names: %v", got)
	}
	for _, n := range []string{"incidents.json", "a-b_c.1", "x"} {
		if err := d.WriteAtomic(n, []byte("x"), 10); err != nil {
			t.Errorf("WriteAtomic(%q): %v", n, err)
		}
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("a", []byte("one"), 100); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteAtomic("a", []byte("two!"), 100); err != nil {
		t.Fatal(err)
	}
	b, err := d.ReadCapped("a", 100)
	if err != nil || string(b) != "two!" {
		t.Fatalf("got %q, %v", b, err)
	}
	fi, err := os.Stat(filepath.Join(p, "a"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	if got := entries(t, p); len(got) != 1 {
		t.Fatalf("leftovers: %v", got)
	}
}

func TestWriteOversizeRefused(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("a", []byte("keep"), 100); err != nil {
		t.Fatal(err)
	}
	err := d.WriteAtomic("a", bytes.Repeat([]byte("x"), 11), 10)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, "a")); string(b) != "keep" {
		t.Fatalf("old content lost: %q", b)
	}
	// Exactly at the cap is fine.
	if err := d.WriteAtomic("b", bytes.Repeat([]byte("x"), 10), 10); err != nil {
		t.Fatal(err)
	}
	if got := entries(t, p); len(got) != 2 {
		t.Fatalf("unexpected entries: %v", got)
	}
}

// Whatever step of a write fails, the old file stays and no temporary file is
// left behind.
func TestWriteFailureKeepsOldContentAndCleansTemp(t *testing.T) {
	boom := errors.New("boom")
	steps := map[string]func(h *hooks){
		"partial write": func(h *hooks) {
			h.write = func(f *os.File, b []byte) (int, error) {
				n, _ := f.Write(b[:len(b)/2])
				return n, boom
			}
		},
		"short write": func(h *hooks) {
			h.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:1]) }
		},
		"sync":    func(h *hooks) { h.sync = func(*os.File) error { return boom } },
		"rename":  func(h *hooks) { h.rename = func(*os.Root, string, string) error { return boom } },
		"tempgen": func(h *hooks) { h.tempName = func() (string, error) { return "", boom } },
	}
	for name, inject := range steps {
		t.Run(name, func(t *testing.T) {
			d, p := newDir(t)
			if err := d.WriteAtomic("a", []byte("old content"), 100); err != nil {
				t.Fatal(err)
			}
			inject(&d.hooks)
			if err := d.WriteAtomic("a", []byte("brand new content"), 100); err == nil {
				t.Fatal("want an error")
			}
			if b, _ := os.ReadFile(filepath.Join(p, "a")); string(b) != "old content" {
				t.Fatalf("old content not preserved: %q", b)
			}
			if got := entries(t, p); len(got) != 1 {
				t.Fatalf("leftover files: %v", got)
			}
		})
	}
}

func TestSyncDirFailureReported(t *testing.T) {
	d, p := newDir(t)
	boom := errors.New("boom")
	d.hooks.syncDir = func(*os.File) error { return boom }
	if err := d.WriteAtomic("a", []byte("x"), 10); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	// The rename already happened; the file is complete and no temp remains.
	if got := entries(t, p); len(got) != 1 || got[0] != "a" {
		t.Fatalf("entries %v", got)
	}
}

func TestStaleTempDoesNotCollideWithRealNames(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, tempPrefix+"0000000000000000"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteAtomic("a", []byte("x"), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadCapped(tempPrefix+"0000000000000000", 10); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("got %v", err)
	}
	// A temp name already taken makes the exclusive create fail, not overwrite.
	d.hooks.tempName = func() (string, error) { return tempPrefix + "0000000000000000", nil }
	if err := d.WriteAtomic("b", []byte("x"), 10); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, tempPrefix+"0000000000000000")); string(b) != "stale" {
		t.Fatalf("existing temp file was touched: %q", b)
	}
}

func TestTempNamesAreDistinctAndPrefixed(t *testing.T) {
	a, _ := randomTempName()
	b, _ := randomTempName()
	if a == b || !strings.HasPrefix(a, tempPrefix) {
		t.Fatalf("%q %q", a, b)
	}
}

func TestReadMissing(t *testing.T) {
	d, _ := newDir(t)
	if _, err := d.ReadCapped("nope", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want ErrNotExist", err)
	}
}

func TestReadSymlinkedFile(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("real", []byte("secret"), 100); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(p, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadCapped("link", 100); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("ReadCapped: got %v, want ErrUntrusted", err)
	}
	if f, _, err := d.OpenAppend("link", 100); !errors.Is(err, ErrUntrusted) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("OpenAppend: got %v, want ErrUntrusted", err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, "real")); string(b) != "secret" {
		t.Fatalf("target was modified: %q", b)
	}
}

// A symlink swapped in between the look at the path and the open is refused.
func TestReadSymlinkSwappedBeforeOpen(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("real", []byte("secret"), 100); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteAtomic("a", []byte("plain"), 100); err != nil {
		t.Fatal(err)
	}
	d.hooks.beforeOpen = func() {
		if err := os.Remove(filepath.Join(p, "a")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(p, "a")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.ReadCapped("a", 100); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestReadNotRegular(t *testing.T) {
	d, p := newDir(t)
	if err := os.Mkdir(filepath.Join(p, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadCapped("sub", 100); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestReadGroupOrOtherWritableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o660, 0o606, 0o666, 0o620} {
		d, p := newDir(t)
		fp := filepath.Join(p, "a")
		if err := os.WriteFile(fp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(fp, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadCapped("a", 10); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("ReadCapped %o: got %v", mode, err)
		}
		if f, _, err := d.OpenAppend("a", 10); !errors.Is(err, ErrUntrusted) {
			if f != nil {
				f.Close()
			}
			t.Fatalf("OpenAppend %o: got %v", mode, err)
		}
	}
	// Group/other read is fine.
	d, p := newDir(t)
	fp := filepath.Join(p, "a")
	if err := os.WriteFile(fp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fp, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadCapped("a", 10); err != nil {
		t.Fatalf("0644: %v", err)
	}
}

func TestReadAndAppendForeignOwner(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.ownerOf = foreign
	if _, err := d.ReadCapped("a", 10); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("ReadCapped: got %v", err)
	}
	if f, _, err := d.OpenAppend("a", 10); !errors.Is(err, ErrUntrusted) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("OpenAppend: got %v", err)
	}
	d.ownerOf = func(fs.FileInfo) (int, error) { return 0, nil }
	if _, err := d.ReadCapped("a", 10); err != nil {
		t.Fatalf("uid 0: %v", err)
	}
}

func TestReadOversize(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "a"), bytes.Repeat([]byte("x"), 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadCapped("a", 10); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	if b, err := d.ReadCapped("a", 11); err != nil || len(b) != 11 {
		t.Fatalf("at the cap: %d bytes, %v", len(b), err)
	}
}

// A file that passes the size check and then grows is cut by the read cap.
func TestReadGrowsAfterSizeCheck(t *testing.T) {
	d, p := newDir(t)
	fp := filepath.Join(p, "a")
	if err := os.WriteFile(fp, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.hooks.afterStat = func() {
		if err := os.WriteFile(fp, bytes.Repeat([]byte("x"), 50), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := d.ReadCapped("a", 20)
	if !errors.Is(err, ErrTooLarge) || b != nil {
		t.Fatalf("got %d bytes, %v", len(b), err)
	}
}

func TestOpenAppend(t *testing.T) {
	d, p := newDir(t)
	f, size, err := d.OpenAppend("audit", 100)
	if err != nil || size != 0 {
		t.Fatalf("new: size %d, %v", size, err)
	}
	if _, err := f.WriteString("line1\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	fi, err := os.Stat(filepath.Join(p, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want 0600", fi.Mode().Perm())
	}
	f, size, err = d.OpenAppend("audit", 100)
	if err != nil || size != 6 {
		t.Fatalf("existing: size %d, %v", size, err)
	}
	if _, err := f.WriteString("line2\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if b, _ := os.ReadFile(filepath.Join(p, "audit")); string(b) != "line1\nline2\n" {
		t.Fatalf("content %q", b)
	}
}

func TestOpenAppendOversizeExisting(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "audit"), bytes.Repeat([]byte("x"), 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := d.OpenAppend("audit", 10); !errors.Is(err, ErrTooLarge) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("got %v, want ErrTooLarge", err)
	}
	f, size, err := d.OpenAppend("audit", 11)
	if err != nil || size != 11 {
		t.Fatalf("at the cap: %d, %v", size, err)
	}
	f.Close()
}

// A symlink planted after the path was seen to be absent is refused by the
// open itself (no earlier look to compare with), and its target is untouched.
func TestOpenAppendSymlinkPlantedBeforeCreate(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("real", []byte("secret"), 100); err != nil {
		t.Fatal(err)
	}
	d.hooks.beforeOpen = func() {
		if err := os.Symlink("real", filepath.Join(p, "audit")); err != nil {
			t.Fatal(err)
		}
	}
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, "real")); string(b) != "secret" {
		t.Fatalf("target was modified: %q", b)
	}
}
