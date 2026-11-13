package securefile

import (
	"bytes"
	"errors"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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

// A symlink planted after the path was seen to be absent is not stopped by the
// open (os.Root follows an in-directory link); the look after the open refuses
// it, and the target's content is untouched.
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

func TestOpenDirPathForms(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link + "/", link + "/.", link + "//"} {
		if d, err := OpenDir(p, false, nil); !errors.Is(err, ErrUntrusted) {
			if d != nil {
				d.Close()
			}
			t.Errorf("%q: got %v, want ErrUntrusted", p, err)
		}
	}
	for _, p := range []string{"rel/dir", "", ".", "/", "//", "/."} {
		for _, create := range []bool{false, true} {
			if d, err := OpenDir(p, create, nil); err == nil {
				d.Close()
				t.Errorf("%q create=%v: accepted", p, create)
			}
		}
	}
	// A messy but real path is cleaned and stored cleaned.
	d, err := OpenDir(real+"/./", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Path() != real {
		t.Fatalf("Path() = %q, want %q", d.Path(), real)
	}
}

func withTimeout(t *testing.T, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("%s blocked", what)
		return nil
	}
}

func TestFIFOAndDirectoryEntries(t *testing.T) {
	d, p := newDir(t)
	if err := syscall.Mkfifo(filepath.Join(p, "fifo"), 0o600); err != nil {
		t.Skip(err)
	}
	if err := os.Mkdir(filepath.Join(p, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	opened := false
	d.hooks.beforeOpen = func() { opened = true }
	defer func() {
		if opened {
			t.Error("an existing non-regular entry was opened, not refused at the first look")
		}
	}()
	for _, n := range []string{"fifo", "sub"} {
		err := withTimeout(t, "OpenAppend "+n, func() error {
			f, _, err := d.OpenAppend(n, 100)
			if f != nil {
				f.Close()
			}
			return err
		})
		if !errors.Is(err, ErrUntrusted) {
			t.Errorf("OpenAppend %s: got %v, want ErrUntrusted", n, err)
		}
		err = withTimeout(t, "ReadCapped "+n, func() error { _, err := d.ReadCapped(n, 100); return err })
		if !errors.Is(err, ErrUntrusted) {
			t.Errorf("ReadCapped %s: got %v, want ErrUntrusted", n, err)
		}
	}
}

// A FIFO swapped in after the first look must not block the open.
func TestFIFOSwappedBeforeOpen(t *testing.T) {
	for _, op := range []string{"read", "append"} {
		t.Run(op, func(t *testing.T) {
			d, p := newDir(t)
			if err := d.WriteAtomic("a", []byte("x"), 10); err != nil {
				t.Fatal(err)
			}
			d.hooks.beforeOpen = func() {
				fp := filepath.Join(p, "a")
				if err := os.Remove(fp); err != nil {
					t.Error(err)
					return
				}
				if err := syscall.Mkfifo(fp, 0o600); err != nil {
					t.Error(err)
				}
			}
			err := withTimeout(t, op, func() error {
				if op == "read" {
					_, err := d.ReadCapped("a", 10)
					return err
				}
				f, _, err := d.OpenAppend("a", 10)
				if f != nil {
					f.Close()
				}
				return err
			})
			if !errors.Is(err, ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
	}
}

// A reader racing atomic replaces sees one complete version and never a trust
// error.
func TestConcurrentReplaceAndRead(t *testing.T) {
	d, _ := newDir(t)
	versions := map[string]bool{}
	var vs [3][]byte
	for i := range vs {
		vs[i] = bytes.Repeat([]byte{byte('a' + i)}, 4096)
		versions[string(vs[i])] = true
	}
	if err := d.WriteAtomic("a", vs[0], 1<<20); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			if err := d.WriteAtomic("a", vs[i%3], 1<<20); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	var reads, changed int
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		b, err := d.ReadCapped("a", 1<<20)
		switch {
		case errors.Is(err, ErrUntrusted):
			t.Fatalf("benign replace reported as untrusted: %v", err)
		case errors.Is(err, ErrChanged):
			changed++
		case err != nil:
			t.Fatal(err)
		case !versions[string(b)]:
			t.Fatalf("incomplete or mixed read of %d bytes", len(b))
		default:
			reads++
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d reads, %d ErrChanged", reads, changed)
	if reads == 0 {
		t.Fatal("no read succeeded")
	}
}

func replaceFile(t *testing.T, p, name, content string) {
	t.Helper()
	tmp := filepath.Join(p, "swap-"+name)
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(p, name)); err != nil {
		t.Fatal(err)
	}
}

// A file replaced once while it is being opened is read on the next attempt.
func TestReplacedOnceIsRetried(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("a", []byte("old"), 10); err != nil {
		t.Fatal(err)
	}
	n := 0
	d.hooks.afterOpen = func() {
		if n++; n == 1 {
			replaceFile(t, p, "a", "new")
		}
	}
	b, err := d.ReadCapped("a", 10)
	if err != nil || string(b) != "new" {
		t.Fatalf("got %q, %v", b, err)
	}
}

// A file replaced on every attempt yields ErrChanged, which is not a trust
// error.
func TestReplacedEveryTimeIsErrChanged(t *testing.T) {
	d, p := newDir(t)
	if err := d.WriteAtomic("a", []byte("old"), 10); err != nil {
		t.Fatal(err)
	}
	n := 0
	d.hooks.afterOpen = func() { n++; replaceFile(t, p, "a", "new") }
	_, err := d.ReadCapped("a", 10)
	if !errors.Is(err, ErrChanged) || errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrChanged only", err)
	}
	if n != openAttempts {
		t.Fatalf("%d attempts, want %d", n, openAttempts)
	}
}

func TestMaxSizeBounds(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "a"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, m := range []int64{-1, math.MinInt64, math.MaxInt64} {
		if err := d.WriteAtomic("w", []byte("x"), m); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("WriteAtomic %d: %v", m, err)
		}
		if _, err := d.ReadCapped("a", m); !errors.Is(err, ErrInvalidSize) {
			t.Errorf("ReadCapped %d: %v", m, err)
		}
		if f, _, err := d.OpenAppend("new", m); !errors.Is(err, ErrInvalidSize) {
			if f != nil {
				f.Close()
			}
			t.Errorf("OpenAppend %d: %v", m, err)
		}
	}
	if got := entries(t, p); len(got) != 1 {
		t.Fatalf("entries after refused sizes: %v", got)
	}
	// 0 and MaxInt64-1 are valid.
	if err := d.WriteAtomic("z", nil, 0); err != nil {
		t.Errorf("WriteAtomic cap 0: %v", err)
	}
	if b, err := d.ReadCapped("a", math.MaxInt64-1); err != nil || string(b) != "12345" {
		t.Errorf("ReadCapped big cap: %q, %v", b, err)
	}
}

func TestOpenAppendCreatedFileCleanup(t *testing.T) {
	d, p := newDir(t)
	// A created file that fails the owner check is removed again.
	d.ownerOf = foreign
	if f, _, err := d.OpenAppend("audit", 10); !errors.Is(err, ErrUntrusted) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if got := entries(t, p); len(got) != 0 {
		t.Fatalf("created file left behind: %v", got)
	}
	// An existing file that fails the check is kept.
	if err := os.WriteFile(filepath.Join(p, "old"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f, _, err := d.OpenAppend("old", 10); !errors.Is(err, ErrUntrusted) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("got %v", err)
	}
	if got := entries(t, p); len(got) != 1 {
		t.Fatalf("existing file removed: %v", got)
	}
}

func TestOpenAppendSyncsDirAfterCreate(t *testing.T) {
	d, _ := newDir(t)
	synced := 0
	d.hooks.syncDir = func(f *os.File) error { synced++; return f.Sync() }
	f, _, err := d.OpenAppend("audit", 10)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if synced != 1 {
		t.Fatalf("dir synced %d times after create, want 1", synced)
	}
	f, _, err = d.OpenAppend("audit", 10)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if synced != 1 {
		t.Fatalf("dir synced for an existing file")
	}
	d.hooks.syncDir = func(*os.File) error { return errors.New("boom") }
	if f, _, err := d.OpenAppend("audit2", 10); err == nil {
		f.Close()
		t.Fatal("want the sync error")
	}
}

// A link that leaves the directory, planted after the first look, is a trust
// failure.
func TestEscapingLinkPlantedBeforeOpen(t *testing.T) {
	d, p := newDir(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("o"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := d.WriteAtomic("a", []byte("x"), 10); err != nil {
		t.Fatal(err)
	}
	d.hooks.beforeOpen = func() {
		_ = os.Remove(filepath.Join(p, "a"))
		_ = os.Symlink(outside, filepath.Join(p, "a"))
	}
	if _, err := d.ReadCapped("a", 10); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

func TestTempPrefixExported(t *testing.T) {
	if TempPrefix != tempPrefix || !strings.HasPrefix(TempPrefix, ".") {
		t.Fatalf("TempPrefix %q", TempPrefix)
	}
}

// A file someone else created after the first look is never removed by the
// cleanup of a failed check, even though this call asked to create it.
func TestForeignCreatedFileIsKept(t *testing.T) {
	d, p := newDir(t)
	fp := filepath.Join(p, "audit")
	n := 0
	d.hooks.beforeOpen = func() {
		if n++; n == 1 {
			if err := os.WriteFile(fp, []byte("theirs"), 0o666); err != nil {
				t.Error(err)
			}
			if err := os.Chmod(fp, 0o666); err != nil {
				t.Error(err)
			}
		}
	}
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if b, rerr := os.ReadFile(fp); rerr != nil || string(b) != "theirs" {
		t.Fatalf("their file was removed or changed: %q, %v", b, rerr)
	}
}

// A dangling link planted after the first look does not make the create go
// through it.
func TestDanglingLinkNotCreatedThrough(t *testing.T) {
	d, p := newDir(t)
	d.hooks.beforeOpen = func() {
		_ = os.Symlink("victim", filepath.Join(p, "audit"))
	}
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if _, serr := os.Lstat(filepath.Join(p, "victim")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("link target was created: %v", serr)
	}
}

// A file created by this call and replaced before the cleanup keeps the
// replacement.
func TestCreatedFileReplacedBeforeCleanupIsKept(t *testing.T) {
	d, p := newDir(t)
	d.ownerOf = foreign
	d.hooks.afterOpen = func() { replaceFile(t, p, "audit", "replacement") }
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if b, rerr := os.ReadFile(filepath.Join(p, "audit")); rerr != nil || string(b) != "replacement" {
		t.Fatalf("replacement removed: %q, %v", b, rerr)
	}
}

// A link to itself planted after the first look is a trust failure.
func TestSelfLinkPlantedBeforeOpen(t *testing.T) {
	for _, op := range []string{"read", "append"} {
		t.Run(op, func(t *testing.T) {
			d, p := newDir(t)
			if err := d.WriteAtomic("a", []byte("x"), 10); err != nil {
				t.Fatal(err)
			}
			d.hooks.beforeOpen = func() {
				_ = os.Remove(filepath.Join(p, "a"))
				_ = os.Symlink("a", filepath.Join(p, "a"))
			}
			var err error
			if op == "read" {
				_, err = d.ReadCapped("a", 10)
			} else {
				var f *os.File
				f, _, err = d.OpenAppend("a", 10)
				if f != nil {
					f.Close()
				}
			}
			if !errors.Is(err, ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
	}
}

func TestOpenAppendRetriedAfterReplaceOrRemoval(t *testing.T) {
	t.Run("replace", func(t *testing.T) {
		d, p := newDir(t)
		if err := os.WriteFile(filepath.Join(p, "audit"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		n := 0
		d.hooks.afterOpen = func() {
			if n++; n == 1 {
				replaceFile(t, p, "audit", "newer!")
			}
		}
		f, size, err := d.OpenAppend("audit", 100)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if size != 6 || n != 2 {
			t.Fatalf("size %d after %d attempts, want 6 after 2", size, n)
		}
	})
	t.Run("removal", func(t *testing.T) {
		d, p := newDir(t)
		if err := os.WriteFile(filepath.Join(p, "audit"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		n := 0
		d.hooks.afterOpen = func() {
			if n++; n == 1 {
				_ = os.Remove(filepath.Join(p, "audit"))
			}
		}
		f, size, err := d.OpenAppend("audit", 100)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if size != 0 || n != 2 {
			t.Fatalf("size %d after %d attempts, want 0 after 2", size, n)
		}
		if _, serr := os.Stat(filepath.Join(p, "audit")); serr != nil {
			t.Fatal(serr)
		}
	})
}

// An existing file swapped for a dangling link after the first look is not
// opened through: the link target is not created.
func TestExistingSwappedForDanglingLink(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "audit"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.hooks.beforeOpen = func() {
		_ = os.Remove(filepath.Join(p, "audit"))
		_ = os.Symlink("victim", filepath.Join(p, "audit"))
	}
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
	if _, serr := os.Lstat(filepath.Join(p, "victim")); !errors.Is(serr, fs.ErrNotExist) {
		t.Fatalf("link target was created: %v", serr)
	}
}

// An existing file renamed away after the first look is created anew,
// exclusively, with one directory flush.
func TestExistingRenamedAwayIsCreated(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "audit"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := 0
	d.hooks.beforeOpen = func() {
		if n++; n == 1 {
			_ = os.Rename(filepath.Join(p, "audit"), filepath.Join(p, "moved"))
		}
	}
	synced := 0
	d.hooks.syncDir = func(f *os.File) error { synced++; return f.Sync() }
	f, size, err := d.OpenAppend("audit", 100)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if size != 0 || synced != 1 {
		t.Fatalf("size %d, %d flushes; want 0 and 1", size, synced)
	}
}

// A directory swapped in after the first look is refused when appending.
func TestDirectorySwappedBeforeAppend(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "audit"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.hooks.beforeOpen = func() {
		_ = os.Remove(filepath.Join(p, "audit"))
		_ = os.Mkdir(filepath.Join(p, "audit"), 0o700)
	}
	f, _, err := d.OpenAppend("audit", 100)
	if f != nil {
		f.Close()
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("got %v, want ErrUntrusted", err)
	}
}

// A trusted file that appears between the look and the exclusive create is
// taken as it is, with its size, and no directory flush.
func TestFileAppearsBeforeExclusiveCreate(t *testing.T) {
	d, p := newDir(t)
	n := 0
	d.hooks.beforeOpen = func() {
		if n++; n == 1 {
			_ = os.WriteFile(filepath.Join(p, "audit"), []byte("theirs"), 0o600)
		}
	}
	synced := 0
	d.hooks.syncDir = func(f *os.File) error { synced++; return f.Sync() }
	f, size, err := d.OpenAppend("audit", 100)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if size != 6 || synced != 0 {
		t.Fatalf("size %d, %d flushes; want 6 and 0", size, synced)
	}
}

// A unix socket swapped in after the first look is refused for read and
// append (opening it fails with a different errno per platform).
func TestSocketSwappedBeforeOpen(t *testing.T) {
	for _, op := range []string{"read", "append"} {
		t.Run(op, func(t *testing.T) {
			// A unix socket path is limited to about 100 bytes, so use a short
			// base directory instead of the test's temporary one.
			base, err := os.MkdirTemp("/tmp", "kw")
			if err != nil {
				t.Skip(err)
			}
			t.Cleanup(func() { os.RemoveAll(base) })
			p := filepath.Join(base, "s")
			d, err := OpenDir(p, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { d.Close() })
			if err := d.WriteAtomic("a", []byte("x"), 10); err != nil {
				t.Fatal(err)
			}
			var l net.Listener
			d.hooks.beforeOpen = func() {
				_ = os.Remove(filepath.Join(p, "a"))
				var err error
				l, err = net.Listen("unix", filepath.Join(p, "a"))
				if err != nil {
					t.Error(err)
				}
			}
			defer func() {
				if l != nil {
					l.Close()
				}
			}()
			if op == "read" {
				_, err = d.ReadCapped("a", 10)
			} else {
				var f *os.File
				f, _, err = d.OpenAppend("a", 10)
				if f != nil {
					f.Close()
				}
			}
			if !errors.Is(err, ErrUntrusted) {
				t.Fatalf("got %v, want ErrUntrusted", err)
			}
		})
	}
}
