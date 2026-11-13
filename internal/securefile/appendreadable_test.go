package securefile

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type openFn func(d *Dir, name string, maxSize int64) (*os.File, int64, error)

// appendOpens are the two ways to open for appending. They share one code
// path, so every refusal case below runs against both.
var appendOpens = map[string]openFn{
	"OpenAppend":         (*Dir).OpenAppend,
	"OpenAppendReadable": (*Dir).OpenAppendReadable,
}

func eachAppendOpen(t *testing.T, fn func(t *testing.T, open openFn)) {
	t.Helper()
	for name, open := range appendOpens {
		t.Run(name, func(t *testing.T) { fn(t, open) })
	}
}

// closeIf closes f when the open returned one, so a refusal that wrongly
// succeeded does not leak a descriptor.
func closeIf(f *os.File) {
	if f != nil {
		f.Close()
	}
}

func TestOpenAppendReadableReadsWhatItAppendsTo(t *testing.T) {
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "audit"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, size, err := d.OpenAppendReadable("audit", 100)
	if err != nil || size != 10 {
		t.Fatalf("size %d, %v", size, err)
	}
	defer f.Close()
	buf := make([]byte, 4)
	if n, err := f.ReadAt(buf, 3); err != nil || n != 4 || string(buf) != "3456" {
		t.Fatalf("ReadAt: %q, %d, %v", buf[:n], n, err)
	}
	// Reading does not move where the writes go: they land at the end.
	if _, err := f.Seek(2, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(p, "audit")); string(b) != "0123456789ab" {
		t.Fatalf("content %q", b)
	}
	// What was appended is readable through the same descriptor.
	tail := make([]byte, 2)
	if _, err := f.ReadAt(tail, 10); err != nil || string(tail) != "ab" {
		t.Fatalf("tail %q, %v", tail, err)
	}
}

func TestOpenAppendReadableCreatesPrivateFile(t *testing.T) {
	d, p := newDir(t)
	f, size, err := d.OpenAppendReadable("audit", 100)
	if err != nil || size != 0 {
		t.Fatalf("size %d, %v", size, err)
	}
	f.Close()
	fi, err := os.Stat(filepath.Join(p, "audit"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
}

func TestOpenAppendReadableNotWritableOnlyAccess(t *testing.T) {
	// The plain OpenAppend descriptor cannot be read, the readable one can.
	d, p := newDir(t)
	if err := os.WriteFile(filepath.Join(p, "a"), []byte("xy"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, _, err := d.OpenAppend("a", 10)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("the write-only descriptor was readable")
	}
}

func TestAppendOpensNameValidation(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		for _, n := range []string{"", ".", "..", "a/b", ".hidden", ".kwtmp-1", `a\b`, "a\x00b"} {
			f, _, err := open(d, n, 10)
			closeIf(f)
			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("%q: got %v", n, err)
			}
		}
		if got := entries(t, p); len(got) != 0 {
			t.Fatalf("directory not empty after refused names: %v", got)
		}
	})
}

func TestAppendOpensSizeBounds(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		for _, m := range []int64{-1, 1<<63 - 1} {
			f, _, err := open(d, "new", m)
			closeIf(f)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("%d: %v", m, err)
			}
		}
		if got := entries(t, p); len(got) != 0 {
			t.Fatalf("entries after refused sizes: %v", got)
		}
	})
}

func TestAppendOpensOversizeExisting(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		if err := os.WriteFile(filepath.Join(p, "audit"), []byte("12345678901"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, _, err := open(d, "audit", 10)
		closeIf(f)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("got %v, want ErrTooLarge", err)
		}
		f, size, err := open(d, "audit", 11)
		if err != nil || size != 11 {
			t.Fatalf("at the cap: %d, %v", size, err)
		}
		f.Close()
	})
}

func TestAppendOpensRefuseSymlinkAndNonRegular(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		if err := d.WriteAtomic("real", []byte("secret"), 100); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(p, "link")); err != nil {
			t.Skip(err)
		}
		if err := os.Mkdir(filepath.Join(p, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		fifo := syscall.Mkfifo(filepath.Join(p, "fifo"), 0o600)
		names := []string{"link", "sub"}
		if fifo == nil {
			names = append(names, "fifo")
		}
		for _, n := range names {
			err := withTimeout(t, n, func() error {
				f, _, err := open(d, n, 100)
				closeIf(f)
				return err
			})
			if !errors.Is(err, ErrUntrusted) {
				t.Errorf("%s: got %v, want ErrUntrusted", n, err)
			}
		}
		if b, _ := os.ReadFile(filepath.Join(p, "real")); string(b) != "secret" {
			t.Fatalf("target was modified: %q", b)
		}
	})
}

func TestAppendOpensRefuseGroupOrOtherWritable(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		for _, mode := range []os.FileMode{0o660, 0o606, 0o666, 0o620} {
			d, p := newDir(t)
			fp := filepath.Join(p, "a")
			if err := os.WriteFile(fp, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(fp, mode); err != nil {
				t.Fatal(err)
			}
			f, _, err := open(d, "a", 10)
			closeIf(f)
			if !errors.Is(err, ErrUntrusted) {
				t.Fatalf("%o: got %v", mode, err)
			}
		}
	})
}

func TestAppendOpensRefuseForeignOwnerAndCleanUp(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		d.ownerOf = foreign
		// A file this call created is removed again.
		f, _, err := open(d, "audit", 10)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
		if got := entries(t, p); len(got) != 0 {
			t.Fatalf("created file left behind: %v", got)
		}
		// An existing file that fails the check is kept.
		if err := os.WriteFile(filepath.Join(p, "old"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		f, _, err = open(d, "old", 10)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v", err)
		}
		if got := entries(t, p); len(got) != 1 {
			t.Fatalf("existing file removed: %v", got)
		}
	})
}

func TestAppendOpensSyncDirAfterCreateOnly(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, _ := newDir(t)
		synced := 0
		d.hooks.syncDir = func(f *os.File) error { synced++; return f.Sync() }
		for i := 0; i < 2; i++ {
			f, _, err := open(d, "audit", 10)
			if err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
		if synced != 1 {
			t.Fatalf("dir synced %d times, want 1 (the create only)", synced)
		}
		d.hooks.syncDir = func(*os.File) error { return errors.New("boom") }
		f, _, err := open(d, "audit2", 10)
		closeIf(f)
		if err == nil {
			t.Fatal("want the sync error")
		}
	})
}

func TestAppendOpensSymlinkPlantedBeforeCreate(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		if err := d.WriteAtomic("real", []byte("secret"), 100); err != nil {
			t.Fatal(err)
		}
		d.hooks.beforeOpen = func() {
			_ = os.Symlink("real", filepath.Join(p, "audit"))
		}
		f, _, err := open(d, "audit", 100)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
		if b, _ := os.ReadFile(filepath.Join(p, "real")); string(b) != "secret" {
			t.Fatalf("target was modified: %q", b)
		}
	})
}

func TestAppendOpensDanglingLinkNotCreatedThrough(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		d.hooks.beforeOpen = func() {
			_ = os.Symlink("victim", filepath.Join(p, "audit"))
		}
		f, _, err := open(d, "audit", 100)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
		if _, serr := os.Lstat(filepath.Join(p, "victim")); !errors.Is(serr, fs.ErrNotExist) {
			t.Fatalf("link target was created: %v", serr)
		}
	})
}

func TestAppendOpensForeignCreatedFileIsKept(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		fp := filepath.Join(p, "audit")
		n := 0
		d.hooks.beforeOpen = func() {
			if n++; n == 1 {
				_ = os.WriteFile(fp, []byte("theirs"), 0o666)
				_ = os.Chmod(fp, 0o666)
			}
		}
		f, _, err := open(d, "audit", 100)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
		if b, rerr := os.ReadFile(fp); rerr != nil || string(b) != "theirs" {
			t.Fatalf("their file was removed or changed: %q, %v", b, rerr)
		}
	})
}

func TestAppendOpensRetriedAfterReplaceOrRemoval(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
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
		f, size, err := open(d, "audit", 100)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if size != 6 || n != 2 {
			t.Fatalf("replace: size %d after %d attempts, want 6 after 2", size, n)
		}

		n = 0
		d.hooks.afterOpen = func() {
			if n++; n == 1 {
				_ = os.Remove(filepath.Join(p, "audit"))
			}
		}
		f, size, err = open(d, "audit", 100)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		if size != 0 || n != 2 {
			t.Fatalf("removal: size %d after %d attempts, want 0 after 2", size, n)
		}
	})
}

func TestAppendOpensDirectorySwappedBeforeOpen(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		if err := os.WriteFile(filepath.Join(p, "audit"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		d.hooks.beforeOpen = func() {
			_ = os.Remove(filepath.Join(p, "audit"))
			_ = os.Mkdir(filepath.Join(p, "audit"), 0o700)
		}
		f, _, err := open(d, "audit", 100)
		closeIf(f)
		if !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrUntrusted", err)
		}
	})
}

func TestAppendOpensKeepChangingIsRetryable(t *testing.T) {
	eachAppendOpen(t, func(t *testing.T, open openFn) {
		d, p := newDir(t)
		if err := os.WriteFile(filepath.Join(p, "audit"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		d.hooks.afterOpen = func() { replaceFile(t, p, "audit", "again") }
		f, _, err := open(d, "audit", 100)
		closeIf(f)
		if !errors.Is(err, ErrChanged) || errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v, want ErrChanged and not ErrUntrusted", err)
		}
	})
}
