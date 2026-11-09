//go:build unix

package probes_test

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
)

// A tree of the shape of a home directory: the user owns everything.
func homeTree(t *testing.T) (home, outside string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home = filepath.Join(base, "home")
	outside = filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(home, ".ssh"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(home, ".ssh", "authorized_keys"), "key\n")
	writeFile(t, filepath.Join(outside, "secret"), "secret\n")
	return home, outside
}

func me() uint32 { return uint32(os.Getuid()) }

// otherUID is a user id that is neither the owner of the test files nor root.
func otherUID() uint32 {
	if me() == 1 {
		return 2
	}
	return me() + 1
}

func link(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

func TestReadHomeFileRegular(t *testing.T) {
	home, _ := homeTree(t)
	b, err := probes.OSFS{}.ReadHomeFile(home, me(), ".ssh/authorized_keys", 100)
	if err != nil || string(b) != "key\n" {
		t.Fatalf("got %q, %v", b, err)
	}
	// a link that stays inside the home is followed
	link(t, "authorized_keys", filepath.Join(home, ".ssh", "ak2"))
	if b, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh/ak2", 100); err != nil || string(b) != "key\n" {
		t.Fatalf("inner link: %q, %v", b, err)
	}
	link(t, ".ssh", filepath.Join(home, "dotssh"))
	if b, err := (probes.OSFS{}).ReadHomeFile(home, me(), "dotssh/authorized_keys", 100); err != nil || string(b) != "key\n" {
		t.Fatalf("inner directory link: %q, %v", b, err)
	}
	// at the cap and beyond it
	if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh/authorized_keys", 4); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh/authorized_keys", 3); !errors.Is(err, probes.ErrTooLarge) {
		t.Fatalf("over the cap: %v", err)
	}
}

func TestReadHomeFileCannotLeaveTheHome(t *testing.T) {
	home, outside := homeTree(t)
	link(t, "../outside", filepath.Join(home, "out"))                         // directory link out
	link(t, "../outside/secret", filepath.Join(home, "secret-link"))          // file link out
	link(t, filepath.Join(outside, "secret"), filepath.Join(home, "abs"))     // absolute link
	link(t, filepath.Join(home, ".ssh"), filepath.Join(home, "abs-inside"))   // absolute link that points back in
	link(t, "../../outside", filepath.Join(home, ".ssh", "up"))               // from a subdirectory
	link(t, "../../outside/secret", filepath.Join(home, ".ssh", "up-secret")) // two levels
	link(t, "loop", filepath.Join(home, "loop"))
	cases := []string{
		"out/secret", "secret-link", "abs", "abs-inside/authorized_keys", ".ssh/up/secret", ".ssh/up-secret",
		"../outside/secret", ".ssh/../../outside/secret", "loop",
	}
	for _, rel := range cases {
		t.Run(rel, func(t *testing.T) {
			b, err := probes.OSFS{}.ReadHomeFile(home, me(), rel, 100)
			if err == nil {
				t.Fatalf("read %q through %s", b, rel)
			}
			if strings.Contains(string(b), "secret") {
				t.Fatalf("content leaked: %q", b)
			}
			if errors.Is(err, fs.ErrNotExist) && rel != "loop" {
				t.Fatalf("an escape must not look like a missing file: %v", err)
			}
		})
	}
	t.Run("the error says the path escapes", func(t *testing.T) {
		_, err := probes.OSFS{}.ReadHomeFile(home, me(), "out/secret", 100)
		if err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("an absolute or empty relative path is refused", func(t *testing.T) {
		for _, rel := range []string{"", filepath.Join(outside, "secret")} {
			if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), rel, 100); !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("%q: %v", rel, err)
			}
		}
		if _, err := (probes.OSFS{}).ReadHomeFile("relative/home", me(), "x", 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("relative home: %v", err)
		}
	})
}

func TestReadHomeFileRefusesWhatIsNotAFile(t *testing.T) {
	home, _ := homeTree(t)
	t.Run("directory", func(t *testing.T) {
		if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh", 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("FIFO without a writer does not block", func(t *testing.T) {
		if err := syscall.Mkfifo(filepath.Join(home, ".ssh", "fifo"), 0o600); err != nil {
			t.Skipf("no FIFO here: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := probes.OSFS{}.ReadHomeFile(home, me(), ".ssh/fifo", 100)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked on a FIFO")
		}
	})
	t.Run("FIFO that someone is writing to is not read", func(t *testing.T) {
		path := filepath.Join(home, ".ssh", "fifo2")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("no FIFO here: %v", err)
		}
		w, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		_, _ = w.WriteString("data\n")
		done := make(chan error, 1)
		go func() {
			_, err := probes.OSFS{}.ReadHomeFile(home, me(), ".ssh/fifo2", 100)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("err = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked on a FIFO")
		}
	})
	t.Run("socket", func(t *testing.T) {
		path := filepath.Join(home, ".ssh", "sock")
		l, err := net.Listen("unix", path)
		if err != nil {
			t.Skipf("no unix socket here: %v", err)
		}
		defer l.Close()
		if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh/sock", 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("device node is never opened", func(t *testing.T) {
		// /dev is not a home, but the reader works on any directory
		if _, err := os.Stat("/dev/null"); err != nil {
			t.Skip("no /dev/null")
		}
		if _, err := (probes.OSFS{}).ReadHomeFile("/dev", 0, "null", 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing file, missing directory, missing home", func(t *testing.T) {
		for _, c := range [][2]string{{home, ".ssh/none"}, {home, "nodir/none"}, {filepath.Join(home, "gone"), "x"}} {
			if _, err := (probes.OSFS{}).ReadHomeFile(c[0], me(), c[1], 100); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%v: err = %v", c, err)
			}
		}
	})
	t.Run("a file below a file", func(t *testing.T) {
		_, err := probes.OSFS{}.ReadHomeFile(home, me(), ".ssh/authorized_keys/x", 100)
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReadHomeFileOwner(t *testing.T) {
	home, _ := homeTree(t)
	path := filepath.Join(home, ".ssh", "authorized_keys")
	t.Run("owned by somebody else than the user", func(t *testing.T) {
		_, err := probes.OSFS{}.ReadHomeFile(home, otherUID(), ".ssh/authorized_keys", 100)
		if me() == 0 {
			// root owns the file: root is always accepted
			if err != nil {
				t.Fatalf("root-owned: %v", err)
			}
			return
		}
		if !errors.Is(err, probes.ErrUnsafe) || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("err = %v", err)
		}
	})
	if me() == 0 {
		t.Run("owned by a third user while root runs the check", func(t *testing.T) {
			if err := os.Chown(path, 4242, 4242); err != nil {
				t.Skipf("cannot chown: %v", err)
			}
			if _, err := (probes.OSFS{}).ReadHomeFile(home, 1000, ".ssh/authorized_keys", 100); !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("err = %v", err)
			}
			if _, err := (probes.OSFS{}).ReadHomeFile(home, 4242, ".ssh/authorized_keys", 100); err != nil {
				t.Fatalf("owned by the user: %v", err)
			}
		})
	} else {
		t.Run("owned by the user", func(t *testing.T) {
			if _, err := (probes.OSFS{}).ReadHomeFile(home, me(), ".ssh/authorized_keys", 100); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// trustedFS treats the current user as root and checks the directories from
// base down; the real thing checks from "/".
func trustedFS(t *testing.T, base string) probes.OSFS {
	return probes.OSFS{TrustedOwners: []uint32{me()}, CheckFrom: base}
}

// osfsFrom is an OSFS with root as the only trusted owner that checks from base.
func osfsFrom(base string) probes.OSFS { return probes.OSFS{CheckFrom: base} }

func certTree(t *testing.T) (base string) {
	t.Helper()
	b, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"live/example", "archive/example"} {
		if err := os.MkdirAll(filepath.Join(b, d), 0o755); err != nil {
			t.Fatal(err)
		}
		// MkdirAll applies the umask
		for p := filepath.Join(b, d); p != b; p = filepath.Dir(p) {
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(b, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(b, "archive/example/fullchain1.pem")
	writeFile(t, f, "pem\n")
	if err := os.Chmod(f, 0o644); err != nil {
		t.Fatal(err)
	}
	link(t, "../../archive/example/fullchain1.pem", filepath.Join(b, "live/example/fullchain.pem"))
	return b
}

func TestReadTrusted(t *testing.T) {
	t.Run("a plain file", func(t *testing.T) {
		b := certTree(t)
		got, resolved, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "archive/example/fullchain1.pem"), 100)
		if err != nil || string(got) != "pem\n" || resolved != filepath.Join(b, "archive/example/fullchain1.pem") {
			t.Fatalf("%q %q %v", got, resolved, err)
		}
	})
	t.Run("a Let's Encrypt style link is followed", func(t *testing.T) {
		b := certTree(t)
		got, resolved, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/fullchain.pem"), 100)
		if err != nil || string(got) != "pem\n" || resolved != filepath.Join(b, "archive/example/fullchain1.pem") {
			t.Fatalf("%q %q %v", got, resolved, err)
		}
	})
	t.Run("size cap", func(t *testing.T) {
		b := certTree(t)
		p := filepath.Join(b, "live/example/fullchain.pem")
		if _, _, err := trustedFS(t, b).ReadTrusted(p, 4); err != nil {
			t.Fatalf("at the cap: %v", err)
		}
		if _, _, err := trustedFS(t, b).ReadTrusted(p, 3); !errors.Is(err, probes.ErrTooLarge) {
			t.Fatalf("over the cap: %v", err)
		}
	})
	t.Run("missing and dangling", func(t *testing.T) {
		b := certTree(t)
		link(t, "nowhere", filepath.Join(b, "live/example/dangling.pem"))
		for _, p := range []string{"live/example/none.pem", "live/example/dangling.pem", "nodir/x"} {
			if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, p), 100); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("%s: %v", p, err)
			}
		}
	})
	t.Run("a relative path", func(t *testing.T) {
		if _, _, err := (probes.OSFS{}).ReadTrusted("x/y", 10); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatal(err)
		}
	})
	t.Run("a directory and special files", func(t *testing.T) {
		b := certTree(t)
		if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live"), 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("directory: %v", err)
		}
		fifo := filepath.Join(b, "archive/example/fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Skip("no FIFO here")
		}
		done := make(chan error, 1)
		go func() {
			_, _, err := trustedFS(t, b).ReadTrusted(fifo, 100)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("fifo: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked on a FIFO")
		}
	})
	t.Run("a file nobody trusts", func(t *testing.T) {
		b := certTree(t)
		o := probes.OSFS{TrustedOwners: []uint32{otherUID()}, CheckFrom: b}
		_, _, err := o.ReadTrusted(filepath.Join(b, "archive/example/fullchain1.pem"), 100)
		if !errors.Is(err, probes.ErrUnsafe) || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the default owner is root", func(t *testing.T) {
		b := certTree(t)
		_, _, err := probes.OSFS{CheckFrom: b}.ReadTrusted(filepath.Join(b, "archive/example/fullchain1.pem"), 100)
		if me() == 0 {
			if err != nil {
				t.Fatalf("root-owned tree: %v", err)
			}
			return
		}
		if !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("a tree owned by %d must not be trusted: %v", me(), err)
		}
	})
	writable := map[string]os.FileMode{"group-writable": 0o775, "world-writable": 0o757, "world-writable sticky": 0o1777, "all-writable": 0o777}
	for name, mode := range writable {
		t.Run("the file is "+name, func(t *testing.T) {
			b := certTree(t)
			p := filepath.Join(b, "archive/example/fullchain1.pem")
			if err := os.Chmod(p, mode&0o777); err != nil {
				t.Fatal(err)
			}
			if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/fullchain.pem"), 100); !errors.Is(err, probes.ErrUnsafe) || !strings.Contains(err.Error(), "writable by group or others") {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("the archive directory is "+name, func(t *testing.T) {
			b := certTree(t)
			if err := os.Chmod(filepath.Join(b, "archive/example"), mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/fullchain.pem"), 100)
			if !errors.Is(err, probes.ErrUnsafe) || !strings.Contains(err.Error(), "directory") {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("a directory further up is "+name, func(t *testing.T) {
			b := certTree(t)
			if err := os.Chmod(filepath.Join(b, "archive"), mode); err != nil {
				t.Fatal(err)
			}
			if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/fullchain.pem"), 100); !errors.Is(err, probes.ErrUnsafe) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	t.Run("the directory of the link does not matter, the resolved path does", func(t *testing.T) {
		b := certTree(t)
		// live/ is writable by others, but the file is read from archive/
		if err := os.Chmod(filepath.Join(b, "live/example"), 0o777); err != nil {
			t.Fatal(err)
		}
		if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/fullchain.pem"), 100); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a link that leads into a writable directory is refused", func(t *testing.T) {
		b := certTree(t)
		evil := filepath.Join(b, "evil")
		if err := os.Mkdir(evil, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(evil, 0o777); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(evil, "cert.pem"), "fake\n")
		link(t, "../../evil/cert.pem", filepath.Join(b, "live/example/other.pem"))
		_, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/example/other.pem"), 100)
		if !errors.Is(err, probes.ErrUnsafe) || !strings.Contains(err.Error(), "evil") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a directory link is resolved before it is checked", func(t *testing.T) {
		b := certTree(t)
		evil := filepath.Join(b, "evil")
		if err := os.Mkdir(evil, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(evil, 0o777); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(evil, "cert.pem"), "fake\n")
		link(t, "../evil", filepath.Join(b, "live/dirlink"))
		if _, _, err := trustedFS(t, b).ReadTrusted(filepath.Join(b, "live/dirlink/cert.pem"), 100); !errors.Is(err, probes.ErrUnsafe) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestOSFSRefusesSpecialFilesWithoutOpening(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("no /dev/null")
	}
	if _, err := (probes.OSFS{}).ReadFile("/dev/null", 100); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v", err)
	}
	path := filepath.Join(t.TempDir(), "sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skip("no unix socket")
	}
	defer l.Close()
	if _, err := (probes.OSFS{}).ReadFile(path, 100); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("socket: %v", err)
	}
}

func TestOSFSGlobAndModTime(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"b_InRelease", "a_InRelease", "c_Release"} {
		writeFile(t, filepath.Join(dir, n), "x")
	}
	got, err := probes.OSFS{}.Glob(filepath.Join(dir, "*InRelease"))
	if err != nil || len(got) != 2 || got[0] != filepath.Join(dir, "a_InRelease") || got[1] != filepath.Join(dir, "b_InRelease") {
		t.Fatalf("glob %v %v", got, err)
	}
	if got, err := (probes.OSFS{}).Glob(filepath.Join(dir, "none*")); err != nil || len(got) != 0 {
		t.Fatalf("no match: %v %v", got, err)
	}
	if _, err := (probes.OSFS{}).Glob("relative/*"); err == nil {
		t.Fatal("relative pattern accepted")
	}
	if _, err := (probes.OSFS{}).Glob(filepath.Join(dir, "[")); err == nil {
		t.Fatal("bad pattern accepted")
	}

	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := filepath.Join(dir, "a_InRelease")
	if err := os.Chtimes(p, want, want); err != nil {
		t.Fatal(err)
	}
	if got, err := (probes.OSFS{}).ModTime(p); err != nil || !got.Equal(want) {
		t.Fatalf("mtime %v %v", got, err)
	}
	link(t, p, filepath.Join(dir, "link"))
	if _, err := (probes.OSFS{}).ModTime(filepath.Join(dir, "link")); !errors.Is(err, probes.ErrUnsafe) {
		t.Fatalf("link: %v", err)
	}
	if _, err := (probes.OSFS{}).ModTime(dir); !errors.Is(err, probes.ErrUnsafe) {
		t.Fatalf("dir: %v", err)
	}
	if _, err := (probes.OSFS{}).ModTime(filepath.Join(dir, "none")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}
