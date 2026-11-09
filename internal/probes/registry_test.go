package probes_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
)

func TestRegistry(t *testing.T) {
	want := []string{"fail2ban_jail", "listeners", "package_installed", "reboot_required", "service_active", "sshd_effective"}
	if got := probes.Names(); !eq(got, want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
	for _, n := range want {
		k, ok := probes.Lookup(n)
		if !ok || k.Name() != n || len(k.Programs()) == 0 {
			t.Fatalf("kind %s: %v %v", n, k, ok)
		}
	}
	if _, ok := probes.Lookup("no_such_kind"); ok {
		t.Fatal("unknown kind found")
	}
}

func TestPrograms(t *testing.T) {
	got, err := probes.Programs("service_active", "package_installed", "service_active", "sshd_effective", "fail2ban_jail", "listeners", "reboot_required")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dpkg-query", "fail2ban-client", "needrestart", "sshd", "ss", "systemctl"}; !eq(got, sorted(want)) {
		t.Fatalf("Programs = %v", got)
	}
	if got, err := probes.Programs(); err != nil || len(got) != 0 {
		t.Fatalf("Programs() = %v, %v", got, err)
	}
	if _, err := probes.Programs("service_active", "bogus"); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("err = %v", err)
	}
}

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestOSFSReadFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var f probes.FS = probes.OSFS{}
	if b, err := f.ReadFile(write("small", "hello"), 5); err != nil || string(b) != "hello" {
		t.Fatalf("at the cap: %q, %v", b, err)
	}
	if _, err := f.ReadFile(write("big", "hello!"), 5); !errors.Is(err, probes.ErrTooLarge) {
		t.Fatalf("one byte over the cap: %v", err)
	}
	if _, err := f.ReadFile(filepath.Join(dir, "missing"), 5); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := f.ReadFile(dir, 5); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
}

func TestMemFS(t *testing.T) {
	m := probestest.MemFS{"/a": "abc"}
	if b, err := m.ReadFile("/a", 3); err != nil || string(b) != "abc" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := m.ReadFile("/a", 2); !errors.Is(err, probes.ErrTooLarge) {
		t.Fatalf("cap: %v", err)
	}
	if _, err := m.ReadFile("/b", 2); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := (probestest.ErrFS{Err: fs.ErrPermission}).ReadFile("/a", 1); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("ErrFS: %v", err)
	}
}
