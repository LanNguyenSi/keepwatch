package execx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveMatchesRun(t *testing.T) {
	trusted := t.TempDir()
	other := t.TempDir()
	write := func(dir, name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write(trusted, "tool")
	write(trusted, "other")
	outside := write(other, "evil")
	if err := os.Symlink(outside, filepath.Join(trusted, "linked")); err != nil {
		t.Fatal(err)
	}
	r := NewReal([]string{"tool", "linked"}, WithSearchDirs(trusted))

	got, err := r.Resolve("tool")
	if err != nil {
		t.Fatalf("Resolve(tool): %v", err)
	}
	want, _ := filepath.EvalSymlinks(good)
	if got != want {
		t.Errorf("Resolve(tool) = %q, want %q", got, want)
	}
	if _, err := r.Resolve("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Resolve(missing) = %v, want ErrNotFound", err)
	}
	if _, err := r.Resolve("other"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Resolve(other) = %v, want ErrNotAllowed (on the file system, not on the allowlist)", err)
	}
	// Run and Resolve agree on a link that leaves the trusted directories.
	if _, err := r.Resolve("linked"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Resolve(linked) = %v, want ErrNotAllowed", err)
	}
	if _, err := r.Run(bg, []string{"linked"}, Opts{}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Run(linked) = %v, want ErrNotAllowed", err)
	}
}
