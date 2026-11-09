package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ReadToken uses the owner lookup that Load used, so the owner checks on
// the token directory and on the token file are testable unprivileged:
// an owner that turns foreign after Load is refused on read.
func TestReadTokenUsesLoadOwnerLookup(t *testing.T) {
	for _, target := range []string{"dir", "file"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "keepwatch.yaml")
			tokDir := filepath.Join(dir, "sec")
			if err := os.Mkdir(tokDir, 0o700); err != nil {
				t.Fatal(err)
			}
			token := filepath.Join(tokDir, "token")
			writeMode(t, token, []byte("s3cret\n"), 0o600)
			if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
				t.Fatal(err)
			}
			foreign := false
			of := func(fi fs.FileInfo) (int, error) {
				if foreign {
					if (target == "dir" && fi.Name() == "sec") || (target == "file" && fi.Name() == "token") {
						return 65534, nil
					}
				}
				return ownerOf(fi)
			}
			cfg, err := Load(main, WithOwnerOf(of))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if b, err := cfg.ReadToken(); err != nil || string(b) != "s3cret" {
				t.Fatalf("ReadToken before = %q, %v", b, err)
			}
			foreign = true
			if _, err := cfg.ReadToken(); err == nil || !strings.Contains(err.Error(), "uid 65534") {
				t.Fatalf("ReadToken after owner change: err = %v, want a refusal naming uid 65534", err)
			}
		})
	}
}

// The directory check is lexical while the kernel resolves "link/.."
// through the symlink, so an unclean token path is refused up front.
func TestTokenFileMustBeClean(t *testing.T) {
	for _, p := range []string{"/etc/keepwatch/link/../sec/token", "/etc/keepwatch/./token", "/etc//keepwatch/token", "/etc/keepwatch/token/"} {
		t.Run(p, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": tokenCfg(p)})
			loadErrs(t, main, "must be a clean path")
		})
	}
}

// A dangling conf.d symlink must not read as "no conf.d": that would
// silently drop every drop-in.
func TestConfDDanglingSymlinkIsError(t *testing.T) {
	dir, main := setup(t, map[string]string{"keepwatch.yaml": "host:\n  profile: p\n"})
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "conf.d")); err != nil {
		t.Fatal(err)
	}
	loadErrs(t, main, "conf.d", "must not be a symlink")
}
