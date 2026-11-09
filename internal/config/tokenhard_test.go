package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTokenHardlinkRejected(t *testing.T) {
	// A token with a second hard link is rejected: the link count comes
	// from the fd's fstat, both when validating and when reading.
	t.Run("hard link present at Load", func(t *testing.T) {
		dir, main := setup(t, nil)
		token := filepath.Join(dir, "token")
		writeMode(t, token, []byte("s3cr3t\n"), 0o600)
		if err := os.Link(token, filepath.Join(dir, "token.alt")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
			t.Fatal(err)
		}
		loadErrs(t, main, token, "hard links")
	})
	t.Run("hard link added after Load", func(t *testing.T) {
		dir, main := setup(t, nil)
		token := filepath.Join(dir, "token")
		writeMode(t, token, []byte("s3cr3t\n"), 0o600)
		cfg := loadTokenCfg(t, main, token)
		if err := os.Link(token, filepath.Join(dir, "token.alt")); err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.ReadToken(); err == nil {
			t.Fatal("ReadToken of a hardlinked token: want error, got nil")
		}
	})
}

func TestTokenDirGroupWritableRejected(t *testing.T) {
	// The directory holding the token is checked like conf.d: a
	// group-writable one lets another user swap the token.
	dir, main := setup(t, nil)
	secrets := filepath.Join(dir, "secrets")
	if err := os.Mkdir(secrets, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secrets, 0o770); err != nil { // defeat the umask
		t.Fatal(err)
	}
	token := filepath.Join(secrets, "token")
	writeMode(t, token, []byte("s3cr3t\n"), 0o600)
	if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
		t.Fatal(err)
	}
	loadErrs(t, main, "notify.ntfy.token_file: "+secrets+":", "allow group or other writes")
}

func TestMainDirGroupWritableRejected(t *testing.T) {
	// The directory holding the main file is checked too: a world- or
	// group-writable one lets another user replace the whole config.
	dir, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	loadErrs(t, main, dir+":", "allow group or other writes")
}

func TestMissingMainDirReportsOnlyMissingFile(t *testing.T) {
	// When the main file's directory does not exist there is nothing to
	// check on it: the load reports exactly the missing main file, not
	// also a "directory does not exist" error.
	dir := filepath.Join(t.TempDir(), "absent")
	errs := errsOf(t, filepath.Join(dir, "keepwatch.yaml"))
	if len(errs) != 1 || !strings.Contains(errs[0], "cannot read") {
		t.Errorf("errors = %q, want exactly the missing main file", errs)
	}
}

func TestSecretDirsRootOwnedAcceptedViaInjection(t *testing.T) {
	// Directories owned by uid 0 (the production case) pass while the
	// running uid is not 0: injecting uid 0 for the token directory or
	// for the main file's directory must not fail Load.
	if os.Getuid() == 0 {
		t.Skip("running as root: an injected uid 0 cannot be told from the real owner")
	}
	t.Run("token dir root-owned", func(t *testing.T) {
		dir, main := setup(t, nil)
		secrets := filepath.Join(dir, "secrets")
		if err := os.Mkdir(secrets, 0o755); err != nil {
			t.Fatal(err)
		}
		token := filepath.Join(secrets, "token")
		writeMode(t, token, []byte("s3cr3t\n"), 0o600)
		if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(main, WithOwnerOf(injectUID("secrets", 0))); err != nil {
			t.Fatalf("Load with a root-owned token dir: %v", err)
		}
	})
	t.Run("main dir root-owned", func(t *testing.T) {
		dir, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
		if _, err := Load(main, WithOwnerOf(injectUID(filepath.Base(dir), 0))); err != nil {
			t.Fatalf("Load with a root-owned main dir: %v", err)
		}
	})
}

// injectUID reports uid for files and directories whose base name is
// name, and the real owner for everything else.
func injectUID(name string, uid int) OwnerOf {
	return func(fi fs.FileInfo) (int, error) {
		if fi.Name() == name {
			return uid, nil
		}
		return ownerOf(fi)
	}
}
