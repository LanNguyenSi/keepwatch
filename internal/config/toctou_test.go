package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func writeMode(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // defeat the umask
		t.Fatal(err)
	}
}

// loadTokenCfg writes a main file referencing token and loads it,
// requiring success.
func loadTokenCfg(t *testing.T, main, token string) *Config {
	t.Helper()
	if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestReadTokenRejectsSymlinkSwapAfterLoad(t *testing.T) {
	// The reviewer's attack: swap the token path for a symlink to
	// another file after Load. ReadToken must refuse, not return the
	// target's content.
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "token")
	writeMode(t, token, []byte("s3cr3t\n"), 0o600)
	cfg := loadTokenCfg(t, main, token)

	other := filepath.Join(dir, "other")
	writeMode(t, other, []byte("OTHER FILE\n"), 0o600)
	if err := os.Remove(token); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, token); err != nil {
		t.Fatal(err)
	}
	got, err := cfg.ReadToken()
	if err == nil {
		t.Fatalf("ReadToken after symlink swap = %q, want an error", got)
	}
	if bytes.Contains(got, []byte("OTHER")) {
		t.Errorf("ReadToken returned the symlink target's content: %q", got)
	}
}

func TestReadTokenRejectsModeRelaxAfterLoad(t *testing.T) {
	// Relaxing the token mode after Load is rejected by the re-check
	// in ReadToken.
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "token")
	writeMode(t, token, []byte("s3cr3t\n"), 0o600)
	cfg := loadTokenCfg(t, main, token)

	if err := os.Chmod(token, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ReadToken(); err == nil || !strings.Contains(err.Error(), "grant access to group or other") {
		t.Fatalf("ReadToken after chmod 0644: err = %v, want a permissions error", err)
	}
}

func TestTokenFIFORejectedWithoutHang(t *testing.T) {
	// A FIFO at the token path must be an error, not a hang: opening
	// O_RDONLY without O_NONBLOCK would block until a writer arrives.
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "fifo.token")
	if err := syscall.Mkfifo(token, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(main)
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("Load with a FIFO at the token path: err = %v, want a regular-file error", err)
	}
}

func TestTokenOversizedRejected(t *testing.T) {
	// A token file larger than the 4096-byte cap is an error, both at
	// Load and when it grew only after Load.
	t.Run("oversized at Load", func(t *testing.T) {
		dir, main := setup(t, nil)
		token := filepath.Join(dir, "token")
		writeMode(t, token, bytes.Repeat([]byte("x"), maxTokenSize+1), 0o600)
		if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(main)
		if err == nil || !strings.Contains(err.Error(), "larger than the limit") {
			t.Fatalf("Load with oversized token: err = %v, want a size error", err)
		}
	})
	t.Run("grew after Load", func(t *testing.T) {
		dir, main := setup(t, nil)
		token := filepath.Join(dir, "token")
		writeMode(t, token, []byte("s3cr3t\n"), 0o600)
		cfg := loadTokenCfg(t, main, token)
		writeMode(t, token, bytes.Repeat([]byte("x"), maxTokenSize+1), 0o600)
		if _, err := cfg.ReadToken(); err == nil || !strings.Contains(err.Error(), "larger than the limit") {
			t.Fatalf("ReadToken after the token grew: err = %v, want a size error", err)
		}
	})
}

func TestTokenExactlyAtCapIsRead(t *testing.T) {
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "token")
	want := bytes.Repeat([]byte("x"), maxTokenSize)
	writeMode(t, token, want, 0o600)
	cfg := loadTokenCfg(t, main, token)
	got, err := cfg.ReadToken()
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("ReadToken returned %d bytes, want %d", len(got), len(want))
	}
}
