package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenCfg(path string) string {
	return "notify:\n  ntfy:\n    url: https://example.com/t\n    topic: t\n    token_file: " + path + "\n"
}

func TestTokenFileChecks(t *testing.T) {
	// Each row creates a token file in a particular shape and says
	// whether Load must reject it and with what message.
	tests := []struct {
		name   string
		mode   os.FileMode
		make   func(t *testing.T, dir string) string // returns token path
		wantOK bool
		want   string // substring of the expected error
	}{
		{
			name:   "0600 regular file owned by me is accepted",
			make:   writeToken(0o600),
			wantOK: true,
		},
		{
			name: "0640 is rejected (group-readable)",
			make: writeToken(0o640),
			want: "grant access to group or other",
		},
		{
			name: "0644 is rejected (world-readable)",
			make: writeToken(0o644),
			want: "grant access to group or other",
		},
		{
			name:   "0400 is accepted (stricter than 0600)",
			make:   writeToken(0o400),
			wantOK: true,
		},
		{
			name: "missing file is rejected",
			make: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "absent.token")
			},
			want: "does not exist",
		},
		{
			name: "symlink is rejected even when the target is 0600",
			make: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "real.token")
				if err := os.WriteFile(target, []byte("s"), 0o600); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(dir, "link.token")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
			want: "must be a regular file",
		},
		{
			name: "directory is rejected",
			make: func(t *testing.T, dir string) string {
				d := filepath.Join(dir, "token.dir")
				if err := os.Mkdir(d, 0o600); err != nil {
					t.Fatal(err)
				}
				return d
			},
			want: "must be a regular file",
		},
		{
			name: "foreign owner is rejected via the injected check",
			make: writeToken(0o600),
			want: "owned by uid 60001",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, main := setup(t, nil)
			token := tc.make(t, dir)
			if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
				t.Fatal(err)
			}
			var opts []Option
			if strings.Contains(tc.name, "foreign owner") {
				// Foreign owner only for the token file; the config
				// files keep their real owner so the error below can
				// only come from the token check.
				opts = append(opts, WithOwnerOf(func(fi fs.FileInfo) (int, error) {
					if fi.Name() == "token" {
						return 60001, nil
					}
					return ownerOf(fi)
				}))
			}
			_, err := Load(main, opts...)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load: want error %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q lacks %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), token) {
				t.Errorf("error %q must name the token file %s", err, token)
			}
		})
	}
}

func writeToken(mode os.FileMode) func(t *testing.T, dir string) string {
	return func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "token")
		if err := os.WriteFile(p, []byte("secret\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // defeat the umask
			t.Fatal(err)
		}
		return p
	}
}

func TestTokenFileErrorNamesConfigFileAndLine(t *testing.T) {
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "absent.token")
	if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
		t.Fatal(err)
	}
	errs := errsOf(t, main)
	if !containsSub(errs, main+":5: notify.ntfy.token_file:") {
		t.Errorf("errors %q lack file:line of token_file", errs)
	}
}

func TestReadTokenLazy(t *testing.T) {
	dir, main := setup(t, nil)
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(token, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, []byte(tokenCfg(token)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := cfg.ReadToken()
	if err != nil {
		t.Fatalf("ReadToken: %v", err)
	}
	if string(got) != "s3cr3t" {
		t.Errorf("ReadToken = %q, want %q", got, "s3cr3t")
	}
}

func TestReadTokenWithoutTokenFile(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": ""})
	cfg, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ReadToken(); err == nil || !strings.Contains(err.Error(), "token_file") {
		t.Errorf("ReadToken error = %v, want it to name token_file", err)
	}
}
