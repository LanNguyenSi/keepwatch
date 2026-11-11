package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// nest creates the directories below base (slash-separated, 0755, mode
// forced past the umask) and returns the path of the last one.
func nest(t *testing.T, base, rel string) string {
	t.Helper()
	p := base
	for _, c := range strings.Split(rel, "/") {
		p = filepath.Join(p, c)
		if err := os.Mkdir(p, 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// ownerOverride answers uid for the directory or file named name and the
// real owner for everything else.
func ownerOverride(name string, uid int) OwnerOf {
	return func(fi fs.FileInfo) (int, error) {
		if fi.Name() == name {
			return uid, nil
		}
		return ownerOf(fi)
	}
}

// ancestorCase damages one ancestor of a path that is given as
// "<base>/top/mid/leaf" and returns the path through which the loader is
// called plus the ancestor the message must name and the reason.
type ancestorCase struct {
	name   string
	damage func(t *testing.T, base string) (access, failing string)
	want   string // the reason after "ancestor <failing>: "
	opts   []Option
}

func ancestorCases() []ancestorCase {
	return []ancestorCase{
		{
			name: "symlinked grandparent",
			damage: func(t *testing.T, base string) (string, string) {
				nest(t, base, "real/mid/leaf")
				if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "top")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(base, "top", "mid", "leaf"), filepath.Join(base, "top")
			},
			want: "is a symlink",
		},
		{
			name: "symlinked parent",
			damage: func(t *testing.T, base string) (string, string) {
				nest(t, base, "top/realmid/leaf")
				if err := os.Symlink(filepath.Join(base, "top", "realmid"), filepath.Join(base, "top", "mid")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(base, "top", "mid", "leaf"), filepath.Join(base, "top", "mid")
			},
			want: "is a symlink",
		},
		{
			name: "group-writable grandparent",
			damage: func(t *testing.T, base string) (string, string) {
				leaf := nest(t, base, "top/mid/leaf")
				if err := os.Chmod(filepath.Join(base, "top"), 0o775); err != nil {
					t.Fatal(err)
				}
				return leaf, filepath.Join(base, "top")
			},
			want: "permissions 0775 allow group or other writes",
		},
		{
			name: "other-writable parent",
			damage: func(t *testing.T, base string) (string, string) {
				leaf := nest(t, base, "top/mid/leaf")
				if err := os.Chmod(filepath.Join(base, "top", "mid"), 0o757); err != nil {
					t.Fatal(err)
				}
				return leaf, filepath.Join(base, "top", "mid")
			},
			want: "permissions 0757 allow group or other writes",
		},
		{
			name: "grandparent of a foreign owner",
			damage: func(t *testing.T, base string) (string, string) {
				return nest(t, base, "top/mid/leaf"), filepath.Join(base, "top")
			},
			want: "owned by uid 60001, want uid 0 or",
			opts: []Option{WithOwnerOf(ownerOverride("top", 60001))},
		},
		{
			name: "ancestor that is a file",
			damage: func(t *testing.T, base string) (string, string) {
				nest(t, base, "top")
				writeMode(t, filepath.Join(base, "top", "mid"), []byte("x\n"), 0o644)
				return filepath.Join(base, "top", "mid", "leaf"), filepath.Join(base, "top", "mid")
			},
			want: "is not a directory",
		},
	}
}

func TestOpenCheckedDirRefusesAncestorsAtAnyDepth(t *testing.T) {
	for _, c := range ancestorCases() {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			access, failing := c.damage(t, base)
			opt := options{ownerOf: ownerOf}
			for _, fn := range c.opts {
				fn(&opt)
			}
			root, err := openCheckedDir(access, opt.ownerOf, false)
			if err == nil {
				root.Close()
				t.Fatalf("openCheckedDir(%s) = nil, want a refusal", access)
			}
			want := access + ": ancestor " + failing + ": " + c.want
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		})
	}
}

func TestOpenCheckedDirAcceptsAGoodChain(t *testing.T) {
	base := t.TempDir()
	leaf := nest(t, base, "a/b/c/d")
	root, err := openCheckedDir(leaf, ownerOf, false)
	if err != nil {
		t.Fatalf("openCheckedDir(%s): %v", leaf, err)
	}
	root.Close()
}

func TestOpenCheckedDirFinalComponentIsStrict(t *testing.T) {
	// The directory itself may not be sticky-and-writable, only an
	// ancestor may.
	base := t.TempDir()
	leaf := nest(t, base, "a/b")
	if err := os.Chmod(leaf, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	_, err := openCheckedDir(leaf, ownerOf, false)
	if err == nil || !strings.Contains(err.Error(), leaf+": permissions 0777 allow group or other writes") {
		t.Fatalf("openCheckedDir of a sticky world-writable directory: err = %v, want a permissions refusal", err)
	}
}

func TestOpenCheckedDirStickyAncestorIsAccepted(t *testing.T) {
	// /tmp is sticky and world-writable on every Linux: others cannot
	// rename or remove the entries they do not own.
	base := t.TempDir()
	leaf := nest(t, base, "a/b/c")
	if err := os.Chmod(filepath.Join(base, "a"), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	root, err := openCheckedDir(leaf, ownerOf, false)
	if err != nil {
		t.Fatalf("openCheckedDir below a sticky world-writable ancestor: %v", err)
	}
	root.Close()
	// Without the sticky bit the same mode is refused.
	if err := os.Chmod(filepath.Join(base, "a"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openCheckedDir(leaf, ownerOf, false); err == nil {
		t.Fatal("openCheckedDir below a world-writable ancestor without the sticky bit: want a refusal")
	}
}

func TestOpenCheckedDirMissingIsNotExist(t *testing.T) {
	base := t.TempDir()
	for _, p := range []string{filepath.Join(base, "absent"), filepath.Join(base, "absent", "deeper")} {
		_, err := openCheckedDir(p, ownerOf, false)
		if !isNotExist(err) {
			t.Errorf("openCheckedDir(%s) = %v, want a not-exist error", p, err)
		}
	}
}

func TestOpenCheckedDirRelativePath(t *testing.T) {
	// A relative directory is resolved against the physical working
	// directory and walked from "/" like an absolute one.
	base := t.TempDir()
	nest(t, base, "top/leaf")
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	root, err := openCheckedDir("top/leaf", ownerOf, false)
	if err != nil {
		t.Fatalf("relative directory: %v", err)
	}
	root.Close()
	if err := os.Chmod(filepath.Join(base, "top"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openCheckedDir("top/leaf", ownerOf, false); err == nil ||
		!strings.Contains(err.Error(), "ancestor "+filepath.Join(base, "top")+": permissions 0777") {
		t.Fatalf("relative directory below a writable ancestor: err = %v, want the ancestor named", err)
	}
}

func TestOpenCheckedDirDetectsASwapBetweenLookAndOpen(t *testing.T) {
	base := t.TempDir()
	leaf := nest(t, base, "top/mid/leaf")
	other := nest(t, base, "other")
	mid := filepath.Join(base, "top", "mid")
	afterLstat = func(path string) {
		if path != mid {
			return
		}
		// Replace the directory that was just looked at by another one.
		if err := os.Rename(mid, mid+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Rename(other, mid); err != nil {
			t.Error(err)
		}
	}
	defer func() { afterLstat = nil }()
	_, err := openCheckedDir(leaf, ownerOf, false)
	if err == nil || !strings.Contains(err.Error(), "ancestor "+mid+": changed while it was being opened") {
		t.Fatalf("openCheckedDir with a swapped ancestor: err = %v, want the swap reported", err)
	}
}

func TestOpenSecureInOpensThroughTheCheckedDirectory(t *testing.T) {
	// Once the directory is checked and open, the files are read from
	// that directory even when the path is pointed at another one.
	base := t.TempDir()
	dir := nest(t, base, "etc/conf.d")
	writeMode(t, filepath.Join(dir, "a.yaml"), []byte("host:\n  profile: genuine\n"), 0o644)
	root, err := openCheckedDir(dir, ownerOf, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(dir, dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMode(t, filepath.Join(dir, "a.yaml"), []byte("host:\n  profile: planted\n"), 0o644)
	node, _, errs := parseFile(root, "a.yaml", filepath.Join(dir, "a.yaml"), configPolicy(ownerOf))
	if len(errs) != 0 {
		t.Fatalf("parseFile: %v", errs)
	}
	if got := node.Content[1].Content[1].Value; got != "genuine" {
		t.Errorf("profile = %q, want genuine: the file was opened by path, not through the checked directory", got)
	}
}

func TestOpenSecureInDetectsASwapBetweenLookAndOpen(t *testing.T) {
	dir := nest(t, t.TempDir(), "etc")
	file := filepath.Join(dir, "a.yaml")
	writeMode(t, file, []byte("host:\n  profile: genuine\n"), 0o644)
	root, err := openCheckedDir(dir, ownerOf, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	afterLstat = func(path string) {
		if path != file {
			return
		}
		// Keep the old file alive, so the new one cannot reuse its inode.
		if err := os.Rename(file, file+".old"); err != nil {
			t.Error(err)
		}
		writeMode(t, file, []byte("host:\n  profile: planted\n"), 0o644)
	}
	defer func() { afterLstat = nil }()
	f, _, err := openSecureIn(root, "a.yaml", file, configPolicy(ownerOf))
	if err == nil {
		f.Close()
		t.Fatal("openSecureIn with a swapped file: want an error")
	}
	if !strings.Contains(err.Error(), file+": changed while it was being opened") {
		t.Errorf("error %q lacks the swap report", err)
	}
}

// loadAt writes a main file at dir/keepwatch.yaml and loads it with opts.
func loadAt(t *testing.T, dir, content string, opts ...Option) error {
	t.Helper()
	main := filepath.Join(dir, "keepwatch.yaml")
	writeMode(t, main, []byte(content), 0o644)
	_, err := Load(main, opts...)
	return err
}

func TestLoadRefusesTheAncestorsOfTheMainFileAndConfD(t *testing.T) {
	for _, c := range ancestorCases() {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			access, failing := c.damage(t, base)
			// conf.d sits below the directory of the main file, so its
			// whole chain is the chain of the main file.
			os.Mkdir(filepath.Join(access, "conf.d"), 0o755) // fails below a file, which is the case
			main := filepath.Join(access, "keepwatch.yaml")
			if err := os.WriteFile(main, []byte("state_dir: /srv/kw\n"), 0o644); err != nil && !strings.Contains(c.name, "file") {
				t.Fatal(err)
			}
			_, err := Load(main, c.opts...)
			if err == nil {
				t.Fatal("Load: want a refusal")
			}
			want := access + ": ancestor " + failing + ": " + c.want
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		})
	}
}

func TestLoadRefusesTheAncestorsOfTheTokenFile(t *testing.T) {
	for _, c := range ancestorCases() {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			access, failing := c.damage(t, base)
			token := filepath.Join(access, "token")
			if err := os.WriteFile(token, []byte("s3cr3t\n"), 0o600); err != nil && !strings.Contains(c.name, "file") {
				t.Fatal(err)
			}
			cfgDir := nest(t, t.TempDir(), "etc")
			err := loadAt(t, cfgDir, tokenCfg(token), c.opts...)
			if err == nil {
				t.Fatal("Load: want a refusal")
			}
			want := "notify.ntfy.token_file: " + access + ": ancestor " + failing + ": " + c.want
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		})
	}
}

func TestReadTokenRefusesAnAncestorChangedAfterLoad(t *testing.T) {
	base := t.TempDir()
	dir := nest(t, base, "top/mid/secrets")
	token := filepath.Join(dir, "token")
	writeMode(t, token, []byte("s3cr3t\n"), 0o600)
	cfgDir := nest(t, t.TempDir(), "etc")
	main := filepath.Join(cfgDir, "keepwatch.yaml")
	cfg := loadTokenCfg(t, main, token)
	if b, err := cfg.ReadToken(); err != nil || string(b) != "s3cr3t" {
		t.Fatalf("ReadToken before the change = %q, %v", b, err)
	}
	if err := os.Chmod(filepath.Join(base, "top"), 0o777); err != nil {
		t.Fatal(err)
	}
	b, err := cfg.ReadToken()
	if err == nil || !strings.Contains(err.Error(), "ancestor "+filepath.Join(base, "top")+": permissions 0777") {
		t.Fatalf("ReadToken after an ancestor became writable = %q, %v; want the ancestor named", b, err)
	}
	if len(b) != 0 {
		t.Errorf("ReadToken returned %q along with the error", b)
	}
}

func TestLoadAcceptsDeepChains(t *testing.T) {
	base := t.TempDir()
	dir := nest(t, base, "a/b/c/etc")
	nest(t, base, "a/b/c/etc/conf.d")
	writeMode(t, filepath.Join(dir, "conf.d", "x.yaml"), []byte("host:\n  profile: x\n"), 0o644)
	if err := loadAt(t, dir, "state_dir: /srv/kw\n"); err != nil {
		t.Fatalf("Load through a deep, well-formed chain: %v", err)
	}
}

func TestWriteExampleChecksTheAncestors(t *testing.T) {
	for _, c := range ancestorCases() {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			access, failing := c.damage(t, base)
			opt := []Option{}
			opt = append(opt, c.opts...)
			err := WriteExample(filepath.Join(access, "keepwatch.yaml"), false, opt...)
			if err == nil {
				t.Fatal("WriteExample: want a refusal")
			}
			want := "ancestor " + failing + ": " + c.want
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
			if _, serr := os.Lstat(filepath.Join(access, "keepwatch.yaml")); serr == nil {
				t.Error("the refusal must not write the file")
			}
			ents, _ := os.ReadDir(access)
			for _, e := range ents {
				t.Errorf("the refusal left %s behind", e.Name())
			}
		})
	}
}

func TestWriteExampleCreatesMissingDirectoriesChecked(t *testing.T) {
	defer syscall.Umask(syscall.Umask(0o077))
	base := t.TempDir()
	main := filepath.Join(base, "a", "b", "keepwatch.yaml")
	if err := WriteExample(main, false); err != nil {
		t.Fatalf("WriteExample into missing directories: %v", err)
	}
	for _, d := range []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b")} {
		fi, err := os.Lstat(d)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o750 {
			t.Errorf("%s mode = 0%o, want 0750", d, fi.Mode().Perm())
		}
	}
	if _, err := Load(main); err != nil {
		t.Errorf("the written example fails Load: %v", err)
	}
}
