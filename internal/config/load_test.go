package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setup writes files (map of slash-separated relative path to content)
// into a fresh temp dir next to a keepwatch.yaml main file location and
// returns the dir and the main path. A path ending in "/" creates an
// empty directory.
func setup(t *testing.T, files map[string]string) (dir, mainPath string) {
	t.Helper()
	dir = t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, filepath.Join(dir, "keepwatch.yaml")
}

// loadErrs loads path and requires that it fails with errors containing
// every want substring.
func loadErrs(t *testing.T, path string, want ...string) {
	t.Helper()
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load(%s): want error containing %q, got nil", path, want)
	}
	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("Load(%s): error %q lacks %q", path, msg, w)
		}
	}
}

// errsOf loads path expecting failure and returns the error strings.
func errsOf(t *testing.T, path string) []string {
	t.Helper()
	_, err := Load(path)
	var errs Errors
	if err == nil {
		t.Fatalf("Load(%s): want errors, got nil", path)
	}
	if !asErrors(err, &errs) {
		t.Fatalf("Load(%s): want config.Errors, got %T: %v", path, err, err)
	}
	out := make([]string, len(errs))
	for i, e := range errs {
		out[i] = e.Error()
	}
	return out
}

func asErrors(err error, target *Errors) bool {
	if errs, ok := err.(Errors); ok {
		*target = errs
		return true
	}
	return false
}

func TestLoadValid(t *testing.T) {
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": `
host:
  profile: staging
state_dir: /srv/keepwatch
checks:
  sshd:
    severity: high
    params:
      config: /etc/ssh/sshd_config
      timeout: 5
listeners:
  allow:
    - port: 22
      proto: tcp
    - port: 161
      proto: udp
      bind: 2001:db8::1
authorized_keys:
  expected:
    root:
      - SHA256:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE
exceptions:
  - check: sshd
    match: port
    reason: maintenance window
    expires: 2035-01-15
notify:
  ntfy:
    url: http://127.0.0.1:8080/t
    topic: t
`,
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host.Profile != "staging" {
		t.Errorf("Host.Profile = %q", cfg.Host.Profile)
	}
	if cfg.StateDir != "/srv/keepwatch" {
		t.Errorf("StateDir = %q", cfg.StateDir)
	}
	c := cfg.Checks["sshd"]
	if !c.Enabled {
		t.Error("Checks[sshd].Enabled = false, want default true")
	}
	if c.Severity != "high" {
		t.Errorf("Checks[sshd].Severity = %q", c.Severity)
	}
	if got := fmt.Sprint(c.Params["config"]); got != "/etc/ssh/sshd_config" {
		t.Errorf("Checks[sshd].params[config] = %v", c.Params["config"])
	}
	if fmt.Sprint(c.Params["timeout"]) != "5" {
		t.Errorf("Checks[sshd].params[timeout] = %v", c.Params["timeout"])
	}
	if len(cfg.Listeners.Allow) != 2 {
		t.Fatalf("len(Listeners.Allow) = %d, want 2", len(cfg.Listeners.Allow))
	}
	if cfg.Listeners.Allow[0].Bind != "*" {
		t.Errorf("Allow[0].Bind = %q, want default *", cfg.Listeners.Allow[0].Bind)
	}
	if cfg.Listeners.Allow[1].Bind != "2001:db8::1" || cfg.Listeners.Allow[1].Proto != "udp" {
		t.Errorf("Allow[1] = %+v", cfg.Listeners.Allow[1])
	}
	if len(cfg.AuthorizedKeys.Expected["root"]) != 1 {
		t.Errorf("Expected[root] = %v", cfg.AuthorizedKeys.Expected["root"])
	}
	if len(cfg.Exceptions) != 1 || cfg.Exceptions[0].Match != "port" {
		t.Errorf("Exceptions = %+v", cfg.Exceptions)
	}
	if cfg.Notify.Ntfy == nil || cfg.Notify.Ntfy.Topic != "t" {
		t.Errorf("Notify = %+v", cfg.Notify)
	}
	if cfg.Sources.Main != main || len(cfg.Sources.ConfD) != 0 {
		t.Errorf("Sources = %+v", cfg.Sources)
	}
}

func TestDefaults(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": ""})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load of empty file: %v", err)
	}
	if cfg.StateDir != DefaultStateDir {
		t.Errorf("StateDir = %q, want default %q", cfg.StateDir, DefaultStateDir)
	}
	if cfg.Notify.Ntfy != nil {
		t.Errorf("Notify.Ntfy = %+v, want nil", cfg.Notify.Ntfy)
	}
}

func TestDefaultPathWhenFlagAbsent(t *testing.T) {
	// Load("") must fall back to DefaultPath: the error names it (the
	// file is absent in the sandbox, so a missing main file proves the
	// fallback won over an empty path). Where /etc is a symlink (macOS)
	// the load stops at that ancestor and names the directory instead.
	_, err := Load("")
	if err == nil || !strings.Contains(err.Error(), filepath.Dir(DefaultPath)) {
		t.Fatalf("Load(\"\") error = %v, want it to name %s", err, DefaultPath)
	}
}

func TestMainFileMissingIsError(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	errMsg := ""
	_, err := Load(main)
	if err == nil {
		t.Fatal("want error for missing main file")
	}
	errMsg = err.Error()
	if !strings.Contains(errMsg, main) {
		t.Errorf("error %q must name the file %s", errMsg, main)
	}
	var errs Errors
	if !asErrors(err, &errs) {
		t.Fatalf("want config.Errors, got %T", err)
	}
}

func TestConfDDirAbsentIsFine(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load without conf.d: %v", err)
	}
	if cfg.StateDir != "/srv/kw" || len(cfg.Sources.ConfD) != 0 {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestConfDEmptyDirIsFine(t *testing.T) {
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /srv/kw\n",
		"conf.d/":        "",
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load with empty conf.d: %v", err)
	}
	if len(cfg.Sources.ConfD) != 0 {
		t.Errorf("Sources.ConfD = %v, want none", cfg.Sources.ConfD)
	}
}

func TestConfDPrecedence(t *testing.T) {
	// For every combination of inputs, state which input wins:
	// main alone -> main; main + one conf.d -> conf.d (later file);
	// main + two conf.d -> the lexicographically later file.
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "main alone",
			files: map[string]string{"keepwatch.yaml": "state_dir: /from-main\n"},
			want:  "/from-main",
		},
		{
			name: "one conf.d overrides main",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/a.yaml":  "state_dir: /from-a\n",
			},
			want: "/from-a",
		},
		{
			name: "lexicographically later conf.d wins",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/a.yaml":  "state_dir: /from-a\n",
				"conf.d/b.yaml":  "state_dir: /from-b\n",
			},
			want: "/from-b",
		},
		{
			name: "10 sorts before 9 so 9 wins",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/10.yaml": "state_dir: /from-10\n",
				"conf.d/9.yaml":  "state_dir: /from-9\n",
			},
			want: "/from-9",
		},
		{
			name: "empty conf.d file is skipped",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/a.yaml":  "",
				"conf.d/b.yaml":  "state_dir: /from-b\n",
			},
			want: "/from-b",
		},
		{
			name: "non-yaml non-yml files are ignored",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/notes":   "state_dir: /from-n\n",
			},
			want: "/from-main",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, tc.files)
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.StateDir != tc.want {
				t.Errorf("StateDir = %q, want %q", cfg.StateDir, tc.want)
			}
		})
	}
}

func TestConfDMapMerge(t *testing.T) {
	// Two files touching the same map key: mappings merge per key and
	// the later file's key wins; keys the later file does not name
	// survive.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": `
host:
  profile: main
checks:
  sshd:
    enabled: true
    severity: high
`,
		"conf.d/a.yaml": `
host:
  profile: from-a
checks:
  sshd:
    severity: low
  fail2ban:
    severity: medium
`,
		"conf.d/b.yaml": `
checks:
  sshd:
    params:
      port: 22
`,
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host.Profile != "from-a" {
		t.Errorf("Host.Profile = %q, want from-a (a.yaml wins over main)", cfg.Host.Profile)
	}
	ssh := cfg.Checks["sshd"]
	if ssh.Severity != "low" {
		t.Errorf("Checks[sshd].Severity = %q, want low (a.yaml wins over main)", ssh.Severity)
	}
	if !ssh.Enabled {
		t.Error("Checks[sshd].Enabled = false, want true (main's key survives a.yaml's merge)")
	}
	if fmt.Sprint(ssh.Params["port"]) != "22" {
		t.Errorf("Checks[sshd].Params = %v, want port 22 from b.yaml", ssh.Params)
	}
	if _, ok := cfg.Checks["fail2ban"]; !ok {
		t.Error("Checks[fail2ban] missing after merge")
	}
}

func TestConfDSequenceAppend(t *testing.T) {
	// Both files append exceptions (and listeners.allow): main first,
	// then conf.d files in lexicographic order.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": `
listeners:
  allow:
    - port: 22
      proto: tcp
exceptions:
  - check: main1
    reason: from main
    expires: 2035-01-01
  - check: main2
    reason: from main
    expires: 2035-01-01
`,
		"conf.d/a.yaml": `
listeners:
  allow:
    - port: 80
      proto: tcp
exceptions:
  - check: a1
    reason: from a
    expires: 2035-01-01
`,
		"conf.d/b.yaml": `
listeners:
  allow:
    - port: 443
      proto: tcp
exceptions:
  - check: b1
    reason: from b
    expires: 2035-01-01
`,
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var ports []int
	for _, l := range cfg.Listeners.Allow {
		ports = append(ports, l.Port)
	}
	if fmt.Sprint(ports) != "[22 80 443]" {
		t.Errorf("allow ports = %v, want [22 80 443] in merge order", ports)
	}
	var ids []string
	for _, e := range cfg.Exceptions {
		ids = append(ids, e.Check)
	}
	if fmt.Sprint(ids) != "[main1 main2 a1 b1]" {
		t.Errorf("exceptions order = %v, want [main1 main2 a1 b1]", ids)
	}
	if len(cfg.Sources.ConfD) != 2 {
		t.Errorf("Sources.ConfD = %v, want 2 files", cfg.Sources.ConfD)
	}
}

func TestAllErrorsCollected(t *testing.T) {
	// Several problems, several files: every one is reported with its
	// own file and line.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml": `
state_dir: relative/path
unknown_top: 1
exceptions:
  - check: x
    expires: 2035-01-01
`,
		"conf.d/a.yaml": `
listeners:
  allow:
    - port: 0
      proto: tcp
    - port: 65536
      proto: tcp
`,
	})
	errs := errsOf(t, main)
	wantLines := []string{
		fmt.Sprintf("%s:2: state_dir: must be an absolute path", main),
		fmt.Sprintf("%s:3: unknown key \"unknown_top\"", main),
		fmt.Sprintf("%s:5: exceptions[0]: reason is required", main),
	}
	for _, want := range wantLines {
		if !containsSub(errs, want) {
			t.Errorf("missing error line %q in %q", want, errs)
		}
	}
	confd := filepath.Join(dir, "conf.d", "a.yaml")
	for _, want := range []string{
		confd + ":4: listeners.allow[0].port: must be between 1 and 65535, got 0",
		confd + ":6: listeners.allow[1].port: must be between 1 and 65535, got 65536",
	} {
		if !containsSub(errs, want) {
			t.Errorf("missing error line %q in %q", want, errs)
		}
	}
}

func containsSub(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestMultipleDocumentsRejected(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /a\n---\nstate_dir: /b\n"})
	loadErrs(t, main, "unexpected content after the first document")
}
