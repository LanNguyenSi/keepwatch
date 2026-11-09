package config

import (
	"strings"
	"testing"
)

// nullMergeMain sets every section a drop-in could blank.
const nullMergeMain = `host:
  profile: web
checks:
  sshd:
    enabled: false
    params:
      key: main
listeners:
  allow:
    - port: 22
      proto: tcp
authorized_keys:
  expected:
    root:
      - SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ
exceptions:
  - check: a
    reason: r
    expires: 2099-01-01
notify:
  ntfy:
    url: https://ntfy.example.com
    topic: alerts
`

// requireMainIntact asserts every value nullMergeMain sets survived.
func requireMainIntact(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.Host.Profile != "web" {
		t.Errorf("Host.Profile = %q, want web", cfg.Host.Profile)
	}
	if c, ok := cfg.Checks["sshd"]; !ok || c.Enabled || c.Params["key"] != "main" {
		t.Errorf("Checks[sshd] = %+v (present %v), want disabled with params.key main", c, ok)
	}
	if len(cfg.Listeners.Allow) != 1 || cfg.Listeners.Allow[0].Port != 22 {
		t.Errorf("Listeners.Allow = %+v, want the port 22 entry", cfg.Listeners.Allow)
	}
	if len(cfg.AuthorizedKeys.Expected["root"]) != 1 {
		t.Errorf("AuthorizedKeys.Expected = %+v, want one root fingerprint", cfg.AuthorizedKeys.Expected)
	}
	if len(cfg.Exceptions) != 1 || cfg.Exceptions[0].Check != "a" {
		t.Errorf("Exceptions = %+v, want the one main entry", cfg.Exceptions)
	}
	if cfg.Notify.Ntfy == nil || cfg.Notify.Ntfy.URL != "https://ntfy.example.com" || cfg.Notify.Ntfy.Topic != "alerts" {
		t.Errorf("Notify.Ntfy = %+v, want the main ntfy section", cfg.Notify.Ntfy)
	}
}

func TestNullInConfDLeavesMainSectionIntact(t *testing.T) {
	// A null section in a conf.d file contributes nothing: the main
	// file's section stays. Without the skip in the merge, the null
	// replaced the section and notifications went silently away.
	tests := []struct {
		name  string
		confd string
	}{
		{"bare notify", "notify:\n"},
		{"notify with a fully commented-out block", "# all commented\nnotify:\n#  ntfy:\n#    topic: other\n"},
		{"explicit null notify", "notify: ~\n"},
		{"bare listeners", "listeners:\n"},
		{"bare listeners.allow", "listeners:\n  allow:\n"},
		{"bare exceptions", "exceptions:\n"},
		{"bare checks", "checks:\n"},
		{"bare host", "host:\n"},
		{"bare authorized_keys", "authorized_keys:\n"},
		{"null notify.ntfy", "notify:\n  ntfy:\n"},
		{"null authorized_keys.expected", "authorized_keys:\n  expected: null\n"},
		{"null checks.sshd", "checks:\n  sshd:\n"},
		{"null checks.sshd.params", "checks:\n  sshd:\n    params: ~\n"},
		{"null checks.sshd.enabled", "checks:\n  sshd:\n    enabled:\n"},
		{"null ntfy.url", "notify:\n  ntfy:\n    url:\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{
				"keepwatch.yaml":        nullMergeMain,
				"conf.d/50-dropin.yaml": tc.confd,
			})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			requireMainIntact(t, cfg)
		})
	}
}

func TestNullInMainDoesNotBlockConfD(t *testing.T) {
	// The other direction: a null in an earlier file does not block a
	// later file, whose value applies.
	t.Run("main null notify, conf.d sets it", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":      "notify:\n",
			"conf.d/10-ntfy.yaml": "notify:\n  ntfy:\n    url: https://ntfy.example.com\n    topic: alerts\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Notify.Ntfy == nil || cfg.Notify.Ntfy.Topic != "alerts" {
			t.Errorf("Notify.Ntfy = %+v, want the conf.d section", cfg.Notify.Ntfy)
		}
	})
	t.Run("main null ntfy, conf.d sets it", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":      "notify:\n  ntfy:\n",
			"conf.d/10-ntfy.yaml": "notify:\n  ntfy:\n    url: https://ntfy.example.com\n    topic: alerts\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Notify.Ntfy == nil || cfg.Notify.Ntfy.Topic != "alerts" {
			t.Errorf("Notify.Ntfy = %+v, want the conf.d section", cfg.Notify.Ntfy)
		}
	})
	t.Run("main null params, conf.d sets them", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "checks:\n  sshd:\n    params:\n",
			"conf.d/10-p.yaml": "checks:\n  sshd:\n    params:\n      k: v\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Checks["sshd"].Params["k"] != "v" {
			t.Errorf("Checks[sshd] = %+v, want params.k v", cfg.Checks["sshd"])
		}
	})
	t.Run("main null exceptions, conf.d appends", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "exceptions:\n",
			"conf.d/10-e.yaml": "exceptions:\n  - check: a\n    reason: r\n    expires: 2099-01-01\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.Exceptions) != 1 {
			t.Errorf("Exceptions = %+v, want the conf.d entry", cfg.Exceptions)
		}
	})
}

func TestNullInEarlierConfDDoesNotBlockLaterOne(t *testing.T) {
	// 10 has a bare notify, 20 sets it, 30 has a bare notify again:
	// the 20 section survives 30 and 10 did not block 20.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml":   "state_dir: /srv/kw\n",
		"conf.d/10-a.yaml": "notify:\n",
		"conf.d/20-b.yaml": "notify:\n  ntfy:\n    url: https://ntfy.example.com\n    topic: b\n",
		"conf.d/30-c.yaml": "notify:\n",
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Notify.Ntfy == nil || cfg.Notify.Ntfy.Topic != "b" {
		t.Errorf("Notify.Ntfy = %+v, want topic b", cfg.Notify.Ntfy)
	}
}

func TestNullKeyOnlyInConfDKeepsItsValidation(t *testing.T) {
	// A null for a key the main file does not have is kept, so it is
	// judged exactly like the same null in a single file: a check
	// entry must be a mapping.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml":   "checks:\n  other:\n    enabled: false\n",
		"conf.d/10-c.yaml": "checks:\n  sshd:\n",
	})
	_, err := Load(main)
	if err == nil || !strings.Contains(err.Error(), "checks.sshd: expected a mapping") {
		t.Fatalf("Load err = %v, want checks.sshd: expected a mapping", err)
	}
}

func TestOptionalNestedNullsCountAsAbsent(t *testing.T) {
	// checks.<id>.params, authorized_keys.expected and notify.ntfy are
	// optional mappings: null means absent, in a single file too.
	t.Run("checks.sshd.params null", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "checks:\n  sshd:\n    enabled: false\n    params: ~\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		c, ok := cfg.Checks["sshd"]
		if !ok || c.Enabled || c.Params != nil {
			t.Errorf("Checks[sshd] = %+v (present %v), want disabled with no params", c, ok)
		}
	})
	t.Run("checks.sshd.params bare", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "checks:\n  sshd:\n    params:\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if c := cfg.Checks["sshd"]; !c.Enabled || c.Params != nil {
			t.Errorf("Checks[sshd] = %+v, want enabled with no params", c)
		}
	})
	t.Run("authorized_keys.expected null", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "authorized_keys:\n  expected:\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if len(cfg.AuthorizedKeys.Expected) != 0 {
			t.Errorf("AuthorizedKeys.Expected = %+v, want empty", cfg.AuthorizedKeys.Expected)
		}
	})
	t.Run("notify.ntfy null", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "notify:\n  ntfy: ~\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Notify.Ntfy != nil {
			t.Errorf("Notify.Ntfy = %+v, want nil", cfg.Notify.Ntfy)
		}
	})
	t.Run("notify.ntfy bare", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "notify:\n  ntfy:\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Notify.Ntfy != nil {
			t.Errorf("Notify.Ntfy = %+v, want nil", cfg.Notify.Ntfy)
		}
	})
	t.Run("a scalar is still an error", func(t *testing.T) {
		for _, y := range []string{
			"checks:\n  sshd:\n    params: 5\n",
			"authorized_keys:\n  expected: 5\n",
			"notify:\n  ntfy: 5\n",
		} {
			_, main := setup(t, map[string]string{"keepwatch.yaml": y})
			loadErrs(t, main, "expected a mapping")
		}
	})
}
