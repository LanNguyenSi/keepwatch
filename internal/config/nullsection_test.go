package config

import (
	"testing"
)

func TestNullSectionsAreAbsent(t *testing.T) {
	// A section key with a null value (a bare "~", "null" or nothing
	// after the colon) counts as absent: the section keeps its default
	// and no error is reported.
	tests := []struct {
		name  string
		files map[string]string
	}{
		{name: "exceptions with no value", files: map[string]string{"keepwatch.yaml": "exceptions:\n"}},
		{name: "checks with no value", files: map[string]string{"keepwatch.yaml": "checks:\n"}},
		{name: "exceptions explicitly null", files: map[string]string{"keepwatch.yaml": "exceptions: ~\n"}},
		{name: "checks explicitly null", files: map[string]string{"keepwatch.yaml": "checks: null\n"}},
		{name: "host null", files: map[string]string{"keepwatch.yaml": "host:\n"}},
		{name: "listeners null", files: map[string]string{"keepwatch.yaml": "listeners:\n"}},
		{name: "listeners allow null", files: map[string]string{"keepwatch.yaml": "listeners:\n  allow:\n"}},
		{name: "authorized_keys null", files: map[string]string{"keepwatch.yaml": "authorized_keys: ~\n"}},
		{name: "notify null", files: map[string]string{"keepwatch.yaml": "notify: ~\n"}},
		{
			name: "fully commented-out exceptions block",
			files: map[string]string{"keepwatch.yaml": `
state_dir: /srv/kw
exceptions:
  # - check: sshd
  #   reason: maintenance window
  #   expires: 2035-01-15
`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, tc.files)
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load with a null section: %v", err)
			}
			if len(cfg.Exceptions) != 0 || len(cfg.Checks) != 0 || len(cfg.Listeners.Allow) != 0 {
				t.Errorf("cfg = %+v, want all sections absent", cfg)
			}
		})
	}
}
