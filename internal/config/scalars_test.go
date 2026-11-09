package config

import (
	"testing"
)

func TestScalarTagsRequired(t *testing.T) {
	// Scalars are validated by resolved tag, not raw text: enabled is
	// !!bool, port is !!int, string fields are !!str. 1 and "false" are
	// not booleans; a quoted "22" is not an integer.
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "enabled: 1 is an int, not a bool",
			yaml: "checks:\n  x:\n    enabled: 1\n",
			want: "checks.x.enabled: expected true or false",
		},
		{
			name: "enabled: \"false\" is a string, not a bool",
			yaml: "checks:\n  x:\n    enabled: \"false\"\n",
			want: "checks.x.enabled: expected true or false",
		},
		{
			name: "port: \"22\" is a string, not an int",
			yaml: "listeners:\n  allow:\n    - port: \"22\"\n      proto: tcp\n",
			want: "port: expected an integer",
		},
		{
			name: "port: 2.5 is a float, not an int",
			yaml: "listeners:\n  allow:\n    - port: 2.5\n      proto: tcp\n",
			want: "port: expected an integer",
		},
		{
			name: "null check is an error (required)",
			yaml: "exceptions:\n  - check: ~\n    reason: r\n    expires: 2035-01-01\n",
			want: "check is required",
		},
		{
			name: "null reason is an error (required)",
			yaml: "exceptions:\n  - check: c\n    reason: ~\n    expires: 2035-01-01\n",
			want: "reason is required",
		},
		{
			name: "null expires is an error (required)",
			yaml: "exceptions:\n  - check: c\n    reason: r\n    expires: ~\n",
			want: "expires is required",
		},
		{
			name: "state_dir: 5 is not a string",
			yaml: "state_dir: 5\n",
			want: "state_dir: expected a string",
		},
		{
			name: "bind: 5 is not a string",
			yaml: "listeners:\n  allow:\n    - port: 22\n      proto: tcp\n      bind: 5\n",
			want: "bind: expected a string",
		},
		{
			name: "profile: 5 is not a string",
			yaml: "host:\n  profile: 5\n",
			want: "host.profile: expected a string",
		},
		{
			name: "null user name is rejected",
			yaml: "authorized_keys:\n  expected:\n    ~:\n      - SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
			want: "expected a string user name",
		},
		{
			name: "int user name is rejected",
			yaml: "authorized_keys:\n  expected:\n    1:\n      - SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
			want: "expected a string user name",
		},
		{
			name: "null fingerprint is rejected",
			yaml: "authorized_keys:\n  expected:\n    root:\n      - ~\n",
			want: "is not a SHA256:<base64> fingerprint",
		},
		{
			name: "int fingerprint is rejected",
			yaml: "authorized_keys:\n  expected:\n    root:\n      - 5\n",
			want: "is not a SHA256:<base64> fingerprint",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": tc.yaml})
			loadErrs(t, main, tc.want)
		})
	}
}

func TestNullIsAbsentForOptionalScalars(t *testing.T) {
	// A !!null value counts as absent for optional fields, and the
	// default applies.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": `
host:
  profile: ~
checks:
  x:
    enabled: ~
    severity: ~
listeners:
  allow:
    - port: 22
      proto: tcp
      bind: ~
exceptions:
  - check: c
    match: null
    reason: r
    expires: 2035-01-01
`,
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Host.Profile != "" {
		t.Errorf("Host.Profile = %q, want empty (null is absent)", cfg.Host.Profile)
	}
	if !cfg.Checks["x"].Enabled {
		t.Error("Checks[x].Enabled = false, want default true (null enabled is absent)")
	}
	if cfg.Checks["x"].Severity != "" {
		t.Errorf("Checks[x].Severity = %q, want empty", cfg.Checks["x"].Severity)
	}
	if cfg.Listeners.Allow[0].Bind != "*" {
		t.Errorf("Allow[0].Bind = %q, want default *", cfg.Listeners.Allow[0].Bind)
	}
	if cfg.Exceptions[0].Match != "" {
		t.Errorf("Exceptions[0].Match = %q, want empty (null match is absent)", cfg.Exceptions[0].Match)
	}
}

func TestNtfyURLRequired(t *testing.T) {
	// url is required when notify.ntfy is present.
	t.Run("missing url", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "notify:\n  ntfy:\n    topic: t\n"})
		loadErrs(t, main, "notify.ntfy.url: required when notify.ntfy is set")
	})
	t.Run("null url", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "notify:\n  ntfy:\n    url: ~\n    topic: t\n"})
		loadErrs(t, main, "notify.ntfy.url: required when notify.ntfy is set")
	})
	t.Run("url present is fine", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "notify:\n  ntfy:\n    url: https://example.com/t\n    topic: t\n"})
		if _, err := Load(main); err != nil {
			t.Fatalf("Load: %v", err)
		}
	})
}

func TestNtfyURLPortRange(t *testing.T) {
	// A port in the ntfy url must be 1-65535.
	tests := []struct {
		url  string
		want string // empty means the url must load
	}{
		{url: "https://example.com:70000/t", want: "port must be between 1 and 65535"},
		{url: "https://example.com:0/t", want: "port must be between 1 and 65535"},
		{url: "http://127.0.0.1:70000/t", want: "port must be between 1 and 65535"},
		{url: "https://example.com:1/t", want: ""},
		{url: "https://example.com:65535/t", want: ""},
		{url: "https://example.com:443/t", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.url, func(t *testing.T) {
			yaml := "notify:\n  ntfy:\n    url: " + tc.url + "\n    topic: t\n"
			_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
			if tc.want == "" {
				if _, err := Load(main); err != nil {
					t.Fatalf("Load(%s): %v", tc.url, err)
				}
				return
			}
			loadErrs(t, main, tc.want)
		})
	}
}
