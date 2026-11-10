package config

import (
	"strings"
	"testing"
)

// neg runs one invalid YAML fragment through Load and requires the
// reported error to contain both want and the line of the fragment's
// marked line (the line containing the substring marked with "#!").
func TestSchemaNegative(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown key at top level",
			yaml: "state_di: /srv/kw\n",
			want: `unknown key "state_di"`,
		},
		{
			name: "unknown key nested in host",
			yaml: "host:\n  profil: x\n",
			want: `host: unknown key "profil"`,
		},
		{
			name: "unknown key nested in a check",
			yaml: "checks:\n  sshd:\n    enabld: true\n",
			want: `checks.sshd: unknown key "enabld"`,
		},
		{
			name: "unknown key nested in listeners",
			yaml: "listeners:\n  alloww: []\n",
			want: `listeners: unknown key "alloww"`,
		},
		{
			name: "wrong type: state_dir not a string",
			yaml: "state_dir: [a, b]\n",
			want: "state_dir: expected a string",
		},
		{
			name: "wrong type: enabled not a bool",
			yaml: "checks:\n  x:\n    enabled: maybe\n",
			want: "checks.x.enabled: expected true or false",
		},
		{
			name: "wrong severity",
			yaml: "checks:\n  x:\n    severity: fatal\n",
			want: "checks.x.severity",
		},
		{
			name: "port 0 rejected",
			yaml: "listeners:\n  allow:\n    - port: 0\n      proto: tcp\n",
			want: "port: must be between 1 and 65535",
		},
		{
			name: "port 65536 rejected",
			yaml: "listeners:\n  allow:\n    - port: 65536\n      proto: tcp\n",
			want: "port: must be between 1 and 65535",
		},
		{
			name: "port not a number",
			yaml: "listeners:\n  allow:\n    - port: http\n      proto: tcp\n",
			want: "port: expected an integer",
		},
		{
			name: "port missing",
			yaml: "listeners:\n  allow:\n    - proto: tcp\n",
			want: "listeners.allow[0]: port is required",
		},
		{
			name: "proto missing",
			yaml: "listeners:\n  allow:\n    - port: 22\n",
			want: "listeners.allow[0]: proto is required",
		},
		{
			name: "proto other than tcp or udp",
			yaml: "listeners:\n  allow:\n    - port: 22\n      proto: icmp\n",
			want: "proto: \"icmp\" is not tcp or udp",
		},
		{
			name: "bind not an IP literal or star",
			yaml: "listeners:\n  allow:\n    - port: 22\n      proto: tcp\n      bind: example.com\n",
			want: "bind:",
		},
		{
			name: "bad fingerprint (no prefix)",
			yaml: "authorized_keys:\n  expected:\n    root:\n      - abcdef\n",
			want: "is not a SHA256:<base64> fingerprint",
		},
		{
			name: "bad fingerprint (too short)",
			yaml: "authorized_keys:\n  expected:\n    root:\n      - SHA256:short\n",
			want: "is not a SHA256:<base64> fingerprint",
		},
		{
			name: "bad fingerprint (bad chars)",
			yaml: "authorized_keys:\n  expected:\n    root:\n      - SHA256:@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n",
			want: "is not a SHA256:<base64> fingerprint",
		},
		{
			name: "exception missing reason",
			yaml: "exceptions:\n  - check: x\n    expires: 2035-01-01\n",
			want: "reason is required",
		},
		{
			name: "exception empty reason",
			yaml: "exceptions:\n  - check: x\n    reason: \"   \"\n    expires: 2035-01-01\n",
			want: "reason: must not be empty",
		},
		{
			name: "exception missing expires",
			yaml: "exceptions:\n  - check: x\n    reason: r\n",
			want: "expires is required",
		},
		{
			name: "exception missing check",
			yaml: "exceptions:\n  - reason: r\n    expires: 2035-01-01\n",
			want: "check is required",
		},
		{
			name: "wrong date format (text)",
			yaml: "exceptions:\n  - check: x\n    reason: r\n    expires: soon\n",
			want: "is not a date in YYYY-MM-DD form",
		},
		{
			name: "wrong date format (single digit)",
			yaml: "exceptions:\n  - check: x\n    reason: r\n    expires: 2035-1-1\n",
			want: "is not a date in YYYY-MM-DD form",
		},
		{
			name: "wrong date format (impossible day)",
			yaml: "exceptions:\n  - check: x\n    reason: r\n    expires: 2035-02-30\n",
			want: "is not a date in YYYY-MM-DD form",
		},
		{
			name: "ntfy http to non-loopback host",
			yaml: "notify:\n  ntfy:\n    url: http://example.com/t\n    topic: t\n",
			want: "http is only allowed for loopback hosts",
		},
		{
			name: "ntfy other scheme",
			yaml: "notify:\n  ntfy:\n    url: ftp://localhost/t\n    topic: t\n",
			want: "the scheme must be https",
		},
		{
			name: "ntfy missing topic",
			yaml: "notify:\n  ntfy:\n    url: https://example.com/t\n",
			want: "topic",
		},
		{
			name: "ntfy empty topic",
			yaml: "notify:\n  ntfy:\n    url: https://example.com/t\n    topic: \"\"\n",
			want: "topic must be 1 to 64 characters",
		},
		{
			name: "token_file must be absolute",
			yaml: "notify:\n  ntfy:\n    url: https://example.com/t\n    topic: t\n    token_file: rel/token\n",
			want: "token_file: must be an absolute path",
		},
		{
			name: "checks must be a mapping",
			yaml: "checks: [a]\n",
			want: "checks: expected a mapping",
		},
		{
			name: "exceptions must be a list",
			yaml: "exceptions: {x: 1}\n",
			want: "exceptions: expected a list",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": tc.yaml})
			loadErrs(t, main, tc.want)
		})
	}
}

func TestSchemaPositiveLoopbackVariants(t *testing.T) {
	// http is allowed for every loopback form; https anywhere.
	for _, url := range []string{
		"http://localhost:8080/t",
		"http://127.0.0.1:8080/t",
		"http://[::1]:8080/t",
		"https://ntfy.example.com/t",
	} {
		t.Run(url, func(t *testing.T) {
			yaml := "notify:\n  ntfy:\n    url: " + url + "\n    topic: t\n"
			_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
			if _, err := Load(main); err != nil {
				t.Errorf("Load(%s): %v", url, err)
			}
		})
	}
}

func TestSchemaValidFingerprintWithPadding(t *testing.T) {
	// Accept the padded base64 form as well as the OpenSSH unpadded one.
	yaml := "authorized_keys:\n  expected:\n    root:\n      - SHA256:" + strings.Repeat("A", 43) + "=\n"
	_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
	if _, err := Load(main); err != nil {
		t.Errorf("Load: %v", err)
	}
}

func TestSyntaxErrorNamesLine(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": "host: [unclosed\n"})
	loadErrs(t, main, main+":1:")
}
