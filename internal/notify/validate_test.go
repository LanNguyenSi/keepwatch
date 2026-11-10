package notify

import (
	"strings"
	"testing"
)

func TestValidateURL(t *testing.T) {
	good := []string{
		"https://ntfy.example.org", "https://ntfy.example.org/", "https://ntfy.example.org/ntfy", "https://ntfy.example.org:8443",
		"https://[2001:db8::1]:443/x", "http://127.0.0.1", "http://127.0.0.1:80", "http://localhost:8080", "http://[::1]:2586",
		"https://example.com:1", "https://example.com:65535",
	}
	for _, u := range good {
		if err := ValidateURL(u); err != nil {
			t.Errorf("ValidateURL(%q) = %v", u, err)
		}
	}
	bad := map[string]string{
		"":                             "not a valid absolute URL",
		"ntfy.example.org":             "not a valid absolute URL",
		"https://":                     "not a valid absolute URL",
		"https://:443/x":               "not a valid absolute URL",
		"https://host:/x":              "not a valid absolute URL",
		"https://exa mple.com":         "not a valid absolute URL",
		"%":                            "not a valid absolute URL",
		"https://user@example.com":     "must not hold credentials",
		"https://user:pw@example.com":  "must not hold credentials",
		"http://u:p@127.0.0.1:80/":     "must not hold credentials",
		"https://example.com/?auth=x":  "query or a fragment",
		"https://example.com?":         "query or a fragment",
		"https://example.com/#f":       "query or a fragment",
		"https://example.com/#":        "query or a fragment",
		"https://example.com:0":        "port must be between 1 and 65535",
		"https://example.com:65536":    "port must be between 1 and 65535",
		"https://example.com:99999":    "port must be between 1 and 65535",
		"http://example.com":           "http is only allowed for loopback",
		"http://10.0.0.1:80":           "http is only allowed for loopback",
		"http://localhost.example.com": "http is only allowed for loopback",
		"ftp://example.com":            "scheme must be https",
		"ws://127.0.0.1":               "scheme must be https",
		"HTTPS-://example.com":         "scheme must be https",
	}
	for u, want := range bad {
		err := ValidateURL(u)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateURL(%q) = %v, want %q", u, err, want)
		}
	}
}

// A message never holds the URL: it may carry credentials.
func TestValidateURLNeverEchoesTheURL(t *testing.T) {
	for _, u := range []string{
		"https://kwuser:kwSECRETpass@example.com/?auth=QXV0aFNlY3JldA", "http://kwuser:kwSECRETpass@10.0.0.1:99999/x#frag",
		"ftp://kwuser:kwSECRETpass@example.com", "https://kwSECRETpass@:/x", "https://example.com:99999/kwSECRETpath?kwSECRETq",
	} {
		err := ValidateURL(u)
		if err == nil {
			t.Fatalf("%q was accepted", u)
		}
		for _, secret := range []string{"kwSECRET", "kwuser", "QXV0", "example.com", "10.0.0.1"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("ValidateURL(%q): the message holds %q: %v", u, secret, err)
			}
		}
	}
}

func TestValidateTopic(t *testing.T) {
	for _, s := range []string{"a", "alerts", "kw-alerts_1", "A-Z_a-z-0-9", strings.Repeat("a", 64)} {
		if err := ValidateTopic(s); err != nil {
			t.Errorf("ValidateTopic(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"", "kw.alerts", "a b", "a/b", "a?b", "a#b", "ü", "a\n", strings.Repeat("a", 65), "%2e", "a:b", "a@b"} {
		if err := ValidateTopic(s); err == nil || !strings.Contains(err.Error(), "1 to 64 characters") {
			t.Errorf("ValidateTopic(%q) = %v", s, err)
		}
	}
}

// NewNtfy applies exactly these rules.
func TestNewNtfyAppliesTheValidationRules(t *testing.T) {
	if _, err := NewNtfy(NtfyConfig{URL: "https://example.com:99999", Topic: "t"}); err == nil || !strings.Contains(err.Error(), "port must be between") {
		t.Errorf("a bad port: %v", err)
	}
	if _, err := NewNtfy(NtfyConfig{URL: "https://example.com", Topic: "kw.alerts"}); err == nil || !strings.Contains(err.Error(), "topic must be") {
		t.Errorf("a bad topic: %v", err)
	}
	if _, err := NewNtfy(NtfyConfig{URL: "https://u:p@example.com", Topic: "t"}); err == nil || strings.Contains(err.Error(), "u:p") {
		t.Errorf("credentials: %v", err)
	}
	if _, err := NewNtfy(NtfyConfig{URL: "https://example.com/ntfy/", Topic: "t"}); err != nil {
		t.Errorf("a good config: %v", err)
	}
}
