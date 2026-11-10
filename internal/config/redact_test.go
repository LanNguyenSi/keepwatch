package config

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/redact"
)

func TestRedactPatternsLoad(t *testing.T) {
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "redact:\n  patterns:\n    - 'corp-[0-9]{4}'\n    - '(?i)internal-\\w+'\n",
		"conf.d/10.yaml": "redact:\n  patterns:\n    - 'session=([a-z]+)'\n",
	})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{`corp-[0-9]{4}`, `(?i)internal-\w+`, `session=([a-z]+)`}
	if !reflect.DeepEqual(cfg.Redact.Patterns, want) {
		t.Errorf("patterns = %q, want %q (a conf.d list is appended)", cfg.Redact.Patterns, want)
	}
}

func TestRedactAbsentAndNull(t *testing.T) {
	for name, content := range map[string]string{
		"absent":              "state_dir: /srv/kw\n",
		"null section":        "redact:\n",
		"null patterns":       "redact:\n  patterns:\n",
		"empty patterns":      "redact:\n  patterns: []\n",
		"commented out items": "redact:\n  patterns:\n    # - 'x'\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": content})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(cfg.Redact.Patterns) != 0 {
				t.Errorf("patterns = %q", cfg.Redact.Patterns)
			}
		})
	}
	// A bare "redact:" in a drop-in leaves the main file's patterns alone.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "redact:\n  patterns: ['abc']\n",
		"conf.d/10.yaml": "redact:\n",
	})
	cfg, err := Load(main)
	if err != nil || len(cfg.Redact.Patterns) != 1 {
		t.Errorf("Load = %+v, %v", cfg, err)
	}
}

func TestRedactPatternErrors(t *testing.T) {
	long := strings.Repeat("a", redact.MaxPatternLen+1)
	var many strings.Builder
	many.WriteString("redact:\n  patterns:\n")
	for i := 0; i <= redact.MaxPatterns; i++ {
		fmt.Fprintf(&many, "    - 'x%d'\n", i)
	}
	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"not a mapping", "redact: [a]\n", []string{"keepwatch.yaml:1: redact: expected a mapping"}},
		{"unknown key", "redact:\n  extra: 1\n", []string{`keepwatch.yaml:2: redact: unknown key "extra"`}},
		{"patterns not a list", "redact:\n  patterns: abc\n", []string{"keepwatch.yaml:2: redact.patterns: expected a list"}},
		{"item not a string", "redact:\n  patterns:\n    - 5\n", []string{"keepwatch.yaml:3: redact.patterns[0]: expected a string"}},
		{"item a mapping", "redact:\n  patterns:\n    - {a: b}\n", []string{"keepwatch.yaml:3: redact.patterns[0]: expected a string"}},
		{"item null", "redact:\n  patterns:\n    - ~\n", []string{"keepwatch.yaml:3: redact.patterns[0]: expected a string"}},
		{"bad regexp", "redact:\n  patterns:\n    - 'ok'\n    - '('\n", []string{"keepwatch.yaml:4: redact.patterns[1]: is not a valid regular expression"}},
		{"lookahead", "redact:\n  patterns:\n    - '(?=x)y'\n", []string{"keepwatch.yaml:3: redact.patterns[0]: is not a valid regular expression"}},
		{"empty pattern", "redact:\n  patterns:\n    - ''\n", []string{"keepwatch.yaml:3: redact.patterns[0]: must not be empty"}},
		{"matches empty", "redact:\n  patterns:\n    - 'a*'\n", []string{"keepwatch.yaml:3: redact.patterns[0]: matches the empty string"}},
		{"too complex", "redact:\n  patterns:\n    - '(a|b|c|d|e){1000}x'\n", []string{"keepwatch.yaml:3: redact.patterns[0]: is too complex: it compiles to 3003 instructions, the limit is 1000"}},
		{"too long", "redact:\n  patterns:\n    - '" + long + "'\n", []string{"keepwatch.yaml:3: redact.patterns[0]: is 257 bytes long, the limit is 256"}},
		{"too many", many.String(), []string{"keepwatch.yaml:3: redact.patterns: 33 patterns, the limit is 32"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": c.yaml})
			loadErrs(t, main, c.want...)
		})
	}
	// All problems are reported together.
	_, main := setup(t, map[string]string{"keepwatch.yaml": "redact:\n  patterns:\n    - '('\n    - 7\n    - 'a*'\n"})
	loadErrs(t, main, "redact.patterns[0]", "redact.patterns[1]", "redact.patterns[2]")
}

func TestRedactPatternLimitsCountTheMergedList(t *testing.T) {
	var a, b strings.Builder
	a.WriteString("redact:\n  patterns:\n")
	b.WriteString("redact:\n  patterns:\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&a, "    - 'a%d'\n", i)
		fmt.Fprintf(&b, "    - 'b%d'\n", i)
	}
	_, main := setup(t, map[string]string{"keepwatch.yaml": a.String(), "conf.d/10.yaml": b.String()})
	loadErrs(t, main, "redact.patterns: 40 patterns, the limit is 32")
}

func TestRedactPatternsBuildARedactor(t *testing.T) {
	_, main := setup(t, map[string]string{"keepwatch.yaml": "redact:\n  patterns: ['corp-[0-9]{4}']\n"})
	cfg, err := Load(main)
	if err != nil {
		t.Fatal(err)
	}
	r, err := redact.New(cfg.Redact.Patterns)
	if err != nil {
		t.Fatalf("a validated pattern list must build a Redactor: %v", err)
	}
	if got := r.Redact("id corp-1234"); got != "id [REDACTED]" {
		t.Errorf("got %q", got)
	}
}
