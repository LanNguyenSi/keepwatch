package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/redact"
)

// The example that `keepwatch init` writes must work with the catalog it
// ships with: every check id and parameter it names has to be known to the
// engine, or `keepwatch check` would refuse the very file `init` wrote.
func TestExampleConfigPassesEnginePrepare(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	if err := os.WriteFile(main, config.Example(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cat, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	deps := engine.Deps{Runner: fake.New(nil), FS: probestest.MemFS{}, Now: time.Now}
	if _, err := engine.Prepare(cat, cfg, deps); err != nil {
		t.Fatalf("the example configuration does not pass engine.Prepare:\n%v", err)
	}
	// The example really configures checks and an exception, so the test
	// above exercises the id and parameter validation.
	if len(cfg.Checks) == 0 || len(cfg.Exceptions) == 0 {
		t.Errorf("the example configures %d checks and %d exceptions", len(cfg.Checks), len(cfg.Exceptions))
	}
	for id := range cfg.Checks {
		if !cat.Has(id) {
			t.Errorf("example check %q is not in the catalog", id)
		}
	}
	for _, e := range cfg.Exceptions {
		if !cat.Has(e.Check) {
			t.Errorf("example exception check %q is not in the catalog", e.Check)
		}
	}
}

// uncommentBlock removes the leading "# " of the line that starts with head
// and of the commented lines that follow it, up to the first line that is not
// part of the comment block.
func uncommentBlock(t *testing.T, text, head string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	start := -1
	for i, l := range lines {
		if l == head {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the example has no line %q", head)
	}
	for i := start; i < len(lines) && strings.HasPrefix(lines[i], "#"); i++ {
		lines[i] = strings.TrimPrefix(strings.TrimPrefix(lines[i], "#"), " ")
	}
	return strings.Join(lines, "\n")
}

// The redact block of the example is commented out, and the README and the
// comment promise what its two patterns do. Uncommented, it must load, pass
// the engine, compile as redaction patterns and behave as documented.
func TestExampleRedactBlockIsValidWhenUncommented(t *testing.T) {
	text := uncommentBlock(t, string(config.Example()), "# redact:")
	dir := t.TempDir()
	main := filepath.Join(dir, "keepwatch.yaml")
	if err := os.WriteFile(main, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(main)
	if err != nil {
		t.Fatalf("the example with its redact block uncommented does not load: %v", err)
	}
	if len(cfg.Redact.Patterns) != 2 {
		t.Fatalf("patterns = %q, want the two of the example", cfg.Redact.Patterns)
	}
	cat, err := catalog.Base()
	if err != nil {
		t.Fatal(err)
	}
	deps := engine.Deps{Runner: fake.New(nil), FS: probestest.MemFS{}, Now: time.Now}
	if _, err := engine.Prepare(cat, cfg, deps); err != nil {
		t.Fatalf("engine.Prepare: %v", err)
	}
	red, err := redact.New(cfg.Redact.Patterns)
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}
	for in, want := range map[string]string{
		"id corp-1234 end":            "id [REDACTED] end",               // the whole match
		"cookie session=abc123; path": "cookie session=[REDACTED]; path", // only the group
		"nothing to see":              "nothing to see",
	} {
		if got := red.Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}
