package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
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
