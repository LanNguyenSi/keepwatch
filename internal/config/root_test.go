package config

import (
	"path/filepath"
	"testing"
)

func TestRootMustBeMapping(t *testing.T) {
	// Every file's root must be a mapping or empty (a null document
	// counts as empty). A non-mapping root is an error naming the file
	// and line; no file ever replaces another root wholesale.
	t.Run("main file is a list, conf.d is a mapping", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml": "- a\n- b\n",
			"conf.d/a.yaml":  "state_dir: /from-a\n",
		})
		loadErrs(t, main, main+":1: the configuration root must be a mapping")
	})
	t.Run("main file is a scalar", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "just text\n"})
		loadErrs(t, main, main+":1: the configuration root must be a mapping")
	})
	t.Run("conf.d file is a list", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /from-main\n",
			"conf.d/a.yaml":  "- a\n",
		})
		confd := filepath.Join(dir, "conf.d", "a.yaml")
		loadErrs(t, main, confd+":1: the configuration root must be a mapping")
	})
	t.Run("conf.d file is a scalar", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /from-main\n",
			"conf.d/a.yaml":  "5\n",
		})
		confd := filepath.Join(dir, "conf.d", "a.yaml")
		loadErrs(t, main, confd+":1: the configuration root must be a mapping")
	})
	t.Run("empty conf.d file is fine", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_dir: /from-main\n",
			"conf.d/a.yaml":  "",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load with empty conf.d file: %v", err)
		}
		if cfg.StateDir != "/from-main" {
			t.Errorf("StateDir = %q, want /from-main", cfg.StateDir)
		}
	})
	t.Run("null document root is empty and fine", func(t *testing.T) {
		for _, doc := range []string{"~\n", "null\n", "--- ~\n"} {
			_, main := setup(t, map[string]string{
				"keepwatch.yaml": doc,
				"conf.d/a.yaml":  "~\n",
			})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load with document %q: %v", doc, err)
			}
			if cfg.StateDir != DefaultStateDir {
				t.Errorf("StateDir = %q, want default", cfg.StateDir)
			}
		}
	})
	t.Run("quoted scalar root is not null", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "\"null\"\n"})
		loadErrs(t, main, "the configuration root must be a mapping")
	})
}
