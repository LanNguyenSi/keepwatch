package config

import (
	"path/filepath"
	"strconv"
	"testing"
)

func TestConfDYmlIsError(t *testing.T) {
	// A *.yml file in conf.d is silently skipped today; it must be an
	// error because it would look loaded but never is.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /from-main\n",
		"conf.d/a.yml":   "state_dir: /from-a\n",
		"conf.d/b.yaml":  "host:\n  profile: b\n",
	})
	errs := errsOf(t, main)
	yml := filepath.Join(dir, "conf.d", "a.yml")
	if !containsSub(errs, yml+`: unsupported extension ".yml": use the .yaml extension`) {
		t.Errorf("errors %q lack the .yml error for %s", errs, yml)
	}
}

func TestConfDExtensionCaseIsError(t *testing.T) {
	// A .yaml/.yml extension in any other case is an error with a
	// clear message: only the exact lower-case extension is loaded,
	// and a file that would look loaded must not be skipped silently.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /from-main\n",
		"conf.d/a.YAML":  "state_dir: /from-a\n",
		"conf.d/b.Yml":   "state_dir: /from-b\n",
	})
	errs := errsOf(t, main)
	for _, name := range []struct{ file, ext string }{
		{"a.YAML", ".YAML"},
		{"b.Yml", ".Yml"},
	} {
		p := filepath.Join(dir, "conf.d", name.file)
		want := "unsupported extension " + strconv.Quote(name.ext) + ": use lower-case .yaml"
		if !containsSub(errs, p+": "+want) {
			t.Errorf("errors %q lack %q for %s", errs, want, p)
		}
	}
}

func TestConfDSubdirectoryIsError(t *testing.T) {
	// A subdirectory inside conf.d is an error: silently skipping it
	// would let a file tree that looks loaded never be loaded.
	dir, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /from-main\n",
		"conf.d/sub/":    "",
	})
	errs := errsOf(t, main)
	sub := filepath.Join(dir, "conf.d", "sub")
	if !containsSub(errs, sub+": conf.d must not contain directories") {
		t.Errorf("errors %q lack the subdirectory error for %s", errs, sub)
	}
}

func TestMultiDocumentReportsSecondDocumentLine(t *testing.T) {
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "# comment\nstate_dir: /a\n---\nstate_dir: /b\n",
	})
	loadErrs(t, main, main+":3: unexpected content after the first document")
}

func TestParseErrorDoesNotHideOtherFileErrors(t *testing.T) {
	// A syntax problem in one file must not hide the validation
	// problems of the other files: every file that parses is still
	// validated and all errors are reported together.
	t.Run("main has a syntax error, conf.d has a schema error", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "host: [unclosed\n",
			"conf.d/a.yaml":  "listeners:\n  allow:\n    - port: 0\n      proto: tcp\n",
		})
		confd := filepath.Join(dir, "conf.d", "a.yaml")
		errs := errsOf(t, main)
		if !containsSub(errs, main+":1: ") {
			t.Errorf("errors %q lack the main syntax error", errs)
		}
		if !containsSub(errs, confd+":3: listeners.allow[0].port: must be between 1 and 65535, got 0") {
			t.Errorf("errors %q lack the conf.d validation error", errs)
		}
	})
	t.Run("conf.d has a syntax error, main has a schema error", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml": "state_di: /srv/kw\n",
			"conf.d/a.yaml":  "host: [unclosed\n",
		})
		confd := filepath.Join(dir, "conf.d", "a.yaml")
		errs := errsOf(t, main)
		if !containsSub(errs, confd+":1: ") {
			t.Errorf("errors %q lack the conf.d syntax error", errs)
		}
		if !containsSub(errs, main+":1: unknown key \"state_di\"") {
			t.Errorf("errors %q lack the main validation error", errs)
		}
	})
	t.Run("missing main file still reports conf.d errors", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"conf.d/a.yaml": "listeners:\n  allow:\n    - port: 0\n      proto: tcp\n",
		})
		errs := errsOf(t, main)
		if !containsSub(errs, main+": cannot read:") {
			t.Errorf("errors %q lack the missing-main error", errs)
		}
		confd := filepath.Join(dir, "conf.d", "a.yaml")
		if !containsSub(errs, confd+":3: listeners.allow[0].port: must be between 1 and 65535, got 0") {
			t.Errorf("errors %q lack the conf.d validation error", errs)
		}
	})
}
