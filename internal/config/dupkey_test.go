package config

import (
	"testing"
)

func TestDuplicateKeys(t *testing.T) {
	// Node decoding skips yaml.v3's unique-key check, so every repeated
	// key in one mapping is reported at any depth:
	// file:line: duplicate key "x" (first at line N).
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "top-level duplicate",
			files: map[string]string{"keepwatch.yaml": "state_dir: /a\nstate_dir: /b\n"},
			want:  ":2: duplicate key \"state_dir\" (first at line 1)",
		},
		{
			name:  "duplicate inside checks.<id>",
			files: map[string]string{"keepwatch.yaml": "checks:\n  x:\n    severity: high\n    severity: low\n"},
			want:  ":4: duplicate key \"severity\" (first at line 3)",
		},
		{
			name:  "duplicate check id inside checks",
			files: map[string]string{"keepwatch.yaml": "checks:\n  x:\n    severity: high\n  x:\n    severity: low\n"},
			want:  ":4: duplicate key \"x\" (first at line 2)",
		},
		{
			name: "duplicate inside notify.ntfy",
			files: map[string]string{
				"keepwatch.yaml": "notify:\n  ntfy:\n    url: https://example.com/t\n    topic: a\n    topic: b\n",
			},
			want: ":5: duplicate key \"topic\" (first at line 4)",
		},
		{
			name: "duplicate inside check params",
			files: map[string]string{
				"keepwatch.yaml": "checks:\n  x:\n    params:\n      a: 1\n      a: 2\n",
			},
			want: ":5: duplicate key \"a\" (first at line 4)",
		},
		{
			name: "duplicate inside a list entry",
			files: map[string]string{
				"keepwatch.yaml": "listeners:\n  allow:\n    - port: 22\n      proto: tcp\n      proto: udp\n",
			},
			want: ":5: duplicate key \"proto\" (first at line 4)",
		},
		{
			name: "duplicate in conf.d file names that file",
			files: map[string]string{
				"keepwatch.yaml": "state_dir: /from-main\n",
				"conf.d/a.yaml":  "host:\n  profile: a\n  profile: b\n",
			},
			want: "conf.d/a.yaml:3: duplicate key \"profile\" (first at line 2)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, tc.files)
			loadErrs(t, main, tc.want)
		})
	}
}

func TestDuplicateKeySwallowsConfDOverride(t *testing.T) {
	// A duplicated key in the main file would silently drop the first
	// value and change which value a conf.d override lands on. The
	// duplicate must be an error, not a merge order choice.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /from-main\nlisteners:\n  allow:\n    - port: 22\n      proto: tcp\nlisteners:\n  allow:\n    - port: 80\n      proto: tcp\n",
		"conf.d/a.yaml":  "listeners:\n  allow:\n    - port: 443\n      proto: tcp\n",
	})
	loadErrs(t, main, main+":6: duplicate key \"listeners\" (first at line 2)")
}

func TestDuplicateKeyThreeOccurrences(t *testing.T) {
	// Every repeated occurrence is reported, each pointing at the first.
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": "state_dir: /a\nstate_dir: /b\nstate_dir: /c\n",
	})
	errs := errsOf(t, main)
	for _, want := range []string{
		":2: duplicate key \"state_dir\" (first at line 1)",
		":3: duplicate key \"state_dir\" (first at line 1)",
	} {
		if !containsSub(errs, want) {
			t.Errorf("errors %q lack %q", errs, want)
		}
	}
	if len(errs) != 2 {
		t.Errorf("len(errs) = %d, want exactly 2: %q", len(errs), errs)
	}
}

func TestRepeatedKeyAcrossMappingsIsFine(t *testing.T) {
	// The same key in different mappings (two checks, or main vs conf.d
	// for an override) is not a duplicate.
	files := map[string]string{
		"keepwatch.yaml": "checks:\n  x:\n    severity: high\n  y:\n    severity: low\n",
		"conf.d/a.yaml":  "state_dir: /from-a\n",
	}
	_, main := setup(t, files)
	if _, err := Load(main); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
