package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// kindSnippets are one value of each kind, as they appear after "key:".
var kindSnippets = []struct{ name, val string }{
	{"mapping", "{a: 1}"},
	{"sequence", "[1]"},
	{"scalar", "5"},
	{"null", "null"},
}

// mergeFiles merges the documents in order, each as the file named
// names[i], and returns the errors of the merge.
func mergeFiles(t *testing.T, names, docs []string) (*yaml.Node, Errors) {
	t.Helper()
	origins := map[*yaml.Node]string{}
	var root *yaml.Node
	var errs Errors
	for i, d := range docs {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(d), &doc); err != nil {
			t.Fatalf("%s: %v", names[i], err)
		}
		n := doc.Content[0]
		register(n, names[i], origins)
		if root == nil {
			root = n
			continue
		}
		mergeMapping(root, n, "", origins, &errs)
	}
	return root, errs
}

func TestMergeKindChangeTable(t *testing.T) {
	// Every kind of the earlier file against every kind of the later
	// one, at the top level and nested, with the later value in the
	// second and in the third file.
	for _, dk := range kindSnippets {
		for _, vk := range kindSnippets {
			mismatch := dk.name != vk.name && dk.name != "null" && vk.name != "null"
			layouts := []struct {
				name    string
				doc     func(val string) string
				key     string
				keyLine int
			}{
				{name: "top level", doc: func(v string) string { return "k: " + v + "\n" }, key: "k", keyLine: 1},
				{name: "nested", doc: func(v string) string { return "outer:\n  k: " + v + "\n" }, key: "outer.k", keyLine: 2},
				{name: "nested twice", doc: func(v string) string { return "a:\n  b:\n    k: " + v + "\n" }, key: "a.b.k", keyLine: 3},
			}
			for _, l := range layouts {
				t.Run(fmt.Sprintf("%s/%s to %s", l.name, dk.name, vk.name), func(t *testing.T) {
					_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml"}, []string{l.doc(dk.val), l.doc(vk.val)})
					want := fmt.Sprintf("%s in a.yaml:%d changes the type set in main.yaml:%d", l.key, l.keyLine, l.keyLine)
					if !mismatch {
						if len(errs) != 0 {
							t.Fatalf("errors = %v, want none", errs)
						}
						return
					}
					if len(errs) != 1 || errs[0].Msg != want || errs[0].File != "a.yaml" || errs[0].Line != l.keyLine {
						t.Fatalf("errors = %v, want exactly %q at a.yaml:%d", errs, want, l.keyLine)
					}
				})
			}
			t.Run(fmt.Sprintf("third file/%s to %s", dk.name, vk.name), func(t *testing.T) {
				// The second file does not mention the key: the third is
				// compared with the first.
				_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml", "b.yaml"},
					[]string{"k: " + dk.val + "\n", "other: 1\n", "k: " + vk.val + "\n"})
				want := "k in b.yaml:1 changes the type set in main.yaml:1"
				if !mismatch {
					if len(errs) != 0 {
						t.Fatalf("errors = %v, want none", errs)
					}
					return
				}
				if len(errs) != 1 || errs[0].Msg != want || errs[0].File != "b.yaml" {
					t.Fatalf("errors = %v, want exactly %q", errs, want)
				}
			})
		}
	}
}

func TestMergeKindChangeIsComparedWithTheLatestSetter(t *testing.T) {
	// main sets a scalar, a.yaml replaces it by a scalar again, b.yaml
	// by a sequence: the message names a.yaml, which set the value b.yaml
	// replaces. A null in between does not change that, and a null before
	// the value is replaced silently.
	t.Run("latest scalar setter", func(t *testing.T) {
		_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml", "b.yaml"},
			[]string{"x: 1\n", "# comment\nx: 2\n", "x: [1]\n"})
		if len(errs) != 1 || errs[0].Msg != "x in b.yaml:1 changes the type set in a.yaml:2" {
			t.Fatalf("errors = %v", errs)
		}
	})
	t.Run("a null in between", func(t *testing.T) {
		_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml", "b.yaml"},
			[]string{"x: 1\n", "x:\n", "x: [1]\n"})
		if len(errs) != 1 || errs[0].Msg != "x in b.yaml:1 changes the type set in main.yaml:1" {
			t.Fatalf("errors = %v", errs)
		}
	})
	t.Run("a null before", func(t *testing.T) {
		root, errs := mergeFiles(t, []string{"main.yaml", "a.yaml", "b.yaml"},
			[]string{"x:\n", "x: 1\n", "x: 2\n"})
		if len(errs) != 0 {
			t.Fatalf("errors = %v, want none", errs)
		}
		if got := root.Content[1].Value; got != "2" {
			t.Errorf("x = %q, want 2", got)
		}
	})
}

func TestMergeKeepsTheRulesForSameKinds(t *testing.T) {
	// The merge rule of the same kinds is unchanged: mappings merge,
	// sequences append, scalars are replaced, a null later value
	// contributes nothing.
	root, errs := mergeFiles(t, []string{"main.yaml", "a.yaml"},
		[]string{"m: {a: 1, b: 2}\ns: [1, 2]\nc: old\nn: keep\n", "m: {b: 3, c: 4}\ns: [3]\nc: new\nn:\n"})
	if len(errs) != 0 {
		t.Fatalf("errors = %v", errs)
	}
	var got map[string]any
	if err := root.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "map[c:new m:map[a:1 b:3 c:4] n:keep s:[1 2 3]]" {
		t.Errorf("merged = %v", got)
	}
}

func TestMergeKindChangeThroughAliases(t *testing.T) {
	// An alias counts as the kind of its anchor: the same kind is not an
	// error, another one is.
	for _, c := range []struct{ name, anchor, later string }{
		{"sequence", "[1]", "[2]"},
		{"scalar", "5", "6"},
		{"mapping", "{a: 1}", "{b: 2}"},
	} {
		_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml"},
			[]string{"base: &b " + c.anchor + "\nk: *b\n", "k: " + c.later + "\n"})
		if len(errs) != 0 {
			t.Errorf("alias of a %s replaced by a %s: errors = %v, want none", c.name, c.name, errs)
		}
	}
	_, errs := mergeFiles(t, []string{"main.yaml", "a.yaml"},
		[]string{"base: &b [1]\nk: *b\n", "k: 5\n"})
	if len(errs) != 1 || errs[0].Msg != "k in a.yaml:1 changes the type set in main.yaml:2" {
		t.Fatalf("errors = %v", errs)
	}
}

func TestLoadReportsKindChanges(t *testing.T) {
	cases := []struct {
		name  string
		main  string
		confd map[string]string
		want  []string
	}{
		{
			name:  "a sequence replaces a scalar",
			main:  "exceptions: 5\n",
			confd: map[string]string{"a.yaml": "exceptions:\n  - check: a\n    reason: r\n    expires: 2099-01-01\n"},
			want:  []string{"exceptions in {conf}/a.yaml:1 changes the type set in {main}:1"},
		},
		{
			name:  "a scalar replaces a sequence",
			main:  "state_dir: [1]\n",
			confd: map[string]string{"a.yaml": "state_dir: /srv/kw\n"},
			want:  []string{"state_dir in {conf}/a.yaml:1 changes the type set in {main}:1"},
		},
		{
			name:  "a mapping replaces a scalar below notify",
			main:  "notify:\n  ntfy: nothing\n",
			confd: map[string]string{"a.yaml": "notify:\n  ntfy:\n    url: https://ntfy.example.com\n    topic: alerts\n"},
			want:  []string{"notify.ntfy in {conf}/a.yaml:2 changes the type set in {main}:2"},
		},
		{
			name:  "the second of two drop-ins",
			main:  "host:\n  profile: web\n",
			confd: map[string]string{"a.yaml": "host:\n  profile: a\n", "b.yaml": "host: [web]\n"},
			want:  []string{"host in {conf}/b.yaml:1 changes the type set in {main}:1"},
		},
		{
			name:  "a mapping replaces a mapping value that is a sequence below checks",
			main:  "checks:\n  sshd:\n    params:\n      key: [1]\n",
			confd: map[string]string{"a.yaml": "checks:\n  sshd:\n    params:\n      key: x\n"},
			want:  []string{"checks.sshd.params.key in {conf}/a.yaml:4 changes the type set in {main}:4"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"keepwatch.yaml": c.main}
			for n, v := range c.confd {
				files["conf.d/"+n] = v
			}
			dir, main := setup(t, files)
			errs := errsOf(t, main)
			for _, w := range c.want {
				w = strings.NewReplacer("{conf}", filepath.Join(dir, "conf.d"), "{main}", main).Replace(w)
				if !containsSub(errs, w) {
					t.Errorf("errors %q lack %q", errs, w)
				}
			}
			n := 0
			for _, e := range errs {
				if strings.Contains(e, "changes the type") {
					n++
				}
			}
			if n != len(c.want) {
				t.Errorf("%d kind-change errors in %q, want %d", n, errs, len(c.want))
			}
		})
	}
}

func TestLoadAcceptsSameKindsAndNulls(t *testing.T) {
	_, main := setup(t, map[string]string{
		"keepwatch.yaml": nullMergeMain,
		"conf.d/a.yaml":  "host:\n  profile: a\nnotify:\nexceptions:\n  - check: b\n    reason: r\n    expires: 2099-01-01\n",
		"conf.d/b.yaml":  "state_dir: /srv/kw\n",
	})
	if _, err := Load(main); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
