package install

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// `uninstall --purge` removes what keepwatch writes in state_dir and leaves the
// rest. These two tests tie the owned set to the packages that write the
// directory: a file one of them starts to write has to be owned, or the test
// fails and purge would otherwise leave the directory behind.

// Every file the real writers produce is owned.
func TestOwnedSetCoversTheFilesTheWritersProduce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(state.FromResults(nil, time.Now(), nil)); err != nil {
		t.Fatal(err)
	}
	hs, err := history.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem, err := hs.Append(history.Run{RunAt: time.Now().UTC().Truncate(time.Second), Changes: []history.Change{}}); err != nil || problem != "" {
		t.Fatalf("history append: %q %v", problem, err)
	}
	// The doctor probe and the atomic writer of a Dir.
	od, err := (OSFS{}).OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer od.Close()
	if err := od.WriteFile(ProbePrefix+"0123456789abcdef", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		if !ownedInStateDir(e.Name()) {
			t.Errorf("the writers produced %s, which purge does not own", e.Name())
		}
	}
	sort.Strings(names)
	if len(names) != 3 {
		t.Errorf("the directory holds %v, want state.json, history.json and the probe file", names)
	}
	// A leftover of each kind of crash.
	for _, n := range []string{state.TempPrefix + "0123", history.TempPrefix + "0123", tmpWritePrefix + "0123", ProbePrefix + "0123"} {
		if !ownedInStateDir(n) {
			t.Errorf("the leftover %s is not owned", n)
		}
	}
	for _, n := range []string{"history.json.bak", "state.json~", "other.json", ".state.json", "notes.txt", "backup.tar"} {
		if ownedInStateDir(n) {
			t.Errorf("%s is owned", n)
		}
	}
}

var fileNameLiteral = regexp.MustCompile(`^\.?[A-Za-z0-9_-][A-Za-z0-9._-]*\.json$|^\.[A-Za-z0-9._-]*\.tmp-$`)

// Any file name literal in the packages that write state_dir is owned: a new
// writer cannot add a file without this test noticing.
func TestEveryFileNameTheStateWritersMentionIsOwned(t *testing.T) {
	fset := token.NewFileSet()
	found := 0
	for _, pkg := range []string{"../state", "../history"} {
		files, err := filepath.Glob(filepath.Join(pkg, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no sources in %s: %v", pkg, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			tree, err := parser.ParseFile(fset, f, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(tree, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil || !fileNameLiteral.MatchString(s) {
					return true
				}
				found++
				if !ownedInStateDir(s) && !ownedInStateDir(s+"0123") {
					t.Errorf("%s mentions the file name %q, which purge does not own", fset.Position(lit.Pos()), s)
				}
				return true
			})
		}
	}
	if found < 4 {
		t.Errorf("the scan found %d file name literals, want at least the four constants (state, history and their temp prefixes)", found)
	}
}
