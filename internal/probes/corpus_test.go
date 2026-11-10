package probes_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// The apt corpus. The output of "apt-cache policy" and of "apt-get -s
// dist-upgrade" is read by strict parsers (an unknown line is an error, never
// a pass), so they must be shown to read everything apt really prints, not
// only the states that a test builds itself. testdata/aptcorpus.sh writes the
// corpus in a container: the simulation, apt-cache policy for the packages it
// upgrades or keeps back, for every installed package and for a sample of all
// package names, in batches of 100 as the probe asks for them.
//
// TestAptCorpus runs the checked-in slices of it. With KW_APT_CORPUS=<dir> it
// reads the full corpus of that directory (one directory per release, each
// holding the files of aptcorpus.sh) and logs the number of lines per shape.

// aptCorpusFiles lists the policy files of a corpus directory.
func aptCorpusFiles(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	for _, pattern := range []string{"simpolicy.*", "instpolicy.*", "samplepolicy.*", "phasedpolicy.txt"} {
		m, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			if !strings.HasSuffix(f, ".err") && !strings.HasSuffix(f, ".exit") {
				files = append(files, f)
			}
		}
	}
	sort.Strings(files)
	return files
}

// policyBlocks splits apt-cache policy output into the text of each package.
func policyBlocks(out string) map[string]string {
	blocks := map[string]string{}
	var cur string
	for _, l := range strings.SplitAfter(out, "\n") {
		if m := regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?):\n$`).FindStringSubmatch(l); m != nil {
			cur = m[1]
		}
		if cur != "" {
			blocks[cur] += l
		}
	}
	return blocks
}

// corpusRunner answers the simulation with sim and apt-cache policy for any
// batch of names from the blocks of the corpus.
type corpusRunner struct {
	sim    string
	blocks map[string]string
}

func (c corpusRunner) Run(_ context.Context, argv []string, _ execx.Opts) (execx.Result, error) {
	if argv[0] == "apt-get" {
		return execx.Result{Stdout: []byte(c.sim)}, nil
	}
	var b strings.Builder
	for _, n := range argv[len(policyArgv()):] {
		b.WriteString(c.blocks[n])
	}
	return execx.Result{Stdout: []byte(b.String())}, nil
}

func checkAptCorpus(t *testing.T, dir string, shapes map[string]int) (lines int) {
	t.Helper()
	files := aptCorpusFiles(t, dir)
	if len(files) == 0 {
		t.Fatalf("%s: no policy files", dir)
	}
	all := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			s := probes.AptPolicyShape(l)
			if s == "" {
				t.Errorf("%s line %d is not a known shape of apt-cache policy: %q", filepath.Base(f), i+1, l)
			}
			shapes[s]++
			lines++
		}
		if strings.HasPrefix(filepath.Base(f), "simpolicy.") || strings.HasPrefix(filepath.Base(f), "instpolicy.") {
			for n, blk := range policyBlocks(string(b)) {
				all[n] = blk
			}
		}
	}
	// the simulation of the corpus, with the policy of the packages it names
	if sim, err := os.ReadFile(filepath.Join(dir, "sim.txt")); err == nil {
		r := corpusRunner{sim: string(sim), blocks: all}
		p := prepare(t, "security_updates", nil)
		o := p.Run(context.Background(), &probes.Env{Runner: r, FS: lists(time.Hour), Now: func() time.Time { return t0 }})
		if o.Status == result.Error {
			t.Errorf("%s: the probe does not understand the corpus: %s", dir, o.Summary)
		}
		kinds := map[string]int{}
		for _, l := range strings.Split(string(sim), "\n") {
			k := "other"
			for _, p := range []string{"Inst ", "Conf ", "Remv ", "Purg ", " "} {
				if strings.HasPrefix(l, p) {
					k = strings.TrimSpace(p)
					if k == "" {
						k = "indented"
					}
				}
			}
			kinds[k]++
		}
		t.Logf("%s: simulation: %s (%d evidence items); lines: %v", dir, o.Status, len(o.Evidence), kinds)
	}
	return lines
}

func TestAptCorpus(t *testing.T) {
	var dirs []string
	if d := os.Getenv("KW_APT_CORPUS"); d != "" {
		m, _ := filepath.Glob(filepath.Join(d, "*"))
		for _, x := range m {
			if st, err := os.Stat(x); err == nil && st.IsDir() {
				dirs = append(dirs, x)
			}
		}
		if len(dirs) == 0 {
			dirs = []string{d}
		}
	} else {
		for _, v := range versions {
			dirs = append(dirs, filepath.Join("testdata", v, "aptcorpus"))
		}
	}
	for _, dir := range dirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			shapes := map[string]int{}
			n := checkAptCorpus(t, dir, shapes)
			var keys []string
			for k := range shapes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%d", k, shapes[k]))
			}
			t.Logf("%s: %d lines, shapes: %s", dir, n, strings.Join(parts, " "))
		})
	}
}
