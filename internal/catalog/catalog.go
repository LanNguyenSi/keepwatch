// Package catalog holds the check catalog: the list of checks keepwatch
// knows, as data. The base catalog is embedded YAML; every entry names a
// probe kind and the parameters it runs with. Loading validates everything
// that can be validated without a host: unique ids, known kinds, valid
// severities and parameters that the kind accepts.
package catalog

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

//go:embed catalog.yaml
var baseYAML []byte

// Entry is one check of the catalog.
type Entry struct {
	ID       string
	Title    string
	Kind     string
	Params   map[string]any
	Severity result.Severity
	// Rationale says why the check matters.
	Rationale string
	// FixHint is advice for the operator, plain text. It is never executed.
	FixHint string
}

// rawEntry is the YAML shape of an entry (severity arrives as a string).
type rawEntry struct {
	ID        string         `yaml:"id"`
	Title     string         `yaml:"title"`
	Kind      string         `yaml:"kind"`
	Params    map[string]any `yaml:"params"`
	Severity  string         `yaml:"severity"`
	Rationale string         `yaml:"rationale"`
	FixHint   string         `yaml:"fix_hint"`
}

type document struct {
	Checks []rawEntry `yaml:"checks"`
}

// Catalog is a validated, ordered set of entries.
type Catalog struct {
	entries []Entry
	byID    map[string]int
}

// idPattern requires a dotted id of at least two lower-case segments, so no
// catalog id can collide with a single-word synthetic id.
var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Base returns the embedded base catalog.
func Base() (*Catalog, error) { return Parse(baseYAML) }

// Parse decodes and validates a catalog. Unknown YAML keys, duplicate keys
// and trailing documents are errors. All validation problems are reported
// together.
func Parse(data []byte) (*Catalog, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var doc document
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("catalog: empty document")
		}
		return nil, fmt.Errorf("catalog: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("catalog: more than one YAML document")
	}
	if len(doc.Checks) == 0 {
		return nil, errors.New("catalog: no checks")
	}

	c := &Catalog{byID: map[string]int{}}
	var errs []string
	fail := func(i int, format string, a ...any) {
		errs = append(errs, fmt.Sprintf("checks[%d] %q: %s", i, doc.Checks[i].ID, fmt.Sprintf(format, a...)))
	}
	for i, r := range doc.Checks {
		e := Entry{ID: r.ID, Title: r.Title, Kind: r.Kind, Params: r.Params, Rationale: r.Rationale, FixHint: r.FixHint}
		if !idPattern.MatchString(r.ID) {
			fail(i, "id must be dotted lower-case words, like ssh.password_authentication")
		} else if _, dup := c.byID[r.ID]; dup {
			fail(i, "duplicate id")
		}
		if strings.TrimSpace(r.Title) == "" {
			fail(i, "title is required")
		}
		if strings.TrimSpace(r.Rationale) == "" {
			fail(i, "rationale is required")
		}
		if strings.TrimSpace(r.FixHint) == "" {
			fail(i, "fix_hint is required")
		}
		sev, err := result.ParseSeverity(r.Severity)
		if err != nil {
			fail(i, "%v", err)
		}
		e.Severity = sev
		if k, ok := probes.Lookup(r.Kind); !ok {
			fail(i, "unknown kind %q (known: %s)", r.Kind, strings.Join(probes.Names(), ", "))
		} else if _, err := k.Prepare(r.Params); err != nil {
			fail(i, "params: %v", err)
		}
		if _, dup := c.byID[r.ID]; !dup {
			c.byID[r.ID] = len(c.entries)
		}
		c.entries = append(c.entries, e)
	}
	if len(errs) > 0 {
		return nil, errors.New("catalog: " + strings.Join(errs, "\n"))
	}
	return c, nil
}

// Entries returns the entries in catalog order. The slice is a copy.
func (c *Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

// Get returns the entry with the given id.
func (c *Catalog) Get(id string) (Entry, bool) {
	i, ok := c.byID[id]
	if !ok {
		return Entry{}, false
	}
	return c.entries[i], true
}

// Has reports whether the catalog has an entry with the given id.
func (c *Catalog) Has(id string) bool { _, ok := c.byID[id]; return ok }
