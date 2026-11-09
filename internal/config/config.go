// Package config loads and validates keepwatch configuration strictly.
//
// The main file (default /etc/keepwatch/keepwatch.yaml) is read first,
// then every *.yaml file in the conf.d directory next to it, in
// lexicographic order. Each file is decoded with a yaml.Decoder that
// has KnownFields(true) set; the schema is then validated against the
// parsed yaml.Node tree so that every error names file and line and so
// that all errors are collected, not only the first. A *.yml file in
// conf.d is an error (use the .yaml extension), a .yaml or .yml
// extension in any other case is an error (use lower-case .yaml), and
// so is a subdirectory inside conf.d; a file whose root is not a
// mapping (an empty or null document is fine) is an error; a file
// never replaces another file's root. A section key with a null value
// (host, checks, listeners, listeners.allow, authorized_keys,
// exceptions, notify) counts as an absent section.
//
// Merge rule: a conf.d file may only set or override the top-level
// sections it names. Mappings merge per key, recursively, and a key set
// by a later file wins. Sequences (such as exceptions and
// listeners.allow) append: main file first, then conf.d files in
// lexicographic order. Scalars are replaced by the later file. A missing
// conf.d directory is fine; a missing main file is an error. Repeated
// keys within one mapping of one file are an error at any depth
// (duplicate key "x" (first at line N)); a key repeated across files is
// an override and fine.
//
// Scalars are validated by their resolved YAML tag: booleans are
// !!bool (1 and "false" are rejected), ports are !!int, string fields
// are !!str, and expires is a YYYY-MM-DD date. A !!null value counts
// as absent for optional fields and is an error where the field is
// required.
//
// File access rules, because keepwatch runs as root: the final path
// component of every loaded file (main and conf.d) is never followed
// (a symlink is refused), and the file's type, size (max 1 MiB),
// permissions (no group or other write bits) and ownership (uid 0 or
// the running user) are checked on the open file descriptor itself, so
// a swap of the path between validation and a later open is caught by
// the next check, not slipped past. The directories holding the main
// file, conf.d and notify.ntfy.token_file must each be a real
// directory (not a symlink), owned by uid 0 or the running user, and
// not writable by group or other; deeper ancestor directories are not
// checked (known limit). notify.ntfy.token_file is stricter: regular
// file, at most 4096 bytes, exactly one hard link, mode 0600 or
// stricter, owned by the running user and not empty; it is validated
// without reading it and fully re-checked every time ReadToken opens
// it.
package config

import (
	_ "embed"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed example.yaml
var example []byte

// Example returns the commented example configuration written by
// keepwatch init. It passes Load and validation.
func Example() []byte { return example }

// DefaultPath is the main configuration file used when --config is absent.
const DefaultPath = "/etc/keepwatch/keepwatch.yaml"

// DefaultStateDir is the state directory used when state_dir is absent.
const DefaultStateDir = "/var/lib/keepwatch"

// Sources records which files were applied by Load, in merge order.
type Sources struct {
	Main  string
	ConfD []string
}

// Config is a validated keepwatch configuration.
type Config struct {
	Sources        Sources
	Host           Host
	StateDir       string
	Checks         map[string]Check
	Listeners      Listeners
	AuthorizedKeys AuthorizedKeys
	Exceptions     []Exception
	Notify         Notify
}

// Host carries free-form information about this machine.
type Host struct {
	Profile string
}

// Check is one enabled or disabled check with its opaque parameters.
type Check struct {
	Enabled  bool
	Severity string // empty when the probe default applies
	Params   map[string]any
}

// Listeners configures the listener allowlist.
type Listeners struct {
	Allow []Listener
}

// Listener is one allowed listening socket.
type Listener struct {
	Port  int
	Proto string // tcp or udp
	Bind  string // IP literal or "*"
}

// AuthorizedKeys configures expected SSH key fingerprints per user.
type AuthorizedKeys struct {
	Expected map[string][]string
}

// Exception suppresses a check until (and including) its expiry date.
type Exception struct {
	Check   string
	Match   string
	Reason  string
	Expires time.Time // midnight, local zone, on the expiry date
}

// Notify configures the notification channels.
type Notify struct {
	Ntfy *Ntfy
}

// Ntfy is an ntfy.sh-style webhook publisher.
type Ntfy struct {
	URL       string
	Topic     string
	TokenFile string
}

// Option customises Load for testing; production callers use none.
type Option func(*options)

type options struct {
	ownerOf OwnerOf // file owner uid from the fd's fstat; injectable for tests
}

// WithOwnerOf replaces the file-owner lookup (which receives the
// fs.FileInfo from the file descriptor's fstat) used when validating
// the configuration files and notify.ntfy.token_file. Tests use it to
// simulate foreign owners without privileges. A non-nil error is
// reported as a config error.
func WithOwnerOf(fn OwnerOf) Option {
	return func(o *options) { o.ownerOf = fn }
}

// Load reads the main file (DefaultPath when path is empty), then every
// *.yaml in the conf.d directory next to it, in lexicographic order,
// merges them per the package merge rule, and validates the result.
// The returned error is an Errors value naming file and line for every
// problem found, or nil when the configuration is valid.
func Load(path string, opts ...Option) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	path = filepath.Clean(path)
	opt := options{ownerOf: ownerOf}
	for _, fn := range opts {
		fn(&opt)
	}

	var errs Errors
	// keepwatch runs as root: the directory holding the main file is
	// part of the trust chain too. It must be a real, owned,
	// non-writable directory; a missing one is reported as the missing
	// main file instead.
	mainDir := filepath.Dir(path)
	if derr := checkConfigDir(mainDir, opt.ownerOf); derr != nil && !isNotExist(derr) {
		errs = append(errs, Error{File: mainDir, Msg: trimPath(cleanErr(derr), mainDir)})
	}
	policy := configPolicy(opt.ownerOf)
	root, origins, perrs := parseFile(path, policy)
	errs = append(errs, perrs...)
	switch {
	case root == nil || isNull(root): // empty file or null document: nothing to merge
		root = emptyMapping()
	case !isMapping(root):
		errs = append(errs, Error{File: path, Line: root.Line, Msg: "the configuration root must be a mapping"})
		root = emptyMapping()
	}

	var confd []string
	dir := filepath.Join(filepath.Dir(path), "conf.d")
	names, dirErr := osReadDir(dir)
	switch {
	case dirErr == nil:
		// keepwatch runs as root: a conf.d that group or other can
		// write, or that is a symlink, could suppress findings or
		// redirect the token. It must be a real, owned, non-writable
		// directory before any of its files are read.
		if derr := checkConfigDir(dir, opt.ownerOf); derr != nil {
			errs = append(errs, Error{File: dir, Msg: trimPath(cleanErr(derr), dir)})
		} else {
			for _, e := range names {
				name := e.Name()
				p := filepath.Join(dir, name)
				switch {
				case e.IsDir():
					errs = append(errs, Error{File: p, Msg: "conf.d must not contain directories"})
				case filepath.Ext(name) == ".yaml":
					confd = append(confd, p)
				case filepath.Ext(name) == ".yml":
					errs = append(errs, Error{File: p, Msg: `unsupported extension ".yml": use the .yaml extension`})
				case strings.EqualFold(filepath.Ext(name), ".yaml") || strings.EqualFold(filepath.Ext(name), ".yml"):
					// "a.YAML" and "b.Yml" would look loaded to anyone
					// who globs case-insensitively: only the exact
					// lower-case extensions count.
					errs = append(errs, Error{File: p, Msg: "unsupported extension " + strconv.Quote(filepath.Ext(name)) + ": use lower-case .yaml"})
				}
			}
		}
	case !isNotExist(dirErr):
		errs = append(errs, Error{File: dir, Msg: "cannot read conf.d: " + dirErr.Error()})
	}

	for _, file := range confd {
		node, fileOrigins, ferrs := parseFile(file, policy)
		for n, f := range fileOrigins {
			origins[n] = f
		}
		errs = append(errs, ferrs...)
		if node == nil || isNull(node) {
			continue
		}
		if !isMapping(node) {
			errs = append(errs, Error{File: file, Line: node.Line, Msg: "the configuration root must be a mapping"})
			continue
		}
		mergeMapping(root, node)
	}
	// Validate the merged tree even when some file had a parse problem:
	// every file that parses gets validated, and all problems from all
	// files are reported together, sorted by file then line.
	cfg, verrs := validate(root, origins, path, opt)
	errs = append(errs, verrs...)
	if len(errs) == 0 {
		cfg.Sources = Sources{Main: path, ConfD: confd}
		return cfg, nil
	}
	sortErrors(errs)
	return nil, errs
}

// sortErrors orders errors by file, then line, stably.
func sortErrors(errs Errors) {
	sort.SliceStable(errs, func(i, j int) bool {
		if errs[i].File != errs[j].File {
			return errs[i].File < errs[j].File
		}
		return errs[i].Line < errs[j].Line
	})
}
