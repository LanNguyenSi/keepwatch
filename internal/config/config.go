// Package config loads and validates keepwatch configuration strictly.
//
// The main file (default /etc/keepwatch/keepwatch.yaml) is read first,
// then every *.yaml file in the conf.d directory next to it, in
// lexicographic order. Each file is decoded with a yaml.Decoder that has
// KnownFields(true) set; the schema is then validated against the parsed
// yaml.Node tree so that every error names file and line and so that all
// errors are collected, not only the first.
//
// Merge rule: a conf.d file may only set or override the top-level
// sections it names. Mappings merge per key, recursively, and a key set
// by a later file wins. Sequences (such as exceptions and
// listeners.allow) append: main file first, then conf.d files in
// lexicographic order. Scalars are replaced by the later file. A missing
// conf.d directory is fine; a missing main file is an error.
package config

import (
	_ "embed"
	"path/filepath"
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
	ownerOf func(path string) (int, error) // file owner uid; injectable for tests
}

// WithOwnerOf replaces the file-owner lookup used when validating a
// notify.ntfy.token_file. Tests use it to simulate foreign owners
// without privileges. A non-nil error is reported as a config error.
func WithOwnerOf(fn func(path string) (int, error)) Option {
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
	root, origins, err := parseFile(path)
	if err != nil {
		return nil, Errors{*err}
	}
	if root == nil {
		root = emptyMapping()
	}

	var confd []string
	dir := filepath.Join(filepath.Dir(path), "conf.d")
	names, dirErr := osReadDir(dir)
	switch {
	case dirErr == nil:
		for _, name := range names {
			if filepath.Ext(name) != ".yaml" {
				continue
			}
			confd = append(confd, filepath.Join(dir, name))
		}
	case !isNotExist(dirErr):
		errs = append(errs, Error{File: dir, Msg: "cannot read conf.d: " + dirErr.Error()})
	}

	for _, file := range confd {
		node, fileOrigins, err := parseFile(file)
		for n, f := range fileOrigins {
			origins[n] = f
		}
		if err != nil {
			errs = append(errs, *err)
			continue
		}
		if node == nil {
			continue
		}
		if isMapping(root) && isMapping(node) {
			mergeMapping(root, node)
		} else {
			root = node // later file wins wholesale when the kinds differ
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}

	cfg, verrs := validate(root, origins, path, opt)
	if len(verrs) > 0 {
		return nil, verrs
	}
	cfg.Sources = Sources{Main: path, ConfD: confd}
	return cfg, nil
}
