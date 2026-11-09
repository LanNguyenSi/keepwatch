// Package probes implements the check kinds: each kind turns a few
// parameters and the host state into an Outcome.
//
// Every probe is read-only. A probe reads files only through the injected
// FS (a read-only abstraction with a size cap) and runs programs only
// through the injected execx.Runner; it never starts a shell and never
// touches the network. Values from the configuration that reach a command
// line are checked against a strict pattern first and a leading "-" is
// always rejected, so a parameter cannot turn into an option.
//
// keepwatch runs as root, so a parser that turns garbage or a failed
// command into a pass is the worst bug class here. The rule for every
// kind: only output that was fully understood can produce pass or fail;
// a timeout, truncated output, a signal, an unexpected exit status or
// output that does not parse is error. A program that is not installed is
// skipped, never fail.
package probes

import (
	"context"
	"fmt"
	"sort"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Kind is one check kind.
type Kind interface {
	// Name is the kind's name as used in the catalog.
	Name() string
	// Programs lists the base names of the programs the kind may execute.
	// The engine builds the execx allowlist from the union of these.
	Programs() []string
	// Prepare validates params (unknown key, wrong type or bad value is an
	// error) and returns a probe bound to them. It is called at load time,
	// before any probe runs.
	Prepare(params map[string]any) (Probe, error)
}

// Probe is a kind bound to validated parameters.
type Probe interface {
	Run(ctx context.Context, env *Env) Outcome
}

// Outcome is what a probe reports. Status is one of pass, fail, error or
// skipped; the engine adds the check identity, severity and exceptions.
// Every evidence item of a failing outcome is a failing item. An error or
// skipped outcome carries no evidence.
type Outcome struct {
	Status   result.Status
	Summary  string
	Evidence []result.Evidence
}

// Env is everything a probe may use besides its parameters.
type Env struct {
	// Runner executes programs. It must enforce the program allowlist.
	Runner execx.Runner
	// FS reads files.
	FS FS
	// ListenerAllow is the configured listener allowlist.
	ListenerAllow []ListenerRule
}

// ListenerRule allows one listening socket.
type ListenerRule struct {
	Port  int
	Proto string // tcp or udp
	Bind  string // IP literal or "*" for any address
}

var kinds = func() map[string]Kind {
	m := map[string]Kind{}
	for _, k := range []Kind{
		serviceActive{},
		packageInstalled{},
		sshdEffective{},
		fail2banJail{},
		listeners{},
		rebootRequired{},
	} {
		m[k.Name()] = k
	}
	return m
}()

// Lookup returns the kind with the given name.
func Lookup(name string) (Kind, bool) {
	k, ok := kinds[name]
	return k, ok
}

// Names returns the registered kind names, sorted.
func Names() []string {
	out := make([]string, 0, len(kinds))
	for n := range kinds {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Programs returns the sorted union of the programs the named kinds may
// execute. An unknown kind name is an error.
func Programs(names ...string) ([]string, error) {
	set := map[string]bool{}
	for _, n := range names {
		k, ok := Lookup(n)
		if !ok {
			return nil, fmt.Errorf("unknown check kind %q", n)
		}
		for _, p := range k.Programs() {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}
