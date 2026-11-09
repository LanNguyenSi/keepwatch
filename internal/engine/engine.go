// Package engine turns the catalog and the configuration into check
// results: it validates the configuration against the catalog, runs the
// enabled checks through their probes, applies the active exceptions and
// reports the expired ones.
//
// Parameters: the parameters of a check are the catalog's parameters with
// the configuration's checks.<id>.params merged over them. The merge is
// shallow: a key set in the configuration replaces the catalog's value for
// that key as a whole. For a list-valued parameter that means the
// configuration's list REPLACES the catalog default and never extends it;
// the kinds' Go documentation says which parameters are lists. Lists that
// conf.d drop-ins set for the same key have already been appended to the main
// file's list by the config loader when the engine sees them, so a drop-in
// widens a list the main file set.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// ExpiredID is the id of the synthetic check that reports an expired
// exception. It is not in the catalog: it cannot be configured under
// checks, but an exception may name it.
const ExpiredID = "exception_expired"

// expiredKind is the kind reported for ExpiredID results.
const expiredKind = "exception"

// Deps are the things the engine needs from the outside.
type Deps struct {
	// Runner executes programs; production code builds it with
	// execx.NewReal(Programs(cat)).
	Runner execx.Runner
	// FS reads files for probes.
	FS probes.FS
	// Now returns the current time; exception expiry is decided with it.
	Now func() time.Time
}

// Programs returns the sorted union of the program base names the catalog's
// kinds may execute: the allowlist for execx.NewReal.
func Programs(cat *catalog.Catalog) []string {
	set := map[string]bool{}
	for _, e := range cat.Entries() {
		set[e.Kind] = true
	}
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k)
	}
	progs, err := probes.Programs(names...)
	if err != nil { // the catalog only holds known kinds
		panic(err)
	}
	return progs
}

// Plan is a validated run: catalog and configuration are consistent and
// every check's parameters are known to be valid.
type Plan struct {
	cfg    *config.Config
	deps   Deps
	checks []plannedCheck
}

type plannedCheck struct {
	entry    catalog.Entry
	severity result.Severity
	enabled  bool
	probe    probes.Probe
}

// Prepare validates the configuration against the catalog before any probe
// runs. It reports every problem at once: a checks.<id> or exceptions[].check
// that names an id that is not in the catalog (exceptions may name
// ExpiredID), and merged parameters that the kind rejects.
func Prepare(cat *catalog.Catalog, cfg *config.Config, deps Deps) (*Plan, error) {
	var errs []string
	if cat == nil || cfg == nil {
		return nil, errors.New("engine: catalog and configuration are required")
	}
	if deps.Runner == nil || deps.FS == nil || deps.Now == nil {
		return nil, errors.New("engine: Runner, FS and Now are required")
	}

	ids := make([]string, 0, len(cfg.Checks))
	for id := range cfg.Checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		switch {
		case id == ExpiredID:
			errs = append(errs, fmt.Sprintf("checks.%s: %s is not a catalog check and cannot be configured", id, ExpiredID))
		case !cat.Has(id):
			errs = append(errs, fmt.Sprintf("checks.%s: unknown check id", id))
		}
	}
	for i, e := range cfg.Exceptions {
		if e.Check != ExpiredID && !cat.Has(e.Check) {
			errs = append(errs, fmt.Sprintf("exceptions[%d].check: unknown check id %q", i, e.Check))
		}
	}

	p := &Plan{cfg: cfg, deps: deps}
	for _, entry := range cat.Entries() {
		pc := plannedCheck{entry: entry, severity: entry.Severity, enabled: true}
		cc, configured := cfg.Checks[entry.ID]
		if configured {
			pc.enabled = cc.Enabled
			if cc.Severity != "" {
				sev, err := result.ParseSeverity(cc.Severity)
				if err != nil {
					errs = append(errs, fmt.Sprintf("checks.%s.severity: %v", entry.ID, err))
				}
				pc.severity = sev
			}
		}
		kind, _ := probes.Lookup(entry.Kind) // the catalog only holds known kinds
		probe, err := kind.Prepare(mergeParams(entry.Params, cc.Params))
		if err != nil {
			errs = append(errs, fmt.Sprintf("checks.%s.params: %v", entry.ID, err))
		}
		pc.probe = probe
		p.checks = append(p.checks, pc)
	}
	if len(errs) > 0 {
		return nil, errors.New("engine: " + strings.Join(errs, "\n"))
	}
	return p, nil
}

// mergeParams returns the catalog parameters with the configured ones
// merged over them: a configured key replaces the catalog's value.
func mergeParams(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

// Run prepares and runs: see Prepare and Plan.Run. When the configuration is
// inconsistent with the catalog it returns the error and no results; no
// probe has run.
func Run(ctx context.Context, cat *catalog.Catalog, cfg *config.Config, deps Deps) ([]result.Result, error) {
	p, err := Prepare(cat, cfg, deps)
	if err != nil {
		return nil, err
	}
	return p.Run(ctx), nil
}

// Run executes the plan and returns one result per catalog check, in
// catalog order, followed by one exception_expired result per expired
// exception, in configuration order.
func (p *Plan) Run(ctx context.Context) []result.Result {
	now := p.deps.Now()
	active := p.cfg.ActiveExceptions(now)
	expired := p.cfg.ExpiredExceptions(now)

	env := &probes.Env{
		Runner:        newCachingRunner(p.deps.Runner),
		FS:            p.deps.FS,
		ListenerAllow: listenerRules(p.cfg),
	}

	out := make([]result.Result, 0, len(p.checks)+len(expired))
	for _, pc := range p.checks {
		r := result.Result{CheckID: pc.entry.ID, Kind: pc.entry.Kind, Severity: pc.severity, Evidence: []result.Evidence{}}
		switch {
		case !pc.enabled:
			r.Status, r.Summary = result.Skipped, "disabled in the configuration"
		case ctx.Err() != nil:
			r.Status, r.Summary = result.Error, "not run: "+ctx.Err().Error()
		default:
			o := pc.probe.Run(ctx, env)
			r.Status, r.Summary = o.Status, o.Summary
			if o.Evidence != nil {
				r.Evidence = o.Evidence
			}
		}
		applyExceptions(&r, active)
		out = append(out, r)
	}
	for _, e := range expired {
		subject := e.Check
		if e.Match != "" {
			subject += " " + e.Match
		}
		on := e.Expires.Format("2006-01-02")
		r := result.Result{
			CheckID:  ExpiredID,
			Kind:     expiredKind,
			Status:   result.Fail,
			Severity: result.Low,
			Summary:  fmt.Sprintf("the exception for %s expired on %s", subject, on),
			Evidence: []result.Evidence{{Subject: subject, Detail: fmt.Sprintf("expired on %s; reason was: %s", on, e.Reason)}},
		}
		applyExceptions(&r, active)
		out = append(out, r)
	}
	return out
}

func listenerRules(cfg *config.Config) []probes.ListenerRule {
	rules := make([]probes.ListenerRule, len(cfg.Listeners.Allow))
	for i, l := range cfg.Listeners.Allow {
		rules[i] = probes.ListenerRule{Port: l.Port, Proto: l.Proto, Bind: l.Bind}
	}
	return rules
}

// applyExceptions applies the active exceptions to a failing result.
//
// An exception with an empty match covers the whole check. One with a match
// covers the evidence items whose subject equals it exactly. If the whole
// check is covered, or the result has evidence and every item is covered,
// the status becomes excepted; otherwise it stays fail and the covered items
// carry excepted and their reason. Results that did not fail (pass, error,
// skipped) are never touched: an exception cannot turn an error into
// anything else.
func applyExceptions(r *result.Result, active []config.Exception) {
	if r.Status != result.Fail {
		return
	}
	var whole []string
	for _, e := range active {
		if e.Check == r.CheckID && e.Match == "" {
			whole = appendUnique(whole, e.Reason)
		}
	}
	reasons := append([]string(nil), whole...)
	// all stays true while every evidence item is covered; a whole-check
	// exception covers every item, and a result without items is covered
	// only by a whole-check exception (no reasons means nothing applies).
	all := true
	for i := range r.Evidence {
		item := &r.Evidence[i]
		itemReasons := append([]string(nil), whole...)
		for _, e := range active {
			if e.Check == r.CheckID && e.Match != "" && e.Match == item.Subject {
				itemReasons = appendUnique(itemReasons, e.Reason)
			}
		}
		if len(itemReasons) == 0 {
			all = false
			continue
		}
		item.Excepted = true
		item.ExceptionReason = strings.Join(itemReasons, "; ")
		for _, reason := range itemReasons {
			reasons = appendUnique(reasons, reason)
		}
	}
	if len(reasons) == 0 {
		return
	}
	r.ExceptionReasons = reasons
	if all {
		r.Status = result.Excepted
		r.Summary += " (excepted: " + strings.Join(reasons, "; ") + ")"
	}
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}
