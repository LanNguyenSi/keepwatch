package probes

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// aptListsGlob matches the signed release files apt keeps of every
// repository; the newest modification time among them is when the package
// lists were last refreshed.
const aptListsGlob = "/var/lib/apt/lists/*InRelease"

// securityUpdates reports pending upgrades from a security pocket.
//
// Parameters:
//
//	max_list_age_hours  (integer 1 to 8760, default 48)  how old the package
//	                    lists may be before the check warns
//
// It takes no list parameters.
//
// Two read-only apt commands are run, both with the options
// "-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=" (an empty value
// tells apt to build its cache in memory; without it apt writes
// /var/cache/apt/pkgcache.bin and srcpkgcache.bin, about 130 MB, whenever
// the distribution's docker-clean snippet is not there, which was measured on
// Ubuntu 22.04 and 24.04: no file under /var/cache/apt or /var/lib/apt changes
// with the options, with or without docker-clean):
//
//	apt-get -s -o Debug::NoLocking=true dist-upgrade
//	        -s simulates (nothing is installed, removed or written),
//	        Debug::NoLocking=true makes apt take no lock, so the run neither
//	        waits for a running apt or unattended-upgrades nor can it make one
//	        fail. It works with /var/cache/apt and /var/lib/apt mounted
//	        read-only (as a systemd unit with ProtectSystem=strict has them).
//	apt-cache policy -- <package>...
//	        for the packages the simulation upgrades: the versions each
//	        package has, newest first, with the pockets that carry them. No
//	        lock, no write, exit status 0; apt-cache exits 100 on every error
//	        ("E: ..." on stderr), which is error here. The packages are named
//	        in batches of at most 100, after "--", each name matched against
//	        a strict pattern first; at most 2000 packages are looked up
//	        (more is error). A package apt-cache prints nothing for is error.
//
// "apt-get update" is never run, which would write: the check judges the
// package lists the host has, and says how old they are.
//
// Only exit status 0 is interpreted for either command. The output of
// apt-get must be understood in full: every line is a known kind of line, the
// summary line "N upgraded, M newly installed, K to remove and L not
// upgraded." is present exactly once, and the number of "Inst" lines equals
// N + M. Anything else is error.
//
// What is a pending security update. The simulation installs the best
// candidate, and that may come from an "-updates" pocket that is newer than
// the security fix; the security fix is then still not installed. A package
// that is installed (an "Inst" line with an old version) is therefore a
// pending security update when any version that a pocket named
// "<release>-security", "<release>-infra-security" or "<release>-apps-security"
// carries is newer than the installed version, whatever the candidate is.
// "Newer" is apt's own order and not a comparison implemented here: apt-cache
// policy lists the versions of a package sorted by Debian version, newest
// first, and marks the installed one, so the versions above the marked row
// are the newer ones. That is the order apt itself uses to pick the
// candidate, with epochs, tildes and revisions handled by apt and not by this
// code. Exactly one marked row must be present, else error. A package that is
// newly installed has no installed version; it counts when its candidate
// comes from a security pocket (the Inst line names the pockets).
//
// Result: fail with one evidence item per package (subject: the package name,
// detail: old and new version, the pocket and the security version when the
// candidate does not come from it), sorted and limited to 100 items. The age
// of the package lists is the newest modification time of
// /var/lib/apt/lists/*InRelease. Without a pending security update, lists
// older than max_list_age_hours, or no such file at all, make the status warn
// (one evidence item with subject "apt-lists"); with pending updates the age
// appears in the summary, and the stale lists are a warning that is reported
// next to the failure (Outcome.Warnings), so an exception for the updates
// leaves a warning. The count of "not upgraded" packages (held back, or phased
// by Ubuntu) is named in the summary; the simulation does not list them, so
// they are not judged: a held package with a security fix is not seen.
type securityUpdates struct{}

func (securityUpdates) Name() string       { return "security_updates" }
func (securityUpdates) Programs() []string { return []string{"apt-cache", "apt-get"} }

func (securityUpdates) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	hours := p.integer("max_list_age_hours", 48, 1, 24*365)
	if err := p.err(); err != nil {
		return nil, err
	}
	return updatesProbe{maxAge: time.Duration(hours) * time.Hour}, nil
}

type updatesProbe struct{ maxAge time.Duration }

// aptNoCache is the pair of options that keeps apt from writing its cache
// files: an empty file name means the cache lives in memory.
var aptNoCache = []string{"-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache="}

var aptArgv = append(append([]string{"apt-get", "-s", "-o", "Debug::NoLocking=true"}, aptNoCache...), "dist-upgrade")

// Limits of the policy lookup.
const (
	aptPolicyBatch = 100
	aptPolicyMax   = 2000
)

func (u updatesProbe) Run(ctx context.Context, env *Env) Outcome {
	res, out := run(ctx, env, aptArgv, 90*time.Second)
	if out != nil {
		return *out
	}
	if res.ExitCode != 0 {
		return *unexpectedExit("apt-get", res)
	}
	sim, err := parseAptSimulation(string(res.Stdout))
	if err != nil {
		return *errorOutcome("apt-get -s dist-upgrade: %v", err)
	}
	if o := lookupPolicy(ctx, env, &sim); o != nil {
		return *o
	}
	ageNote, stale, err := u.listAge(env)
	if err != nil {
		return *errorOutcome("%v", err)
	}

	var ev []result.Evidence
	other := 0
	for _, p := range sim.pkgs {
		if !p.security {
			other++
			continue
		}
		ev = append(ev, result.Evidence{Subject: p.name, Detail: clean(p.detail(), 200)})
	}
	base := fmt.Sprintf("%d other upgrade(s) pending", other)
	if sim.notUpgraded > 0 {
		base += fmt.Sprintf("; %d package(s) not upgraded (held back or phased)", sim.notUpgraded)
	}

	if len(ev) > 0 {
		names := make([]string, 0, 5)
		for _, e := range ev {
			if len(names) == 5 {
				names = append(names, "...")
				break
			}
			names = append(names, e.Subject)
		}
		warn := ""
		var warnings []result.Evidence
		if stale {
			warn = " (stale: newer updates may exist)"
			warnings = []result.Evidence{u.staleItem(ageNote)}
		}
		shown, hidden := limitEvidence(ev)
		return Outcome{
			Status:   result.Fail,
			Summary:  fmt.Sprintf("%d pending security update(s): %s; %s; package lists %s%s", len(ev), strings.Join(names, ", "), base, ageNote, warn) + moreNote(hidden),
			Evidence: shown,
			Warnings: warnings,
		}
	}
	if stale {
		return Outcome{
			Status:   result.Warn,
			Summary:  "no pending security updates in the package lists, but the lists " + ageNote + ", so newer updates may exist; " + base,
			Evidence: []result.Evidence{u.staleItem(ageNote)},
		}
	}
	return Outcome{Status: result.Pass, Summary: "no pending security updates; " + base + "; package lists " + ageNote}
}

func (u updatesProbe) staleItem(ageNote string) result.Evidence {
	return result.Evidence{Subject: "apt-lists", Detail: fmt.Sprintf("package lists %s; limit is %s", ageNote, hoursText(u.maxAge))}
}

func orNone(s string) string {
	if s == "" {
		return "(new)"
	}
	return s
}

// listAge reads the age of the package lists. stale is true when the lists
// are older than the limit, when their age cannot be told, or when their
// modification time lies in the future.
func (u updatesProbe) listAge(env *Env) (note string, stale bool, err error) {
	files, gerr := env.glob(aptListsGlob)
	if gerr != nil {
		return "", false, fmt.Errorf("listing the apt package lists failed: %s", clean(gerr.Error(), 150))
	}
	var newest time.Time
	for _, f := range files {
		t, merr := env.modTime(f)
		if merr != nil {
			if errors.Is(merr, errNoCapability) {
				return "", false, merr
			}
			continue
		}
		if t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return "have no InRelease file, so their age is unknown", true, nil
	}
	age := env.now().Sub(newest)
	switch {
	case age < 0:
		return "have a modification time in the future (clock skew?)", true, nil
	case age > u.maxAge:
		return "are " + durationText(age) + " old", true, nil
	}
	return "are " + durationText(age) + " old", false, nil
}

func hoursText(d time.Duration) string { return fmt.Sprintf("%d hours", int(d/time.Hour)) }

// durationText renders a duration for people: hours below three days, days
// above.
func durationText(d time.Duration) string {
	if d < 72*time.Hour {
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	}
	return fmt.Sprintf("%d days", int(d/(24*time.Hour)))
}

// aptPkg is one package "Inst" line of the simulation.
type aptPkg struct {
	name, oldVer, newVer string
	pockets              []string // the "-security" pockets of the candidate, sorted
	security             bool
	secVer, secPocket    string // the newest security version above the installed one (see lookupPolicy)
}

// detail renders what is pending for a package that counts as a security
// update.
func (p aptPkg) detail() string {
	if len(p.pockets) > 0 {
		return fmt.Sprintf("%s -> %s from %s", orNone(p.oldVer), p.newVer, strings.Join(p.pockets, ", "))
	}
	return fmt.Sprintf("%s -> %s, but the security version %s from %s is newer than the installed one", orNone(p.oldVer), p.newVer, p.secVer, p.secPocket)
}

type aptSim struct {
	pkgs        []aptPkg
	notUpgraded int
}

var (
	aptSummaryRe = regexp.MustCompile(`^(\d+) upgraded, (\d+) newly installed(?:, (\d+) reinstalled)?(?:, (\d+) downgraded)?, (\d+) to remove and (\d+) not upgraded\.$`)
	aptInstRe    = regexp.MustCompile(`^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+) \[(\S+)\]\)(?: \[[^\[\]]*\])*$`)
	aptNameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?$`)
	aptPocketRe  = regexp.MustCompile(`^[a-z][a-z0-9.]*(-infra|-apps)?-security$`)
	aptLinePfx   = []string{
		"Reading package lists", "Building dependency tree", "Reading state information",
		"Calculating upgrade", "Correcting dependencies", "Done",
		"The following ", "Suggested packages:", "Recommended packages:", "Use 'apt autoremove'",
		"NOTE: This is only a simulation!",
		"Conf ", "Remv ", "Purg ",
	}
)

// parseAptSimulation reads the output of "apt-get -s dist-upgrade".
func parseAptSimulation(out string) (aptSim, error) {
	var sim aptSim
	summaries := 0
	var upgraded, installed, reinstalled int
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "" || line[0] == ' ':
			continue
		case aptSummaryRe.MatchString(line):
			m := aptSummaryRe.FindStringSubmatch(line)
			upgraded, installed = atoi(m[1]), atoi(m[2])
			reinstalled = atoi(m[3])
			sim.notUpgraded = atoi(m[6])
			summaries++
			continue
		case strings.HasPrefix(line, "Inst "):
			p, err := parseAptInst(line)
			if err != nil {
				return aptSim{}, fmt.Errorf("line %d: %v", i+1, err)
			}
			sim.pkgs = append(sim.pkgs, p)
			continue
		}
		known := false
		for _, pfx := range aptLinePfx {
			if strings.HasPrefix(line, pfx) {
				known = true
				break
			}
		}
		if !known {
			return aptSim{}, fmt.Errorf("line %d is not a line of apt's simulation: %q", i+1, clean(line, 60))
		}
	}
	if summaries != 1 {
		return aptSim{}, fmt.Errorf("expected one summary line, found %d", summaries)
	}
	if want := upgraded + installed + reinstalled; len(sim.pkgs) != want {
		return aptSim{}, fmt.Errorf("the summary announces %d package(s) to install or upgrade, but the output lists %d", want, len(sim.pkgs))
	}
	sort.Slice(sim.pkgs, func(i, j int) bool { return sim.pkgs[i].name < sim.pkgs[j].name })
	return sim, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s) // the pattern only lets digits through
	return n
}

// parseAptInst reads one "Inst" line.
func parseAptInst(line string) (aptPkg, error) {
	m := aptInstRe.FindStringSubmatch(line)
	if m == nil || !aptNameRe.MatchString(m[1]) {
		return aptPkg{}, fmt.Errorf("cannot read the Inst line %q", clean(line, 80))
	}
	p := aptPkg{name: m[1], oldVer: m[2], newVer: m[3]}
	seen := map[string]bool{}
	for _, origin := range strings.Split(m[4], ", ") {
		pocket := origin[strings.LastIndexByte(origin, '/')+1:]
		if aptPocketRe.MatchString(pocket) && !seen[pocket] {
			seen[pocket] = true
			p.pockets = append(p.pockets, pocket)
		}
	}
	sort.Strings(p.pockets)
	p.security = len(p.pockets) > 0
	return p, nil
}

var (
	aptHeaderRe     = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?):$`)
	aptPolicyKeyRe  = regexp.MustCompile(`^  (?:Installed|Candidate|Package pin): \S.*$`)
	aptVersionRowRe = regexp.MustCompile(`^( \*\*\* |     )([0-9A-Za-z][0-9A-Za-z.+~:_-]*) (-?\d+)$`)
	aptOriginRe     = regexp.MustCompile(`^        (-?\d+) (\S+)(?: (\S+)(?: (\S+))? Packages)?$`)
)

// lookupPolicy asks apt-cache policy for the packages the simulation
// upgrades and marks as security updates those that have a newer version in a
// security pocket than the installed one (see securityUpdates). It returns a
// non-nil outcome (an error) when the answer cannot be had or understood.
func lookupPolicy(ctx context.Context, env *Env, sim *aptSim) *Outcome {
	var names []string
	byName := map[string]*aptPkg{}
	for i := range sim.pkgs {
		p := &sim.pkgs[i]
		if p.oldVer == "" || byName[p.name] != nil {
			continue
		}
		names = append(names, p.name)
		byName[p.name] = p
	}
	if len(names) > aptPolicyMax {
		return errorOutcome("%d packages are to be upgraded, more than the %d whose security versions are looked up", len(names), aptPolicyMax)
	}
	for len(names) > 0 {
		n := min(aptPolicyBatch, len(names))
		batch := names[:n]
		names = names[n:]
		argv := append(append([]string{"apt-cache"}, aptNoCache...), "policy", "--")
		argv = append(argv, batch...)
		res, out := run(ctx, env, argv, 60*time.Second)
		if out != nil {
			if out.Status == result.Skipped {
				return errorOutcome(`program "apt-cache" is not installed, but apt-get is: the security versions cannot be looked up`)
			}
			return out
		}
		if res.ExitCode != 0 {
			return unexpectedExit("apt-cache policy", res)
		}
		found, err := parseAptPolicy(string(res.Stdout), batch)
		if err != nil {
			return errorOutcome("apt-cache policy: %v", err)
		}
		for name, f := range found {
			p := byName[name]
			p.secVer, p.secPocket = f.version, f.pocket
			p.security = p.security || f.version != ""
		}
	}
	return nil
}

// aptNewerSecurity is the newest security version above the installed one.
type aptNewerSecurity struct{ version, pocket string }

// parseAptPolicy reads "apt-cache policy -- <names>" for exactly the packages
// in want. Per package the output is
//
//	<name>:
//	  Installed: <version>
//	  Candidate: <version>
//	  Version table:
//	 *** <version> <priority>          (the installed version)
//	        <priority> <url> <suite>/<component> <arch> Packages
//	        100 /var/lib/dpkg/status
//	     <version> <priority>          (any other version)
//	        ...
//
// with the versions newest first (apt keeps them sorted by Debian version
// order). The versions above the installed row are newer than the installed
// one; the first of them that one of its origin lines puts into a security
// pocket is reported. The package header is the name apt prints: no
// architecture for the native one, "name:arch" for others, which is how the
// simulation names them. Every line must be one of the shapes above, every
// wanted package must be present exactly once and have exactly one installed
// row.
func parseAptPolicy(out string, want []string) (map[string]aptNewerSecurity, error) {
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w] = true
	}
	found := map[string]aptNewerSecurity{}
	described := map[string]bool{}
	var cur string
	var above, haveRow bool // above: no installed row seen yet in this package
	var rowAbove bool       // the last version row lies above the installed one
	var rowVer string
	installedRows := 0
	finish := func() error {
		if cur != "" && installedRows != 1 {
			return fmt.Errorf("package %s has %d installed version rows, want 1", cur, installedRows)
		}
		return nil
	}
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
		case aptHeaderRe.MatchString(line):
			if err := finish(); err != nil {
				return nil, err
			}
			cur = aptHeaderRe.FindStringSubmatch(line)[1]
			if !wanted[cur] {
				return nil, fmt.Errorf("line %d: a package that was not asked for: %q", i+1, clean(cur, 60))
			}
			if described[cur] {
				return nil, fmt.Errorf("package %s is described twice", cur)
			}
			described[cur] = true
			above, haveRow, rowAbove, rowVer, installedRows = true, false, false, "", 0
		case cur == "":
			return nil, fmt.Errorf("line %d is not part of a package: %q", i+1, clean(line, 60))
		case aptPolicyKeyRe.MatchString(line) || line == "  Version table:":
		case aptVersionRowRe.MatchString(line):
			m := aptVersionRowRe.FindStringSubmatch(line)
			haveRow = true
			if m[1] == " *** " {
				installedRows++
				above = false
				rowAbove, rowVer = false, m[2]
			} else {
				rowAbove, rowVer = above, m[2]
			}
		case aptOriginRe.MatchString(line):
			if !haveRow {
				return nil, fmt.Errorf("line %d: an origin line before any version", i+1)
			}
			if !rowAbove {
				continue
			}
			m := aptOriginRe.FindStringSubmatch(line)
			if m[3] == "" {
				continue // the dpkg status file, or a local source without a suite
			}
			pocket, _, _ := strings.Cut(m[3], "/")
			if _, done := found[cur]; !done && aptPocketRe.MatchString(pocket) {
				found[cur] = aptNewerSecurity{version: rowVer, pocket: pocket}
			}
		default:
			return nil, fmt.Errorf("line %d is not a line of apt-cache policy: %q", i+1, clean(line, 60))
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	for _, w := range want {
		if !described[w] {
			return nil, fmt.Errorf("package %s is not described", clean(w, 60))
		}
	}
	return found, nil
}
