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
// "-o APT::Get::Always-Include-Phased-Updates=true" (see "Phased updates"
// below) and "-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=" (an empty value
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
//	        for the packages the simulation upgrades and for the ones it
//	        keeps back: the versions each package has, newest first, with the
//	        pockets that carry them. No lock, no write, exit status 0;
//	        apt-cache exits 100 on every error ("E: ..." on stderr), which is
//	        error here. The packages are named in batches of at most 100,
//	        after "--", each name matched against a strict pattern first; at
//	        most 2000 packages are looked up (more is error). A package
//	        apt-cache prints nothing for is error.
//
// "apt-get update" is never run, which would write: the check judges the
// package lists the host has, and says how old they are.
//
// Phased updates. Ubuntu rolls some updates out in percentages: a version with
// "Phased-Update-Percentage: N" in the Packages index is offered to a machine
// only when a number derived from the machine-id and the source package is not
// above N. Whether apt holds such an update back is decided by
// IsIgnoredPhasedUpdate (apt-pkg/depcache.cc, apt 2.8.4), which pkgDistUpgrade
// (apt-pkg/upgrade.cc), pkgProblemResolver::KeepPhasedUpdates
// (apt-pkg/algorithms.cc) and InstallPackages (apt-private/private-install.cc)
// ask through pkgDepCache::PhasingApplied; with APT::Get::Phase-Policy set,
// ExcludePhased (apt-pkg/policy.cc) caps the priority of the version instead.
// Both return "not phased" when APT::Configuration::isChroot()
// (apt-pkg/aptconfiguration.cc) is true. That function runs "ischroot -t",
// and ischroot (debianutils 5.17, ischroot_mountinfo in ischroot.c) calls a
// process a chroot as soon as /proc/self/mountinfo differs from
// /proc/1/mountinfo, which is the case in every service that has a mount
// namespace of its own (ProtectSystem=, PrivateTmp=, ProtectKernel*=, ...).
// The scheduled run of keepwatch is such a service. So under systemd apt
// upgrades the phased packages in its simulation, and a direct run as root
// keeps them back: the same host gave "N other upgrade(s) pending" with no
// "not upgraded" count in one and fewer upgrades plus a "not upgraded" count in
// the other. The security list was the same in both, because PhasingApplied
// returns false for a security update. The cause was measured on Ubuntu 22.04
// (apt 2.4.15) and 24.04 (apt 2.8.4) with a local repository.
//
// A second effect of the same setting: with APT::Get::Phase-Policy set (the
// default is off in 2.8.4; a host can switch it on in apt.conf), ExcludePhased
// caps the priority of a phased version at 1 whatever pocket it comes from, so
// a phased security fix drops out of the simulation without a trace: it is
// neither upgraded nor named as held back.
//
// Both commands therefore run with APT::Get::Always-Include-Phased-Updates=true.
// It is checked first, in IsIgnoredPhasedUpdate and in ExcludePhased, before the
// machine-id and the chroot test, and it comes before a "Never" setting of the
// host (an option on the command line replaces the configuration files). apt then treats
// every phased version as available, in a service and in a direct run, whatever
// the machine-id, and the packages that phasing would defer are counted as
// upgrades that are pending. The check reports what the package lists offer, not
// what apt would install on this machine today.
//
// Only exit status 0 is interpreted for either command. The output of
// apt-get must be understood in full: every line is a known kind of line, the
// summary line "N upgraded, M newly installed, K to remove and L not
// upgraded." is present exactly once, the number of "Inst" lines equals
// N + M, and the number of names under the headings of the packages apt does
// not upgrade ("The following packages have been kept back:" and, with apt
// 2.8, "The following upgrades have been deferred due to phasing:") equals L.
// Anything else is error. The output of apt-cache policy is read the same way,
// line by line (classifyAptPolicyLine): the version rows may end in
// " (phased N%)", which apt prints for a version with a
// Phased-Update-Percentage (apt-private/private-show.cc, function Policy, in
// apt 2.4.15 and 2.8.4; the commands run with LC_ALL=C, so the word is not
// translated), and the origin lines carry the priority as printf("%4i")
// prints it. Everything else is error. The shapes were checked against the
// output for every installed package and for 3000 package names of the real
// archive on both releases (testdata/aptcorpus.sh, corpus_test.go).
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
// comes from a security pocket (the Inst line names the pockets). A package
// that apt keeps back (apt-mark hold, a dependency that cannot be met) has no
// Inst line, but apt names it, and it is looked up in the same way: when a
// security pocket carries a version newer than the installed one, it is a
// pending security update whose detail says that apt keeps it back.
// The simulation leaves such a package alone, so a fix for it would otherwise
// never be seen.
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
// leaves a warning. The count of "not upgraded" packages (kept back by a hold
// or by a dependency; phasing no longer keeps one back, see above) is named in
// the summary; all of them are judged, as above, so a held package with a newer
// security version fails the check.
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

// aptPhasing makes apt treat every phased update as available. Without it the
// result depends on where apt runs (see securityUpdates): a service with a mount
// namespace of its own is taken for a chroot, where apt does not phase, and a
// direct run is not.
var aptPhasing = []string{"-o", "APT::Get::Always-Include-Phased-Updates=true"}

var aptArgv = append(append(append([]string{"apt-get", "-s", "-o", "Debug::NoLocking=true"}, aptNoCache...), aptPhasing...), "dist-upgrade")

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
		ev = append(ev, result.Evidence{Subject: p.name, Detail: hostText(p.detail())})
	}
	base := fmt.Sprintf("%d other upgrade(s) pending", other)
	if sim.notUpgraded > 0 {
		base += fmt.Sprintf("; %d package(s) not upgraded (kept back by apt)", sim.notUpgraded)
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
		shown, hidden, set := limitEvidence(ev)
		return Outcome{
			Status:   result.Fail,
			Summary:  fmt.Sprintf("%d pending security update(s): %s; %s; package lists %s%s", len(ev), strings.Join(names, ", "), base, ageNote, warn) + moreNote(hidden),
			Evidence: shown,
			Set:      set,
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
		return "", false, fmt.Errorf("listing the apt package lists failed: %s", hostText(gerr.Error()))
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
	kept                 bool   // apt keeps the package back; it is not in the simulation's Inst lines
	secVer, secPocket    string // the newest security version above the installed one (see lookupPolicy)
}

// detail renders what is pending for a package that counts as a security
// update.
func (p aptPkg) detail() string {
	if p.kept {
		return fmt.Sprintf("kept back by apt (held, or blocked by a dependency); installed %s, the security version %s from %s is newer", p.oldVer, p.secVer, p.secPocket)
	}
	if len(p.pockets) > 0 {
		return fmt.Sprintf("%s -> %s from %s", orNone(p.oldVer), p.newVer, strings.Join(p.pockets, ", "))
	}
	return fmt.Sprintf("%s -> %s, but the security version %s from %s is newer than the installed one", orNone(p.oldVer), p.newVer, p.secVer, p.secPocket)
}

type aptSim struct {
	pkgs        []aptPkg
	keptBack    []string // names under the headings of aptKeptHeadings, sorted
	notUpgraded int
}

// The headings of the lists of packages that apt does not upgrade, with the
// names on the indented lines that follow. apt 2.4 lists all of them under
// "kept back" (a hold, a dependency that cannot be met, phasing); apt 2.8 puts
// the ones that phasing defers under a heading of their own, so the two
// lists together name what the summary counts as "not upgraded"
// (InstallPackages in apt-private/private-install.cc splits HeldBackPackages
// into ShowPhasing and ShowKept; Stats counts them all).
var aptKeptHeadings = map[string]bool{
	"The following packages have been kept back:":               true,
	"The following upgrades have been deferred due to phasing:": true,
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
	inKept := false
	seenKept := map[string]bool{}
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if inKept && line != "" && line[0] == ' ' {
			for _, name := range strings.Fields(line) {
				if !aptNameRe.MatchString(name) {
					return aptSim{}, fmt.Errorf("line %d: %s is not a package name in the list of kept back packages", i+1, quoted(name))
				}
				if !seenKept[name] {
					seenKept[name] = true
					sim.keptBack = append(sim.keptBack, name)
				}
			}
			continue
		}
		inKept = false
		switch {
		case line == "" || line[0] == ' ':
			continue
		case aptKeptHeadings[line]:
			inKept = true
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
			return aptSim{}, fmt.Errorf("line %d is not a line of apt's simulation: %s", i+1, quoted(line))
		}
	}
	if summaries != 1 {
		return aptSim{}, fmt.Errorf("expected one summary line, found %d", summaries)
	}
	if len(sim.keptBack) != sim.notUpgraded {
		return aptSim{}, fmt.Errorf("the summary announces %d package(s) not upgraded, but %d are named under the headings of the kept back and deferred packages", sim.notUpgraded, len(sim.keptBack))
	}
	if want := upgraded + installed + reinstalled; len(sim.pkgs) != want {
		return aptSim{}, fmt.Errorf("the summary announces %d package(s) to install or upgrade, but the output lists %d", want, len(sim.pkgs))
	}
	sort.Slice(sim.pkgs, func(i, j int) bool { return sim.pkgs[i].name < sim.pkgs[j].name })
	sort.Strings(sim.keptBack)
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
		return aptPkg{}, fmt.Errorf("cannot read the Inst line %s", quoted(line))
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
	aptHeaderRe    = regexp.MustCompile(`^([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?):$`)
	aptPolicyKeyRe = regexp.MustCompile(`^  (?:Installed|Candidate|Package pin): \S.*$`)
	// A version row: " *** " (the installed version) or five blanks, the
	// version, the priority, and for a phased version " (phased N%)".
	aptVersionRowRe = regexp.MustCompile(`^( \*\*\* |     )([0-9A-Za-z][0-9A-Za-z.+~:_-]*) (-?\d+)( \(phased ([0-9]|[1-9][0-9])%\))?$`)
	// An origin line: seven blanks, the priority as printf("%4i") prints it,
	// a blank and the description of the index file.
	aptOriginRe = regexp.MustCompile(`^ {7}( *-?\d+) (\S.*)$`)
)

// aptLine is one classified line of "apt-cache policy -- <names>".
type aptLine struct {
	shape  string
	name   string // header: the package name
	ver    string // version row: the version
	pocket string // origin line: the pocket of the suite, "" without one
}

// Shapes of the lines of apt-cache policy, as the policy function in
// apt-private/private-show.cc of apt 2.4.15 and 2.8.4 prints them (the
// output is run with LC_ALL=C, so "phased" is not translated):
//
//	header          "<name>:"                       std::cout << Pkg.FullName(true) << ":"
//	installed       "  Installed: <ver>|(none)"
//	candidate       "  Candidate: <ver>|(none)"
//	table           "  Version table:"
//	row             "     <ver> <prio>"              std::cout << "     " << V.VerStr() << " " << GetPriority(V)
//	row-installed   " *** <ver> <prio>"
//	row-phased      the same with " (phased N%)"   printed when PhasedUpdatePercentage() != 100,
//	                (N is 0..99: values above 100 are ignored by the list parser)
//	row-installed-phased
//	origin-suite    "       %4i <site> <release>/<component> <arch> Packages"  Describe(true) of an index file
//	origin-flat     "       %4i <site> <release> Packages"                     (a flat repository)
//	origin-file     "       %4i /path"                                          (the dpkg status file)
//	blank           ""
//
// An unknown line has shape "".
func classifyAptPolicyLine(line string) aptLine {
	switch {
	case line == "":
		return aptLine{shape: "blank"}
	case aptHeaderRe.MatchString(line):
		return aptLine{shape: "header", name: aptHeaderRe.FindStringSubmatch(line)[1]}
	case strings.HasPrefix(line, "  Installed: ") && aptPolicyKeyRe.MatchString(line):
		return aptLine{shape: "installed"}
	case strings.HasPrefix(line, "  Candidate: ") && aptPolicyKeyRe.MatchString(line):
		return aptLine{shape: "candidate"}
	case aptPolicyKeyRe.MatchString(line):
		return aptLine{shape: "pin"}
	case line == "  Version table:":
		return aptLine{shape: "table"}
	}
	if m := aptVersionRowRe.FindStringSubmatch(line); m != nil {
		shape := "row"
		if m[1] == " *** " {
			shape = "row-installed"
		}
		if m[4] != "" {
			shape += "-phased"
		}
		return aptLine{shape: shape, ver: m[2]}
	}
	if m := aptOriginRe.FindStringSubmatch(line); m != nil {
		prio, _ := strconv.Atoi(strings.TrimSpace(m[1])) // a number too large to read fails the width check below
		if fmt.Sprintf("%4d", prio) != m[1] {
			return aptLine{}
		}
		desc := m[2]
		if strings.HasPrefix(desc, "/") {
			return aptLine{shape: "origin-file"}
		}
		f := strings.Split(desc, " ")
		for _, x := range f {
			if x == "" {
				return aptLine{}
			}
		}
		switch {
		case len(f) == 4 && f[3] == "Packages":
			release, _, ok := strings.Cut(f[1], "/")
			if !ok {
				return aptLine{}
			}
			return aptLine{shape: "origin-suite", pocket: release}
		case len(f) == 3 && f[2] == "Packages":
			return aptLine{shape: "origin-flat", pocket: f[1]}
		}
	}
	return aptLine{}
}

// lookupPolicy asks apt-cache policy for the packages the simulation
// upgrades and for the packages it keeps back, and marks as security updates
// those that have a newer version in a security pocket than the installed one
// (see securityUpdates). A kept back package with such a version is added to
// the packages as a pending security update. It returns a non-nil outcome (an
// error) when the answer cannot be had or understood.
func lookupPolicy(ctx context.Context, env *Env, sim *aptSim) *Outcome {
	var names []string
	seen := map[string]bool{}
	for _, p := range sim.pkgs {
		if p.oldVer == "" || seen[p.name] {
			continue
		}
		seen[p.name] = true
		names = append(names, p.name)
	}
	for _, name := range sim.keptBack {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) > aptPolicyMax {
		return errorOutcome("%d packages are to be upgraded or are kept back, more than the %d whose security versions are looked up", len(names), aptPolicyMax)
	}
	newer := map[string]aptNewerSecurity{}
	for len(names) > 0 {
		n := min(aptPolicyBatch, len(names))
		batch := names[:n]
		names = names[n:]
		argv := append(append(append([]string{"apt-cache"}, aptNoCache...), aptPhasing...), "policy", "--")
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
			newer[name] = f
		}
	}
	for i := range sim.pkgs {
		p := &sim.pkgs[i]
		if f, ok := newer[p.name]; ok {
			p.secVer, p.secPocket, p.security = f.version, f.pocket, true
		}
	}
	for _, name := range sim.keptBack {
		if f, ok := newer[name]; ok {
			sim.pkgs = append(sim.pkgs, aptPkg{name: name, oldVer: f.installed, kept: true, security: true, secVer: f.version, secPocket: f.pocket})
		}
	}
	sort.Slice(sim.pkgs, func(i, j int) bool { return sim.pkgs[i].name < sim.pkgs[j].name })
	return nil
}

// aptNewerSecurity is the newest security version above the installed one.
type aptNewerSecurity struct{ installed, version, pocket string }

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
//	     <version> <priority>          (any other version, " (phased N%)" appended for a phased one)
//	        ...
//
// with the versions newest first (apt keeps them sorted by Debian version
// order). The versions above the installed row are newer than the installed
// one; the first of them that one of its origin lines puts into a security
// pocket is reported. The package header is the name apt prints: no
// architecture for the native one, "name:arch" for others, which is how the
// simulation names them. Every line must be one of the shapes of
// classifyAptPolicyLine, every wanted package must be present exactly once and
// have exactly one installed row.
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
	var rowVer, instVer string
	installedRows := 0
	finish := func() error {
		if cur != "" && installedRows != 1 {
			return fmt.Errorf("package %s has %d installed version rows, want 1", cur, installedRows)
		}
		// the installed row comes after the newer ones, so it is entered now
		if f, ok := found[cur]; ok {
			f.installed = instVer
			found[cur] = f
		}
		return nil
	}
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		l := classifyAptPolicyLine(line)
		switch l.shape {
		case "blank":
		case "header":
			if err := finish(); err != nil {
				return nil, err
			}
			cur = l.name
			if !wanted[cur] {
				return nil, fmt.Errorf("line %d: a package that was not asked for: %s", i+1, quoted(cur))
			}
			if described[cur] {
				return nil, fmt.Errorf("package %s is described twice", cur)
			}
			described[cur] = true
			above, haveRow, rowAbove, rowVer, instVer, installedRows = true, false, false, "", "", 0
		case "":
			return nil, fmt.Errorf("line %d is not a line of apt-cache policy: %s", i+1, quoted(line))
		case "installed", "candidate", "pin", "table":
			if cur == "" {
				return nil, fmt.Errorf("line %d is not part of a package: %s", i+1, quoted(line))
			}
		case "row", "row-phased", "row-installed", "row-installed-phased":
			if cur == "" {
				return nil, fmt.Errorf("line %d is not part of a package: %s", i+1, quoted(line))
			}
			haveRow = true
			if strings.HasPrefix(l.shape, "row-installed") {
				installedRows++
				above = false
				rowAbove, rowVer, instVer = false, l.ver, l.ver
			} else {
				rowAbove, rowVer = above, l.ver
			}
		default: // an origin line
			if cur == "" {
				return nil, fmt.Errorf("line %d is not part of a package: %s", i+1, quoted(line))
			}
			if !haveRow {
				return nil, fmt.Errorf("line %d: an origin line before any version", i+1)
			}
			if !rowAbove || l.pocket == "" {
				continue // a version at or below the installed one; the dpkg status file
			}
			if _, done := found[cur]; !done && aptPocketRe.MatchString(l.pocket) {
				found[cur] = aptNewerSecurity{version: rowVer, pocket: l.pocket}
			}
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	for _, w := range want {
		if !described[w] {
			return nil, fmt.Errorf("package %s is not described", w)
		}
	}
	return found, nil
}
