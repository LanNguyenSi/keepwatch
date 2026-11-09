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
// It runs "apt-get -s -o Debug::NoLocking=true dist-upgrade": -s simulates
// (nothing is installed, removed or written), and Debug::NoLocking=true makes
// apt take no lock, so the run neither waits for a running apt or
// unattended-upgrades nor can it make one fail. It does not run
// "apt-get update", which would write: the check judges the package lists the
// host has, and says how old they are. The simulation also works with
// /var/cache/apt and /var/lib/apt mounted read-only (as a systemd unit with
// ProtectSystem=strict has them): apt then builds its cache in memory.
//
// Only exit status 0 is interpreted; apt-get exits 100 on every error
// ("E: ..." on stderr), which is error here. The output must be understood in
// full: every line is a known kind of line, the summary line "N upgraded, M
// newly installed, K to remove and L not upgraded." is present exactly once,
// and the number of "Inst" lines equals N + M. Anything else is error. Each
// "Inst <package> [<old>] (<new> <origin>:<version>/<pocket>, ... [<arch>])"
// line names the pockets the new version is available from; the version is
// a pending security update when one of them ends in "-security" (this
// covers Ubuntu's "<release>-security" and the ESM pockets
// "<release>-infra-security" and "<release>-apps-security"). A package that
// is available from both "-updates" and "-security" counts, because the
// security pocket carries the fix.
//
// Result: fail with one evidence item per package (subject: the package name,
// detail: old and new version and the pocket), sorted and limited to 100
// items. The age of the package lists is the newest modification time of
// /var/lib/apt/lists/*InRelease. Without a pending security update, lists
// older than max_list_age_hours, or no such file at all, make the status
// warn (one evidence item with subject "apt-lists"); with pending updates the
// age appears in the summary. The count of "not upgraded" packages (held
// back, or phased by Ubuntu) is named in the summary; the simulation does not
// say which pocket they would come from, so they are not judged.
type securityUpdates struct{}

func (securityUpdates) Name() string       { return "security_updates" }
func (securityUpdates) Programs() []string { return []string{"apt-get"} }

func (securityUpdates) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	hours := p.integer("max_list_age_hours", 48, 1, 24*365)
	if err := p.err(); err != nil {
		return nil, err
	}
	return updatesProbe{maxAge: time.Duration(hours) * time.Hour}, nil
}

type updatesProbe struct{ maxAge time.Duration }

var aptArgv = []string{"apt-get", "-s", "-o", "Debug::NoLocking=true", "dist-upgrade"}

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
		ev = append(ev, result.Evidence{
			Subject: p.name,
			Detail:  clean(fmt.Sprintf("%s -> %s from %s", orNone(p.oldVer), p.newVer, strings.Join(p.pockets, ", ")), 150),
		})
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
		if stale {
			warn = " (stale: newer updates may exist)"
		}
		shown, hidden := limitEvidence(ev)
		return Outcome{
			Status:   result.Fail,
			Summary:  fmt.Sprintf("%d pending security update(s): %s; %s; package lists %s%s", len(ev), strings.Join(names, ", "), base, ageNote, warn) + moreNote(hidden),
			Evidence: shown,
		}
	}
	if stale {
		return Outcome{
			Status:   result.Warn,
			Summary:  "no pending security updates in the package lists, but the lists " + ageNote + ", so newer updates may exist; " + base,
			Evidence: []result.Evidence{{Subject: "apt-lists", Detail: fmt.Sprintf("package lists %s; limit is %s", ageNote, hoursText(u.maxAge))}},
		}
	}
	return Outcome{Status: result.Pass, Summary: "no pending security updates; " + base + "; package lists " + ageNote}
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
	pockets              []string // the "-security" pockets, sorted
	security             bool
}

type aptSim struct {
	pkgs        []aptPkg
	notUpgraded int
}

var (
	aptSummaryRe = regexp.MustCompile(`^(\d+) upgraded, (\d+) newly installed(?:, (\d+) reinstalled)?(?:, (\d+) downgraded)?, (\d+) to remove and (\d+) not upgraded\.$`)
	aptInstRe    = regexp.MustCompile(`^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.+) \[(\S+)\]\)(?: \[\])?$`)
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
