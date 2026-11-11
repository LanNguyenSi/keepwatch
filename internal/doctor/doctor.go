// Package doctor diagnoses whether keepwatch will work on this host: whether
// the configuration and the catalog are valid, whether the programs the
// enabled checks need can be run, whether the state directory is usable, and
// whether the scheduled run is installed and active. It judges the installed
// units by what they say (the program, the --config and the ReadWritePaths of
// their ExecStart), and where a path lies by the placement check of install.
// It changes nothing on the host except one short-lived probe file inside the
// state directory.
//
// The rule for every finding: doctor must not be green when a check would not
// work. A program that the execution layer would refuse counts as a problem
// (the check would be an error); a program that is not installed is a warning
// that names the checks that will be skipped.
package doctor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/catalog"
	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/engine"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
)

// Level ranks a finding.
type Level int

// The levels of a finding.
const (
	OK Level = iota
	Warn
	Problem
)

func (l Level) String() string {
	switch l {
	case Warn:
		return "warn"
	case Problem:
		return "PROBLEM"
	}
	return "ok"
}

// Finding is one line of the report.
type Finding struct {
	Level   Level
	Area    string
	Message string
}

// Resolver finds out which file the execution layer would run for a program.
// *execx.Real implements it.
type Resolver interface {
	Resolve(name string) (string, error)
}

// StateStatus is what the state directory prober found.
type StateStatus struct {
	// Exists is false when the directory has not been created yet.
	Exists bool
	// Err: the directory cannot be trusted or used (a symlink, foreign
	// owner, writable by others, a failed write probe).
	Err error
	// FileProblem: the state file exists but will not be used, the next run
	// becomes a new baseline.
	FileProblem string
}

// StateProber examines a state directory and proves it is writable by
// creating and removing one probe file inside it, never outside.
type StateProber func(dir string) StateStatus

// Deps are the things doctor needs from the outside.
type Deps struct {
	// ConfigPath is the configuration file given to doctor with --config.
	// Empty means none was given: doctor then examines the file the installed
	// services run with, and the default path when none is installed.
	ConfigPath string
	// LoadConfig loads the configuration; nil means config.Load.
	LoadConfig func(path string) (*config.Config, error)
	// Catalog is the check catalog; nil means the base catalog.
	Catalog *catalog.Catalog
	// Resolver resolves programs through the execution layer.
	Resolver Resolver
	// Runner runs systemctl, read-only.
	Runner execx.Runner
	// FS reads the unit files and looks at /run/sshd.
	FS install.FS
	// Geteuid returns the effective user id.
	Geteuid func() int
	// State examines the state directory.
	State StateProber
	// UnitDir is where the units live; empty means install.DefaultUnitDir.
	UnitDir string
	// SystemdRunDir overrides /run/systemd/system in tests.
	SystemdRunDir string
	// SSHRunDir overrides /run/sshd in tests.
	SSHRunDir string
}

// Report is the outcome of a doctor run.
type Report struct {
	Findings []Finding
	// ConfigPath is the configuration file the run examined: the one given,
	// else the one the installed check service runs with, else the default.
	ConfigPath string
}

// Problems counts the findings of level Problem.
func (r Report) Problems() int { return r.count(Problem) }

// Warnings counts the findings of level Warn.
func (r Report) Warnings() int { return r.count(Warn) }

func (r Report) count(l Level) int {
	n := 0
	for _, f := range r.Findings {
		if f.Level == l {
			n++
		}
	}
	return n
}

// Write prints the report, one finding per line, and a summary.
func (r Report) Write(w io.Writer) {
	for _, f := range r.Findings {
		fmt.Fprintf(w, "%-7s %s: %s\n", f.Level, f.Area, f.Message)
	}
	switch p, wn := r.Problems(), r.Warnings(); {
	case p > 0:
		fmt.Fprintf(w, "doctor: %d problem(s), %d warning(s)\n", p, wn)
	case wn > 0:
		fmt.Fprintf(w, "doctor: no problems, %d warning(s)\n", wn)
	default:
		fmt.Fprintln(w, "doctor: all ok")
	}
}

type reporter struct{ r *Report }

func (p reporter) add(l Level, area, format string, a ...any) {
	p.r.Findings = append(p.r.Findings, Finding{Level: l, Area: area, Message: fmt.Sprintf(format, a...)})
}

// Run performs all checks.
//
// doctor judges what the scheduled run will do, so the configuration it
// examines is the one the installed services are given (the --config of their
// ExecStart), not an assumption of its own: without Deps.ConfigPath that is the
// file of the installed check service, and the default path only when no
// service is installed. With Deps.ConfigPath that file is examined, and every
// installed service that runs with another one is a problem and is judged by
// its own file as well.
func Run(ctx context.Context, d Deps) Report {
	var rep Report
	out := reporter{&rep}
	if d.Geteuid == nil {
		d.Geteuid = func() int { return -1 }
	}

	if d.Geteuid() == 0 {
		out.add(OK, "user", "running as root")
	} else {
		out.add(Problem, "user", "not running as root: sshd -T, ss -p, fail2ban-client, docker and the apt simulation need root, so the checks would fail or see less when run by this user")
	}

	units, unitsErr := d.readUnits()
	path, source := d.configPath(units)
	rep.ConfigPath = path
	main := d.judge(path)
	cfg := main.cfg
	if cfg != nil {
		out.add(OK, "config", "%s is valid (+%d conf.d files)", cfg.Sources.Main, len(cfg.Sources.ConfD))
	}
	for _, m := range main.loadErrs {
		out.add(Problem, "config", "%s", m)
	}

	cat := d.Catalog
	if cat == nil {
		var err error
		cat, err = catalog.Base()
		if err != nil {
			out.add(Problem, "catalog", "%v", err)
			cat = nil
		}
	}
	if cat != nil {
		out.add(OK, "catalog", "%d checks", len(cat.Entries()))
	}

	if cfg != nil && cat != nil {
		if _, err := engine.Prepare(cat, cfg, engine.Deps{Runner: d.Runner, FS: probes.OSFS{}, Now: time.Now}); err != nil {
			for _, line := range strings.Split(strings.TrimPrefix(err.Error(), "engine: "), "\n") {
				out.add(Problem, "config", "%s", line)
			}
		}
		d.programs(out, cat, cfg)
		d.sshRunDir(out, cat, cfg)
	}
	// Where the configuration, the token file and the state directory lie: the
	// check install makes, with its words.
	for _, p := range main.placement {
		area := "config"
		if p.Entry.Role == install.RoleState {
			area = "state"
		}
		out.add(Problem, area, "%s", p.Error())
	}
	if cfg != nil {
		d.notify(out, cfg)
		// A state directory with a placement problem is not probed: the probe
		// writes a file, and the path cannot be relied on.
		if !install.Blocks(main.placement, filepath.Clean(cfg.StateDir)) {
			installed := false
			for _, u := range units {
				installed = installed || u.ours()
			}
			d.state(out, cfg, installed)
		}
	}
	d.units(ctx, out, units, unitsErr, main, source)
	return rep
}

// unitFile is one of the four unit files as it was found.
type unitFile struct {
	name, path string
	content    []byte
	// err is the error of reading it, fs.ErrNotExist when it is not there.
	err error
}

// ours reports whether the file was read and carries the keepwatch marker.
func (u unitFile) ours() bool { return u.err == nil && install.HasMarker(u.content) }

// service reports whether the file is one of the two services.
func (u unitFile) service() bool { return strings.HasSuffix(u.name, ".service") }

func (d Deps) unitDir() string {
	if d.UnitDir == "" {
		return install.DefaultUnitDir
	}
	return d.UnitDir
}

// readUnits reads the four unit files, in the order of install.UnitNames
// (services first). The error is the one of opening the unit directory.
func (d Deps) readUnits() ([]unitFile, error) {
	if d.FS == nil {
		return nil, errors.New("no file system")
	}
	ud, err := d.FS.OpenDir(d.unitDir())
	if err != nil {
		return nil, err
	}
	defer ud.Close()
	var out []unitFile
	for _, name := range install.UnitNames {
		u := unitFile{name: name, path: filepath.Join(d.unitDir(), name)}
		u.content, u.err = ud.ReadFile(name, 64<<10)
		out = append(out, u)
	}
	return out, nil
}

// cleanAbs reports whether p is a clean absolute path.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// configPath returns the configuration file this run examines and, for
// messages, where the choice came from.
func (d Deps) configPath(units []unitFile) (path, source string) {
	if d.ConfigPath != "" {
		// Abs also cleans. A path it cannot make absolute stays as it is, and
		// judge refuses it.
		path = d.ConfigPath
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		return path, "given with --config"
	}
	for _, u := range units {
		if !u.ours() || !u.service() {
			continue
		}
		if p := install.Inspect(u.content).ConfigPath; cleanAbs(p) {
			return p, "the --config of " + u.name
		}
	}
	return filepath.Clean(config.DefaultPath), "the default path"
}

// judged is one configuration file and what doctor found out about it.
type judged struct {
	path string
	// cfg is nil when the file did not load.
	cfg *config.Config
	// loadErrs are the reasons it did not load, one per problem.
	loadErrs []string
	// placement are the problems of where the file and the paths it names
	// lie (install.CheckPlacement).
	placement []install.PlacementProblem
}

// judge loads the configuration file at path, the way a scheduled run given
// that path does, and checks the placement of the file and of the paths it
// names.
func (d Deps) judge(path string) judged {
	j := judged{path: path}
	if !cleanAbs(path) {
		j.loadErrs = []string{fmt.Sprintf("%q is not a clean absolute path", path)}
		return j
	}
	load := d.LoadConfig
	if load == nil {
		load = func(p string) (*config.Config, error) { return config.Load(p) }
	}
	cfg, err := load(path)
	var errs config.Errors
	switch {
	case err == nil:
		j.cfg = cfg
	case errors.As(err, &errs):
		for _, e := range errs {
			j.loadErrs = append(j.loadErrs, e.Error())
		}
	default:
		j.loadErrs = []string{err.Error()}
	}
	paths := install.Paths{ConfigPath: path}
	if j.cfg != nil {
		paths.StateDir = filepath.Clean(j.cfg.StateDir)
		if n := j.cfg.Notify.Ntfy; n != nil {
			paths.TokenFile = n.TokenFile
		}
	}
	if d.FS != nil {
		j.placement = install.CheckPlacement(d.FS, install.Manifest(paths))
	}
	return j
}

// enabled lists the catalog entries that are not switched off.
func enabled(cat *catalog.Catalog, cfg *config.Config) []catalog.Entry {
	var out []catalog.Entry
	for _, e := range cat.Entries() {
		if cc, ok := cfg.Checks[e.ID]; ok && !cc.Enabled {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (d Deps) programs(out reporter, cat *catalog.Catalog, cfg *config.Config) {
	if d.Resolver == nil {
		out.add(Problem, "programs", "internal error: no program resolver")
		return
	}
	type status struct {
		path string
		err  error
	}
	seen := map[string]status{}
	find := func(prog string) status {
		if s, ok := seen[prog]; ok {
			return s
		}
		p, err := d.Resolver.Resolve(prog)
		s := status{p, err}
		seen[prog] = s
		return s
	}
	disabled := 0
	for _, e := range cat.Entries() {
		if cc, ok := cfg.Checks[e.ID]; ok && !cc.Enabled {
			disabled++
		}
	}
	allOK := true
	for _, e := range enabled(cat, cfg) {
		kind, ok := probes.Lookup(e.Kind)
		if !ok {
			continue
		}
		progs := kind.Programs()
		var missing, refused []string
		for _, p := range progs {
			switch s := find(p); {
			case s.err == nil:
			case errors.Is(s.err, execx.ErrNotFound):
				missing = append(missing, p)
			default:
				refused = append(refused, fmt.Sprintf("%s (%v)", p, s.err))
			}
		}
		if len(refused) > 0 {
			allOK = false
			out.add(Problem, "programs", "%s needs %s, which the execution layer refuses: the check would be an error", e.ID, strings.Join(refused, ", "))
		}
		if len(missing) == 0 {
			continue
		}
		if lvl, msg, say := missingMessage(e, missing); say {
			allOK = false
			out.add(lvl, "programs", "%s", msg)
		}
	}
	if allOK {
		out.add(OK, "programs", "every program the enabled checks need was found (%d checks disabled in the configuration)", disabled)
	}
}

// missingMessage says what missing programs do to a check. Most kinds are
// skipped; three read more than one source. ok is false when nothing needs to
// be said.
func missingMessage(e catalog.Entry, missing []string) (lvl Level, msg string, ok bool) {
	list := strings.Join(missing, ", ")
	has := func(p string) bool {
		for _, m := range missing {
			if m == p {
				return true
			}
		}
		return false
	}
	switch e.Kind {
	case "firewall_default":
		// nft covers both address families; without it iptables and ip6tables
		// are needed together, and ufw is only a note.
		switch {
		case has("nft") && has("iptables") && has("ip6tables"):
			return Warn, fmt.Sprintf("%s: none of nft, iptables and ip6tables found, the check will be skipped", e.ID), true
		case has("nft") && (has("iptables") != has("ip6tables")):
			return Problem, fmt.Sprintf("%s: not found: %s; without nft, iptables and ip6tables are both needed, so one address family has no readable source and the check would be an error", e.ID, list), true
		}
		return OK, "", false
	case "reboot_required":
		return Warn, fmt.Sprintf("%s: %s not found, the check still reads /var/run/reboot-required but the kernel status stays unknown", e.ID, list), true
	case "docker_exposure":
		return Warn, fmt.Sprintf("%s: %s not found, the check will be skipped unless a Docker daemon is configured or running (then it is an error)", e.ID, list), true
	}
	return Warn, fmt.Sprintf("%s: %s not found, the check will be skipped", e.ID, list), true
}

// sshRunDir names the cause of error results of the ssh checks on Ubuntu
// 24.04: sshd -T needs /run/sshd, which the ssh.service unit creates, and
// with socket activation it does not exist before the first login.
func (d Deps) sshRunDir(out reporter, cat *catalog.Catalog, cfg *config.Config) {
	var ids []string
	for _, e := range enabled(cat, cfg) {
		if e.Kind == "sshd_effective" || e.Kind == "authorized_keys" {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) == 0 || d.Resolver == nil || d.FS == nil {
		return
	}
	if _, err := d.Resolver.Resolve("sshd"); err != nil {
		return // the checks are skipped, see programs
	}
	dir := d.SSHRunDir
	if dir == "" {
		dir = "/run/sshd"
	}
	info, err := d.FS.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.add(Problem, "ssh", "%s does not exist, so \"sshd -T\" fails and these checks will be errors: %s. On Ubuntu 24.04 with ssh.socket the directory is created when ssh.service starts, not before the first login; start it once with \"systemctl start ssh\" (keepwatch does not create it)", dir, strings.Join(ids, ", "))
	case err != nil:
		out.add(Problem, "ssh", "cannot look at %s: %v", dir, err)
	case !info.IsDir():
		out.add(Problem, "ssh", "%s is not a directory, so \"sshd -T\" fails and the ssh checks will be errors", dir)
	default:
		out.add(OK, "ssh", "%s exists", dir)
	}
}

func (d Deps) notify(out reporter, cfg *config.Config) {
	if cfg.Notify.Ntfy == nil {
		out.add(Warn, "notify", "no notification channel is configured (notify.ntfy), results are only shown, nobody is told of changes")
		return
	}
	out.add(OK, "notify", "ntfy is configured (%s); \"keepwatch doctor --send-test\" delivers a test message", origin(cfg.Notify.Ntfy.URL))
}

func (d Deps) state(out reporter, cfg *config.Config, unitsInstalled bool) {
	if d.State == nil {
		out.add(Problem, "state", "internal error: no state prober")
		return
	}
	st := d.State(cfg.StateDir)
	switch {
	case st.Err != nil:
		out.add(Problem, "state", "state_dir %s is not usable, checks would exit 3: %v", cfg.StateDir, st.Err)
	case !st.Exists && unitsInstalled:
		out.add(Problem, "state", "state_dir %s does not exist, but the units are installed: the services have ReadWritePaths=%s and fail to start (status 226/NAMESPACE) while it is missing; run \"keepwatch install\" again, which creates it", cfg.StateDir, cfg.StateDir)
	case !st.Exists:
		out.add(Warn, "state", "state_dir %s does not exist yet; \"keepwatch install\" creates it, and so does the first \"keepwatch check\" run", cfg.StateDir)
	case st.FileProblem != "":
		out.add(Warn, "state", "state_dir %s is writable, but the previous state will not be used and the next run is a new baseline: %s", cfg.StateDir, st.FileProblem)
	default:
		out.add(OK, "state", "state_dir %s is writable", cfg.StateDir)
	}
}

// units checks the installed units and the timers. main is the configuration
// this run examined and source says where its path came from.
func (d Deps) units(ctx context.Context, out reporter, units []unitFile, unitsErr error, main judged, source string) {
	if d.FS == nil || d.Runner == nil {
		out.add(Problem, "units", "internal error: no file system or runner")
		return
	}
	unitDir := d.unitDir()
	runDir := d.SystemdRunDir
	if runDir == "" {
		runDir = "/run/systemd/system"
	}
	booted := false
	if i, err := d.FS.Lstat(runDir); err == nil && i.IsDir() {
		booted = true
	}
	if !booted {
		out.add(Problem, "systemd", "systemd is not running on this host (%s is missing): the timers cannot run", runDir)
	}

	if unitsErr != nil {
		out.add(Problem, "units", "cannot open %s: %v", unitDir, unitsErr)
		return
	}
	// A service that runs with another configuration than the one examined
	// above is judged by its own file, loaded once.
	others := map[string]judged{}
	installedAll := true
	// missing are the unit files that are not there.
	missing := map[string]bool{}
	for _, u := range units {
		switch {
		case errors.Is(u.err, fs.ErrNotExist):
			installedAll = false
			missing[u.name] = true
			out.add(Problem, "units", "%s is not installed; run \"keepwatch install\"", u.path)
			continue
		case u.err != nil:
			installedAll = false
			out.add(Problem, "units", "%s: %v", u.path, u.err)
			continue
		case !u.ours():
			installedAll = false
			out.add(Problem, "units", "%s exists but was not written by keepwatch (no marker comment); \"keepwatch install\" refuses to overwrite it", u.path)
			continue
		}
		if !u.service() {
			continue
		}
		in := install.Inspect(u.content)
		if in.Binary == "" {
			out.add(Problem, "units", "%s has no ExecStart program that doctor can read; run \"keepwatch install\" again", u.path)
		} else {
			// The program the service runs as root: it must be there, the
			// sandbox must show it and only root may be able to change it.
			for _, p := range install.CheckPlacement(d.FS, install.Manifest(install.Paths{Binary: in.Binary})) {
				out.add(Problem, "units", "%s: %s", u.path, p.Error())
			}
		}
		if in.Binary != "" && in.ConfigPath != "" {
			d.unitDrift(out, u)
		}
		var cfg *config.Config
		switch {
		case in.ConfigPath == "":
			out.add(Problem, "units", "%s has no --config that doctor can read; run \"keepwatch install\" again", u.path)
			continue
		case in.ConfigPath == main.path:
			cfg = main.cfg // judged above
		default:
			out.add(Problem, "units", "%s runs with --config %s, but this doctor run examined %s (%s): the findings of the other areas are about that file, not about what this service uses. Run \"keepwatch doctor\" without --config to examine the installed units, or \"keepwatch install --config FILE\" to give both services the file you mean", u.path, in.ConfigPath, main.path, source)
			j, seen := others[in.ConfigPath]
			if !seen {
				j = d.judge(in.ConfigPath)
				others[in.ConfigPath] = j
			}
			for _, m := range j.loadErrs {
				out.add(Problem, "units", "%s runs with --config %s, which is not valid, so every scheduled run exits 3: %s", u.path, in.ConfigPath, m)
			}
			for _, p := range j.placement {
				out.add(Problem, "units", "%s: %s", u.path, p.Error())
			}
			cfg = j.cfg
		}
		if cfg == nil {
			continue // said where the configuration was judged
		}
		if stateDir := filepath.Clean(cfg.StateDir); in.ReadWritePaths != stateDir {
			out.add(Problem, "units", "%s allows writes to %q but state_dir is %s: under systemd the state could not be saved; run \"keepwatch install\" again", u.path, in.ReadWritePaths, stateDir)
		}
		d.unitNotify(out, u.path, in.Notify, cfg)
	}
	if installedAll {
		out.add(OK, "units", "the four unit files in %s carry the keepwatch marker", unitDir)
	}
	if !booted {
		return
	}
	for _, t := range install.Timers {
		v, err := install.Show(ctx, d.Runner, t, "LoadState", "ActiveState", "UnitFileState")
		if err != nil {
			out.add(Problem, "timers", "cannot ask systemd about %s: %v", t, err)
			continue
		}
		switch {
		case v["LoadState"] != "loaded":
			out.add(Problem, "timers", "%s is not loaded (%s)", t, v["LoadState"])
		case v["UnitFileState"] != "enabled":
			out.add(Problem, "timers", "%s is %s, not enabled; run \"keepwatch install\"", t, v["UnitFileState"])
		case v["ActiveState"] != "active":
			out.add(Problem, "timers", "%s is %s, not active; run \"keepwatch install\"", t, v["ActiveState"])
		default:
			out.add(OK, "timers", "%s is enabled and active", t)
		}
	}
	for _, s := range []string{install.CheckService, install.ReportService} {
		// A service whose file is missing was reported as not installed, and
		// that systemd does not know it adds nothing. For every other one (the
		// file is there: ours, foreign or unreadable) the questions below are
		// the only thing that tells what systemd runs, so a question without an
		// answer, or a unit systemd did not load, is a problem and never a
		// silent skip.
		v, err := install.Show(ctx, d.Runner, s, "LoadState", "Result", "ExecMainStatus", "ActiveState", "ExecMainStartTimestamp", "DropInPaths", "FragmentPath", "NeedDaemonReload")
		if err != nil {
			if !missing[s] {
				out.add(Problem, "units", "cannot ask systemd about %s: %s. So doctor cannot tell whether drop-ins are merged into the service, which file systemd loaded and how the last run ended, and nothing says that the service runs as \"keepwatch install\" renders it. \"systemctl show %s\" fails, for one, when a drop-in of the unit has a file name that is not valid UTF-8", s, quoteUnprintable(err.Error()), s)
			}
			continue
		}
		if v["LoadState"] != "loaded" {
			if !missing[s] {
				out.add(Problem, "units", "systemd has not loaded %s although its unit file is there (load state %q), so the timer cannot start the service: the unit is masked, or systemd refuses a setting of the unit file or of a drop-in. \"systemctl status %s\" shows which", s, v["LoadState"], s)
			}
			continue
		}
		d.loadedUnit(out, s, v)
		// SuccessExitStatus=1 makes a run with findings a success.
		switch {
		case v["ActiveState"] == "failed" || (v["Result"] != "" && v["Result"] != "success"):
			out.add(Problem, "last run", "%s did not succeed (result %s, exit status %s%s); see \"journalctl -u %s\"", s, v["Result"], v["ExecMainStatus"], exitMeaning(v["ExecMainStatus"]), s)
		case s == install.CheckService && v["ExecMainStartTimestamp"] == "":
			// The sandbox only shows when the service runs: nothing above proves it can.
			out.add(Warn, "last run", "%s has not run since the host booted, so nothing proves that the sandbox lets the checks run; start it once with \"systemctl start %s\" and look at \"journalctl -u %s\"", s, s, s)
		}
	}
}

// loadedUnit judges what systemd has loaded of a service, not the file in the
// unit directory: the file it took the unit from, whether that is the file
// doctor read, whether it has been reloaded since the file changed, and the
// drop-ins merged into it.
func (d Deps) loadedUnit(out reporter, name string, v map[string]string) {
	if want := filepath.Join(d.unitDir(), name); v["FragmentPath"] != want {
		out.add(Problem, "units", "systemd loaded %s from %q, not from %s, which is the file doctor judges: the service runs as that file says. Remove the other file and run \"systemctl daemon-reload\"; \"keepwatch install\" writes only the file in the unit directory", name, v["FragmentPath"], want)
	}
	if v["NeedDaemonReload"] == "yes" {
		out.add(Problem, "units", "systemd has not reloaded %s since the unit file or a drop-in changed, so the service runs as it was when systemd last read it, not as the file on disk says: run \"systemctl daemon-reload\"", name)
	}
	var own, shared []string
	for _, p := range splitQuoted(v["DropInPaths"]) {
		// systemd reads the drop-ins of a unit from <name>.service.d for each
		// name the unit has (an alias included), from the directories named
		// for a prefix of the name (keepwatch-.service.d) and from service.d,
		// which holds for every service of the host. Only service.d can have
		// been put there by someone who did not mean these units: a vendor, an
		// image or a generator. Everything else is aimed at this unit.
		if filepath.Base(filepath.Dir(p)) == "service.d" {
			shared = append(shared, p)
		} else {
			own = append(own, p)
		}
	}
	if len(own) > 0 {
		// systemd merges a drop-in into the unit, so the service runs with it
		// whatever its file says. What it changes (ExecStart, a hardening
		// option) is not something doctor judges.
		out.add(Problem, "units", "%s has drop-ins (%s): systemd runs the service with them applied, so it does not run as \"keepwatch install\" renders it, and doctor does not judge what they change. Remove them: install writes the unit without them and does not remove a drop-in", name, listPaths(own))
	}
	if len(shared) > 0 {
		out.add(Warn, "units", "%s is merged with %s from a service.d directory, which applies to every service of the host and may come from the system, an image or a generator; doctor does not judge what it changes, so look at it if the service does not run as install renders it", name, listPaths(shared))
	}
}

// splitQuoted splits the value of a systemctl property that lists paths, as
// "systemctl show" prints it (measured on systemd 249 and 255, which print the
// same bytes). The entries are separated by blanks. systemctl puts an entry in
// double quotes when it holds a blank, a control character or one of a set of
// characters a shell reads specially (a quote, a backslash, & ; * ? among
// them), and inside the quotes it writes
//
//   - a backslash before a double quote, a backslash, a dollar sign and a
//     backquote;
//   - \a \b \f \n \r \t \v for these control characters;
//   - a backslash and three octal digits for every other byte below 0x20 and
//     for 0x7f (\033, \177).
//
// Valid UTF-8 above 0x7f is printed as it is, quoted or not, whatever the
// character is. splitQuoted undoes exactly that, and reads two more forms of
// systemd's escaping that systemctl does not print here: \xNN (two hexadecimal
// digits) and a backslash before a single quote. A backslash before any other
// byte stands for that byte, and one that is not followed by three octal digits
// of a value up to 0377 (or by x and two hexadecimal digits) is not a number.
// A backslash outside quotes is kept. A quote that is not closed takes the rest
// of the value. The entries are the bytes of the file names: they can hold
// control characters and must be quoted before they are printed (listPaths).
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inToken, inQuote := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '\\' && i+1 < len(s):
			if b, ok := escapedNumber(s[i+1:]); ok {
				cur.WriteByte(b)
				i += escapedNumberLen
				continue
			}
			i++
			switch e := s[i]; e {
			case 'a':
				cur.WriteByte('\a')
			case 'b':
				cur.WriteByte('\b')
			case 'f':
				cur.WriteByte('\f')
			case 'n':
				cur.WriteByte('\n')
			case 'r':
				cur.WriteByte('\r')
			case 't':
				cur.WriteByte('\t')
			case 'v':
				cur.WriteByte('\v')
			default:
				cur.WriteByte(e)
			}
		case inQuote && c == '"':
			inQuote = false
		case inQuote:
			cur.WriteByte(c)
		case c == '"':
			inQuote, inToken = true, true
		case c == ' ' || c == '\t' || c == '\n':
			if inToken {
				out = append(out, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteByte(c)
			inToken = true
		}
	}
	if inToken {
		out = append(out, cur.String())
	}
	return out
}

// escapedNumberLen is how many bytes the number of an escape takes after the
// backslash, in both forms.
const escapedNumberLen = 3

// escapedNumber reads the number of an escape, s being what follows the
// backslash: three octal digits of a value up to 0377, or x and two
// hexadecimal digits.
func escapedNumber(s string) (b byte, ok bool) {
	if len(s) < escapedNumberLen {
		return 0, false
	}
	digits, base := s[:3], 8
	if s[0] == 'x' {
		digits, base = s[1:3], 16
	}
	// ParseUint takes digits of the base and nothing else (no sign, no
	// prefix), and refuses a value that does not fit a byte.
	v, err := strconv.ParseUint(digits, base, 8)
	if err != nil {
		return 0, false
	}
	return byte(v), true
}

// printable reports whether s can be written to a terminal as it is: valid
// UTF-8 that holds nothing but printable characters (unicode.IsPrint: no
// control character, no escape, no character that changes the direction of the
// text or draws nothing but a blank).
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// quoteUnprintable returns a text of another program for a message: as it is
// when it is printable, and quoted like a path of listPaths when it is not.
func quoteUnprintable(s string) string {
	if printable(s) {
		return s
	}
	return strconv.Quote(s)
}

// listPaths joins paths for a message. The paths are file names of the host,
// so they can hold any byte but NUL. One that is printable and holds no blank,
// no double quote and no backslash is written as it is; every other one is
// written as strconv.Quote writes it (\r, \x1b, \x7f, \u202e, \xff for a byte
// that is not UTF-8), so that no control character and no byte that is not
// UTF-8 reaches the output and the end of each path can be seen.
func listPaths(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = p
		if p == "" || !printable(p) || strings.ContainsAny(p, " \"\\") {
			q[i] = strconv.Quote(p)
		}
	}
	return strings.Join(q, " ")
}

// unitDrift reports a service file that is not what "keepwatch install" writes
// for the values the file holds. Inspect reads only the last ExecStart and a
// few values, so a second ExecStart line, an added or changed option or any
// other line would pass the other checks while systemd runs something else.
func (d Deps) unitDrift(out reporter, u unitFile) {
	want, err := install.RenderInstalled(u.name, u.content)
	if err != nil {
		out.add(Problem, "units", "%s is not a unit that \"keepwatch install\" can have written: %v; run \"keepwatch install\" again", u.path, err)
		return
	}
	diff, differs := install.FirstDifference(want, u.content)
	if !differs {
		return
	}
	var where string
	switch {
	case diff.GotEnded:
		where = fmt.Sprintf("the file ends after line %d, where the rendered unit goes on with %s", diff.Line-1, shown(diff.Want))
	case diff.WantEnded:
		where = fmt.Sprintf("line %d, %s, is not in the rendered unit", diff.Line, shown(diff.Got))
	case diff.Want == diff.Got:
		where = fmt.Sprintf("line %d, %s, lacks or has a line feed that the rendered unit does not", diff.Line, shown(diff.Got))
	default:
		where = fmt.Sprintf("line %d is %s, the rendered unit has %s", diff.Line, shown(diff.Got), shown(diff.Want))
	}
	out.add(Problem, "units", "%s was changed after \"keepwatch install\" wrote it, so systemd does not run it as rendered (rendered from the values the file holds): %s. Run \"keepwatch install\" again to write it as rendered", u.path, where)
}

// shown quotes a line of a unit file for a message, shortened.
func shown(line string) string {
	if len(line) > 160 {
		line = line[:160] + "..."
	}
	return strconv.Quote(line)
}

// unitNotify checks that an installed service notifies exactly when
// notify.ntfy is configured. A service with --notify and no notify.ntfy exits
// 3 on every run. One without --notify while notify.ntfy is configured moves
// the state forward past the alerts, so nobody is told of them: a loss, and a
// problem.
func (d Deps) unitNotify(out reporter, unit string, unitNotifies bool, cfg *config.Config) {
	if cfg == nil {
		return
	}
	configured := cfg.Notify.Ntfy != nil
	switch {
	case unitNotifies && !configured:
		out.add(Problem, "units", "%s runs with --notify, but notify.ntfy is not configured: every scheduled run exits 3. Configure notify.ntfy, or run \"keepwatch install\" again to drop --notify", unit)
	case !unitNotifies && configured:
		out.add(Problem, "units", "notify.ntfy is configured, but %s runs without --notify: every scheduled run consumes the alerts it finds and nobody is told, which is a loss. Run \"keepwatch install\" again", unit)
	}
}

// exitMeaning names the exit statuses of keepwatch that fail a service.
func exitMeaning(status string) string {
	switch status {
	case "3":
		return ": keepwatch could not do its job"
	case "4":
		return ": the notification could not be delivered"
	case "226":
		return ": the sandbox could not be set up, for example ReadWritePaths names a missing directory"
	}
	return ""
}

// origin returns scheme://host[:port] of a URL and nothing else: the user
// info, the path and the query may hold credentials or the topic, and doctor's
// output does not go through the redactor.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "address not shown"
	}
	return u.Scheme + "://" + u.Host
}
