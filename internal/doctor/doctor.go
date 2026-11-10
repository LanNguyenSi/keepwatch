// Package doctor diagnoses whether keepwatch will work on this host: whether
// the configuration and the catalog are valid, whether the programs the
// enabled checks need can be run, whether the state directory is usable, and
// whether the scheduled run is installed and active. It changes nothing on the
// host except one short-lived probe file inside the state directory.
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
	"path/filepath"
	"strings"
	"time"

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
	// ConfigPath is the main configuration file; empty means the default.
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

	path := d.ConfigPath
	if path == "" {
		path = config.DefaultPath
	}
	path = filepath.Clean(path)
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	load := d.LoadConfig
	if load == nil {
		load = func(p string) (*config.Config, error) { return config.Load(p) }
	}
	cfg, err := load(path)
	if err != nil {
		var errs config.Errors
		if errors.As(err, &errs) {
			for _, e := range errs {
				out.add(Problem, "config", "%s", e.Error())
			}
		} else {
			out.add(Problem, "config", "%v", err)
		}
	} else {
		out.add(OK, "config", "%s is valid (+%d conf.d files)", cfg.Sources.Main, len(cfg.Sources.ConfD))
	}

	cat := d.Catalog
	if cat == nil {
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
	if cfg != nil {
		d.notify(out, cfg)
		d.state(out, cfg)
	}
	var stateDir string
	if cfg != nil {
		stateDir = cfg.StateDir
	}
	d.units(ctx, out, path, stateDir)
	return rep
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
	out.add(OK, "notify", "ntfy is configured (%s); \"keepwatch doctor --send-test\" delivers a test message", cfg.Notify.Ntfy.URL)
}

func (d Deps) state(out reporter, cfg *config.Config) {
	if d.State == nil {
		out.add(Problem, "state", "internal error: no state prober")
		return
	}
	st := d.State(cfg.StateDir)
	switch {
	case st.Err != nil:
		out.add(Problem, "state", "state_dir %s is not usable, checks would exit 3: %v", cfg.StateDir, st.Err)
	case !st.Exists:
		out.add(Warn, "state", "state_dir %s does not exist yet; \"keepwatch install\" or the first run creates it", cfg.StateDir)
	case st.FileProblem != "":
		out.add(Warn, "state", "state_dir %s is writable, but the previous state will not be used and the next run is a new baseline: %s", cfg.StateDir, st.FileProblem)
	default:
		out.add(OK, "state", "state_dir %s is writable", cfg.StateDir)
	}
}

// units checks the installed units and the timers. stateDir is empty when the
// configuration did not load.
func (d Deps) units(ctx context.Context, out reporter, configPath, stateDir string) {
	if d.FS == nil || d.Runner == nil {
		out.add(Problem, "units", "internal error: no file system or runner")
		return
	}
	unitDir := d.UnitDir
	if unitDir == "" {
		unitDir = install.DefaultUnitDir
	}
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

	ud, err := d.FS.OpenDir(unitDir)
	if err != nil {
		out.add(Problem, "units", "cannot open %s: %v", unitDir, err)
		return
	}
	defer ud.Close()
	installedAll := true
	for _, name := range install.UnitNames {
		p := filepath.Join(unitDir, name)
		content, err := ud.ReadFile(name, 64<<10)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			installedAll = false
			out.add(Problem, "units", "%s is not installed; run \"keepwatch install\"", p)
			continue
		case err != nil:
			installedAll = false
			out.add(Problem, "units", "%s: %v", p, err)
			continue
		case !install.HasMarker(content):
			installedAll = false
			out.add(Problem, "units", "%s exists but was not written by keepwatch (no marker comment); \"keepwatch install\" refuses to overwrite it", p)
			continue
		}
		if !strings.HasSuffix(name, ".service") {
			continue
		}
		in := install.Inspect(content)
		d.binary(out, p, in.Binary)
		if stateDir != "" && in.ReadWritePaths != stateDir {
			out.add(Problem, "units", "%s allows writes to %q but state_dir is %s: under systemd the state could not be saved; run \"keepwatch install\" again", p, in.ReadWritePaths, stateDir)
		}
		if in.ConfigPath != configPath {
			out.add(Warn, "units", "%s runs with --config %s, this doctor run used %s", p, in.ConfigPath, configPath)
		}
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
		v, err := install.Show(ctx, d.Runner, s, "LoadState", "Result", "ExecMainStatus", "ActiveState")
		if err != nil || v["LoadState"] != "loaded" {
			continue // not installed, said above
		}
		// SuccessExitStatus=1 makes a run with findings a success.
		if v["ActiveState"] == "failed" || (v["Result"] != "" && v["Result"] != "success") {
			out.add(Problem, "last run", "%s did not succeed (result %s, exit status %s); see \"journalctl -u %s\"", s, v["Result"], v["ExecMainStatus"], s)
		}
	}
}

// binary checks the program the installed service runs as root: it must be
// there and only root may be able to change it or anything above it.
func (d Deps) binary(out reporter, unit, bin string) {
	if bin == "" {
		out.add(Problem, "units", "%s has no ExecStart program that doctor can read; run \"keepwatch install\" again", unit)
		return
	}
	err := install.TrustedPath(d.FS, bin, install.KindFile)
	switch {
	case err == nil:
	case install.IsMissing(err):
		out.add(Problem, "units", "%s runs %s, which does not exist (%v): the scheduled run fails; install the binary there or run \"keepwatch install\" from the new location", unit, bin, err)
	default:
		out.add(Problem, "units", "%s runs %s as root, but it cannot be trusted: %v. Anybody who can change it or a directory above it gets root; install it for example with \"install -o root -g root -m 0755 keepwatch /usr/local/bin/\" and run \"keepwatch install\" again", unit, bin, err)
	}
}
