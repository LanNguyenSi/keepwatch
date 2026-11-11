package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/history"
	"github.com/LanNguyenSi/keepwatch/internal/state"
)

// The names keepwatch owns inside the state directory come from the packages
// that write them (state, history), so a name is written in one place. A test
// scans those packages for any other file name literal.
var (
	ownedStateNames    = []string{state.FileName, history.FileName}
	ownedStatePrefixes = []string{state.TempPrefix, history.TempPrefix, ProbePrefix, tmpWritePrefix}
)

// ownedInStateDir reports whether name is a file keepwatch writes in state_dir.
func ownedInStateDir(name string) bool {
	for _, n := range ownedStateNames {
		if name == n {
			return true
		}
	}
	for _, p := range ownedStatePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// ProbePrefix starts the name of the file WriteProbe (run by `keepwatch
// install` and `keepwatch doctor`) creates inside state_dir to prove it is
// writable; the value keeps its old name so purge still recognises it; one left behind by a crash is keepwatch's
// own. tmpWritePrefix starts the temporary names of Dir.WriteFile.
const (
	ProbePrefix    = ".keepwatch-doctor-probe-"
	tmpWritePrefix = ".keepwatch-tmp-"
)

// UninstallOptions are the inputs of Uninstall.
type UninstallOptions struct {
	DryRun bool
	// Purge also removes keepwatch's configuration and state.
	Purge bool
	// ConfigPath is the main configuration file as the command line gave it
	// (or the default), ConfigExplicit says whether it was given.
	ConfigPath     string
	ConfigExplicit bool
	// DefaultConfigPath is the default path of the configuration file;
	// DefaultStateDir the default state directory.
	DefaultConfigPath string
	DefaultStateDir   string
	// StateDirOf returns the state_dir of the configuration file at the path
	// (found is false when the file does not exist).
	StateDirOf func(configPath string) (dir string, found bool, err error)
}

// Uninstall stops and disables the timers, removes the unit files that carry
// the marker, and reloads systemd. A file with the name of a unit that does
// not carry the marker (or that is a link) is left alone and reported. With
// Purge it then removes keepwatch's own state files, and its configuration
// files if the configuration provably is keepwatch's, and the directories that
// are empty afterwards; see the README for the list.
//
// A configuration file is proven to be keepwatch's only by its path: the
// default path, or the --config recorded in an installed unit that carries the
// marker (read before the units are removed). That a file loads as a keepwatch
// configuration proves nothing: an empty YAML file loads. Anything else is
// left alone and reported, and the result is ErrRefused.
func Uninstall(ctx context.Context, d Deps, o UninstallOptions) error {
	say := func(format string, a ...any) { fmt.Fprintf(d.Out, format+"\n", a...) }
	would := ""
	if o.DryRun {
		would = "would "
	}
	if !o.DryRun && d.Geteuid() != 0 {
		return refuse("uninstall removes files below /etc and runs systemctl, run it as root (or use --dry-run)")
	}

	unitDir := d.unitDir()
	ours := map[string]bool{}
	var rec Installed // what the installed units say, read before they are removed
	ud, err := d.FS.OpenDir(unitDir)
	switch {
	case err == nil:
		defer ud.Close()
		for _, name := range UnitNames {
			p := filepath.Join(unitDir, name)
			info, lerr := ud.Lstat(name)
			switch {
			case errors.Is(lerr, fs.ErrNotExist):
			case lerr != nil:
				return failed("%s: %v", p, lerr)
			case info.IsSymlink():
				say("left %s: it is a symlink", p)
			case !info.IsRegular():
				say("left %s: it is not a regular file", p)
			default:
				cur, rerr := ud.ReadFile(name, maxUnitSize)
				switch {
				case rerr != nil:
					say("left %s: %v", p, rerr)
				case !HasMarker(cur):
					say("left %s: not written by keepwatch (no marker comment)", p)
				default:
					ours[name] = true
					if strings.HasSuffix(name, ".service") {
						in := Inspect(cur)
						if rec.ConfigPath == "" {
							rec.ConfigPath = in.ConfigPath
						}
						if rec.ReadWritePaths == "" {
							rec.ReadWritePaths = in.ReadWritePaths
						}
					}
				}
			}
		}
	case errors.Is(err, fs.ErrNotExist):
		say("%s does not exist, no unit files to remove", unitDir)
	default:
		return refuse("unit directory: %v", err)
	}

	run := func(args ...string) error {
		say("%srun systemctl %s", would, strings.Join(args, " "))
		if o.DryRun {
			return nil
		}
		return d.systemctl(ctx, args...)
	}
	// Timers first, so nothing starts the services again; a failure here
	// stops the removal so the next run can finish it.
	for _, t := range Timers {
		if ours[t] {
			if err := run("disable", "--now", t); err != nil {
				return err
			}
		}
	}
	for _, s := range []string{CheckService, ReportService} {
		if ours[s] {
			if err := run("stop", s); err != nil {
				return err
			}
		}
	}
	removed := 0
	for _, name := range UnitNames {
		if !ours[name] {
			continue
		}
		removed++
		say("%sremove %s", would, filepath.Join(unitDir, name))
		if !o.DryRun {
			if err := ud.Remove(name); err != nil {
				return failed("remove %s: %v", filepath.Join(unitDir, name), err)
			}
		}
	}
	if removed > 0 {
		if err := run("daemon-reload"); err != nil {
			return err
		}
	} else {
		say("no keepwatch unit files found, nothing to remove")
	}

	if o.Purge {
		return d.purge(o, rec, say, would)
	}
	say("configuration and state are kept; --purge removes them")
	return nil
}

// purge removes keepwatch's files from the state directory and the
// configuration directory, and each directory if nothing else is in it. It
// never removes a directory with content it does not own, never follows a link
// and never goes outside the two directories (and conf.d below the second).
// The configuration side is only for a path that is provably keepwatch's (see
// Uninstall); rec is what the installed units recorded.
func (d Deps) purge(o UninstallOptions, rec Installed, say func(string, ...any), would string) error {
	cfgPath := o.ConfigPath
	if !o.ConfigExplicit && rec.ConfigPath != "" {
		cfgPath = rec.ConfigPath
	}
	trusted := cfgPath == o.DefaultConfigPath || (rec.ConfigPath != "" && cfgPath == rec.ConfigPath)

	// The state directory: from a configuration that is keepwatch's, else from
	// what the units recorded, else not at all.
	stateDir := ""
	if trusted && o.StateDirOf != nil {
		dir, found, err := o.StateDirOf(cfgPath)
		switch {
		case err != nil:
			say("warning: the configuration %s cannot be read (%v)", cfgPath, firstLine(err.Error()))
		case found:
			stateDir = dir
		}
	}
	if stateDir == "" {
		stateDir = rec.ReadWritePaths
	}
	if stateDir == "" && trusted {
		stateDir = o.DefaultStateDir
		say("the state directory is not known from a configuration or an installed unit, purging the default %s", stateDir)
	}

	var problems []string
	var refusals []string
	if !trusted {
		m := fmt.Sprintf("%s is neither the default configuration path (%s) nor the --config of an installed keepwatch unit, so it is not provably keepwatch's: remove it and its conf.d by hand", cfgPath, o.DefaultConfigPath)
		say("left %s: %s", cfgPath, m)
		refusals = append(refusals, m)
	}
	if stateDir == "" {
		m := "no installed unit records a state directory for that configuration: remove its state by hand"
		say("left the state directory: %s", m)
		refusals = append(refusals, m)
	}
	do := func(dir, label string, owned func(name string) bool) {
		od, err := d.FS.OpenDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			say("%s does not exist, nothing to purge", dir)
			return
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		names, err := od.Names()
		if err != nil {
			od.Close()
			problems = append(problems, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		left := []string{}
		for _, n := range names {
			p := filepath.Join(dir, n)
			info, lerr := od.Lstat(n)
			if lerr != nil || !owned(n) || !info.IsRegular() {
				left = append(left, n)
				continue
			}
			say("%sremove %s", would, p)
			if !o.DryRun {
				if rerr := od.Remove(n); rerr != nil {
					problems = append(problems, fmt.Sprintf("remove %s: %v", p, rerr))
					left = append(left, n)
				}
			}
		}
		od.Close()
		if len(left) > 0 {
			say("left %s: it holds entries that are not keepwatch's own (%s)", dir, strings.Join(left, ", "))
			return
		}
		say("%sremove directory %s (%s)", would, dir, label)
		if !o.DryRun {
			if rerr := d.FS.Rmdir(dir); rerr != nil {
				problems = append(problems, fmt.Sprintf("remove directory %s: %v", dir, rerr))
			}
		}
	}
	if stateDir != "" {
		do(stateDir, "state", ownedInStateDir)
	}

	if trusted {
		cfgDir := filepath.Dir(cfgPath)
		confd := filepath.Join(cfgDir, "conf.d")
		if info, err := d.FS.Lstat(confd); err == nil {
			if info.IsDir() {
				do(confd, "drop-ins", func(n string) bool { return strings.HasSuffix(n, ".yaml") && !strings.HasPrefix(n, ".") })
			} else {
				say("left %s: not a directory", confd)
			}
		}
		mainName := filepath.Base(cfgPath)
		do(cfgDir, "configuration", func(n string) bool { return n == mainName })
	}

	if len(problems) > 0 {
		return failed("%s", strings.Join(problems, "\n"))
	}
	if len(refusals) > 0 {
		return refuse("%s", strings.Join(refusals, "; "))
	}
	return nil
}
