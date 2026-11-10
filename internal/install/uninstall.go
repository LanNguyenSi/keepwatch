package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// File names keepwatch owns inside the state directory. stateFile is
// state.FileName; tempPrefix starts the name of the temporary file the state
// writer leaves behind after a crash (kept in step with package state).
const (
	stateFile  = "state.json"
	tempPrefix = ".state.json.tmp-"
)

// ProbePrefix starts the name of the file `keepwatch doctor` creates inside
// state_dir to prove it is writable; one left behind by a crash is keepwatch's
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
	// ConfigPath and StateDir are the paths Purge works on.
	ConfigPath string
	StateDir   string
}

// Uninstall stops and disables the timers, removes the unit files that carry
// the marker, and reloads systemd. A file with the name of a unit that does
// not carry the marker (or that is a link) is left alone and reported. With
// Purge it then removes keepwatch's own configuration and state files and the
// directories that are empty afterwards; see the README for the list.
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
		return d.purge(o, say, would)
	}
	say("configuration (%s) and state (%s) are kept; --purge removes them", filepath.Dir(o.ConfigPath), o.StateDir)
	return nil
}

// purge removes keepwatch's files from the state directory and the
// configuration directory, and each directory if nothing else is in it. It
// never removes a directory with content it does not own, never follows a link
// and never goes outside the two directories (and conf.d below the second).
func (d Deps) purge(o UninstallOptions, say func(string, ...any), would string) error {
	var problems []string
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
	do(o.StateDir, "state", func(n string) bool {
		return n == stateFile || strings.HasPrefix(n, tempPrefix) || strings.HasPrefix(n, ProbePrefix) || strings.HasPrefix(n, tmpWritePrefix)
	})

	cfgDir := filepath.Dir(o.ConfigPath)
	confd := filepath.Join(cfgDir, "conf.d")
	if info, err := d.FS.Lstat(confd); err == nil {
		if info.IsDir() {
			do(confd, "drop-ins", func(n string) bool { return strings.HasSuffix(n, ".yaml") && !strings.HasPrefix(n, ".") })
		} else {
			say("left %s: not a directory", confd)
		}
	}
	mainName := filepath.Base(o.ConfigPath)
	do(cfgDir, "configuration", func(n string) bool { return n == mainName })

	if len(problems) > 0 {
		return failed("%s", strings.Join(problems, "\n"))
	}
	return nil
}
