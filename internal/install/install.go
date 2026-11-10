package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
)

// Modes of the directories install creates.
const (
	ConfigDirMode fs.FileMode = 0o750
	StateDirMode  fs.FileMode = 0o700
	unitFileMode  fs.FileMode = 0o644
)

// maxUnitSize bounds a unit file that is read: a larger file cannot be ours.
const maxUnitSize = 64 << 10

// systemdRunDir exists when systemd is the init system that booted the host
// (the check sd_booted() makes).
const systemdRunDir = "/run/systemd/system"

// Error kinds, mapped to exit codes by the caller.
var (
	// ErrRefused: the request cannot be carried out as given (not root, a
	// file that is not keepwatch's, a value that does not validate). Nothing
	// was changed. Exit code 2.
	ErrRefused = errors.New("refused")
	// ErrFailed: a step failed after the work started. What was done is
	// reported and a second run continues. Exit code 1.
	ErrFailed = errors.New("failed")
)

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

func failed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFailed, fmt.Sprintf(format, a...))
}

// Deps are the things install and uninstall need from the outside.
type Deps struct {
	FS FS
	// Runner runs systemctl (and nothing else).
	Runner execx.Runner
	// Geteuid returns the effective user id.
	Geteuid func() int
	// UnitDir is where the units live; empty means DefaultUnitDir.
	UnitDir string
	// SystemdRunDir overrides systemdRunDir in tests.
	SystemdRunDir string
	// Out receives the report of what was done or would be done.
	Out io.Writer
}

func (d Deps) unitDir() string {
	if d.UnitDir == "" {
		return DefaultUnitDir
	}
	return d.UnitDir
}

func (d Deps) runDir() string {
	if d.SystemdRunDir == "" {
		return systemdRunDir
	}
	return d.SystemdRunDir
}

// InstallOptions are the inputs of Install.
type InstallOptions struct {
	Spec   Spec
	DryRun bool
	// ConfigFound is false when the configuration file does not exist; install
	// then warns that the service has nothing to read yet.
	ConfigFound bool
}

type fileAction struct {
	file   File
	action string // "create", "update" or "unchanged"
}

type dirAction struct {
	path string
	mode fs.FileMode
	make bool
}

// Install writes the directories and the four unit files and enables the
// timers. With DryRun nothing is written or run, except for read-only queries
// of systemd. It is idempotent: a second run changes nothing and says so.
func Install(ctx context.Context, d Deps, o InstallOptions) error {
	files, err := Render(o.Spec)
	if err != nil {
		return refuse("%v", err)
	}
	say := func(format string, a ...any) { fmt.Fprintf(d.Out, format+"\n", a...) }
	would := ""
	if o.DryRun {
		would = "would "
	}
	if !o.DryRun && d.Geteuid() != 0 {
		return refuse("install writes below /etc and runs systemctl, run it as root (or use --dry-run or --print)")
	}
	booted := false
	if i, err := d.FS.Lstat(d.runDir()); err == nil && i.IsDir() {
		booted = true
	}
	if !booted {
		if !o.DryRun {
			return refuse("systemd is not running on this host (%s is missing), the units would never start", d.runDir())
		}
		say("note: systemd is not running on this host (%s is missing); a real install would stop here", d.runDir())
	}

	// Plan everything before the first write, so a conflict leaves the host
	// as it was.
	var dirs []dirAction
	for _, want := range []dirAction{
		{path: filepath.Dir(o.Spec.ConfigPath), mode: ConfigDirMode},
		{path: o.Spec.StateDir, mode: StateDirMode},
	} {
		_, err := d.FS.Lstat(want.path)
		switch {
		case err == nil:
			// Opening checks it the way the loaders will.
			dir, derr := d.FS.OpenDir(want.path)
			if derr != nil {
				return refuse("%v", derr)
			}
			dir.Close()
		case errors.Is(err, fs.ErrNotExist):
			want.make = true
			parent := filepath.Dir(want.path)
			if pi, perr := d.FS.Lstat(parent); perr != nil || !pi.IsDir() {
				return refuse("%s: the parent directory %s does not exist", want.path, parent)
			}
		default:
			return refuse("%s: %v", want.path, err)
		}
		dirs = append(dirs, want)
	}

	unitDir := d.unitDir()
	ud, err := d.FS.OpenDir(unitDir)
	if err != nil {
		return refuse("unit directory: %v", err)
	}
	defer ud.Close()
	var plan []fileAction
	var conflicts []string
	for _, f := range files {
		a, cerr := classify(ud, unitDir, f)
		if cerr != nil {
			conflicts = append(conflicts, cerr.Error())
			continue
		}
		plan = append(plan, fileAction{file: f, action: a})
	}
	if len(conflicts) > 0 {
		return refuse("%s", strings.Join(conflicts, "\n"))
	}

	changed := false
	if !o.ConfigFound {
		say("warning: %s does not exist; create it with \"keepwatch init\" before the first run", o.Spec.ConfigPath)
	}
	for _, da := range dirs {
		if !da.make {
			continue
		}
		changed = true
		say("%screate directory %s (mode %04o)", would, da.path, da.mode)
		if !o.DryRun {
			if err := d.FS.Mkdir(da.path, da.mode); err != nil {
				return failed("create %s: %v", da.path, err)
			}
		}
	}
	// The state directory must be usable by the services as it now is.
	if !o.DryRun {
		for _, da := range dirs {
			dir, err := d.FS.OpenDir(da.path)
			if err != nil {
				return failed("%v", err)
			}
			dir.Close()
		}
	}
	updatedTimers := map[string]bool{}
	for _, pa := range plan {
		name := filepath.Join(unitDir, pa.file.Name)
		if pa.action == "unchanged" {
			say("unchanged %s", name)
			continue
		}
		changed = true
		say("%s%s %s", would, pa.action, name)
		if !o.DryRun {
			if err := ud.WriteFile(pa.file.Name, pa.file.Content, unitFileMode); err != nil {
				return failed("write %s: %v", name, err)
			}
		}
		if pa.action == "update" && strings.HasSuffix(pa.file.Name, ".timer") {
			updatedTimers[pa.file.Name] = true
		}
	}

	run := func(args ...string) error {
		say("%srun systemctl %s", would, strings.Join(args, " "))
		if o.DryRun {
			return nil
		}
		return d.systemctl(ctx, args...)
	}
	if changed {
		if err := run("daemon-reload"); err != nil {
			return err
		}
		if err := run(append([]string{"enable", "--now"}, Timers...)...); err != nil {
			return err
		}
		for _, t := range Timers {
			if updatedTimers[t] {
				// A running timer keeps its old schedule until it is restarted.
				if err := run("restart", t); err != nil {
					return err
				}
			}
		}
		if o.DryRun {
			say("dry run: nothing was written or run")
		} else {
			say("installed: the check runs every %s, the weekly report on %s", o.Spec.Interval, o.Spec.Weekly.OnCalendar())
		}
		return nil
	}

	// Nothing to write: make sure the timers are enabled and running anyway.
	ok := true
	for _, t := range Timers {
		st, err := d.QueryTimer(ctx, t)
		if err != nil || !st.Enabled() || !st.Active() {
			ok = false
		}
	}
	if ok {
		say("already installed, nothing to change")
		return nil
	}
	if err := run(append([]string{"enable", "--now"}, Timers...)...); err != nil {
		return err
	}
	say("the unit files were up to date; the timers were enabled and started")
	return nil
}

// classify decides what writing f would do: "create", "update" (the file is
// keepwatch's and differs) or "unchanged"; any other state of the target is
// an error that names the file.
func classify(ud Dir, unitDir string, f File) (string, error) {
	p := filepath.Join(unitDir, f.Name)
	info, err := ud.Lstat(f.Name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "create", nil
	case err != nil:
		return "", fmt.Errorf("%s: %v", p, err)
	case info.IsSymlink():
		return "", fmt.Errorf("%s is a symlink, refusing to write through it", p)
	case !info.IsRegular():
		return "", fmt.Errorf("%s exists and is not a regular file, refusing to replace it", p)
	}
	cur, err := ud.ReadFile(f.Name, maxUnitSize)
	if err != nil {
		return "", fmt.Errorf("%s: %v", p, err)
	}
	if !HasMarker(cur) {
		return "", fmt.Errorf("%s exists and was not written by keepwatch (no marker comment), refusing to overwrite it; move it away or remove it first", p)
	}
	if string(cur) == string(f.Content) {
		return "unchanged", nil
	}
	return "update", nil
}

// systemctl runs systemctl with args. A start failure, a signal or a status
// other than 0 is an ErrFailed that quotes stderr.
func (d Deps) systemctl(ctx context.Context, args ...string) error {
	res, err := d.Runner.Run(ctx, append([]string{"systemctl"}, args...), execx.Opts{})
	if err != nil {
		return failed("systemctl %s: %v", strings.Join(args, " "), err)
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		return failed("systemctl %s exited with status %d: %s", strings.Join(args, " "), res.ExitCode, firstLine(msg))
	}
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	if len(line) > 300 {
		line = line[:300] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return '?'
		}
		return r
	}, line)
}

// TimerState is what systemd says about one timer.
type TimerState struct {
	LoadState     string
	ActiveState   string
	UnitFileState string
}

// Enabled reports whether the timer is enabled.
func (s TimerState) Enabled() bool { return s.UnitFileState == "enabled" }

// Active reports whether the timer is active (waiting for its next run).
func (s TimerState) Active() bool { return s.ActiveState == "active" }

// QueryTimer asks systemd (read-only) about a timer unit.
func (d Deps) QueryTimer(ctx context.Context, unit string) (TimerState, error) {
	v, err := Show(ctx, d.Runner, unit, "LoadState", "ActiveState", "UnitFileState")
	if err != nil {
		return TimerState{}, err
	}
	return TimerState{LoadState: v["LoadState"], ActiveState: v["ActiveState"], UnitFileState: v["UnitFileState"]}, nil
}

// Show runs "systemctl show <unit> --property=..." (read-only) and returns the
// values by property name.
func Show(ctx context.Context, r execx.Runner, unit string, props ...string) (map[string]string, error) {
	argv := []string{"systemctl", "show", unit}
	for _, p := range props {
		argv = append(argv, "--property="+p)
	}
	res, err := r.Run(ctx, argv, execx.Opts{})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("systemctl show %s exited with status %d: %s", unit, res.ExitCode, firstLine(string(res.Stderr)))
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out, nil
}
