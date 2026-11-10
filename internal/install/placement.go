package install

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// The scheduled run is a root process in a sandbox. Every path it depends on
// must be one the sandbox shows and one that nobody but root can rename,
// replace or redirect. This file has the one list of those paths (Manifest)
// and the one check of them (CheckPlacement). install refuses when the check
// finds a problem, doctor reports the same problem with the same words, and
// neither has a second rule of its own.

// Paths are the inputs of the manifest: what the unit lines carry (Binary,
// ConfigPath) and what the configuration behind ConfigPath names (StateDir,
// TokenFile). An empty field adds no entry.
type Paths struct {
	// Binary is the program of ExecStart.
	Binary string
	// ConfigPath is the --config of ExecStart.
	ConfigPath string
	// StateDir is state_dir of that configuration, which is also
	// ReadWritePaths. Empty when the configuration did not load.
	StateDir string
	// TokenFile is notify.ntfy.token_file of that configuration. Empty when
	// there is none.
	TokenFile string
}

// Absence says what a missing path means for an entry.
type Absence int

// What a missing path means.
const (
	// MustExist: a missing path is a problem.
	MustExist Absence = iota
	// MayBeAbsent: a missing path is fine (conf.d, and state_dir, which
	// install creates). While it is missing its parent directory is checked
	// in its place: that is where it would be created, and nobody but root
	// may be able to do that. When it exists it must pass like any other.
	MayBeAbsent
)

// PathEntry is one path the scheduled run depends on.
type PathEntry struct {
	// Name says what the path is, for messages: "the configuration file".
	Name string
	Path string
	// Role says what the path is used for. The table of places the run
	// cannot use (HiddenBy) is asked with it and binds every role alike; the
	// role words what a problem does to the run.
	Role Role
	// Kind is what the path must be.
	Kind   PathKind
	Absent Absence
}

// Manifest lists every path the scheduled run depends on, in the order they
// are checked: a directory comes before what is inside it.
func Manifest(p Paths) []PathEntry {
	var m []PathEntry
	if p.Binary != "" {
		m = append(m, PathEntry{Name: "the keepwatch binary", Path: p.Binary, Role: RoleBinary, Kind: KindFile})
	}
	if p.ConfigPath != "" {
		dir := path.Dir(p.ConfigPath)
		m = append(m,
			PathEntry{Name: "the configuration directory", Path: dir, Role: RoleConfig, Kind: KindDir},
			PathEntry{Name: "the configuration file", Path: p.ConfigPath, Role: RoleConfig, Kind: KindFile},
			PathEntry{Name: "the conf.d directory", Path: path.Join(dir, "conf.d"), Role: RoleConfig, Kind: KindDir, Absent: MayBeAbsent})
	}
	if p.TokenFile != "" {
		m = append(m,
			PathEntry{Name: "the directory of notify.ntfy.token_file", Path: path.Dir(p.TokenFile), Role: RoleConfig, Kind: KindDir},
			PathEntry{Name: "notify.ntfy.token_file", Path: p.TokenFile, Role: RoleConfig, Kind: KindFile})
	}
	if p.StateDir != "" {
		m = append(m, PathEntry{Name: "state_dir", Path: p.StateDir, Role: RoleState, Kind: KindDir, Absent: MayBeAbsent})
	}
	return m
}

// PlacementProblem is one entry that the scheduled run cannot use or that
// somebody other than root can change. Exactly one of Hidden and Err is set.
type PlacementProblem struct {
	Entry PathEntry
	// Hidden: the sandbox hides the path, or it does not survive a reboot.
	Hidden *Hidden
	// Checked is the path that was walked when Err is set: the entry's path,
	// or its parent for a missing MayBeAbsent entry.
	Checked string
	// Err is what TrustedPath said about Checked.
	Err error
}

// consequence says what the problem does to the scheduled run, by role.
func (p PlacementProblem) consequence() string {
	switch p.Entry.Role {
	case RoleBinary:
		return "the scheduled run cannot start"
	case RoleState:
		return "the scheduled run fails to start"
	}
	return "the scheduled run exits 3"
}

// Error is the message of the problem. install and doctor both print exactly
// this text.
func (p PlacementProblem) Error() string {
	e := p.Entry
	switch {
	case p.Hidden != nil:
		return fmt.Sprintf("%s %s is under %s: %s: %s; put it elsewhere and run \"keepwatch install\" again", e.Name, e.Path, p.Hidden.Path, p.Hidden.Why, p.consequence())
	case IsMissing(p.Err) && p.Checked != e.Path:
		return fmt.Sprintf("%s %s does not exist and cannot be created, because its parent directory is missing too (%v): create the parent directory first, owned by root and not writable by group or other", e.Name, e.Path, p.Err)
	case IsMissing(p.Err) && e.Role == RoleBinary:
		return fmt.Sprintf("%s %s does not exist (%v): %s; install the binary there, or run \"keepwatch install\" from where it is now", e.Name, e.Path, p.Err, p.consequence())
	case IsMissing(p.Err):
		return fmt.Sprintf("%s %s does not exist (%v): %s", e.Name, e.Path, p.Err, p.consequence())
	}
	what := "cannot be trusted"
	if e.Role == RoleBinary {
		what = "cannot be trusted to run as root"
	}
	if p.Checked != e.Path {
		what = "cannot be created in a trusted place"
	}
	var fix string
	switch {
	case e.Role == RoleBinary:
		fix = "put it where only root can change it and run install from there, for example: install -o root -g root -m 0755 keepwatch /usr/local/bin/ && /usr/local/bin/keepwatch install"
	case IsSymlink(p.Err):
		fix = fmt.Sprintf("give the real path, with every symbolic link resolved (\"realpath %s\" prints it): for example /run for /var/run, /usr/bin for /bin", e.Path)
	default:
		fix = "everything from / down to it must be owned by root and not writable by group or other, or another user can rename or replace it and the scheduled run fails or reads something else"
	}
	return fmt.Sprintf("%s %s %s: %v; %s", e.Name, e.Path, what, p.Err, fix)
}

// below reports whether p is dir or lies under it.
func below(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// Blocks reports whether one of the problems is about p or about a directory
// above it, so that p itself cannot be relied on (and was not looked at).
func Blocks(problems []PlacementProblem, p string) bool {
	for _, pr := range problems {
		if below(p, pr.Entry.Path) {
			return true
		}
	}
	return false
}

// CheckPlacement checks every entry and returns the problems, in the order of
// the entries. It only looks (Lstat); it creates and changes nothing.
//
// For each entry the sandbox table comes first (HiddenBy, on the text of the
// path), because for a path such as /var/run/x "it is empty after a reboot"
// says more than "/var/run is a symbolic link". Then TrustedPath walks the path
// from "/": no component may be a symbolic link, each must be owned by root
// and not writable by group or other. That walk is also what makes the table
// right: without a link in it, the text of the path is where the kernel goes.
//
// An entry under a path that already has a problem is not reported again: it
// has that problem too, and one message per cause is enough.
func CheckPlacement(fsys FS, entries []PathEntry) []PlacementProblem {
	var out []PlacementProblem
	for _, e := range entries {
		if Blocks(out, e.Path) {
			continue
		}
		if p, bad := checkEntry(fsys, e); bad {
			out = append(out, p)
		}
	}
	return out
}

func checkEntry(fsys FS, e PathEntry) (PlacementProblem, bool) {
	if h, ok := HiddenBy(e.Path, e.Role); ok {
		return PlacementProblem{Entry: e, Hidden: &h}, true
	}
	checked, kind := e.Path, e.Kind
	if e.Absent == MayBeAbsent {
		// Only "it is not there" counts as absent; a path that cannot be
		// looked at is walked and fails there.
		if _, err := fsys.Lstat(e.Path); errors.Is(err, fs.ErrNotExist) {
			checked, kind = path.Dir(e.Path), KindDir
		}
	}
	if err := TrustedPath(fsys, checked, kind); err != nil {
		return PlacementProblem{Entry: e, Checked: checked, Err: err}, true
	}
	return PlacementProblem{}, false
}

// PlacementError joins the messages of the problems, one per line.
func PlacementError(problems []PlacementProblem) string {
	lines := make([]string, len(problems))
	for i, p := range problems {
		lines[i] = p.Error()
	}
	return strings.Join(lines, "\n")
}
