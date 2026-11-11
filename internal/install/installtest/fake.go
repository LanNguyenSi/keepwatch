// Package installtest has the fakes the tests of install, doctor and the
// command line share: an in-memory file system that follows the rules of
// install.FS and a runner that records what it was asked to run.
package installtest

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
)

type node struct {
	mode   fs.FileMode // type bits and permissions
	uid    int
	data   []byte
	target string // symlink target
}

// MemFS is an in-memory install.FS. Paths are absolute and clean. It records
// every mutation in Log, so a test can show that nothing was written.
type MemFS struct {
	mu    sync.Mutex
	nodes map[string]*node
	// Log lists the mutations in order: "mkdir P", "rmdir P", "write P",
	// "remove P".
	Log []string
	// FailWrite makes WriteFile of the named path fail with the error.
	FailWrite map[string]error
	// FailOpenDir makes OpenDir of the named path fail with the error.
	FailOpenDir map[string]error
	// FailMkdir makes Mkdir of the named path fail with the error.
	FailMkdir map[string]error
	// AfterMkdir runs after Mkdir created the path; a test changes the new
	// directory there, as somebody else on the host could.
	AfterMkdir func(p string)
}

// NewMemFS returns a file system with a root-owned "/", the directories /etc,
// /run, /var, /var/lib and /usr/local/bin, and a root-owned keepwatch binary in
// the last.
func NewMemFS() *MemFS {
	m := &MemFS{nodes: map[string]*node{}, FailWrite: map[string]error{}, FailOpenDir: map[string]error{}, FailMkdir: map[string]error{}}
	for _, d := range []string{"/", "/etc", "/etc/systemd", "/etc/systemd/system", "/run", "/run/systemd", "/run/systemd/system", "/var", "/var/lib", "/usr", "/usr/local", "/usr/local/bin"} {
		m.nodes[d] = &node{mode: fs.ModeDir | 0o755}
	}
	m.nodes["/usr/local/bin/keepwatch"] = &node{mode: 0o755}
	return m
}

// AddDir adds a directory with the mode and owner.
func (m *MemFS) AddDir(p string, perm fs.FileMode, uid int) {
	m.nodes[p] = &node{mode: fs.ModeDir | perm, uid: uid}
}

// AddFile adds a regular file.
func (m *MemFS) AddFile(p string, perm fs.FileMode, uid int, data string) {
	m.nodes[p] = &node{mode: perm, uid: uid, data: []byte(data)}
}

// AddSymlink adds a symbolic link.
func (m *MemFS) AddSymlink(p, target string) {
	m.nodes[p] = &node{mode: fs.ModeSymlink | 0o777, target: target}
}

// Remove drops a node without logging (test setup).
func (m *MemFS) Remove(p string) { delete(m.nodes, p) }

// Content returns the data of a regular file.
func (m *MemFS) Content(p string) (string, bool) {
	n, ok := m.nodes[p]
	if !ok || !n.mode.IsRegular() {
		return "", false
	}
	return string(n.data), true
}

// Exists reports whether the path exists (not following links).
func (m *MemFS) Exists(p string) bool { _, ok := m.nodes[p]; return ok }

// Mode returns the mode of a node.
func (m *MemFS) Mode(p string) fs.FileMode {
	if n, ok := m.nodes[p]; ok {
		return n.mode
	}
	return 0
}

func info(n *node) install.Info {
	return install.Info{Mode: n.mode, UID: n.uid, Size: int64(len(n.data))}
}

// Lstat implements install.FS.
func (m *MemFS) Lstat(p string) (install.Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[path.Clean(p)]
	if !ok {
		return install.Info{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	return info(n), nil
}

// Mkdir implements install.FS.
func (m *MemFS) Mkdir(p string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p = path.Clean(p)
	if err, ok := m.FailMkdir[p]; ok {
		return err
	}
	if _, ok := m.nodes[p]; ok {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrExist}
	}
	if par, ok := m.nodes[path.Dir(p)]; !ok || !par.mode.IsDir() {
		return &fs.PathError{Op: "mkdir", Path: p, Err: fs.ErrNotExist}
	}
	m.nodes[p] = &node{mode: fs.ModeDir | perm}
	m.Log = append(m.Log, "mkdir "+p)
	if m.AfterMkdir != nil {
		m.AfterMkdir(p)
	}
	return nil
}

// Rmdir implements install.FS.
func (m *MemFS) Rmdir(p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p = path.Clean(p)
	n, ok := m.nodes[p]
	if !ok {
		return &fs.PathError{Op: "rmdir", Path: p, Err: fs.ErrNotExist}
	}
	if !n.mode.IsDir() {
		return fmt.Errorf("%s: not a directory", p)
	}
	if len(m.children(p)) > 0 {
		return &fs.PathError{Op: "rmdir", Path: p, Err: fmt.Errorf("directory not empty")}
	}
	delete(m.nodes, p)
	m.Log = append(m.Log, "rmdir "+p)
	return nil
}

func (m *MemFS) children(p string) []string {
	var out []string
	for q := range m.nodes {
		if q != p && path.Dir(q) == p {
			out = append(out, path.Base(q))
		}
	}
	sort.Strings(out)
	return out
}

// OpenDir implements install.FS with the same refusals as the real one.
func (m *MemFS) OpenDir(p string) (install.Dir, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p = path.Clean(p)
	if err, ok := m.FailOpenDir[p]; ok {
		return nil, err
	}
	n, ok := m.nodes[p]
	if !ok {
		return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	if err := install.CheckDir(p, info(n), func(uid int) bool { return uid == 0 }); err != nil {
		return nil, err
	}
	return &memDir{m: m, path: p}, nil
}

type memDir struct {
	m    *MemFS
	path string
}

func (d *memDir) full(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return "", fmt.Errorf("invalid name %q", name)
	}
	return path.Join(d.path, name), nil
}

func (d *memDir) Close() error { return nil }

func (d *memDir) Lstat(name string) (install.Info, error) {
	p, err := d.full(name)
	if err != nil {
		return install.Info{}, err
	}
	return d.m.Lstat(p)
}

func (d *memDir) ReadFile(name string, max int64) ([]byte, error) {
	p, err := d.full(name)
	if err != nil {
		return nil, err
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	n, ok := d.m.nodes[p]
	switch {
	case !ok:
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	case n.mode&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symlink, it is not followed", p)
	case !n.mode.IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", p)
	case int64(len(n.data)) > max:
		return nil, fmt.Errorf("%s is larger than the limit %d", p, max)
	}
	return append([]byte(nil), n.data...), nil
}

func (d *memDir) WriteFile(name string, data []byte, perm fs.FileMode) error {
	p, err := d.full(name)
	if err != nil {
		return err
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if err, ok := d.m.FailWrite[p]; ok {
		return err
	}
	// Like rename(2), the new file replaces whatever is at the name, a link
	// included, and never writes through it.
	d.m.nodes[p] = &node{mode: perm, data: append([]byte(nil), data...)}
	d.m.Log = append(d.m.Log, "write "+p)
	return nil
}

func (d *memDir) Remove(name string) error {
	p, err := d.full(name)
	if err != nil {
		return err
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	if _, ok := d.m.nodes[p]; !ok {
		return &fs.PathError{Op: "remove", Path: p, Err: fs.ErrNotExist}
	}
	delete(d.m.nodes, p)
	d.m.Log = append(d.m.Log, "remove "+p)
	return nil
}

func (d *memDir) Names() ([]string, error) {
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	return d.m.children(d.path), nil
}

// Runner is an execx.Runner for tests. Handler decides the result of a run; a
// nil Handler answers every run with exit status 0 and no output.
type Runner struct {
	mu      sync.Mutex
	Calls   [][]string
	Handler func(argv []string) (execx.Result, error)
}

// Run implements execx.Runner.
func (r *Runner) Run(_ context.Context, argv []string, _ execx.Opts) (execx.Result, error) {
	r.mu.Lock()
	r.Calls = append(r.Calls, append([]string(nil), argv...))
	h := r.Handler
	r.mu.Unlock()
	if h == nil {
		return execx.Result{}, nil
	}
	return h(argv)
}

// Lines returns the recorded runs as one space-joined string each.
func (r *Runner) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.Calls))
	for i, c := range r.Calls {
		out[i] = strings.Join(c, " ")
	}
	return out
}

// Systemd answers systemctl runs like a small systemd: enable and disable
// change what "show" reports. Mutating runs are recorded in Runner.Calls.
type Systemd struct {
	Runner *Runner
	// Loaded, Enabled and Active are the units' states by name.
	Loaded, Enabled, Active map[string]bool
	// Fail makes the first argument (daemon-reload, enable, disable, stop,
	// restart, show) fail with the result.
	Fail map[string]execx.Result
	// Props overrides what show reports, by unit and property.
	Props map[string]map[string]string
}

// NewSystemd returns a Systemd and the Runner that talks to it.
func NewSystemd() *Systemd {
	s := &Systemd{Loaded: map[string]bool{}, Enabled: map[string]bool{}, Active: map[string]bool{},
		Fail: map[string]execx.Result{}, Props: map[string]map[string]string{}}
	s.Runner = &Runner{Handler: s.handle}
	return s
}

// Mutations returns the recorded runs that are not "show".
func (s *Systemd) Mutations() []string {
	var out []string
	for _, l := range s.Runner.Lines() {
		if !strings.HasPrefix(l, "systemctl show ") {
			out = append(out, l)
		}
	}
	return out
}

func (s *Systemd) handle(argv []string) (execx.Result, error) {
	if len(argv) < 2 || argv[0] != "systemctl" {
		return execx.Result{}, fmt.Errorf("%w: %v", execx.ErrNotAllowed, argv)
	}
	if r, ok := s.Fail[argv[1]]; ok {
		return r, nil
	}
	units := func() []string {
		var u []string
		for _, a := range argv[2:] {
			if !strings.HasPrefix(a, "-") {
				u = append(u, a)
			}
		}
		return u
	}
	switch argv[1] {
	case "enable":
		for _, u := range units() {
			s.Loaded[u], s.Enabled[u], s.Active[u] = true, true, true
		}
	case "disable":
		for _, u := range units() {
			s.Enabled[u], s.Active[u] = false, false
		}
	case "show":
		u := units()[0]
		var b strings.Builder
		for _, a := range argv[3:] {
			prop := strings.TrimPrefix(a, "--property=")
			v := s.prop(u, prop)
			fmt.Fprintf(&b, "%s=%s\n", prop, v)
		}
		return execx.Result{Stdout: []byte(b.String())}, nil
	}
	return execx.Result{}, nil
}

func (s *Systemd) prop(unit, prop string) string {
	if v, ok := s.Props[unit][prop]; ok {
		return v
	}
	yes := func(b bool, a, c string) string {
		if b {
			return a
		}
		return c
	}
	switch prop {
	case "LoadState":
		return yes(s.Loaded[unit], "loaded", "not-found")
	case "ActiveState":
		return yes(s.Active[unit], "active", "inactive")
	case "UnitFileState":
		return yes(s.Enabled[unit], "enabled", "disabled")
	case "Result":
		return "success"
	case "ExecMainStatus":
		return "0"
	case "FragmentPath":
		return yes(s.Loaded[unit], install.DefaultUnitDir+"/"+unit, "")
	case "NeedDaemonReload":
		return "no"
	case "ExecMainStartTimestamp":
		return "Mon 2026-01-05 08:00:00 UTC"
	}
	return ""
}
