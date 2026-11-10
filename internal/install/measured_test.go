package install

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The files in test/systemd/measured say what a real sandbox does: which
// directories the installed check service does not see, which of the
// directories inside those it sees all the same, which volatile and kernel
// file systems are mounted, and which links lead into them. test/systemd/run.sh
// measures that on each supported release and fails when a file no longer
// agrees with the sandbox. This test ties the files to sandboxPaths, in both
// directions, so that the table cannot say something about the sandbox that
// was not measured, and the sandbox cannot do something the table misses.

// measuredLine is one line of a file: "hidden DIR", "visible DIR",
// "mount DIR TYPE" or "link PATH DIR".
type measuredLine struct {
	kind, path, arg string
}

func parseMeasured(t *testing.T, text string) []measuredLine {
	t.Helper()
	var out []measuredLine
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		want := map[string]int{"hidden": 2, "visible": 2, "mount": 3, "link": 3}[f[0]]
		if want == 0 || len(f) != want || !strings.HasPrefix(f[1], "/") {
			t.Fatalf("not a line of a measurement: %q", line)
		}
		l := measuredLine{kind: f[0], path: f[1]}
		if want == 3 {
			l.arg = f[2]
		}
		out = append(out, l)
	}
	return out
}

// measuredErrors compares a table with a measurement.
func measuredErrors(table []sandboxEntry, lines []measuredLine) []string {
	var errs []string
	of := func(kind string) []string {
		var out []string
		for _, l := range lines {
			if l.kind == kind {
				out = append(out, l.path)
			}
		}
		return out
	}
	under := func(p string, dirs []string) bool {
		for _, d := range dirs {
			if below(p, d) {
				return true
			}
		}
		return false
	}
	hidden, visible, mounts, links := of("hidden"), of("visible"), of("mount"), of("link")

	// From the measurement to the table: every line is a place the table
	// refuses for every role, the place itself and what is in it, and the
	// entry that refuses it says the right thing about it.
	for _, l := range lines {
		for _, role := range every {
			for _, p := range []string{l.path, l.path + "/x"} {
				h, ok := hiddenIn(table, p, role)
				switch {
				case !ok:
					errs = append(errs, l.kind+" "+l.path+": the table does not refuse "+p)
				case l.kind == "hidden" && !h.Hides:
					errs = append(errs, "hidden "+l.path+": the sandbox hides it, but the entry that refuses "+p+" ("+h.Path+") does not say so")
				case l.kind == "visible" && h.Hides:
					errs = append(errs, "visible "+l.path+": the service sees it, but the entry that refuses "+p+" ("+h.Path+") says the sandbox hides it")
				case l.kind == "link" && (h.Path != l.path || !strings.Contains(h.Why, l.path+" is "+l.arg)):
					errs = append(errs, "link "+l.path+": the entry that refuses "+p+" ("+h.Path+") does not say that "+l.path+" is "+l.arg)
				}
			}
		}
	}

	// From the table to the measurement: an entry that says the sandbox hides
	// a path needs a hidden line for it, and one that says it does not needs
	// a file system or a link that makes the place unusable all the same.
	for _, e := range table {
		for _, p := range e.paths {
			isLink := false
			for _, l := range links {
				isLink = isLink || l == p
			}
			inHidden := under(p, hidden) && !under(p, visible)
			switch {
			case e.hides && !inHidden:
				errs = append(errs, "the table says the sandbox hides "+p+", the measurement does not")
			case !e.hides && inHidden:
				errs = append(errs, "the table says the service sees "+p+", the measurement says it is hidden")
			case !e.hides && !isLink && !under(p, mounts):
				errs = append(errs, "the table refuses "+p+" as volatile or as the kernel's, but the measurement has no such file system and no link there")
			}
		}
	}
	sort.Strings(errs)
	return errs
}

func TestSandboxPathsFollowTheMeasuredSandbox(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "test", "systemd", "measured", "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if strings.Join(names, " ") != "22.04.txt 24.04.txt" {
		t.Fatalf("measurements: %v, want one for each supported release", names)
	}
	var first []measuredLine
	for _, f := range files {
		text, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := parseMeasured(t, string(text))
		if first == nil {
			first = lines
		}
		// A measurement that found nothing would agree with everything.
		counts := map[string]int{}
		for _, l := range lines {
			counts[l.kind]++
		}
		if counts["hidden"] < 4 || counts["mount"] < 3 || counts["link"] < 1 || counts["visible"] < 1 {
			t.Errorf("%s is too thin to be a measurement: %v", filepath.Base(f), counts)
		}
		for _, e := range measuredErrors(sandboxPaths, lines) {
			t.Errorf("%s: %s", filepath.Base(f), e)
		}
	}

	// The comparison notices each way the two can part. The table is right for
	// the measurement; each case breaks one of them.
	without := func(path string) []sandboxEntry {
		var out []sandboxEntry
		for _, e := range sandboxPaths {
			var keep []string
			for _, p := range e.paths {
				if p != path {
					keep = append(keep, p)
				}
			}
			if len(keep) > 0 {
				e.paths = keep
				out = append(out, e)
			}
		}
		return out
	}
	with := func(e sandboxEntry) []sandboxEntry {
		return append(append([]sandboxEntry(nil), sandboxPaths...), e)
	}
	flipped := func(path string) []sandboxEntry {
		out := without(path)
		for _, e := range sandboxPaths {
			for _, p := range e.paths {
				if p == path {
					out = append(out, sandboxEntry{e.option, !e.hides, e.why, []string{p}, e.roles})
				}
			}
		}
		return out
	}
	narrowed := func(path string) []sandboxEntry {
		out := without(path)
		for _, e := range sandboxPaths {
			for _, p := range e.paths {
				if p == path {
					out = append(out, sandboxEntry{e.option, e.hides, e.why, []string{p}, []Role{RoleState}})
				}
			}
		}
		return out
	}
	plus := func(l measuredLine) []measuredLine {
		return append(append([]measuredLine(nil), first...), l)
	}
	broken := []struct {
		name  string
		table []sandboxEntry
		lines []measuredLine
		want  string
	}{
		{"/run is no longer refused", without("/run"), first, "mount /run: the table does not refuse /run"},
		{"/run/credentials has no entry of its own", without("/run/credentials"), first, "hidden /run/credentials: the sandbox hides it, but the entry that refuses /run/credentials (/run) does not say so"},
		{"/run/systemd/incoming has no entry of its own", without("/run/systemd/incoming"), first, "hidden /run/systemd/incoming: the sandbox hides it"},
		{"/tmp is no longer refused", without("/tmp"), first, "hidden /tmp: the table does not refuse /tmp"},
		{"/sys is no longer refused", without("/sys"), first, "mount /sys: the table does not refuse /sys"},
		{"/proc is no longer refused", without("/proc"), first, "hidden /proc: the table does not refuse /proc"},
		{"/dev is no longer refused", without("/dev"), first, "hidden /dev: the table does not refuse /dev"},
		{"the module directory is no longer refused", without("/usr/lib/modules"), first, "hidden /usr/lib/modules: the table does not refuse /usr/lib/modules"},
		{"/dev/shm is refused for the reason of /dev", without("/dev/shm"), first, "visible /dev/shm: the service sees it, but the entry that refuses /dev/shm (/dev) says the sandbox hides it"},
		{"/var/run has no entry", without("/var/run"), first, "link /var/run: the table does not refuse /var/run"},
		{"/run is refused for state_dir only", narrowed("/run"), first, "mount /run: the table does not refuse /run"},
		{"/run/credentials is refused for state_dir only", narrowed("/run/credentials"), first, "hidden /run/credentials: the sandbox hides it, but the entry that refuses /run/credentials (/run) does not say so"},
		{"/var/lock is said to be something else", with(sandboxEntry{"", false, "/var/lock is /srv/lock", []string{"/var/lock/x"}, every}), plus(measuredLine{"link", "/var/lock/x", "/run/y"}), "link /var/lock/x: the entry that refuses /var/lock/x (/var/lock/x) does not say that /var/lock/x is /run/y"},
		{"the table calls /run hidden", flipped("/run"), first, "the table says the sandbox hides /run, the measurement does not"},
		{"the table calls /tmp visible", flipped("/tmp"), first, "the table says the service sees /tmp, the measurement says it is hidden"},
		{"the table calls /dev/shm hidden", flipped("/dev/shm"), first, "the table says the sandbox hides /dev/shm, the measurement does not"},
		{"the table hides a place the sandbox leaves alone", with(sandboxEntry{"", true, "w", []string{"/srv"}, every}), first, "the table says the sandbox hides /srv, the measurement does not"},
		{"the table calls a place volatile that is not", with(sandboxEntry{"", false, "w", []string{"/srv"}, every}), first, "the table refuses /srv as volatile or as the kernel's"},
		{"the sandbox hides a new place", sandboxPaths, plus(measuredLine{"hidden", "/srv", ""}), "hidden /srv: the table does not refuse /srv"},
		{"the sandbox hides a new place inside /run", sandboxPaths, plus(measuredLine{"hidden", "/run/user", ""}), "hidden /run/user: the sandbox hides it, but the entry that refuses /run/user (/run) does not say so"},
		{"a new volatile file system", sandboxPaths, plus(measuredLine{"mount", "/mnt/scratch", "tmpfs"}), "mount /mnt/scratch: the table does not refuse /mnt/scratch"},
		{"a new link into /run", sandboxPaths, plus(measuredLine{"link", "/var/spool/run", "/run/spool"}), "link /var/spool/run: the table does not refuse /var/spool/run"},
	}
	for _, c := range broken {
		errs := measuredErrors(c.table, c.lines)
		found := false
		for _, e := range errs {
			found = found || strings.Contains(e, c.want)
		}
		if !found {
			t.Errorf("%s: errors = %q, want one with %q", c.name, errs, c.want)
		}
	}
}
