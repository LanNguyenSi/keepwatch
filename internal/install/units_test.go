package install

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func defaultSpec() Spec {
	iv, _ := ParseInterval(DefaultInterval)
	wk, _ := ParseWeekly(DefaultWeeklyReport)
	return Spec{Binary: "/usr/local/bin/keepwatch", ConfigPath: "/etc/keepwatch/keepwatch.yaml", StateDir: "/var/lib/keepwatch", Interval: iv, Weekly: wk}
}

func customSpec() Spec {
	iv, _ := ParseInterval("30m")
	wk, _ := ParseWeekly("Sun 23:59")
	return Spec{Binary: "/opt/kw-1.2/bin/keepwatch", ConfigPath: "/srv/kw/main.yaml", StateDir: "/srv/kw/state", Notify: true, Interval: iv, Weekly: wk}
}

func TestRenderGolden(t *testing.T) {
	for name, spec := range map[string]Spec{"default": defaultSpec(), "custom": customSpec()} {
		files, err := Render(spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(files) != 4 {
			t.Fatalf("%s: %d files, want 4", name, len(files))
		}
		for _, f := range files {
			golden := filepath.Join("testdata", name, f.Name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, f.Content, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test -update ./internal/install)", err)
			}
			if string(want) != string(f.Content) {
				t.Errorf("%s/%s differs from %s:\n--- got ---\n%s--- want ---\n%s", name, f.Name, golden, f.Content, want)
			}
		}
	}
}

func TestRenderedFilesCarryTheMarkerAndNothingElseDoes(t *testing.T) {
	files, err := Render(defaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !HasMarker(f.Content) {
			t.Errorf("%s has no marker", f.Name)
		}
		if got := strings.Count(string(f.Content), markerPrefix); got != 1 {
			t.Errorf("%s: marker appears %d times", f.Name, got)
		}
	}
}

func TestHasMarker(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"marker line", markerLine + "\n[Unit]\n", true},
		{"marker prefix only", markerPrefix, true},
		{"empty", "", false},
		{"not first line", "[Unit]\n" + markerLine + "\n", false},
		{"preceded by a space", " " + markerLine, false},
		{"other comment", "# managed by someone else\n", false},
		{"similar", "# keepwatch-managed-unit\n", false},
	}
	for _, c := range cases {
		if got := HasMarker([]byte(c.in)); got != c.want {
			t.Errorf("%s: HasMarker = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseInterval(t *testing.T) {
	good := map[string]string{
		"5m": "5min", "30m": "30min", "90m": "90min", "1h": "1h", "6h": "6h", "24h": "24h",
		"720h": "720h", "1d": "1d", "30d": "30d",
	}
	for in, want := range good {
		got, err := ParseInterval(in)
		if err != nil || got.String() != want {
			t.Errorf("ParseInterval(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "6", "h", "m", "d", "0h", "0m", "06h", "6H", "6M", "6D", "4m", "6 h", " 6h", "6h ", "6h\n", "\n6h",
		"6h\nExecStartPre=/bin/sh -c id", "6h;ls", "6%h", "%h", "-6h", "+6h", "6.5h", "1h30m", "1h 30m", "infinity",
		"31d", "721h", "43201m", "100000m", "99999d", "٣h", "6hh", "6min", "6hour", "6s", "300s", "6h\x00", "6h\r\n",
		"$(id)", "0x10h", "1e1h",
	}
	for _, in := range bad {
		if got, err := ParseInterval(in); err == nil {
			t.Errorf("ParseInterval(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseWeekly(t *testing.T) {
	good := map[string]string{
		"Mon 08:00": "Mon *-*-* 08:00:00", "Sun 23:59": "Sun *-*-* 23:59:00", "Wed 00:00": "Wed *-*-* 00:00:00",
		"Fri 12:30": "Fri *-*-* 12:30:00", "Tue 01:05": "Tue *-*-* 01:05:00", "Thu 09:09": "Thu *-*-* 09:09:00", "Sat 18:45": "Sat *-*-* 18:45:00",
	}
	for in, want := range good {
		got, err := ParseWeekly(in)
		if err != nil || got.OnCalendar() != want {
			t.Errorf("ParseWeekly(%q) = %q, %v; want %q", in, got.OnCalendar(), err, want)
		}
	}
	bad := []string{
		"", "Mon", "08:00", "Mon 8:00", "Mon 08:0", "mon 08:00", "MON 08:00", "Monday 08:00", "Mo 08:00", "Mon  08:00", " Mon 08:00",
		"Mon 08:00 ", "Mon\t08:00", "Mon 24:00", "Mon 08:60", "Mon 99:99", "Mon 08:00\n", "Mon 08:00:00", "*-*-* 08:00", "Mon,Tue 08:00",
		"Mon..Fri 08:00", "daily", "weekly", "Mon 08:00\nExecStart=/bin/sh", "Mon 08%00", "Mon 0８:00", "Mon 08:00;id", "Mon -1:00", "Mon +8:00",
		"Mon 08.00", "Mon 8h", "2026-11-09 08:00", "Mon *-*-* 08:00:00", "Mon 08:00\x00",
	}
	for _, in := range bad {
		if got, err := ParseWeekly(in); err == nil {
			t.Errorf("ParseWeekly(%q) = %q, want an error", in, got.OnCalendar())
		}
	}
}

// Everything that reaches a unit line is checked: no value can add a line, a
// specifier or an option.
func TestSpecValidateRefusesInjection(t *testing.T) {
	bad := map[string]func(*Spec){
		"binary with newline":         func(s *Spec) { s.Binary = "/usr/bin/kw\nExecStartPre=/bin/sh" },
		"binary with space":           func(s *Spec) { s.Binary = "/usr/local/bin/keep watch" },
		"binary with percent":         func(s *Spec) { s.Binary = "/usr/local/bin/kw%n" },
		"binary with dollar":          func(s *Spec) { s.Binary = "/usr/local/bin/kw$HOME" },
		"binary with quote":           func(s *Spec) { s.Binary = `/usr/local/bin/kw"` },
		"binary with backslash":       func(s *Spec) { s.Binary = `/usr/local/bin/kw\x` },
		"binary with semicolon":       func(s *Spec) { s.Binary = "/usr/local/bin/kw;id" },
		"binary relative":             func(s *Spec) { s.Binary = "keepwatch" },
		"binary with dotdot":          func(s *Spec) { s.Binary = "/usr/local/../bin/keepwatch" },
		"binary empty":                func(s *Spec) { s.Binary = "" },
		"binary non-ascii":            func(s *Spec) { s.Binary = "/usr/local/bin/k\u00e9ep" },
		"binary trailing slash":       func(s *Spec) { s.Binary = "/usr/local/bin/keepwatch/" },
		"config with newline":         func(s *Spec) { s.ConfigPath = "/etc/kw.yaml\n[Install]" },
		"config with percent":         func(s *Spec) { s.ConfigPath = "/etc/%H.yaml" },
		"config with space":           func(s *Spec) { s.ConfigPath = "/etc/kw dir/kw.yaml" },
		"config relative":             func(s *Spec) { s.ConfigPath = "kw.yaml" },
		"state_dir with newline":      func(s *Spec) { s.StateDir = "/var/lib/kw\nReadWritePaths=/" },
		"state_dir with space":        func(s *Spec) { s.StateDir = "/var/lib/kw /etc" },
		"state_dir with percent":      func(s *Spec) { s.StateDir = "/var/lib/%u" },
		"state_dir is root":           func(s *Spec) { s.StateDir = "/" },
		"state_dir relative":          func(s *Spec) { s.StateDir = "var/lib/kw" },
		"state_dir with dotdot":       func(s *Spec) { s.StateDir = "/var/lib/kw/../../etc" },
		"state_dir with colon":        func(s *Spec) { s.StateDir = "/var/lib/kw:/etc" },
		"state_dir with dash prefix":  func(s *Spec) { s.StateDir = "-/var/lib/kw" },
		"state_dir with double slash": func(s *Spec) { s.StateDir = "/var//lib/kw" },
		"interval unset":              func(s *Spec) { s.Interval = Interval{} },
		"weekly unset":                func(s *Spec) { s.Weekly = Weekly{} },
	}
	for name, mutate := range bad {
		s := defaultSpec()
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, s)
		}
		if files, err := Render(s); err == nil {
			t.Errorf("%s: Render produced %d files for %+v", name, len(files), s)
		}
	}
	if err := defaultSpec().Validate(); err != nil {
		t.Errorf("default spec: %v", err)
	}
	if err := customSpec().Validate(); err != nil {
		t.Errorf("custom spec: %v", err)
	}
}

// The services have one ExecStart, one ReadWritePaths and no specifier
// character, whatever the (valid) values are.
func TestRenderLineStructure(t *testing.T) {
	files, err := Render(customSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		body := strings.ReplaceAll(string(f.Content), "CPUQuota=50%", "") // a percentage, not a specifier
		if strings.Contains(body, "%") {
			t.Errorf("%s contains a %% specifier character", f.Name)
		}
		if !strings.HasSuffix(f.Name, ".service") {
			continue
		}
		for _, key := range []string{"\nExecStart=", "\nReadWritePaths=", "\n[Service]\n", "\nType=oneshot\n"} {
			if got := strings.Count(string(f.Content), key); got != 1 {
				t.Errorf("%s: %q appears %d times, want 1", f.Name, strings.TrimSpace(key), got)
			}
		}
	}
}

func TestInspect(t *testing.T) {
	files, err := Render(customSpec())
	if err != nil {
		t.Fatal(err)
	}
	got := Inspect(files[0].Content)
	if got.ReadWritePaths != "/srv/kw/state" || got.ConfigPath != "/srv/kw/main.yaml" {
		t.Errorf("Inspect = %+v", got)
	}
	if (Inspect([]byte("garbage")) != Installed{}) {
		t.Errorf("Inspect(garbage) should be empty")
	}
}

func TestHiddenBy(t *testing.T) {
	type c struct {
		path string
		role Role
		want string // the hiding path; empty means allowed
	}
	cases := []c{
		{"/tmp/x", RoleBinary, "/tmp"}, {"/tmp/x", RoleConfig, "/tmp"}, {"/tmp/x", RoleState, "/tmp"},
		{"/tmp", RoleState, "/tmp"}, {"/var/tmp/a/b", RoleConfig, "/var/tmp"}, {"/var/tmp", RoleBinary, "/var/tmp"},
		{"/dev/kw", RoleState, "/dev"}, {"/dev/shm/kw", RoleBinary, "/dev"},
		{"/run/kw", RoleState, "/run"}, {"/var/run/kw", RoleState, "/var/run"}, {"/dev/shm/kw", RoleState, "/dev"},
		{"/var/lock/kw", RoleState, "/var/lock"}, {"/var/lock", RoleState, "/var/lock"}, {"/var/lock/kw.yaml", RoleConfig, ""},
		{"/usr/lib/modules/kw", RoleBinary, "/usr/lib/modules"}, {"/usr/lib/modules/kw.yaml", RoleConfig, "/usr/lib/modules"},
		{"/lib/modules/kw", RoleState, "/lib/modules"}, {"/usr/lib/keepwatch", RoleState, ""},
		// /run holds a binary or a configuration file without trouble.
		{"/run/kw/keepwatch", RoleBinary, ""}, {"/run/kw/kw.yaml", RoleConfig, ""},
		// Names that only start like a hidden path.
		{"/tmpfiles/x", RoleState, ""}, {"/var/tmpx", RoleState, ""}, {"/runner/x", RoleState, ""}, {"/devices", RoleBinary, ""},
		{"/var/lib/keepwatch", RoleState, ""}, {"/etc/keepwatch/keepwatch.yaml", RoleConfig, ""}, {"/usr/local/bin/keepwatch", RoleBinary, ""},
	}
	for _, c := range cases {
		h, ok := HiddenBy(c.path, c.role)
		if ok != (c.want != "") || h.Path != c.want {
			t.Errorf("HiddenBy(%q, %v) = %+v, %v; want %q", c.path, c.role, h, ok, c.want)
		}
		if ok && (h.Option == "" || h.Why == "") {
			t.Errorf("HiddenBy(%q) names no option or reason: %+v", c.path, h)
		}
	}
}

// optionClass says whether one option of the hardening takes paths away from
// the service (or makes them unreliable), and why.
type optionClass struct {
	// value is the value the judgement was made for; another value must be
	// judged again. Empty means the value does not matter.
	value string
	// hides: the option hides paths, so sandboxPaths needs an entry for it.
	hides bool
	why   string
}

// hardeningClasses classifies every option of serviceHardening. A new option,
// or a new value of one that is listed with its value, fails
// TestSandboxPathsFollowTheHardening until it is judged here.
var hardeningClasses = map[string]optionClass{
	"PrivateTmp":           {"yes", true, "an own, empty /tmp and /var/tmp"},
	"PrivateDevices":       {"yes", true, "an own /dev with only the pseudo devices"},
	"ProtectKernelModules": {"yes", true, "/usr/lib/modules is made inaccessible"},
	"ReadWritePaths":       {"{{state}}", true, "the directory must exist when the service starts, so it cannot lie where a reboot empties it"},

	"ProtectSystem":           {"strict", false, "read-only, everything stays visible; the one writable path is ReadWritePaths"},
	"ProtectHome":             {"read-only", false, "read-only: /home, /root and /run/user stay visible (yes or tmpfs would hide them)"},
	"ProtectKernelTunables":   {"yes", false, "/proc/sys, /sys and some files of /proc become read-only and stay visible; nothing can be created in a kernel file system anyway"},
	"ProtectKernelLogs":       {"yes", false, "/proc/kmsg and /dev/kmsg: two kernel files, no directory a path could lie under"},
	"ProtectControlGroups":    {"yes", false, "/sys/fs/cgroup becomes read-only and stays visible"},
	"ProtectClock":            {"yes", false, "device access to the clock, no path of the file system"},
	"ProtectHostname":         {"yes", false, "a UTS namespace, no path"},
	"SuccessExitStatus":       {"", false, "an exit status"},
	"UMask":                   {"", false, "the mode of new files"},
	"NoNewPrivileges":         {"yes", false, "no path"},
	"LockPersonality":         {"yes", false, "no path"},
	"MemoryDenyWriteExecute":  {"yes", false, "no path"},
	"RestrictRealtime":        {"yes", false, "no path"},
	"RestrictSUIDSGID":        {"yes", false, "no path"},
	"RestrictNamespaces":      {"yes", false, "no path"},
	"RemoveIPC":               {"yes", false, "System V and POSIX IPC objects, no path"},
	"SystemCallArchitectures": {"", false, "no path"},
	"RestrictAddressFamilies": {"", false, "socket families"},
	"MemoryMax":               {"", false, "a resource limit"},
	"Environment":             {"", false, "an environment variable"},
	"CPUQuota":                {"", false, "a resource limit"},
	"TimeoutStartSec":         {"", false, "a time limit"},
}

// couplingErrors checks the hardening text against the table of hidden paths
// in both directions, with the classification in between.
func couplingErrors(hardening string, table []sandboxEntry, classes map[string]optionClass) []string {
	var errs []string
	set := map[string]bool{}  // option lines of the hardening
	seen := map[string]bool{} // option names of the hardening
	for _, line := range strings.Split(hardening, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			errs = append(errs, "not an option line: "+line)
			continue
		}
		set[line], seen[name] = true, true
		c, known := classes[name]
		switch {
		case !known:
			errs = append(errs, "unclassified option "+line+": say in hardeningClasses whether it hides paths")
			continue
		case c.value != "" && c.value != value:
			errs = append(errs, "option "+line+" was classified for the value "+c.value+": judge the new value")
			continue
		}
		if c.hides {
			found := false
			for _, e := range table {
				found = found || e.option == line
			}
			if !found {
				errs = append(errs, "option "+line+" hides paths but sandboxPaths has no entry for it")
			}
		}
	}
	for name := range classes {
		if !seen[name] {
			errs = append(errs, "hardeningClasses names "+name+", which the hardening does not set")
		}
	}
	for _, e := range table {
		name, _, _ := strings.Cut(e.option, "=")
		switch {
		case !set[e.option]:
			errs = append(errs, "sandboxPaths names "+e.option+", which the hardening does not set")
		case !classes[name].hides:
			errs = append(errs, "sandboxPaths names "+e.option+", which is classified as not hiding paths")
		case len(e.paths) == 0 || len(e.roles) == 0 || e.why == "":
			errs = append(errs, "the sandboxPaths entry of "+e.option+" has no path, no role or no reason")
		}
	}
	return errs
}

// The table of hidden paths and the hardening options are tied in both
// directions: every option is classified as hiding paths or not, an option
// that hides paths has an entry in the table, and every entry of the table
// names an option that is set and that hides paths. So an option cannot be
// added, changed or removed without this table being looked at again.
func TestSandboxPathsFollowTheHardening(t *testing.T) {
	for _, e := range couplingErrors(serviceHardening, sandboxPaths, hardeningClasses) {
		t.Error(e)
	}
	with := func(extra ...sandboxEntry) []sandboxEntry {
		return append(append([]sandboxEntry(nil), sandboxPaths...), extra...)
	}
	without := func(option string) []sandboxEntry {
		var out []sandboxEntry
		for _, e := range sandboxPaths {
			if e.option != option {
				out = append(out, e)
			}
		}
		return out
	}
	all := []Role{RoleBinary, RoleConfig, RoleState}
	broken := []struct {
		name      string
		hardening string
		table     []sandboxEntry
		want      string
	}{
		{"a new option nobody classified", serviceHardening + "InaccessiblePaths=/srv\n", sandboxPaths, "unclassified option InaccessiblePaths=/srv"},
		{"a new option that hides a temporary file system", serviceHardening + "TemporaryFileSystem=/var\n", sandboxPaths, "unclassified option TemporaryFileSystem=/var"},
		{"a classified option with a new value", strings.Replace(serviceHardening, "ProtectHome=read-only", "ProtectHome=yes", 1), sandboxPaths, "option ProtectHome=yes was classified for the value read-only"},
		{"a hiding option without an entry", serviceHardening, without("PrivateDevices=yes"), "option PrivateDevices=yes hides paths but sandboxPaths has no entry"},
		{"the state entry is gone", serviceHardening, without("ReadWritePaths={{state}}"), "option ReadWritePaths={{state}} hides paths but sandboxPaths has no entry"},
		{"an option was removed, its entry stayed", strings.Replace(serviceHardening, "PrivateTmp=yes\n", "", 1), sandboxPaths, "sandboxPaths names PrivateTmp=yes, which the hardening does not set"},
		{"an option was removed, its classification stayed", strings.Replace(serviceHardening, "RemoveIPC=yes\n", "", 1), sandboxPaths, "hardeningClasses names RemoveIPC, which the hardening does not set"},
		{"an entry for an option that is not set", serviceHardening, with(sandboxEntry{"PrivateUsers=yes", "w", []string{"/x"}, all}), "sandboxPaths names PrivateUsers=yes, which the hardening does not set"},
		{"an entry for an option that does not hide", serviceHardening, with(sandboxEntry{"ProtectHome=read-only", "w", []string{"/home"}, all}), "sandboxPaths names ProtectHome=read-only, which is classified as not hiding paths"},
		{"an entry without a path", serviceHardening, append(without("PrivateTmp=yes"), sandboxEntry{"PrivateTmp=yes", "w", nil, all}), "the sandboxPaths entry of PrivateTmp=yes has no path"},
		{"an entry without a role", serviceHardening, append(without("PrivateTmp=yes"), sandboxEntry{"PrivateTmp=yes", "w", []string{"/tmp"}, nil}), "the sandboxPaths entry of PrivateTmp=yes has no path"},
		{"an entry without a reason", serviceHardening, append(without("PrivateTmp=yes"), sandboxEntry{"PrivateTmp=yes", "", []string{"/tmp"}, all}), "the sandboxPaths entry of PrivateTmp=yes has no path"},
		{"a line that is no option", serviceHardening + "PrivateTmp\n", sandboxPaths, "not an option line: PrivateTmp"},
	}
	for _, c := range broken {
		errs := couplingErrors(c.hardening, c.table, hardeningClasses)
		found := false
		for _, e := range errs {
			found = found || strings.Contains(e, c.want)
		}
		if !found {
			t.Errorf("%s: errors = %q, want one with %q", c.name, errs, c.want)
		}
	}
	// What is rendered is what was classified: every option line of a service
	// file is a line of serviceHardening (with state_dir filled in), plus the
	// two lines Render adds itself.
	files, err := Render(defaultSpec())
	if err != nil {
		t.Fatal(err)
	}
	_, service, _ := strings.Cut(string(files[0].Content), "[Service]\n")
	for _, line := range strings.Split(service, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Type=") || strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		if !strings.Contains(serviceHardening, "\n"+strings.Replace(line, defaultSpec().StateDir, "{{state}}", 1)+"\n") {
			t.Errorf("the service has the line %q, which is not in serviceHardening", line)
		}
	}
}

// Validate is the grammar of the unit lines and nothing else: a path the
// sandbox hides has a valid grammar, and it is the placement check, on the
// manifest of the same spec, that refuses it. The check that used to sit in
// Validate did not go away, it moved.
func TestValidateLeavesWhatTheSandboxHidesToThePlacementCheck(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"binary in /tmp":        func(s *Spec) { s.Binary = "/tmp/keepwatch" },
		"binary in /dev":        func(s *Spec) { s.Binary = "/dev/shm/keepwatch" },
		"config in /tmp":        func(s *Spec) { s.ConfigPath = "/tmp/kwc/keepwatch.yaml" },
		"config in /var/tmp":    func(s *Spec) { s.ConfigPath = "/var/tmp/kw.yaml" },
		"state_dir in /tmp":     func(s *Spec) { s.StateDir = "/tmp/kwstate" },
		"state_dir in /run":     func(s *Spec) { s.StateDir = "/run/keepwatch" },
		"state_dir in /dev/shm": func(s *Spec) { s.StateDir = "/dev/shm/keepwatch" },
	} {
		s := defaultSpec()
		mutate(&s)
		if err := s.Validate(); err != nil {
			t.Errorf("%s: Validate judged the placement: %v", name, err)
		}
		hidden := 0
		for _, e := range Manifest(Paths{Binary: s.Binary, ConfigPath: s.ConfigPath, StateDir: s.StateDir}) {
			if _, ok := HiddenBy(e.Path, e.Role); ok {
				hidden++
			}
		}
		if hidden == 0 {
			t.Errorf("%s: no entry of the manifest is hidden", name)
		}
	}
	hidden := 0
	d := defaultSpec()
	for _, e := range Manifest(Paths{Binary: d.Binary, ConfigPath: "/run/kw/kw.yaml", StateDir: d.StateDir}) {
		if _, ok := HiddenBy(e.Path, e.Role); ok {
			hidden++
		}
	}
	if hidden != 0 {
		t.Errorf("a configuration file below /run: %d entries hidden", hidden)
	}
}

// A path of 1024 bytes is the longest that goes into a unit; one more is not.
func TestSpecValidateBoundsThePathLength(t *testing.T) {
	long := func(n int) string { return "/" + strings.Repeat("a", n-1) }
	s := defaultSpec()
	s.ConfigPath = long(1024)
	if err := s.Validate(); err != nil {
		t.Errorf("a 1024-byte path: %v", err)
	}
	s.ConfigPath = long(1025)
	if err := s.Validate(); err == nil {
		t.Error("a 1025-byte path was accepted")
	}
}

// --notify is in both services exactly when the spec notifies, and Inspect
// reads it back.
func TestRenderNotifyFlag(t *testing.T) {
	for _, notify := range []bool{false, true} {
		s := defaultSpec()
		s.Notify = notify
		files, err := Render(s)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			body := string(f.Content)
			if !strings.HasSuffix(f.Name, ".service") {
				if strings.Contains(body, "--notify") {
					t.Errorf("%s (notify=%v): a timer mentions --notify", f.Name, notify)
				}
				continue
			}
			want := "--notify"
			line := ""
			for _, l := range strings.Split(body, "\n") {
				if strings.HasPrefix(l, "ExecStart=") {
					line = l
				}
			}
			if strings.Contains(line, want) != notify {
				t.Errorf("%s (notify=%v): %s", f.Name, notify, line)
			}
			if Inspect(f.Content).Notify != notify {
				t.Errorf("%s (notify=%v): Inspect says %v", f.Name, notify, Inspect(f.Content).Notify)
			}
			if got := Inspect(f.Content).ConfigPath; got != s.ConfigPath {
				t.Errorf("%s: --config read back as %q", f.Name, got)
			}
		}
	}
	s := defaultSpec()
	s.Notify = true
	files, _ := Render(s)
	for want, i := range map[string]int{
		"ExecStart=/usr/local/bin/keepwatch check --notify --config /etc/keepwatch/keepwatch.yaml\n":           0,
		"ExecStart=/usr/local/bin/keepwatch report --weekly --notify --config /etc/keepwatch/keepwatch.yaml\n": 1,
	} {
		if !strings.Contains(string(files[i].Content), want) {
			t.Errorf("%s lacks %q", files[i].Name, want)
		}
	}
}
