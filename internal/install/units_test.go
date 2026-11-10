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
	return Spec{Binary: "/opt/kw-1.2/bin/keepwatch", ConfigPath: "/srv/kw/main.yaml", StateDir: "/srv/kw/state", Interval: iv, Weekly: wk}
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
		"binary in /tmp":              func(s *Spec) { s.Binary = "/tmp/keepwatch" },
		"binary in /var/tmp":          func(s *Spec) { s.Binary = "/var/tmp/x/keepwatch" },
		"binary in /dev/shm":          func(s *Spec) { s.Binary = "/dev/shm/keepwatch" },
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
