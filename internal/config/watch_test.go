package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wantWatch builds the expected Watch from defaults: keys not listed
// here stay at the defaults of the section.
type wantWatch struct {
	enabled             bool
	learningPeriod      string // "" keeps the default
	sshThreshold        int    // 0 keeps the default
	sshWindow           string // "" keeps the default
	restartThreshold    int
	restartWindow       string
	queue               int
	perIncidentInterval string
	globalPerMinute     int
}

// build turns the partial expectation into the full Watch, applying the
// documented defaults to the keys it does not override.
func (w wantWatch) build(t *testing.T) Watch {
	t.Helper()
	want := defaultWatch()
	want.Enabled = w.enabled
	for _, c := range []struct {
		s   string
		dst *time.Duration
	}{
		{w.learningPeriod, &want.LearningPeriod},
		{w.sshWindow, &want.SSHBruteforce.Window},
		{w.restartWindow, &want.RestartLoop.Window},
		{w.perIncidentInterval, &want.Notify.PerIncidentInterval},
	} {
		if c.s == "" {
			continue
		}
		d, err := parseWatchDuration(c.s)
		if err != nil {
			t.Fatalf("bad test duration %q: %v", c.s, err)
		}
		*c.dst = d
	}
	if w.sshThreshold != 0 {
		want.SSHBruteforce.Threshold = w.sshThreshold
	}
	if w.restartThreshold != 0 {
		want.RestartLoop.Threshold = w.restartThreshold
	}
	if w.queue != 0 {
		want.Notify.Queue = w.queue
	}
	if w.globalPerMinute != 0 {
		want.Notify.GlobalPerMinute = w.globalPerMinute
	}
	return want
}

func checkWatch(t *testing.T, cfg *Config, w wantWatch) {
	t.Helper()
	if want := w.build(t); cfg.Watch != want {
		t.Errorf("Watch = %+v, want %+v", cfg.Watch, want)
	}
}

func TestWatchAbsentKeepsDefaults(t *testing.T) {
	// No watch key at all: the documented defaults apply and enabled
	// stays false.
	_, main := setup(t, map[string]string{"keepwatch.yaml": "state_dir: /srv/kw\n"})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkWatch(t, cfg, wantWatch{})
	if cfg.Watch.Enabled {
		t.Error("Watch.Enabled must default to false")
	}
}

func TestWatchNullSectionCountsAsAbsent(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"bare watch", "watch:\n"},
		{"explicit null", "watch: ~\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": tc.yaml})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			checkWatch(t, cfg, wantWatch{})
		})
	}
}

func TestWatchAllKeysInMain(t *testing.T) {
	// Every key set in the main file at once: each value applies.
	yaml := `watch:
  enabled: true
  learning_period: 36h
  ssh_bruteforce:
    threshold: 9
    window: 30m
  restart_loop:
    threshold: 4
    window: 2h
  notify:
    queue: 7
    per_incident_interval: 45m
    global_per_minute: 2
`
	_, main := setup(t, map[string]string{"keepwatch.yaml": yaml})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkWatch(t, cfg, wantWatch{
		enabled: true, learningPeriod: "36h",
		sshThreshold: 9, sshWindow: "30m",
		restartThreshold: 4, restartWindow: "2h",
		queue: 7, perIncidentInterval: "45m", globalPerMinute: 2,
	})
}

func TestWatchDurationForms(t *testing.T) {
	// Accepted duration forms through Load; quoting changes nothing.
	// A 1s is tested on a window (learning_period has a 1h minimum).
	for _, tc := range []struct{ in, want string }{
		{"90m", "90m"}, {"12h", "12h"}, {"7d", "168h"}, {"30d", "720h"},
		{"\"7d\"", "168h"},
	} {
		t.Run("learning_period "+tc.in, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": "watch:\n  learning_period: " + tc.in + "\n"})
			cfg, err := Load(main)
			if err != nil {
				t.Fatalf("Load(%s): %v", tc.in, err)
			}
			want, err := time.ParseDuration(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Watch.LearningPeriod != want {
				t.Errorf("LearningPeriod = %v, want %v", cfg.Watch.LearningPeriod, want)
			}
		})
	}
	t.Run("ssh_bruteforce.window 1s", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": "watch:\n  ssh_bruteforce:\n    window: 1s\n"})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.Watch.SSHBruteforce.Window != time.Second {
			t.Errorf("Window = %v, want 1s", cfg.Watch.SSHBruteforce.Window)
		}
	})
}

func TestWatchDurationGrammar(t *testing.T) {
	// The parser's grammar: one positive number without leading zeros,
	// at most five digits, and one unit of s, m, h or d, nothing else.
	// At most five digits, so the day multiplication cannot overflow.
	for _, s := range []string{
		"213504d", "106752d", "9223372036854775807d", // would overflow
		"100000d", // six digits
		"+3d", "-1d", "1d12h", "1h1h", "1.5h", "00007d",
		"0d", "0s", "0", "7", "500ms", "7D", " 7d", "7d ", "", "d",
	} {
		if d, err := parseWatchDuration(s); err == nil {
			t.Errorf("parseWatchDuration(%q) = %v, want rejection", s, d)
		}
	}
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"1s", time.Second},
		{"1m", time.Minute},
		{"1h", time.Hour},
		{"90m", 90 * time.Minute},
		{"12h", 12 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"99999s", 99999 * time.Second},
	} {
		if d, err := parseWatchDuration(tc.in); err != nil || d != tc.want {
			t.Errorf("parseWatchDuration(%q) = %v, %v, want %v", tc.in, d, err, tc.want)
		}
	}
}

func TestWatchDurationRejectedNamesFileAndLine(t *testing.T) {
	// Through config.Load: the error names the file, the line and the
	// new grammar.
	_, main := setup(t, map[string]string{"keepwatch.yaml": "watch:\n  learning_period: 1d12h\n"})
	errs := errsOf(t, main)
	want := main + `:2: watch.learning_period: "1d12h" is not a duration: want one number`
	if !containsSub(errs, want) {
		t.Errorf("errors %q lack %q", errs, want)
	}
}

func TestWatchMinimumsAccepted(t *testing.T) {
	// Exactly at the per-key minimum: a 1s window, a 1h
	// learning_period and a 1m per_incident_interval.
	_, main := setup(t, map[string]string{"keepwatch.yaml": `watch:
  learning_period: 1h
  ssh_bruteforce:
    window: 1s
  restart_loop:
    window: 1s
  notify:
    per_incident_interval: 1m
`})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkWatch(t, cfg, wantWatch{learningPeriod: "1h", sshWindow: "1s", restartWindow: "1s", perIncidentInterval: "1m"})
}

func TestWatchThresholdMaximumAccepted(t *testing.T) {
	// Exactly at the threshold maximum, for both rules.
	_, main := setup(t, map[string]string{"keepwatch.yaml": `watch:
  ssh_bruteforce:
    threshold: 10000
  restart_loop:
    threshold: 10000
`})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checkWatch(t, cfg, wantWatch{sshThreshold: 10000, restartThreshold: 10000})
}

func TestWatchConfDPrefix(t *testing.T) {
	// The key is set in the main file only, in conf.d only, and in both
	// (the later file wins); the nested mappings merge per key.
	t.Run("main only", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  enabled: true\n  learning_period: 3d\n",
			"conf.d/10-x.yaml": "host:\n  profile: web\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{enabled: true, learningPeriod: "3d"})
	})
	t.Run("conf.d only", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "host:\n  profile: web\n",
			"conf.d/10-w.yaml": "watch:\n  enabled: true\n  ssh_bruteforce:\n    threshold: 8\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{enabled: true, sshThreshold: 8})
	})
	t.Run("both set, conf.d wins", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  enabled: false\n  learning_period: 3d\n",
			"conf.d/10-w.yaml": "watch:\n  enabled: true\n  learning_period: 9d\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{enabled: true, learningPeriod: "9d"})
	})
	t.Run("mappings merge per key", func(t *testing.T) {
		// conf.d sets only the window of one rule: the threshold the
		// main file set survives, and so does the whole other rule.
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  ssh_bruteforce:\n    threshold: 9\n  restart_loop:\n    threshold: 4\n",
			"conf.d/10-w.yaml": "watch:\n  ssh_bruteforce:\n    window: 45m\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{sshThreshold: 9, sshWindow: "45m", restartThreshold: 4})
	})
	t.Run("third file wins", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  notify:\n    queue: 5\n",
			"conf.d/10-a.yaml": "watch:\n  notify:\n    queue: 6\n",
			"conf.d/20-b.yaml": "watch:\n  notify:\n    queue: 7\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{queue: 7})
	})
}

func TestWatchNullsFollowTheMergeRule(t *testing.T) {
	t.Run("bare watch in conf.d leaves main intact", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  enabled: true\n  ssh_bruteforce:\n    threshold: 9\n",
			"conf.d/10-w.yaml": "watch:\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{enabled: true, sshThreshold: 9})
	})
	t.Run("null key in conf.d leaves the main value", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  learning_period: 3d\n  ssh_bruteforce:\n    threshold: 9\n",
			"conf.d/10-w.yaml": "watch:\n  learning_period: ~\n  ssh_bruteforce:\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{learningPeriod: "3d", sshThreshold: 9})
	})
	t.Run("null in main does not block conf.d", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  learning_period:\n  ssh_bruteforce:\n",
			"conf.d/10-w.yaml": "watch:\n  learning_period: 5d\n  ssh_bruteforce:\n    threshold: 8\n",
		})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{learningPeriod: "5d", sshThreshold: 8})
	})
	t.Run("null nested keys keep their defaults", func(t *testing.T) {
		_, main := setup(t, map[string]string{"keepwatch.yaml": `watch:
  learning_period: ~
  ssh_bruteforce: ~
  restart_loop:
    threshold: ~
    window: ~
  notify:
    queue: null
    per_incident_interval: ~
    global_per_minute: ~
`})
		cfg, err := Load(main)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		checkWatch(t, cfg, wantWatch{})
	})
}

func TestWatchKindChangesBetweenFiles(t *testing.T) {
	t.Run("a sequence replaces the mapping", func(t *testing.T) {
		dir, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  enabled: true\n",
			"conf.d/10-w.yaml": "watch: [a]\n",
		})
		errs := errsOf(t, main)
		want := "watch in " + filepath.Join(dir, "conf.d/10-w.yaml") + ":1 changes the type set in " + main + ":1"
		if !containsSub(errs, want) {
			t.Errorf("errors %q lack %q", errs, want)
		}
	})
	t.Run("a scalar replaces a nested mapping", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  notify:\n    queue: 5\n",
			"conf.d/10-w.yaml": "watch:\n  notify: 3\n",
		})
		loadErrs(t, main, "watch.notify in", "changes the type set in")
	})
	t.Run("a mapping replaces a scalar duration", func(t *testing.T) {
		_, main := setup(t, map[string]string{
			"keepwatch.yaml":   "watch:\n  learning_period: 3d\n",
			"conf.d/10-w.yaml": "watch:\n  learning_period: {a: 1}\n",
		})
		loadErrs(t, main, "watch.learning_period in", "changes the type set in")
	})
}

func TestWatchNegative(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown key in watch",
			yaml: "watch:\n  enabledx: true\n",
			want: `watch: unknown key "enabledx"`,
		},
		{
			name: "unknown key in ssh_bruteforce",
			yaml: "watch:\n  ssh_bruteforce:\n    windows: 5m\n",
			want: `watch.ssh_bruteforce: unknown key "windows"`,
		},
		{
			name: "unknown key in restart_loop",
			yaml: "watch:\n  restart_loop:\n    thresholdt: 3\n",
			want: `watch.restart_loop: unknown key "thresholdt"`,
		},
		{
			name: "unknown key in watch notify",
			yaml: "watch:\n  notify:\n    queues: 5\n",
			want: `watch.notify: unknown key "queues"`,
		},
		{
			name: "watch must be a mapping",
			yaml: "watch: 5\n",
			want: "watch: expected a mapping",
		},
		{
			name: "watch must not be a list",
			yaml: "watch: [a]\n",
			want: "watch: expected a mapping",
		},
		{
			name: "rule must be a mapping",
			yaml: "watch:\n  ssh_bruteforce: 5\n",
			want: "watch.ssh_bruteforce: expected a mapping",
		},
		{
			name: "notify must be a mapping",
			yaml: "watch:\n  notify: 5\n",
			want: "watch.notify: expected a mapping",
		},
		{
			name: "enabled must be a bool",
			yaml: "watch:\n  enabled: maybe\n",
			want: "watch.enabled: expected true or false",
		},
		{
			name: "enabled is not an int",
			yaml: "watch:\n  enabled: 1\n",
			want: "watch.enabled: expected true or false",
		},
		{
			name: "threshold 0 rejected",
			yaml: "watch:\n  ssh_bruteforce:\n    threshold: 0\n",
			want: "watch.ssh_bruteforce.threshold: must be between 1 and 10000, got 0",
		},
		{
			name: "negative threshold rejected",
			yaml: "watch:\n  restart_loop:\n    threshold: -3\n",
			want: "watch.restart_loop.threshold: must be between 1 and 10000, got -3",
		},
		{
			name: "threshold above the maximum rejected",
			yaml: "watch:\n  ssh_bruteforce:\n    threshold: 10001\n",
			want: "watch.ssh_bruteforce.threshold: must be between 1 and 10000, got 10001",
		},
		{
			name: "restart_loop threshold above the maximum rejected",
			yaml: "watch:\n  restart_loop:\n    threshold: 10001\n",
			want: "watch.restart_loop.threshold: must be between 1 and 10000, got 10001",
		},
		{
			name: "threshold is not a string",
			yaml: "watch:\n  ssh_bruteforce:\n    threshold: \"5\"\n",
			want: "watch.ssh_bruteforce.threshold: expected an integer",
		},
		{
			name: "window 0 rejected",
			yaml: "watch:\n  ssh_bruteforce:\n    window: 0m\n",
			want: `watch.ssh_bruteforce.window: "0m" is not a duration`,
		},
		{
			name: "negative window rejected",
			yaml: "watch:\n  restart_loop:\n    window: -5m\n",
			want: `watch.restart_loop.window: "-5m" is not a duration`,
		},
		{
			name: "sub-second window rejected",
			yaml: "watch:\n  ssh_bruteforce:\n    window: 500ms\n",
			want: `watch.ssh_bruteforce.window: "500ms" is not a duration`,
		},
		{
			name: "window above the maximum rejected",
			yaml: "watch:\n  restart_loop:\n    window: 721h\n",
			want: "watch.restart_loop.window: must be between 1s and 720h0m0s, got 721h0m0s",
		},
		{
			name: "learning period 0 rejected",
			yaml: "watch:\n  learning_period: 0s\n",
			want: `watch.learning_period: "0s" is not a duration`,
		},
		{
			name: "learning period below the minimum rejected",
			yaml: "watch:\n  learning_period: 59m\n",
			want: "watch.learning_period: must be between 1h0m0s and 720h0m0s, got 59m0s",
		},
		{
			name: "learning period above the maximum rejected",
			yaml: "watch:\n  learning_period: 31d\n",
			want: "watch.learning_period: must be between 1h0m0s and 720h0m0s, got 744h0m0s",
		},
		{
			name: "duration must not be a bare number",
			yaml: "watch:\n  learning_period: 60\n",
			want: "watch.learning_period: expected a duration",
		},
		{
			name: "duration text rejected",
			yaml: "watch:\n  learning_period: soon\n",
			want: "watch.learning_period: \"soon\" is not a duration",
		},
		{
			name: "fractional days rejected",
			yaml: "watch:\n  learning_period: 0.5d\n",
			want: "watch.learning_period: \"0.5d\" is not a duration",
		},
		{
			name: "per_incident_interval 0 rejected",
			yaml: "watch:\n  notify:\n    per_incident_interval: 0s\n",
			want: `watch.notify.per_incident_interval: "0s" is not a duration`,
		},
		{
			name: "per_incident_interval below the minimum rejected",
			yaml: "watch:\n  notify:\n    per_incident_interval: 59s\n",
			want: "watch.notify.per_incident_interval: must be between 1m0s and 720h0m0s, got 59s",
		},
		{
			name: "queue 0 rejected",
			yaml: "watch:\n  notify:\n    queue: 0\n",
			want: "watch.notify.queue: must be between 1 and 1000, got 0",
		},
		{
			name: "queue above the bound rejected",
			yaml: "watch:\n  notify:\n    queue: 1001\n",
			want: "watch.notify.queue: must be between 1 and 1000, got 1001",
		},
		{
			name: "global_per_minute 0 rejected",
			yaml: "watch:\n  notify:\n    global_per_minute: 0\n",
			want: "watch.notify.global_per_minute: must be between 1 and 60, got 0",
		},
		{
			name: "global_per_minute above the bound rejected",
			yaml: "watch:\n  notify:\n    global_per_minute: 61\n",
			want: "watch.notify.global_per_minute: must be between 1 and 60, got 61",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, main := setup(t, map[string]string{"keepwatch.yaml": tc.yaml})
			loadErrs(t, main, tc.want)
		})
	}
}

func TestExampleWatchBlockUncommentedIsValid(t *testing.T) {
	// The commented watch block of the example, uncommented, loads and
	// yields exactly the defaults it advertises. The block runs from
	// "# watch:" to the first line that is not a comment.
	var block []string
	in := false
	for _, ln := range strings.Split(string(Example()), "\n") {
		if ln == "# watch:" {
			in = true
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(ln, "#") {
			break
		}
		block = append(block, strings.TrimPrefix(strings.TrimPrefix(ln, "#"), " "))
	}
	src := strings.Join(block, "\n")
	if !strings.Contains(src, "enabled: false") {
		t.Fatalf("the example watch block must show enabled: false, got:\n%s", src)
	}
	_, main := setup(t, map[string]string{"keepwatch.yaml": src + "\n"})
	cfg, err := Load(main)
	if err != nil {
		t.Fatalf("the uncommented example watch block must load: %v", err)
	}
	if cfg.Watch.Enabled {
		t.Error("the example watch block enables watch")
	}
	if want := defaultWatch(); cfg.Watch != want {
		t.Errorf("the uncommented example watch block = %+v, want the defaults %+v", cfg.Watch, want)
	}
}
