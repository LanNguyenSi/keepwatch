package doctor_test

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/config"
	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/install"
)

const otherCfg = "/srv/kw/main.yaml"

func unitFile(name string) string { return install.DefaultUnitDir + "/" + name }

// editUnit replaces text in an installed unit file, as a hand edit would.
func editUnit(r *rig, name, old, new string) {
	c, _ := r.fs.Content(unitFile(name))
	r.fs.AddFile(unitFile(name), 0o644, 0, strings.ReplaceAll(c, old, new))
}

// withOtherConfig adds /srv/kw/main.yaml with its own state directory to the
// host and makes the named services run with it.
func withOtherConfig(r *rig, services ...string) *config.Config {
	r.fs.AddDir("/srv", 0o755, 0)
	r.fs.AddDir("/srv/kw", 0o750, 0)
	r.fs.AddFile(otherCfg, 0o640, 0, "{}\n")
	r.fs.AddDir("/srv/kw/state", 0o700, 0)
	c := &config.Config{Sources: config.Sources{Main: otherCfg}, StateDir: "/srv/kw/state", Checks: map[string]config.Check{},
		Notify: config.Notify{Ntfy: &config.Ntfy{URL: "https://ntfy.example.org", Topic: "t"}}}
	r.cfgs[otherCfg] = c
	for _, s := range services {
		editUnit(r, s, "--config "+cfgPath, "--config "+otherCfg)
		editUnit(r, s, "ReadWritePaths="+stateDir, "ReadWritePaths=/srv/kw/state")
	}
	return c
}

var bothServices = []string{install.CheckService, install.ReportService}

// The defect this closes: the installed units run with a configuration that is
// not valid, so every scheduled run exits 3, while the file at the default
// path is fine. doctor without --config looked at the default path and said
// "no problems". It examines what the units run with.
func TestDoctorJudgesTheConfigurationOfTheInstalledUnits(t *testing.T) {
	r := newRig(t)
	withOtherConfig(r, bothServices...)
	r.cfgErrs[otherCfg] = config.Errors{{File: otherCfg, Line: 1, Msg: `unknown key "nonsense"`}}
	rep := r.run()
	if !has(rep, doctor.Problem, "config", otherCfg+":1", "nonsense") {
		t.Errorf("the invalid configuration of the units is not a problem:\n%s", dump(rep))
	}
	if rep.ConfigPath != otherCfg {
		t.Errorf("examined %q, want the file of the units", rep.ConfigPath)
	}
	if !reflect.DeepEqual(r.loaded, []string{otherCfg}) {
		t.Errorf("loaded %v, want only the file of the units", r.loaded)
	}
	// Valid, it is the file every area is about, and nothing is left to say.
	delete(r.cfgErrs, otherCfg)
	rep = r.run()
	if rep.Problems() != 0 || rep.Warnings() != 0 || !strings.Contains(dump(rep), "config: "+otherCfg+" is valid") || !strings.Contains(dump(rep), "state_dir /srv/kw/state is writable") {
		t.Errorf("a healthy host with a custom configuration:\n%s", dump(rep))
	}
}

func TestDoctorConfigurationChoice(t *testing.T) {
	t.Run("no unit installed: the default path", func(t *testing.T) {
		r := newRig(t)
		for _, n := range install.UnitNames {
			r.fs.Remove(unitFile(n))
		}
		if rep := r.run(); rep.ConfigPath != config.DefaultPath || !reflect.DeepEqual(r.loaded, []string{config.DefaultPath}) {
			t.Errorf("examined %q, loaded %v", rep.ConfigPath, r.loaded)
		}
	})
	t.Run("a unit file without the marker does not choose", func(t *testing.T) {
		r := newRig(t)
		withOtherConfig(r, install.CheckService)
		c, _ := r.fs.Content(unitFile(install.CheckService))
		_, rest, _ := strings.Cut(c, "\n")
		r.fs.AddFile(unitFile(install.CheckService), 0o644, 0, rest)
		if rep := r.run(); rep.ConfigPath != cfgPath {
			t.Errorf("examined %q, want the file of the report service, which carries the marker", rep.ConfigPath)
		}
	})
	t.Run("a timer does not choose", func(t *testing.T) {
		r := newRig(t)
		for _, s := range bothServices {
			r.fs.Remove(unitFile(s))
		}
		r.fs.AddFile(unitFile(install.CheckTimer), 0o644, 0, "# keepwatch-managed-unit: x\nExecStart=/usr/local/bin/keepwatch check --config /srv/timer.yaml\n")
		if rep := r.run(); rep.ConfigPath != config.DefaultPath {
			t.Errorf("examined %q", rep.ConfigPath)
		}
	})
	t.Run("--config is cleaned and wins over the units", func(t *testing.T) {
		r := newRig(t)
		withOtherConfig(r)
		r.configPath = "/srv/kw/../kw/main.yaml"
		if rep := r.run(); rep.ConfigPath != otherCfg || r.loaded[0] != otherCfg {
			t.Errorf("examined %q, loaded %v", rep.ConfigPath, r.loaded)
		}
	})
	t.Run("--config naming the file of the units is no mismatch", func(t *testing.T) {
		r := newRig(t)
		r.configPath = cfgPath
		if rep := r.run(); rep.Problems() != 0 || rep.Warnings() != 0 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("the unit directory cannot be opened: the default path", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove(install.DefaultUnitDir)
		r.fs.AddSymlink(install.DefaultUnitDir, "/srv")
		rep := r.run()
		if rep.ConfigPath != config.DefaultPath || !has(rep, doctor.Problem, "units", "cannot open") {
			t.Errorf("examined %q\n%s", rep.ConfigPath, dump(rep))
		}
	})
}

// --config names another file than the installed services run with: that is a
// problem (the areas above are not about the scheduled run), and each service
// is still judged by its own file.
func TestDoctorWithAConfigTheUnitsDoNotUse(t *testing.T) {
	t.Run("the file of the units is valid: only the mismatch", func(t *testing.T) {
		r := newRig(t)
		withOtherConfig(r, bothServices...)
		r.configPath = cfgPath
		rep := r.run()
		for _, s := range bothServices {
			if !has(rep, doctor.Problem, "units", unitFile(s), "runs with --config "+otherCfg, "examined "+cfgPath+" (given with --config)") {
				t.Errorf("%s:\n%s", s, dump(rep))
			}
		}
		// ReadWritePaths and --notify are compared with the file of the unit,
		// not with the one given: they agree, so nothing more is said.
		if rep.Problems() != 2 {
			t.Errorf("want exactly the two mismatches:\n%s", dump(rep))
		}
		// One load per file, however many services use it.
		if !reflect.DeepEqual(r.loaded, []string{cfgPath, otherCfg}) {
			t.Errorf("loaded %v", r.loaded)
		}
	})
	t.Run("the file of the units is invalid", func(t *testing.T) {
		r := newRig(t)
		withOtherConfig(r, bothServices...)
		r.cfgErrs[otherCfg] = config.Errors{{File: otherCfg, Line: 7, Msg: "bad"}, {File: otherCfg, Line: 9, Msg: "worse"}}
		r.configPath = cfgPath
		rep := r.run()
		for _, s := range bothServices {
			for _, line := range []string{otherCfg + ":7: bad", otherCfg + ":9: worse"} {
				if !has(rep, doctor.Problem, "units", unitFile(s), "runs with --config "+otherCfg+", which is not valid", "exits 3", line) {
					t.Errorf("%s %s:\n%s", s, line, dump(rep))
				}
			}
		}
		if has(rep, doctor.Problem, "config") {
			t.Errorf("the file given with --config is valid:\n%s", dump(rep))
		}
	})
	t.Run("an error that is not a list of configuration errors", func(t *testing.T) {
		r := newRig(t)
		withOtherConfig(r, install.ReportService)
		r.cfgErrs[otherCfg] = context.DeadlineExceeded
		if rep := r.run(); !has(rep, doctor.Problem, "units", unitFile(install.ReportService), "which is not valid", context.DeadlineExceeded.Error()) {
			t.Errorf("\n%s", dump(rep))
		}
		r = newRig(t)
		r.cfgErr = context.DeadlineExceeded
		if rep := r.run(); !has(rep, doctor.Problem, "config", context.DeadlineExceeded.Error()) {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("the file of the units lies where the sandbox hides it", func(t *testing.T) {
		r := newRig(t)
		c := withOtherConfig(r, bothServices...)
		c.Notify.Ntfy.TokenFile = "/tmp/kwtok/ntfy.token"
		r.configPath = cfgPath
		rep := r.run()
		for _, s := range bothServices {
			if !has(rep, doctor.Problem, "units", unitFile(s)+": the directory of notify.ntfy.token_file /tmp/kwtok is under /tmp") {
				t.Errorf("%s:\n%s", s, dump(rep))
			}
		}
	})
	t.Run("ReadWritePaths and --notify are compared with the file of the unit", func(t *testing.T) {
		r := newRig(t)
		c := withOtherConfig(r, bothServices...)
		c.StateDir = "/srv/kw/state2"
		c.Notify.Ntfy = nil
		r.fs.AddDir("/srv/kw/state2", 0o700, 0)
		r.configPath = cfgPath
		rep := r.run()
		if !has(rep, doctor.Problem, "units", unitFile(install.CheckService), `allows writes to "/srv/kw/state"`, "state_dir is /srv/kw/state2") {
			t.Errorf("ReadWritePaths:\n%s", dump(rep))
		}
		if !has(rep, doctor.Problem, "units", unitFile(install.CheckService), "runs with --notify, but notify.ntfy is not configured") {
			t.Errorf("--notify:\n%s", dump(rep))
		}
	})
}

// The two services must run with one configuration. When a hand edit made
// them differ, the check service decides what is examined and the other one
// is a problem, judged by its own file.
func TestDoctorServicesWithDifferentConfigurations(t *testing.T) {
	r := newRig(t)
	withOtherConfig(r, install.ReportService)
	r.cfgErrs[otherCfg] = config.Errors{{File: otherCfg, Line: 2, Msg: "bad"}}
	rep := r.run()
	if rep.ConfigPath != cfgPath {
		t.Errorf("examined %q, want the file of the check service", rep.ConfigPath)
	}
	if !has(rep, doctor.Problem, "units", unitFile(install.ReportService), "runs with --config "+otherCfg, "examined "+cfgPath+" (the --config of "+install.CheckService+")") {
		t.Errorf("the mismatch:\n%s", dump(rep))
	}
	if !has(rep, doctor.Problem, "units", unitFile(install.ReportService), "which is not valid", otherCfg+":2: bad") {
		t.Errorf("the invalid file of the report service:\n%s", dump(rep))
	}
	if has(rep, doctor.Problem, "units", unitFile(install.CheckService)) {
		t.Errorf("the check service is fine:\n%s", dump(rep))
	}
}

// A --config in a unit that is not a clean absolute path (a hand edit) is
// never loaded: relative to what would it be? It is a problem of that unit.
func TestDoctorUnitWithAnUncleanConfigPath(t *testing.T) {
	for _, bad := range []string{"kw.yaml", "/etc/keepwatch/../keepwatch/keepwatch.yaml", "/etc//keepwatch/keepwatch.yaml"} {
		r := newRig(t)
		for _, s := range bothServices {
			editUnit(r, s, "--config "+cfgPath, "--config "+bad)
		}
		rep := r.run()
		if rep.ConfigPath != config.DefaultPath {
			t.Errorf("%s: examined %q", bad, rep.ConfigPath)
		}
		for _, p := range r.loaded {
			if p == bad {
				t.Errorf("%s was loaded", bad)
			}
		}
		if !has(rep, doctor.Problem, "units", unitFile(install.CheckService), "which is not valid", "is not a clean absolute path") {
			t.Errorf("%s:\n%s", bad, dump(rep))
		}
	}
}

// Where the paths lie is judged by the placement check of install, with its
// words, for the paths the installed units and their configuration name.
func TestDoctorPlacement(t *testing.T) {
	user := func(r *rig) {
		r.fs.AddDir("/home", 0o755, 0)
		r.fs.AddDir("/home/tester", 0o750, 1000)
	}
	cases := []struct {
		name  string
		setup func(r *rig)
		area  string
		parts []string
		// probed: the state directory is still probed.
		probed bool
	}{
		{"token file under /tmp", func(r *rig) { r.cfg.Notify.Ntfy.TokenFile = "/tmp/kwtok/ntfy.token" },
			"config", []string{"the directory of notify.ntfy.token_file /tmp/kwtok is under /tmp", "the scheduled run exits 3"}, true},
		{"token file below /run/credentials", func(r *rig) { r.cfg.Notify.Ntfy.TokenFile = "/run/credentials/kw/ntfy.token" },
			"config", []string{"the directory of notify.ntfy.token_file /run/credentials/kw is under /run/credentials", "does not exist for it", "the scheduled run exits 3"}, true},
		{"token file below /run", func(r *rig) { r.cfg.Notify.Ntfy.TokenFile = "/run/kw/ntfy.token" },
			"config", []string{"the directory of notify.ntfy.token_file /run/kw is under /run", "empty after a reboot"}, true},
		{"state_dir in the control group file system", func(r *rig) { r.cfg.StateDir = "/sys/fs/cgroup/kwstate" },
			"state", []string{"state_dir /sys/fs/cgroup/kwstate is under /sys"}, false},
		{"token file in the home of a user", func(r *rig) {
			user(r)
			r.fs.AddFile("/home/tester/ntfy.token", 0o600, 0, "t\n")
			r.cfg.Notify.Ntfy.TokenFile = "/home/tester/ntfy.token"
		}, "config", []string{"the directory of notify.ntfy.token_file /home/tester cannot be trusted", "uid 1000"}, true},
		{"configuration directory a user can write", func(r *rig) { r.fs.AddDir("/etc/keepwatch", 0o777, 0) },
			"config", []string{"the configuration directory /etc/keepwatch cannot be trusted", "permissions 0777"}, true},
		{"conf.d of a user", func(r *rig) { r.fs.AddDir("/etc/keepwatch/conf.d", 0o755, 1000) },
			"config", []string{"the conf.d directory /etc/keepwatch/conf.d cannot be trusted", "uid 1000"}, true},
		{"state_dir below the home of a user", func(r *rig) {
			user(r)
			r.fs.AddDir("/home/tester/kwstate", 0o700, 0)
			r.cfg.StateDir = "/home/tester/kwstate"
		}, "state", []string{"state_dir /home/tester/kwstate cannot be trusted: /home/tester is owned by uid 1000", "rename or replace"}, false},
		{"missing state_dir below the home of a user", func(r *rig) {
			user(r)
			r.cfg.StateDir = "/home/tester/kwstate"
		}, "state", []string{"state_dir /home/tester/kwstate cannot be created in a trusted place"}, false},
		{"state_dir under /run", func(r *rig) { r.cfg.StateDir = "/run/keepwatch" },
			"state", []string{"state_dir /run/keepwatch is under /run", "the scheduled run fails to start"}, false},
		{"a state_dir under /run that is not written as a clean path", func(r *rig) { r.cfg.StateDir = "/run/x/../keepwatch" },
			"state", []string{"state_dir /run/keepwatch is under /run"}, false},
		{"state_dir inside a configuration directory with a problem", func(r *rig) {
			r.fs.AddDir("/etc/keepwatch", 0o777, 0)
			r.fs.AddDir("/etc/keepwatch/state", 0o700, 0)
			r.cfg.StateDir = "/etc/keepwatch/state"
		}, "config", []string{"the configuration directory /etc/keepwatch cannot be trusted"}, false},
		{"binary under /dev in a hand-edited unit", func(r *rig) {
			for _, s := range bothServices {
				editUnit(r, s, "ExecStart=/usr/local/bin/keepwatch", "ExecStart=/dev/kw/keepwatch")
			}
		}, "units", []string{unitFile(install.ReportService) + ": the keepwatch binary /dev/kw/keepwatch is under /dev", "PrivateDevices=yes", "the scheduled run cannot start"}, true},
	}
	for _, c := range cases {
		r := newRig(t)
		c.setup(r)
		probes := 0
		rep := doctor.Run(context.Background(), doctor.Deps{LoadConfig: r.load, Resolver: r.missing, Runner: r.sd.Runner, FS: r.fs,
			Geteuid: func() int { return 0 }, State: func(string) doctor.StateStatus { probes++; return r.state }})
		if !has(rep, doctor.Problem, c.area, c.parts...) {
			t.Errorf("%s:\n%s", c.name, dump(rep))
		}
		if (probes == 1) != c.probed || probes > 1 {
			t.Errorf("%s: the state directory was probed %d times, want probed=%v", c.name, probes, c.probed)
		}
		// The message is the one install refuses with.
		paths := install.Paths{ConfigPath: cfgPath, StateDir: filepath.Clean(r.cfg.StateDir), TokenFile: r.cfg.Notify.Ntfy.TokenFile}
		if c.area == "units" {
			paths = install.Paths{Binary: "/dev/kw/keepwatch"}
		}
		probs := install.CheckPlacement(r.fs, install.Manifest(paths))
		if len(probs) == 0 || !strings.Contains(dump(rep), probs[0].Error()) {
			t.Errorf("%s: doctor does not print the message of the placement check %q:\n%s", c.name, install.PlacementError(probs), dump(rep))
		}
	}
	// A state_dir written with a trailing slash is the same directory: it is
	// cleaned before it is compared with ReadWritePaths and before it is walked.
	r := newRig(t)
	r.cfg.StateDir = stateDir + "/"
	if rep := r.run(); rep.Problems() != 0 {
		t.Errorf("state_dir with a trailing slash:\n%s", dump(rep))
	}
	// Without a file system doctor says so and does not fall over.
	rep := doctor.Run(context.Background(), doctor.Deps{LoadConfig: r.load, Resolver: r.missing, Runner: r.sd.Runner,
		Geteuid: func() int { return 0 }, State: func(string) doctor.StateStatus { return r.state }})
	if !has(rep, doctor.Problem, "units", "internal error") || rep.ConfigPath != config.DefaultPath {
		t.Errorf("without a file system:\n%s", dump(rep))
	}
}
