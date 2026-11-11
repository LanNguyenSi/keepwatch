package doctor_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/LanNguyenSi/keepwatch/internal/doctor"
	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/install"
)

// unitText returns the installed text of a service file.
func unitText(t *testing.T, r *rig, name string) string {
	t.Helper()
	c, ok := r.fs.Content(unitFile(name))
	if !ok {
		t.Fatalf("%s is not installed", name)
	}
	return c
}

// execStart returns the ExecStart line of a service file.
func execStart(c string) string {
	for _, l := range strings.Split(c, "\n") {
		if strings.HasPrefix(l, "ExecStart=") {
			return l
		}
	}
	return ""
}

func setUnit(r *rig, name, content string) { r.fs.AddFile(unitFile(name), 0o644, 0, content) }

// Hand edits of an installed service file that keep the marker. Inspect reads
// the last ExecStart, ReadWritePaths and the flags; none of these changes what
// it reads, while systemd runs something else. Each was reproduced on systemd
// 249 and 255: the unit failed with 203 or 3 and doctor said "no problems".
func TestDoctorJudgesTheServiceFileAsRendered(t *testing.T) {
	t.Run("healthy host: no difference", func(t *testing.T) {
		r := newRig(t)
		if rep := r.run(); rep.Problems() != 0 || strings.Contains(dump(rep), "was changed") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	cases := []struct {
		name  string
		edit  func(c string) string
		parts []string
	}{
		{"an ExecStart line in front of the real one",
			func(c string) string {
				return strings.Replace(c, execStart(c), "ExecStart=/opt/gone/keepwatch check --config "+cfgPath+"\n"+execStart(c), 1)
			},
			[]string{"line 9 is", `"ExecStart=/opt/gone/keepwatch check --config ` + cfgPath + `"`, `the rendered unit has "ExecStart=/usr/local/bin/keepwatch `}},
		{"another program in an ExecStart line behind the real one",
			func(c string) string {
				return strings.Replace(c, execStart(c), execStart(c)+"\n"+strings.Replace(execStart(c), "/usr/local/bin/keepwatch", "/opt/gone/keepwatch", 1), 1)
			},
			[]string{"line 9 is", `"ExecStart=/usr/local/bin/keepwatch `, `the rendered unit has "ExecStart=/opt/gone/keepwatch `}},
		{"the same ExecStart twice",
			func(c string) string { return strings.Replace(c, execStart(c), execStart(c)+"\n"+execStart(c), 1) },
			[]string{"line 10 is", `"ExecStart=/usr/local/bin/keepwatch `, `the rendered unit has "# 0 and 1`}},
		{"a hardening option changed",
			func(c string) string { return strings.Replace(c, "ProtectHome=read-only", "ProtectHome=yes", 1) },
			[]string{`"ProtectHome=yes"`, `the rendered unit has "ProtectHome=read-only"`}},
		{"a hardening line added at the end",
			func(c string) string { return c + "InaccessiblePaths=/etc/keepwatch\n" },
			[]string{`"InaccessiblePaths=/etc/keepwatch", is not in the rendered unit`}},
		{"a hardening line added in the middle",
			func(c string) string {
				return strings.Replace(c, "PrivateTmp=yes\n", "PrivateTmp=yes\nInaccessiblePaths=/etc/keepwatch\n", 1)
			},
			[]string{`"InaccessiblePaths=/etc/keepwatch"`, `the rendered unit has "PrivateDevices=yes"`}},
		{"the last line cut off",
			func(c string) string { return strings.Replace(c, "TimeoutStartSec=10min\n", "", 1) },
			[]string{"the file ends after line", `goes on with "TimeoutStartSec=10min"`}},
		{"the final line feed missing",
			func(c string) string { return strings.TrimSuffix(c, "\n") },
			[]string{"lacks or has a line feed", `"TimeoutStartSec=10min"`}},
		{"a hardening option removed",
			func(c string) string { return strings.Replace(c, "NoNewPrivileges=yes\n", "", 1) },
			[]string{`"ProtectSystem=strict"`, `the rendered unit has "NoNewPrivileges=yes"`}},
		{"the text of the marker line changed",
			func(c string) string { return strings.Replace(c, "do not edit", "edit freely", 1) },
			[]string{"line 1 is", "edit freely"}},
		{"a line ending changed",
			func(c string) string { return strings.Replace(c, "Type=oneshot\n", "Type=oneshot\r\n", 1) },
			[]string{`"Type=oneshot\r"`, `the rendered unit has "Type=oneshot"`}},
		{"an environment line added",
			func(c string) string {
				return strings.Replace(c, "Environment=GOMEMLIMIT=384MiB\n", "Environment=GOMEMLIMIT=384MiB\nEnvironment=KEEPWATCH_X=1\n", 1)
			},
			[]string{"KEEPWATCH_X=1"}},
	}
	for _, c := range cases {
		for _, svc := range bothServices {
			t.Run(c.name+" in "+svc, func(t *testing.T) {
				r := newRig(t)
				setUnit(r, svc, c.edit(unitText(t, r, svc)))
				rep := r.run()
				if !has(rep, doctor.Problem, "units", append([]string{unitFile(svc), "was changed after", "keepwatch install"}, c.parts...)...) {
					t.Errorf("not reported:\n%s", dump(rep))
				}
				for _, other := range bothServices {
					if other != svc && has(rep, doctor.Problem, "units", unitFile(other), "was changed") {
						t.Errorf("%s is untouched but reported:\n%s", other, dump(rep))
					}
				}
			})
		}
	}
	t.Run("a long line is shortened", func(t *testing.T) {
		r := newRig(t)
		long := strings.Repeat("x", 400)
		setUnit(r, install.CheckService, unitText(t, r, install.CheckService)+"Environment=A="+long+"\n")
		rep := r.run()
		if !has(rep, doctor.Problem, "units", "was changed", "Environment=A=xxx", `xxx..."`) || strings.Contains(dump(rep), long) {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a service with other values is judged against its own", func(t *testing.T) {
		// A unit written for another configuration, another binary and no
		// --notify is as rendered when it differs from the stock one only there.
		r := newRig(t)
		withOtherConfig(r, bothServices...)
		editUnit(r, install.CheckService, "/usr/local/bin/keepwatch", "/opt/kw/bin/keepwatch")
		editUnit(r, install.CheckService, " --notify", "")
		rep := r.run()
		if strings.Contains(dump(rep), "was changed") {
			t.Errorf("a unit as install would render it for its own values is reported:\n%s", dump(rep))
		}
	})
	t.Run("the check service with the arguments of the report", func(t *testing.T) {
		r := newRig(t)
		editUnit(r, install.CheckService, "keepwatch check ", "keepwatch report --weekly ")
		if rep := r.run(); !has(rep, doctor.Problem, "units", unitFile(install.CheckService), "was changed", "report --weekly") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a change next to a wrong value says both", func(t *testing.T) {
		r := newRig(t)
		editUnit(r, install.CheckService, "ReadWritePaths="+stateDir, "ReadWritePaths=/srv/other")
		r.cfg.StateDir = stateDir
		rep := r.run()
		if !has(rep, doctor.Problem, "units", unitFile(install.CheckService), "allows writes to") {
			t.Errorf("\n%s", dump(rep))
		}
		// Both lines name the same value, the file is as rendered for it.
		if strings.Contains(dump(rep), "was changed") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("values install would refuse", func(t *testing.T) {
		for name, edit := range map[string]func(c string) string{
			"a space in the state directory": func(c string) string {
				return strings.Replace(c, "ReadWritePaths="+stateDir, "ReadWritePaths="+stateDir+" /etc", 1)
			},
			"no ReadWritePaths": func(c string) string { return strings.Replace(c, "ReadWritePaths="+stateDir+"\n", "", 1) },
			"a specifier in the binary": func(c string) string {
				return strings.Replace(c, "/usr/local/bin/keepwatch", "/usr/local/bin/%n", 1)
			},
		} {
			r := newRig(t)
			setUnit(r, install.CheckService, edit(unitText(t, r, install.CheckService)))
			rep := r.run()
			if !has(rep, doctor.Problem, "units", unitFile(install.CheckService), `is not a unit that "keepwatch install" can have written`) {
				t.Errorf("%s:\n%s", name, dump(rep))
			}
		}
	})
	t.Run("a unit without ExecStart is one problem, not two", func(t *testing.T) {
		r := newRig(t)
		setUnit(r, install.CheckService, "# keepwatch-managed-unit: x\n[Service]\nType=oneshot\n")
		rep := r.run()
		if !has(rep, doctor.Problem, "units", "no ExecStart program") || strings.Contains(dump(rep), "was changed") || strings.Contains(dump(rep), "can have written") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a unit without --config is one problem, not two", func(t *testing.T) {
		for _, svc := range bothServices {
			r := newRig(t)
			editUnit(r, svc, " --config "+cfgPath, "")
			rep := r.run()
			if !has(rep, doctor.Problem, "units", unitFile(svc), "has no --config") || strings.Contains(dump(rep), "was changed") || strings.Contains(dump(rep), "can have written") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
	})
	t.Run("the timers are not rendered from the services", func(t *testing.T) {
		r := newRig(t)
		c, _ := r.fs.Content(unitFile(install.CheckTimer))
		setUnit(r, install.CheckTimer, strings.Replace(c, "AccuracySec=1min", "AccuracySec=1h", 1))
		if rep := r.run(); strings.Contains(dump(rep), "was changed") {
			t.Errorf("a timer is not covered by this check:\n%s", dump(rep))
		}
	})
}

// A drop-in changes a unit without touching its file. The path lists are what
// systemctl printed on Ubuntu 22.04 and 24.04 for a unit with one and two
// drop-ins.
func TestDoctorReportsDropIns(t *testing.T) {
	const (
		one = "/etc/systemd/system/keepwatch-check.service.d/override.conf"
		two = "/etc/systemd/system/keepwatch-check.service.d/10-quota.conf /etc/systemd/system/keepwatch-check.service.d/override.conf"
	)
	t.Run("none: nothing to say", func(t *testing.T) {
		r := newRig(t)
		if rep := r.run(); strings.Contains(dump(rep), "drop-in") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	for name, paths := range map[string]string{"one": one, "two": two} {
		for _, svc := range bothServices {
			t.Run(name+" on "+svc, func(t *testing.T) {
				r := newRig(t)
				r.sd.Props[svc] = map[string]string{"DropInPaths": paths}
				rep := r.run()
				if !has(rep, doctor.Problem, "units", svc, "has drop-ins ("+paths+")", "does not run as", "does not judge") {
					t.Errorf("\n%s", dump(rep))
				}
				if rep.Problems() != 1 {
					t.Errorf("want exactly the one problem:\n%s", dump(rep))
				}
			})
		}
	}
	t.Run("both services", func(t *testing.T) {
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": one}
		r.sd.Props[install.ReportService] = map[string]string{"DropInPaths": one}
		if rep := r.run(); rep.Problems() != 2 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a drop-in in service.d is a warning, not a problem", func(t *testing.T) {
		// The path a generator of LXC and Incus images writes at every boot,
		// and the places a vendor and an administrator use for the same.
		for _, p := range []string{
			"/run/systemd/system/service.d/zzz-lxc-service.conf",
			"/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
			"/etc/systemd/system/service.d/90-x.conf",
		} {
			r := newRig(t)
			r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": p}
			rep := r.run()
			if !has(rep, doctor.Warn, "units", install.CheckService, p, "service.d directory", "applies to every service", "system, an image or a generator") {
				t.Errorf("%s:\n%s", p, dump(rep))
			}
			if rep.Problems() != 0 || strings.Contains(dump(rep), "Remove them") {
				t.Errorf("%s is no problem the operator can fix:\n%s", p, dump(rep))
			}
		}
	})
	t.Run("a drop-in in any other directory is aimed at the unit", func(t *testing.T) {
		// systemd reads <name>.service.d for every name of the unit, so a
		// directory of an alias, whatever it is called, changes this service.
		// On Ubuntu 24.04 a kwalias.service symlinked to the unit with
		// ExecStart= and ExecStart=/bin/true in its drop-in ran /bin/true.
		for _, p := range []string{
			"/etc/systemd/system/other.service.d/90-x.conf",
			"/etc/systemd/system/kwalias.service.d/x.conf",
			"/etc/systemd/system/keepwatch-.service.d/x.conf",
			"/run/systemd/system/anything.d/x.conf",
			"/etc/systemd/system/service.d.d/x.conf",
		} {
			r := newRig(t)
			r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": p}
			rep := r.run()
			if !has(rep, doctor.Problem, "units", install.CheckService, "has drop-ins ("+p+")") || rep.Warnings() != 0 {
				t.Errorf("%s:\n%s", p, dump(rep))
			}
		}
	})
	t.Run("a name with a space is quoted by systemctl and read whole", func(t *testing.T) {
		// systemctl show of keepwatch-check.service.d/a b.conf (systemd 255).
		const quoted = `"/etc/systemd/system/keepwatch-check.service.d/a b.conf"`
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": quoted}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", install.CheckService, "has drop-ins ("+quoted+")") || rep.Warnings() != 0 || rep.Problems() != 1 {
			t.Errorf("\n%s", dump(rep))
		}
		// In a service.d it is one file as well, and still only a warning.
		const shared = `"/run/systemd/system/service.d/a b.conf" /etc/systemd/system/keepwatch-check.service.d/o.conf`
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": shared}
		rep = r.run()
		if !has(rep, doctor.Warn, "units", `"/run/systemd/system/service.d/a b.conf" from a service.d`) || !has(rep, doctor.Problem, "units", "has drop-ins (/etc/systemd/system/keepwatch-check.service.d/o.conf)") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("both kinds: the problem lists only the files named for keepwatch", func(t *testing.T) {
		const global = "/run/systemd/system/service.d/zzz-lxc-service.conf"
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": global + " /etc/systemd/system/keepwatch-check.service.d/override.conf"}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", install.CheckService, "has drop-ins (/etc/systemd/system/keepwatch-check.service.d/override.conf)") {
			t.Errorf("\n%s", dump(rep))
		}
		if has(rep, doctor.Problem, "units", global) || !has(rep, doctor.Warn, "units", install.CheckService, global) {
			t.Errorf("\n%s", dump(rep))
		}
		if rep.Problems() != 1 || rep.Warnings() != 1 {
			t.Errorf("want one problem and one warning:\n%s", dump(rep))
		}
	})
	t.Run("drop-ins named for keepwatch in any unit directory", func(t *testing.T) {
		for _, p := range []string{
			"/etc/systemd/system.control/keepwatch-check.service.d/50-CPUQuota.conf",
			"/run/systemd/system.control/keepwatch-check.service.d/50-CPUQuota.conf",
			"/run/systemd/system/keepwatch-check.service.d/x.conf",
			"/usr/lib/systemd/system/keepwatch-check.service.d/x.conf",
			"/etc/systemd/system/keepwatch-.service.d/x.conf",
		} {
			r := newRig(t)
			r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": p}
			if rep := r.run(); !has(rep, doctor.Problem, "units", install.CheckService, "has drop-ins ("+p+")") || rep.Warnings() != 0 {
				t.Errorf("%s:\n%s", p, dump(rep))
			}
		}
	})
	t.Run("a drop-in of a service that is not loaded", func(t *testing.T) {
		// systemd lists the drop-ins of a unit it refused as well. doctor says
		// that the unit is not loaded, which is the problem, and does not list
		// what was merged into a unit that does not run.
		r := newRig(t)
		r.sd.Loaded[install.CheckService] = false
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": one}
		rep := r.run()
		if strings.Contains(dump(rep), "has drop-ins") || !has(rep, doctor.Problem, "units", "systemd has not loaded "+install.CheckService) {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("the property is asked for", func(t *testing.T) {
		r := newRig(t)
		before := len(r.sd.Runner.Calls)
		r.run()
		found := false
		for _, l := range r.sd.Runner.Lines()[before:] {
			found = found || (strings.HasPrefix(l, "systemctl show "+install.CheckService) && strings.Contains(l, "--property=DropInPaths"))
		}
		if !found {
			t.Errorf("DropInPaths is not asked for: %v", r.sd.Runner.Lines()[before:])
		}
	})
	t.Run("systemd not running: no question, no finding", func(t *testing.T) {
		r := newRig(t)
		r.fs.Remove("/run/systemd/system")
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": one}
		if rep := r.run(); strings.Contains(dump(rep), "drop-in") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

// doctor judges what systemd loaded, not only the file in the unit directory.
func TestDoctorJudgesTheLoadedUnit(t *testing.T) {
	const control = "/etc/systemd/system.control/keepwatch-check.service"
	t.Run("loaded from the unit directory: nothing to say", func(t *testing.T) {
		r := newRig(t)
		if rep := r.run(); rep.Problems() != 0 || strings.Contains(dump(rep), "systemd loaded") || strings.Contains(dump(rep), "reload") {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a unit file in a directory that takes precedence", func(t *testing.T) {
		for _, p := range []string{control, "/run/systemd/system.control/keepwatch-check.service", "/usr/lib/systemd/system/keepwatch-check.service", ""} {
			r := newRig(t)
			r.sd.Props[install.CheckService] = map[string]string{"FragmentPath": p}
			rep := r.run()
			if !has(rep, doctor.Problem, "units", install.CheckService, "systemd loaded", `from "`+p+`"`, "not from "+unitFile(install.CheckService)) {
				t.Errorf("%q:\n%s", p, dump(rep))
			}
			if rep.Problems() != 1 {
				t.Errorf("%q: want exactly the one problem:\n%s", p, dump(rep))
			}
		}
	})
	t.Run("both services", func(t *testing.T) {
		r := newRig(t)
		for _, s := range bothServices {
			r.sd.Props[s] = map[string]string{"FragmentPath": "/run/systemd/system.control/" + s}
		}
		if rep := r.run(); rep.Problems() != 2 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("changed on disk and not reloaded", func(t *testing.T) {
		for _, s := range bothServices {
			r := newRig(t)
			r.sd.Props[s] = map[string]string{"NeedDaemonReload": "yes"}
			rep := r.run()
			if !has(rep, doctor.Problem, "units", s, "has not reloaded", `"systemctl daemon-reload"`) || rep.Problems() != 1 {
				t.Errorf("%s:\n%s", s, dump(rep))
			}
		}
	})
	t.Run("the properties are asked for", func(t *testing.T) {
		r := newRig(t)
		before := len(r.sd.Runner.Calls)
		r.run()
		for _, prop := range []string{"FragmentPath", "NeedDaemonReload"} {
			found := false
			for _, l := range r.sd.Runner.Lines()[before:] {
				found = found || (strings.HasPrefix(l, "systemctl show "+install.ReportService) && strings.Contains(l, "--property="+prop))
			}
			if !found {
				t.Errorf("%s is not asked for: %v", prop, r.sd.Runner.Lines()[before:])
			}
		}
	})
	t.Run("a unit that is not loaded is not asked about its file", func(t *testing.T) {
		r := newRig(t)
		r.sd.Loaded[install.CheckService] = false
		r.sd.Props[install.CheckService] = map[string]string{"NeedDaemonReload": "yes"}
		if rep := r.run(); strings.Contains(dump(rep), "reloaded") || strings.Contains(dump(rep), "systemd loaded") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

// showAnswers makes "systemctl show" of one unit end as given; every other run
// is answered as before.
func showAnswers(r *rig, unit string, res execx.Result, err error) {
	next := r.sd.Runner.Handler
	r.sd.Runner.Handler = func(argv []string) (execx.Result, error) {
		if len(argv) > 2 && argv[0] == "systemctl" && argv[1] == "show" && argv[2] == unit {
			return res, err
		}
		return next(argv)
	}
}

// What systemctl show printed and how it exited for a service with a drop-in
// whose file name is not valid UTF-8 (hi<0xff>.conf), on systemd 249 and 255.
// The drop-in replaced ExecStart and the service ran it.
var showFailures = map[string]execx.Result{
	"systemd 249": {ExitCode: 1, Stderr: []byte("Failed to get properties: Bad message\n")},
	"systemd 255": {ExitCode: 1, Stderr: []byte("Failed to get properties: Invalid argument\n")},
}

// A service systemd gives no answer for is not judged: its drop-ins, the file
// systemd loaded and its last run stay unknown. doctor must say so and must
// not come out clean.
func TestDoctorReportsAServiceSystemdDoesNotAnswerFor(t *testing.T) {
	for name, res := range showFailures {
		for _, svc := range bothServices {
			t.Run(name+" "+svc, func(t *testing.T) {
				r := newRig(t)
				showAnswers(r, svc, res, nil)
				rep := r.run()
				reason := strings.TrimSpace(string(res.Stderr))
				if !has(rep, doctor.Problem, "units", "cannot ask systemd about "+svc+": systemctl show "+svc+" exited with status 1: "+reason, "drop-ins", "last run", "not valid UTF-8") {
					t.Errorf("not reported:\n%s", dump(rep))
				}
				if rep.Problems() != 1 {
					t.Errorf("want exactly the one problem:\n%s", dump(rep))
				}
				for _, other := range bothServices {
					if other != svc && strings.Contains(dump(rep), "cannot ask systemd about "+other) {
						t.Errorf("%s answers but is reported:\n%s", other, dump(rep))
					}
				}
				if !has(rep, doctor.OK, "timers", install.CheckTimer) || !has(rep, doctor.OK, "timers", install.ReportTimer) {
					t.Errorf("the timers answer:\n%s", dump(rep))
				}
			})
		}
	}
	t.Run("systemctl cannot be run for the service", func(t *testing.T) {
		for _, svc := range bothServices {
			r := newRig(t)
			showAnswers(r, svc, execx.Result{}, fmt.Errorf("%w: systemctl", execx.ErrNotFound))
			if rep := r.run(); !has(rep, doctor.Problem, "units", "cannot ask systemd about "+svc, "systemctl") || rep.Problems() != 1 {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
	})
	t.Run("both services", func(t *testing.T) {
		r := newRig(t)
		for _, svc := range bothServices {
			showAnswers(r, svc, showFailures["systemd 255"], nil)
		}
		if rep := r.run(); rep.Problems() != 2 {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a service that is not installed is not asked about twice", func(t *testing.T) {
		// The file is missing, which is said; that systemd does not answer for
		// a unit that is not there adds nothing.
		for _, svc := range bothServices {
			r := newRig(t)
			r.fs.Remove(unitFile(svc))
			showAnswers(r, svc, showFailures["systemd 255"], nil)
			rep := r.run()
			if !has(rep, doctor.Problem, "units", unitFile(svc), "is not installed") || strings.Contains(dump(rep), "cannot ask systemd") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
	})
	t.Run("a file that is there in another form is asked about", func(t *testing.T) {
		// A foreign file and one doctor cannot read are units systemd may run.
		for name, set := range map[string]func(r *rig, svc string){
			"foreign":    func(r *rig, svc string) { setUnit(r, svc, "[Service]\nExecStart=/bin/true\n") },
			"too large":  func(r *rig, svc string) { setUnit(r, svc, unitText(t, r, svc)+strings.Repeat("#\n", 40<<10)) },
			"a symlink":  func(r *rig, svc string) { r.fs.Remove(unitFile(svc)); r.fs.AddSymlink(unitFile(svc), "/srv/x.service") },
			"our marker": func(r *rig, svc string) {},
		} {
			for _, svc := range bothServices {
				r := newRig(t)
				set(r, svc)
				showAnswers(r, svc, showFailures["systemd 249"], nil)
				if rep := r.run(); !has(rep, doctor.Problem, "units", "cannot ask systemd about "+svc) {
					t.Errorf("%s, %s:\n%s", name, svc, dump(rep))
				}
			}
		}
	})
	t.Run("an error text that is not printable is quoted", func(t *testing.T) {
		// The first line of the error output of systemctl with a C1 control
		// and a character that reverses the direction of the text.
		r := newRig(t)
		showAnswers(r, install.CheckService, execx.Result{ExitCode: 1, Stderr: []byte("Failed: \u009b31mred\u202e\n")}, nil)
		rep := r.run()
		if !has(rep, doctor.Problem, "units", "cannot ask systemd about "+install.CheckService+`: "systemctl show `+install.CheckService+` exited with status 1: Failed: \u009b31mred\u202e". So doctor`) {
			t.Errorf("\n%s", dump(rep))
		}
		safeReport(t, rep)
	})
}

// A unit file that is there while systemd has not loaded the unit: the timer
// cannot start the service. On systemd 249 and 255 a drop-in that clears
// ExecStart gave LoadState=bad-setting, a link to /dev/null in
// /etc/systemd/system.control gave masked and a line systemd cannot read gave
// error; "systemctl start" failed each time.
func TestDoctorReportsAServiceSystemdDidNotLoad(t *testing.T) {
	for _, state := range []string{"masked", "bad-setting", "error", "not-found", ""} {
		for _, svc := range bothServices {
			t.Run(state+" "+svc, func(t *testing.T) {
				r := newRig(t)
				r.sd.Props[svc] = map[string]string{"LoadState": state, "ExecMainStartTimestamp": ""}
				rep := r.run()
				if !has(rep, doctor.Problem, "units", "systemd has not loaded "+svc+" although its unit file is there", `load state "`+state+`"`, "timer cannot start", `"systemctl status `+svc+`"`) {
					t.Errorf("not reported:\n%s", dump(rep))
				}
				if rep.Problems() != 1 || rep.Warnings() != 0 {
					t.Errorf("want the one problem and nothing about a run:\n%s", dump(rep))
				}
			})
		}
	}
	t.Run("a service that is not installed is not reported twice", func(t *testing.T) {
		for _, svc := range bothServices {
			r := newRig(t)
			r.fs.Remove(unitFile(svc))
			r.sd.Loaded[svc] = false
			rep := r.run()
			if !has(rep, doctor.Problem, "units", unitFile(svc), "is not installed") || strings.Contains(dump(rep), "has not loaded") {
				t.Errorf("%s:\n%s", svc, dump(rep))
			}
		}
	})
	t.Run("a foreign file that is not loaded", func(t *testing.T) {
		r := newRig(t)
		setUnit(r, install.ReportService, "[Service]\nExecStart=/bin/true\n")
		r.sd.Loaded[install.ReportService] = false
		if rep := r.run(); !has(rep, doctor.Problem, "units", "systemd has not loaded "+install.ReportService) {
			t.Errorf("\n%s", dump(rep))
		}
	})
	t.Run("a file that is missing while systemd still has the unit is judged", func(t *testing.T) {
		// Removed without a reload: systemd runs what it read (systemd 255:
		// LoadState=loaded, NeedDaemonReload=yes).
		r := newRig(t)
		r.fs.Remove(unitFile(install.ReportService))
		r.sd.Props[install.ReportService] = map[string]string{"NeedDaemonReload": "yes"}
		if rep := r.run(); !has(rep, doctor.Problem, "units", install.ReportService, "has not reloaded") {
			t.Errorf("\n%s", dump(rep))
		}
	})
}

// safeReport fails the test when the printed report holds anything a terminal
// acts on, or a line that does not start as a line of doctor does.
func safeReport(t *testing.T, rep doctor.Report) {
	t.Helper()
	out := dump(rep)
	if !utf8.ValidString(out) {
		t.Errorf("the report is not valid UTF-8: %q", out)
	}
	for i := 0; i < len(out); i++ {
		if b := out[i]; (b < 0x20 && b != '\n') || b == 0x7f {
			t.Errorf("the report holds the byte 0x%02x: %q", b, out)
		}
	}
	for _, r := range out {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Errorf("the report holds %U, which is not printable: %q", r, out)
		}
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(rep.Findings)+1 {
		t.Errorf("%d findings and a summary are %d lines:\n%s", len(rep.Findings), len(lines), out)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "ok      ") && !strings.HasPrefix(l, "warn    ") && !strings.HasPrefix(l, "PROBLEM ") && !strings.HasPrefix(l, "doctor: ") {
			t.Errorf("a line that is not one of doctor: %q", l)
		}
	}
}

// File names are bytes: a drop-in can be called anything but "/" and NUL. The
// values are what systemctl show printed for these names on systemd 249 and
// 255 (the same bytes): a bell, a carriage return and a line feed in front of
// text that reads like a line of doctor, DEL, an escape sequence that colours
// the terminal, 0x01 and an e with an acute accent.
func TestDoctorPrintsDropInNamesSafely(t *testing.T) {
	const (
		d        = "/etc/systemd/system/keepwatch-check.service.d/"
		captured = `"` + d + `bel\a.conf" "` + d + `cr\rok   units: fine.conf" "` + d + `del\177.conf" "` + d + `esc\033[31mred.conf" "` + d + `nl\nok   units: fine.conf" "` + d + `one\001.conf" ` + d + "utf\u00e9.conf"
		listed   = `"` + d + `bel\a.conf" "` + d + `cr\rok   units: fine.conf" "` + d + `del\x7f.conf" "` + d + `esc\x1b[31mred.conf" "` + d + `nl\nok   units: fine.conf" "` + d + `one\x01.conf" ` + d + "utf\u00e9.conf"
	)
	t.Run("drop-ins of the unit", func(t *testing.T) {
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": captured}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", install.CheckService, "has drop-ins ("+listed+"): systemd runs") || rep.Problems() != 1 {
			t.Errorf("\n%q", dump(rep))
		}
		safeReport(t, rep)
	})
	t.Run("drop-ins in service.d", func(t *testing.T) {
		const s = "/run/systemd/system/service.d/"
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": strings.ReplaceAll(captured, d, s)}
		rep := r.run()
		if !has(rep, doctor.Warn, "units", install.CheckService, "is merged with "+strings.ReplaceAll(listed, d, s)+" from a service.d directory") || rep.Problems() != 0 {
			t.Errorf("\n%q", dump(rep))
		}
		safeReport(t, rep)
	})
	t.Run("names systemctl does not quote", func(t *testing.T) {
		// Valid UTF-8 is printed as it is by systemctl, whatever it does to a
		// terminal: a C1 control (CSI), a character that reverses the
		// direction of the text, one that draws nothing.
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"DropInPaths": d + "csi\u009bx.conf " + d + "bidi\u202ex.conf " + d + "zw\u200bx.conf " + d + "plain.conf"}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", `has drop-ins ("`+d+`csi\u009bx.conf" "`+d+`bidi\u202ex.conf" "`+d+`zw\u200bx.conf" `+d+`plain.conf)`) {
			t.Errorf("\n%q", dump(rep))
		}
		safeReport(t, rep)
	})
	t.Run("the file systemd loaded", func(t *testing.T) {
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"FragmentPath": "/etc/systemd/system.control/x\x1b[31m\u202e\xff\x7f.service"}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", `systemd loaded `+install.CheckService+` from "/etc/systemd/system.control/x\x1b[31m\u202e\xff\x7f.service"`) {
			t.Errorf("\n%q", dump(rep))
		}
		safeReport(t, rep)
	})
	t.Run("the load state", func(t *testing.T) {
		r := newRig(t)
		r.sd.Props[install.CheckService] = map[string]string{"LoadState": "x\x1b[31m\r"}
		rep := r.run()
		if !has(rep, doctor.Problem, "units", `load state "x\x1b[31m\r"`) {
			t.Errorf("\n%q", dump(rep))
		}
		safeReport(t, rep)
	})
}
