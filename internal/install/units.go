// Package install writes and removes the systemd units that run keepwatch on
// a schedule, and renders them. keepwatch runs as root, so this package is
// careful about what it writes and removes:
//
//   - A unit file carries a marker comment on its first line. install never
//     overwrites a file without the marker, and uninstall removes only files
//     with it.
//   - Every write goes through an opened, checked directory (see FS): the
//     target is never a symlink, the data goes into a temporary file that is
//     renamed into place.
//   - Everything that reaches a unit line (paths, the interval, the calendar
//     time) is validated against a strict grammar first, so no value can add
//     a line, an option or a specifier.
package install

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// Unit file names, in the order they are written. Services come before the
// timers that start them.
const (
	CheckService  = "keepwatch-check.service"
	CheckTimer    = "keepwatch-check.timer"
	ReportService = "keepwatch-report.service"
	ReportTimer   = "keepwatch-report.timer"
)

// UnitNames lists the unit files keepwatch owns, services first.
var UnitNames = []string{CheckService, ReportService, CheckTimer, ReportTimer}

// Timers lists the timer units, which install enables and uninstall disables.
var Timers = []string{CheckTimer, ReportTimer}

// DefaultUnitDir is where the units are written.
const DefaultUnitDir = "/etc/systemd/system"

// markerPrefix starts the first line of every unit file keepwatch writes. A
// file is keepwatch's if, and only if, its first line starts with it.
const markerPrefix = "# keepwatch-managed-unit:"

// markerLine is the whole first line.
const markerLine = markerPrefix + ` written by "keepwatch install" and removed by "keepwatch uninstall"; do not edit, changes are overwritten.`

// HasMarker reports whether content starts with the keepwatch marker line.
func HasMarker(content []byte) bool {
	first, _, _ := bytes.Cut(content, []byte("\n"))
	return bytes.HasPrefix(first, []byte(markerPrefix))
}

// Defaults of the schedule.
const (
	DefaultInterval     = "6h"
	DefaultWeeklyReport = "Mon 08:00"
)

// Interval is the time between two checks.
type Interval struct {
	N    int
	Unit string // "min", "h" or "d"
}

// Bounds of the interval: below five minutes a check would overlap its own
// slowest probe (apt takes up to 90 seconds), above thirty days it is no
// longer a watch.
const (
	minIntervalMinutes = 5
	maxIntervalMinutes = 30 * 24 * 60
)

// String returns the interval as systemd writes a time span: 5min, 6h, 2d.
func (i Interval) String() string { return strconv.Itoa(i.N) + i.Unit }

// ParseInterval parses the --interval value. The grammar is one positive
// number without leading zeros (at most five digits) and one unit, m, h or d
// (minutes, hours, days), lower case, nothing else: no spaces, no sign, no
// fraction, no second unit, no "infinity". The span must be at least five
// minutes and at most thirty days.
func ParseInterval(s string) (Interval, error) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	num, unit := s[:i], s[i:]
	bad := func() (Interval, error) {
		return Interval{}, fmt.Errorf("interval \"%s\": want one number and one unit (m, h or d), for example 30m, 6h or 1d", quote(s))
	}
	if num == "" || len(num) > 5 || num[0] == '0' {
		return bad()
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return bad()
	}
	var iv Interval
	var minutes int
	switch unit {
	case "m":
		iv, minutes = Interval{n, "min"}, n
	case "h":
		iv, minutes = Interval{n, "h"}, n*60
	case "d":
		iv, minutes = Interval{n, "d"}, n*60*24
	default:
		return bad()
	}
	if minutes < minIntervalMinutes || minutes > maxIntervalMinutes {
		return Interval{}, fmt.Errorf("interval \"%s\": must be between 5m and 30d", quote(s))
	}
	return iv, nil
}

// Weekly is the day and time of the weekly report.
type Weekly struct {
	Day    string // Mon .. Sun
	Hour   int
	Minute int
}

var weekdays = []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

// OnCalendar returns the value of the OnCalendar= line.
func (w Weekly) OnCalendar() string {
	return fmt.Sprintf("%s *-*-* %02d:%02d:00", w.Day, w.Hour, w.Minute)
}

// ParseWeekly parses the --weekly-report value. The grammar is a three-letter
// English day name (Mon, Tue, Wed, Thu, Fri, Sat or Sun, capitalised exactly
// so), one space and a time HH:MM on the 24-hour clock with two digits each.
// It is the local time of the host; the schedule is persistent, so a report
// missed while the host was off runs when it is back.
func ParseWeekly(s string) (Weekly, error) {
	bad := func() (Weekly, error) {
		return Weekly{}, fmt.Errorf("weekly report time \"%s\": want a day and a time like \"Mon 08:00\" (Mon..Sun, HH:MM, 24 hours)", quote(s))
	}
	day, clock, ok := strings.Cut(s, " ")
	if !ok || len(clock) != 5 || clock[2] != ':' {
		return bad()
	}
	found := false
	for _, d := range weekdays {
		found = found || d == day
	}
	if !found {
		return bad()
	}
	for _, i := range []int{0, 1, 3, 4} {
		if clock[i] < '0' || clock[i] > '9' {
			return bad()
		}
	}
	h, _ := strconv.Atoi(clock[:2])
	m, _ := strconv.Atoi(clock[3:])
	if h > 23 || m > 59 {
		return bad()
	}
	return Weekly{Day: day, Hour: h, Minute: m}, nil
}

// quote shortens and escapes a value for a message.
func quote(s string) string {
	q := strconv.Quote(s)
	q = q[1 : len(q)-1]
	if len(q) > 60 {
		q = q[:60] + "..."
	}
	return q
}

// safePath reports whether p can be written into a unit line unquoted: an
// absolute, clean path of ASCII letters, digits and . _ - + @ / only. No
// space, quote, backslash, dollar, percent (a systemd specifier), semicolon
// or control character can be in it, and no component is "." or "..".
func safePath(p string) error {
	if p == "" || p[0] != '/' || path.Clean(p) != p || len(p) > 1024 {
		return errors.New("must be a clean absolute path")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._-+@/", c) >= 0:
		default:
			return fmt.Errorf("contains %q, only letters, digits and . _ - + @ / are allowed", string(c))
		}
	}
	return nil
}

// Spec is everything the units depend on.
type Spec struct {
	// Binary is the absolute path of the keepwatch executable.
	Binary string
	// ConfigPath is the absolute path of the main configuration file.
	ConfigPath string
	// StateDir is state_dir of the configuration.
	StateDir string
	// Notify makes the services notify (check --notify, report --weekly
	// --notify). It is set when notify.ntfy is configured in the configuration
	// that install validated: a run with --notify and no notify.ntfy exits 3,
	// and a run without --notify consumes the alerts nobody is told of.
	Notify   bool
	Interval Interval
	Weekly   Weekly
}

// Validate checks every value that reaches a unit line.
func (s Spec) Validate() error {
	var errs []string
	chk := func(what, p string) {
		if err := safePath(p); err != nil {
			errs = append(errs, fmt.Sprintf("%s \"%s\": %v", what, quote(p), err))
		}
	}
	chk("keepwatch binary", s.Binary)
	chk("configuration file", s.ConfigPath)
	chk("state_dir", s.StateDir)
	if s.StateDir == "/" {
		errs = append(errs, "state_dir must not be /")
	}
	for _, u := range []struct {
		what, p string
		role    Role
	}{{"keepwatch binary", s.Binary, RoleBinary}, {"configuration file", s.ConfigPath, RoleConfig}, {"state_dir", s.StateDir, RoleState}} {
		if h, ok := HiddenBy(u.p, u.role); ok {
			errs = append(errs, fmt.Sprintf("%s \"%s\" is under %s: %s; put it elsewhere", u.what, quote(u.p), h.Path, h.Why))
		}
	}
	if s.Interval.N == 0 {
		errs = append(errs, "interval is not set")
	}
	if s.Weekly.Day == "" {
		errs = append(errs, "weekly report time is not set")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Role says what a path is used for by the service.
type Role int

// The roles of a path in a unit.
const (
	RoleBinary Role = iota // the program in ExecStart
	RoleConfig             // the configuration file given with --config
	RoleState              // state_dir, in ReadWritePaths
)

// sandboxPaths lists, next to the hardening constants below that cause them,
// the paths a service does not see (or cannot rely on) and the roles for
// which that is refused. option is the option that hides the path, or says why
// it cannot be used; a test checks that every option of the form NAME=yes is
// still in the hardening, so removing one forces this table to be revisited.
var sandboxPaths = []struct {
	option string
	why    string
	paths  []string
	roles  []Role
}{
	{"PrivateTmp=yes", "the service has its own empty /tmp and /var/tmp (PrivateTmp=yes), so the path does not exist for it",
		[]string{"/tmp", "/var/tmp"}, []Role{RoleBinary, RoleConfig, RoleState}},
	{"PrivateDevices=yes", "the service has its own /dev (PrivateDevices=yes), so the path does not exist for it",
		[]string{"/dev"}, []Role{RoleBinary, RoleConfig, RoleState}},
	{"volatile", "it lives on a tmpfs that is empty after a reboot, and ReadWritePaths needs the directory to exist when the service starts",
		[]string{"/run", "/var/run", "/dev/shm"}, []Role{RoleState}},
}

// Hidden is a sandbox path a value lies under.
type Hidden struct {
	Path, Option, Why string
}

// HiddenBy reports whether p lies under a path that the sandbox of the
// services hides or that is volatile, for the role.
func HiddenBy(p string, role Role) (Hidden, bool) {
	for _, e := range sandboxPaths {
		applies := false
		for _, r := range e.roles {
			applies = applies || r == role
		}
		if !applies {
			continue
		}
		for _, d := range e.paths {
			if p == d || strings.HasPrefix(p, d+"/") {
				return Hidden{Path: d, Option: e.option, Why: e.why}, true
			}
		}
	}
	return Hidden{}, false
}

// File is one unit file to be written.
type File struct {
	Name    string
	Content []byte
}

// Hardening of both services. The reason for every option is in the README.
const (
	memoryMax        = "1536M"
	goMemLimit       = "384MiB"
	cpuQuota         = "50%"
	timeoutStartSec  = "10min"
	addressFamilies  = "AF_UNIX AF_INET AF_INET6 AF_NETLINK"
	serviceHardening = `# 0 and 1 are normal: 1 means the host has findings, and the notification (not
# a failed unit) tells the operator. 3 (internal error) and 4 (delivery) fail.
SuccessExitStatus=1
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={{state}}
# read-only, not yes: the authorized_keys check reads /home and /root.
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
SystemCallArchitectures=native
# AF_UNIX: docker.sock, fail2ban.sock, the journal. AF_NETLINK: ss, nft.
RestrictAddressFamilies=` + addressFamilies + `
# Sized by the most memory the listeners check can use (two 64 MiB buffers of
# "ss" output and their copies), measured as the peak of the unit's cgroup under
# the GOMEMLIMIT below, with at least 1.5 times headroom. GOMEMLIMIT is not
# needed to stay under MemoryMax, but it lowers the usual worst case
# considerably; keep it unless the sizing is measured again. MemoryMax is the
# backstop for a runaway check.
MemoryMax=` + memoryMax + `
Environment=GOMEMLIMIT=` + goMemLimit + `
CPUQuota=` + cpuQuota + `
TimeoutStartSec=` + timeoutStartSec + `
`
)

// checkArgs and reportArgs are what the services run after the binary;
// notifyFlag is added when the spec notifies.
var (
	checkArgs  = []string{"check"}
	reportArgs = []string{"report", "--weekly"}
)

const notifyFlag = "--notify"

// Render returns the four unit files for spec, in write order. It fails if
// the spec does not validate.
func Render(s Spec) ([]File, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	hard := strings.ReplaceAll(serviceHardening, "{{state}}", s.StateDir)
	exec := func(args []string) string {
		if s.Notify {
			args = append(append([]string(nil), args...), notifyFlag)
		}
		return s.Binary + " " + strings.Join(args, " ") + " --config " + s.ConfigPath
	}
	service := func(desc string, args []string) string {
		return markerLine + `
[Unit]
Description=` + desc + `
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=` + exec(args) + `
` + hard
	}
	timer := func(desc, unit, schedule string) string {
		return markerLine + `
[Unit]
Description=` + desc + `

[Timer]
` + schedule + `
Unit=` + unit + `

[Install]
WantedBy=timers.target
`
	}
	return []File{
		{CheckService, []byte(service("keepwatch posture check", checkArgs))},
		{ReportService, []byte(service("keepwatch weekly report", reportArgs))},
		{CheckTimer, []byte(timer("keepwatch periodic check", CheckService,
			"OnBootSec=5min\nOnUnitActiveSec="+s.Interval.String()+"\nAccuracySec=1min"))},
		{ReportTimer, []byte(timer("keepwatch weekly report", ReportService,
			"OnCalendar="+s.Weekly.OnCalendar()+"\nPersistent=true"))},
	}, nil
}

// Installed describes what an installed service file says; doctor compares it
// with the configuration.
type Installed struct {
	Binary         string
	Notify         bool // ExecStart carries --notify
	ReadWritePaths string
	ConfigPath     string
}

// Inspect reads the values doctor needs out of a service file written by
// Render. Values it does not find are empty.
func Inspect(content []byte) Installed {
	var in Installed
	for _, line := range strings.Split(string(content), "\n") {
		switch {
		case strings.HasPrefix(line, "ReadWritePaths="):
			in.ReadWritePaths = strings.TrimPrefix(line, "ReadWritePaths=")
		case strings.HasPrefix(line, "ExecStart="):
			f := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
			if len(f) > 0 {
				in.Binary = f[0]
			}
			for i := range f {
				if f[i] == notifyFlag {
					in.Notify = true
				}
			}
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "--config" {
					in.ConfigPath = f[i+1]
				}
			}
		}
	}
	return in
}
