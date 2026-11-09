package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Files and limits of dockerExposure.
const (
	dockerDaemonJSON    = "/etc/docker/daemon.json"
	maxDockerConfig     = 1 << 20
	maxCmdline          = 128 << 10
	maxDockerContainers = 500
	inspectChunk        = 25
	inspectMaxOutput    = int64(32 << 20)
)

var dockerPidFiles = []string{"/run/docker.pid", "/var/run/docker.pid"}

// dockerExposure checks that the Docker daemon is not reachable over TCP and
// that no running container is privileged, shares the host's PID or network
// namespace, or has the Docker socket mounted.
//
// It takes no parameters (and so has no list parameters).
//
// The daemon. Two sources are read, and a TCP listener in either one fails the
// check:
//
//	the daemon configuration   /etc/docker/daemon.json (or the file named by
//	                           --config-file on the running daemon): every
//	                           entry of "hosts" that is "tcp://..." or has no
//	                           scheme at all (dockerd treats "0.0.0.0:2375" as
//	                           TCP)
//	the running daemon         the pid from /run/docker.pid or
//	                           /var/run/docker.pid, then /proc/<pid>/cmdline,
//	                           which must be a dockerd: every -H, -Hvalue,
//	                           -H=value, --host value and --host=value that is
//	                           TCP in that sense
//
// The detail names whether TLS is on ("tls" or "tlsverify" in the file, or the
// flags): a TCP listener with client verification is still a finding, only a
// weaker one, and the operator decides with an exception. A stale pid file (no
// such process, or not a dockerd) is a note. The scheme "unix://", "fd://" and
// "npipe://" are not TCP; any other scheme is not understood and makes the
// check error. A listener that systemd opens for "-H fd://" is not visible
// here; the listeners check sees it.
//
// The containers. "docker ps -q --no-trunc" lists the running ids (each must
// be 64 lower-case hex digits), and "docker inspect --type container -- <ids>"
// in chunks reads them: HostConfig.Privileged, HostConfig.PidMode "host",
// HostConfig.NetworkMode "host", and a bind mount whose source is a Docker
// socket (/var/run/docker.sock, /run/docker.sock, or any path whose last
// element is docker.sock; a mount of the directory that holds it is not
// recognised). One evidence item per container with the reasons in the detail;
// the subject is the container name. The name is text a user of the Docker
// API chooses, so it is cut and sanitised, and a name that does not look like a
// Docker name is replaced by "id:" and the first twelve characters of the id.
// An exception matches that subject. Required fields that are missing in the
// inspect output are an error, never "not privileged". At most 500 running
// containers are examined; with more the result is error (partial). A
// container that stops between the two commands is ignored and said so in the
// summary.
//
// Exit statuses: docker ps 0 only; docker inspect 0, or 1 when every message
// on stderr says "No such container" for one of the requested ids and stdout
// is the JSON array of the others. Anything else, and a docker daemon that
// cannot be reached ("Cannot connect to the Docker daemon", status 1), is
// error. When docker is not installed the containers are not examined; if
// there is no daemon.json and no pid file either, the check is skipped. A file
// that cannot be read, or an error of one source, makes the status error but
// keeps the findings already confirmed in the evidence.
type dockerExposure struct{}

func (dockerExposure) Name() string       { return "docker_exposure" }
func (dockerExposure) Programs() []string { return []string{"docker"} }

func (dockerExposure) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	if err := p.err(); err != nil {
		return nil, err
	}
	return dockerProbe{}, nil
}

type dockerProbe struct{}

func (dockerProbe) Run(ctx context.Context, env *Env) Outcome {
	d := &dockerRun{env: env}
	// The running daemon first: it may name a different config file.
	cfgPath := dockerDaemonJSON
	cmdTLS := d.readCmdline()
	if d.configFile != "" {
		cfgPath = d.configFile
	}
	cfgTLS, cfgSeen := d.readConfig(cfgPath)
	d.tcpFindings(cmdTLS, cfgTLS)

	installed := d.containers(ctx)
	if !installed && !cfgSeen && !d.pidSeen && len(d.causes) == 0 {
		return Outcome{Status: result.Skipped, Summary: `program "docker" is not installed and the daemon left no configuration, check skipped`}
	}

	ev, hidden := limitEvidence(d.ev)
	switch {
	case len(d.causes) > 0:
		o := partialError(d.causes, d.ev)
		o.Evidence = ev
		return o
	case len(d.ev) > 0:
		return Outcome{
			Status:   result.Fail,
			Summary:  fmt.Sprintf("%d docker exposure finding(s): %s", len(d.ev), d.names()) + d.noteText() + moreNote(hidden),
			Evidence: ev,
		}
	}
	return Outcome{Status: result.Pass, Summary: "the docker daemon is not reachable over TCP" + d.passText() + d.noteText()}
}

// dockerRun is the state of one run.
type dockerRun struct {
	env        *Env
	ev         []result.Evidence
	causes     []string
	notes      []string
	configFile string // --config-file of the running daemon
	pidSeen    bool
	examined   int
	haveDocker bool
}

func (d *dockerRun) names() string {
	var n []string
	for i, e := range d.ev {
		if i == 5 {
			n = append(n, "...")
			break
		}
		n = append(n, e.Subject)
	}
	return strings.Join(n, ", ")
}

func (d *dockerRun) noteText() string {
	if len(d.notes) == 0 {
		return ""
	}
	return " (" + clean(strings.Join(d.notes, "; "), 300) + ")"
}

func (d *dockerRun) passText() string {
	if !d.haveDocker {
		return ""
	}
	return fmt.Sprintf(" and %d running container(s) are not exposed", d.examined)
}

// tlsInfo describes what a daemon source says about TLS.
type tlsInfo struct{ tls, verify bool }

func (t tlsInfo) String() string {
	switch {
	case t.verify:
		return "tlsverify on"
	case t.tls:
		return "tls on, clients not verified"
	}
	return "no TLS"
}

// dockerTCPHost classifies a daemon host entry: tcp true when dockerd would
// listen on TCP for it, known false for schemes that are not understood.
func dockerTCPHost(h string) (tcp, known bool) {
	l := strings.ToLower(strings.TrimSpace(h))
	scheme, _, hasScheme := strings.Cut(l, "://")
	if !hasScheme {
		return l != "", l != ""
	}
	switch scheme {
	case "tcp":
		return true, true
	case "unix", "fd", "npipe":
		return false, true
	}
	return false, false
}

type tcpHost struct {
	source, host string
	tls          tlsInfo
}

func (d *dockerRun) addTCP(h tcpHost) {
	d.ev = append(d.ev, result.Evidence{
		Subject: clean(h.source+" "+h.host, 120),
		Detail:  fmt.Sprintf("the docker daemon listens on TCP (%s)", h.tls),
	})
}

func (d *dockerRun) readCmdline() []tcpHost {
	for _, pf := range dockerPidFiles {
		b, err := d.env.FS.ReadFile(pf, 64)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		d.pidSeen = true
		if err != nil {
			d.causes = append(d.causes, fmt.Sprintf("cannot read %s: %s", pf, clean(err.Error(), 120)))
			return nil
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid < 1 || strconv.Itoa(pid) != strings.TrimSpace(string(b)) {
			d.causes = append(d.causes, fmt.Sprintf("%s does not hold a process id", pf))
			return nil
		}
		raw, err := d.env.FS.ReadFile("/proc/"+strconv.Itoa(pid)+"/cmdline", maxCmdline)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			d.notes = append(d.notes, "the docker pid file is stale (no such process), the running daemon was not examined")
			return nil
		case err != nil:
			d.causes = append(d.causes, fmt.Sprintf("cannot read the command line of process %d: %s", pid, clean(err.Error(), 120)))
			return nil
		}
		args := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
		if path.Base(args[0]) != "dockerd" {
			d.notes = append(d.notes, "the docker pid file points to a process that is not dockerd, the running daemon was not examined")
			return nil
		}
		hosts, cfg, tls, err := parseDockerdArgs(args[1:])
		if err != nil {
			d.causes = append(d.causes, "dockerd command line: "+err.Error())
			return nil
		}
		d.configFile = cfg
		for i := range hosts {
			hosts[i].tls = tls
		}
		return hosts
	}
	return nil
}

// parseDockerdArgs reads the daemon's arguments: the -H/--host values, the
// --config-file value and the TLS flags.
func parseDockerdArgs(args []string) (hosts []tcpHost, cfg string, tls tlsInfo, err error) {
	add := func(v string) error {
		tcp, known := dockerTCPHost(v)
		if !known {
			return fmt.Errorf("host %q is not understood", clean(v, 60))
		}
		if tcp {
			hosts = append(hosts, tcpHost{source: "dockerd", host: v})
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch {
		case a == "--":
			return
		case a == "-H" || a == "--host":
			v, ok := next()
			if !ok {
				return nil, "", tls, fmt.Errorf("%s without a value", a)
			}
			if err = add(v); err != nil {
				return nil, "", tls, err
			}
		case strings.HasPrefix(a, "--host="):
			if err = add(strings.TrimPrefix(a, "--host=")); err != nil {
				return nil, "", tls, err
			}
		case strings.HasPrefix(a, "-H="):
			if err = add(strings.TrimPrefix(a, "-H=")); err != nil {
				return nil, "", tls, err
			}
		case strings.HasPrefix(a, "-H") && len(a) > 2:
			if err = add(a[2:]); err != nil {
				return nil, "", tls, err
			}
		case a == "--config-file":
			v, ok := next()
			if !ok {
				return nil, "", tls, errors.New("--config-file without a value")
			}
			cfg = v
		case strings.HasPrefix(a, "--config-file="):
			cfg = strings.TrimPrefix(a, "--config-file=")
		case a == "--tlsverify" || a == "--tlsverify=true":
			tls.verify, tls.tls = true, true
		case a == "--tls" || a == "--tls=true":
			tls.tls = true
		}
	}
	return hosts, cfg, tls, nil
}

// readConfig reads the daemon configuration file. It reports whether the file
// exists.
func (d *dockerRun) readConfig(file string) ([]tcpHost, bool) {
	if !pathOK(file) {
		d.causes = append(d.causes, fmt.Sprintf("the daemon config file %q is not an absolute path", clean(file, 80)))
		return nil, true
	}
	b, err := d.env.FS.ReadFile(file, maxDockerConfig)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	case err != nil:
		d.causes = append(d.causes, fmt.Sprintf("cannot read %s: %s", clean(file, 80), clean(err.Error(), 120)))
		return nil, true
	}
	hosts, err := parseDaemonJSON(b)
	if err != nil {
		d.causes = append(d.causes, fmt.Sprintf("%s: %v", clean(file, 80), err))
		return nil, true
	}
	return hosts, true
}

func pathOK(p string) bool { return strings.HasPrefix(p, "/") && !strings.ContainsRune(p, 0) }

// parseDaemonJSON reads the keys of daemon.json that matter: "hosts" and the
// TLS switches. The result lists the TCP hosts.
func parseDaemonJSON(b []byte) ([]tcpHost, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil || top == nil {
		return nil, errors.New("is not a JSON object")
	}
	boolKey := func(k string) bool {
		var v bool
		raw, ok := top[k]
		return ok && json.Unmarshal(raw, &v) == nil && v
	}
	tls := tlsInfo{tls: boolKey("tls"), verify: boolKey("tlsverify")}
	if tls.verify {
		tls.tls = true
	}
	raw, ok := top["hosts"]
	if !ok {
		return nil, nil
	}
	var hosts []string
	if err := json.Unmarshal(raw, &hosts); err != nil {
		return nil, errors.New(`"hosts" is not a list of strings`)
	}
	var out []tcpHost
	for _, h := range hosts {
		tcp, known := dockerTCPHost(h)
		if !known {
			return nil, fmt.Errorf("host %q is not understood", clean(h, 60))
		}
		if tcp {
			out = append(out, tcpHost{source: "daemon.json", host: h, tls: tls})
		}
	}
	return out, nil
}

// tcpFindings turns the TCP hosts of both sources into evidence. A host both
// sources name is reported once per source: they are different subjects an
// exception can name.
func (d *dockerRun) tcpFindings(cmd, cfg []tcpHost) {
	for _, h := range append(append([]tcpHost(nil), cmd...), cfg...) {
		d.addTCP(h)
	}
}

var hexID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// containers examines the running containers. It reports whether docker is
// installed.
func (d *dockerRun) containers(ctx context.Context) bool {
	res, out := run(ctx, d.env, []string{"docker", "ps", "-q", "--no-trunc"}, 30*time.Second)
	if out != nil {
		if out.Status == result.Skipped {
			d.notes = append(d.notes, "docker is not installed, containers not examined")
			return false
		}
		d.causes = append(d.causes, out.Summary)
		return true
	}
	if res.ExitCode != 0 {
		d.causes = append(d.causes, "docker daemon not reachable: "+unexpectedExit("docker ps", res).Summary)
		return true
	}
	var ids []string
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		if !hexID.MatchString(line) {
			d.causes = append(d.causes, fmt.Sprintf("docker ps printed %q, not a container id", clean(line, 40)))
			return true
		}
		ids = append(ids, line)
	}
	d.haveDocker = true
	if len(ids) > maxDockerContainers {
		d.causes = append(d.causes, fmt.Sprintf("%d containers are running, only the first %d were examined", len(ids), maxDockerContainers))
		ids = ids[:maxDockerContainers]
	}
	gone := 0
	for len(ids) > 0 {
		n := min(inspectChunk, len(ids))
		g, ok := d.inspect(ctx, ids[:n])
		if !ok {
			return true
		}
		gone += g
		ids = ids[n:]
	}
	if gone > 0 {
		d.notes = append(d.notes, fmt.Sprintf("%d container(s) stopped while they were examined", gone))
	}
	return true
}

type inspected struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	HostConfig *struct {
		Privileged  *bool    `json:"Privileged"`
		PidMode     *string  `json:"PidMode"`
		NetworkMode *string  `json:"NetworkMode"`
		Binds       []string `json:"Binds"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
	} `json:"Mounts"`
}

// inspect reads one chunk of containers. It returns how many vanished and
// false when the chunk could not be read (the cause is recorded).
func (d *dockerRun) inspect(ctx context.Context, ids []string) (int, bool) {
	argv := append([]string{"docker", "inspect", "--type", "container", "--"}, ids...)
	res, out := runWith(ctx, d.env, argv, execx.Opts{Timeout: 60 * time.Second, MaxOutput: inspectMaxOutput}, false)
	if out != nil {
		d.causes = append(d.causes, out.Summary)
		return 0, false
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	switch res.ExitCode {
	case 0:
	case 1:
		if !onlyNoSuchContainer(string(res.Stderr), want) {
			d.causes = append(d.causes, unexpectedExit("docker inspect", res).Summary)
			return 0, false
		}
	default:
		d.causes = append(d.causes, unexpectedExit("docker inspect", res).Summary)
		return 0, false
	}
	var list []inspected
	dec := json.NewDecoder(bytes.NewReader(res.Stdout))
	if err := dec.Decode(&list); err != nil || dec.More() {
		d.causes = append(d.causes, "docker inspect printed output that is not a JSON array of containers")
		return 0, false
	}
	seen := map[string]bool{}
	for _, c := range list {
		if !want[c.ID] || seen[c.ID] {
			d.causes = append(d.causes, "docker inspect printed a container that was not asked for")
			return 0, false
		}
		seen[c.ID] = true
		reasons, err := containerReasons(c)
		if err != nil {
			d.causes = append(d.causes, fmt.Sprintf("container %s: %v", c.ID[:12], err))
			return 0, false
		}
		d.examined++
		if len(reasons) > 0 {
			subject, detail := containerSubject(c)
			d.ev = append(d.ev, result.Evidence{Subject: subject, Detail: detail + strings.Join(reasons, "; ")})
		}
	}
	gone := len(ids) - len(list)
	if res.ExitCode == 0 && gone != 0 {
		d.causes = append(d.causes, "docker inspect printed fewer containers than asked for")
		return 0, false
	}
	return gone, true
}

var noSuchRe = regexp.MustCompile(`^Error response from daemon: No such container: ([0-9a-f]{64})$`)

// onlyNoSuchContainer reports whether every line of stderr says that one of
// the requested containers does not exist.
func onlyNoSuchContainer(stderr string, want map[string]bool) bool {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for _, l := range lines {
		m := noSuchRe.FindStringSubmatch(l)
		if m == nil || !want[m[1]] {
			return false
		}
	}
	return len(lines) > 0 && strings.TrimSpace(stderr) != ""
}

var dockerNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// containerSubject returns the evidence subject of a container and a prefix
// for its detail.
func containerSubject(c inspected) (string, string) {
	name := strings.TrimPrefix(c.Name, "/")
	if dockerNameRe.MatchString(name) {
		return name, ""
	}
	return "id:" + c.ID[:12], fmt.Sprintf("name %q (sanitised); ", clean(name, 40))
}

var dockerSocketPaths = map[string]bool{"/var/run/docker.sock": true, "/run/docker.sock": true}

func isDockerSocket(src string) bool {
	if !strings.HasPrefix(src, "/") {
		return false
	}
	p := path.Clean(src)
	return dockerSocketPaths[p] || path.Base(p) == "docker.sock"
}

// containerReasons lists why a container is exposed. A required field that is
// missing is an error.
func containerReasons(c inspected) ([]string, error) {
	h := c.HostConfig
	if h == nil || h.Privileged == nil || h.PidMode == nil || h.NetworkMode == nil || len(c.ID) != 64 {
		return nil, errors.New("inspect output lacks HostConfig fields")
	}
	var r []string
	if *h.Privileged {
		r = append(r, "privileged")
	}
	if *h.PidMode == "host" {
		r = append(r, "host PID namespace")
	}
	if *h.NetworkMode == "host" {
		r = append(r, "host network namespace")
	}
	sockets := map[string]bool{}
	for _, b := range h.Binds {
		if src, _, ok := strings.Cut(b, ":"); ok && isDockerSocket(src) {
			sockets[path.Clean(src)] = true
		}
	}
	for _, m := range c.Mounts {
		if isDockerSocket(m.Source) {
			sockets[path.Clean(m.Source)] = true
		}
	}
	paths := make([]string, 0, len(sockets))
	for s := range sockets {
		paths = append(paths, s)
	}
	sort.Strings(paths)
	for _, s := range paths {
		r = append(r, "docker socket mounted ("+clean(s, 60)+")")
	}
	return r, nil
}
