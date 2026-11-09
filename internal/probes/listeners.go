package probes

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// trustedMaxOutput is the output limit of the runs that decide the socket
// set ("ss -Hltn", "ss -Hlun"). The execx default of 1 MiB is far below what
// an unprivileged process can print: every listening socket is one line of
// about 60 bytes, and any local user can open tens of thousands (SO_REUSEPORT
// on one port needs no privilege). 64 MiB holds about a million lines, which
// is beyond what a host can hold open, and still bounds the memory of the
// run. The best-effort "-p" runs keep the execx default.
const trustedMaxOutput = int64(64 << 20)

// listeners compares the listening sockets of the host with the listener
// allowlist of the configuration (listeners.allow).
//
// Parameters:
//
//	allow_loopback  (bool, default true)  listeners bound to a loopback
//	                address (127.0.0.0/8, ::1) are allowed without an
//	                allowlist entry
//	protos          (list of "tcp" and "udp", default [tcp, udp])  which
//	                protocols to examine
//
// List semantics: a "protos" list under checks.<id>.params REPLACES the
// default (it is not appended to it). Lists from conf.d drop-ins are already
// appended to the main file's list when the config is loaded. The allowlist
// itself is not a parameter: it is the top-level listeners.allow section,
// where conf.d lists append.
//
// The socket set comes from "ss -Hltn" (tcp) and "ss -Hlun" (udp) alone,
// without -p. Only exit status 0 is interpreted. Every output line must be
// exactly "STATE RECV SEND LOCAL PEER" with state LISTEN (tcp) or UNCONN
// (udp) and a local address of the form host:port, where host is "*", an
// IPv4 address or an IPv6 address in brackets, optionally followed by a
// "%interface" suffix OUTSIDE the brackets, which is how ss prints a socket
// bound to a device: "0.0.0.0%lo:80", "[::]%lo:80", "[fe80::1]%eth0:546",
// "*%lo:80". A suffix inside the brackets is not a form ss prints and is
// error. Anything else is error. ss prints nothing when nothing listens; if
// both protocols print nothing the result is error, because on a reachable
// host that is far more likely a broken ss than a host without a single
// listener.
//
// Process names are text any local process can choose (the name may even
// hold a newline) and must never decide what the check sees. They are read
// from a separate, best-effort run of "ss -Hltnp" / "ss -Hlunp" that is made
// only when some listener is not allowed, is used only for the detail text,
// and is matched to the sockets of the first run by local address. A line of
// that output that does not parse is skipped; a failed, timed out, truncated
// or unparseable run only makes the detail say the processes are unknown.
// It cannot add, remove or change a socket, and it never changes the status.
//
// If one protocol cannot be read, the result is error, but the listeners
// that the other protocol confirmed as not allowed stay in the evidence and
// the summary says that the picture is partial.
//
// Output limit: the two runs that decide the socket set may print up to 64
// MiB (trustedMaxOutput), so a local flood of listening sockets does not
// reach the limit. If the output is cut anyway, the complete lines of the
// prefix are parsed (a last line without its newline is dropped; a complete
// line that does not parse makes the run error without evidence as for any
// output), the sockets found there that are not allowed stay in the evidence
// and the result is error, partial. Residual limit: ss prints sockets in
// the order of the kernel, not sorted, so a flood that exceeds even 64 MiB can
// still hide sockets that come after the cut. The result is then error
// with the evidence of the prefix, never pass.
//
// A listener is allowed when an allowlist entry has the same port and
// protocol and a bind that is "*" (any address) or the same address. The
// allowlist cannot name an interface, so a listener with an interface suffix
// is matched without it: an entry for "::" allows "[::]%lo", and only an
// entry with bind "*" allows "*" and "*%lo" (the dual-stack socket that ss
// prints with no address). A socket bound to a device is not thereby a
// loopback listener: only a loopback ADDRESS is allowed by allow_loopback.
// Each listener that is not allowed is one evidence item with subject
// "<proto>/<address>:<port>" (IPv6 in brackets, the interface suffix kept
// after the address, for example "udp/[fe80::1]%eth0:546") and the owning
// process names in the detail, shown quoted and sanitised, never
// interpreted.
type listeners struct{}

func (listeners) Name() string       { return "listeners" }
func (listeners) Programs() []string { return []string{"ss"} }

func (listeners) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	loop := p.boolean("allow_loopback", true)
	protos := p.strList("protos", false, true, []string{"tcp", "udp"}, func(s string) error {
		if s != "tcp" && s != "udp" {
			return fmt.Errorf("protocol %q is not tcp or udp", s)
		}
		return nil
	})
	if err := p.err(); err != nil {
		return nil, err
	}
	return listenersProbe{allowLoopback: loop, protos: protos}, nil
}

type listenersProbe struct {
	allowLoopback bool
	protos        []string
}

// socket is one parsed listening socket.
type socket struct {
	proto string
	any   bool // the "*" address
	addr  netip.Addr
	zone  string // "%interface" as ss prints it after the address, or ""
	port  int
}

func (s socket) subject() string {
	return fmt.Sprintf("%s/%s:%d", s.proto, s.host(), s.port)
}

// host renders the address the way ss does: "*", an IPv4 address, or an IPv6
// address in brackets, each followed by the interface suffix if there is one.
func (s socket) host() string {
	if s.any {
		return "*" + s.zone
	}
	h := s.addr.String()
	if s.addr.Is6() {
		h = "[" + h + "]"
	}
	return h + s.zone
}

func (s socket) loopback() bool {
	return !s.any && s.addr.IsLoopback()
}

// protoSpec is how one protocol is listed.
type protoSpec struct {
	state       string // LISTEN or UNCONN
	flag, pflag string // ss options without and with -p
}

func specFor(proto string) protoSpec {
	if proto == "udp" {
		return protoSpec{"UNCONN", "-Hlun", "-Hlunp"}
	}
	return protoSpec{"LISTEN", "-Hltn", "-Hltnp"}
}

func (l listenersProbe) Run(ctx context.Context, env *Env) Outcome {
	var socks []socket
	var failures []string
	for i, proto := range l.protos {
		sp := specFor(proto)
		res, out := runWith(ctx, env, []string{"ss", sp.flag}, execx.Opts{MaxOutput: trustedMaxOutput}, true)
		if out != nil {
			if out.Status == result.Skipped && i == 0 {
				return *out
			}
			failures = append(failures, proto+": "+out.Summary)
			continue
		}
		if res.ExitCode != 0 {
			failures = append(failures, proto+": "+unexpectedExit("ss", res).Summary)
			continue
		}
		stdout := string(res.Stdout)
		if res.Truncated {
			stdout = completeLines(stdout)
		}
		got, err := parseSS(stdout, proto, sp.state)
		if err != nil {
			failures = append(failures, fmt.Sprintf("ss %s: %v", sp.flag, err))
			continue
		}
		socks = append(socks, got...)
		if res.Truncated {
			failures = append(failures, fmt.Sprintf("%s: ss output was truncated at the size limit", proto))
		}
	}
	if len(failures) == 0 && len(socks) == 0 {
		return *errorOutcome("ss reported no listening sockets at all, which cannot be told apart from a broken ss")
	}

	var bad []socket // the sockets that are not allowed, one per subject
	seen := map[string]bool{}
	for _, s := range socks {
		if (l.allowLoopback && s.loopback()) || allowed(env.ListenerAllow, s) || seen[s.subject()] {
			continue
		}
		seen[s.subject()] = true
		bad = append(bad, s)
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i].subject() < bad[j].subject() })

	var ev []result.Evidence
	if len(bad) > 0 {
		procs, note := l.processes(ctx, env)
		for _, s := range bad {
			ev = append(ev, result.Evidence{Subject: s.subject(), Detail: processDetail(procs[s.subject()], note)})
		}
	}

	switch {
	case len(failures) > 0:
		return partialError(failures, ev)
	case len(ev) == 0:
		return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%d listening sockets, all allowed", len(socks))}
	}
	return Outcome{
		Status:   result.Fail,
		Summary:  fmt.Sprintf("%d of %d listening sockets are not in the allowlist", len(ev), len(socks)),
		Evidence: ev,
	}
}

// processes asks ss for the process names of the listening sockets. It is
// best effort and feeds the detail text only: it returns the names by socket
// subject and a note that is empty when the answer is complete. Whatever
// goes wrong here, the caller has the sockets already.
func (l listenersProbe) processes(ctx context.Context, env *Env) (map[string][]string, string) {
	names := map[string][]string{}
	var problems []string
	for _, proto := range l.protos {
		sp := specFor(proto)
		res, out := run(ctx, env, []string{"ss", sp.pflag}, 0)
		switch {
		case out != nil:
			problems = append(problems, proto+": "+out.Summary)
			continue
		case res.ExitCode != 0:
			problems = append(problems, proto+": "+unexpectedExit("ss", res).Summary)
			continue
		}
		complete := parseProcesses(string(res.Stdout), proto, sp.state, names)
		if !complete {
			problems = append(problems, proto+": ss -p output not understood in full")
		}
	}
	if len(problems) == 0 {
		return names, ""
	}
	return names, "process names may be missing, " + clean(strings.Join(problems, "; "), 200)
}

// processDetail renders the detail of one listener.
func processDetail(names []string, note string) string {
	d := "listening, processes: " + procList(names)
	if note != "" {
		d += " (" + note + ")"
	}
	return d
}

// allowed reports whether an allowlist entry covers the socket. The "*" that
// ss prints for a dual-stack socket has no address (the zero netip.Addr, which
// no entry parses to), so only an entry with bind "*" covers it. The interface
// suffix is not part of the address: the allowlist cannot express it.
func allowed(rules []ListenerRule, s socket) bool {
	for _, r := range rules {
		if r.Port != s.port || r.Proto != s.proto {
			continue
		}
		if r.Bind == "*" {
			return true
		}
		if a, err := netip.ParseAddr(r.Bind); err == nil && a == s.addr {
			return true
		}
	}
	return false
}

const (
	maxProcNames = 5
	maxProcRunes = 32
)

var zonePattern = regexp.MustCompile(`^%[A-Za-z0-9._@-]{1,32}$`)

var procEntry = regexp.MustCompile(`\("(.*?)",pid=[0-9]+,fd=[0-9]+\)`)

// completeLines cuts a truncated output back to its last newline, so a line
// that was cut in the middle is never parsed.
func completeLines(out string) string {
	if i := strings.LastIndexByte(out, '\n'); i >= 0 {
		return out[:i+1]
	}
	return ""
}

// parseSS parses the output of "ss -H" without -p for one protocol. The
// format is strict: exactly five columns per line.
func parseSS(out, proto, wantState string) ([]socket, error) {
	var socks []socket
	for i, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 5 || f[0] != wantState {
			return nil, fmt.Errorf("line %d does not look like a %s listener: %q", i+1, proto, clean(line, 60))
		}
		s, err := parseLocal(f[3])
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		s.proto = proto
		socks = append(socks, s)
	}
	return socks, nil
}

// parseProcesses reads "ss -Hltnp" / "ss -Hlunp" output and adds the process
// names of each socket to names, keyed by the socket's subject. It is lenient
// on purpose and cannot produce a socket: a line counts only when it is a
// whole record (state, three more columns and a local address that parses,
// then either nothing or a users:(...) column that ends the line); every
// other line is skipped. A process name that holds a newline splits its
// record into lines like that, so the record and the lines it leaves behind
// are skipped. It reports whether every non-blank line was understood.
func parseProcesses(out, proto, wantState string, names map[string][]string) bool {
	complete := true
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != wantState {
			complete = false
			continue
		}
		s, err := parseLocal(f[3])
		if err != nil {
			complete = false
			continue
		}
		s.proto = proto
		if len(f) == 5 {
			continue
		}
		if !strings.HasPrefix(f[5], "users:((") || !strings.HasSuffix(line, "))") {
			complete = false
			continue
		}
		for _, m := range procEntry.FindAllStringSubmatch(strings.Join(f[5:], " "), -1) {
			names[s.subject()] = append(names[s.subject()], m[1])
		}
	}
	return complete
}

// parseLocal parses the local address column: "*:80", "0.0.0.0:22",
// "[::]:22", "127.0.0.53%lo:53", "[::]%lo:22", "*%lo:22". An interface
// suffix comes after the address (and after the closing bracket), never
// inside the brackets.
func parseLocal(col string) (socket, error) {
	i := strings.LastIndexByte(col, ':')
	if i < 0 {
		return socket{}, fmt.Errorf("local address %q has no port", clean(col, 60))
	}
	host, portStr := col[:i], col[i+1:]
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 || portStr != strconv.Itoa(port) {
		return socket{}, fmt.Errorf("local address %q has an invalid port", clean(col, 60))
	}
	s := socket{port: port}
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host, s.zone = host[:j], host[j:]
		if !zonePattern.MatchString(s.zone) {
			return socket{}, fmt.Errorf("local address %q has an invalid interface suffix", clean(col, 60))
		}
	}
	if host == "*" {
		s.any = true
		return s, nil
	}
	bracketed := strings.HasPrefix(host, "[")
	if bracketed {
		if !strings.HasSuffix(host, "]") {
			return socket{}, fmt.Errorf("local address %q has unbalanced brackets", clean(col, 60))
		}
		host = host[1 : len(host)-1]
	}
	a, err := netip.ParseAddr(host)
	// ss brackets IPv6 addresses and only those.
	if err != nil || a.Zone() != "" || bracketed != a.Is6() {
		return socket{}, fmt.Errorf("local address %q has an invalid host", clean(col, 60))
	}
	s.addr = a
	return s, nil
}

// procList renders process names as quoted, sanitised text.
func procList(names []string) string {
	if len(names) == 0 {
		return "unknown"
	}
	var shown []string
	seen := map[string]bool{}
	for _, n := range names {
		q := strconv.Quote(clean(n, maxProcRunes))
		if seen[q] {
			continue
		}
		seen[q] = true
		if len(shown) == maxProcNames {
			shown = append(shown, "...")
			break
		}
		shown = append(shown, q)
	}
	return strings.Join(shown, ", ")
}
