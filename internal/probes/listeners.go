package probes

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

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
// It runs "ss -Hltnp" (tcp) and "ss -Hlunp" (udp). Only exit status 0 is
// interpreted. Every output line must be "STATE RECV SEND LOCAL PEER
// [PROCESS]" with state LISTEN (tcp) or UNCONN (udp) and a local address of
// the form host:port, where host is "*", an IPv4 address, an IPv6 address in
// brackets, optionally with a "%interface" suffix. Anything else is error.
// ss prints nothing when nothing listens; if both protocols print nothing
// the result is error, because on a reachable host that is far more likely a
// broken ss than a host without a single listener.
//
// A listener is allowed when an allowlist entry has the same port and
// protocol and a bind that is "*" (any address) or the same address. The
// address "*" that ss prints for a dual-stack socket only matches an entry
// with bind "*". Each listener that is not allowed is one evidence item with
// subject "<proto>/<address>:<port>" (IPv6 in brackets, interface suffix kept)
// and the owning process names in the detail. Process names are text
// chosen by whoever runs the process: they are shown quoted and sanitised
// and never interpreted.
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
	zone  string
	port  int
	procs []string
}

func (s socket) subject() string {
	return fmt.Sprintf("%s/%s:%d", s.proto, s.host(), s.port)
}

func (s socket) host() string {
	if s.any {
		return "*"
	}
	h := s.addr.String() + s.zone
	if s.addr.Is6() {
		return "[" + h + "]"
	}
	return h
}

func (s socket) loopback() bool {
	return !s.any && s.addr.IsLoopback()
}

func (l listenersProbe) Run(ctx context.Context, env *Env) Outcome {
	var socks []socket
	for _, proto := range l.protos {
		flag, state := "-Hltnp", "LISTEN"
		if proto == "udp" {
			flag, state = "-Hlunp", "UNCONN"
		}
		res, out := run(ctx, env, []string{"ss", flag}, 0)
		if out != nil {
			return *out
		}
		if res.ExitCode != 0 {
			return *unexpectedExit("ss", res)
		}
		got, err := parseSS(string(res.Stdout), proto, state)
		if err != nil {
			return *errorOutcome("ss %s: %v", flag, err)
		}
		socks = append(socks, got...)
	}
	if len(socks) == 0 {
		return *errorOutcome("ss reported no listening sockets at all, which cannot be told apart from a broken ss")
	}

	bySubject := map[string]*result.Evidence{}
	var order []string
	for _, s := range socks {
		if (l.allowLoopback && s.loopback()) || allowed(env.ListenerAllow, s) {
			continue
		}
		subj := s.subject()
		detail := "listening, processes: " + procList(s.procs)
		if e, ok := bySubject[subj]; ok {
			// Several sockets on the same address (SO_REUSEPORT): one item.
			e.Detail = detail + " (and others)"
			continue
		}
		bySubject[subj] = &result.Evidence{Subject: subj, Detail: detail}
		order = append(order, subj)
	}
	if len(order) == 0 {
		return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%d listening sockets, all allowed", len(socks))}
	}
	sort.Strings(order)
	ev := make([]result.Evidence, len(order))
	for i, subj := range order {
		ev[i] = *bySubject[subj]
	}
	return Outcome{
		Status:   result.Fail,
		Summary:  fmt.Sprintf("%d of %d listening sockets are not in the allowlist", len(ev), len(socks)),
		Evidence: ev,
	}
}

// allowed reports whether an allowlist entry covers the socket. The "*" that
// ss prints for a dual-stack socket has no address (the zero netip.Addr, which
// no entry parses to), so only an entry with bind "*" covers it.
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

// parseSS parses "ss -H" output for one protocol.
func parseSS(out, proto, wantState string) ([]socket, error) {
	var socks []socket
	for i, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != wantState {
			return nil, fmt.Errorf("line %d does not look like a %s listener: %q", i+1, proto, clean(line, 60))
		}
		s, err := parseLocal(f[3])
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		s.proto = proto
		if len(f) > 5 {
			for _, m := range procEntry.FindAllStringSubmatch(strings.Join(f[5:], " "), -1) {
				s.procs = append(s.procs, m[1])
			}
		}
		socks = append(socks, s)
	}
	return socks, nil
}

// parseLocal parses the local address column: "*:80", "0.0.0.0:22",
// "[::]:22", "127.0.0.53%lo:53", "[fe80::1%eth0]:22".
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
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host, s.zone = host[:j], host[j:]
		if !zonePattern.MatchString(s.zone) {
			return socket{}, fmt.Errorf("local address %q has an invalid interface suffix", clean(col, 60))
		}
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
