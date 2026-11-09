package probes_test

import (
	"strings"
	"testing"
	"unicode"

	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var (
	ssTCP = []string{"ss", "-Hltnp"}
	ssUDP = []string{"ss", "-Hlunp"}
)

func rule(proto string, port int, bind string) probes.ListenerRule {
	return probes.ListenerRule{Port: port, Proto: proto, Bind: bind}
}

func ssRunner(v, tcp, udp string) *fake.FakeRunner {
	return newRunner().Add(ssTCP, v+"/"+tcp).Add(ssUDP, v+"/"+udp)
}

func listenersProbe(t *testing.T, params map[string]any) probes.Probe {
	return prepare(t, "listeners", params)
}

func TestListenersSSHDOnly(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			p := listenersProbe(t, nil)
			ok := exec(p, ssRunner(v, "ss_tcp_sshd_only", "ss_udp_none"), nil, rule("tcp", 22, "*"))
			wantStatus(t, ok, result.Pass)

			o := exec(p, ssRunner(v, "ss_tcp_sshd_only", "ss_udp_none"), nil)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"tcp/0.0.0.0:22", "tcp/[::]:22"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			if !strings.Contains(o.Evidence[0].Detail, `"sshd"`) {
				t.Fatalf("detail = %q", o.Evidence[0].Detail)
			}

			// Only the IPv4 wildcard is allowed: the IPv6 one is reported.
			o = exec(p, ssRunner(v, "ss_tcp_sshd_only", "ss_udp_none"), nil, rule("tcp", 22, "0.0.0.0"))
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"tcp/[::]:22"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
		})
	}
}

func TestListenersMixed(t *testing.T) {
	allowSSH := rule("tcp", 22, "*")
	cases := []struct {
		name   string
		params map[string]any
		allow  []probes.ListenerRule
		want   []string // failing subjects
	}{
		{"loopback allowed by default", nil, []probes.ListenerRule{allowSSH},
			[]string{"tcp/*:3000", "tcp/0.0.0.0:8080", "tcp/[::]:8443", "udp/0.0.0.0:5353", "udp/[::]:5355"}},
		{"loopback not allowed", map[string]any{"allow_loopback": false}, []probes.ListenerRule{allowSSH},
			[]string{"tcp/*:3000", "tcp/0.0.0.0:8080", "tcp/127.0.0.1:5432", "tcp/[::1]:6379", "tcp/[::]:8443",
				"udp/0.0.0.0:5353", "udp/127.0.0.1:8125", "udp/[::]:5355"}},
		{"wildcard entries allow any address", nil, []probes.ListenerRule{
			allowSSH, rule("tcp", 8080, "*"), rule("tcp", 8443, "*"), rule("tcp", 3000, "*"), rule("udp", 5353, "*"), rule("udp", 5355, "*")}, nil},
		{"exact addresses", nil, []probes.ListenerRule{
			allowSSH, rule("tcp", 8080, "0.0.0.0"), rule("tcp", 8443, "::"), rule("udp", 5353, "0.0.0.0"), rule("udp", 5355, "::")},
			[]string{"tcp/*:3000"}},
		{"the dual-stack star is not the IPv4 wildcard", nil, []probes.ListenerRule{
			allowSSH, rule("tcp", 8080, "0.0.0.0"), rule("tcp", 8443, "::"), rule("tcp", 3000, "0.0.0.0"), rule("tcp", 3000, "::"), rule("udp", 5353, "*"), rule("udp", 5355, "*")},
			[]string{"tcp/*:3000"}},
		{"another address does not match", nil, []probes.ListenerRule{
			allowSSH, rule("tcp", 8080, "127.0.0.1"), rule("tcp", 8443, "192.0.2.1"), rule("tcp", 3000, "*"), rule("udp", 5353, "*"), rule("udp", 5355, "*")},
			[]string{"tcp/0.0.0.0:8080", "tcp/[::]:8443"}},
		{"protocol must match", nil, []probes.ListenerRule{
			allowSSH, rule("udp", 8080, "*"), rule("tcp", 8443, "*"), rule("tcp", 3000, "*"), rule("tcp", 5353, "*"), rule("udp", 5355, "*")},
			[]string{"tcp/0.0.0.0:8080", "udp/0.0.0.0:5353"}},
		{"port must match", nil, []probes.ListenerRule{
			allowSSH, rule("tcp", 8081, "*"), rule("tcp", 8443, "*"), rule("tcp", 3000, "*"), rule("udp", 5353, "*"), rule("udp", 5355, "*")},
			[]string{"tcp/0.0.0.0:8080"}},
		{"tcp only", map[string]any{"protos": []any{"tcp"}}, []probes.ListenerRule{allowSSH},
			[]string{"tcp/*:3000", "tcp/0.0.0.0:8080", "tcp/[::]:8443"}},
		{"udp only", map[string]any{"protos": []any{"udp"}}, nil,
			[]string{"udp/0.0.0.0:5353", "udp/[::]:5355"}},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.name, func(t *testing.T) {
				o := exec(listenersProbe(t, c.params), ssRunner(v, "ss_tcp_mixed", "ss_udp_mixed"), nil, c.allow...)
				if len(c.want) == 0 {
					wantStatus(t, o, result.Pass)
					return
				}
				wantStatus(t, o, result.Fail)
				if !eq(subjects(o), c.want) {
					t.Fatalf("subjects = %v, want %v", subjects(o), c.want)
				}
				for _, e := range o.Evidence {
					if !strings.Contains(e.Detail, `"perl"`) || e.Excepted {
						t.Fatalf("evidence %+v", e)
					}
				}
			})
		}
	}
}

func TestListenersInterfaceSuffix(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			// loopback with an interface suffix is allowed by default ...
			o := exec(listenersProbe(t, nil), ssRunner(v, "ss_tcp_resolved", "ss_udp_resolved"), nil, rule("tcp", 22, "*"))
			wantStatus(t, o, result.Pass)
			// ... and reported, suffix included, when loopback is not allowed
			o = exec(listenersProbe(t, map[string]any{"allow_loopback": false}), ssRunner(v, "ss_tcp_resolved", "ss_udp_resolved"), nil, rule("tcp", 22, "*"))
			wantStatus(t, o, result.Fail)
			var want []string
			for _, s := range subjects(o) {
				if strings.Contains(s, "%lo") {
					want = append(want, s)
				}
			}
			if !eq(want, []string{"tcp/127.0.0.53%lo:53", "udp/127.0.0.53%lo:53"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			// an allowlist entry names the address without the suffix
			o = exec(listenersProbe(t, map[string]any{"allow_loopback": false}), ssRunner(v, "ss_tcp_resolved", "ss_udp_resolved"), nil,
				rule("tcp", 22, "*"), rule("tcp", 53, "127.0.0.53"), rule("udp", 53, "127.0.0.53"))
			for _, s := range subjects(o) {
				if strings.Contains(s, "127.0.0.53%lo") {
					t.Fatalf("allowed listener reported: %v", subjects(o))
				}
			}
		})
	}
}

func TestListenersStrictParsing(t *testing.T) {
	const line = "LISTEN 0      128    0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
	cases := []struct {
		name     string
		tcp, udp string
		tcpExit  int
		want     result.Status
	}{
		{"ok", line, "", 0, result.Pass},
		{"udp only content", "", "UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n", 0, result.Fail},
		{"nothing at all", "", "", 0, result.Error},
		{"blank lines only", "\n\n", "\n", 0, result.Error},
		{"ss failed", line, "", 1, result.Error},
		{"ss failed, exit 2", line, "", 2, result.Error},
		{"wrong state for tcp", "ESTAB 0 0 0.0.0.0:22 0.0.0.0:*\n", "", 0, result.Error},
		{"udp state in tcp output", "UNCONN 0 0 0.0.0.0:22 0.0.0.0:*\n", "", 0, result.Error},
		{"too few columns", "LISTEN 0 128 0.0.0.0:22\n", "", 0, result.Error},
		{"no port", "LISTEN 0 128 0.0.0.0 0.0.0.0:*\n", "", 0, result.Error},
		{"port zero", "LISTEN 0 128 0.0.0.0:0 0.0.0.0:*\n", "", 0, result.Error},
		{"port too large", "LISTEN 0 128 0.0.0.0:65536 0.0.0.0:*\n", "", 0, result.Error},
		{"port with sign", "LISTEN 0 128 0.0.0.0:+22 0.0.0.0:*\n", "", 0, result.Error},
		{"port with leading zero", "LISTEN 0 128 0.0.0.0:022 0.0.0.0:*\n", "", 0, result.Error},
		{"port not a number", "LISTEN 0 128 0.0.0.0:ssh 0.0.0.0:*\n", "", 0, result.Error},
		{"not an address", "LISTEN 0 128 localhost:22 0.0.0.0:*\n", "", 0, result.Error},
		{"unbalanced bracket", "LISTEN 0 128 [::1:22 [::]:*\n", "", 0, result.Error},
		{"brackets around v4 are not valid", "LISTEN 0 128 [0.0.0.0]:22 0.0.0.0:*\n", "", 0, result.Error},
		{"v6 without brackets is not valid", "LISTEN 0 128 ::1:22 [::]:*\n", "", 0, result.Error},
		{"v4 zone is checked", "LISTEN 0 128 192.0.2.1%a/b:22 0.0.0.0:*\n", "", 0, result.Error},
		{"zone inside address", "LISTEN 0 128 [fe80::1%%eth0]:22 [::]:*\n", "", 0, result.Error},
		{"html", "<html>502</html>\n", "", 0, result.Error},
		{"valid line then garbage", line + "garbage\n", "", 0, result.Error},
		{"ipv4 mapped loopback", "LISTEN 0 128 [::ffff:127.0.0.1]:22 [::]:*\n", "", 0, result.Pass},
		{"ipv4 mapped non-loopback", "LISTEN 0 128 [::ffff:192.0.2.1]:22 [::]:*\n", "", 0, result.Fail},
		{"ipv6 link local with zone", "LISTEN 0 128 [fe80::1%eth0]:22 [::]:*\n", "", 0, result.Fail},
		{"127.0.0.2 is loopback", "LISTEN 0 128 127.0.0.2:22 0.0.0.0:*\n", "", 0, result.Pass},
		{"128.0.0.1 is not", "LISTEN 0 128 128.0.0.1:22 0.0.0.0:*\n", "", 0, result.Fail},
	}
	p := listenersProbe(t, nil)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fake.New(nil)
			r.AddResult(ssTCP, inline(c.tcp, c.tcpExit))
			r.AddResult(ssUDP, inline(c.udp, 0))
			// 0.0.0.0:22 is the only allowlisted socket
			wantStatus(t, exec(p, r, nil, rule("tcp", 22, "0.0.0.0")), c.want)
		})
	}
}

func TestListenersUDPErrorWinsOverTCPFail(t *testing.T) {
	r := newRunner().AddResult(ssTCP, inline("LISTEN 0 1 0.0.0.0:9 0.0.0.0:*\n", 0)).AddResult(ssUDP, inline("", 1))
	wantStatus(t, exec(listenersProbe(t, nil), r, nil), result.Error)
	r = newRunner().AddResult(ssTCP, inline("LISTEN 0 1 0.0.0.0:9 0.0.0.0:*\n", 1)).AddResult(ssUDP, inline("UNCONN 0 0 0.0.0.0:9 0.0.0.0:*\n", 0))
	wantStatus(t, exec(listenersProbe(t, nil), r, nil), result.Error)
}

func TestListenersArgv(t *testing.T) {
	r := ssRunner("ubuntu2404", "ss_tcp_sshd_only", "ss_udp_none")
	exec(listenersProbe(t, nil), r, nil, rule("tcp", 22, "*"))
	var got []string
	for _, c := range r.Calls() {
		got = append(got, strings.Join(c.Argv, " "))
	}
	if !eq(got, []string{"ss -Hltnp", "ss -Hlunp"}) {
		t.Fatalf("calls = %v", got)
	}
	r = ssRunner("ubuntu2404", "ss_tcp_sshd_only", "ss_udp_none")
	exec(listenersProbe(t, map[string]any{"protos": []any{"tcp"}}), r, nil, rule("tcp", 22, "*"))
	if len(r.Calls()) != 1 {
		t.Fatalf("protos=[tcp] ran %d commands", len(r.Calls()))
	}
}

func TestListenersProcessNamesAreUntrustedText(t *testing.T) {
	long := strings.Repeat("A", 100)
	tcp := strings.Join([]string{
		// control characters, an ANSI escape and a quote that tries to end the entry
		"LISTEN 0 5 0.0.0.0:1001 0.0.0.0:* users:((\"a\x1b[31mred\x07\",pid=1,fd=3))",
		"LISTEN 0 5 0.0.0.0:1002 0.0.0.0:* users:((\"x\",pid=1,fd=3),(\"y\",pid=2,fd=3))",
		"LISTEN 0 5 0.0.0.0:1003 0.0.0.0:* users:((\"" + long + "\",pid=1,fd=3))",
		"LISTEN 0 5 0.0.0.0:1004 0.0.0.0:*",
		"LISTEN 0 5 0.0.0.0:1005 0.0.0.0:* users:((\"p1\",pid=1,fd=3),(\"p2\",pid=2,fd=3),(\"p3\",pid=3,fd=3),(\"p4\",pid=4,fd=3),(\"p5\",pid=5,fd=3),(\"p6\",pid=6,fd=3),(\"p7\",pid=7,fd=3))",
		"LISTEN 0 5 0.0.0.0:1006 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))", // a process that calls itself sshd is just text
		"LISTEN 0 5 0.0.0.0:1007 0.0.0.0:* users:((\"a b \\\"c\",pid=1,fd=3))",
		"LISTEN 0 5 0.0.0.0:1008 0.0.0.0:* users:((\"\xff\xfe\",pid=1,fd=3))",
		"",
	}, "\n")
	r := newRunner().AddResult(ssTCP, inline(tcp, 0)).AddResult(ssUDP, inline("", 0))
	o := exec(listenersProbe(t, nil), r, nil)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 8 {
		t.Fatalf("evidence = %+v", o.Evidence)
	}
	byPort := map[string]string{}
	for _, e := range o.Evidence {
		byPort[e.Subject] = e.Detail
		for _, r := range e.Detail {
			if !unicode.IsPrint(r) {
				t.Fatalf("detail %q holds a non-printable rune %q", e.Detail, r)
			}
		}
	}
	for subj, want := range map[string]string{
		"tcp/0.0.0.0:1001": `processes: "a?[31mred?"`,
		"tcp/0.0.0.0:1002": `processes: "x", "y"`,
		"tcp/0.0.0.0:1004": `processes: unknown`,
		"tcp/0.0.0.0:1005": `processes: "p1", "p2", "p3", "p4", "p5", ...`,
		"tcp/0.0.0.0:1006": `processes: "sshd"`,
	} {
		if !strings.HasSuffix(byPort[subj], want) {
			t.Errorf("%s detail = %q, want suffix %q", subj, byPort[subj], want)
		}
	}
	if d := byPort["tcp/0.0.0.0:1003"]; !strings.Contains(d, strings.Repeat("A", 32)+`..."`) || strings.Contains(d, strings.Repeat("A", 33)) {
		t.Errorf("long name not cut: %q", d)
	}
	if d := byPort["tcp/0.0.0.0:1008"]; !strings.Contains(d, `"??"`) {
		t.Errorf("invalid utf-8 not replaced: %q", d)
	}
}

func TestListenersSameAddressTwice(t *testing.T) {
	tcp := "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\nLISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=2,fd=3))\n"
	r := newRunner().AddResult(ssTCP, inline(tcp, 0)).AddResult(ssUDP, inline("", 0))
	o := exec(listenersProbe(t, nil), r, nil)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 1 || o.Evidence[0].Subject != "tcp/0.0.0.0:9000" {
		t.Fatalf("evidence = %+v", o.Evidence)
	}
}

func TestListenersFailureModes(t *testing.T) {
	commonFailures(t, listenersProbe(t, nil), ssTCP, "ss", nil)
	commonFailures(t, listenersProbe(t, map[string]any{"protos": []any{"udp"}}), ssUDP, "ss", nil)
}

func TestListenersParams(t *testing.T) {
	listenersProbe(t, map[string]any{"allow_loopback": false, "protos": []any{"udp", "tcp"}})
	listenersProbe(t, map[string]any{"protos": []string{"tcp"}})
	bad := map[string]map[string]any{
		"allow_loopback string": {"allow_loopback": "yes"},
		"allow_loopback int":    {"allow_loopback": 1},
		"protos empty":          {"protos": []any{}},
		"protos not a list":     {"protos": "tcp"},
		"protos unknown":        {"protos": []any{"sctp"}},
		"protos upper case":     {"protos": []any{"TCP"}},
		"protos element int":    {"protos": []any{6}},
		"unknown key":           {"ports": []any{22}},
	}
	for name, params := range bad {
		t.Run(name, func(t *testing.T) { prepareErr(t, "listeners", params) })
	}
}
