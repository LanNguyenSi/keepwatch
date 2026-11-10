package probes_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// The socket set comes from ss without -p; ss with -p only names processes.
var (
	ssTCP  = []string{"ss", "-Hltn"}
	ssUDP  = []string{"ss", "-Hlun"}
	ssTCPp = []string{"ss", "-Hltnp"}
	ssUDPp = []string{"ss", "-Hlunp"}
)

func rule(proto string, port int, bind string) probes.ListenerRule {
	return probes.ListenerRule{Port: port, Proto: proto, Bind: bind}
}

// ssRunner serves the captured fixtures of one scenario ("mixed", "zones",
// ...) for the version v, for all four ss commands.
func ssRunner(v, scenario string) *fake.FakeRunner {
	return newRunner().
		Add(ssTCP, v+"/ss_tcp_"+scenario).Add(ssUDP, v+"/ss_udp_"+scenario).
		Add(ssTCPp, v+"/ssp_tcp_"+scenario).Add(ssUDPp, v+"/ssp_udp_"+scenario)
}

// plain returns ss -p output without its process column: what ss prints
// without -p. Only for lines whose process names hold no newline.
func plain(sspOutput string) string {
	var b strings.Builder
	for _, line := range strings.Split(sspOutput, "\n") {
		if i := strings.Index(line, " users:("); i >= 0 {
			line = line[:i]
		}
		if line != "" {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// pair registers the same listing for ss without -p (stripped) and with -p.
func pair(r *fake.FakeRunner, tcpP, udpP string) *fake.FakeRunner {
	return r.AddResult(ssTCP, inline(plain(tcpP), 0)).AddResult(ssUDP, inline(plain(udpP), 0)).
		AddResult(ssTCPp, inline(tcpP, 0)).AddResult(ssUDPp, inline(udpP, 0))
}

func listenersProbe(t *testing.T, params map[string]any) probes.Probe {
	return prepare(t, "listeners", params)
}

func TestListenersSSHDOnly(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			p := listenersProbe(t, nil)
			ok := exec(p, ssRunner(v, "sshd_only"), nil, rule("tcp", 22, "*"))
			wantStatus(t, ok, result.Pass)

			o := exec(p, ssRunner(v, "sshd_only"), nil)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"tcp/0.0.0.0:22", "tcp/[::]:22"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			if !strings.Contains(o.Evidence[0].Detail, `"sshd"`) {
				t.Fatalf("detail = %q", o.Evidence[0].Detail)
			}

			// Only the IPv4 wildcard is allowed: the IPv6 one is reported.
			o = exec(p, ssRunner(v, "sshd_only"), nil, rule("tcp", 22, "0.0.0.0"))
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
				o := exec(listenersProbe(t, c.params), ssRunner(v, "mixed"), nil, c.allow...)
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
			o := exec(listenersProbe(t, nil), ssRunner(v, "resolved"), nil, rule("tcp", 22, "*"))
			wantStatus(t, o, result.Pass)
			// ... and reported, suffix included, when loopback is not allowed
			o = exec(listenersProbe(t, map[string]any{"allow_loopback": false}), ssRunner(v, "resolved"), nil, rule("tcp", 22, "*"))
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
			o = exec(listenersProbe(t, map[string]any{"allow_loopback": false}), ssRunner(v, "resolved"), nil,
				rule("tcp", 22, "*"), rule("tcp", 53, "127.0.0.53"), rule("udp", 53, "127.0.0.53"))
			for _, s := range subjects(o) {
				if strings.Contains(s, "127.0.0.53%lo") {
					t.Fatalf("allowed listener reported: %v", subjects(o))
				}
			}
		})
	}
}

// The interface suffix of a socket bound to a device comes after the address
// and, for IPv6, after the closing bracket. The fixtures are real ss output
// (sockets bound with SO_BINDTODEVICE to lo and to a dummy interface that
// holds fe80::1).
func TestListenersZoneForms(t *testing.T) {
	allowSSH := rule("tcp", 22, "*")
	all := []string{
		"tcp/*%lo:7002", "tcp/0.0.0.0%lo:7003", "tcp/[::]%lo:7001", "tcp/[::ffff:0.0.0.0]:7006", "tcp/[fe80::1]%dum0:7008",
		"udp/0.0.0.0%lo:7009", "udp/[::]%lo:7004", "udp/[fe80::1]%dum0:7007",
	}
	cases := []struct {
		name  string
		allow []probes.ListenerRule
		want  []string // subjects that stay
	}{
		{"nothing allowed", []probes.ListenerRule{allowSSH}, all},
		{"an entry without the interface allows the zoned address", []probes.ListenerRule{
			allowSSH, rule("tcp", 7001, "::"), rule("tcp", 7003, "0.0.0.0"), rule("tcp", 7008, "fe80::1"),
			rule("udp", 7004, "::"), rule("udp", 7007, "fe80::1"), rule("udp", 7009, "0.0.0.0")},
			[]string{"tcp/*%lo:7002", "tcp/[::ffff:0.0.0.0]:7006"}},
		{"the star entry allows the zoned star and the zoned addresses", []probes.ListenerRule{
			allowSSH, rule("tcp", 7002, "*"), rule("tcp", 7001, "*"), rule("tcp", 7003, "*"), rule("tcp", 7006, "*"), rule("tcp", 7008, "*"),
			rule("udp", 7004, "*"), rule("udp", 7007, "*"), rule("udp", 7009, "*")}, nil},
		{"an address entry does not allow the zoned star", []probes.ListenerRule{
			allowSSH, rule("tcp", 7002, "::"), rule("tcp", 7002, "0.0.0.0")},
			all},
		{"another address does not match", []probes.ListenerRule{
			allowSSH, rule("tcp", 7008, "fe80::2"), rule("tcp", 7001, "0.0.0.0"), rule("udp", 7007, "::1")},
			all},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.name, func(t *testing.T) {
				o := exec(listenersProbe(t, nil), ssRunner(v, "zones"), nil, c.allow...)
				if len(c.want) == 0 {
					wantStatus(t, o, result.Pass)
					return
				}
				wantStatus(t, o, result.Fail)
				if want := sorted(c.want); !eq(subjects(o), want) {
					t.Fatalf("subjects = %v, want %v", subjects(o), want)
				}
				for _, e := range o.Evidence {
					if !strings.Contains(e.Detail, `processes: "perl"`) {
						t.Fatalf("evidence %+v", e)
					}
				}
			})
		}
		t.Run(v+"/a socket bound to a device is not a loopback address", func(t *testing.T) {
			// [::]%lo and 0.0.0.0%lo are wildcard addresses on lo, not ::1 or
			// 127.0.0.1: allow_loopback does not cover them.
			o := exec(listenersProbe(t, nil), ssRunner(v, "zones"), nil, allowSSH)
			for _, want := range []string{"tcp/[::]%lo:7001", "tcp/0.0.0.0%lo:7003", "tcp/*%lo:7002"} {
				if !contains(subjects(o), want) {
					t.Fatalf("%s is missing in %v", want, subjects(o))
				}
			}
			// the loopback address itself stays allowed
			if contains(subjects(o), "tcp/[::ffff:127.0.0.1]:7005") {
				t.Fatalf("loopback listener reported: %v", subjects(o))
			}
		})
	}
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// Zone forms in inline ss output: the accepted ones and the ones that are
// not a form ss prints.
func TestListenersZoneParsing(t *testing.T) {
	allow := []probes.ListenerRule{rule("tcp", 22, "0.0.0.0")}
	cases := []struct {
		name string
		line string
		want result.Status
		subj string // the evidence subject of a fail
	}{
		{"ipv6 outside brackets", "LISTEN 0 128 [fe80::1]%eth0:22 [::]:*", result.Fail, "tcp/[fe80::1]%eth0:22"},
		{"ipv6 wildcard", "LISTEN 0 128 [::]%lo:22 [::]:*", result.Fail, "tcp/[::]%lo:22"},
		{"star", "LISTEN 0 128 *%lo:22 *:*", result.Fail, "tcp/*%lo:22"},
		{"ipv4 allowed by address", "LISTEN 0 128 0.0.0.0%lo:22 0.0.0.0:*", result.Pass, ""},
		{"ipv4 not allowed", "LISTEN 0 128 192.0.2.1%eth0:22 0.0.0.0:*", result.Fail, "tcp/192.0.2.1%eth0:22"},
		{"4in6 with zone", "LISTEN 0 128 [::ffff:192.0.2.1]%lo:22 [::]:*", result.Fail, "tcp/[::ffff:192.0.2.1]%lo:22"},
		{"zone with the characters of real names", "LISTEN 0 128 [::]%br-1a.2_b@x:22 [::]:*", result.Fail, "tcp/[::]%br-1a.2_b@x:22"},
		{"inside the brackets", "LISTEN 0 128 [fe80::1%eth0]:22 [::]:*", result.Error, ""},
		{"inside the brackets, wildcard", "LISTEN 0 128 [::%lo]:22 [::]:*", result.Error, ""},
		{"empty zone", "LISTEN 0 128 [::]%:22 [::]:*", result.Error, ""},
		{"empty zone, star", "LISTEN 0 128 *%:22 *:*", result.Error, ""},
		{"empty zone, ipv4", "LISTEN 0 128 0.0.0.0%:22 0.0.0.0:*", result.Error, ""},
		{"two zones", "LISTEN 0 128 [::]%a%b:22 [::]:*", result.Error, ""},
		{"zone with a slash", "LISTEN 0 128 [::]%a/b:22 [::]:*", result.Error, ""},
		{"zone too long", "LISTEN 0 128 [::]%" + strings.Repeat("a", 33) + ":22 [::]:*", result.Error, ""},
		{"zone before the bracket", "LISTEN 0 128 %lo[::]:22 [::]:*", result.Error, ""},
		{"closing bracket after the zone", "LISTEN 0 128 [::%lo]:22 [::]:*", result.Error, ""},
		{"brackets around ipv4", "LISTEN 0 128 [0.0.0.0]%lo:22 0.0.0.0:*", result.Error, ""},
		{"ipv6 without brackets", "LISTEN 0 128 ::%lo:22 [::]:*", result.Error, ""},
		{"zone only", "LISTEN 0 128 %lo:22 [::]:*", result.Error, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fake.New(nil).AddResult(ssTCP, inline(c.line+"\n", 0)).AddResult(ssUDP, inline("", 0))
			o := exec(listenersProbe(t, map[string]any{"protos": []any{"tcp", "udp"}}), r, nil, allow...)
			wantStatus(t, o, c.want)
			if c.want == result.Fail && !eq(subjects(o), []string{c.subj}) {
				t.Fatalf("subjects = %v, want %s", subjects(o), c.subj)
			}
		})
	}
	t.Run("udp", func(t *testing.T) {
		r := fake.New(nil).AddResult(ssTCP, inline("", 0)).AddResult(ssUDP, inline("UNCONN 0 0 [fe80::1]%eth0:546 [::]:*\n", 0))
		o := exec(listenersProbe(t, nil), r, nil)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"udp/[fe80::1]%eth0:546"}) {
			t.Fatalf("subjects = %v", subjects(o))
		}
	})
}

// A process name is chosen by the process, and a name that holds a newline
// breaks the line structure of ss -p. The fixture is real ss output of a
// process that renamed itself to "a\nLISTEN 0 0 x" and listens on three
// ports. The socket set comes from ss without -p, so the check neither
// errors nor loses them.
func TestListenersNewlineInProcessName(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			r := ssRunner(v, "newline")
			// the fixture really holds the broken line structure
			raw, _ := r.Run(context.Background(), ssTCPp, execx.Opts{})
			if !strings.Contains(string(raw.Stdout), "\"a\nLISTEN 0 0 x\"") {
				t.Fatalf("fixture does not hold the newline name: %q", raw.Stdout)
			}
			o := exec(listenersProbe(t, nil), r, nil, rule("tcp", 22, "*"))
			wantStatus(t, o, result.Fail)
			want := []string{"tcp/0.0.0.0:7020", "tcp/[::]:7021", "udp/0.0.0.0:7022"}
			if !eq(subjects(o), want) {
				t.Fatalf("subjects = %v, want %v", subjects(o), want)
			}
			for _, e := range o.Evidence {
				if !strings.Contains(e.Detail, "processes: unknown") || !strings.Contains(e.Detail, "may be missing") {
					t.Fatalf("detail = %q", e.Detail)
				}
			}
		})
	}
}

// Whatever the -p output says, it cannot add, remove or alter a socket.
func TestListenersProcessOutputCannotChangeTheSocketSet(t *testing.T) {
	socketsTCP := "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\nLISTEN 0 5 0.0.0.0:9001 0.0.0.0:*\n"
	cases := []struct {
		name string
		p    string // the -p output for tcp
		want map[string]string
	}{
		{"a fake socket line in a name", "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"a\nLISTEN 0 0 *:1\",pid=9,fd=3))\n" +
			"LISTEN 0 5 0.0.0.0:9001 0.0.0.0:* users:((\"ok\",pid=2,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": "processes: unknown", "tcp/0.0.0.0:9001": `processes: "ok"`}},
		{"a whole fake record", "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"a\n" + "LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:((\"nc\",pid=3,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": "processes: unknown", "tcp/0.0.0.0:9001": "processes: unknown"}},
		{"a socket that only -p knows", "LISTEN 0 5 0.0.0.0:4444 0.0.0.0:* users:((\"nc\",pid=3,fd=3))\n" +
			"LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": `processes: "w"`, "tcp/0.0.0.0:9001": "processes: unknown"}},
		{"a record that names another process", "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\n" +
			"LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"evil\",pid=2,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": `processes: "w", "evil"`, "tcp/0.0.0.0:9001": "processes: unknown"}},
		{"a record cut after a complete entry", "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3),(\"a\nLISTEN 0 0 x\",pid=2,fd=3))\n" +
			"LISTEN 0 5 0.0.0.0:9001 0.0.0.0:* users:((\"ok\",pid=2,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": "processes: unknown", "tcp/0.0.0.0:9001": `processes: "ok"`}},
		{"an empty -p listing", "", map[string]string{"tcp/0.0.0.0:9000": "processes: unknown", "tcp/0.0.0.0:9001": "processes: unknown"}},
		{"a name that ends its own entry", "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"x\",pid=1,fd=3),(\"LISTEN 0 5 0.0.0.0:4444 0.0.0.0:*\",pid=2,fd=3))\n",
			map[string]string{"tcp/0.0.0.0:9000": `processes: "x", "LISTEN 0 5 0.0.0.0:4444 0.0.0.0:..."`, "tcp/0.0.0.0:9001": "processes: unknown"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fake.New(nil).AddResult(ssTCP, inline(socketsTCP, 0)).AddResult(ssUDP, inline("", 0)).
				AddResult(ssTCPp, inline(c.p, 0)).AddResult(ssUDPp, inline("", 0))
			o := exec(listenersProbe(t, nil), r, nil)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"tcp/0.0.0.0:9000", "tcp/0.0.0.0:9001"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			for _, e := range o.Evidence {
				if !strings.Contains(e.Detail, c.want[e.Subject]) {
					t.Errorf("%s detail = %q, want it to contain %q", e.Subject, e.Detail, c.want[e.Subject])
				}
			}
		})
	}
}

// A failing, slow, cut or unreadable -p run only leaves the processes unknown.
func TestListenersProcessRunFailureOnlyHidesNames(t *testing.T) {
	sockets := "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\nLISTEN 0 5 [::]:9000 [::]:*\n"
	cases := []struct {
		name string
		add  func(*fake.FakeRunner)
	}{
		{"exit status 1", func(r *fake.FakeRunner) { r.AddResult(ssTCPp, inline("", 1)) }},
		{"exit status 255 with output", func(r *fake.FakeRunner) {
			r.AddResult(ssTCPp, inline("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\n", 255))
		}},
		{"timeout", func(r *fake.FakeRunner) { r.AddError(ssTCPp, execx.ErrTimeout) }},
		{"io timeout", func(r *fake.FakeRunner) { r.AddError(ssTCPp, execx.ErrIOTimeout) }},
		{"not allowlisted", func(r *fake.FakeRunner) { r.AddError(ssTCPp, execx.ErrNotAllowed) }},
		{"not found", func(r *fake.FakeRunner) { r.AddError(ssTCPp, execx.ErrNotFound) }},
		{"other error", func(r *fake.FakeRunner) { r.AddError(ssTCPp, os.ErrPermission) }},
		{"truncated", func(r *fake.FakeRunner) {
			r.AddResult(ssTCPp, execx.Result{Stdout: []byte("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\n"), Truncated: true})
		}},
		{"killed", func(r *fake.FakeRunner) { r.AddResult(ssTCPp, execx.Result{ExitCode: -1, Signaled: true}) }},
		{"html", func(r *fake.FakeRunner) { r.AddResult(ssTCPp, inline("<html>502</html>\n", 0)) }},
		{"half a record", func(r *fake.FakeRunner) {
			r.AddResult(ssTCPp, inline("LISTEN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\n", 0))
		}},
		{"wrong state", func(r *fake.FakeRunner) {
			r.AddResult(ssTCPp, inline("UNCONN 0 5 0.0.0.0:9000 0.0.0.0:* users:((\"w\",pid=1,fd=3))\n", 0))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fake.New(nil).AddResult(ssTCP, inline(sockets, 0)).AddResult(ssUDP, inline("", 0)).AddResult(ssUDPp, inline("", 0))
			c.add(r)
			o := exec(listenersProbe(t, nil), r, nil)
			wantStatus(t, o, result.Fail)
			if !eq(subjects(o), []string{"tcp/0.0.0.0:9000", "tcp/[::]:9000"}) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			for _, e := range o.Evidence {
				if !strings.Contains(e.Detail, "processes: unknown") {
					t.Errorf("detail = %q", e.Detail)
				}
			}
		})
	}
	t.Run("every ss -p run fails and the sockets are all allowed", func(t *testing.T) {
		r := fake.New(nil).AddResult(ssTCP, inline(sockets, 0)).AddResult(ssUDP, inline("", 0)).
			AddError(ssTCPp, execx.ErrTimeout).AddError(ssUDPp, execx.ErrTimeout)
		wantStatus(t, exec(listenersProbe(t, nil), r, nil, rule("tcp", 9000, "*")), result.Pass)
	})
}

// ss -p runs only when there is something to name, and never decides alone.
func TestListenersProcessRunOnlyWhenNeeded(t *testing.T) {
	calls := func(r *fake.FakeRunner) []string {
		var got []string
		for _, c := range r.Calls() {
			got = append(got, strings.Join(c.Argv, " "))
		}
		return got
	}
	sockets := "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*\n"
	r := fake.New(nil).AddResult(ssTCP, inline(sockets, 0)).AddResult(ssUDP, inline("", 0))
	wantStatus(t, exec(listenersProbe(t, nil), r, nil, rule("tcp", 9000, "*")), result.Pass)
	if want := []string{"ss -Hltn", "ss -Hlun"}; !eq(calls(r), want) {
		t.Fatalf("calls = %v, want %v", calls(r), want)
	}
	r = fake.New(nil).AddResult(ssTCP, inline(sockets, 0)).AddResult(ssUDP, inline("", 0))
	wantStatus(t, exec(listenersProbe(t, nil), r, nil), result.Fail)
	if want := []string{"ss -Hltn", "ss -Hlun", "ss -Hltnp", "ss -Hlunp"}; !eq(calls(r), want) {
		t.Fatalf("calls = %v, want %v", calls(r), want)
	}
	r = fake.New(nil).AddResult(ssTCP, inline(sockets, 0))
	wantStatus(t, exec(listenersProbe(t, map[string]any{"protos": []any{"tcp"}}), r, nil), result.Fail)
	if want := []string{"ss -Hltn", "ss -Hltnp"}; !eq(calls(r), want) {
		t.Fatalf("calls = %v, want %v", calls(r), want)
	}
}

func TestListenersStrictParsing(t *testing.T) {
	const line = "LISTEN 0      128    0.0.0.0:22 0.0.0.0:*\n"
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
		{"a process column is not accepted", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", "", 0, result.Error},
		{"a sixth column", "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* x\n", "", 0, result.Error},
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
		{"html", "<html>502</html>\n", "", 0, result.Error},
		{"valid line then garbage", line + "garbage\n", "", 0, result.Error},
		{"ipv4 mapped loopback", "LISTEN 0 128 [::ffff:127.0.0.1]:22 [::]:*\n", "", 0, result.Pass},
		{"ipv4 mapped non-loopback", "LISTEN 0 128 [::ffff:192.0.2.1]:22 [::]:*\n", "", 0, result.Fail},
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

// An error keeps the failing listeners that the other protocol confirmed,
// and says the picture is partial.
func TestListenersErrorKeepsConfirmedEvidence(t *testing.T) {
	tcpBad := "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\nLISTEN 0 5 [::]:8080 [::]:*\n"
	udpBad := "UNCONN 0 0 0.0.0.0:5353 0.0.0.0:*\n"
	cases := []struct {
		name         string
		tcp, udp     execx.Result
		wantSubjects []string
		wantSummary  []string
	}{
		{"tcp confirmed, udp exits 1", inline(tcpBad, 0), inline("", 1),
			[]string{"tcp/0.0.0.0:8080", "tcp/[::]:8080"}, []string{"udp: ss exited with status 1", "partial", "tcp/0.0.0.0:8080, tcp/[::]:8080"}},
		{"udp confirmed, tcp exits 1", inline("", 1), inline(udpBad, 0),
			[]string{"udp/0.0.0.0:5353"}, []string{"tcp: ss exited with status 1", "partial", "udp/0.0.0.0:5353"}},
		{"tcp confirmed, udp output unparseable", inline(tcpBad, 0), inline("garbage\n", 0),
			[]string{"tcp/0.0.0.0:8080", "tcp/[::]:8080"}, []string{"ss -Hlun", "partial"}},
		{"tcp confirmed, udp truncated: its complete lines count too", inline(tcpBad, 0), execx.Result{Stdout: []byte(udpBad), Truncated: true},
			[]string{"tcp/0.0.0.0:8080", "tcp/[::]:8080", "udp/0.0.0.0:5353"}, []string{"truncated", "partial"}},
		{"tcp confirmed, udp killed", inline(tcpBad, 0), execx.Result{ExitCode: -1, Signaled: true},
			[]string{"tcp/0.0.0.0:8080", "tcp/[::]:8080"}, []string{"terminated", "partial"}},
		{"tcp allowed, udp exits 1: nothing to keep", inline("LISTEN 0 5 0.0.0.0:22 0.0.0.0:*\n", 0), inline("", 1),
			nil, []string{"udp: ss exited with status 1"}},
		{"both fail: nothing to keep", inline("", 1), inline("", 2), nil, []string{"tcp: ", "udp: "}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(ssTCP, c.tcp).AddResult(ssUDP, c.udp)
			o := exec(listenersProbe(t, nil), r, nil, rule("tcp", 22, "*"))
			wantStatus(t, o, result.Error)
			if !eq(subjects(o), c.wantSubjects) {
				t.Fatalf("subjects = %v, want %v", subjects(o), c.wantSubjects)
			}
			for _, sub := range c.wantSummary {
				wantSummary(t, o, sub)
			}
			if len(c.wantSubjects) == 0 && strings.Contains(o.Summary, "partial") {
				t.Fatalf("summary %q claims a partial picture without evidence", o.Summary)
			}
		})
	}
}

func TestListenersArgv(t *testing.T) {
	r := ssRunner("ubuntu2404", "sshd_only")
	exec(listenersProbe(t, nil), r, nil, rule("tcp", 22, "*"))
	var got []string
	for _, c := range r.Calls() {
		got = append(got, strings.Join(c.Argv, " "))
	}
	if !eq(got, []string{"ss -Hltn", "ss -Hlun"}) {
		t.Fatalf("calls = %v", got)
	}
	r = ssRunner("ubuntu2404", "sshd_only")
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
	r := pair(newRunner(), tcp, "")
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
	o := exec(listenersProbe(t, nil), pair(newRunner(), tcp, ""), nil)
	wantStatus(t, o, result.Fail)
	if len(o.Evidence) != 1 || o.Evidence[0].Subject != "tcp/0.0.0.0:9000" {
		t.Fatalf("evidence = %+v", o.Evidence)
	}
}

func TestListenersFailureModes(t *testing.T) {
	// the other protocol answers, so the failure under test is the only one
	commonFailures(t, listenersProbe(t, nil), ssTCP, "ss", nil,
		func(f *fake.FakeRunner) { f.AddResult(ssUDP, inline("", 0)) })
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

// A truncated trusted run is never pass: the complete lines of the prefix are
// examined, the not allowed sockets there stay as evidence, the status is error.
func TestListenersTruncatedOutput(t *testing.T) {
	good := "LISTEN 0 5 0.0.0.0:22 0.0.0.0:*\n"
	bad := "LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\n"
	udpOK := inline("UNCONN 0 0 0.0.0.0:22 0.0.0.0:*\n", 0)
	trunc := func(s string) execx.Result { return execx.Result{Stdout: []byte(s), Truncated: true} }
	cases := []struct {
		name     string
		tcp      execx.Result
		wantSubj []string
		partial  bool
	}{
		{"complete lines with an unallowed socket", trunc(good + bad), []string{"tcp/0.0.0.0:8080"}, true},
		{"cut last line is dropped, earlier ones kept", trunc(good + bad + "LISTEN 0 5 0.0.0.0:99"), []string{"tcp/0.0.0.0:8080"}, true},
		{"only the cut last line would be unallowed", trunc(good + "LISTEN 0 5 0.0.0.0:80"), nil, false},
		{"no complete line at all", trunc("LISTEN 0 5 0.0"), nil, false},
		{"only allowed sockets before the cut", trunc(good), nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(ssTCP, c.tcp).AddResult(ssUDP, udpOK).
				AddResult(ssTCPp, inline(bad, 0)).AddResult(ssUDPp, inline("", 0))
			o := exec(listenersProbe(t, nil), r, nil, rule("tcp", 22, "*"), rule("udp", 22, "*"))
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "truncated")
			if !eq(subjects(o), c.wantSubj) {
				t.Fatalf("subjects = %v, want %v", subjects(o), c.wantSubj)
			}
			if c.partial {
				wantSummary(t, o, "partial")
			} else if strings.Contains(o.Summary, "partial") {
				t.Fatalf("summary %q claims a partial picture without evidence", o.Summary)
			}
		})
	}
}

// A complete line of a truncated run that does not parse is an error without
// evidence from that run, as for any output.
func TestListenersTruncatedGarbageLine(t *testing.T) {
	r := newRunner().AddResult(ssTCP, execx.Result{Stdout: []byte("LISTEN 0 5 0.0.0.0:8080 0.0.0.0:*\ngarbage\n"), Truncated: true}).
		AddResult(ssUDP, inline("UNCONN 0 0 0.0.0.0:22 0.0.0.0:*\n", 0))
	o := exec(listenersProbe(t, nil), r, nil, rule("udp", 22, "*"))
	wantStatus(t, o, result.Error)
	if len(o.Evidence) != 0 {
		t.Fatalf("evidence from an unparseable run: %+v", o.Evidence)
	}
}

// The runs that decide the socket set get the 64 MiB limit; the best-effort
// -p runs keep the execx default (zero).
func TestListenersOutputLimits(t *testing.T) {
	r := ssRunner("ubuntu2404", "mixed")
	exec(listenersProbe(t, nil), r, nil)
	seen := map[string]int64{}
	for _, c := range r.Calls() {
		seen[strings.Join(c.Argv, " ")] = c.Opts.MaxOutput
	}
	for _, a := range []string{"ss -Hltn", "ss -Hlun"} {
		if seen[a] != 64<<20 {
			t.Errorf("%s: MaxOutput = %d, want %d", a, seen[a], int64(64<<20))
		}
	}
	for _, a := range []string{"ss -Hltnp", "ss -Hlunp"} {
		v, ok := seen[a]
		if !ok {
			t.Fatalf("%s was not run", a)
		}
		if v != 0 {
			t.Errorf("%s: MaxOutput = %d, want the default (0)", a, v)
		}
	}
}

// A local user can open tens of thousands of sockets. At most 100 evidence
// items come back, sorted by subject: 99 sockets and a marker that says how
// many are not shown. The status does not change.
func TestListenersEvidenceIsLimited(t *testing.T) {
	flood := func(n int) *fake.FakeRunner {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "LISTEN 0 5 0.0.0.0:%d 0.0.0.0:*\n", 10000+i)
		}
		return newRunner().AddResult(ssTCP, inline(sb.String(), 0)).AddResult(ssUDP, inline("", 0)).
			AddResult(ssTCPp, inline("", 0)).AddResult(ssUDPp, inline("", 0))
	}
	t.Run("exactly 100 are all shown", func(t *testing.T) {
		o := exec(listenersProbe(t, nil), flood(100), nil)
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 100 || strings.Contains(o.Evidence[99].Subject, "more not shown") || strings.Contains(o.Summary, "and") {
			t.Fatalf("%d items, last %+v, summary %q", len(o.Evidence), o.Evidence[99], o.Summary)
		}
	})
	t.Run("101 are cut", func(t *testing.T) {
		o := exec(listenersProbe(t, nil), flood(101), nil)
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 100 || o.Evidence[99].Subject != "(2 more not shown)" {
			t.Fatalf("%d items, last %+v", len(o.Evidence), o.Evidence[len(o.Evidence)-1])
		}
		wantSummary(t, o, "and 2 more")
	})
	t.Run("sorted by subject, the first 99 shown", func(t *testing.T) {
		o := exec(listenersProbe(t, nil), flood(500), nil)
		wantStatus(t, o, result.Fail)
		if len(o.Evidence) != 100 {
			t.Fatalf("%d items", len(o.Evidence))
		}
		for i := 1; i < 99; i++ {
			if o.Evidence[i-1].Subject >= o.Evidence[i].Subject {
				t.Fatalf("not sorted at %d: %q %q", i, o.Evidence[i-1].Subject, o.Evidence[i].Subject)
			}
		}
		if o.Evidence[0].Subject != "tcp/0.0.0.0:10000" || o.Evidence[98].Subject != "tcp/0.0.0.0:10098" || o.Evidence[99].Subject != "(401 more not shown)" {
			t.Fatalf("first %q, 99th %q, marker %q", o.Evidence[0].Subject, o.Evidence[98].Subject, o.Evidence[99].Subject)
		}
		wantSummary(t, o, "500 listening sockets")
		wantSummary(t, o, "and 401 more")
	})
	t.Run("a partial error is limited the same way", func(t *testing.T) {
		r := flood(300).AddError(ssUDP, execx.ErrTimeout)
		o := exec(listenersProbe(t, nil), r, nil)
		wantStatus(t, o, result.Error)
		if len(o.Evidence) != 100 {
			t.Fatalf("%d items", len(o.Evidence))
		}
		wantSummary(t, o, "also found")
		wantSummary(t, o, "and 295 more")
	})
}
