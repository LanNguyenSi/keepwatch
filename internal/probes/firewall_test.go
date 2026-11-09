package probes_test

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var (
	fwNft   = []string{"nft", "-j", "list", "ruleset"}
	fwUfw   = []string{"ufw", "status", "verbose"}
	fwIpt   = []string{"iptables", "-S", "INPUT"}
	fwIpt6  = []string{"ip6tables", "-S", "INPUT"}
	fwAllOf = [][]string{fwNft, fwUfw, fwIpt, fwIpt6}
)

func fwProbe(t *testing.T) probes.Probe { return prepare(t, "firewall_default", nil) }

// fwFixtures serves the four captured commands of one scenario.
func fwFixtures(v, scenario string) *fake.FakeRunner {
	p := v + "/fw_" + scenario + "_"
	return newRunner().Add(fwUfw, p+"ufw").Add(fwNft, p+"nft").Add(fwIpt, p+"iptables").Add(fwIpt6, p+"ip6tables")
}

// A minimal nft document with the given chains; each chain is
// "family table name type hook policy".
func nftDoc(chains ...string) string {
	var b strings.Builder
	b.WriteString(`{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}`)
	tables := map[string]bool{}
	for _, c := range chains {
		f := strings.Fields(c)
		if !tables[f[0]+f[1]] {
			tables[f[0]+f[1]] = true
			b.WriteString(`, {"table": {"family": "` + f[0] + `", "name": "` + f[1] + `", "handle": 1}}`)
		}
		b.WriteString(`, {"chain": {"family": "` + f[0] + `", "table": "` + f[1] + `", "name": "` + f[2] + `", "handle": 1, "type": "` + f[3] + `", "hook": "` + f[4] + `", "prio": 0, "policy": "` + f[5] + `"}}`)
	}
	b.WriteString("]}")
	return b.String()
}

func TestFirewallCapturedScenarios(t *testing.T) {
	cases := []struct {
		scenario string
		want     result.Status
		subjects []string
		sub      string
	}{
		{"none", result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"ufw_deny", result.Pass, nil, "iptables INPUT policy DROP"},
		{"ufw_reject", result.Pass, nil, "default for incoming packets: reject"},
		{"ufw_allow", result.Fail, []string{"input/ipv4", "input/ipv6"}, "ufw: active, default for incoming packets: allow"},
		// ufw says deny, the rules were reset behind its back: the kernel decides
		{"ufw_stale", result.Fail, []string{"input/ipv4", "input/ipv6"}, "ufw reports deny but the kernel does not drop them"},
		{"nft_drop_inet", result.Pass, nil, "nftables inet kw/input"},
		{"nft_drop_ip4", result.Fail, []string{"input/ipv6"}, "IPv6 incoming packets are accepted"},
		{"nft_drop_ip6", result.Fail, []string{"input/ipv4"}, "IPv4 incoming packets are accepted"},
		{"nft_accept_inet", result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		// a forward chain with policy drop is not a default for incoming packets
		{"nft_forward_drop", result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		// the table is not hooked, so its drop chain does nothing
		{"nft_dormant", result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"ipt_drop", result.Pass, nil, "iptables INPUT policy DROP"},
		{"ipt_drop4", result.Fail, []string{"input/ipv6"}, ""},
		// a running Docker daemon changes forward and nat chains, not the input policy
		{"docker", result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.scenario, func(t *testing.T) {
				o := exec(fwProbe(t), fwFixtures(v, c.scenario), nil)
				wantStatus(t, o, c.want)
				if c.want == result.Fail && !eq(subjects(o), c.subjects) {
					t.Fatalf("subjects = %v, want %v", subjects(o), c.subjects)
				}
				if c.want == result.Pass && len(o.Evidence) != 0 {
					t.Fatalf("pass with evidence %+v", o.Evidence)
				}
				if c.sub != "" && !strings.Contains(allText(o), c.sub) {
					t.Fatalf("%q lacks %q", allText(o), c.sub)
				}
			})
		}
	}
}

// Without root every command fails; none of that is a pass.
func TestFirewallNotRootIsError(t *testing.T) {
	for _, v := range versions {
		t.Run(v, func(t *testing.T) {
			o := exec(fwProbe(t), fwFixtures(v, "notroot"), nil)
			wantStatus(t, o, result.Error)
			wantSummary(t, o, "nft exited with status 1")
			if len(o.Evidence) != 0 {
				t.Fatalf("evidence %+v", o.Evidence)
			}
		})
	}
}

// allText is the summary and every evidence detail of an outcome.
func allText(o probes.Outcome) string {
	s := o.Summary
	for _, e := range o.Evidence {
		s += " | " + e.Detail
	}
	return s
}

func fwRunner(nft, ipt4, ipt6 string, ufw string) *fake.FakeRunner {
	r := newRunner()
	r.AddResult(fwNft, inline(nft, 0)).AddResult(fwIpt, inline(ipt4, 0)).AddResult(fwIpt6, inline(ipt6, 0))
	if ufw == "" {
		r.AddError(fwUfw, execx.ErrNotFound)
	} else {
		r.AddResult(fwUfw, inline(ufw, 0))
	}
	return r
}

const (
	nftNothing = `{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]}`
	iptDrop    = "-P INPUT DROP\n-A INPUT -j ufw-before-input\n"
	iptAccept  = "-P INPUT ACCEPT\n"
)

func TestFirewallDropInAnySourcePasses(t *testing.T) {
	cases := []struct {
		name            string
		nft, ipt4, ipt6 string
		want            result.Status
		subjects        []string
		sub             string
	}{
		{"iptables drop both, nft empty", nftNothing, iptDrop, iptDrop, result.Pass, nil, "IPv6 by ip6tables"},
		{"nft inet drop, iptables accept", nftDoc("inet f in filter input drop"), iptAccept, iptAccept, result.Pass, nil, "nftables inet f/in"},
		{"v4 by nft ip, v6 by ip6tables", nftDoc("ip f in filter input drop"), iptAccept, iptDrop, result.Pass, nil, ""},
		{"v4 only", nftNothing, iptDrop, iptAccept, result.Fail, []string{"input/ipv6"}, ""},
		{"v6 only", nftNothing, iptAccept, iptDrop, result.Fail, []string{"input/ipv4"}, ""},
		{"nothing drops", nftNothing, iptAccept, iptAccept, result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"nat chain on input does not count", nftDoc("ip n in nat input drop"), iptAccept, iptAccept, result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"prerouting does not count", nftDoc("inet f pre filter prerouting drop"), iptAccept, iptAccept, result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"bridge family does not count", nftDoc("bridge f in filter input drop"), iptAccept, iptAccept, result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"accept policy chain", nftDoc("inet f in filter input accept"), iptAccept, iptAccept, result.Fail, []string{"input/ipv4", "input/ipv6"}, ""},
		{"drop in one of two input chains", nftDoc("inet f a filter input accept", "inet f b filter input drop"), iptAccept, iptAccept, result.Pass, nil, "inet f/b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := exec(fwProbe(t), fwRunner(c.nft, c.ipt4, c.ipt6, ""), nil)
			wantStatus(t, o, c.want)
			if c.want == result.Fail && !eq(subjects(o), c.subjects) {
				t.Fatalf("subjects = %v", subjects(o))
			}
			if c.sub != "" && !strings.Contains(allText(o), c.sub) {
				t.Fatalf("%q lacks %q", allText(o), c.sub)
			}
		})
	}
}

func TestFirewallSourceFailures(t *testing.T) {
	t.Run("nft unreadable but iptables drops both", func(t *testing.T) {
		r := fwRunner(nftNothing, iptDrop, iptDrop, "").AddResult(fwNft, execx.Result{ExitCode: 1, Stderr: []byte("Operation not permitted\n")})
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Pass)
		wantSummary(t, o, "not read")
	})
	t.Run("nft unreadable and iptables accepts: might drop, so error", func(t *testing.T) {
		r := fwRunner(nftNothing, iptAccept, iptAccept, "").AddError(fwNft, execx.ErrTimeout)
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "timed out")
	})
	t.Run("ip6tables unreadable, v6 not otherwise covered", func(t *testing.T) {
		r := fwRunner(nftNothing, iptDrop, iptDrop, "").AddResult(fwIpt6, execx.Result{ExitCode: 4, Stderr: []byte("denied\n")})
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Error)
	})
	t.Run("only iptables present: no source for IPv6", func(t *testing.T) {
		r := fwRunner(nftNothing, iptDrop, iptDrop, "").AddError(fwNft, execx.ErrNotFound).AddError(fwIpt6, execx.ErrNotFound)
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "no readable source for IPv6")
	})
	t.Run("only nft present and it drops", func(t *testing.T) {
		r := fwRunner(nftDoc("inet f in filter input drop"), "", "", "").AddError(fwIpt, execx.ErrNotFound).AddError(fwIpt6, execx.ErrNotFound)
		wantStatus(t, exec(fwProbe(t), r, nil), result.Pass)
	})
	t.Run("only nft present and it accepts", func(t *testing.T) {
		r := fwRunner(nftNothing, "", "", "").AddError(fwIpt, execx.ErrNotFound).AddError(fwIpt6, execx.ErrNotFound)
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Fail)
		if !eq(subjects(o), []string{"input/ipv4", "input/ipv6"}) {
			t.Fatalf("subjects %v", subjects(o))
		}
	})
	t.Run("nothing installed", func(t *testing.T) {
		r := newRunner()
		for _, a := range fwAllOf {
			r.AddError(a, execx.ErrNotFound)
		}
		o := exec(fwProbe(t), r, nil)
		wantStatus(t, o, result.Skipped)
	})
	t.Run("not allowlisted", func(t *testing.T) {
		o := exec(fwProbe(t), fwRunner(nftNothing, iptDrop, iptDrop, "").AddError(fwNft, execx.ErrNotAllowed), nil)
		wantStatus(t, o, result.Pass) // iptables still drops both
		o = exec(fwProbe(t), fwRunner(nftNothing, iptAccept, iptAccept, "").AddError(fwNft, execx.ErrNotAllowed), nil)
		wantStatus(t, o, result.Error)
		wantSummary(t, o, "allowlist")
	})
	for name, res := range map[string]execx.Result{
		"truncated": {Stdout: []byte(nftDoc("inet f in filter input drop")), Truncated: true},
		"signaled":  {Stdout: []byte(nftDoc("inet f in filter input drop")), Signaled: true, ExitCode: -1},
		"exit 1":    {Stdout: []byte(nftDoc("inet f in filter input drop")), ExitCode: 1},
	} {
		t.Run("nft "+name+" never counts as a drop", func(t *testing.T) {
			r := fwRunner(nftNothing, iptAccept, iptAccept, "").AddResult(fwNft, res)
			o := exec(fwProbe(t), r, nil)
			wantStatus(t, o, result.Error)
		})
	}
}

func TestFirewallGarbageIsNeverAPass(t *testing.T) {
	garbage := []string{
		"", "null", "[]", "{}", `{"nftables": null}`, `{"nftables": []}`, "not json", `{"nftables": [{"metainfo": {"json_schema_version": 2}}]}`,
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"metainfo": {"json_schema_version": 1}}]}`,
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, "x"]}`,
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"chain": {"family": "inet"}}]}`,
		// a drop chain whose table is not listed
		`{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"chain": {"family": "inet", "table": "t", "name": "c", "type": "filter", "hook": "input", "policy": "drop"}}]}`,
		// an unknown policy on an input chain
		nftDoc("inet f in filter input maybe"),
		nftDoc("inet f in filter input drop") + " trailing",
	}
	for i, g := range garbage {
		t.Run("nft "+string(rune('a'+i)), func(t *testing.T) {
			o := exec(fwProbe(t), fwRunner(g, iptAccept, iptAccept, ""), nil)
			if o.Status == result.Pass {
				t.Fatalf("pass on %q", g)
			}
		})
	}
	badIpt := []string{
		"", "\n", "-P INPUT\n", "-P INPUT REJECT\n", "-P INPUT DROP\n-P INPUT DROP\n", "-P FORWARD DROP\n", "-A INPUT -j ACCEPT\n",
		"-P INPUT DROP\nsomething else\n", "-P INPUT DROP\n-N foo\n", "-p INPUT DROP\n",
	}
	for i, g := range badIpt {
		t.Run("iptables "+string(rune('a'+i)), func(t *testing.T) {
			o := exec(fwProbe(t), fwRunner(nftNothing, g, iptAccept, ""), nil)
			if o.Status == result.Pass {
				t.Fatalf("pass on %q", g)
			}
			o = exec(fwProbe(t), fwRunner(nftNothing, iptAccept, g, ""), nil)
			if o.Status == result.Pass {
				t.Fatalf("pass on %q for ip6tables", g)
			}
		})
	}
}

func TestFirewallUFWOnlyExplains(t *testing.T) {
	deny := "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"
	t.Run("deny from ufw alone does not pass", func(t *testing.T) {
		o := exec(fwProbe(t), fwRunner(nftNothing, iptAccept, iptAccept, deny), nil)
		wantStatus(t, o, result.Fail)
		if !strings.Contains(o.Evidence[0].Detail, "ufw reports deny but the kernel does not drop them") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
	t.Run("unreadable ufw changes nothing", func(t *testing.T) {
		for _, u := range []string{"garbage\n", "Status: active\n", "Status: active\nDefault: sideways (incoming), allow (outgoing)\n", "Status: inactive extra\n"} {
			wantStatus(t, exec(fwProbe(t), fwRunner(nftNothing, iptDrop, iptDrop, u), nil), result.Pass)
			wantStatus(t, exec(fwProbe(t), fwRunner(nftNothing, iptAccept, iptAccept, u), nil), result.Fail)
		}
		r := fwRunner(nftNothing, iptDrop, iptDrop, "").AddResult(fwUfw, execx.Result{ExitCode: 1, Stderr: []byte("ERROR: You need to be root\n")})
		wantStatus(t, exec(fwProbe(t), r, nil), result.Pass)
		r = fwRunner(nftNothing, iptDrop, iptDrop, "").AddError(fwUfw, execx.ErrTimeout)
		wantStatus(t, exec(fwProbe(t), r, nil), result.Pass)
	})
	t.Run("the rule table after the header is not read", func(t *testing.T) {
		u := "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\nNew profiles: skip\n\nTo   Action   From\n22   ALLOW IN  Anywhere   # Default: allow (incoming), x\n"
		o := exec(fwProbe(t), fwRunner(nftNothing, iptAccept, iptAccept, u), nil)
		wantStatus(t, o, result.Fail)
		wantSummary(t, o, "incoming packets are not dropped")
		if !strings.Contains(o.Evidence[0].Detail, "default for incoming packets: deny") {
			t.Fatalf("detail %q", o.Evidence[0].Detail)
		}
	})
}

func TestFirewallNftTableFlags(t *testing.T) {
	doc := func(flags string) string {
		return `{"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": {"family": "inet", "name": "f", "flags": ` + flags + `}}, ` +
			`{"chain": {"family": "inet", "table": "f", "name": "i", "type": "filter", "hook": "input", "policy": "drop"}}]}`
	}
	for flags, want := range map[string]result.Status{
		`"owner"`: result.Pass, `["owner"]`: result.Pass, `["owner","persist"]`: result.Pass, `null`: result.Pass, `[]`: result.Pass,
		`"dormant"`: result.Fail, `["dormant"]`: result.Fail, `"kw"`: result.Fail, `["owner","x"]`: result.Fail, `7`: result.Fail, `{}`: result.Fail,
	} {
		t.Run(flags, func(t *testing.T) {
			o := exec(fwProbe(t), fwRunner(doc(flags), iptAccept, iptAccept, ""), nil)
			wantStatus(t, o, want)
			if want == result.Fail {
				if len(o.Evidence) != 2 {
					t.Fatalf("evidence %+v", o.Evidence)
				}
			}
		})
	}
}

func TestFirewallPrepareTakesNoParameters(t *testing.T) {
	if err := prepareErr(t, "firewall_default", map[string]any{"x": 1}); !strings.Contains(err.Error(), `unknown parameter "x"`) {
		t.Fatal(err)
	}
}

func TestFirewallArgvAndOptions(t *testing.T) {
	r := fwFixtures("ubuntu2404", "ufw_deny")
	exec(fwProbe(t), r, nil)
	var nft *fake.Call
	for _, c := range r.Calls() {
		c := c
		if c.Argv[0] == "nft" {
			nft = &c
		}
	}
	if nft == nil || nft.Opts.MaxOutput < 4<<20 {
		t.Fatalf("nft call %+v: large rulesets need a larger output limit", nft)
	}
}
