package probes_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/execx/fake"
	"github.com/LanNguyenSi/keepwatch/internal/probes"
	"github.com/LanNguyenSi/keepwatch/internal/probes/probestest"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// fwHost serves the six commands of the firewall probe for a host whose
// firewall accepts everything. over replaces the stdout of one of them by
// name: ufw, nft, iptables, ip6tables, iptablesV, ip6tablesV.
func fwHost(over map[string]string) *fake.FakeRunner {
	out := map[string]string{
		"ufw":        "Status: inactive\n",
		"nft":        nftDoc("ip filter INPUT filter input accept", "ip6 filter INPUT filter input accept"),
		"iptables":   "-P INPUT ACCEPT\n",
		"ip6tables":  "-P INPUT ACCEPT\n",
		"iptablesV":  "iptables v1.8.10 (nf_tables)\n",
		"ip6tablesV": "ip6tables v1.8.10 (nf_tables)\n",
	}
	for k, v := range over {
		out[k] = v
	}
	return newRunner().
		AddResult(fwUfw, inline(out["ufw"], 0)).AddResult(fwNft, inline(out["nft"], 0)).
		AddResult(fwIpt, inline(out["iptables"], 0)).AddResult(fwIpt6, inline(out["ip6tables"], 0)).
		AddResult(fwIptV, inline(out["iptablesV"], 0)).AddResult(fwIpt6V, inline(out["ip6tablesV"], 0))
}

// nftTableChain is an nft document with one input chain of the inet family;
// the strings are encoded as JSON, so they can hold any character. With
// noTable the table is not listed; flags is the table's flags value.
func nftTableChain(t *testing.T, table, chain, policy string, noTable bool, flags any) string {
	t.Helper()
	items := []any{map[string]any{"metainfo": map[string]any{"version": "1.0.9", "json_schema_version": 1}}}
	if !noTable {
		tb := map[string]any{"family": "inet", "name": table, "handle": 1}
		if flags != nil {
			tb["flags"] = flags
		}
		items = append(items, map[string]any{"table": tb})
	}
	items = append(items, map[string]any{"chain": map[string]any{
		"family": "inet", "table": table, "name": chain, "handle": 1, "type": "filter", "hook": "input", "prio": 0, "policy": policy,
	}})
	b, err := json.Marshal(map[string]any{"nftables": items})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// commandRoles are the places where the output of a command or the text of a
// file that the probes of the system, firewall, update, listener, package and
// service kinds read reaches a summary or a detail.
func commandRoles() []corpusRole {
	const sshdKind = "sshd_effective"
	sshd := func(t *testing.T, stdout string) probes.Outcome {
		p := prepare(t, sshdKind, sshdParams("permitrootlogin", "no", "prohibit-password"))
		return exec(p, newRunner().AddResult(sshdArgv, inline(stdout, 0)), nil)
	}
	svc := func(t *testing.T, res execx.Result) probes.Outcome {
		p := prepare(t, "service_active", map[string]any{"service": "fail2ban.service"})
		return exec(p, newRunner().AddResult(svcArgv("fail2ban.service"), res), nil)
	}
	pkg := func(t *testing.T, res execx.Result) probes.Outcome {
		p := prepare(t, "package_installed", map[string]any{"package": "fail2ban"})
		return exec(p, newRunner().AddResult(pkgArgv("fail2ban"), res), nil)
	}
	jail := func(t *testing.T, res execx.Result) probes.Outcome {
		p := prepare(t, "fail2ban_jail", map[string]any{"jail": "sshd"})
		return exec(p, newRunner().AddResult(jailArgv("sshd"), res), nil)
	}
	fw := func(t *testing.T, r *fake.FakeRunner) probes.Outcome { return exec(fwProbe(t), r, nil) }
	nftOf := func(t *testing.T, table, chain, policy string, noTable bool, flags any) probes.Outcome {
		return fw(t, fwHost(map[string]string{"nft": nftTableChain(t, table, chain, policy, noTable, flags)}))
	}
	ss := func(t *testing.T, tcp, tcpP string, tcpPRes *execx.Result) probes.Outcome {
		r := newRunner().AddResult(ssTCP, inline(tcp, 0)).AddResult(ssUDP, inline("", 0)).AddResult(ssUDPp, inline("", 0))
		if tcpPRes != nil {
			r.AddResult(ssTCPp, *tcpPRes)
		} else {
			r.AddResult(ssTCPp, inline(tcpP, 0))
		}
		return exec(listenersProbe(t, nil), r, nil)
	}
	const listen = "LISTEN 0 5 0.0.0.0:9000 0.0.0.0:*"
	reboot := func(t *testing.T, needrestart string, fsys probes.FS) probes.Outcome {
		r := newRunner().AddResult(needrestartArgv, inline(needrestart, 0))
		return exec(rebootProbe(t), r, fsys)
	}
	aptPolicy := rawPolicy("     3.0 500", "        500 http://archive.example noble-updates/main amd64 Packages", " *** 1.0 100", "        100 /var/lib/dpkg/status")
	apt := func(t *testing.T, sim, policy string) probes.Outcome {
		r := newRunner().AddResult(aptArgv, inline(sim, 0))
		if policy != "" {
			r.AddResult(policyArgv("pkg-a"), inline(policy, 0))
		}
		return execAt(updatesProbe(t, nil), r, lists(time.Hour), t0)
	}

	return []corpusRole{
		// service_active
		{name: "service state that does not fit", kind: "service_active", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return svc(t, inline(f+"\n", 0))
		}},
		// run: the message of a command that fails, and the error of one that cannot be run
		{name: "run exit status with a message", kind: "service_active", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return svc(t, execx.Result{ExitCode: 1, Stderr: []byte(f + "\n")})
		}},
		{name: "run command that cannot be started", kind: "service_active", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			p := prepare(t, "service_active", map[string]any{"service": "fail2ban.service"})
			return exec(p, newRunner().AddError(svcArgv("fail2ban.service"), errors.New("boom "+f)), nil)
		}},

		// fail2ban_jail
		{name: "fail2ban unexpected status line", kind: "fail2ban_jail", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return jail(t, inline(f+"\n", 0))
		}},

		// package_installed
		{name: "package record that cannot be parsed", kind: "package_installed", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return pkg(t, inline(f+"\n", 0))
		}},
		{name: "package version", kind: "package_installed", status: result.Pass, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return pkg(t, inline("install ok installed\t"+f+"\n", 0))
		}},

		// sshd_effective
		{name: "sshd value", kind: sshdKind, status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return sshd(t, "permitrootlogin "+f+"\n")
		}},
		{name: "sshd line that is no keyword line", kind: sshdKind, status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return sshd(t, f+"\n")
		}},

		// firewall_default
		{name: "firewall ufw message", kind: "firewall_default", status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return fw(t, newRunner().AddResult(fwUfw, execx.Result{ExitCode: 1, Stderr: []byte(f + "\n")}).
				AddResult(fwNft, inline(nftDoc("ip filter INPUT filter input accept", "ip6 filter INPUT filter input accept"), 0)).
				AddResult(fwIpt, inline("-P INPUT ACCEPT\n", 0)).AddResult(fwIpt6, inline("-P INPUT ACCEPT\n", 0)).
				AddResult(fwIptV, inline("iptables v1.8.10 (nf_tables)\n", 0)).AddResult(fwIpt6V, inline("ip6tables v1.8.10 (nf_tables)\n", 0)))
		}},
		{name: "firewall iptables version line", kind: "firewall_default", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return fw(t, fwHost(map[string]string{"iptablesV": f + "\n"}))
		}},
		{name: "firewall iptables policy line", kind: "firewall_default", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return fw(t, fwHost(map[string]string{"iptables": "-P INPUT " + f + "\n"}))
		}},
		{name: "firewall iptables line that is no rule", kind: "firewall_default", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return fw(t, fwHost(map[string]string{"ip6tables": f + "\n-P INPUT ACCEPT\n"}))
		}},
		{name: "firewall nft policy", kind: "firewall_default", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return nftOf(t, "kw", "input", f, false, nil)
		}},
		{name: "firewall nft chain without a table", kind: "firewall_default", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return nftOf(t, f, "input", "drop", true, nil)
		}},
		{name: "firewall nft dropping table", kind: "firewall_default", status: result.Pass, run: func(t *testing.T, f string) probes.Outcome {
			return nftOf(t, f, "input", "drop", false, nil)
		}},
		{name: "firewall nft dropping chain", kind: "firewall_default", status: result.Pass, run: func(t *testing.T, f string) probes.Outcome {
			return nftOf(t, "kw", f, "drop", false, nil)
		}},
		{name: "firewall nft dormant table", kind: "firewall_default", status: result.Fail, run: func(t *testing.T, f string) probes.Outcome {
			return nftOf(t, f, "input", "drop", false, "dormant")
		}},

		// listeners
		{name: "listeners line that is no socket", kind: "listeners", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return ss(t, f+"\n", "", nil)
		}},
		{name: "listeners local address", kind: "listeners", status: result.Error, noWS: true, url: "full", run: func(t *testing.T, f string) probes.Outcome {
			return ss(t, "LISTEN 0 5 "+f+" 0.0.0.0:*\n", "", nil)
		}},
		{name: "listeners process name", kind: "listeners", status: result.Fail, noWS: true, url: "full", run: func(t *testing.T, f string) probes.Outcome {
			return ss(t, plain(listen+" users:((\"x\",pid=1,fd=3))\n"), listen+" users:((\""+f+"\",pid=1,fd=3))\n", nil)
		}},
		{name: "listeners process listing that fails", kind: "listeners", status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return ss(t, listen+"\nLISTEN 0 5 0.0.0.0:9001 0.0.0.0:*\n", "", &execx.Result{ExitCode: 1, Stderr: []byte(f + "\n")})
		}},

		// reboot_required
		{name: "reboot package list", kind: "reboot_required", status: result.Fail, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, needrestartOut("1"), probestest.MemFS{rebootFile: "x", pkgsFile: "libc6\n" + f + "\n"})
		}},
		{name: "reboot marker file that cannot be read", kind: "reboot_required", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, needrestartOut("1"), probestest.ErrFS{Err: errors.New("denied " + f)})
		}},
		{name: "reboot package list that cannot be read", kind: "reboot_required", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, needrestartOut("1"), probestest.FakeFS{Files: map[string]string{rebootFile: "x"}, Errs: map[string]error{pkgsFile: errors.New("denied " + f)}})
		}},
		{name: "reboot kernel status value", kind: "reboot_required", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: "+f+"\n", probestest.MemFS{})
		}},
		{name: "reboot running kernel", kind: "reboot_required", status: result.Fail, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: "+f+"\nNEEDRESTART-KEXP: 6.8.0-48-generic\nNEEDRESTART-KSTA: 3\n", probestest.MemFS{})
		}},
		{name: "reboot expected kernel", kind: "reboot_required", status: result.Fail, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return reboot(t, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.8.0-45-generic\nNEEDRESTART-KEXP: "+f+"\nNEEDRESTART-KSTA: 3\n", probestest.MemFS{})
		}},

		// security_updates
		{name: "updates simulation line", kind: "security_updates", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, f+"\n", "")
		}},
		{name: "updates kept back name", kind: "security_updates", status: result.Error, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, "Reading package lists...\nThe following packages have been kept back:\n  "+f+"\n0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.\n", "")
		}},
		{name: "updates Inst line", kind: "security_updates", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, aptOut(1, 0, "Inst "+f+"\n"), "")
		}},
		{name: "updates policy line", kind: "security_updates", status: result.Error, noNL: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, aptOut(1, 0, instOne), rawPolicy("     3.0 500", f, " *** 1.0 100", "        100 /var/lib/dpkg/status"))
		}},
		// the versions of an Inst line are not checked against the policy rows
		{name: "updates candidate version", kind: "security_updates", status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, aptOut(1, 0, "Inst pkg-a [1.0] ("+f+" Ubuntu:24.04/noble-security [amd64])\n"), aptPolicy)
		}},
		{name: "updates installed version", kind: "security_updates", status: result.Fail, noWS: true, run: func(t *testing.T, f string) probes.Outcome {
			return apt(t, aptOut(1, 0, "Inst pkg-a ["+f+"] (3.0 Ubuntu:24.04/noble-security [amd64])\n"), aptPolicy)
		}},
		{name: "updates package lists that cannot be listed", kind: "security_updates", status: result.Error, run: func(t *testing.T, f string) probes.Outcome {
			r := newRunner().AddResult(aptArgv, inline(aptOut(0, 0, ""), 0))
			return execAt(updatesProbe(t, nil), r, probestest.FakeFS{GlobErr: errors.New("boom " + f)}, t0)
		}},
	}
}
