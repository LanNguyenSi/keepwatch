package probes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/execx"
	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// nftMaxOutput bounds "nft -j list ruleset": a host with many container
// networks prints a lot of rules. Only root can add rules, so the size is not
// something a local user controls.
const nftMaxOutput = int64(16 << 20)

// firewallDefault checks that the firewall drops incoming packets by default,
// for IPv4 and for IPv6.
//
// It takes no parameters (and so has no list parameters).
//
// What counts is what the kernel enforces, so the verdict comes from the two
// kernel-level views, and a packet is dropped as soon as any hook drops it:
//
//	nft -j list ruleset   a base chain of type filter on hook input with
//	                      policy drop, in a table of family ip (IPv4), ip6
//	                      (IPv6) or inet (both). Chains on other hooks (a
//	                      forward chain with policy drop, as Docker sets one
//	                      up) and chains of type nat do not count, nor does a
//	                      table that is dormant or carries flags keepwatch does
//	                      not know.
//	iptables -S INPUT     "-P INPUT DROP" (IPv4)
//	ip6tables -S INPUT    "-P INPUT DROP" (IPv6)
//
// A family passes when at least one readable source drops it. On Ubuntu
// 22.04 and 24.04 iptables is the nftables variant, so both views usually show
// the same rules.
//
// ufw is read as well ("ufw status verbose") but it only configures iptables:
// it can neither add a drop nor take one away, and it can report "deny" while
// the rules were flushed behind its back. Its state (inactive, or active with
// the default for incoming packets: deny, reject or allow) is shown in the
// detail, and a ufw that says deny/reject while the kernel does not drop is
// called out. A ufw that cannot be read changes nothing but a note.
//
// The summary says what drops each family on a pass. Of the exit statuses only
// 0 is interpreted: any other status of nft, iptables or ip6tables is error
// for that source, and a ufw status other than 0 is a note. A source that
// cannot be read (error) does not stop a pass that other sources confirm,
// because a drop in any hook is final; it does turn what would be a fail into
// error, since the unreadable source might drop. The status is error too when
// no source can be read for a family (for example ip6tables is missing and nft
// is not installed). Programs that are not installed are skipped as sources;
// if none of nft, iptables and ip6tables exists the check is skipped.
//
// Failing evidence has one item per family that is not dropped, with subject
// "input/ipv4" or "input/ipv6".
//
// Limits: it judges the default policy, not the rules. A chain with policy
// drop whose first rule accepts everything passes. Rules in iptables-legacy
// and in nftables that a different tool shows are seen only through the
// variant "iptables" points to and through nft. A host without IPv6 support in
// the kernel makes ip6tables fail, which is error here.
type firewallDefault struct{}

func (firewallDefault) Name() string { return "firewall_default" }
func (firewallDefault) Programs() []string {
	return []string{"ip6tables", "iptables", "nft", "ufw"}
}

func (firewallDefault) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	if err := p.err(); err != nil {
		return nil, err
	}
	return firewallProbe{}, nil
}

type firewallProbe struct{}

// The two address families.
const (
	fam4 = iota
	fam6
)

var famName = [2]string{"IPv4", "IPv6"}
var famSubject = [2]string{"input/ipv4", "input/ipv6"}

// view is what the probe learned for the two families.
type view struct {
	readable [2]bool     // some readable source covers the family
	dropBy   [2][]string // sources that drop incoming packets by default
	openSeen [2][]string // observations of sources that do not drop
	failures []string    // sources that could not be read
	notes    []string    // sources that are not installed, tables not counted
}

func (firewallProbe) Run(ctx context.Context, env *Env) Outcome {
	var v view
	installed := 0

	// nftables
	if res, out := runWith(ctx, env, []string{"nft", "-j", "list", "ruleset"}, execx.Opts{Timeout: 30 * time.Second, MaxOutput: nftMaxOutput}, false); out != nil {
		v.sourceProblem("nft", out)
		if out.Status != result.Skipped {
			installed++
		}
	} else {
		installed++
		if res.ExitCode != 0 {
			v.failures = append(v.failures, unexpectedExit("nft", res).Summary)
		} else if chains, err := parseNft(res.Stdout); err != nil {
			v.failures = append(v.failures, "nft: "+err.Error())
		} else {
			for f := fam4; f <= fam6; f++ {
				v.readable[f] = true
				if len(chains.drops[f]) > 0 {
					v.dropBy[f] = append(v.dropBy[f], "nftables "+strings.Join(chains.drops[f], ", "))
				} else {
					v.openSeen[f] = append(v.openSeen[f], "nftables: no input chain drops by default")
				}
			}
			v.notes = append(v.notes, chains.notes...)
		}
	}

	// iptables and ip6tables
	for _, t := range []struct {
		prog string
		fam  int
	}{{"iptables", fam4}, {"ip6tables", fam6}} {
		res, out := run(ctx, env, []string{t.prog, "-S", "INPUT"}, 0)
		if out != nil {
			v.sourceProblem(t.prog, out)
			if out.Status != result.Skipped {
				installed++
			}
			continue
		}
		installed++
		if res.ExitCode != 0 {
			v.failures = append(v.failures, unexpectedExit(t.prog, res).Summary)
			continue
		}
		policy, err := parseIptablesInput(string(res.Stdout))
		if err != nil {
			v.failures = append(v.failures, fmt.Sprintf("%s -S INPUT: %v", t.prog, err))
			continue
		}
		v.readable[t.fam] = true
		if policy == "DROP" {
			v.dropBy[t.fam] = append(v.dropBy[t.fam], t.prog+" INPUT policy DROP")
		} else {
			v.openSeen[t.fam] = append(v.openSeen[t.fam], t.prog+": INPUT policy ACCEPT")
		}
	}

	// ufw explains; it never decides.
	ufwState, ufwIncoming := firewallUFW(ctx, env)

	if installed == 0 {
		return Outcome{Status: result.Skipped, Summary: "none of nft, iptables and ip6tables is installed, check skipped"}
	}

	var missing []string
	var open []int
	for f := fam4; f <= fam6; f++ {
		switch {
		case len(v.dropBy[f]) > 0:
		case !v.readable[f]:
			missing = append(missing, famName[f])
		default:
			open = append(open, f)
		}
	}
	if len(missing) > 0 {
		v.failures = append(v.failures, fmt.Sprintf("no readable source for %s", strings.Join(missing, " and ")))
	}

	switch {
	case len(open) == 0 && len(missing) == 0:
		s := fmt.Sprintf("incoming packets are dropped by default: IPv4 by %s; IPv6 by %s",
			strings.Join(v.dropBy[fam4], ", "), strings.Join(v.dropBy[fam6], ", "))
		return Outcome{Status: result.Pass, Summary: s + v.suffix(ufwState, true)}
	case len(v.failures) > 0:
		return *errorOutcome("cannot tell whether incoming packets are dropped by default: %s%s", strings.Join(v.failures, "; "), v.suffix(ufwState, false))
	}
	var ev []result.Evidence
	for _, f := range open {
		d := fmt.Sprintf("%s incoming packets are accepted by default (%s)", famName[f], strings.Join(v.openSeen[f], "; "))
		if ufwIncoming == "deny" {
			d += "; ufw reports deny but the kernel does not drop them"
		}
		if ufwState != "" {
			d += "; ufw: " + ufwState
		}
		ev = append(ev, result.Evidence{Subject: famSubject[f], Detail: d})
	}
	return Outcome{
		Status:   result.Fail,
		Summary:  fmt.Sprintf("incoming packets are not dropped by default for %d of 2 address families", len(open)),
		Evidence: ev,
	}
}

// sourceProblem files the outcome of a source that did not run.
func (v *view) sourceProblem(prog string, out *Outcome) {
	if out.Status == result.Skipped {
		v.notes = append(v.notes, prog+" not installed")
		return
	}
	v.failures = append(v.failures, out.Summary)
}

// suffix renders the notes and unreadable sources that go after a summary.
func (v *view) suffix(ufw string, withFailures bool) string {
	var parts []string
	if ufw != "" {
		parts = append(parts, "ufw: "+ufw)
	}
	parts = append(parts, v.notes...)
	if withFailures {
		for _, f := range v.failures {
			parts = append(parts, "not read: "+f)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + clean(strings.Join(parts, "; "), 400) + ")"
}

// firewallUFW reads ufw's own view for the explanation. It returns a short
// description for the detail text and the default for incoming packets
// ("deny" for deny and reject, "allow", or "" when unknown or inactive).
func firewallUFW(ctx context.Context, env *Env) (string, string) {
	res, out := run(ctx, env, []string{"ufw", "status", "verbose"}, 15*time.Second)
	switch {
	case out != nil && out.Status == result.Skipped:
		return "", ""
	case out != nil:
		return "could not be read", ""
	case res.ExitCode != 0:
		return "could not be read (" + unexpectedExit("ufw", res).Summary + ")", ""
	}
	active, incoming, err := parseUFW(string(res.Stdout))
	switch {
	case err != nil:
		return "output not understood", ""
	case !active:
		return "inactive", ""
	}
	return "active, default for incoming packets: " + incoming, map[string]string{"deny": "deny", "reject": "deny", "allow": "allow"}[incoming]
}

// parseUFW reads the header of "ufw status verbose": "Status: active" or
// "Status: inactive", and for an active ufw the line "Default: <policy>
// (incoming), <policy> (outgoing), <policy> (routed)". Only the header, up to
// the first empty line, is read; the rule table after it holds text the
// administrator chose.
func parseUFW(out string) (active bool, incoming string, err error) {
	header := out
	if i := strings.Index(out, "\n\n"); i >= 0 {
		header = out[:i]
	}
	lines := strings.Split(strings.TrimRight(header, "\n"), "\n")
	switch lines[0] {
	case "Status: inactive":
		return false, "", nil
	case "Status: active":
	default:
		return false, "", fmt.Errorf("unexpected first line %q", clean(lines[0], 40))
	}
	for _, l := range lines[1:] {
		rest, ok := strings.CutPrefix(l, "Default: ")
		if !ok {
			continue
		}
		parts := strings.Split(rest, ", ")
		if len(parts) < 2 || !strings.HasSuffix(parts[0], " (incoming)") {
			return false, "", fmt.Errorf("unexpected Default line %q", clean(l, 80))
		}
		in := strings.TrimSuffix(parts[0], " (incoming)")
		switch in {
		case "allow", "deny", "reject":
			return true, in, nil
		}
		return false, "", fmt.Errorf("unexpected incoming default %q", clean(in, 20))
	}
	return false, "", errors.New("active, but no Default line")
}

// parseIptablesInput reads "iptables -S INPUT" / "ip6tables -S INPUT": one
// "-P INPUT <ACCEPT|DROP>" line and any number of "-A INPUT ..." rules.
func parseIptablesInput(out string) (string, error) {
	policy := ""
	for i, line := range strings.Split(out, "\n") {
		switch {
		case line == "":
		case strings.HasPrefix(line, "-P INPUT "):
			p := strings.TrimPrefix(line, "-P INPUT ")
			if (p != "ACCEPT" && p != "DROP") || policy != "" {
				return "", fmt.Errorf("line %d: unexpected policy line %q", i+1, clean(line, 40))
			}
			policy = p
		case strings.HasPrefix(line, "-A INPUT "):
		default:
			return "", fmt.Errorf("line %d does not look like iptables -S output: %q", i+1, clean(line, 40))
		}
	}
	if policy == "" {
		return "", errors.New("no policy line for INPUT")
	}
	return policy, nil
}

// nftView is what parseNft found: per family the base input chains that drop
// by default ("family table/chain"), and notes about tables not counted.
type nftView struct {
	drops [2][]string
	notes []string
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftTable struct {
	Family string          `json:"family"`
	Name   string          `json:"name"`
	Flags  json.RawMessage `json:"flags"`
}

// parseNft reads "nft -j list ruleset". Input base chains (type filter, hook
// input) in the families ip, ip6 and inet count; their policy must be accept
// or drop. A table that is dormant (its chains are not hooked), or whose flags
// are not ones keepwatch knows, is not counted and a note says so.
func parseNft(out []byte) (nftView, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	dec := json.NewDecoder(bytes.NewReader(out))
	if err := dec.Decode(&doc); err != nil {
		return nftView{}, fmt.Errorf("not valid JSON: %v", clean(err.Error(), 100))
	}
	if dec.More() {
		return nftView{}, errors.New("unexpected data after the JSON document")
	}
	schema := 0
	tables := map[[2]string]nftTable{}
	var chains []nftChain
	for i, item := range doc.Nftables {
		if len(item) != 1 {
			return nftView{}, fmt.Errorf("entry %d is not a single-key object", i)
		}
		for key, raw := range item {
			switch key {
			case "metainfo":
				var m struct {
					Version int `json:"json_schema_version"`
				}
				if err := json.Unmarshal(raw, &m); err != nil || m.Version != 1 {
					return nftView{}, errors.New("unsupported JSON schema version")
				}
				schema++
			case "table":
				var t nftTable
				if err := json.Unmarshal(raw, &t); err != nil || t.Family == "" || t.Name == "" {
					return nftView{}, fmt.Errorf("entry %d: unexpected table shape", i)
				}
				tables[[2]string{t.Family, t.Name}] = t
			case "chain":
				var c nftChain
				if err := json.Unmarshal(raw, &c); err != nil || c.Family == "" || c.Table == "" || c.Name == "" {
					return nftView{}, fmt.Errorf("entry %d: unexpected chain shape", i)
				}
				chains = append(chains, c)
			}
		}
	}
	if schema != 1 {
		return nftView{}, errors.New("no single metainfo entry")
	}
	var v nftView
	skipped := map[string]bool{}
	for _, c := range chains {
		if c.Hook != "input" || c.Type != "filter" {
			continue
		}
		var fams []int
		switch c.Family {
		case "ip":
			fams = []int{fam4}
		case "ip6":
			fams = []int{fam6}
		case "inet":
			fams = []int{fam4, fam6}
		default:
			continue // bridge, netdev, arp: not the host's incoming traffic
		}
		if c.Policy != "accept" && c.Policy != "drop" {
			return nftView{}, fmt.Errorf("input chain %s/%s has policy %q", clean(c.Table, 30), clean(c.Name, 30), clean(c.Policy, 20))
		}
		t, ok := tables[[2]string{c.Family, c.Table}]
		if !ok {
			return nftView{}, fmt.Errorf("chain %s/%s belongs to no listed table", clean(c.Table, 30), clean(c.Name, 30))
		}
		if !nftTableActive(t) {
			name := c.Family + " " + clean(c.Table, 30)
			if !skipped[name] {
				skipped[name] = true
				v.notes = append(v.notes, fmt.Sprintf("nftables table %s is dormant or has flags that are not known, not counted", name))
			}
			continue
		}
		if c.Policy == "drop" {
			for _, f := range fams {
				v.drops[f] = append(v.drops[f], fmt.Sprintf("%s %s/%s", c.Family, clean(c.Table, 30), clean(c.Name, 30)))
			}
		}
	}
	return v, nil
}

// nftTableActive reports whether the chains of the table are hooked. A table
// without flags is. "owner" and "persist" do not change that; "dormant" does,
// and so does a flags value this code does not know (nft 1.0.9 prints a
// dormant table's flags as an unrelated string, so unknown means unhooked).
func nftTableActive(t nftTable) bool {
	if len(t.Flags) == 0 || string(t.Flags) == "null" {
		return true
	}
	var one string
	var many []string
	switch {
	case json.Unmarshal(t.Flags, &one) == nil:
		many = []string{one}
	case json.Unmarshal(t.Flags, &many) != nil:
		return false
	}
	for _, f := range many {
		if f != "owner" && f != "persist" {
			return false
		}
	}
	return true
}
