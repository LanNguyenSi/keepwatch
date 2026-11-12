package probes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// Files rebootRequired reads.
const (
	rebootFile     = "/var/run/reboot-required"
	rebootPkgsFile = "/var/run/reboot-required.pkgs"
	maxRebootFile  = 64 << 10
	maxRebootPkgs  = 20
)

// rebootRequired reports whether the host needs a reboot.
//
// It takes no parameters (and so has no list parameters).
//
// Two sources. The marker file /var/run/reboot-required (written by the
// update tooling): when it exists the check fails, and the packages listed
// in /var/run/reboot-required.pkgs, when present, become part of the detail.
// And, when needrestart is installed, its kernel status in batch mode:
// "needrestart -b -k -r l" (batch output, kernel check only, restart mode
// "list only"; it never restarts anything). Only exit status 0 is
// interpreted. The output must contain the NEEDRESTART-VER line; the
// NEEDRESTART-KSTA value means 0 unknown, 1 current, 2 ABI-compatible kernel
// upgrade pending, 3 version upgrade pending, and 2 or 3 fail. An output
// without KSTA (needrestart skips the kernel check inside a container) or
// with KSTA 0 does not fail the check; the summary says the kernel status
// is unknown. A missing needrestart skips only this part. Any other problem
// with needrestart, or a file that cannot be read for a reason other than
// not existing, is error, and an error wins over a fail: an incomplete
// picture is never reported as a clean failure. Both sources are always
// read; the reasons already confirmed stay in the evidence of an error
// result and the summary names them ("also found") and says the picture is
// partial.
//
// The paths keep the /var/run spelling the update tooling uses. On Ubuntu
// /var/run is a symbolic link to /run; OSFS follows links in the directories
// of a path and refuses only a link (or FIFO, device) as the file itself, so
// a marker that is a link is an error rather than something to follow.
type rebootRequired struct{}

func (rebootRequired) Name() string       { return "reboot_required" }
func (rebootRequired) Programs() []string { return []string{"needrestart"} }

func (rebootRequired) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	if err := p.err(); err != nil {
		return nil, err
	}
	return rebootProbe{}, nil
}

type rebootProbe struct{}

func (rebootProbe) Run(ctx context.Context, env *Env) Outcome {
	var ev []result.Evidence
	var notes, failures []string

	_, err := env.FS.ReadFile(rebootFile, maxRebootFile)
	switch {
	case err == nil || errors.Is(err, ErrTooLarge):
		detail := "the marker file exists"
		pkgs, perr := env.FS.ReadFile(rebootPkgsFile, maxRebootFile)
		switch {
		case perr == nil:
			detail += "; packages: " + pkgList(string(pkgs))
		case errors.Is(perr, fs.ErrNotExist):
		default:
			failures = append(failures, fmt.Sprintf("cannot read %s: %s", rebootPkgsFile, hostText(perr.Error())))
		}
		ev = append(ev, result.Evidence{Subject: "reboot-required", Detail: detail})
	case errors.Is(err, fs.ErrNotExist):
	default:
		failures = append(failures, fmt.Sprintf("cannot read %s: %s", rebootFile, hostText(err.Error())))
	}

	res, out := run(ctx, env, []string{"needrestart", "-b", "-k", "-r", "l"}, 30*time.Second)
	switch {
	case out != nil && out.Status == result.Skipped:
		notes = append(notes, "needrestart not installed, kernel status not checked")
	case out != nil:
		failures = append(failures, out.Summary)
	case res.ExitCode != 0:
		failures = append(failures, unexpectedExit("needrestart", res).Summary)
	default:
		item, note, err := parseNeedrestart(string(res.Stdout))
		if err != nil {
			failures = append(failures, fmt.Sprintf("needrestart: %v", err))
			break
		}
		if item != nil {
			ev = append(ev, *item)
		}
		if note != "" {
			notes = append(notes, note)
		}
	}

	switch {
	case len(failures) > 0:
		return partialError(failures, ev)
	case len(ev) > 0:
		return Outcome{Status: result.Fail, Summary: fmt.Sprintf("a reboot is required (%d reason(s))", len(ev)), Evidence: ev}
	}
	summary := "no reboot is required"
	if len(notes) > 0 {
		summary += " (" + strings.Join(notes, "; ") + ")"
	}
	return Outcome{Status: result.Pass, Summary: summary}
}

// pkgList renders the package names of a reboot-required.pkgs file.
func pkgList(content string) string {
	var names []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(names) == maxRebootPkgs {
			names = append(names, "...")
			break
		}
		names = append(names, hostText(line))
	}
	if len(names) == 0 {
		return "none listed"
	}
	return strings.Join(names, ", ")
}

// parseNeedrestart reads needrestart batch output. It returns an evidence
// item when a kernel upgrade is pending, and a note when the kernel status
// is unknown. A NEEDRESTART-* key that appears twice is an error (which of
// the two values counts would be a guess), and so is a KSTA value that is
// not exactly one digit from 0 to 3.
func parseNeedrestart(out string) (*result.Evidence, string, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.HasPrefix(k, "NEEDRESTART-") {
			if _, dup := kv[k]; dup {
				return nil, "", fmt.Errorf("output has %s more than once", k)
			}
			kv[k] = strings.TrimSpace(v)
		}
	}
	if _, ok := kv["NEEDRESTART-VER"]; !ok {
		return nil, "", errors.New("output has no NEEDRESTART-VER line")
	}
	raw, ok := kv["NEEDRESTART-KSTA"]
	if !ok {
		return nil, "kernel status not reported by needrestart", nil
	}
	// Exactly one digit from 0 to 3: no sign, no padding.
	if len(raw) != 1 || raw[0] < '0' || raw[0] > '3' {
		return nil, "", fmt.Errorf("unexpected NEEDRESTART-KSTA value %s", quoted(raw))
	}
	ksta := int(raw[0] - '0')
	switch ksta {
	case 0:
		return nil, "kernel status unknown to needrestart", nil
	case 1:
		return nil, "", nil
	}
	kind := "ABI-compatible kernel upgrade pending"
	if ksta == 3 {
		kind = "kernel version upgrade pending"
	}
	detail := kind
	if cur := kv["NEEDRESTART-KCUR"]; cur != "" {
		detail += "; running " + hostText(cur)
	}
	if exp := kv["NEEDRESTART-KEXP"]; exp != "" {
		detail += "; expected " + hostText(exp)
	}
	return &result.Evidence{Subject: "kernel", Detail: detail}, "", nil
}
