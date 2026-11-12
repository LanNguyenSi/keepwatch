package probes

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

var (
	sshdOptionPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,63}$`)
	sshdValuePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._,:@/+-]{0,127}$`)
)

// sshdEffective checks one option of the effective sshd configuration, as
// printed by "sshd -T" (drop-ins under sshd_config.d are already merged in
// by sshd, which is the point: files are not read).
//
// Parameters:
//
//	option   (string, required)  option keyword, lower case, as sshd -T
//	                             prints it, for example "passwordauthentication"
//	allow    (list of strings, required, not empty)  accepted values,
//	                             lower case, compared with the whole value
//	aliases  (list of strings, optional)  other keywords for the same
//	                             option; used only when option itself is
//	                             absent from the output
//
// List semantics: a list set under checks.<id>.params REPLACES the
// catalog's list for that key (the whole value is replaced, never merged
// element by element). Lists from conf.d drop-ins are already appended to
// the main file's list when the config is loaded, so a drop-in can widen
// "allow"; review drop-ins accordingly.
//
// The kind runs "sshd -T" and takes no exit status as meaningful except 0:
// any failure of sshd -T (a missing privilege separation directory, a bad
// configuration, a signal) is error, never pass. Every output line must
// look like "keyword value"; any other line makes the whole output
// unparseable (error). If the option (or an alias) occurs on several lines,
// every occurrence must be allowed. An option missing from the output is
// error.
//
// Known limit: sshd -T is run without -C, so Match blocks are not
// evaluated; a Match block can still change the value for some users.
//
// Name differences between Ubuntu releases: 22.04 and 24.04 both print
// "kbdinteractiveauthentication" (OpenSSH 8.7 renamed
// "challengeresponseauthentication", so the catalog lists the old name as an
// alias for older hosts), and both print "permitrootlogin without-password"
// for a configured "prohibit-password" (the catalog allows both spellings).
type sshdEffective struct{}

func (sshdEffective) Name() string       { return "sshd_effective" }
func (sshdEffective) Programs() []string { return []string{"sshd"} }

func (sshdEffective) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	valid := func(re *regexp.Regexp, what string) func(string) error {
		return func(s string) error {
			if !re.MatchString(s) {
				return fmt.Errorf("%s %q does not match %s", what, s, re)
			}
			return nil
		}
	}
	opt := p.str("option", true, "", valid(sshdOptionPattern, "option"))
	allow := p.strList("allow", true, true, nil, valid(sshdValuePattern, "value"))
	aliases := p.strList("aliases", false, false, nil, valid(sshdOptionPattern, "option"))
	if err := p.err(); err != nil {
		return nil, err
	}
	return sshdProbe{option: opt, allow: allow, aliases: aliases}, nil
}

type sshdProbe struct {
	option  string
	allow   []string
	aliases []string
}

func (s sshdProbe) Run(ctx context.Context, env *Env) Outcome {
	res, out := run(ctx, env, []string{"sshd", "-T"}, 0)
	if out != nil {
		return *out
	}
	if res.ExitCode != 0 {
		return *unexpectedExit("sshd -T", res)
	}
	values, err := parseSSHDConfig(string(res.Stdout))
	if err != nil {
		return *errorOutcome("sshd -T: %v", err)
	}
	found := values[s.option]
	for _, a := range s.aliases {
		if len(found) > 0 {
			break
		}
		found = values[a]
	}
	if len(found) == 0 {
		return *errorOutcome("sshd -T did not print the option %q", s.option)
	}
	// norm is compared with the allowed values; raw is what is shown, so the
	// case of a value is the one the host printed (a pattern such as an AWS
	// key id is case sensitive).
	var bad, shown []string
	for _, v := range found {
		shown = append(shown, v.raw)
		if !contains(s.allow, v.norm) {
			bad = append(bad, v.raw)
		}
	}
	if len(bad) == 0 {
		return Outcome{Status: result.Pass, Summary: fmt.Sprintf("sshd %s is %s", s.option, strings.Join(shown, ", "))}
	}
	return Outcome{
		Status:  result.Fail,
		Summary: fmt.Sprintf("sshd %s is %s, expected %s", s.option, strings.Join(bad, ", "), strings.Join(s.allow, " or ")),
		Evidence: []result.Evidence{{
			Subject: s.option,
			Detail:  fmt.Sprintf("effective value: %s; allowed: %s", strings.Join(bad, ", "), strings.Join(s.allow, ", ")),
		}},
	}
}

// sshdValue is one value of an sshd -T line: norm is lower case with white
// space collapsed (what is compared), raw keeps the case the host printed.
type sshdValue struct{ norm, raw string }

var sshdKeyword = regexp.MustCompile(`^[a-z0-9]+$`)

// parseSSHDConfig reads sshd -T output into keyword -> values (lower case,
// one entry per line, whitespace collapsed). An empty output or a line that
// does not start with a keyword is an error.
func parseSSHDConfig(out string) (map[string][]sshdValue, error) {
	values := map[string][]sshdValue{}
	for i, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		kw, rest, _ := strings.Cut(line, " ")
		if !sshdKeyword.MatchString(kw) {
			return nil, fmt.Errorf("line %d is not a keyword line: %s", i+1, quoted(line))
		}
		raw := strings.Join(strings.Fields(rest), " ")
		values[kw] = append(values[kw], sshdValue{norm: strings.ToLower(raw), raw: hostText(raw)})
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("empty output")
	}
	return values, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
