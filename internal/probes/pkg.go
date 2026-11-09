package probes

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

// packagePattern follows the Debian policy for package names: lower-case
// letters, digits and "+-.", at least two characters, starting with a
// letter or digit. No glob characters, no architecture qualifier.
var packagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,127}$`)

// packageInstalled checks that a Debian package is installed.
//
// Parameters:
//
//	package  (string, required)  package name, for example "fail2ban"
//
// It runs dpkg-query -W with a Status/Version format and "--" before the
// name, and reads one "want flag status<TAB>version" record per line. The
// package counts as installed when status is "installed" and flag is "ok".
// The documented exit statuses it interprets:
//
//	0  records printed. Any other status word (config-files, unpacked,
//	   half-configured, ...) is a fail with that status as the detail.
//	1  with empty stdout and stderr "dpkg-query: no packages found
//	   matching <package>": the package is unknown to dpkg; fail.
//
// Any other status, or stdout on status 1, is error.
//
// The kind has no list parameters.
type packageInstalled struct{}

func (packageInstalled) Name() string       { return "package_installed" }
func (packageInstalled) Programs() []string { return []string{"dpkg-query"} }

func (packageInstalled) Prepare(params map[string]any) (Probe, error) {
	p := newParams(params)
	pkg := p.str("package", true, "", argPattern("package name", packagePattern))
	if err := p.err(); err != nil {
		return nil, err
	}
	return packageProbe{pkg: pkg}, nil
}

type packageProbe struct{ pkg string }

var packageStatusWords = map[string]bool{
	"not-installed": true, "config-files": true, "half-installed": true, "unpacked": true,
	"half-configured": true, "triggers-awaited": true, "triggers-pending": true, "installed": true,
}

func (p packageProbe) Run(ctx context.Context, env *Env) Outcome {
	argv := []string{"dpkg-query", "-W", `-f=${Status}` + "\t" + `${Version}` + "\n", "--", p.pkg}
	res, out := run(ctx, env, argv, 0)
	if out != nil {
		return *out
	}
	switch res.ExitCode {
	case 0:
		return p.parse(string(res.Stdout))
	case 1:
		if len(res.Stdout) == 0 && firstLine(res.Stderr) == "dpkg-query: no packages found matching "+p.pkg {
			return p.fail("not installed")
		}
	}
	return *unexpectedExit("dpkg-query", res)
}

func (p packageProbe) parse(out string) Outcome {
	if strings.TrimSpace(out) == "" {
		return *errorOutcome("dpkg-query %s: empty output", p.pkg)
	}
	var last, installedVersion string
	installed := false
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		status, version, ok := strings.Cut(line, "\t")
		words := strings.Fields(status)
		if !ok || len(words) != 3 || !packageStatusWords[words[2]] {
			return *errorOutcome("dpkg-query %s: cannot parse record %q", p.pkg, clean(line, 80))
		}
		if words[2] == "installed" && words[1] == "ok" {
			installed, installedVersion = true, version
		}
		last = status
	}
	if installed {
		return Outcome{Status: result.Pass, Summary: fmt.Sprintf("%s %s is installed", p.pkg, clean(installedVersion, 80))}
	}
	return p.fail(clean(last, 80))
}

func (p packageProbe) fail(detail string) Outcome {
	return Outcome{
		Status:   result.Fail,
		Summary:  fmt.Sprintf("package %s is not installed", p.pkg),
		Evidence: []result.Evidence{{Subject: p.pkg, Detail: detail}},
	}
}
