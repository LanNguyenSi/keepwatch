package probes_test

import (
	"strings"
	"testing"

	"github.com/LanNguyenSi/keepwatch/internal/result"
)

func pkgArgv(pkg string) []string {
	return []string{"dpkg-query", "-W", "-f=${Status}\t${Version}\n", "--", pkg}
}

func TestPackageInstalledFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		pkg     string
		want    result.Status
		detail  string
	}{
		{"dpkg_installed", "fail2ban", result.Pass, ""},
		{"dpkg_unknown", "nosuchpkg-x", result.Fail, "not installed"},
		{"dpkg_config_files", "rsync", result.Fail, "deinstall ok config-files"},
	}
	for _, v := range versions {
		for _, c := range cases {
			t.Run(v+"/"+c.fixture, func(t *testing.T) {
				p := prepare(t, "package_installed", map[string]any{"package": c.pkg})
				o := exec(p, newRunner().Add(pkgArgv(c.pkg), v+"/"+c.fixture), nil)
				wantStatus(t, o, c.want)
				if c.want == result.Fail {
					if len(o.Evidence) != 1 || o.Evidence[0].Subject != c.pkg || !strings.Contains(o.Evidence[0].Detail, c.detail) {
						t.Fatalf("evidence = %+v", o.Evidence)
					}
				}
				if c.want == result.Pass {
					wantSummary(t, o, c.pkg)
				}
			})
		}
	}
}

func TestPackageInstalledStrictParsing(t *testing.T) {
	const pkg = "fail2ban"
	noMatch := execResult("", "dpkg-query: no packages found matching fail2ban\n", 1)
	cases := []struct {
		name string
		res  execResultT
		want result.Status
	}{
		{"installed", execResult("install ok installed\t1.0\n", "", 0), result.Pass},
		{"held but installed", execResult("hold ok installed\t1.0\n", "", 0), result.Pass},
		{"marked for removal but installed", execResult("deinstall ok installed\t1.0\n", "", 0), result.Pass},
		{"installed on one architecture of several", execResult("install ok installed\t1.0\ninstall ok not-installed\t\n", "", 0), result.Pass},
		{"installed, then garbage line", execResult("install ok installed\t1.0\nsomething else\n", "", 0), result.Error},
		{"needs reinstall", execResult("install reinstreq installed\t1.0\n", "", 0), result.Fail},
		{"half configured", execResult("install ok half-configured\t1.0\n", "", 0), result.Fail},
		{"unpacked", execResult("install ok unpacked\t1.0\n", "", 0), result.Fail},
		{"config files", execResult("deinstall ok config-files\t1.0\n", "", 0), result.Fail},
		{"not installed record", execResult("unknown ok not-installed\t\n", "", 0), result.Fail},
		{"no match message", noMatch, result.Fail},
		{"no match message but stdout present", execResult("install ok installed\t1\n", "dpkg-query: no packages found matching fail2ban\n", 1), result.Error},
		{"exit 1 without the message", execResult("", "dpkg-query: error: something else\n", 1), result.Error},
		{"exit 1 with the message for another package", execResult("", "dpkg-query: no packages found matching other\n", 1), result.Error},
		{"exit 1 and nothing at all", execResult("", "", 1), result.Error},
		{"exit 2", execResult("install ok installed\t1.0\n", "dpkg-query: error: db locked\n", 2), result.Error},
		{"exit 255", execResult("", "", 255), result.Error},
		{"empty output exit 0", execResult("", "", 0), result.Error},
		{"blank output exit 0", execResult("\n", "", 0), result.Error},
		{"no tab", execResult("install ok installed 1.0\n", "", 0), result.Error},
		{"two words", execResult("install installed\t1.0\n", "", 0), result.Error},
		{"four words", execResult("install ok installed extra\t1.0\n", "", 0), result.Error},
		{"unknown status word", execResult("install ok installed-ish\t1.0\n", "", 0), result.Error},
		{"html", execResult("<html>502</html>", "", 0), result.Error},
	}
	p := prepare(t, "package_installed", map[string]any{"package": pkg})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRunner().AddResult(pkgArgv(pkg), c.res.Result)
			wantStatus(t, exec(p, r, nil), c.want)
		})
	}
}

func TestPackageInstalledFailureModes(t *testing.T) {
	p := prepare(t, "package_installed", map[string]any{"package": "fail2ban"})
	commonFailures(t, p, pkgArgv("fail2ban"), "dpkg-query", nil)
}

func TestPackageInstalledParams(t *testing.T) {
	for _, s := range []string{"fail2ban", "libstdc++6", "python3.12", "g++", "ab", "0ad"} {
		prepare(t, "package_installed", map[string]any{"package": s})
	}
	// The case that matters: "-fail2ban" is read by dpkg-query as the option
	// "-f" with the argument "ail2ban" and dumps the whole package database.
	bad := []string{"-fail2ban", "--help", "-W", "-", "", "a", "Fail2ban", "fail*", "fail2ban:amd64", "a b", "a;b", "$(id)", "a\nb", "a/b", "[a-z]x", "fa?l", strings.Repeat("a", 129)}
	for _, s := range bad {
		t.Run("package="+s, func(t *testing.T) {
			err := prepareErr(t, "package_installed", map[string]any{"package": s})
			if strings.HasPrefix(s, "-") && !strings.Contains(err.Error(), "must not start with") {
				t.Fatalf("a leading dash must be rejected as such, got %v", err)
			}
		})
	}
	prepareErr(t, "package_installed", nil)
	prepareErr(t, "package_installed", map[string]any{"package": true})
	prepareErr(t, "package_installed", map[string]any{"package": "fail2ban", "extra": "x"})
}
