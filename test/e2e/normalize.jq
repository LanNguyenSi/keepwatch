# Normalises one keepwatch JSON report for the golden comparison.
# Every rewrite here is listed with its reason in the README (section
# "End-to-end tests"). Nothing here may touch a check id, a status, a
# severity, a change kind, an alert flag or an exit code: run.sh checks that
# separately (see signature.jq).

def ts: if . == null then . else "<timestamp>" end;

# apt installs the current archive version of a package, so the version in
# "<pkg> <version> is installed" drifts between builds.
def pkgver: sub("^(?<p>fail2ban|unattended-upgrades|needrestart) [^ ]+ is installed$"; "\(.p) <version> is installed");

# The number of mounts a container runtime shows differs between runtimes.
def mounts: sub("^[0-9]+ file system\\(s\\) below"; "<n> file system(s) below");

.generated_at |= ts
| if .state.previous_run_at != null then .state.previous_run_at |= ts else . end
| .results |= map(.summary |= (pkgver | mounts))
