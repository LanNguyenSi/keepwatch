# keepwatch

A small, self-hosted guardian for Linux servers.

Status: pre-MVP, under active development. Not ready for use.

keepwatch checks the security posture of a host (for example: is fail2ban
running, is SSH password login disabled, which ports are listening), reports
only what changed since the last run, and sends the result to a notification
channel. Later stages add log-based detection, optional triage with a local
LLM, and policy-gated, human-approved actions with a tamper-evident audit log.

## Build

Requires Go 1.27 or newer.

```sh
make build    # bin/keepwatch (host) and bin/keepwatch-linux-amd64, static
```

## Test

```sh
make test     # go test -race ./...
make lint     # gofmt, go vet, staticcheck
```

## End-to-end tests

```sh
make e2e                              # Ubuntu 22.04 and 24.04, needs docker, jq and go
test/e2e/run.sh 24.04                 # one release
test/e2e/run.sh -update               # rewrite the golden files after a deliberate change
```

`test/e2e/` builds keepwatch for `linux/<arch of the docker daemon>`, copies it
into a fresh container of an image per release (`keepwatch-e2e:22.04`,
`keepwatch-e2e:24.04`; the Ubuntu base is pinned by digest, the packages are the
current archive) and runs `keepwatch check --format json` in five scenarios:

| Scenario | What it does | Expected exit codes |
|---|---|---|
| `hardened` | sshd with password, keyboard-interactive and root login off | 0 |
| `open` | sshd with password login, keyboard-interactive, root login and X11 forwarding on; the four `ssh.*` checks fail | 1 |
| `diff` | a run, then a TCP listener on port 8080 outside the allowlist, then a second run: `network.listeners` is a `new_failure` with an alert | 0, 1 |
| `nochange` | two runs without a change: no changes | 0, 0 |
| `reboot` | a run, then the reboot marker file, then a second run: `system.reboot_required` is a `new_failure` with an alert | 0, 1 |

`run.sh` also asserts the exit code of every run against a table of its own, independent of the golden files, and in `-update` mode it refuses to write an empty or invalid result.

The reports are compared with `test/e2e/golden/<release>/<scenario>.json`, which
also hold the exit code of every run and its stderr (empty). The container
starts sshd and fail2ban by hand, because there is no systemd.

The deployment targets are x86_64 servers. The optional workflow
`.github/workflows/e2e.yml` (manual, and on pull requests that touch `test/e2e`,
`internal`, `cmd`, `go.mod` or the Makefile; not a required check) runs the same
target on an x86_64 runner. Locally on an arm64 machine the binary is built for
arm64.

### Container limits

These are expected in the golden files, each with the reason keepwatch gives:

| Check | Status | Why |
|---|---|---|
| `services.fail2ban_active`, `services.unattended_upgrades_active` | `skipped` | there is no systemd, so no `systemctl` |
| `network.firewall_default` | `skipped` | neither nft, iptables nor ip6tables is installed in the image, a container has no firewall backend of its own |
| `updates.security_pending` | `warn` | the image carries no apt package lists (no `InRelease`), so the age of the lists is unknown; a pending update would not be seen |
| `docker.exposure` | `skipped` | no docker, no daemon configuration |
| `ssh.authorized_keys` | `skipped` | the test configuration names no expected keys |
| `certs.expiry` | `skipped` | the image holds no certificate |
| `system.reboot_required` | `skipped` (disabled in the configuration) | a container has no kernel to reboot; only the `reboot` scenario enables the check, and there the `pass` of the first run only says that the marker file is absent |

No golden file holds a `pass` that exists only because the container lacks the
thing: the checks above are `skipped` or `warn` instead. The `pass` results are
real findings about the container: the three packages are installed, the
effective sshd options, the `sshd` jail of fail2ban is running (a drop-in
points it at a plain log file instead of the journal), only sshd listens, and
the file systems are below the thresholds. `disk.usage` is configured with
thresholds of 99 and 100 percent, so a full runner cannot change the result.

### Normalisation

Before the comparison the report is rewritten in `test/e2e/normalize.jq`, and
nothing else:

| Field | Rewritten to | Why |
|---|---|---|
| `generated_at` | `<timestamp>` | the time of the run |
| `state.previous_run_at` | `<timestamp>` | the time of the previous run |
| `summary` of `packages.*_installed` (`fail2ban`, `unattended-upgrades`, `needrestart`): the version | `<version>` | apt installs the current archive version, which changes between image builds |
| `summary` of `disk.usage`: the number of file systems | `<n>` | the number of mounts depends on the container runtime |

The host name is not normalised: the container gets a fixed one. After the
rewrite, `run.sh` compares what `test/e2e/signature.jq` extracts (check ids,
kinds, statuses, severities, changes with their alert flag, subjects and
status transitions, the lists of still failing and warning checks, the counts,
the exit code, `fail_on` and the wording of each summary without its numbers, versions and placeholders) from the raw and the rewritten report, and fails
when they differ. A rewrite cannot hide a status or a check id.

## Sandbox measurement

```sh
make systemd                          # Ubuntu 22.04 and 24.04, needs docker and go
test/systemd/run.sh 24.04             # one release
test/systemd/run.sh -update           # rewrite the measured and answer files after a deliberate change
```

The installed services run in a sandbox, and `install` and `doctor` refuse every path
the sandbox would take away from them ([Where the paths must lie](#where-the-paths-must-lie)).
They decide that from a table of paths. `test/systemd/` checks the table against a real
sandbox, on a container per release whose PID 1 is systemd (`keepwatch-systemd:22.04`,
`keepwatch-systemd:24.04`, privileged, the Ubuntu base pinned by digest):

1. `keepwatch install`, then a probe unit that is the installed check service with
   another program. It prints the device and inode of some two hundred directories; the
   same list is taken on the host before and after. A directory whose pair differs is
   one the service does not see (`hidden`). Inside a hidden directory the ones that are
   the host's all the same are listed too (`visible`), and so are the volatile and
   kernel file systems of the mount table (`mount`) and the links that lead into any of
   it (`link`).
2. For every directory of that list keepwatch is asked: `install` with a `state_dir`
   below it (a real install, which must refuse and create nothing), with a token file
   and with a configuration below it (where a file can be created), and `doctor` for
   units whose binary lies below it. Each must refuse and name the path.
3. The list must equal `test/systemd/measured/<release>.txt`, and the answers of step 2
   must equal `test/systemd/answers/<release>.txt`, so a question that is no longer asked
   fails too.

`go test` then ties those files to the table, in both directions
(`TestSandboxPathsFollowTheMeasuredSandbox`): every measured line is refused for every
role by an entry that says the right thing about it, and every entry of the table is
borne out by a line. So the table cannot claim that the sandbox hides a directory that
it does not hide, and a directory that a new systemd hides makes `make systemd` fail
until the table knows it.

The measurement depends on the kernel and the container runtime as well (`/proc` counts
as hidden because `ProtectKernelTunables=yes` and `ProtectControlGroups=yes` imply
`MountAPIVFS=yes`, which gives the service its own instance of it). It is a
local target; no workflow runs it.

## Configuration

The main file is `/etc/keepwatch/keepwatch.yaml` (override with
`--config`). Every `*.yaml` in a `conf.d` directory next to it is loaded
in lexicographic order and merged in: mappings merge per key (later
files win), sequences such as `exceptions` and `listeners.allow` append,
and scalars are replaced by the later file. A missing `conf.d` is fine;
a missing main file is an error. Unknown keys, wrong types and out-of-range
values are rejected, each error naming `file:line`.

More rules, all reported with `file:line`:

- The root of every file must be a mapping (an empty or null document
  is treated as empty; a file never replaces another file's root).
- A key repeated within the same mapping of the same file is an error
  at any depth; the same key set again by a later file is an override.
  Validation runs on the merged result, so a value that a later file
  replaces is not checked on its own (known limit).
- `conf.d` must not be a symlink, dangling or not.
- `notify.ntfy.token_file` must be a clean absolute path (no `.`, `..`
  or repeated `/`).
- Scalars are matched by YAML type: `enabled` is true/false, `port` is
  an integer, strings are strings (quoted `"22"` is not a port),
  `expires` is a `YYYY-MM-DD` date. A null (`~`) value counts as absent
  for optional fields and is an error for required ones; a section key
  with a null value (an empty `exceptions:` or `checks:`, for example)
  counts as an absent section, and so do the optional nested mappings
  `checks.<id>.params`, `authorized_keys.expected` and `notify.ntfy`.
- A null value in a `conf.d` file contributes nothing where an earlier
  file already has the key: a drop-in with a bare `notify:` (or a block
  that is entirely commented out) leaves the main file's `notify`
  section intact. A null in an earlier file does not block a later one.
- Entries of `conf.d` whose name starts with a dot (`.hidden.yaml`, an
  editor lock symlink such as `.#a.yaml`) are ignored, like a shell glob
  ignores them.
- `*.yml` in `conf.d` is an error, and so is `a.YAML`, `b.Yml` or any
  other case of the extension: use lower-case `.yaml`. A
  subdirectory inside `conf.d` is an error too.
- Because keepwatch runs as root, the final component of every loaded
  path is never followed (a symlink is refused), and each file's type,
  size (max 1 MiB), permissions (no group or other write bits, mode
  0644 or stricter) and ownership (root or the running user) are
  checked on the open file descriptor itself. The directories holding
  the main file, `conf.d` and the token file must be real directories
  owned by root or the running user and not writable by group or
  other; deeper ancestor directories are not checked by the loader
  (known limit of a run by hand; `install` and `doctor` walk every
  ancestor, see [Where the paths must lie](#where-the-paths-must-lie)).
- `notify.ntfy.url` is required when `notify.ntfy` is set (https, or
  http only for loopback; no credentials, query or fragment; a URL port must
  be 1-65535). It is the address of the server, not of the topic: see
  [Notifications](#notifications). `notify.ntfy.topic` is required too, 1 to 64
  characters of `A-Z a-z 0-9 _ -`. Both are checked by the same rule that the
  notifier applies, so a configuration that loads always builds a notifier; the
  error names the file and line and never repeats the URL, which may hold credentials.
- `notify.ntfy.token_file` must be a regular file, at most 4096 bytes,
  with exactly one hard link, mode 0600 or stricter, owned by the
  running user and not empty; it is validated without reading and
  fully re-checked every time the token is read.
- `keepwatch init` writes the example file atomically (temp file +
  rename, mode 0640) into a directory that must not be a symlink or
  writable by group or other and must be owned by root or the running
  user; it refuses to follow symlinks, and `--force` only replaces a
  regular file.

- `redact.patterns` is an optional list of extra redaction patterns, see
  [Redaction](#redaction).

```sh
keepwatch init --config /etc/keepwatch/keepwatch.yaml   # write a commented example
keepwatch config check --config /etc/keepwatch/keepwatch.yaml
```

## Checks

A check is an entry of the catalog (embedded in the binary, one YAML file)
that names a kind and its parameters. Every kind is read-only: it runs fixed
programs without a shell, or reads files, and never touches the network.
A program that is not installed makes the check `skipped`; a timeout,
truncated output, an unexpected exit status or output that does not parse
makes it `error`, never `pass`. Some kinds also report `warn`, a soft
deviation: nothing failed, but something needs a look.

| Kind | Reads | Parameters |
|---|---|---|
| `service_active` | `systemctl is-active -- <service>` | `service` (unit name) |
| `package_installed` | `dpkg-query -W` for one package | `package` (Debian package name) |
| `sshd_effective` | `sshd -T`, the effective configuration with drop-ins merged in | `option`, `allow` (list), `aliases` (list, optional) |
| `fail2ban_jail` | `fail2ban-client -- status <jail>` | `jail` |
| `listeners` | `ss -Hltn` and `ss -Hlun`, compared with `listeners.allow`; `ss -Hltnp` and `ss -Hlunp` only to name the processes | `allow_loopback` (default true), `protos` (list, default tcp and udp) |
| `reboot_required` | `/var/run/reboot-required` and `.pkgs`, and `needrestart -b -k -r l` when installed | none |
| `firewall_default` | `nft -j list ruleset`, `iptables -V` and `-S INPUT`, `ip6tables -V` and `-S INPUT`; `ufw status verbose` for the explanation | none |
| `security_updates` | `apt-get -s -o Debug::NoLocking=true dist-upgrade`, `apt-cache policy -- <packages>` for the packages it upgrades, and the age of `/var/lib/apt/lists/*InRelease` | `max_list_age_hours` (default 48) |
| `docker_exposure` | `/etc/docker/daemon.json`, the running dockerd's command line, `docker ps` and `docker inspect` | none |
| `authorized_keys` | `sshd -T` (the shared run), `/etc/passwd`, and the users' authorized keys files | none (`authorized_keys.expected` is a top-level section) |
| `disk_usage` | `/proc/self/mountinfo` and statfs on the mounts | `warn_percent` (80), `fail_percent` (90), `fstypes` (list) |
| `cert_expiry` | certificate files | `paths` (list), `globs` (list, default Let's Encrypt), `warn_days` (30), `fail_days` (14) |

Names that reach a command line (unit, package and jail names) are checked
against a strict pattern, and a leading `-` is always rejected.

`listeners` takes the socket set from `ss` without `-p` alone; the process
names in the evidence come from a separate best-effort `ss -p` run that only
fills the detail text (a failing run leaves the processes "unknown" and never
changes the status). A listener bound to an interface is reported with the
interface after the address, for example `udp/[fe80::1]%eth0:546` or
`tcp/*%lo:7002`. `listeners.allow` cannot name an interface, so such a
listener is allowed by an entry for its address without the interface, or by
`bind: "*"`; `allow_loopback` only covers loopback addresses, not a wildcard
bound to `lo`. An IPv4-mapped listener (`[::ffff:0.0.0.0]:N`) matches only an
entry with bind `*` or the mapped literal. The two runs that decide the socket
set may print up to 64 MiB, so a flood of listening sockets from an
unprivileged process does not reach the limit. If the output is cut anyway,
the complete lines before the cut are still examined and the result is
`error`, with the not allowed sockets found there as evidence and a summary
that says the output was truncated; it is never `pass`. The limit that
remains: `ss` prints in the order of the kernel, so a flood beyond 64 MiB can
hide sockets that come after the cut. Files are read without following a symbolic link in the last
path component and only if they are regular files.

`firewall_default` judges what the kernel enforces: a base chain of type
filter on the input hook with policy drop in an `ip`, `ip6` or `inet` nftables
table, and `-P INPUT DROP` of iptables (IPv4) and ip6tables (IPv6). Both
families need a drop, from any one readable source, because a drop in any hook
is final. Forward and nat chains (Docker sets some up), chains without a hook
and tables that are dormant do not count. Which iptables it is decides what its
`DROP` means: the legacy variant programs the kernel's xtables, so its policy
counts; the `nf_tables` variant (what Ubuntu 22.04 and 24.04 install) only
writes an nftables table, and prints `-P INPUT DROP` for a table that nft shows
as dormant, where packets are accepted. For that variant the policy counts
only when nft shows the active chain, or (with a note) when nft is not
installed; when nft cannot be read the result is `error`. `ufw` is only read to
explain: it can neither add a drop nor remove one, and the check says when it
reports `deny` while the kernel does not drop. A source that cannot be read
does not stop a pass that another source confirms, but turns a fail into
`error`. Limit: it judges the default policy of the base chains, not their
rules; a drop chain that starts with a rule accepting everything passes. The
priority order of several input chains does not matter: an accept in a chain
with a lower priority number ends only that chain, so a later chain with policy
drop still drops the packet (measured on both releases).

`security_updates` simulates `apt-get dist-upgrade` (nothing is installed, no lock
is taken, and `apt-get update` is not run) and asks `apt-cache policy` about the
packages it upgrades. Both run with `-o Dir::Cache::pkgcache= -o
Dir::Cache::srcpkgcache=`, which keeps apt from writing its cache files under
`/var/cache/apt` (about 130 MB when the distribution's `docker-clean` snippet
is absent; measured on both releases: nothing under `/var/cache/apt` or
`/var/lib/apt` changes). A package fails when any version that a `-security`
pocket carries (`-infra-security` and `-apps-security` too) is newer than the
installed one, even if the version the simulation would install comes from
`-updates` and has superseded the security fix; the order of versions is apt's
own, the check compares no version strings. One evidence item per package. It
also reports how old the package lists are and warns when they are older than
`max_list_age_hours` or missing, because then it cannot see newer updates.
Packages that apt does not upgrade (held with `apt-mark hold`, blocked by a
dependency that cannot be met, or deferred by Ubuntu's phased updates; apt names
them under "kept back" or, with apt 2.8, "deferred due to phasing") are counted
in the summary and looked up the same way: a held package with a newer security
version fails the check, and its detail says apt keeps it back. The output of
both apt commands must be understood line by line (the phased marker
` (phased N%)` that apt prints on a version row is one of the known shapes); a
line of any other shape, or a kept back list that does not match the count in
the summary, makes the result `error`. Together at most 2000 upgraded and kept
back packages are looked up; with more the result is `error`. Limit: an
administrator's apt pin on a `-security` pocket (`Pin-Priority` below 100, or
-1) keeps the security version out of apt's candidates, so the check passes;
that is the administrator's choice and the check does not second-guess it.

`docker_exposure` fails when the daemon listens on TCP (an entry in
`daemon.json` `hosts`, or `-H`/`--host` on the running dockerd's command line,
including combined single-dash letters such as `-DH tcp://...`, which pflag
reads as `-D` and `-H`; an entry without a scheme counts as TCP) and for every running container that
is privileged, shares the host's PID or network namespace, or has a Docker
socket mounted; the subject is the container name. A listener that systemd
opens for `-H fd://` is seen by the `listeners` check. The process behind the pid
file must be owned by root and be a `dockerd` before its command line (and a
`--config-file` in it) is used; otherwise the result is `error`. A running
dockerd without the `docker` program is an `error` too (the containers cannot
be examined). At most 500 running containers are examined. Without the `docker`
program it is skipped, unless a daemon configuration exists. Limit: an
exception matches the container name, so it also covers any new reason the same
container gets later (for example a privileged container that was only
host-networked when the exception was written).

`authorized_keys` compares the SHA256 fingerprints of the keys in each user's
authorized keys files with the top-level `authorized_keys.expected` section
(user name to a list of `SHA256:...` fingerprints, as `ssh-keygen -lf` prints
them); without it the check is skipped. Users are the accounts of `/etc/passwd`
with uid 0 or 1000 and above and a login shell, plus the users named in
`expected` (accounts that only exist in NSS or LDAP are not seen). A passwd line
that does not have exactly seven fields is a `warn` and its user is not
examined. The files come from `AuthorizedKeysFile` in `sshd -T`. A key that is
not expected is a `fail` (subject `user:SHA256:...`); an expected key that is
missing, a file that could not be read or has lines that are not keys, and an
`AuthorizedKeysCommand` (whose keys cannot be checked) are `warn`.

A line is read the way OpenSSH 8.9 and 9.6 read it, and the differences are
stated here. Mirrored (ports of `check_authkey_line`, `sshkey_read`,
`sshkey_advance_past_options`, `b64_pton` and the integer rules of
`sshkey_from_blob`): a line ends at a NUL; a key at the start of the line, else
the options are stepped over (quotes, backslash-quote; they are not
interpreted) and a key follows; the key type must be one of the names `sshkey_read`
accepts (`ssh-ed25519`, `ssh-rsa`, `rsa-sha2-256`, `rsa-sha2-512`, `ssh-dss`,
`ecdsa-sha2-nistp256`/`384`/`521`, `sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`,
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com`), compared exactly and
case-sensitively (`ED25519`, `RSA` are not key types in this file); the base64
text may hold any C whitespace character (vertical tab, form feed, carriage
return) and must decode strictly; the fingerprint is taken over the key as
OpenSSH writes it back (RSA and DSA integers with extra leading zero bytes give
the fingerprint of their canonical form), so it equals the one `ssh-keygen -l`
prints; a comment of any length is ignored. Not mirrored: the options are not
parsed, so a line that sshd refuses because of a bad option is still listed (a
key may be listed that cannot log in); an ECDSA point is checked for its size
and uncompressed form, not for lying on the curve, and an RSA key is not checked
for its length; certificates (`-cert-v01@openssh.com` types) are read by sshd but
never match a login key, so they count as lines that are not keys (a `warn`);
a key blob over 16 KiB (a security key with a very long application string, for
example) is not fingerprinted and counts as a line that cannot be read (a
`fail`, see below).
A line that cannot be read but starts with the name of a key type that sshd
reads (as its first word, or as the first word after the options) is a `fail`
and not a `warn`: sshd may accept a key from it that is not checked (subject
`user:path:line`, the reason is a fixed text, the line is never quoted).
The test set holds 85 lines on each release with what `ssh-keygen -lf` printed
and which keys a real sshd accepted for them (`testdata/ubuntuXXXX/keycases`,
`keycases.sh`), and a test asserts: a key that sshd accepts is listed with
exactly its fingerprint, and no key is listed that neither sshd accepts nor
`ssh-keygen` lists. The users own their files and every directory below
their home, so a path inside the home is resolved by the kernel inside the home:
a symbolic link that leaves it (sshd would follow it), a file that is not a
regular file, one owned by somebody else, and one over 256 KiB are refused and
reported as a `warn`, never read, so their keys are not listed. A line that is
not a key is reported by line number and never quoted.
Limits: `Match` blocks of `sshd_config` are not evaluated, and a `warn` of this
check deserves attention, because it can stand for keys that were not checked.

`disk_usage` examines the mounts of the given file system types (`fstypes`
replaces the default list ext4, xfs, btrfs, vfat, zfs; network and pseudo file
systems are left out so that a hung NFS cannot block the run) for blocks and
inodes, computed like `df`. Each statfs call has a timeout.

`cert_expiry` reads certificate files (`paths`, and files matching `globs`;
setting `paths` does not remove the default glob, `globs: []` does) and examines
the first certificate in each. Symbolic links are followed (certbot's `live/`
points into `archive/`) only when every directory the path goes through (the ones
that hold a link as well as the ones it leads into), every link and the resolved
file are owned by root and not writable by group or others; otherwise that file
is an `error` with the reason. A link in a directory that a user can write to is
refused although it names a root-owned certificate. A listed path that does not exist is an `error`;
with no file found at all the check is `skipped`.

At most 100 evidence items come back from a check, sorted by subject; when
there are more, the last item is a marker "(N more not shown)" and the summary
says "and N more". The marker keeps an exception for the shown items from
hiding the rest. The complete list is kept next to it as a set of keys so that the
comparison with the previous run sees every item, not only the shown ones (see
"The comparison with the last run").

Under `checks.<id>` in the configuration, `enabled: false` skips a check,
`severity` replaces the catalog severity, and `params` are merged over the
catalog's parameters key by key: a key set in the configuration replaces
the catalog value as a whole. For the list parameters that means the
configured list replaces the catalog default (`allow` and `aliases` of
`sshd_effective`, `protos` of `listeners`, `fstypes` of `disk_usage`, `paths`
and `globs` of `cert_expiry`); it never extends it. As for any
list in the configuration, lists set in `conf.d` drop-ins are appended to the
main file's list before the checks see them, so a drop-in can widen an
`allow`. The listener allowlist is the top-level `listeners.allow` section,
not a check parameter. Unknown parameter keys, wrong types and bad values
are errors, and so is a `checks.<id>` or `exceptions[].check` that names an id
the catalog does not have (an exception may also name `exception_expired`).

An active exception without `match` covers the whole check. With `match` it
covers the evidence items whose subject equals `match` exactly (for example
`tcp/0.0.0.0:8080`, `passwordauthentication`, `fail2ban.service`). A check
whose failing items are all covered becomes `excepted`, unless the check also
found warnings (for example an expected key that is missing next to an
unexpected one): then it becomes `warn`, its evidence the warnings, because an
exception removes failures and never warnings. Otherwise it stays `fail` and the
covered items are marked. Exceptions never change an `error` or a `warn`.
An `error` of a check that reads two sources (`reboot_required`, and
`listeners` with tcp and udp) keeps the failing items that the readable source
confirmed and says in its summary that the picture is partial.
Each expired exception is reported as its own `exception_expired` result
(severity low).

## Running a check

```sh
keepwatch check [--config FILE] [--format text|json|markdown] [--no-state] [--fail-on SEVERITY] [--notify]
```

`check` loads the configuration, runs every enabled check of the catalog,
compares the result with the previous run, prints a report and stores the
result as the new "previous run".

| Flag | Meaning |
|---|---|
| `--config FILE` | main configuration file (default `/etc/keepwatch/keepwatch.yaml`) |
| `--format` | `text` (default), `json` or `markdown` |
| `--no-state` | only check: the state of the last run is neither read nor written, and the report has no comparison |
| `--fail-on SEVERITY` | lowest severity that makes the exit code 1: `info`, `low`, `medium` (default), `high`, `critical` |
| `--notify` | send the changes worth an alert (and on a first run the open findings) to the ntfy topic, see [Notifications](#notifications); cannot be combined with `--no-state` |

The JSON report carries `schema_version` 2. Version 2 added the change kinds
`hidden_gone` and `set_changed` (with the fields `hidden_gone`, `old_total` and
`new_total`) and no longer produces `count_change`, which version 1 reports could
hold.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no result counts at `--fail-on` |
| 1 | at least one result counts at `--fail-on` |
| 2 | usage error (unknown flag, bad `--format` or `--fail-on`, extra argument) |
| 3 | keepwatch could not do its job: invalid configuration (also `--notify` without `notify.ntfy`), a state directory that cannot be trusted or a state that cannot be saved, a state of the run itself that contradicts itself (an internal error), an interrupted run, a failed write of the report |
| 4 | `--notify` (or `report --weekly --notify`) could not deliver the notification, see [Notifications](#notifications) |

What counts for exit code 1, per status, when the check's severity is at least
`--fail-on`:

| Status | Counts | Why |
|---|---|---|
| `fail` | yes | a deviation |
| `error` | yes | the check could not be evaluated; an unknown state must not look green |
| `warn` | only for the `authorized_keys` check | a warn there can stand for keys that were never examined; every other warn is a soft deviation and leaves the exit code at 0 |
| `pass`, `skipped`, `excepted` | no | an excepted failure is covered by a dated exception with a reason |

The expired-exception result (`exception_expired`) is a `fail` of severity low,
so it counts only with `--fail-on low` or `--fail-on info`.

The exit code depends on the current results only, never on the comparison with
the last run: a timer that runs `check` every few hours sees exit 1 for as long
as the host stays bad. The comparison decides what is worth a notification.
Precedence: 3 wins over 4, 4 wins over 1, 1 wins over 0. Exit code 3 wins over
everything: if the state could not be handled, the run is not reliable, even
when the report (which is still printed) shows findings, and nothing is sent.
Exit code 4 wins over 1: while the host stays bad, 1 is what every run exits
with and says nothing new, whereas 4 says that an alert did not arrive. The
report was printed in both cases, and the next run repeats the checks' verdict. The
`exit_code` in a report is the one decided before the state is saved; a state
that cannot be saved is found after the report was written (see "State"), so it
is told on stderr and the process exits 3 although the report says 1 or 0.

### The comparison with the last run

Per check the report lists, in the order of the checks:

- `new_failure`: the check fails now and did not before (from `pass`, `skipped`,
  `excepted`, `warn` or `error`);
- `fixed`: it failed and passes now;
- `status_change`: every other change of status (`pass` to `error`, `fail` to
  `warn`, `excepted` to `pass`, ...);
- `severity_change`: the check has the same status (`fail`, `warn` or `error`) in
  both runs and another severity, for example because a configuration override
  changed it; it is an alert when the severity went up and the status counts
  toward the exit code (see above), since a failure that was below `--fail-on`
  can have crossed it;
- `check_added` and `check_removed`: the catalog gained or lost the check;
- for a check that is `fail` (or `warn`) in both runs: `subject_new` and
  `subject_gone` for items that appeared or disappeared, `hidden_new` and
  `hidden_gone` for items that did but that the check does not list, and
  `set_changed` for a list too long to compare item by item (see below);
- the checks that keep failing or warning unchanged ("still failing", "still
  warning").

A change is marked as an alert (worth a notification) when a check starts to
fail or to be in `error`, when a new check is failing or in `error`, when a
failing check has a new item (named, or counted as `hidden_new`) or a changed list that is too long to compare (`set_changed`), when a failing check or one
in `error` gets a higher severity, and when an `authorized_keys` check starts to
warn, is new and warns, or has a new warn item.
Everything else (fixed, gone items, a status change to `skipped`, `excepted` or
a `warn` of another check) is reported without the alert mark.

Two rules keep the comparison honest:

- An `error` is a partial picture: the check could not see everything. Its
  evidence is never compared item by item; the change of status is reported once.
- A check that has more than 100 items lists the first 99 sorted by subject and a
  marker "(N more not shown)". The marker is not an item: a change of N never
  produces new or gone subjects. Besides the 99 items the state keeps the
  complete list as a set of keys (the SHA-256 of each subject as the check
  produced it, sorted, without duplicates) and a digest of that list, so two runs are compared as sets and not
  by what happened to be listed. The failing set of a check is its keys without
  the keys of the items an exception covers. A list that is not cut is its own
  set, so a cut and a complete list compare like any other pair:
  - Both sets have at most 10,000 keys: the difference is exact. A key that is
    new in the failing set is `subject_new` (an alert) when its subject is among
    the items listed, and otherwise counted in one `hidden_new` change with the
    exact number (also an alert); a key that left it is `subject_gone` or counted
    in one `hidden_gone` (no alert). For example, a listener below the cut stops
    and a new one starts above it: `subject_gone` for the first and `hidden_new` 1
    for the second, although the total is the same. A subject that the report
    has to escape, redact or cut for display is still compared by the subject the
    check produced, not by its display text (see below for which checks keep the
    subject as it is).
  - A set has more than 10,000 keys: its keys are not stored, only its total and
    the digest. Equal digests mean the same list. Different digests are one
    `set_changed` change with both totals, an alert: that something changed is
    certain, which items is not told.
  So the limits are: the report names up to 99 items, counts exactly up to
  10,000, and detects any change above that. An item that appeared and went away
  between two runs is invisible, as it is for any comparison of two runs. An
  exception only marks the items that are listed; an excepted item that falls out
  of the listed part (because new items sort before it) is a failing item again
  and is reported as new.

Items are compared by the SHA-256 of the subject the check produced. For the
listeners (address and port), the authorized key fingerprints, the container
names and ids of `docker_exposure` and the package names of `security_updates`
that is the raw subject, so two subjects that look the same after the report
cleans them (they differ in a control character, say) are still two items. The
checks that name a path, a mount point or a free text clean the subject before
it becomes one (non-printable characters become `?`, long names are cut):
`cert_expiry` (file path), `disk_usage` (mount point), the TCP findings of
`docker_exposure` and the path, pattern and line warnings of `authorized_keys`
(its other warnings, such as an expected user or key not found, keep the raw text).
There, two names that differ only in a control character, or only after the cut,
are one item, and a change between them is not seen.

### State

The state is `state.json` in `state_dir` (default `/var/lib/keepwatch`): JSON
with `schema_version` (4; files of version 1 to 3 are not read), the time of the
run, the record of a failed delivery (see [Notifications](#notifications)) and, per check, its id, kind, status, severity and items (hash and cleaned,
redacted subject, and whether an exception covers it). For a check whose list was
cut it also holds the total, the sorted key list (up to 10,000 keys) and the
digest described above; the stored keys must be sorted, unique, hash-sized, match
the digest and include every stored item, otherwise the file is not used. It holds
no evidence detail text and no summaries, and nothing from a subject that is not
already in it as displayed. A key set costs 72 bytes per key in the file; the
largest state keepwatch can write (every one of the 18 checks capped, full and
with the longest subjects) is 15.3 MB, so the limit below is 16 MiB.

keepwatch runs as root and the state decides what the operator is told, so it is
checked:

- `state_dir` is cleaned with `filepath.Clean` and must be absolute. It is created
  with mode 0700 if it does not exist; otherwise it must be a real directory (not
  a symlink) owned by root or the running user that group and other cannot write
  to. Ancestors above it are not examined by `check` itself (known limit of a run by
  hand): they must be root-owned. `install` and `doctor` do examine them, see
  [Where the paths must lie](#where-the-paths-must-lie).
- The state file is opened without following links and checked on the open
  descriptor: a regular file of at most 16 MiB, owned by root or the running user,
  not writable by group or other.
- It is written atomically: a temporary file in the same directory (created
  exclusively, mode 0600), flushed, renamed over `state.json`, then the directory
  is flushed. If a step fails, the previous file stays and the temporary file is
  removed.

Recovery. A missing state file is a first run: a baseline, no changes are
reported. A state file that is a symlink, foreign-owned, group- or
other-writable, too large, truncated, not valid JSON, of another schema version
or invalid is reported as a warning (stderr and in the report) and the run is a
new baseline (this includes a file of an older schema version, which has no key
sets to compare with: the first run after an upgrade is a baseline); it is never an abort and never a silent "nothing changed". The
file is replaced at the end of the run, so nothing needs repairing; to start from
scratch, delete `state.json`. A state directory that cannot be trusted (or a
state that cannot be saved) is different: the report is still printed, state is
not read or written, and the exit code is 3, because the next run could not be
compared reliably.

Before the comparison, keepwatch checks the state it built from this run for
consistency: for each check with a key set, the digest is hash-sized and no
more items are listed than the total; and (for sets small enough to list their
keys) the keys are sorted, unique and hash-sized, the total and the digest match
them and every listed item is in the set. This cannot fail on a correct
build; if it does, it is a defect in keepwatch, not a property of the host. The
run then takes the same path as an unusable state directory: the report is still
printed, no changes are reported, a warning names the check and the rule (never
a subject), the stored state is left as it was and the exit code is 3.

The report is built first, written to stdout, then (with `--notify`) the
notification is sent, and only then is the state saved. A report that could not
be written (a closed pipe, a full disk) therefore leaves the state as it was: the
next run reports the same changes again instead of losing them, and the exit code
is 3. A notification that could not be delivered leaves the snapshot as it was too
(see [Notifications](#notifications)). A failed save cannot be part of the
report any more; it is a warning on stderr and exit code 3.

The state is written after a successful run, never after an interrupted one. A
manual `keepwatch check` counts as a run: it moves the "previous run" forward,
so a scheduled run after it reports changes only since that manual run. Use
`--no-state` for a look that must not do that.

### Notifications

`keepwatch check --notify` sends one message per run to an
[ntfy](https://docs.ntfy.sh/) topic, and only when there is something to tell.
ntfy is the only channel of stage 0. Nothing else is ever contacted: keepwatch has
no telemetry, and the address comes from the configuration only.

```yaml
notify:
  ntfy:
    url: https://ntfy.example.com        # the server, not the topic
    topic: keepwatch-alerts              # 1-64 characters of A-Z a-z 0-9 _ -
    token_file: /etc/keepwatch/ntfy.token  # optional, an access token (tk_...)
```

The message is posted to `<url>/<topic>` (a path prefix in `url`, for a server behind a
reverse proxy at `/ntfy`, is kept). `url` must be https, or http for a loopback host,
and holds no credentials, query or fragment; a bad `url` or `topic` is a configuration error
(`config check` finds it), and `--notify` without `notify.ntfy` is exit code 3 before any check runs. The token is read from
`token_file` every time a message is sent (through the same checks as at load time:
regular file, mode 0600, owned by the running user, no symlink) and goes only into the
`Authorization: Bearer` header; a token with a space, a control or a non-ASCII
character is refused. `token_file` is optional for a server that accepts anonymous
publishing.

**What is sent when.** The decision is made from the comparison with the last run
(the report's counts), never from the exit code: the exit code says that something
fails now, not that something changed.

| Run | Sent |
|---|---|
| first run, or the previous state was not usable | one notice: the counts and the open findings (`fail`, `warn`, `error`; for `fail` and `warn` up to three subjects, for `error` none) |
| at least one change is an alert (see "The comparison") | one message with the alerts, then the other changes (fixes, items that are gone), then the checks that keep failing |
| only changes that are not alerts (a fix, an item that is gone), or none | nothing; the state moves forward |
| the last delivery failed, whatever else happened | one message that says so, with the changes since the last delivered report |
| the state could not be used (exit 3) | nothing |

At most one message per run, so a timer that runs every few hours sends at most that
many messages a day, however many things change. A check in `error` is one change of
status; the evidence of an `error` is never listed item by item. If the delivery
of a baseline notice fails, the first state is stored with a `delivery` record of kind
`baseline`; the next run with `--notify` sends the open findings of that run again as a
"first report" (not the changes since a snapshot, because nothing was ever delivered),
and keeps doing so until a delivery works.

**Every string of a message is cut at 200 characters** (whole characters, with `...`), so
that one long subject cannot use up the body, and the alerts are listed with the highest
severity first: when the body is too small for all of them it is the low ones that are
left out ("N more lines not shown"), never the critical one. The counts in the title and
heading are always the real ones.

**Use `--notify` for every run that is supposed to tell.** A run without `--notify`
(a manual `keepwatch check`, a script) moves the snapshot forward like any other run, so
the alert-worthy changes it finds are consumed: the next scheduled run with `--notify`
compares with that snapshot and does not send them. When `notify.ntfy` is configured, such
a run says so on stderr ("moved the state forward past N alert-worthy changes that no
notification will tell"). Use `--no-state` for a look that must not do that.

**A signal during the delivery of `check --notify`** (SIGINT, SIGTERM) is an interrupted run like
one during the checks: exit code 3, nothing is stored, the next run reports and sends the same
changes. If the message had already reached the server, it arrives twice; it is never lost.
For `report --weekly --notify` a signal during the delivery counts as a failed delivery (exit
code 4, a weekly failure is recorded).

**Priority and tags.** The priority is that of the highest severity among the alerts
(baseline: among the `fail` and `error` findings): critical 5 (urgent), high 4, medium
3 (default), low 2, info 1. The weekly report has priority 3 (2 when nothing is open).
Tags are fixed words: `keepwatch` plus `rotating_light` (high or critical),
`warning`, `information_source` (baseline) or `calendar` (weekly report). The title is
`keepwatch <host>: N alerts` and the like, in printable ASCII (anything else becomes
`?`, which also keeps a line break or a header out of the title).

**Markdown.** The body is Markdown and is sent with the header `Markdown: yes`. ntfy
renders it only then. Checked against the sources of ntfy (server main at
v2.37.2, web app, Android app): the server does not interpret the body; the web app
renders it with remark-parse 9 (CommonMark, micromark), without the GFM extensions
(so no tables and no autolinks) and without raw HTML (a tag in the source is not
rendered, links and images get a protocol check); the Android app uses Markwon 4.6.2
(commonmark-java) with the image, linkify, table and strikethrough plugins. The
argument of [Output safety](#output-safety) therefore holds for ntfy: everything that
comes from the host or the configuration is put into a code span whose fence is longer
than any run of backticks in it, and nothing outside a code span is anything but bold
words, list markers, numbers and fixed phrases; a link, an image, HTML, a heading, an
`@` or a line that starts a block cannot be made out of evidence. One thing stays:
the Android app's linkify plugin acts on running text only and not on a code span
(Markwon 4.6.2: the listener is fired by the text visitor, not by the code visitor), and
ntfy shows the text of a message
to everybody who can read the topic: on an open server the topic name is the only
secret, so use a long one or an access token. No table is used, because the web app
does not render them. A body is cut at 3,600 bytes (ntfy's limit is 4,096; a longer body
would be turned into an attachment) with a line that says how many lines were left
out; the numbers in the heading are always the real ones.

**Redaction.** Every string of a message, the title included, goes through the
redactor (built-in patterns plus `redact.patterns`, control characters escaped) before
it is sent, the same as in the report. A message holds names of checks, item subjects
as the report shows them, counts, statuses and severities; never evidence detail, a
summary, a file content or a command line.

**The HTTP client.** It uses no proxy from the environment (`HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` are ignored: the token would travel through whatever they name; there is
no proxy setting), verifies TLS certificates (TLS 1.2 or newer), does not follow
redirects (a redirect could take the token to another host: it is an error, and the
`url` in the configuration should be the final address), keeps no connection between
runs, times out after 15 seconds per request and reads at most 64 KiB of an answer.
There is one retry after 2 seconds, and only for a network error, a timeout, a 5xx or
a 429; a `Retry-After` of up to 30 seconds is waited for, a longer one means no retry
in this run. Other 4xx answers (a refused token, an unknown topic) are not retried.
Error messages name the status and ntfy's own error text, never the topic or the token
(a network error names the address and port that could not be reached, as the system
reports it, which is the server you configured).

**When a delivery fails.** The exit code is 4, and the snapshot in `state.json` is not
moved forward: it is stored again as it was, with a `delivery` record (time, number of
failed runs in a row, kind, a short redacted reason). The history is not written
either. The next run therefore compares with the last snapshot whose changes were
delivered and reports the same changes again, together with "last delivery failed",
in the report (a warning), on stderr and in the message. The record is cleared when a
message is delivered. Without `--notify`, a run does not move a snapshot that holds
undelivered changes forward either (it says so on stderr), because that would mark
changes as seen that nobody was told; `--no-state` is the way to look without
touching anything. If the state cannot be saved after a successful delivery (exit
3), the next run tells the same changes a second time. Delivery is at least once.

### Weekly report

```sh
keepwatch report --weekly [--config FILE] [--format text|markdown] [--notify]
```

The digest of the open findings of the last run (from `state.json`, per check: status,
severity and up to three subjects) and of the changes of the last 7 days (from the
history, newest first, at most 25 lines, alerts marked). It runs no checks. Without
`--notify` it is printed (text, or Markdown); with `--notify` it is sent to ntfy (the
Markdown form, priority 3) and the command prints one line. A state or history that
cannot be used is a warning on stderr and a note in the digest, never an abort (an
untrusted state directory is exit code 3). A weekly report that cannot be delivered
is exit code 4 and a `delivery` record of kind `weekly` in the state (unless there is
a record already: the one about undelivered changes is the more important); the next
`check --notify` mentions it. `report` without `--weekly` is not implemented (exit
code 3).

### History

`history.json` in `state_dir`, next to `state.json`, written by `check` when it moves
the state forward (not with `--no-state`, not when a delivery failed): the last 60
runs and per run the changes of the comparison (kind, check id, severities, statuses,
the cleaned and redacted subject, counts, alert mark; at most 100 per run, the rest
is counted), nothing from evidence or summaries. A baseline run is recorded without
changes. The file follows the rules of the state file (real directory owned by root or
the running user, no group or other write, no symlink, regular file of the right owner
and mode, written to a temporary file and renamed) with a limit of 8 MiB: an ordinary
full history (60 runs of 100 changes) is about 1.7 MB, and when hostile subjects would take it past the limit
the oldest runs are dropped. It is a convenience, not a source of truth: a history that
cannot be read or written is a warning on stderr and does not change the exit code; an
unusable file is replaced by the next write. A `check` and a `report` that run at the
same moment are not coordinated, for `history.json` and for `state.json` alike (known
limit, like two `check` runs; there is no lock). `report --notify` narrows the window for
the one write it makes: it reads the state again right after a failed delivery (which
can be a minute after it first read it) and records the failure only if the snapshot and
the record are still the ones it started with, otherwise it only warns. What remains is
the time between that read and the rename.

### Output safety

Text in a report comes from probes and can carry what a local user chose (a
container name, a mount point, a file path) or a secret that someone put in a
command line. Every string of a report is cleaned before it is printed, whatever
the format:

1. secrets are replaced with `[REDACTED]` (see [Redaction](#redaction));
2. control characters are escaped into visible sequences: C0 controls and DEL
   (`\n`, `\r`, `\t`, `\x1b`, ...), C1 controls (`\u0085`), Unicode format
   characters including the bidirectional overrides, zero-width characters and
   the byte order mark, line and paragraph separators (`\u2028`), the right-to-left override (`\u202e`), characters
   that draw nothing and could make two names look alike (the Hangul and Khmer
   fillers such as `\u3164`, the combining grapheme joiner `\u034f`, the braille
   blank `\u2800`, the variation selectors `\ufe0f` and `\U000e0100`), private-use and
   unassigned code points, and bytes that are not valid UTF-8 (`\xff`), so an
   escape sequence cannot move the cursor, set a window title, forge a line,
   reverse the text or hide a difference between two names;
3. the result is cut at 2000 characters.

JSON is produced by `encoding/json` only. In Markdown, untrusted text appears
only in code spans whose fence is longer than any run of backticks in the text,
so it cannot open a link, an image, HTML or a heading; pipes are escaped in table
cells. In the text format every field is one line built by keepwatch.

### Redaction

Built-in patterns, applied before escaping, so a multi-line private key is still
one block when it is matched:

- PEM private key blocks (also one cut off before its end line);
- `name=value`, `name: value` and `"name": "value"` when the name ends in
  `password`, `passwd`, `passphrase`, `secret`, `token`, `api_key`, `access_key`,
  `private_key`, `secret_key` (also `auth_`, `signing_`, `encryption_` and
  `master_` plus `key`), `credential` or `credentials`, when it is `pass` or
  `pwd` or ends in them after a separator (`DB_PASS=`, `MYSQL_PWD=`), and
  `NAME_KEY=value` environment style (`token_file`, `passwordauthentication`
  and `bypass` are left alone). A quoted value may hold escaped quotes
  (`"a\"b"`) and a quote that is never closed runs to the end of the text;
- `--password value` style flags (also when a NUL byte, as in a command line
  read from `/proc`, separates the flag from its value; a flag counts only at the
  start or after a separator, so a word such as `prohibit-password` or
  `x-token` is not a flag), `Authorization: ...`
  values, `Cookie:` and `Set-Cookie:` values (the rest of the line), bearer
  tokens;
- URLs with credentials (`scheme://user:password@host`, `scheme://token@host`);
  the credentials end at the last `@` before the host, so a password with an `@`
  in it is covered;
- AWS access key ids, GitHub tokens (`ghp_`, `github_pat_`, ...), GitLab tokens
  (`glpat-`), API keys of the `sk-` family (`sk-...`, `sk-ant-...`), ntfy tokens
  (`tk_`), Slack tokens, Google API keys, Stripe keys and JSON web tokens.

Redaction is best effort: it knows the shapes above and cannot know a secret that
has none. The probes keep secrets out of evidence in the first place (they print
fingerprints and counts, never file contents).

Extra patterns go in the configuration:

```yaml
redact:
  patterns:
    - 'corp-[0-9]{4}'          # the whole match is replaced
    - 'session=([a-z0-9]+)'    # a capturing group: only the group is replaced
```

Patterns use RE2 syntax (no backtracking, no lookahead). They are compiled when
the configuration is loaded: at most 32 patterns of at most 256 bytes, none may
match the empty string or compile to a program of more than 1000 instructions
(a large repeat such as `(a|b|c|d|e){1000}` does; the text of a pattern is
short, but its cost is paid on every byte of every field that is shown), and a
bad one is a configuration error with file and line. Lists in `conf.d` files are appended to the main file's list. The redaction
function (`redact.Redactor.Clean`) is what the notification code uses as well.

## Scheduled runs: install, uninstall, doctor

```sh
keepwatch install [--interval 6h] [--weekly-report "Mon 08:00"] [--config FILE] [--dry-run] [--print]
keepwatch uninstall [--purge] [--config FILE] [--dry-run]
keepwatch doctor [--config FILE] [--send-test]
```

### install

`install` (run as root) writes four systemd units to `/etc/systemd/system`:
`keepwatch-check.service` and `.timer`, which run `keepwatch check --config FILE`
every `--interval`, and `keepwatch-report.service` and `.timer`, which run
`keepwatch report --weekly --config FILE` at the weekly time. When `notify.ntfy` is
configured in the configuration file that `install` reads, both commands get
`--notify`; without it they do not. The reason is the rule of
[Notifications](#notifications): a run without `--notify` consumes the alerts it
finds and nobody is told, and a run with `--notify` and no `notify.ntfy` exits 3.
So after adding `notify.ntfy` run `install` again (it updates the two services;
`doctor` reports a problem while they lack `--notify`). It creates `state_dir`
(mode 0700) if it is missing, runs `systemctl daemon-reload` and
`systemctl enable --now` for both timers, and restarts a timer whose schedule
changed. The units run the binary that ran `install` (its path is written into
them), so install it where it stays, for example `/usr/local/bin`.

It reads `state_dir`, whether `notify.ntfy` is set and its `token_file` from the
configuration file. A
missing file is refused (exit 2, also with `--dry-run` and `--print`, nothing written) with the hint to
create it with `keepwatch init` first, because every scheduled run would exit 3; so is an
invalid one, for the same reason.
`ReadWritePaths` in the units is that directory, so after changing `state_dir`
run `install` again (`doctor` tells when the two differ).

#### Where the paths must lie

The services are root processes in a sandbox. Every path they depend on must be one
that the sandbox shows them and one that nobody but root can rename, replace or
redirect; otherwise a scheduled run fails without telling anybody, or reads what
somebody else put there. `install` checks one list of paths with one rule and refuses
(exit 2, nothing written) when a path does not pass. `doctor` checks the same list
with the same rule, for what the installed units say, and prints the same message as
a problem.

| Path | Must be | May be missing |
|---|---|---|
| the keepwatch binary (`ExecStart`) | a regular file | no |
| the directory of the configuration file, and the file (`--config`) | a directory, a regular file | no |
| `conf.d` next to the configuration file | a directory | yes; checked when it is there |
| the directory of `notify.ntfy.token_file`, and the file | a directory, a regular file | only when `token_file` is not configured |
| `state_dir` (`ReadWritePaths`) | a directory | yes: then its parent directory is checked, `install` creates `state_dir` there and checks it again |

The rule, for each path:

1. It must not lie where the sandbox hides it, in a file system of the kernel, or
   where a reboot empties it. The rule is the same for every path of the table above,
   the binary, the configuration, the token file and `state_dir` alike: none of them
   may lie under `/dev`, `/proc`, `/sys`, `/run`, `/tmp` or `/var/tmp`, nor under the
   module directories `/usr/lib/modules` and `/lib/modules`. The message says what is
   the matter with the place:
   - `/tmp` and `/var/tmp` (`PrivateTmp=yes`), `/dev` (`PrivateDevices=yes`) and the
     module directories (`ProtectKernelModules=yes`): the services have their own or
     none, so the path does not exist for them.
   - `/run`, and so `/var/run` and `/var/lock`, which are links into it: a tmpfs that
     is empty after a reboot. A file there is gone until something puts it back, and a
     service whose `ReadWritePaths` names a missing directory does not start (status
     226/NAMESPACE). `/dev/shm` is the same.
   - `/run/credentials` and `/run/systemd/incoming`: systemd keeps them away from a
     sandboxed service although no option of the unit says so.
   - `/proc` and `/sys`: file systems of the kernel. A `state_dir` there is refused
     before anything is created (a directory made below `/sys/fs/cgroup` would be a
     control group).

   The options of the units are tied to this list by a test: an option cannot be
   added, changed or removed without the list being judged again. The list is also
   held to what a real sandbox was measured to hide, see
   [Sandbox measurement](#sandbox-measurement).
2. Every component of the path, from `/` down to the path itself, is looked at with
   `lstat` and must be no symbolic link, be owned by root and not be writable by
   group or other. So a configuration below `/home/someone` is refused even when the
   directory that holds it is root's: the owner of `/home/someone` can rename it away,
   and every run exits 3 from then on.

Symbolic links are refused in every component, also the harmless ones of the
system: give the real path. `/var/run` is `/run`, `/var/lock` is `/run/lock`, and on
a merged `/usr` the directories `/bin`, `/sbin` and `/lib` are `/usr/bin`,
`/usr/sbin` and `/usr/lib`; `realpath PATH` prints the path with every link
resolved. `install` and `doctor` never resolve a link for this check: the path written
into a unit, the one in the configuration and the one that was checked are the same text. (The binary
needs no care here, its path comes from the kernel already resolved.)

The message names the path, the component that failed and the fix, for a binary for
example `install -o root -g root -m 0755 keepwatch /usr/local/bin/` and then
`/usr/local/bin/keepwatch install`. What lies under a path that already has a
problem is not reported a second time.
Limits:

- A token file below `/run` is refused, also one that a secrets agent writes there at
  every boot: keepwatch cannot tell that it will be back before the timer fires. Keep
  the token on a file system that survives a reboot, for example in `/etc/keepwatch`.
  The units do not use `LoadCredential=`, so nothing can be handed to them through
  `/run/credentials` either.
- The list of places is a list of paths. A tmpfs or another volatile file system
  mounted somewhere else (a `/srv/scratch` on tmpfs, a `/tmp`-like mount under another
  name) is not detected: keepwatch does not read the mount table.
- POSIX ACLs, file capabilities and bind mounts over a checked directory are not
  examined.
- The walk shows who can change a path now; it does not notice a change later, and a
  unit that fails tells nobody (`doctor` shows the failed last run).
- `doctor` compares each installed service file with the unit `install` renders from the
  values the file holds, so a file edited by hand (a second `ExecStart` line, an added
  option that hides a path) is a problem, and so is a drop-in outside `service.d`. What a
  drop-in changes is not judged, see [doctor](#doctor).

`install` is idempotent: with nothing to change it prints `already installed,
nothing to change` and touches nothing (it still makes sure the timers are
enabled and active, and enables them if they are not). `--dry-run` lists the
directories, files and `systemctl` commands, and changes nothing (it asks
systemd read-only, and works without root). `--print` writes the four unit files
to stdout, each after a `# ===== name =====` line, and does nothing else; it wins over `--dry-run`.
Both refuse what `install` refuses about the configuration and the paths, with the
same message, so a unit file that is printed is one `install` would write; neither
creates anything, a missing `state_dir` included.

| Flag | Grammar |
|---|---|
| `--interval` | one number from 1 to 99999 without a leading zero and one unit, `m`, `h` or `d` (minutes, hours, days), lower case: `30m`, `6h`, `1d`. At least `5m`, at most `30d`. Written as `OnUnitActiveSec=`; the first run comes five minutes after boot, or at once when the host has been up for longer. Default `6h`. |
| `--weekly-report` | a day, `Mon` to `Sun` (exactly so, three letters), one space and a time `HH:MM` on the 24-hour clock with two digits each, in the local time of the host: `Mon 08:00`, `Sun 23:59`. Written as `OnCalendar=Mon *-*-* 08:00:00` with `Persistent=true`, so a report missed while the host was off runs when it is back. Default `Mon 08:00`. |
| `--config` | the main configuration file the services use (default `/etc/keepwatch/keepwatch.yaml`); made absolute and cleaned |

Anything else is a usage error (exit 2): a second unit, a fraction, a space or
newline in a value, `%`, a quote. The same goes for every path that is written
into a unit (the binary, the configuration file, `state_dir`): they must be
clean absolute paths of the characters `A-Z a-z 0-9 . _ - + @ /`, so no value can
add a line, an option or a systemd specifier. Where they may lie is the rule
[above](#where-the-paths-must-lie).

What `install` does to the files it writes:

- Every unit file starts with a marker comment (`# keepwatch-managed-unit: ...`).
  The marker alone decides whether a file is keepwatch's: `install` replaces and
  `uninstall` removes any file in the unit directory whose first line starts with it,
  whoever wrote it (acceptable because only root can write to that directory).
  A file that is already there without it is never overwritten (exit 2, the
  message names the file), and nothing is written at all in that case: the
  conflicts are found before the first write. A symbolic link at the target
  name, or a directory, is refused the same way.
- Writes are atomic: a temporary file in the same directory (created exclusively,
  without following links), written, flushed, set to mode 0644, renamed over the
  name, and the directory flushed. The target name is never opened for writing,
  so a link there could not redirect a write.
- The unit directory must be a real directory (not a symbolic link) that group and
  other cannot write to and that root or the running user owns; otherwise `install`
  refuses. The configuration directory and `state_dir` fall under the stricter rule
  [above](#where-the-paths-must-lie). An existing directory is left as it is (mode
  included).

Exit codes of `install` and `uninstall`: 0 done (or nothing to do), 1 a step
failed after work had started (a `systemctl` command, a write; what was done is
printed and a second run continues), 2 refused or usage error (not root, systemd
not running, bad flag, a file that is not keepwatch's, a missing or invalid configuration,
a path that does not lie where it must;
nothing was changed, except that `uninstall --purge` exits 2 after doing what it
could when it refuses a configuration it cannot prove is keepwatch's), 3 internal error.

### The units and their hardening

Both services run as root (the checks need it: `sshd -T`, `ss -p`,
`fail2ban-client`, `docker`, `nft`) and are as confined as the checks allow. The
options, and why each is set:

| Option | Why |
|---|---|
| `Type=oneshot` | one run to completion; the timer arms the next one after it |
| `SuccessExitStatus=1` | exit 1 means the host has findings; that is news for the notification, not a failed unit. Exit 3 (keepwatch could not do its job) and 4 (delivery failed) still fail the unit, and `doctor` reports a failed last run |
| `ProtectSystem=strict` | the whole file system is read-only for the service ... |
| `ReadWritePaths=<state_dir>` | ... except the state directory, the only place keepwatch writes. The apt simulation of `updates.security_pending` runs with `Debug::NoLocking=true` and an in-memory package cache, so it needs no other writable path (checked under systemd) |
| `ProtectHome=read-only` | not `yes`: the `authorized_keys` check reads `/home/*/.ssh` and `/root/.ssh`; read-only is as far as it can go |
| `PrivateTmp=yes` | probes and the programs they start get their own `/tmp` |
| `PrivateDevices=yes` | no access to real device nodes; no check needs any (the results are the same with it) |
| `NoNewPrivileges=yes` | nothing the checks start can gain privileges through set-uid files |
| `UMask=0077` | the state file and anything else the service creates is private |
| `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectClock=yes`, `ProtectHostname=yes`, `ProtectControlGroups=yes` | the checks only read; none of them changes kernel settings, loads modules, reads the kernel log, sets the clock or hostname, or touches cgroups |
| `LockPersonality=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `RestrictNamespaces=yes`, `RemoveIPC=yes`, `SystemCallArchitectures=native` | no check needs these; they remove tools an exploit would use |
| `MemoryDenyWriteExecute=yes` | no JIT in keepwatch or in the programs it runs (Go, perl, C); memory cannot be both writable and executable |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` | `AF_UNIX` for `docker.sock`, `fail2ban.sock` and the journal, `AF_INET` and `AF_INET6` for notifications, `AF_NETLINK` for `ss` and `nft`; no packet or exotic sockets |
| `MemoryMax=1536M` and `Environment=GOMEMLIMIT=384MiB` | the `listeners` check reads up to two 64 MiB buffers of `ss` output (tcp and udp). `MemoryMax` is sized from the peak of the unit's cgroup (`memory.peak`) with two full buffers, measured under the `GOMEMLIMIT` shipped here, with at least 1.5 times headroom. `GOMEMLIMIT` is not required to stay under `MemoryMax`, but it lowers the usual worst case considerably, so it stays; `MemoryMax` is the backstop that stops a runaway check. Re-measure (`memory.peak` of the service, with `MemoryMax=infinity` in a drop-in) before changing either |
| `CPUQuota=50%` | a check must never starve the services it watches |
| `TimeoutStartSec=10min` | the slowest probe is the apt simulation (90 seconds); a check that hangs is killed |

Tried with a test drop-in, one at a time, and not adopted because a check breaks:
`ProtectHome=yes` (the `authorized_keys` check can no longer read `/home` and `/root`,
and its result changes) and `PrivateUsers=yes` (`nft` and `iptables` fail with "you
must be root", the key files of other users are unreadable). `PrivateNetwork` and
`IPAddressDeny` would stop the notifications. `CapabilityBoundingSet` (four
capabilities), `ProtectProc=invisible` with `ProcSubset=pid`, and
`SystemCallFilter=@system-service` changed no result of the current checks, and are
left out on purpose: a check added later that needs one more capability, a file under
`/proc/sys` or one more system call would otherwise fail only under systemd.
`systemd-analyze security keepwatch-check.service` scores the unit 5.3 (MEDIUM) on
Ubuntu 22.04 and 24.04.

With these options every check returned the same status, severity, summary and
evidence subjects as a direct run as root, on Ubuntu 22.04 (systemd 249) and 24.04
(systemd 255).

### uninstall

`uninstall` (run as root) disables and stops the timers, stops the services,
removes the four unit files that carry the marker, and runs `systemctl
daemon-reload`. A file with the name of one of the units that has no marker, or
is a symbolic link, is left alone and reported (`left ...`); if disabling a timer
fails, nothing is removed and a second run continues. Without `--purge`,
configuration and state stay. `--dry-run` lists what would be done.

`--purge` additionally removes keepwatch's own files and nothing else:

- in the state directory: `state.json` and `history.json`, leftover
  `.state.json.tmp-*` and `.history.json.tmp-*` files and the probe and temporary files
  that `doctor` and the atomic writer leave after a crash, then the directory if it is
  empty (a test ties this list to the file names the writers use);
- the main configuration file, the `*.yaml` files in the `conf.d` directory next to
  it, then `conf.d` and the configuration directory if each is empty.

Which configuration is keepwatch's is decided by its path alone, because that a
file loads as a keepwatch configuration proves nothing (an empty YAML file does).
It is keepwatch's if it is the default path, `/etc/keepwatch/keepwatch.yaml`, or the
`--config` recorded in an installed unit that carries the marker (read before the
units are removed). Without `--config`, `--purge` uses the recorded one. The state
directory comes from that configuration, else from the `ReadWritePaths` of the
units. For any other `--config`, and for a plain `uninstall` run earlier followed by
a purge of a custom path, the configuration side is skipped: the output says
`left FILE: ... remove it and its conf.d by hand`, and the exit code is 2 (the units
and the state that could be proven were still removed).

Every other file in these directories (for example the file named by
`notify.ntfy.token_file`) stays, and so does the directory that holds it; the
output says `left DIR: it holds entries that are not keepwatch's own (...)`.
A symbolic link is never followed or removed as if it were a keepwatch file. If
the configuration cannot be read, `--purge` says so and takes the state directory
from the units, or the default one.

### doctor

`doctor` says whether keepwatch will work on this host. It prints one line per
finding, `ok`, `warn` or `PROBLEM`, and a summary. It changes nothing except one
probe file, created and removed inside `state_dir`. Exit codes: 0 no problem
(warnings are allowed), 1 at least one problem, 2 usage error, 3 internal error.

`doctor` judges the installed units by what they say, not by what it assumes. Which
configuration it examines:

- Without `--config`: the file the installed check service is given (the `--config`
  of its `ExecStart`), because that is what the scheduled runs load. Only when no
  service of keepwatch is installed is it the default path,
  `/etc/keepwatch/keepwatch.yaml`. So an invalid configuration behind the units is a
  problem even when the file at the default path is fine.
- With `--config FILE`: that file, for example to look at a configuration before
  `install --config FILE`. An installed service that runs with another file is then a
  problem (exit 1) that names both files: the other areas of the report are about
  `FILE` and say nothing about what the scheduled runs will do, so the report must not
  come out clean. That service is still judged by its own file (it loads, its paths
  pass, `ReadWritePaths` and `--notify` agree with it). Run `doctor` without `--config`
  for the report about the installed units.
- The two services are meant to run with one file. If a hand edit made them differ,
  the check service decides and the other one is a problem in the same way.

A `--config` in a unit that is not a clean absolute path is a problem and is never
loaded.

`doctor` also asks what systemd will run, not only what the file says:

- Each installed service file is compared with the unit `install` renders from the
  values the file itself holds (the program, `--config`, `--notify`, `ReadWritePaths`).
  A file that differs in any line is a problem that names the file and the first line
  that differs: a second `ExecStart` line (a oneshot service runs all of them, in
  order), an option added or changed (`ProtectHome=yes`, `InaccessiblePaths=`), a line
  removed. Running `install` again rewrites the file as rendered. The two timers are
  not compared.
- A drop-in of a service (`systemctl show -p DropInPaths`) is a problem that lists the
  files, unless it lies in a directory called `service.d`. systemd reads the drop-ins
  of a unit from `<name>.service.d` for every name the unit has (an alias, a symbolic
  link to the unit, included), from the directories named for a prefix of the name
  (`keepwatch-.service.d`) and from `service.d`, so every one of these changes this
  service and nothing else does. The unit directories are `/etc/systemd/system`,
  `/run/systemd/system`, the vendor directory and `system.control` (where
  `systemctl set-property` writes). systemd merges the drop-in into the unit, so the
  service no longer runs as `install` renders it, `doctor` does not read what it
  changes, and `install` does not remove it. It is a problem and not a warning because
  a drop-in that replaces `ExecStart` or adds a hardening option fails every scheduled
  run (status 203 or 3) while the unit file looks fine, and a warning does not change
  the exit status.
- A file name is bytes, and `doctor` prints the names of drop-ins. It reads them as
  `systemctl` writes them (in double quotes when they hold a blank, a control character
  or a character a shell reads specially, with `\"`, `\\`, `\$`, a backslash before a
  backquote, `\a \b \f \n \r \t \v` and three octal digits like `\033`; `\xNN` is
  read as well), so a name with a space is one file and a name with an escape character
  is the file on disk. In the report a name is written as it is only when all of it is
  printable and it holds no blank, quote or backslash. Every other name is in double
  quotes with Go's escapes (`\r`, `\x1b`, `\x7f`, `\u202e`, `\xff` for a byte that is
  not UTF-8), and so is the file systemd loaded, always. So the name of a drop-in or of
  the file systemd loaded brings no control character, no escape sequence and no
  character that reverses the direction of the text to the terminal, and it cannot start
  a line that looks like one of `doctor`.
- A drop-in in a `service.d` directory holds for every service of the host, and a
  vendor, an image or a generator may have put it there (the generator of Ubuntu LXC
  and Incus images writes `/run/systemd/system/service.d/zzz-lxc-service.conf` at
  every boot). That is a warning that names the file; there is nothing for the
  operator to remove, and `doctor` does not read what it changes.
- What systemd loaded, asked with `systemctl show` of each service: a `FragmentPath`
  other than the file in the unit directory is a problem naming the file systemd took
  (a unit of the same name in `/etc/systemd/system.control` takes precedence over the
  file `install` wrote), and
  `NeedDaemonReload=yes` is a problem (the file or a drop-in changed after systemd last
  read it, so the service runs as it did then). `systemctl daemon-reload` is the remedy;
  `install` runs it only when it writes a file, not when the files are already as
  rendered.
- A service whose unit file is there and that systemd has not loaded (`LoadState` other
  than `loaded`) is a problem that names the state: the timer cannot start it. A drop-in
  that leaves the service without a valid `ExecStart` gives `bad-setting`, a link to
  `/dev/null` under the unit's name in `system.control` gives `masked`, a line systemd
  cannot read gives `error`. `systemctl status` of the service shows which.
- A service whose unit file is there and for which `systemctl show` fails is a problem,
  `cannot ask systemd about keepwatch-check.service: ...` with the error, because none of
  the questions above has an answer then and the service may run anything. Only for a
  service whose unit file is missing is nothing more said than that it is not installed.

The questions to systemd are asked only while systemd runs. Limits:

- A drop-in is judged by its existence, not by its content.
- A drop-in whose file name is not valid UTF-8 cannot be listed. systemd applies it,
  but `systemctl show` (and `status` and `cat`) of the unit then fails, with
  `Failed to get properties: Bad message` on systemd 249 and with `Invalid argument` on
  systemd 255, so `doctor` cannot name the file: it reports that it cannot ask systemd
  about the service, which is a problem. `ls -b` of the drop-in directories of the unit
  (`/etc/systemd/system/keepwatch-check.service.d` and the others named above) shows
  the file; remove it and run `systemctl daemon-reload`.
- The line about the last run still shows the effect of a change that `doctor` does not
  recognise, as long as systemd answers.

| Area | What it checks | Level |
|---|---|---|
| user | running as root | not root: problem (the checks would fail or see less) |
| config | the configuration loads (file and line of each error) and agrees with the catalog (unknown check ids, bad parameters); the configuration file, its directory, `conf.d` and `notify.ntfy.token_file` lie [where the paths must lie](#where-the-paths-must-lie) | invalid, or a path that does not pass: problem, with the message `install` refuses with |
| catalog | the embedded catalog is valid | |
| programs | for every enabled check, the programs it needs are found the way the checks will find them (the fixed directories `/usr/sbin:/usr/bin:/sbin:/bin`, the same trust rules). A check that is switched off needs nothing | not installed: warn, naming the checks that will be `skipped` (`reboot_required` still reads its marker file, `firewall_default` is skipped only without `nft`, `iptables` and `ip6tables`, `docker_exposure` is an error if a daemon is configured); refused by the execution layer, or `nft` missing with only one of `iptables` and `ip6tables`: problem (the check would be an `error`) |
| ssh | `/run/sshd` exists when an `sshd` check is enabled. Ubuntu 24.04 starts `ssh.service` (which creates it) only at the first login when `ssh.socket` is used, and until then `sshd -T` fails and the five ssh checks are `error` | missing: problem, with the cause and `systemctl start ssh` as the remedy (keepwatch does not create it) |
| notify | a notification channel is configured | none: warn |
| units, notify | the installed services carry `--notify` exactly when `notify.ntfy` is configured | configured but a service lacks `--notify`: problem (each of its runs consumes the alerts, a loss); `--notify` but not configured: problem (every run exits 3) |
| state | `state_dir` lies [where the paths must lie](#where-the-paths-must-lie) (its parent directory while it is missing); then it is judged like `check` judges it (a symbolic link, a foreign owner or a directory others can write to is refused), writable (one probe file is created and removed inside it), and the previous state file is usable. A `state_dir` whose path does not pass is not probed: nothing is written through a path that somebody else can redirect | a path that does not pass (under a path the sandbox hides or a reboot empties, or one somebody but root can change), unusable or not writable: problem; missing yet and no unit installed, or a state file that will not be used: warn; missing while the units are installed: problem (the services do not start, status 226/NAMESPACE) |
| units | the four unit files are installed with the marker; each service file equals what `install` renders from the values it holds, systemd answers for the service, has loaded it from that file and has reloaded it, and no drop-in aims at the unit (one in `service.d` is a warning); the `ExecStart` program lies [where the paths must lie](#where-the-paths-must-lie) (it exists, the sandbox shows it, only root can change it or anything above it); `ReadWritePaths` equals `state_dir` of the configuration the unit runs with; each service runs with the configuration that was examined | missing, foreign, a service file that is not what `install` renders from its own values (changed after install), a drop-in outside `service.d`, a service systemd does not answer for or has not loaded, a unit that systemd loaded from another file or has not reloaded, a program that does not pass, `ReadWritePaths` differing from `state_dir` (the state could not be saved under systemd), no `--config`, or another `--config` than the one examined: problem; a drop-in in `service.d`: warn |
| systemd, timers | systemd is running; both timers are loaded, enabled and active (`systemctl show`, read-only) | problem |
| last run | the last run of each service did not fail (`journalctl -u keepwatch-check.service` has the output; exit 3, 4 and 226 are named); the check service has run since the host booted (the sandbox only shows when it runs) | failed: problem; check service not run yet: warn, with `systemctl start keepwatch-check.service` |

`--send-test` runs all the checks above and then sends one short test message
through `notify.ntfy` of the configuration that was examined (the same notifier
`check --notify` uses, with its timeout and one retry). A delivered test message
shows that the server accepts the token; that the scheduled run can read the token
file is what the placement of `token_file` is checked for. The finding `send-test` is `ok` when the message was delivered, and a
problem (exit 1) with the delivery error when it was not, when `notify.ntfy` is not
configured or when the configuration is not valid. The error never holds the topic or the
token; it may hold the address of the server ("no answer: dial tcp 127.0.0.1:80: connection
refused"). The `notify` line of the report shows only `scheme://host[:port]` of the URL. The message passes the redactor. Nothing is written to
`state_dir`: a test message touches neither the state nor the history.

## Status

Pre-MVP. The command line skeleton, the program execution layer, the
strict configuration loader, the check engine with twelve check kinds, the state
of the last run, the comparison, the text, JSON and Markdown reports, the ntfy
notification and the weekly report exist; `check`, `report --weekly`, `config check`,
`init`, `install`, `uninstall` and `doctor` are implemented, while `report` without
`--weekly` is a stub that exits with status 3.

## License

MIT, see [LICENSE](LICENSE).
