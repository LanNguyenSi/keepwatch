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
  other; deeper ancestor directories are not checked (known limit).
- `notify.ntfy.url` is required when `notify.ntfy` is set (https, or
  http only for loopback; a URL port must be 1-65535).
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
hiding the rest.

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
keepwatch check [--config FILE] [--format text|json|markdown] [--no-state] [--fail-on SEVERITY]
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

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no result counts at `--fail-on` |
| 1 | at least one result counts at `--fail-on` |
| 2 | usage error (unknown flag, bad `--format` or `--fail-on`, extra argument) |
| 3 | keepwatch could not do its job: invalid configuration, a state directory that cannot be trusted or a state that cannot be saved, an interrupted run, a failed write of the report |

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
Exit code 3 wins over 1: if the state could not be handled, the run is not
reliable, even when the report (which is still printed) shows findings.

### The comparison with the last run

Per check the report lists, in the order of the checks:

- `new_failure`: the check fails now and did not before (from `pass`, `skipped`,
  `excepted`, `warn` or `error`);
- `fixed`: it failed and passes now;
- `status_change`: every other change of status (`pass` to `error`, `fail` to
  `warn`, `excepted` to `pass`, ...);
- `check_added` and `check_removed`: the catalog gained or lost the check;
- for a check that is `fail` (or `warn`) in both runs: `subject_new` and
  `subject_gone` for items that appeared or disappeared, and `count_change` when
  the check lists a capped number of items (see below);
- the checks that keep failing or warning unchanged ("still failing", "still
  warning").

A change is marked as an alert (worth a notification) when a check starts to
fail or to be in `error`, when a new check is failing or in `error`, when a
failing check has a new item or a larger item total, and when an
`authorized_keys` check starts to warn, is new and warns, or has a new warn item.
Everything else (fixed, gone items, a status change to `skipped`, `excepted` or
a `warn` of another check) is reported without the alert mark.

Two rules keep the comparison honest:

- An `error` is a partial picture: the check could not see everything. Its
  evidence is never compared item by item; the change of status is reported once.
- A check that has more than 100 items lists the first 99 sorted by subject and a
  marker "(N more not shown)". The marker is not an item: a change of N never
  produces new or gone subjects. With a capped list, the direction that cannot
  be told is not reported (an item that is listed now may have been hidden
  before; one that is no longer listed may only be hidden now) and the totals
  are compared instead.

Items are compared by the SHA-256 of their raw subject, so two subjects that
look the same after cleaning (they differ in a control character, say) are still
two items.

### State

The state is `state.json` in `state_dir` (default `/var/lib/keepwatch`): JSON
with `schema_version`, the time of the run and, per check, its id, kind, status,
severity and failing items (hash and cleaned, redacted subject). It holds no
evidence detail text and no summaries.

keepwatch runs as root and the state decides what the operator is told, so it is
checked:

- `state_dir` is cleaned with `filepath.Clean` and must be absolute. It is created
  with mode 0700 if it does not exist; otherwise it must be a real directory (not
  a symlink) owned by root or the running user that group and other cannot write
  to. Ancestors above it are not examined (known limit): they must be root-owned.
- The state file is opened without following links and checked on the open
  descriptor: a regular file of at most 4 MiB, owned by root or the running user,
  not writable by group or other.
- It is written atomically: a temporary file in the same directory (created
  exclusively, mode 0600), flushed, renamed over `state.json`, then the directory
  is flushed. If a step fails, the previous file stays and the temporary file is
  removed.

Recovery. A missing state file is a first run: a baseline, no changes are
reported. A state file that is a symlink, foreign-owned, group- or
other-writable, too large, truncated, not valid JSON, of another schema version
or invalid is reported as a warning (stderr and in the report) and the run is a
new baseline; it is never an abort and never a silent "nothing changed". The
file is replaced at the end of the run, so nothing needs repairing; to start from
scratch, delete `state.json`. A state directory that cannot be trusted (or a
state that cannot be saved) is different: the report is still printed, state is
not read or written, and the exit code is 3, because the next run could not be
compared reliably.

The state is written after a successful run, never after an interrupted one. A
manual `keepwatch check` counts as a run: it moves the "previous run" forward,
so a scheduled run after it reports changes only since that manual run. Use
`--no-state` for a look that must not do that.

### Output safety

Text in a report comes from probes and can carry what a local user chose (a
container name, a mount point, a file path) or a secret that someone put in a
command line. Every string of a report is cleaned before it is printed, whatever
the format:

1. secrets are replaced with `[REDACTED]` (see [Redaction](#redaction));
2. control characters are escaped into visible sequences: C0 controls and DEL
   (`\n`, `\r`, `\t`, `\x1b`, ...), C1 controls (`\u0085`), Unicode format
   characters including the bidirectional overrides, zero-width characters and
   the byte order mark, line and paragraph separators (`\u2028`), the right-to-left override (`\u202e`), and bytes that
   are not valid UTF-8 (`\xff`), so an escape sequence cannot move the cursor,
   set a window title, forge a line or reverse the text;
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
  `private_key`, `credential` or `credentials` (`token_file` and
  `passwordauthentication` are left alone);
- `--password value` style flags, `Authorization: ...` values, bearer tokens;
- URLs with credentials (`scheme://user:password@host`, `scheme://token@host`);
- AWS access key ids, GitHub tokens (`ghp_`, `github_pat_`, ...), ntfy tokens
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
match the empty string, and a bad one is a configuration error with file and
line. Lists in `conf.d` files are appended to the main file's list. The redaction
function (`redact.Redactor.Clean`) is what the notification code uses as well.

## Status

Pre-MVP. The command line skeleton, the program execution layer, the
strict configuration loader, the check engine with twelve check kinds, the state
of the last run, the comparison and the text, JSON and Markdown reports exist;
`check`, `config check` and `init` are implemented, while the commands
(`report`, `doctor`, `install`, `uninstall`) are stubs that exit with status 3.
There is no notification yet.

## License

MIT, see [LICENSE](LICENSE).
