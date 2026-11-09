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
| `firewall_default` | `nft -j list ruleset`, `iptables -S INPUT`, `ip6tables -S INPUT`; `ufw status verbose` for the explanation | none |
| `security_updates` | `apt-get -s -o Debug::NoLocking=true dist-upgrade` and the age of `/var/lib/apt/lists/*InRelease` | `max_list_age_hours` (default 48) |
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
is final. Forward and nat chains (Docker sets some up) and tables that are
dormant do not count. `ufw` is only read to explain: it can neither add a drop
nor remove one, and the check says when it reports `deny` while the kernel does
not drop. A source that cannot be read does not stop a pass that another source
confirms, but turns a fail into `error`. Limit: it judges the default policy,
not the rules; a drop chain that starts with a rule accepting everything
passes.

`security_updates` simulates `apt-get dist-upgrade` (nothing is written, no lock
is taken, and `apt-get update` is not run) and fails for every package whose
new version is available from a `-security` pocket (`-infra-security` and
`-apps-security` too), one evidence item per package. It also reports how old
the package lists are and warns when they are older than `max_list_age_hours`
or missing, because then it cannot see newer updates. Held-back and phased
packages are counted in the summary, not judged.

`docker_exposure` fails when the daemon listens on TCP (an entry in
`daemon.json` `hosts`, or `-H`/`--host` on the running dockerd's command line;
an entry without a scheme counts as TCP) and for every running container that
is privileged, shares the host's PID or network namespace, or has a Docker
socket mounted; the subject is the container name. A listener that systemd
opens for `-H fd://` is seen by the `listeners` check. At most 500 running
containers are examined. Without the `docker` program it is skipped, unless a
daemon configuration exists.

`authorized_keys` compares the SHA256 fingerprints of the keys in each user's
authorized keys files with the top-level `authorized_keys.expected` section
(user name to a list of `SHA256:...` fingerprints, as `ssh-keygen -lf` prints
them); without it the check is skipped. Users are the accounts with uid 0 or
1000 and above and a login shell, plus the users named in `expected`. The files
come from `AuthorizedKeysFile` in `sshd -T`. A key that is not expected is a
`fail` (subject `user:SHA256:...`); an expected key that is missing, a file that
could not be read or has lines that are not keys, and an
`AuthorizedKeysCommand` (whose keys cannot be checked) are `warn`. The users own
their files and every directory below their home, so a path inside the home is
resolved by the kernel inside the home: a symbolic link that leaves it, a file
that is not a regular file, one owned by somebody else, and one over 256 KiB are
refused and reported, never read. A line that is not a key is reported by line
number and never quoted. Certificates in `authorized_keys` are not compared
and count as lines that are not keys. Limit: `Match` blocks of `sshd_config` are
not evaluated.

`disk_usage` examines the mounts of the given file system types (`fstypes`
replaces the default list ext4, xfs, btrfs, vfat, zfs; network and pseudo file
systems are left out so that a hung NFS cannot block the run) for blocks and
inodes, computed like `df`. Each statfs call has a timeout.

`cert_expiry` reads certificate files (`paths`, and files matching `globs`;
setting `paths` does not remove the default glob, `globs: []` does) and examines
the first certificate in each. Symbolic links are followed (certbot's `live/`
points into `archive/`) only when the resolved file and every directory above it
are owned by root and not writable by group or others; otherwise that file is
an `error` with the reason. A listed path that does not exist is an `error`;
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
whose failing items are all covered becomes `excepted`; otherwise it stays
`fail` and the covered items are marked. Exceptions never change an `error` or
a `warn`.
An `error` of a check that reads two sources (`reboot_required`, and
`listeners` with tcp and udp) keeps the failing items that the readable source
confirmed and says in its summary that the picture is partial.
Each expired exception is reported as its own `exception_expired` result
(severity low).

## Status

Pre-MVP. The command line skeleton, the program execution layer, the
strict configuration loader and the check engine with twelve check kinds exist;
`config check` and `init` are implemented, while the commands (`check`,
`report`, `doctor`, `install`, `uninstall`) are stubs that exit with status 3.

## License

MIT, see [LICENSE](LICENSE).
