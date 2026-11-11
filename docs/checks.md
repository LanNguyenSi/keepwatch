# Checks

Part of the [keepwatch README](../README.md).

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
`/var/lib/apt` changes). Both also run with `-o
APT::Get::Always-Include-Phased-Updates=true`, so apt counts every phased update
(Ubuntu's staged rollout, `Phased-Update-Percentage` in the package index) as
available: "N other upgrade(s) pending" is what the package lists offer, not what
apt would install on this machine today. This holds even when the host sets
`APT::Get::Never-Include-Phased-Updates`: the command-line option wins, and the
check ignores the host's phasing preference on purpose. Without the option the answer would
depend on where apt runs. apt does not phase when `ischroot -t` says it is in a
chroot, and `ischroot` takes any process whose `/proc/self/mountinfo` differs
from PID 1's for one, which is every service with a mount namespace of its own,
so the scheduled run under systemd upgraded the phased packages while a direct run
as root held them back (the count of "not upgraded" packages and of other upgrades
differed on the same host; measured on Ubuntu 22.04 with apt 2.4.15 and 24.04 with
apt 2.8.4). Security updates are never affected: apt does not phase a package whose
candidate comes from a security pocket, and the security list was the same in both.
The option also matters for a host that switches `APT::Get::Phase-Policy` on: apt
then caps the priority of a phased version, whatever pocket it comes from, and a
phased security fix would vanish from the simulation, neither upgraded nor named as
held back; with the option it is found (measured on both releases). A package
fails when any version that a `-security` pocket carries (`-infra-security`
and `-apps-security` too) is newer than the installed one, even if the version the simulation would install comes from
`-updates` and has superseded the security fix; the order of versions is apt's
own, the check compares no version strings. One evidence item per package. It
also reports how old the package lists are and warns when they are older than
`max_list_age_hours` or missing, because then it cannot see newer updates.
Packages that apt does not upgrade (held with `apt-mark hold`, or blocked by a
dependency that cannot be met; apt names them under "kept back") are counted
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
inodes, computed like `df`. Each statfs call has a timeout. Mounts that share
one device (the major:minor of mountinfo) are judged once, at the entry with
the shortest mount point (the first one in mountinfo order on a tie): a bind
mount, such as the ones a systemd sandbox adds for `/tmp`, `/var/tmp` and a
state directory of the file system it already sees, is not counted again.

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
`tcp/0.0.0.0:8080`, `passwordauthentication`, `fail2ban.service`). `match` is compared with
the raw subject the check produced, not with the text a report shows: a subject with a
control character has to be written as a YAML double-quoted string with the
escape (`"/etc/x\x01.pem"`), and a subject that the report redacted, escaped or
cut cannot be matched by copying it from the report. A check
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
