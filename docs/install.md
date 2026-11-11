# Install and scheduled runs

Part of the [keepwatch README](../README.md).

## Install from a release

Each release on the [releases page](https://github.com/LanNguyenSi/keepwatch/releases)
carries static `linux/amd64` and `linux/arm64` archives
(`keepwatch_<version>_linux_<arch>.tar.gz`, containing the binary, `LICENSE` and
`README.md`), a `checksums.txt` with their SHA-256 sums, and a build-provenance
attestation for the archives and the checksum file. The example below installs
version 0.1.0 on `amd64`; the version in the file name has no leading `v`.

```sh
# download keepwatch_0.1.0_linux_amd64.tar.gz and checksums.txt from the release, then:
sha256sum -c checksums.txt --ignore-missing
gh attestation verify keepwatch_0.1.0_linux_amd64.tar.gz --repo LanNguyenSi/keepwatch
tar -xzf keepwatch_0.1.0_linux_amd64.tar.gz keepwatch
sudo install -o root -g root -m 0755 keepwatch /usr/local/bin/keepwatch
keepwatch version
```

`sha256sum -c` checks that the download matches the published sums;
`gh attestation verify` checks that the archive was built from this repository by
the release workflow. It needs the [GitHub CLI](https://cli.github.com/) (`gh`).

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
[Notifications](running.md#notifications): a run without `--notify` consumes the alerts it
finds and nobody is told, and a run with `--notify` and no `notify.ntfy` exits 3.
So after adding `notify.ntfy` run `install` again (it updates the two services;
`doctor` reports a problem while they lack `--notify`). It creates `state_dir`
(mode 0700) if it is missing, then proves that the scheduled runs can write there:
the probe `doctor` runs, one file created and removed inside `state_dir`. A
`state_dir` on a read-only file system, for example, is refused (exit 2) with the
sentence `doctor` prints, before any unit is written; a `state_dir` that this run
created stays, empty, and the next run finds it. The probe runs on every real
`install`, also when the units are up to date. Then `install` runs
`systemctl daemon-reload` and
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
| `state_dir` (`ReadWritePaths`) | a directory | yes: then its parent directory is checked, `install` creates `state_dir` there, checks it again and proves it is writable |

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
   [Sandbox measurement](development.md#sandbox-measurement).
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
creates anything, a missing `state_dir` included. Neither runs the write probe
either, not even on an existing `state_dir`: they stay free of side effects, so a
`state_dir` that cannot be written is refused only by a real `install` (and found by
`doctor`). `--dry-run` says so in its output.

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
a path that does not lie where it must, a `state_dir` that cannot be written;
nothing was changed, except that `install` keeps a `state_dir` it created before
the write probe refused it, and that `uninstall --purge` exits 2 after doing what it
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
(systemd 255), except for the following.

- `updates.security_pending` agrees only because the apt simulation runs with
  `APT::Get::Always-Include-Phased-Updates=true` (see `security_updates` under
  Checks). apt's own phasing differs between a service and a direct run, and
  without the option the counts of other upgrades and of packages not upgraded
  differ; the security list does not.

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
  that the write probe (`install`, `doctor`) and the atomic writer leave after a crash, then the directory if it is
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
