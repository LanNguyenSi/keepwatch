# Probe fixtures

Real outputs of the commands the probes run, captured in local containers of
`ubuntu:22.04` and `ubuntu:24.04` (arm64 images; the output formats do not
depend on the architecture). Fixture files are read by the fake runner as
`<name>.stdout`, `<name>.stderr` and `<name>.exit`; a missing `.stdout` or
`.stderr` means empty. `ubuntu2204/` and `ubuntu2404/` hold one set each.

Package versions at capture time:

| | 22.04 | 24.04 |
|---|---|---|
| openssh-server | 8.9p1-3ubuntu0.18 | 9.6p1-3ubuntu13.20 |
| systemd | 249.11-0ubuntu3.23 | 255.4-1ubuntu8.18 |
| fail2ban | 0.11.2-6 | 1.0.2-3ubuntu0.1 |
| needrestart | 3.5-5ubuntu2.5 | 3.6-7ubuntu4.5 |
| iproute2 (ss) | 5.15.0-1ubuntu2.2 | 6.1.0-1ubuntu6.4 |
| dpkg | 1.21.1ubuntu2.6 | 1.22.6ubuntu6.6 |

## Reproducing

`capture.sh` regenerates everything. It needs four containers per run (two
per release), all started by hand and removed afterwards:

1. A plain container, no systemd as PID 1, privileged (the `zones` scenario
   creates a dummy interface and binds sockets to devices):
   `docker run -d --privileged ubuntu:XX.04 sleep 7200`, then
   `apt-get update && apt-get install -y openssh-server fail2ban
   unattended-upgrades needrestart iproute2 perl`. Used for `sshd -T`, `ss`,
   `dpkg-query` and `needrestart`.
2. A systemd container: a privileged container whose PID 1 is `/sbin/init`
   (`docker run -d --privileged --cgroupns=host -v
   /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock
   ubuntu:XX.04 ...` that installs the packages above plus `systemd`,
   `systemd-sysv` and `dbus`, then `exec /sbin/init`). Used for
   `systemctl is-active`, `fail2ban-client` and the loopback sockets of
   systemd-resolved.

Set `KW_PLAIN_2204`, `KW_PLAIN_2404`, `KW_SYSTEMD_2204` and
`KW_SYSTEMD_2404` to the container names and run `./capture.sh`. The script
runs `docker exec` for the commands below; the arguments listed are exactly
what the probes pass.

## Fixtures

All of them are captured output, not synthesised, except where marked.

| Name | Command | State |
|---|---|---|
| `sshd_T_default` | `sshd -T` | distribution defaults (password login on, X11 forwarding on) |
| `sshd_T_dropin_hardened` | `sshd -T` | `sshd_config` sets `PasswordAuthentication yes`, `PermitRootLogin yes`, `X11Forwarding yes` after the `Include`; the drop-in `sshd_config.d/10-hardening.conf` sets `no`, `prohibit-password`, `no`. sshd -T shows the drop-in values: the first value found wins, and the `Include` line comes first |
| `sshd_T_rootlogin_no` | `sshd -T` | drop-in with `PermitRootLogin no` and `PasswordAuthentication no` |
| `sshd_T_dropin_open` | `sshd -T` | drop-in with password login, root login, keyboard-interactive and X11 forwarding all on |
| `sshd_T_bad_config` | `sshd -T` | an unknown option in a drop-in: exit 255, message on stderr |
| `sshd_T_no_privsep_dir` | `sshd -T` | `/run/sshd` missing: exit 255 |
| `ss_tcp_<scenario>`, `ss_udp_<scenario>` | `ss -Hltn`, `ss -Hlun` | the socket set the probe trusts: no process column. No UDP socket prints nothing |
| `ssp_tcp_<scenario>`, `ssp_udp_<scenario>` | `ss -Hltnp`, `ss -Hlunp` | the same state with the process column, taken right after; the probe reads it only to name processes |
| `dpkg_installed` | `dpkg-query -W -f=${Status}\t${Version}\n -- fail2ban` | installed |
| `dpkg_unknown` | the same for `nosuchpkg-x` | exit 1, `no packages found matching` on stderr |
| `dpkg_config_files` | the same for `rsync` after `apt-get remove` | `deinstall ok config-files`, exit 0 |
| `systemctl_active`, `systemctl_unattended` | `systemctl is-active -- fail2ban.service`, `... unattended-upgrades.service` | active, exit 0 |
| `systemctl_inactive` | `systemctl is-active -- fail2ban.service` | fail2ban stopped, exit 3 |
| `systemctl_failed` | a unit whose `ExecStart=/bin/false` | `failed`, exit 3 |
| `systemctl_activating` | a unit with `ExecStartPre=/bin/sleep 300` | `activating`, exit 3 |
| `systemctl_unknown_unit` | `systemctl is-active -- nosuchunit.service` | `inactive`; exit 3 on 22.04, exit 4 on 24.04 |
| `systemctl_no_systemd` | the same in the plain container | exit 1, `System has not been booted with systemd` on stderr |
| `fail2ban_status_sshd` | `fail2ban-client -- status sshd` | running jail, exit 0 |
| `fail2ban_status_nojail` | `fail2ban-client -- status nosuchjail` | `Sorry but the jail ... does not exist` on stdout, exit 255 |
| `fail2ban_status_server_down` | `fail2ban-client -- status sshd` with the server stopped | `Failed to access socket path` on stderr, exit 255 |
| `needrestart_kernel` | `needrestart -b -k -r l` | plain container: kernel status 0 (unknown), exit 0 |
| `needrestart_kernel_in_container` | the same in the systemd container | needrestart detects the container, skips the kernel check and prints only the version line, exit 0 |

Scenarios of the `ss` fixtures:

| Scenario | State |
|---|---|
| `sshd_only` | only sshd listens |
| `mixed` | `listen.pl` binds IPv4 and IPv6 wildcard and loopback sockets, one dual-stack socket (printed as `*:3000`), UDP sockets |
| `resolved` | systemd container: systemd-resolved on `127.0.0.53%lo:53` (interface suffix), sshd socket-activated by PID 1 on 24.04 |
| `zones` | `zones.pl` binds sockets to a device (`SO_BINDTODEVICE`) to `lo` and to a dummy interface `dum0` that holds `fe80::1`, and two IPv4-mapped sockets. ss prints the interface after the address and, for IPv6, after the closing bracket: `[::]%lo:7001`, `*%lo:7002`, `0.0.0.0%lo:7003`, `[fe80::1]%dum0:7007`. The same forms appear on 22.04 and 24.04 |
| `newline` | `newline.pl` renames itself (`/proc/self/comm`) to `a`, a newline and `LISTEN 0 0 x`, and listens on three ports. In the `ssp_` files that name splits the record over two lines, the second one starting with `LISTEN` (also in the UDP output); the `ss_` files are unaffected |

On 22.04 the sshd jail needs a log file to start; the script touches
`/var/log/auth.log` first. The package status of `rsync` is the only package
state that was changed by hand (installed, then removed with `apt-get
remove`).

## Synthesised inputs

Real `needrestart` output with a pending kernel upgrade (`NEEDRESTART-KSTA`
2 or 3) could not be produced in a container, because there is no kernel
image to compare with. The tests build that output from the documented batch
format (`NEEDRESTART-VER`, `-KCUR`, `-KEXP`, `-KSTA`); the same applies to
the contents of `/var/run/reboot-required` and `.pkgs` (a marker line and
package names), and to the process-name edge cases of the listener tests
(control characters, quotes, very long names, text that looks like further
ss lines, a failing or garbled `ss -p` run) and the table of address forms
that ss does not print (an interface inside the brackets, empty or
overlong interface names). Those are inline in the test files.

## Addresses

No real addresses appear in the fixtures: the containers only listen on
wildcard and loopback addresses. Where a test needs a routable address it
uses the documentation range `192.0.2.0/24`.
