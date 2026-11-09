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
| ufw | 0.36.1-4ubuntu0.1 | 0.36.2-6 |
| nftables | 1.0.2-1ubuntu3.1 | 1.0.9-1ubuntu0.1 |
| iptables (nf_tables variant) | 1.8.7-1ubuntu5.2 | 1.8.10-3ubuntu2 |
| apt | 2.4.15ubuntu0.1 | 2.8.4ubuntu0.1 |
| docker.io | 29.1.3-0ubuntu3~22.04.2 | 29.1.3-0ubuntu3~24.04.2 |
| openssh-client (ssh-keygen) | 8.9p1-3ubuntu0.18 | 9.6p1-3ubuntu13.20 |
| openssl | 3.0.2-0ubuntu1.30 | 3.0.13-0ubuntu3.16 |

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

The sections after `base` (`firewall`, `apt`, `keys`, `certs`, `disk`,
`docker`) run in the plain containers, which need these packages in addition:
`ufw nftables iptables openssl docker.io procps e2fsprogs util-linux` (and
network access: `apt` upgrades packages, `docker` pulls `alpine:3`). Docker
runs inside the privileged container with the `vfs` storage driver, because the
overlay driver does not work inside a container. `KW_SECTIONS` (a comma
separated list, default all) selects sections; the `apt` section starts by
putting `apt`, `libpcre2-8-0` and the apt library back to the versions of the
release pocket, so that updates are pending, and ends with an upgrade.

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

Fixtures of the second group of kinds (all captured by the sections named in
`capture.sh`; the `.stdout` of a few are files, not command output, as noted):

| Name | Command | State |
|---|---|---|
| `fw_<scenario>_ufw`, `_nft`, `_iptables`, `_ip6tables` | `ufw status verbose`, `nft -j list ruleset`, `iptables -S INPUT`, `ip6tables -S INPUT` | one set per firewall scenario, see below |
| `fw_notroot_*` | the same four commands | run as user 65534 with `setpriv`: ufw exits 1 ("You need to be root"), nft exits 1, iptables and ip6tables exit 4 |
| `apt_pending` | `apt-get -s -o Debug::NoLocking=true dist-upgrade` | three packages upgradable, available from `-updates` and `-security` |
| `apt_updates_only` | the same with `-o Dir::Etc::sourcelist=<list without the security suite> -o Dir::Etc::sourceparts=/nonexistent` | the same packages, available from `-updates` only (the argv differs from the probe's; the fake runner maps the probe's argv to this file) |
| `apt_current` | the same | nothing to upgrade |
| `apt_notroot` | the same as user 65534 | prints the "NOTE: This is only a simulation!" lines first |
| `apt_error` | the same with `-o Dir::State::status=<unparseable file>` | exit 100, `E:` lines on stderr (argv differs as above) |
| `sshkey_<type>.pub`, `sshkey_<type>_fp` | files and `ssh-keygen -lf <file>` | throw-away ed25519, rsa and ecdsa keys; `_fp.stdout` is what ssh-keygen prints for the key. `sshkey_cert.pub` is a user certificate; ssh-keygen prints the fingerprint of the key inside it, keepwatch does not compare certificates |
| `etc_passwd` | `cat /etc/passwd` | the container's passwd plus `alice` (1001, bash), `svc` (1002, nologin) and `bob` (1003, default shell) |
| `sshd_T_authkeys_custom` | `sshd -T` | drop-in with `AuthorizedKeysFile %h/.ssh/authorized_keys /etc/ssh/keys/%u .ssh/ak_%U`, `AuthorizedKeysCommand /usr/local/bin/kwkeys %u`: sshd prints the tokens unexpanded |
| `sshd_T_authkeys_none` | `sshd -T` | `AuthorizedKeysFile none` |
| `cert_leaf.pem`, `cert_chain.pem`, `cert_leaf_info`, `cert_ca_info` | files and `openssl x509 -noout -subject -enddate` | self-signed leaf (90 days) and a CA (365 days), the chain is leaf followed by CA; the `_info` files are what openssl prints |
| `mountinfo` | `cat /proc/self/mountinfo` | the container's mounts plus an ext4 loop mount `/mnt/kw ext4`, tmpfs mounts `/mnt/kw tmp`, `/mnt/kw\back` and a mount point with a newline, shown with the octal escapes `\040`, `\134`, `\012` |
| `daemon_json_plain`, `daemon_json_tcp` | the `/etc/docker/daemon.json` of the run (files) | storage driver and snapshotter settings; the second adds `hosts` with a `tcp://127.0.0.1:2375` entry, which the daemon started with |
| `docker_pid` | `cat /run/docker.pid` | the pid file of the running dockerd (no newline) |
| `dockerd_cmdline_plain`, `_hostsfile`, `_tcp` | `cat /proc/<pid>/cmdline` (NUL separated) | dockerd without arguments, dockerd with the hosts in `daemon.json`, and `dockerd -H unix:///var/run/docker.sock -H tcp://127.0.0.1:2375` |
| `docker_ps_none`, `docker_ps_mixed`, `docker_ps_nodaemon` | `docker ps -q --no-trunc` | no container; six containers; the daemon stopped (exit 1, message on stderr) |
| `docker_inspect_mixed` | `docker inspect --type container -- <ids of docker_ps_mixed>` | `kwplain` (plain), `kwpriv` (`--privileged`), `kwhostpid` (`--pid=host`), `kwhostnet` (`--network=host`), `kwsock` (`-v /var/run/docker.sock:/var/run/docker.sock:ro`), `kwall` (privileged, host pid and network, `/run/docker.sock` mounted at another place) |
| `docker_inspect_gone` | the same for the first id and an id that does not exist | exit 1, the found container on stdout, `No such container` on stderr |
| `fw_docker_*` | the four firewall commands | with the Docker daemon running: Docker 29 creates nat and forward chains, the input policy stays accept |

Firewall scenarios (`fw_<scenario>_*`):

| Scenario | State |
|---|---|
| `none` | nothing configured, ufw inactive |
| `ufw_deny`, `ufw_reject`, `ufw_allow` | ufw enabled with `default deny incoming`, `reject incoming` and `allow incoming` (deny and reject make ufw set the iptables and ip6tables policy to DROP, allow leaves it ACCEPT) |
| `ufw_stale` | ufw still reports `deny`, but iptables and ip6tables were reset to ACCEPT behind its back |
| `nft_drop_inet`, `nft_drop_ip4`, `nft_drop_ip6`, `nft_accept_inet` | an nftables input chain with policy drop in an `inet`, an `ip`, an `ip6` table, and one with policy accept |
| `nft_forward_drop` | a chain on the forward hook with policy drop, input accepts |
| `nft_dormant` | a table with `flags dormant` and an input chain with policy drop. nft 1.0.9 prints the table's `flags` as an unrelated string (here the table name), which is why keepwatch counts a table with flags it does not know as not hooked |
| `ipt_drop`, `ipt_drop4` | `iptables -P INPUT DROP` and `ip6tables -P INPUT DROP`, and the first one alone |

In every scenario iptables and nftables show the same state, because the
iptables of both releases is the nf_tables variant, and `iptables -P` creates
the `ip filter` and `ip6 filter` tables with their three base chains.

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

Not captured, built by the tests from the documented formats: ESM pocket names
(`UbuntuESM:<release>/<release>-infra-security`), the `sk-` key types of
authorized keys, `apt` simulation lines for new packages, held packages and
removals, `docker inspect` output with missing fields, `nft` output with unusual
table flags, and the contents of `/etc/passwd` edge cases. Certificates for the
expiry thresholds are generated by the tests with a chosen `NotAfter`.

## Addresses

No real addresses appear in the fixtures: the containers only listen on
wildcard and loopback addresses (the Docker TCP fixtures use `127.0.0.1`). Where a test needs a routable address it
uses the documentation range `192.0.2.0/24`.
