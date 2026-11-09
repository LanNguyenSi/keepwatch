#!/usr/bin/env bash
# Re-captures the fixtures under this directory from local Ubuntu containers.
# See README.md for the container preparation. Usage:
#   KW_PLAIN_2204=<container> KW_PLAIN_2404=<container> \
#   KW_SYSTEMD_2204=<container> KW_SYSTEMD_2404=<container> ./capture.sh
# Plain containers: ubuntu:22.04 / ubuntu:24.04 with openssh-server, fail2ban,
# unattended-upgrades, needrestart, iproute2, perl installed, no systemd as
# PID 1. They run privileged: the zones scenario creates a dummy interface
# and binds sockets to devices.
# Systemd containers: the same packages plus systemd, systemd-sysv, started
# with /sbin/init as PID 1 (privileged).
set -u
here=$(cd "$(dirname "$0")" && pwd)

# cap <container> <dest-dir> <name> <command...>
# Runs the command in the container and stores stdout, stderr and the exit
# status as <dest-dir>/<name>.stdout|.stderr|.exit.
cap() {
  local c=$1 dir=$2 name=$3
  shift 3
  mkdir -p "$here/$dir"
  docker exec "$c" "$@" >"$here/$dir/$name.stdout" 2>"$here/$dir/$name.stderr"
  echo $? >"$here/$dir/$name.exit"
  [ -s "$here/$dir/$name.stderr" ] || rm -f "$here/$dir/$name.stderr"
  [ -s "$here/$dir/$name.stdout" ] || rm -f "$here/$dir/$name.stdout"
}

# ex <container> <script>: runs the script with "set -e", so it stops at its
# first failing command, and stops capture.sh when the script fails.
ex() {
  docker exec "$1" bash -c "set -e; $2" || { echo "capture.sh: step failed in $1: $2" >&2; exit 1; }
}

# capss <container> <dest-dir> <scenario>
# ss without -p is what the probe trusts for the socket set (ss_*), ss with -p
# only names the processes (ssp_*). Both are taken back to back.
capss() {
  cap "$1" "$2" "ss_tcp_$3" ss -Hltn
  cap "$1" "$2" "ss_udp_$3" ss -Hlun
  cap "$1" "$2" "ssp_tcp_$3" ss -Hltnp
  cap "$1" "$2" "ssp_udp_$3" ss -Hlunp
}

for v in 2204 2404; do
  eval "plain=\$KW_PLAIN_$v sd=\$KW_SYSTEMD_$v"
  d=ubuntu$v

  # ---- sshd -T -------------------------------------------------------
  ex "$plain" 'mkdir -p /run/sshd /etc/ssh/sshd_config.d; rm -f /etc/ssh/sshd_config.d/*.conf'
  # defaults of the distribution package
  cap "$plain" $d sshd_T_default sshd -T
  # drop-in overrides values that sshd_config sets explicitly
  ex "$plain" '[ -e /etc/ssh/sshd_config.orig ] || cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig
    cp /etc/ssh/sshd_config.orig /etc/ssh/sshd_config
    printf "PasswordAuthentication yes\nPermitRootLogin yes\nX11Forwarding yes\n" >> /etc/ssh/sshd_config
    printf "PasswordAuthentication no\nPermitRootLogin prohibit-password\nX11Forwarding no\nKbdInteractiveAuthentication no\n" > /etc/ssh/sshd_config.d/10-hardening.conf'
  cap "$plain" $d sshd_T_dropin_hardened sshd -T
  ex "$plain" 'printf "PermitRootLogin no\n" > /etc/ssh/sshd_config.d/10-hardening.conf; printf "PasswordAuthentication no\n" >> /etc/ssh/sshd_config.d/10-hardening.conf'
  cap "$plain" $d sshd_T_rootlogin_no sshd -T
  ex "$plain" 'printf "PasswordAuthentication yes\nPermitRootLogin yes\nKbdInteractiveAuthentication yes\nX11Forwarding yes\n" > /etc/ssh/sshd_config.d/10-hardening.conf'
  cap "$plain" $d sshd_T_dropin_open sshd -T
  ex "$plain" 'printf "ThisIsNotAnOption yes\n" > /etc/ssh/sshd_config.d/10-hardening.conf'
  cap "$plain" $d sshd_T_bad_config sshd -T
  ex "$plain" 'rm -f /etc/ssh/sshd_config.d/10-hardening.conf; cp /etc/ssh/sshd_config.orig /etc/ssh/sshd_config; rmdir /run/sshd'
  cap "$plain" $d sshd_T_no_privsep_dir sshd -T
  ex "$plain" 'mkdir -p /run/sshd'

  # ---- ss -----------------------------------------------------------
  ex "$plain" "pgrep -x sshd >/dev/null || /usr/sbin/sshd"
  capss "$plain" $d sshd_only
  docker cp "$here/listen.pl" "$plain:/tmp/listen.pl"
  docker exec -d "$plain" bash -c 'perl /tmp/listen.pl >/tmp/listen.log 2>&1'
  sleep 2
  capss "$plain" $d mixed
  ex "$plain" "pkill -f '[/]tmp/listen.pl'"
  # sockets bound to a device: ss prints the interface after the address
  ex "$plain" 'ip link show dum0 >/dev/null 2>&1 || ip link add dum0 type dummy
    ip link set dum0 up
    ip -6 addr show dev dum0 | grep -q "fe80::1/" || ip -6 addr add fe80::1/64 dev dum0 nodad'
  docker cp "$here/zones.pl" "$plain:/tmp/zones.pl"
  docker exec -d "$plain" bash -c 'perl /tmp/zones.pl >/tmp/zones.log 2>&1'
  sleep 2
  capss "$plain" $d zones
  ex "$plain" "pkill -f '[/]tmp/zones.pl'"
  # a process whose name holds a newline
  docker cp "$here/newline.pl" "$plain:/tmp/newline.pl"
  docker exec -d "$plain" bash -c 'perl /tmp/newline.pl >/tmp/newline.log 2>&1'
  sleep 2
  capss "$plain" $d newline
  ex "$plain" "pkill -f '[/]tmp/newline.pl'"
  # systemd containers: loopback listeners with an interface suffix
  capss "$sd" $d resolved

  # ---- dpkg-query ---------------------------------------------------
  fmt='-f=${Status}\t${Version}\n'
  cap "$plain" $d dpkg_installed dpkg-query -W "$fmt" -- fail2ban
  cap "$plain" $d dpkg_unknown dpkg-query -W "$fmt" -- nosuchpkg-x
  ex "$plain" 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rsync >/dev/null 2>&1; apt-get remove -y -qq rsync >/dev/null 2>&1'
  cap "$plain" $d dpkg_config_files dpkg-query -W "$fmt" -- rsync

  # ---- systemctl is-active -----------------------------------------
  cap "$plain" $d systemctl_no_systemd systemctl is-active -- fail2ban.service
  ex "$sd" 'printf "[Service]\nExecStart=/bin/false\n" > /etc/systemd/system/kwfail.service
    printf "[Service]\nExecStartPre=/bin/sleep 300\nExecStart=/bin/sleep 300\n" > /etc/systemd/system/kwslow.service
    systemctl daemon-reload; systemctl start kwfail.service 2>/dev/null || true; (systemctl start --no-block kwslow.service); sleep 1'
  cap "$sd" $d systemctl_failed systemctl is-active -- kwfail.service
  cap "$sd" $d systemctl_activating systemctl is-active -- kwslow.service
  cap "$sd" $d systemctl_unknown_unit systemctl is-active -- nosuchunit.service
  cap "$sd" $d systemctl_unattended systemctl is-active -- unattended-upgrades.service
  ex "$sd" 'systemctl stop kwslow.service kwfail.service; rm -f /etc/systemd/system/kwfail.service /etc/systemd/system/kwslow.service; systemctl daemon-reload; touch /var/log/auth.log; systemctl reset-failed fail2ban.service || true; systemctl stop fail2ban.service'
  cap "$sd" $d systemctl_inactive systemctl is-active -- fail2ban.service
  cap "$sd" $d fail2ban_status_server_down fail2ban-client -- status sshd
  ex "$sd" 'systemctl start fail2ban.service; sleep 3'
  cap "$sd" $d systemctl_active systemctl is-active -- fail2ban.service

  # ---- fail2ban-client ---------------------------------------------
  cap "$sd" $d fail2ban_status_sshd fail2ban-client -- status sshd
  cap "$sd" $d fail2ban_status_nojail fail2ban-client -- status nosuchjail

  # ---- needrestart ---------------------------------------------------
  cap "$plain" $d needrestart_kernel needrestart -b -k -r l
  cap "$sd" $d needrestart_kernel_in_container needrestart -b -k -r l
done
