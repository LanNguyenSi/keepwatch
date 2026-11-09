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
#
# KW_SECTIONS selects what to capture: a comma separated list of base,
# firewall, apt, keys, certs, disk, docker (default: all). The last five
# sections run in the plain containers, which need the extra packages ufw,
# nftables, iptables, apt, openssh-client, openssl, e2fsprogs, util-linux
# (setpriv), docker.io and curl; the docker section starts its own dockerd
# there (storage driver vfs, so it works inside a container) and leaves the
# firewall in the state the docker section describes.
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

# want <section>: whether KW_SECTIONS selects the section.
want() {
  case ",${KW_SECTIONS:-all}," in
    *,all,* | *,"$1",*) return 0 ;;
  esac
  return 1
}

for v in 2204 2404; do
  want base || continue
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

# ---- sections added for the second group of kinds ---------------------------
# They run in the plain containers only.

# The state the firewall scenarios start from: no ufw, no nft rules, iptables
# and ip6tables accept everything, ufw manages IPv6 too.
fwreset() {
  ex "$1" 'ufw --force disable >/dev/null 2>&1 || true
    nft flush ruleset; iptables -F; iptables -X; ip6tables -F; ip6tables -X
    for t in iptables ip6tables; do $t -P INPUT ACCEPT; $t -P FORWARD ACCEPT; $t -P OUTPUT ACCEPT; done
    sed -i "s/^IPV6=.*/IPV6=yes/" /etc/default/ufw'
}

# fwcap <container> <dest-dir> <scenario>: the four commands of firewall_default.
fwcap() {
  cap "$1" "$2" "fw_$3_ufw" ufw status verbose
  cap "$1" "$2" "fw_$3_nft" nft -j list ruleset
  cap "$1" "$2" "fw_$3_iptables" iptables -S INPUT
  cap "$1" "$2" "fw_$3_ip6tables" ip6tables -S INPUT
}

for v in 2204 2404; do
  eval "plain=\$KW_PLAIN_$v"
  d=ubuntu$v
  [ -n "$plain" ] || continue

  # ---- firewall_default: ufw status verbose, nft -j list ruleset, iptables -S INPUT, ip6tables -S INPUT
  if want firewall; then
    fwreset "$plain"; fwcap "$plain" $d none
    fwreset "$plain"
    ex "$plain" 'ufw default deny incoming >/dev/null; ufw --force enable >/dev/null'
    fwcap "$plain" $d ufw_deny
    ex "$plain" 'ufw default reject incoming >/dev/null'
    fwcap "$plain" $d ufw_reject
    ex "$plain" 'ufw default allow incoming >/dev/null'
    fwcap "$plain" $d ufw_allow
    # ufw still says deny, but somebody reset the policies behind its back
    ex "$plain" 'ufw default deny incoming >/dev/null; iptables -P INPUT ACCEPT; ip6tables -P INPUT ACCEPT'
    fwcap "$plain" $d ufw_stale
    fwreset "$plain"
    nftdrop() { ex "$plain" "nft add table $1 kw; nft add chain $1 kw input '{ type filter hook input priority 0; policy $2; }'"; }
    nftdrop inet drop; fwcap "$plain" $d nft_drop_inet
    fwreset "$plain"; nftdrop ip drop; fwcap "$plain" $d nft_drop_ip4
    fwreset "$plain"; nftdrop ip6 drop; fwcap "$plain" $d nft_drop_ip6
    fwreset "$plain"; nftdrop inet accept; fwcap "$plain" $d nft_accept_inet
    # a forward chain with policy drop (what Docker sets up) is not a default policy for incoming packets
    fwreset "$plain"
    ex "$plain" "nft add table inet kw; nft add chain inet kw forward '{ type filter hook forward priority 0; policy drop; }'; nft add chain inet kw input '{ type filter hook input priority 0; policy accept; }'"
    fwcap "$plain" $d nft_forward_drop
    # a table that is not hooked
    fwreset "$plain"
    ex "$plain" "nft add table inet kw '{ flags dormant; }'; nft add chain inet kw input '{ type filter hook input priority 0; policy drop; }'"
    fwcap "$plain" $d nft_dormant
    fwreset "$plain"
    ex "$plain" 'iptables -P INPUT DROP; ip6tables -P INPUT DROP'
    fwcap "$plain" $d ipt_drop
    fwreset "$plain"; ex "$plain" 'iptables -P INPUT DROP'; fwcap "$plain" $d ipt_drop4
    fwreset "$plain"
    # the same four commands as an unprivileged user
    nb="setpriv --reuid=65534 --regid=65534 --clear-groups"
    cap "$plain" $d fw_notroot_ufw $nb ufw status verbose
    cap "$plain" $d fw_notroot_nft $nb nft -j list ruleset
    cap "$plain" $d fw_notroot_iptables $nb iptables -S INPUT
    cap "$plain" $d fw_notroot_ip6tables $nb ip6tables -S INPUT
  fi

  # ---- security_updates: apt-get -s -o Debug::NoLocking=true dist-upgrade -------
  if want apt; then
    apt="apt-get -s -o Debug::NoLocking=true dist-upgrade"
    # start from a host with pending updates: put apt, libpcre2 and the apt
    # library back to the versions of the release pocket
    ex "$plain" '. /etc/os-release; pk=""
      for p in apt libpcre2-8-0 $(dpkg-query -W -f="\${Package}\n" "libapt-pkg*" | grep -E "^libapt-pkg[0-9]"); do
        ver=$(apt-cache madison "$p" | awk -v s="$VERSION_CODENAME/" "index(\$0, s) && !/-updates|-security/ {print \$3; exit}")
        [ -n "$ver" ] && pk="$pk $p=$ver"
      done
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --allow-downgrades $pk >/dev/null 2>&1'
    cap "$plain" $d apt_pending $apt
    # the same simulation against a source list without the security suite: the
    # packages are then available from -updates only
    ex "$plain" '. /etc/os-release
      f=$(ls /var/lib/apt/lists | grep -- "-updates_InRelease$" | head -1); base=${f%%_dists_*}; uri="http://${base//_//}"
      printf "deb %s %s main restricted universe multiverse\ndeb %s %s-updates main restricted universe multiverse\n" "$uri" "$VERSION_CODENAME" "$uri" "$VERSION_CODENAME" > /tmp/kw-nosecurity.list'
    cap "$plain" $d apt_updates_only apt-get -s -o Debug::NoLocking=true -o Dir::Etc::sourcelist=/tmp/kw-nosecurity.list -o Dir::Etc::sourceparts=/nonexistent dist-upgrade
    ex "$plain" 'rm -f /tmp/kw-nosecurity.list'
    cap "$plain" $d apt_notroot setpriv --reuid=65534 --regid=65534 --clear-groups $apt
    # a failing run: the dpkg status file is replaced by one that does not parse
    ex "$plain" 'printf "Package: foo\nthis is not\n a valid control stanza\n\n\0garbage" > /tmp/kw-badstatus'
    cap "$plain" $d apt_error apt-get -s -o Debug::NoLocking=true -o Dir::State::status=/tmp/kw-badstatus dist-upgrade
    ex "$plain" 'rm -f /tmp/kw-badstatus'
    ex "$plain" 'DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq >/dev/null 2>&1'
    cap "$plain" $d apt_current $apt
  fi

  # ---- authorized_keys: key files and the sshd -T lines that name them -----------
  if want keys; then
    ex "$plain" 'rm -rf /tmp/kwkeys; mkdir /tmp/kwkeys; cd /tmp/kwkeys
      ssh-keygen -q -t ed25519 -N "" -C kw-ed25519 -f ed25519
      ssh-keygen -q -t rsa -b 2048 -N "" -C kw-rsa -f rsa
      ssh-keygen -q -t ecdsa -b 256 -N "" -C kw-ecdsa -f ecdsa
      ssh-keygen -q -t ed25519 -N "" -C kw-ca -f ca
      ssh-keygen -q -s ca -I kw-cert -n kwuser -V +52w ed25519.pub'
    mkdir -p "$here/$d"
    for k in ed25519 rsa ecdsa; do
      docker cp "$plain:/tmp/kwkeys/$k.pub" "$here/$d/sshkey_$k.pub"
      cap "$plain" $d "sshkey_${k}_fp" ssh-keygen -lf "/tmp/kwkeys/$k.pub"
    done
    docker cp "$plain:/tmp/kwkeys/ed25519-cert.pub" "$here/$d/sshkey_cert.pub"
    cap "$plain" $d sshkey_cert_fp ssh-keygen -lf /tmp/kwkeys/ed25519-cert.pub
    ex "$plain" 'rm -rf /tmp/kwkeys'
    # accounts: a login user, a user without a login shell, one with the default shell
    ex "$plain" 'id alice >/dev/null 2>&1 || useradd -m -u 1001 -s /bin/bash alice
      id svc >/dev/null 2>&1 || useradd -m -u 1002 -s /usr/sbin/nologin svc
      id bob >/dev/null 2>&1 || useradd -m -u 1003 bob'
    cap "$plain" $d etc_passwd cat /etc/passwd
    ex "$plain" 'mkdir -p /run/sshd /etc/ssh/sshd_config.d
      printf "AuthorizedKeysFile %%h/.ssh/authorized_keys /etc/ssh/keys/%%u .ssh/ak_%%U\nAuthorizedKeysCommand /usr/local/bin/kwkeys %%u\nAuthorizedKeysCommandUser nobody\n" > /etc/ssh/sshd_config.d/10-keys.conf'
    cap "$plain" $d sshd_T_authkeys_custom sshd -T
    ex "$plain" 'printf "AuthorizedKeysFile none\n" > /etc/ssh/sshd_config.d/10-keys.conf'
    cap "$plain" $d sshd_T_authkeys_none sshd -T
    ex "$plain" 'rm -f /etc/ssh/sshd_config.d/10-keys.conf'
  fi

  # ---- cert_expiry: certificates and what openssl says about them ----------------
  if want certs; then
    ex "$plain" 'rm -rf /tmp/kwcert; mkdir /tmp/kwcert; cd /tmp/kwcert
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout leaf.key -out leaf.pem -days 90 -subj "/CN=kw-leaf.example.test" 2>/dev/null
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.pem -days 365 -subj "/CN=kw-ca.example.test" 2>/dev/null
      cat leaf.pem ca.pem > chain.pem'
    docker cp "$plain:/tmp/kwcert/leaf.pem" "$here/$d/cert_leaf.pem"
    docker cp "$plain:/tmp/kwcert/chain.pem" "$here/$d/cert_chain.pem"
    cap "$plain" $d cert_leaf_info openssl x509 -noout -subject -enddate -in /tmp/kwcert/leaf.pem
    cap "$plain" $d cert_ca_info openssl x509 -noout -subject -enddate -in /tmp/kwcert/ca.pem
    ex "$plain" 'rm -rf /tmp/kwcert'
  fi

  # ---- docker_exposure: docker ps / inspect, daemon.json, the dockerd command line
  if want docker; then
    stopdockerd() {
      # a dead dockerd stays in the process table as a zombie (nothing reaps it
      # in a container whose PID 1 is sleep), so only live ones count
      ex "$plain" 'alive() { local p; for p in $(pgrep -x dockerd); do [ "$(cut -d" " -f3 /proc/$p/stat)" = Z ] || return 0; done; return 1; }
        pkill -x dockerd || true
        for i in $(seq 1 40); do alive || break; sleep 1; done; ! alive; rm -f /run/docker.pid'
    }
    startdockerd() { # [dockerd arguments]
      docker exec -d "$plain" bash -c "dockerd $* >/tmp/dockerd.log 2>&1"
      ex "$plain" 'for i in $(seq 1 40); do docker info >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'
    }
    stopdockerd
    # vfs: overlay does not work for a dockerd that runs inside a container
    ex "$plain" 'mkdir -p /etc/docker; printf "{\n  \"storage-driver\": \"vfs\",\n  \"features\": {\"containerd-snapshotter\": false}\n}\n" > /etc/docker/daemon.json'
    cap "$plain" $d daemon_json_plain cat /etc/docker/daemon.json
    startdockerd
    cap "$plain" $d docker_pid cat /run/docker.pid
    cap "$plain" $d dockerd_cmdline_plain bash -c 'cat /proc/$(cat /run/docker.pid)/cmdline'
    cap "$plain" $d docker_ps_none docker ps -q --no-trunc
    fwcap "$plain" $d docker
    ex "$plain" 'docker image inspect alpine:3 >/dev/null 2>&1 || docker pull -q alpine:3 >/dev/null
      for n in kwplain kwpriv kwhostpid kwhostnet kwsock kwall; do docker rm -f $n >/dev/null 2>&1 || true; done
      docker run -d --name kwplain alpine:3 sleep 3000 >/dev/null
      docker run -d --name kwpriv --privileged alpine:3 sleep 3000 >/dev/null
      docker run -d --name kwhostpid --pid=host alpine:3 sleep 3000 >/dev/null
      docker run -d --name kwhostnet --network=host alpine:3 sleep 3000 >/dev/null
      docker run -d --name kwsock -v /var/run/docker.sock:/var/run/docker.sock:ro alpine:3 sleep 3000 >/dev/null
      docker run -d --name kwall --privileged --pid=host --network=host -v /run/docker.sock:/tmp/d.sock alpine:3 sleep 3000 >/dev/null'
    cap "$plain" $d docker_ps_mixed docker ps -q --no-trunc
    cap "$plain" $d docker_inspect_mixed bash -c 'docker inspect --type container -- $(docker ps -q --no-trunc)'
    cap "$plain" $d docker_inspect_gone bash -c 'docker inspect --type container -- $(docker ps -q --no-trunc | head -1) 0000000000000000000000000000000000000000000000000000000000000000'
    # the container network is Docker's own bridge; its addresses and the random
    # MAC addresses are replaced by documentation values (192.0.2.0/24, 02:..)
    for f in docker_inspect_mixed docker_inspect_gone fw_docker_nft; do
      sed -E -i.bak 's/172\.[0-9]+\.0\.([0-9]+)/192.0.2.\1/g; s/([0-9a-f]{2}:){5}[0-9a-f]{2}/02:00:00:00:00:01/g' "$here/$d/$f.stdout" && rm -f "$here/$d/$f.stdout.bak"
    done
    # a daemon that listens on TCP: once by the configuration file, once by flags
    stopdockerd
    ex "$plain" 'printf "{\n  \"storage-driver\": \"vfs\",\n  \"features\": {\"containerd-snapshotter\": false},\n  \"hosts\": [\"unix:///var/run/docker.sock\", \"tcp://127.0.0.1:2375\"]\n}\n" > /etc/docker/daemon.json'
    cap "$plain" $d daemon_json_tcp cat /etc/docker/daemon.json
    startdockerd
    ex "$plain" 'docker -H tcp://127.0.0.1:2375 version >/dev/null'
    cap "$plain" $d dockerd_cmdline_hostsfile bash -c 'cat /proc/$(cat /run/docker.pid)/cmdline'
    stopdockerd
    ex "$plain" 'printf "{\n  \"storage-driver\": \"vfs\",\n  \"features\": {\"containerd-snapshotter\": false}\n}\n" > /etc/docker/daemon.json'
    startdockerd -H unix:///var/run/docker.sock -H tcp://127.0.0.1:2375
    ex "$plain" 'docker -H tcp://127.0.0.1:2375 version >/dev/null'
    cap "$plain" $d dockerd_cmdline_tcp bash -c 'cat /proc/$(cat /run/docker.pid)/cmdline'
    stopdockerd
    cap "$plain" $d docker_ps_nodaemon docker ps -q --no-trunc
    ex "$plain" 'rm -f /etc/docker/daemon.json'
  fi

  # ---- disk_usage: /proc/self/mountinfo with escaped mount points --------------
  if want disk; then
    ex "$plain" 'umount "/mnt/kw ext4" 2>/dev/null || true; rm -rf /mnt/kw*; mkdir -p "/mnt/kw ext4" "/mnt/kw tmp" /mnt/kw-tab /mnt/kw-nl
      mkdir -p "$(printf "/mnt/kw\\\\back")"
      truncate -s 24M /tmp/kw.img; mkfs.ext4 -q -F /tmp/kw.img
      mount -o loop /tmp/kw.img "/mnt/kw ext4"
      mount -t tmpfs tmpfs "/mnt/kw tmp"
      mount -t tmpfs tmpfs "$(printf "/mnt/kw\\\\back")"
      nl="$(printf "/mnt/kw-nl\\nline")"; mkdir -p "$nl"; mount -t tmpfs tmpfs "$nl"'
    cap "$plain" $d mountinfo cat /proc/self/mountinfo
    ex "$plain" 'umount "$(printf "/mnt/kw-nl\\nline")" "$(printf "/mnt/kw\\\\back")" "/mnt/kw tmp" "/mnt/kw ext4"; rm -rf /mnt/kw* /tmp/kw.img'
  fi
done
