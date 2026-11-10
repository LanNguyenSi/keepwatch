#!/bin/bash
# Runs inside the e2e container: prepares one scenario and runs keepwatch.
# usage: scenario.sh hardened|open|diff|nochange|reboot
# keepwatch is copied to /opt/keepwatch/keepwatch; results go to /out as
# runN.json (the report), runN.exit (the exit code) and runN.stderr.
set -euo pipefail

scenario=${1:?usage: scenario.sh hardened|open|diff|nochange|reboot}
kw=/opt/keepwatch/keepwatch
cfg=/etc/keepwatch/keepwatch.yaml

case $scenario in
  open) sshd_conf=open.conf ;;
  hardened | diff | nochange | reboot) sshd_conf=hardened.conf ;;
  *) echo "unknown scenario: $scenario" >&2; exit 64 ;;
esac
cp "/opt/e2e/sshd/$sshd_conf" /etc/ssh/sshd_config.d/00-e2e.conf

# No systemd here, so the services are started by hand. sshd needs its
# privilege separation directory, which on 24.04 exists only once the
# service ran once.
mkdir -p /run/sshd
touch /var/log/auth.log
/usr/sbin/sshd
fail2ban-client -x start >/dev/null
for _ in $(seq 1 30); do
  fail2ban-client status sshd >/dev/null 2>&1 && break
  sleep 0.5
done
fail2ban-client status sshd >/dev/null

run() { # run N: keepwatch check as JSON; a non-zero exit code is recorded, not fatal
  local n=$1 code=0
  "$kw" check --format json --config "$cfg" >"/out/run$n.json" 2>"/out/run$n.stderr" || code=$?
  echo "$code" >"/out/run$n.exit"
}

case $scenario in
  hardened | open) run 1 ;;
  nochange) run 1; run 2 ;;
  diff)
    run 1
    python3 /opt/e2e/listen.py 8080 &
    for _ in $(seq 1 30); do
      ss -Hltn 'sport = :8080' | grep -q . && break
      sleep 0.2
    done
    run 2
    ;;
  reboot)
    install -d -m 755 /etc/keepwatch/conf.d
    install -m 644 /opt/e2e/conf.d/reboot.yaml /etc/keepwatch/conf.d/reboot.yaml
    run 1
    echo "*** System restart required ***" >/var/run/reboot-required
    run 2
    ;;
esac
