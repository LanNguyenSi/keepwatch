#!/usr/bin/env bash
# Runs inside a plain container. Builds a local apt repository /srv/kwrepo with
# the three suites <release>, <release>-security and <release>-updates, each
# holding versions of one dummy package, kwtest, and puts kwtest 1.0 (from the
# release suite) on the host. The package sources of the host are replaced by
# the repository, so the simulation is about kwtest alone.
#
#   aptrepo.sh <scenario>    build the repository for a scenario and install kwtest 1.0
#   aptrepo.sh restore       put the host's package sources back
#
# Scenarios (versions in the security and updates suites; "@0" is a
# Phased-Update-Percentage of 0 in the Packages file):
#   plain       security 1.1                         a pending security update
#   superseded  security 1.1, updates 1.2            a newer -updates version has superseded the fix
#   phased      security 1.1, updates 1.2@0          the newer version is phased
#   phasedonly  updates 1.1@0                         a phased update that is not a security fix
#   secphased   security 1.1@0                       the security version itself is phased
#   hold        security 1.1, kwtest on hold         held back by apt-mark hold
#   holdupdate  updates 1.1, kwtest on hold          held back, but not a security fix
#   newdep      security 1.1 that depends on kwmissing   blocked by a dependency that cannot be met
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
save=/etc/apt/kwsave
if [ "${1:-}" = restore ]; then
  if [ -e $save/done ]; then
    rm -f /etc/apt/sources.list.d/kw.list
    [ -e $save/sources.list ] && cp $save/sources.list /etc/apt/sources.list
    for f in $save/sources.list.d/*; do [ -e "$f" ] && cp "$f" /etc/apt/sources.list.d/; done
    rm -rf $save /srv/kwrepo /tmp/kwpkg
    apt-mark unhold kwtest >/dev/null 2>&1 || true
    dpkg -r kwtest >/dev/null 2>&1 || true
    apt-get update -qq 2>&1 | grep -v '^W:' || true
  fi
  exit 0
fi
sc=$1
rel=$(. /etc/os-release; echo "$VERSION_CODENAME")
arch=$(dpkg --print-architecture)
mk() { # version [dependency]
  local d=/tmp/kwpkg/kwtest-$1
  rm -rf "$d"; mkdir -p "$d/DEBIAN"
  printf 'Package: kwtest\nVersion: %s\nArchitecture: all\nMaintainer: kw <kw@example.test>\nDescription: test package\n' "$1" >"$d/DEBIAN/control"
  [ -z "${2:-}" ] || echo "Depends: $2" >>"$d/DEBIAN/control"
  dpkg-deb --build "$d" "/tmp/kwpkg/kwtest_$1_all.deb" >/dev/null
}
suite() { # suite [version[@phase]]
  local s=$1 v=${2:-} phase=""
  local dir=/srv/kwrepo/dists/$s/main/binary-$arch
  mkdir -p "$dir" "/srv/kwrepo/pool/$s"
  : >"$dir/Packages"
  if [ -n "$v" ]; then
    case $v in *@*) phase=${v#*@}; v=${v%@*} ;; esac
    cp "/tmp/kwpkg/kwtest_${v}_all.deb" "/srv/kwrepo/pool/$s/"
    { dpkg-deb -f "/srv/kwrepo/pool/$s/kwtest_${v}_all.deb"
      [ -z "$phase" ] || echo "Phased-Update-Percentage: $phase"
      echo "Filename: pool/$s/kwtest_${v}_all.deb"
      echo "Size: $(stat -c %s "/srv/kwrepo/pool/$s/kwtest_${v}_all.deb")"
      echo "SHA256: $(sha256sum "/srv/kwrepo/pool/$s/kwtest_${v}_all.deb" | cut -d' ' -f1)"
      echo; } >"$dir/Packages"
  fi
  local sz sum
  sz=$(stat -c %s "$dir/Packages"); sum=$(sha256sum "$dir/Packages" | cut -d' ' -f1)
  printf 'Origin: kwtest\nLabel: kwtest\nSuite: %s\nCodename: %s\nDate: %s\nArchitectures: %s\nComponents: main\nSHA256:\n %s %s main/binary-%s/Packages\n' \
    "$s" "$s" "$(date -Ru)" "$arch" "$sum" "$sz" "$arch" >"/srv/kwrepo/dists/$s/Release"
}
rm -rf /srv/kwrepo /tmp/kwpkg; mkdir -p /tmp/kwpkg
mk 1.0; mk 1.1; mk 1.2
sec=1.1 upd=""
hold=0
case $sc in
  plain) ;;
  superseded) upd=1.2 ;;
  phased) upd=1.2@0 ;;
  phasedonly) sec=""; upd=1.1@0 ;;
  secphased) sec=1.1@0 ;;
  hold) hold=1 ;;
  holdupdate) sec=""; upd=1.1; hold=1 ;;
  newdep) mk 1.1 kwmissing ;;
  *) echo "aptrepo.sh: unknown scenario $sc" >&2; exit 2 ;;
esac
suite "$rel" 1.0
suite "$rel-security" "$sec"
suite "$rel-updates" "$upd"
# only the local repository
if [ ! -e $save/done ]; then
  mkdir -p $save/sources.list.d
  cp /etc/apt/sources.list $save/ 2>/dev/null || true
  cp /etc/apt/sources.list.d/* $save/sources.list.d/ 2>/dev/null || true
  touch $save/done
fi
: >/etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list
printf 'deb [trusted=yes] file:/srv/kwrepo %s main\ndeb [trusted=yes] file:/srv/kwrepo %s-security main\ndeb [trusted=yes] file:/srv/kwrepo %s-updates main\n' "$rel" "$rel" "$rel" >/etc/apt/sources.list.d/kw.list
apt-mark unhold kwtest >/dev/null 2>&1 || true
apt-get update -qq 2>&1 | grep -v '^W:' || true
dpkg -i /tmp/kwpkg/kwtest_1.0_all.deb >/dev/null 2>&1 || apt-get install -y -qq --allow-downgrades kwtest=1.0 >/dev/null
dpkg -s kwtest | grep -q '^Version: 1.0$'
[ "$hold" = 0 ] || apt-mark hold kwtest >/dev/null
