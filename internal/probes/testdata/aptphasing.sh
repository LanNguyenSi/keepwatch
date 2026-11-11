#!/usr/bin/env bash
# Runs inside a container with systemd as PID 1 and keepwatch installed
# (keepwatch install writes keepwatch-check.service). Builds a local apt
# repository with phased updates and runs the apt commands of the
# security_updates check twice: directly, and in a unit that has the hardening
# of keepwatch-check.service with another ExecStart (the technique of
# test/systemd/measure.sh). The output of each command is left in a directory.
#
#   aptphasing.sh <outdir>
#   aptphasing.sh restore      put the host's package sources back
#
# The repository (suites <release>, <release>-security, <release>-updates):
#   kwdep     1.0 installed; 1.1 in -updates needs kwnew, a package that is not
#             installed: "apt-get upgrade" keeps it back, "dist-upgrade" installs both
#   kwph1..3  1.0 installed; 1.1 in -updates with Phased-Update-Percentage: 0
#   kwsec     1.0 installed; 1.1 in -security
#   kwsecph   1.0 installed; 1.1 in -security with Phased-Update-Percentage: 0
#
# Output files, for ctx in direct, service and mode in default, fixed, cap,
# capfixed (name = aptphasing_<ctx>_<mode>):
#   <name>.stdout|.exit          apt-get -s -o Debug::NoLocking=true <nocache> <mode options> dist-upgrade
#   <name>_policy.stdout|.exit   apt-cache <nocache> <mode options> policy -- <the packages that run names>
# Mode options: default none; fixed -o APT::Get::Always-Include-Phased-Updates=true;
# cap -o APT::Get::Phase-Policy=true; capfixed both. The probe asks for the
# packages with an old version in the Inst lines, sorted, then for the kept
# back and deferred ones, sorted.
# Also aptphasing_ischroot_<ctx>.txt: the exit status of "ischroot -t" in the context.
set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
save=/etc/apt/kwsave
if [ "${1:-}" = restore ]; then
  if [ -e $save/done ]; then
    rm -f /etc/apt/sources.list.d/kw.list
    [ -e $save/sources.list ] && cp $save/sources.list /etc/apt/sources.list
    for f in $save/sources.list.d/*; do [ -e "$f" ] && cp "$f" /etc/apt/sources.list.d/; done
    rm -rf $save /srv/kwrepo /tmp/kwpkg /var/lib/keepwatch/aptphasing /usr/local/lib/kwphasing
    rm -f /etc/systemd/system/kwphasing.service
    systemctl daemon-reload
    for p in kwdep kwnew kwph1 kwph2 kwph3 kwsec kwsecph; do dpkg -r $p >/dev/null 2>&1 || true; done
    apt-get update -qq 2>&1 | grep -v '^W:' || true
  fi
  exit 0
fi
out=${1:?usage: aptphasing.sh <outdir>}
rel=$(. /etc/os-release; echo "$VERSION_CODENAME")
arch=$(dpkg --print-architecture)
rm -rf /srv/kwrepo /tmp/kwpkg; mkdir -p /tmp/kwpkg
mk() { # name version [dependency]
  local d=/tmp/kwpkg/$1-$2
  mkdir -p "$d/DEBIAN"
  printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: kw <kw@example.test>\nDescription: test package\n' "$1" "$2" >"$d/DEBIAN/control"
  [ -z "${3:-}" ] || echo "Depends: $3" >>"$d/DEBIAN/control"
  dpkg-deb --build "$d" "/tmp/kwpkg/$1_$2_all.deb" >/dev/null
}
for p in kwdep kwph1 kwph2 kwph3 kwsec kwsecph; do mk $p 1.0; done
mk kwdep 1.1 kwnew; mk kwnew 1.0
for p in kwph1 kwph2 kwph3 kwsec kwsecph; do mk $p 1.1; done
# suite NAME "pkg:version[@phase]" ...
suite() {
  local s=$1; shift
  local dir=/srv/kwrepo/dists/$s/main/binary-$arch
  mkdir -p "$dir" "/srv/kwrepo/pool/$s"; : >"$dir/Packages"
  local spec n v phase
  for spec in "$@"; do
    n=${spec%%:*}; v=${spec#*:}; phase=""
    case $v in *@*) phase=${v#*@}; v=${v%@*} ;; esac
    cp "/tmp/kwpkg/${n}_${v}_all.deb" "/srv/kwrepo/pool/$s/"
    { dpkg-deb -f "/srv/kwrepo/pool/$s/${n}_${v}_all.deb"
      [ -z "$phase" ] || echo "Phased-Update-Percentage: $phase"
      echo "Filename: pool/$s/${n}_${v}_all.deb"
      echo "Size: $(stat -c %s "/srv/kwrepo/pool/$s/${n}_${v}_all.deb")"
      echo "SHA256: $(sha256sum "/srv/kwrepo/pool/$s/${n}_${v}_all.deb" | cut -d' ' -f1)"
      echo; } >>"$dir/Packages"
  done
  local sz sum
  sz=$(stat -c %s "$dir/Packages"); sum=$(sha256sum "$dir/Packages" | cut -d' ' -f1)
  printf 'Origin: kwtest\nLabel: kwtest\nSuite: %s\nCodename: %s\nDate: %s\nArchitectures: %s\nComponents: main\nSHA256:\n %s %s main/binary-%s/Packages\n' \
    "$s" "$s" "$(date -Ru)" "$arch" "$sum" "$sz" "$arch" >"/srv/kwrepo/dists/$s/Release"
}
suite "$rel" kwdep:1.0 kwph1:1.0 kwph2:1.0 kwph3:1.0 kwsec:1.0 kwsecph:1.0
suite "$rel-security" kwsec:1.1 kwsecph:1.1@0
suite "$rel-updates" kwdep:1.1 kwnew:1.0 kwph1:1.1@0 kwph2:1.1@0 kwph3:1.1@0
if [ ! -e $save/done ]; then
  mkdir -p $save/sources.list.d
  cp /etc/apt/sources.list $save/ 2>/dev/null || true
  cp /etc/apt/sources.list.d/* $save/sources.list.d/ 2>/dev/null || true
  touch $save/done
fi
: >/etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list
printf 'deb [trusted=yes] file:/srv/kwrepo %s main\ndeb [trusted=yes] file:/srv/kwrepo %s-security main\ndeb [trusted=yes] file:/srv/kwrepo %s-updates main\n' "$rel" "$rel" "$rel" >/etc/apt/sources.list.d/kw.list
apt-get update -qq 2>&1 | grep -v '^W:' || true
dpkg -i /tmp/kwpkg/kw{dep,ph1,ph2,ph3,sec,secph}_1.0_all.deb >/dev/null

# run.sh <ctx> <outdir>: all the commands, in whatever context it is started in.
lib=/usr/local/lib/kwphasing
mkdir -p "$lib" /var/lib/keepwatch/aptphasing
cat >"$lib/run.sh" <<'EOS'
#!/bin/bash
export LC_ALL=C
ctx=$1 o=$2
nocache="-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache="
echo "ischroot -t: $(ischroot -t; echo $?)" >"$o/aptphasing_ischroot_$ctx.txt"
for mode in default fixed cap capfixed; do
  case $mode in
    default) opts="" ;;
    fixed) opts="-o APT::Get::Always-Include-Phased-Updates=true" ;;
    cap) opts="-o APT::Get::Phase-Policy=true" ;;
    capfixed) opts="-o APT::Get::Phase-Policy=true -o APT::Get::Always-Include-Phased-Updates=true" ;;
  esac
  n=$o/aptphasing_${ctx}_$mode
  # shellcheck disable=SC2086
  apt-get -s -o Debug::NoLocking=true $nocache $opts dist-upgrade >"$n.stdout" 2>"$n.stderr"
  echo $? >"$n.exit"
  names=$({ sed -n 's/^Inst \([^ ]*\) \[.*/\1/p' "$n.stdout" | sort
            awk '/^The following packages have been kept back:/ || /^The following upgrades have been deferred due to phasing:/ {k=1;next} k&&/^ /{for(i=1;i<=NF;i++)print $i;next} {k=0}' "$n.stdout" | sort; } | tr '\n' ' ')
  # shellcheck disable=SC2086
  apt-cache $nocache $opts policy -- $names >"${n}_policy.stdout" 2>"${n}_policy.stderr"
  echo $? >"${n}_policy.exit"
done
EOS
chmod 755 "$lib/run.sh"
o=/var/lib/keepwatch/aptphasing
rm -rf "$o"; mkdir -p "$o"
"$lib/run.sh" direct "$o"
units=/etc/systemd/system
sed -e "s#^ExecStart=.*#ExecStart=$lib/run.sh service $o#" -e 's#^Description=.*#Description=keepwatch phasing measurement#' \
  "$units/keepwatch-check.service" >"$units/kwphasing.service"
[ "$(grep -c '^ExecStart=' "$units/kwphasing.service")" -eq 1 ]
systemctl daemon-reload
systemctl start kwphasing.service
rm -f "$units/kwphasing.service"
systemctl daemon-reload
find "$o" -name '*.stderr' -size 0 -delete
rm -rf "$out"; mkdir -p "$out"; cp "$o"/* "$out"/
