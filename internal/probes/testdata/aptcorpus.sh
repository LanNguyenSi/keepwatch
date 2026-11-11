#!/usr/bin/env bash
# Runs inside a plain container: writes the corpus of apt output that the
# parsers of the security_updates probe are tested against (see
# corpus_test.go) into the directory $1. It holds
#   sim.txt          apt-get -s dist-upgrade, as the probe runs it
#   simpolicy.NNN    apt-cache policy for the packages the simulation upgrades
#                    or keeps back, in batches of 100 as the probe asks
#   instpolicy.NNN   apt-cache policy for every KW_CORPUS_INSTALLED_EVERY-th
#                    installed package (default 1: all of them)
#   samplepolicy.NNN apt-cache policy for KW_CORPUS_SAMPLE names (default 3000),
#                    taken evenly from "apt-cache pkgnames", installed or not
#   phasedpolicy.txt apt-cache policy for the packages that carry a
#                    Phased-Update-Percentage in the archive (if there are any)
#   META             release, apt version, architecture, time
#   *.exit, *.err    exit status and stderr of each command
# Run it after apt-get update, against the real archive.
set -u
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
out=${1:?usage: aptcorpus.sh <dir>}
every=${KW_CORPUS_INSTALLED_EVERY:-1}
sample=${KW_CORPUS_SAMPLE:-3000}
rm -rf "$out"; mkdir -p "$out"
nocache="-o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= -o APT::Get::Always-Include-Phased-Updates=true"
{ echo "release: $(. /etc/os-release; echo "$PRETTY_NAME")"; echo "apt: $(dpkg-query -W -f='${Version}' apt)"; echo "arch: $(dpkg --print-architecture)"; echo "installed-every: $every"; echo "sample: $sample"; } >"$out/META"
# policy <prefix> <names-file>: apt-cache policy in batches of 100
policy() {
  split -l 100 -d -a 3 "$2" "$out/$1.names."
  local f b
  for f in "$out/$1.names."[0-9]*; do
    b=${f##*.}
    # shellcheck disable=SC2046
    apt-cache $nocache policy -- $(cat "$f") >"$out/$1.$b" 2>"$out/$1.$b.err"
    echo $? >"$out/$1.$b.exit"
  done
  rm -f "$out/$1.names."[0-9]*
}
apt-get -s -o Debug::NoLocking=true $nocache dist-upgrade >"$out/sim.txt" 2>"$out/sim.err"
echo $? >"$out/sim.exit"
{ sed -n 's/^Inst \([^ ]*\) \[.*/\1/p' "$out/sim.txt"
  awk '/^The following packages have been kept back:/{k=1;next} k&&/^ /{for(i=1;i<=NF;i++)print $i;next} {k=0}' "$out/sim.txt"; } | sort -u >"$out/sim.names"
[ -s "$out/sim.names" ] && policy simpolicy "$out/sim.names"
dpkg-query -W -f='${binary:Package}\n' | sort | awk -v n="$every" 'NR % n == 0' >"$out/installed.names"
[ -s "$out/installed.names" ] && policy instpolicy "$out/installed.names"
apt-cache pkgnames | sort >"$out/all.names"
total=$(wc -l <"$out/all.names"); step=$((total / sample)); [ "$step" -ge 1 ] || step=1
awk -v s="$step" 'NR % s == 0' "$out/all.names" | head -n "$sample" >"$out/sample.names"
policy samplepolicy "$out/sample.names"
apt-cache dumpavail | awk '/^Package:/{p=$2} /^Phased-Update-Percentage:/{print p}' | sort -u >"$out/phased.names"
if [ -s "$out/phased.names" ]; then
  # shellcheck disable=SC2046
  apt-cache $nocache policy -- $(cat "$out/phased.names") >"$out/phasedpolicy.txt" 2>"$out/phasedpolicy.err"
  echo $? >"$out/phasedpolicy.exit"
fi
rm -f "$out/all.names"
find "$out" -name '*.err' -size 0 -delete
echo "sim lines: $(wc -l <"$out/sim.txt"), sim names: $(wc -l <"$out/sim.names"), installed: $(wc -l <"$out/installed.names"), sample: $(wc -l <"$out/sample.names"), phased: $(wc -l <"$out/phased.names")"
