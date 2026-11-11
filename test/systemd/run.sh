#!/bin/bash
# Measures what the sandbox of the installed keepwatch services hides, on
# Ubuntu containers with systemd as PID 1, and checks keepwatch against it.
#
# usage: test/systemd/run.sh [-update] [-keep] [RELEASE...]
#   RELEASE   22.04 and/or 24.04 (default: both)
#   -update   rewrite measured/<release>.txt and answers/<release>.txt
#             instead of comparing with them
#   -keep     keep the work directory (default: remove it on exit)
#
# A host mounts devtmpfs at /dev and a container runtime a tmpfs; mounts.awk
# writes both as tmpfs, so the comparison does not depend on which of the two
# the host gives (see docs/development.md, "Sandbox measurement").
#
# Environment:
#   KEEPWATCH_SYSTEMD_ARCH   GOARCH of the keepwatch binary (default: the arch
#                            of the docker daemon)
#   GO                       the go binary (default: go)
#
# Per release the script builds keepwatch, boots a privileged container whose
# PID 1 is systemd, and runs measure.sh in it. That installs keepwatch, starts a
# probe with the hardening of the installed check service, and lists the
# directories that the probe sees differently from the host. Two things are
# then checked:
#
#   1. keepwatch refuses a path below every directory of the measurement, in
#      every role (measure.sh asks install and doctor; product.txt), and the
#      list of answers equals answers/<release>.txt, so a question that is no
#      longer asked fails as well.
#   2. The measurement equals measured/<release>.txt. A Go test
#      (internal/install) ties that file to the table keepwatch decides by, in
#      both directions, so a table entry that claims a directory is hidden
#      without the sandbox hiding it fails there.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
go=${GO:-go}

update=0
keep=0
releases=()
for arg in "$@"; do
  case $arg in
    -update) update=1 ;;
    -keep) keep=1 ;;
    22.04 | 24.04) releases+=("$arg") ;;
    *) echo "usage: $0 [-update] [-keep] [22.04] [24.04]" >&2; exit 64 ;;
  esac
done
[ ${#releases[@]} -gt 0 ] || releases=(22.04 24.04)

for tool in docker diff "$go"; do
  command -v "$tool" >/dev/null || { echo "systemd: $tool is required" >&2; exit 69; }
done

arch=${KEEPWATCH_SYSTEMD_ARCH:-}
if [ -z "$arch" ]; then
  case $(docker info --format '{{.Architecture}}') in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "systemd: unsupported docker architecture, set KEEPWATCH_SYSTEMD_ARCH" >&2; exit 69 ;;
  esac
fi

# The part of the measurement that has to read alike on every host and runtime.
bash "$here/mounts_test.sh"

work=$(mktemp -d)
containers=()
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
  local c
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  if [ "$keep" -eq 1 ]; then
    echo "systemd: work directory kept: $work" >&2
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

echo "systemd: building keepwatch for linux/$arch"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$go" build -trimpath -o "$work/keepwatch" ./cmd/keepwatch)

# booted ID: waits until systemd in the container has finished starting.
booted() {
  local state
  for _ in $(seq 1 90); do
    state=$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)
    case $state in running | degraded) return 0 ;; esac
    sleep 1
  done
  echo "systemd: systemd did not come up in the container (state: ${state:-none})" >&2
  return 1
}

status=0
for rel in "${releases[@]}"; do
  echo "systemd: building image keepwatch-systemd:$rel"
  docker build -q -t "keepwatch-systemd:$rel" -f "$here/Dockerfile.$rel" "$here" >/dev/null
  out=$work/$rel
  mkdir -p "$out"
  id=$(docker run -d --privileged --cgroupns=host "keepwatch-systemd:$rel")
  containers+=("$id")
  booted "$id" || { status=1; continue; }
  docker cp "$work/keepwatch" "$id:/opt/keepwatch/keepwatch"
  docker cp "$here/measure.sh" "$id:/opt/keepwatch/measure.sh"
  docker cp "$here/mounts.awk" "$id:/opt/keepwatch/mounts.awk"
  asked=0
  docker exec "$id" bash /opt/keepwatch/measure.sh /out >"$out/container.log" 2>&1 || asked=$?
  docker cp "$id:/out/." "$out" || true
  docker rm -f "$id" >/dev/null
  if [ ! -s "$out/measured.txt" ] || [ ! -s "$out/product.txt" ]; then
    echo "systemd: FAIL $rel: the measurement did not finish:" >&2
    cat "$out/container.log" >&2
    status=1
    continue
  fi
  if [ "$asked" -ne 0 ] || grep -q '^FAIL' "$out/product.txt"; then
    echo "systemd: FAIL $rel: keepwatch does not refuse what the sandbox hides:" >&2
    grep '^FAIL' "$out/product.txt" >&2 || cat "$out/container.log" >&2
    status=1
  else
    echo "systemd: ok   $rel keepwatch refuses every measured directory ($(grep -c '^ok' "$out/product.txt") answers)"
  fi
  answers=$here/answers/$rel.txt
  if [ "$update" -eq 1 ]; then
    if grep -q '^FAIL' "$out/product.txt"; then
      echo "systemd: FAIL $rel: answers not written, keepwatch failed a question" >&2
      status=1
    else
      cp "$out/product.txt" "$answers"
      echo "systemd: $rel answers written to ${answers#"$root"/}"
    fi
  elif [ ! -f "$answers" ]; then
    echo "systemd: FAIL $rel: no answers/$rel.txt (run with -update)" >&2
    status=1
  elif diff -u "$answers" "$out/product.txt" >"$work/answers-diff.txt"; then
    echo "systemd: ok   $rel the answers equal answers/$rel.txt"
  else
    echo "systemd: FAIL $rel: the answers differ from answers/$rel.txt:" >&2
    cat "$work/answers-diff.txt" >&2
    status=1
  fi
  measured=$here/measured/$rel.txt
  if [ "$update" -eq 1 ]; then
    cp "$out/measured.txt" "$measured"
    echo "systemd: $rel measurement written to ${measured#"$root"/}"
  elif [ ! -f "$measured" ]; then
    echo "systemd: FAIL $rel: no measured/$rel.txt (run with -update)" >&2
    status=1
  elif diff -u "$measured" "$out/measured.txt" >"$work/diff.txt"; then
    echo "systemd: ok   $rel the measurement equals measured/$rel.txt"
  else
    echo "systemd: FAIL $rel: the sandbox differs from measured/$rel.txt:" >&2
    cat "$work/diff.txt" >&2
    status=1
  fi
done
exit "$status"
