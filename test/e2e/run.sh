#!/bin/bash
# End-to-end test of keepwatch in Ubuntu containers.
#
# usage: test/e2e/run.sh [-update] [-keep] [RELEASE...]
#   RELEASE   22.04 and/or 24.04 (default: both)
#   -update   rewrite the golden files instead of comparing with them
#   -keep     keep the work directory (default: remove it on exit)
#
# Environment:
#   KEEPWATCH_E2E_ARCH   GOARCH of the keepwatch binary (default: the arch of
#                        the docker daemon, so the binary runs in the container)
#   GO                   the go binary (default: go)
#   KEEPWATCH_E2E_JQ     jq program to use for the normalisation (default:
#                        normalize.jq next to this script; tests of the
#                        harness point it at a broken copy)
#
# Per release and scenario the script builds keepwatch, runs the scenario in a
# fresh container, normalises the reports (normalize.jq) and compares them with
# golden/<release>/<scenario>.json. The normalisation is verified not to change
# any check id, status, severity, change or exit code (signature.jq).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
go=${GO:-go}
normalize=${KEEPWATCH_E2E_JQ:-$here/normalize.jq}
scenarios=(hardened open diff nochange reboot)

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

for tool in docker jq diff "$go"; do
  command -v "$tool" >/dev/null || { echo "e2e: $tool is required" >&2; exit 69; }
done

arch=${KEEPWATCH_E2E_ARCH:-}
if [ -z "$arch" ]; then
  case $(docker info --format '{{.Architecture}}') in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "e2e: unsupported docker architecture, set KEEPWATCH_E2E_ARCH" >&2; exit 69 ;;
  esac
fi

work=$(mktemp -d)
containers=()
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
  local c
  for c in ${containers[@]+"${containers[@]}"}; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
  if [ "$keep" -eq 1 ]; then
    echo "e2e: work directory kept: $work" >&2
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

echo "e2e: building keepwatch for linux/$arch"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$go" build -trimpath -o "$work/keepwatch" ./cmd/keepwatch)

# run_scenario RELEASE SCENARIO: runs the container, leaves the raw results in
# $work/raw/RELEASE/SCENARIO/.
run_scenario() {
  local rel=$1 sc=$2 id out
  out=$work/raw/$rel/$sc
  mkdir -p "$out"
  id=$(docker create --hostname keepwatch-e2e "keepwatch-e2e:$rel" "$sc")
  containers+=("$id")
  docker cp "$work/keepwatch" "$id:/opt/keepwatch/keepwatch"
  docker start -a "$id" >"$out/container.log" 2>&1 || {
    echo "e2e: scenario $rel/$sc failed in the container:" >&2
    cat "$out/container.log" >&2
    return 1
  }
  docker cp "$id:/out/." "$out"
  docker rm -f "$id" >/dev/null
}

# assemble RAWDIR: one JSON document with every run of a scenario: the exit
# code of the process, the stderr text and the normalised report. Fails when
# the normalisation changed anything signature.jq protects.
assemble() {
  local dir=$1 f n code raw norm
  local docs=()
  for f in "$dir"/run*.json; do
    n=${f##*/run}
    n=${n%.json}
    code=$(tr -d '[:space:]' <"$dir/run$n.exit")
    raw=$(jq -S -f "$here/signature.jq" "$f")
    norm=$(jq -S -f "$normalize" "$f" | jq -S -f "$here/signature.jq")
    if [ "$raw" != "$norm" ]; then
      echo "e2e: the normalisation changed a protected field in $f" >&2
      diff <(printf '%s\n' "$raw") <(printf '%s\n' "$norm") >&2 || true
      return 1
    fi
    docs+=("$(jq -S -n --argjson n "$n" --argjson code "$code" \
      --rawfile stderr "$dir/run$n.stderr" --slurpfile report <(jq -S -f "$normalize" "$f") \
      '{run: $n, process_exit_code: $code, stderr: $stderr, report: $report[0]}')")
  done
  printf '%s\n' "${docs[@]}" | jq -S -s '{runs: .}'
}

status=0
for rel in "${releases[@]}"; do
  echo "e2e: building image keepwatch-e2e:$rel"
  docker build -q -t "keepwatch-e2e:$rel" -f "$here/Dockerfile.$rel" "$here" >/dev/null
  for sc in "${scenarios[@]}"; do
    run_scenario "$rel" "$sc" || { status=1; continue; }
    actual=$work/actual/$rel/$sc.json
    mkdir -p "$(dirname "$actual")"
    assemble "$work/raw/$rel/$sc" >"$actual" || { status=1; continue; }
    golden=$here/golden/$rel/$sc.json
    if [ "$update" -eq 1 ]; then
      mkdir -p "$(dirname "$golden")"
      cp "$actual" "$golden"
      echo "e2e: $rel/$sc golden updated"
    elif [ ! -f "$golden" ]; then
      echo "e2e: FAIL $rel/$sc: no golden file (run with -update)" >&2
      status=1
    elif diff -u "$golden" "$actual" >"$work/diff.txt"; then
      echo "e2e: ok   $rel/$sc"
    else
      echo "e2e: FAIL $rel/$sc: output differs from the golden file" >&2
      cat "$work/diff.txt" >&2
      status=1
    fi
  done
done
exit "$status"
