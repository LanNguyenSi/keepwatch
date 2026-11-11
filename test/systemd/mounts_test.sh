#!/bin/bash
# Checks mounts.awk, the part of the measurement that has to give the same lines
# on a host that mounts devtmpfs at /dev and in a container that has a tmpfs
# there. No container is needed.
#
# usage: test/systemd/mounts_test.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
awkfile=$here/mounts.awk
data=$here/testdata
status=0

# expect NAME WANTED_FILE: the lines on stdin must equal the file.
expect() {
  local got
  got=$(cat)
  if [ "$got" = "$(cat "$2")" ]; then
    echo "mounts: ok   $1"
  else
    echo "mounts: FAIL $1:" >&2
    diff -u "$2" <(printf '%s\n' "$got") >&2 || true
    status=1
  fi
}

# expect_line NAME WANTED: the lines on stdin must contain WANTED.
expect_line() {
  if grep -qxF -- "$2" <&0; then
    echo "mounts: ok   $1"
  else
    echo "mounts: FAIL $1: no line \"$2\"" >&2
    status=1
  fi
}

expect "devtmpfs at /dev is written as tmpfs" "$data/mounts-expected.txt" \
  < <(awk -f "$awkfile" "$data/mounts-host.txt")
expect "a tmpfs at /dev gives the same lines" "$data/mounts-expected.txt" \
  < <(awk -f "$awkfile" "$data/mounts-container.txt")

# Only the word is normalised: a place that is new, or a type that is not
# devtmpfs, still shows.
expect_line "a new tmpfs shows" "mount /mnt/scratch tmpfs" \
  < <({ cat "$data/mounts-container.txt"; echo "/mnt/scratch tmpfs"; } | sort -u | awk -f "$awkfile")
expect_line "a devtmpfs somewhere else shows" "mount /srv/dev tmpfs" \
  < <({ cat "$data/mounts-container.txt"; echo "/srv/dev devtmpfs"; } | sort -u | awk -f "$awkfile")
expect_line "the type of another file system is kept" "mount /sys sysfs" \
  < <(awk -f "$awkfile" "$data/mounts-host.txt")
expect_line "the type of another file system is kept (proc)" "mount /proc proc" \
  < <(awk -f "$awkfile" "$data/mounts-host.txt")

exit "$status"
