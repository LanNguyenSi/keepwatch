#!/bin/bash
# Runs inside the container of test/systemd/run.sh, as root, with systemd as
# PID 1. It installs keepwatch, measures what the sandbox of the installed
# check service hides, and then asks keepwatch about every path it found.
#
# usage: measure.sh OUTDIR
#   OUTDIR/measured.txt  the measurement, in the format of test/systemd/measured/
#   OUTDIR/product.txt   one line per question put to keepwatch: ok, note or FAIL
#   OUTDIR/log.txt       versions, counts, directories that changed meanwhile
# Exit status: 0 when keepwatch answered every question as expected.
set -euo pipefail
export LC_ALL=C

out=$1
lib=/usr/local/lib/kwsandbox
units=/etc/systemd/system
mkdir -p "$out" "$lib"
: >"$out/product.txt"

install -o root -g root -m 0755 /opt/keepwatch/keepwatch /usr/local/bin/keepwatch
keepwatch init >/dev/null
# Without a notification channel: no run of this harness talks to a server.
sed -i '/^notify:/,$d' /etc/keepwatch/keepwatch.yaml
keepwatch install >/dev/null

{
  grep PRETTY_NAME /etc/os-release
  systemctl --version | head -1
} >"$out/log.txt"

# --- 1. The measurement -------------------------------------------------------
#
# Candidates: every directory down to three levels on the root file system,
# every mount point and two levels below it (of /proc and /sys only the two
# directories themselves: what is inside is the kernel's and differs from host
# to host), and the module directories by name.
findmnt -rno TARGET,FSTYPE | sort -u >"$lib/mounts"
{
  find / -xdev -mindepth 1 -maxdepth 3 -type d 2>/dev/null
  while read -r target _; do
    case $target in /proc | /proc/* | /sys | /sys/*) continue ;; esac
    echo "$target"
    find "$target" -xdev -mindepth 1 -maxdepth 2 -type d 2>/dev/null
  done <"$lib/mounts"
  printf '%s\n' /lib/modules /usr/lib/modules
} | grep -v '[[:space:]]' | sort -u >"$lib/candidates"

# list.sh prints, for every candidate, the device and inode of the directory
# that is at the path where it runs. The same directory has the same pair on
# the host and in the sandbox; a directory the sandbox replaces or takes away
# does not.
cat >"$lib/list.sh" <<'EOF'
#!/bin/sh
while read -r d; do
  if [ -d "$d" ]; then
    printf '%s %s\n' "$d" "$(stat -L -c %d:%i "$d" 2>/dev/null || echo unreadable)"
  else
    printf '%s absent\n' "$d"
  fi
done </usr/local/lib/kwsandbox/candidates
EOF
chmod 755 "$lib/list.sh"

# The probe is the check service as install rendered it, hardening included,
# with another program: what it sees is what a scheduled run sees.
sed -e "s#^ExecStart=.*#ExecStart=$lib/list.sh#" \
  -e 's#^Description=.*#Description=keepwatch sandbox measurement#' \
  "$units/keepwatch-check.service" >"$units/kwsandbox.service"
echo "StandardOutput=file:/var/lib/keepwatch/sandbox.list" >>"$units/kwsandbox.service"
[ "$(grep -c '^ExecStart=' "$units/kwsandbox.service")" -eq 1 ]
systemctl daemon-reload

"$lib/list.sh" >"$lib/host1"
systemctl start kwsandbox.service
"$lib/list.sh" >"$lib/host2"
mv /var/lib/keepwatch/sandbox.list "$lib/sandbox"
rm -f "$units/kwsandbox.service"
systemctl daemon-reload
[ "$(wc -l <"$lib/sandbox")" -eq "$(wc -l <"$lib/candidates")" ]

# A candidate counts when the host showed the same directory before and after
# the probe ran. It is hidden when the sandbox showed another one, or none.
awk '
  FILENAME == ARGV[1] { before[$1] = $2; next }
  FILENAME == ARGV[2] { after[$1] = $2; next }
  { inside[$1] = $2 }
  END {
    for (d in before) {
      if (before[d] == "absent") continue
      if (before[d] != after[d]) { print "unstable " d; continue }
      print (inside[d] != before[d] ? "hidden " : "same ") d
    }
  }' "$lib/host1" "$lib/host2" "$lib/sandbox" | sort -k2 >"$lib/verdicts"

# Symbolic links of the root file system that lead to a directory, with where
# they lead: a path through such a link lies where the link points.
find / -xdev -mindepth 1 -maxdepth 2 -type l 2>/dev/null | grep -v '[[:space:]]' | sort |
  while read -r link; do
    [ -d "$link" ] && printf '%s %s\n' "$link" "$(realpath "$link")"
  done >"$lib/links" || true

{
  echo "candidates: $(wc -l <"$lib/candidates")"
  echo "directories that changed on the host while the probe ran (not judged):"
  grep '^unstable ' "$lib/verdicts" || echo "  none"
} >>"$out/log.txt"

{
  echo "# What the sandbox of the keepwatch services does to the file system of an"
  echo "# Ubuntu host, measured by test/systemd/run.sh with systemd as PID 1."
  echo "#"
  echo "# hidden DIR: the service sees another directory at DIR than the host, or"
  echo "#   none. Directories below a hidden one are left out, except:"
  echo "# visible DIR: DIR lies below a hidden directory, and the service sees the"
  echo "#   directory of the host there all the same. Directories below it are left out."
  echo "# mount DIR TYPE: a file system that does not keep files over a reboot, or"
  echo "#   that belongs to the kernel, is mounted at DIR. Mounts below a listed one"
  echo "#   are left out."
  echo "# link PATH DIR: PATH is a symbolic link to DIR, and DIR lies in a hidden"
  echo "#   directory or on such a file system."
  # Hidden directories, the topmost of each tree only; and inside a hidden
  # tree the directories of the host that are still there, topmost only.
  awk '
    $1 == "hidden" {
      for (p in hidden) if (index($2, p "/") == 1) next
      hidden[$2] = 1
      print
    }
    $1 == "same" {
      inside = 0
      for (p in hidden) if (index($2, p "/") == 1) inside = 1
      if (!inside) next
      for (p in visible) if (index($2, p "/") == 1) next
      visible[$2] = 1
      print "visible " $2
    }' "$lib/verdicts" | sort
  # Volatile and kernel file systems, the topmost mount of each tree only.
  awk '$2 ~ /^(tmpfs|ramfs|devtmpfs|proc|sysfs|cgroup|cgroup2|devpts|mqueue|hugetlbfs|securityfs|debugfs|tracefs|fusectl|configfs|pstore|bpf|binfmt_misc|efivarfs)$/' "$lib/mounts" |
    awk '{
      for (p in seen) if (index($1, p "/") == 1) next
      seen[$1] = 1
      print "mount " $1 " " $2
    }'
} >"$out/measured.txt"
# Links into what was just listed.
while read -r link target; do
  if awk -v t="$target" '$1 != "#" && $1 != "visible" && (t == $2 || index(t, $2 "/") == 1) { found = 1 } END { exit !found }' "$out/measured.txt"; then
    echo "link $link $target"
  fi
done <"$lib/links" >"$lib/linklines"
cat "$lib/linklines" >>"$out/measured.txt"

# --- 2. The installed service still runs --------------------------------------
fail=0
systemctl start keepwatch-check.service || true
result=$(systemctl show keepwatch-check.service -p Result --value)
status=$(systemctl show keepwatch-check.service -p ExecMainStatus --value)
if [ "$result" = success ]; then
  echo "ok   the installed check service runs (Result=success, exit status $status)" >>"$out/product.txt"
else
  echo "FAIL the installed check service: Result=$result, exit status $status" >>"$out/product.txt"
  fail=1
fi

# --- 3. The questions to keepwatch --------------------------------------------
#
# For every directory of the measurement: does keepwatch refuse a path below it,
# in every role? install must refuse (exit 2) and doctor must report a problem
# (exit 1), each naming the path as lying under something.
cfgdir=/etc/kwsandbox
mkdir -p "$cfgdir"
chmod 750 "$cfgdir"

# answer ROLE DIR WANTED_STATUS STATUS TEXT WANTED_TEXT [OR_TEXT]
# OR_TEXT is a second text that also counts: the configuration loader walks
# every ancestor of the configuration and of the token file and refuses a
# symbolic link there (/lib, /var/lock and /var/run are links) before the
# placement rules are reached.
answer() {
  if [ "$4" -eq "$3" ] && { grep -qF -- "$6" <<<"$5" || { [ -n "${7:-}" ] && grep -qF -- "$7" <<<"$5"; }; }; then
    echo "ok   $1 below $2 is refused" >>"$out/product.txt"
  else
    echo "FAIL $1 below $2: exit status $4, wanted $3 and \"$6\": $(head -c 400 <<<"$5" | tr '\n' ' ')" >>"$out/product.txt"
    fail=1
  fi
}

# config FILE STATE_DIR [TOKEN_FILE]
config() {
  printf 'state_dir: %s\n' "$2" >"$1"
  if [ -n "${3:-}" ]; then
    printf 'notify:\n  ntfy:\n    url: http://127.0.0.1:9\n    topic: kwsandbox\n    token_file: %s\n' "$3" >>"$1"
  fi
  chmod 640 "$1"
}

while read -r dir; do
  p=$dir/kwsandbox

  # state_dir: a real install, which must refuse and must not create it.
  config "$cfgdir/keepwatch.yaml" "$p/state"
  set +e
  text=$(keepwatch install --config "$cfgdir/keepwatch.yaml" 2>&1)
  status=$?
  set -e
  answer state_dir "$dir" 2 "$status" "$text" "state_dir $p/state is under "
  if [ -e "$p" ]; then
    echo "FAIL state_dir below $dir: $p was created" >>"$out/product.txt"
    fail=1
    rmdir "$p/state" "$p" 2>/dev/null || true
  fi

  # The binary: the installed units, pointed at a program there, in front of
  # doctor. install puts the units back.
  sed -i "s#^ExecStart=/usr/local/bin/keepwatch #ExecStart=$p/keepwatch #" \
    "$units/keepwatch-check.service" "$units/keepwatch-report.service"
  set +e
  text=$(keepwatch doctor 2>&1)
  status=$?
  set -e
  answer binary "$dir" 1 "$status" "$text" "the keepwatch binary $p/keepwatch is under "
  keepwatch install >/dev/null

  # token_file and the configuration need a file there. A kernel file system
  # takes none, so these two cannot be asked for it.
  if mkdir "$p" 2>/dev/null && (printf 'tk_kwsandbox_0123456789abcdef\n' >"$p/ntfy.token") 2>/dev/null; then
    chmod 700 "$p"
    chmod 600 "$p/ntfy.token"
    config "$cfgdir/keepwatch.yaml" /var/lib/keepwatch "$p/ntfy.token"
    set +e
    text=$(keepwatch install --dry-run --config "$cfgdir/keepwatch.yaml" 2>&1)
    status=$?
    set -e
    answer token_file "$dir" 2 "$status" "$text" "the directory of notify.ntfy.token_file $p is under " "is a symlink, whoever can change it can redirect the path"

    chmod 750 "$p"
    config "$p/keepwatch.yaml" /var/lib/keepwatch
    set +e
    text=$(keepwatch install --print --config "$p/keepwatch.yaml" 2>&1)
    status=$?
    set -e
    answer configuration "$dir" 2 "$status" "$text" "the configuration directory $p is under " "is a symlink, whoever can change it can redirect the path"
    rm -f "$p/ntfy.token" "$p/keepwatch.yaml"
  else
    echo "note configuration and token_file below $dir: no file can be created there, not asked" >>"$out/product.txt"
    rm -f "$p/ntfy.token"
  fi
  rmdir "$p" 2>/dev/null || true
done < <(grep -v '^#' "$out/measured.txt" | awk '{ print $2 }' | sort -u)

exit "$fail"
