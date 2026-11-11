# Picks the mount lines of the measurement out of `findmnt -rno TARGET,FSTYPE |
# sort -u`: the volatile and kernel file systems, the topmost mount of each tree
# only.
#
# A host mounts devtmpfs at /dev, a container runtime mounts a tmpfs there, and
# the same Ubuntu image measured on both would differ in that one word. Both are
# the same kind of place (nothing is kept there over a reboot, and the entry of
# the table that refuses /dev is the same), and the Go test that ties the files
# to the table reads the path of a mount line, not its type. So devtmpfs is
# written as tmpfs, and no measurement depends on which of the two the runtime
# happens to give a container. A new directory, a new mount or a new link still
# changes the file.
$2 ~ /^(tmpfs|ramfs|devtmpfs|proc|sysfs|cgroup|cgroup2|devpts|mqueue|hugetlbfs|securityfs|debugfs|tracefs|fusectl|configfs|pstore|bpf|binfmt_misc|efivarfs)$/ {
  for (p in seen) if (index($1, p "/") == 1) next
  seen[$1] = 1
  type = $2
  if (type == "devtmpfs") type = "tmpfs"
  print "mount " $1 " " type
}
