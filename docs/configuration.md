# Configuration

Part of the [keepwatch README](../README.md).

The main file is `/etc/keepwatch/keepwatch.yaml` (override with
`--config`). Every `*.yaml` in a `conf.d` directory next to it is loaded
in lexicographic order and merged in: mappings merge per key (later
files win), sequences such as `exceptions` and `listeners.allow` append,
and scalars are replaced by the later file. A missing `conf.d` is fine;
a missing main file is an error. Unknown keys, wrong types and out-of-range
values are rejected, each error naming `file:line`.

More rules, all reported with `file:line`:

- The root of every file must be a mapping (an empty or null document
  is treated as empty; a file never replaces another file's root).
- A key repeated within the same mapping of the same file is an error
  at any depth; the same key set again by a later file is an override.
  Validation runs on the merged result, so a later file may not replace
  a value with one of another YAML kind (mapping, sequence or scalar):
  that is an error, `<key> in <file:line> changes the type set in
  <file:line>`, with the dotted path for a nested key (`notify.ntfy`).
  Sequences of two files are the same kind and append. A null is not a
  kind of its own, see the next rules.
- `conf.d` must not be a symlink, dangling or not.
- `notify.ntfy.token_file` must be a clean absolute path (no `.`, `..`
  or repeated `/`).
- Scalars are matched by YAML type: `enabled` is true/false, `port` is
  an integer, strings are strings (quoted `"22"` is not a port),
  `expires` is a `YYYY-MM-DD` date. A null (`~`) value counts as absent
  for optional fields and is an error for required ones; a section key
  with a null value (an empty `exceptions:` or `checks:`, for example)
  counts as an absent section, and so do the optional nested mappings
  `checks.<id>.params`, `authorized_keys.expected` and `notify.ntfy`.
- A null value in a `conf.d` file contributes nothing where an earlier
  file already has the key: a drop-in with a bare `notify:` (or a block
  that is entirely commented out) leaves the main file's `notify`
  section intact. A null in an earlier file does not block a later one.
- Entries of `conf.d` whose name starts with a dot (`.hidden.yaml`, an
  editor lock symlink such as `.#a.yaml`) are ignored, like a shell glob
  ignores them.
- `*.yml` in `conf.d` is an error, and so is `a.YAML`, `b.Yml` or any
  other case of the extension: use lower-case `.yaml`. A
  subdirectory inside `conf.d` is an error too.
- Because keepwatch runs as root, the final component of every loaded
  path is never followed (a symlink is refused), and each file's type,
  size (max 1 MiB), permissions (no group or other write bits, mode
  0644 or stricter) and ownership (root or the running user) are
  checked on the open file descriptor itself. The loader walks the path
  of the main file, of `conf.d` and of the token file from `/` and
  checks every directory on the way, not only the one that holds the
  file: each must be a real directory (a symlink at any depth is
  refused), owned by root or the running user, readable by the running
  user, and not writable by group or other. The path is cleaned first, so
  write it without `..`: in `dir/link/../keepwatch.yaml` the link is never
  looked at. An ancestor with the sticky bit set may be writable by group or
  other (others cannot rename or remove the entries they do not own); the
  directory that holds the files may not. This is the rule of the loader
  only: `install` and `doctor` still refuse a configuration or token file
  below `/tmp`, see [Where the paths must lie](install.md#where-the-paths-must-lie). A refusal names
  the directory and the failing component. Every step opens the next
  directory relative to the one just checked, and the files, `conf.d`
  entries included, are opened through the checked directory, so the
  path cannot be swapped between the check and the read. A relative
  `--config` is resolved against the physical working directory first.
  POSIX ACLs, file capabilities and the mount of a directory are not
  examined (known limit; `install` and `doctor` apply a stricter rule,
  root only, see [Where the paths must lie](install.md#where-the-paths-must-lie)).
- `notify.ntfy.url` is required when `notify.ntfy` is set (https, or
  http only for loopback; no credentials, query or fragment; a URL port must
  be 1-65535). It is the address of the server, not of the topic: see
  [Notifications](running.md#notifications). `notify.ntfy.topic` is required too, 1 to 64
  characters of `A-Z a-z 0-9 _ -`. Both are checked by the same rule that the
  notifier applies, so a configuration that loads always builds a notifier; the
  error names the file and line and never repeats the URL, which may hold credentials.
- `notify.ntfy.token_file` must be a regular file, at most 4096 bytes,
  with exactly one hard link, mode 0600 or stricter, owned by the
  running user and not empty; it is validated without reading and
  fully re-checked every time the token is read.
- `keepwatch init` writes the example file atomically (temp file +
  rename, mode 0640) through a directory that is checked like the
  others: neither it nor any directory above it may be a symlink or
  writable by group or other (sticky ancestors excepted), and all must
  be owned by root or the running user. Missing directories are created
  with mode 0750 and checked in turn. It refuses to follow symlinks, and
  `--force` only replaces a regular file.

- `redact.patterns` is an optional list of extra redaction patterns, see
  [Redaction](running.md#redaction).

## Watch

`watch` is the top-level section the watch daemon and `install` read.
Every key is optional and may appear in `conf.d` like any other
section (mappings merge per key, later files win, a null counts as
absent). Durations are written as a Go duration (`45s`, `90m`, `2h`)
optionally preceded by a whole number of days (`7d`, `1d12h`).
`ssh_bruteforce` and `restart_loop` are rules: `threshold` events
within `window` raise a finding; `learning_period` is the start-up
period during which findings are held back; `notify.queue` is how many
notifications may wait, `notify.per_incident_interval` the least time
between two notices of one incident, and `notify.global_per_minute`
the global notice rate. The ranges are checked, each error naming
`file:line`.

| key | default | range |
| --- | --- | --- |
| `watch.enabled` | `false` | `true` or `false` |
| `watch.learning_period` | `7d` | above 0, at most 720h (30 days) |
| `watch.ssh_bruteforce.threshold` | `5` | at least 1 |
| `watch.ssh_bruteforce.window` | `10m` | above 0, at most 720h (30 days) |
| `watch.restart_loop.threshold` | `3` | at least 1 |
| `watch.restart_loop.window` | `15m` | above 0, at most 720h (30 days) |
| `watch.notify.queue` | `100` | 1 to 1000 |
| `watch.notify.per_incident_interval` | `1h` | above 0, at most 720h (30 days) |
| `watch.notify.global_per_minute` | `6` | 1 to 60 |

```sh
keepwatch init --config /etc/keepwatch/keepwatch.yaml   # write a commented example
keepwatch config check --config /etc/keepwatch/keepwatch.yaml
```
