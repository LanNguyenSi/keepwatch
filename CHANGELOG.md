# Changelog

All notable changes to keepwatch are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change command-line flags, configuration keys and the JSON
report.

## [Unreleased]

### Added

- Configuration: a `watch` section for the watch daemon and its install:
  `enabled` (default off), `learning_period` (default `7d`), the
  `ssh_bruteforce` and `restart_loop` rules with a `threshold` (1 to
  10000) and a `window`, and notification queueing (`notify.queue`,
  `notify.per_incident_interval`, `notify.global_per_minute`), all with
  defaults and ranges that `config check` enforces; durations are one
  number and one unit of `s`, `m`, `h` or `d` (`90m`, `2h`, `7d`), at
  least 1h for `learning_period`, 1m for `per_incident_interval` and
  1s for the windows, and at most 720h (30 days); the keys are
  documented in `docs/configuration.md`.
- A posture source for the daemon: it compares each new timer run in the state
  file with the one it saw before and turns alert-worthy changes into signals
  that do not notify on their own, so `check --notify` stays the only
  notification path for posture.
- Notification worker for the watch daemon: a bounded queue with its own
  goroutine, a per-incident and a global rate limit, reported drops, and an
  incident notice that is cleaned before it is cut.
- A single-instance lock for the state directory: an exclusive non-blocking
  `flock` on `watch.lock`, opened under the secure file rules (no symlink,
  mode `0600`, trusted owner), so a second lock attempt on the same directory
  reports that the lock is held instead of running twice; the lock file is
  kept after release, and the lock is unsupported rather than silently absent
  on platforms without `flock`.
- An incident store for the watch daemon: signals are grouped by fingerprint
  into incidents with a short stable id, and a repeated signal updates the
  count and last-seen time, a closed incident reopens (and counts the
  reopening), and a new or reopened incident asks for a notification that
  stays pending until it is marked as sent. Incidents live in `incidents.json`
  in the state directory (versioned, written atomically, at most 500). Open or
  acked incidents idle for 7 days are closed, and when the store is full the
  least severe incident is evicted for a signal that is at least as severe
  (closed incidents go first), so a flood of low-severity incidents cannot
  blind the daemon. A file that is corrupt or of another version is reported
  and left as it is.
- A request spool for the watch daemon: acknowledging or closing an incident
  is asked for by dropping a small file into `requests/` in the state
  directory, which the daemon reads with owner, mode, size and schema checks
  (a file that fails one is reported with its reason instead of being
  applied) and consumes. At most 100 request files are looked at per pass,
  other entries of the directory are reported apart (at most 20, never
  opened) so they cannot hold requests back, and at most 10000 directory
  entries are examined per pass, with a flag when there are more (while it is
  set, order is kept among the examined entries only). Leftover temporary files
  are swept by age, and those dated ahead of the clock are swept at once.
- An audit log for the daemon: an append-only file in the state directory in
  which every record carries the SHA-256 of its own canonical bytes and of the
  record before it, synced to disk on every append, with a size limit at which
  it refuses to write; ordinary records stop a little earlier, so that one
  last record (a stop or an error) and the recovery record still fit. Opening
  the log reads only its end, so a log of any size opens in constant memory.
  Whatever a crash left after the last intact record, also a crash while the
  log was being recovered, is kept as it is and accounted for by one recovery
  record that names its offset, length and hash, and only the log's own open
  can write that record. The reader checks the whole chain from the first
  record (content, order, links), refuses what the writer could not have
  stored, notices a recovery record whose torn region was cut out of the log,
  and can filter records by kind, incident and time. It does not notice a log
  that was cut off at its end, and anyone who can write the file can rewrite
  all of it consistently; both limits are documented.
- Rules for the daemon that turn journal events into signals: an ssh brute
  force rule (failed and invalid-user logins, plus refused pre-auth
  connections, per source address or IPv6 /64), a restart loop rule (systemd
  automatic restarts per unit) and an OOM kill rule (kernel and systemd lines,
  by unit where the unit is known, otherwise by command name). They count only
  lines whose sender journald vouches for (sshd as root in the ssh unit, PID
  1, the kernel), so a local user cannot inject lines, and a name a user can
  choose inside a genuine line (a cgroup name, a command name, an ssh user
  name) does not decide which unit or address a signal names. They keep a
  capped amount of state per rule.
- Streaming execution for long-running commands such as `journalctl --follow`:
  stdout is delivered line by line to a callback with a per-line cap, an idle
  and a total timeout, and cancellation; after the program exits, its pipe
  backlog is drained within a bounded time and byte volume, and a stream cut
  short is reported as incomplete instead of silently losing lines.

### Security

- Probes no longer cut, escape or replace characters of command output and
  error text before it is redacted. The firewall, security updates, listeners,
  reboot, package, sshd, fail2ban and service checks used to cut such text to a
  few dozen characters (and replace control characters by `?`) first, so a
  token that straddled the cut kept a prefix that no pattern matched and
  reached the report. The one change is now made where the text leaves the
  program, as for the other checks. The note about a failed `ss -p` run in the
  listeners check now stands once in the summary instead of in every item.
- Redaction closes two gaps. A GitHub, GitLab or Slack token glued to the text
  in front of it (`aghp_...`, a digit or an underscore before it) is found, and
  so is any token behind a terminal color sequence. URL user info of the form
  `user:password` is found when host text and a comma, a space or a tab stand
  between the scheme and the user info (`tcp://host, user:password@host`), and
  a URL scheme glued to a digit or an underscore is recognised. Token-only user
  info behind host text and short or common token prefixes glued to a word stay
  as before, to keep ordinary text from being redacted. Keyword rules
  (`Authorization`, `Cookie`, `bearer`, `--password`, `pass=`, `pwd=`) now also
  work directly behind a terminal color sequence, and a second `user:password`
  behind the first one in a list of URLs is found too.

### Changed

- Report texts of the firewall, security updates, listeners, reboot, package,
  sshd, fail2ban and service checks show host text as it is: control
  characters appear escaped (`\x1b`) instead of as `?`, texts are no longer
  cut at 20 to 400 characters, quotes inside a quoted line are no longer
  escaped, and sshd values keep the case the host printed.

### Fixed

- The disk usage check now reads a file system through another mount point of
  the same device when the one it kept cannot be statted (a permission problem,
  a hung path, a lazily unmounted point), instead of reporting the whole device
  as unreadable. The device is still judged once, on the same mount point it
  always reported, and the finding names the mount that answered.

- `keepwatch doctor` escapes every line it prints. A control byte (an escape
  sequence, for one) in a unit-file value such as the `--config` path or in a
  systemd error text reached the terminal raw, where it could move the cursor
  or forge a line of the report the operator pastes into an issue. The area
  and the message of a finding are now escaped once, as they are printed, so
  the report is plain text and the finding keeps its raw text in memory.

## [0.1.0] - 2026-11-11

The first release: stage 0, static posture checks of a Linux server with
reports of what changed, notifications and a scheduled install.

### Added

- `keepwatch check`: eighteen checks of twelve kinds (services, packages, effective sshd
  settings, fail2ban jails, listening sockets against an allowlist, reboot
  required, firewall default policy, pending security updates, Docker
  exposure, authorized keys, disk usage, certificate expiry), with severities,
  exceptions with expiry dates, and text, JSON and Markdown reports.
- Comparison with the last run: only new, changed and resolved findings are
  reported; state and history are kept in `state_dir`.
- Notifications through ntfy for changes worth an alert, and a weekly report
  (`keepwatch report --weekly`).
- A strict configuration loader with `conf.d` drop-ins: unknown keys, wrong
  types, repeated keys and kind changes between files are errors with file
  and line; every directory on the path of the configuration and the token
  file is checked for ownership, permissions and symbolic links.
- `keepwatch install`, `uninstall` and `doctor`: systemd timers for the check
  and the weekly report, run in a hardened sandbox; install refuses paths the
  sandbox would hide or that someone other than root can change, and a
  `state_dir` that cannot be written; doctor judges the units systemd
  actually loads (hand edits, drop-ins, a unit loaded from elsewhere, a
  pending daemon-reload).
- Redaction of secrets in everything keepwatch shows or stores, and output
  escaping of host text.
- Release archives for linux/amd64 and linux/arm64 with SHA-256 checksums and
  a build-provenance attestation.

[Unreleased]: https://github.com/LanNguyenSi/keepwatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/LanNguyenSi/keepwatch/releases/tag/v0.1.0
