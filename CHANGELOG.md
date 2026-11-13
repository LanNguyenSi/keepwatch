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

### Added

- Notification worker for the watch daemon: a bounded queue with its own
  goroutine, a per-incident and a global rate limit, reported drops, and an
  incident notice that is cleaned before it is cut.

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
