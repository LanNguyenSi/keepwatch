# Changelog

All notable changes to keepwatch are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change command-line flags, configuration keys and the JSON
report.

## [Unreleased]

### Security

- Probes no longer cut, escape or replace characters of command output and
  error text before it is redacted. The firewall, security updates, listeners,
  reboot, package, sshd, fail2ban and service checks used to cut such text to a
  few dozen characters (and replace control characters by `?`) first, so a
  token that straddled the cut kept a prefix that no pattern matched and
  reached the report, the notification or the stored state. The one change is
  now made where the text leaves the program, as for the other checks.

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
