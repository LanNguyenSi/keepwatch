# Security policy

## Supported versions

Only the latest release is supported. Security fixes go into the next
release; older releases are not patched back. keepwatch is pre-1.0: update
to the newest release before reporting, so the report is about supported
code.

## Reporting a vulnerability

Report security problems privately, not through a public issue. Use
GitHub's "Report a vulnerability" form on the Security tab of the
repository (private vulnerability reporting). Please do not open a public
issue and do not post details anywhere public until a fix is released.

A useful report holds:

- the output of `keepwatch version`, and the OS with its version;
- the command line you ran and the configuration in use, with secrets
  removed;
- the steps to reproduce, ideally on a fresh host or a fresh container;
- what you believe is affected and what an attacker would need: a local
  user account, a host that can reach the ntfy topic, a writable
  directory, something else;
- the relevant report, state or log output, redacted.

## Why these areas are security-relevant

keepwatch runs as root, so a bug in these areas is a security problem even
when it looks like a plain defect:

- configuration loading: which files are read, and the checks on their
  type, permissions and ownership;
- path placement: where the units, the state, the token file and the
  configuration may lie, and the checks that nobody but root can redirect
  them;
- process execution: the fixed programs the checks run, the sandbox of the
  units, and what an unexpected program output can make a check do;
- output redaction: what reaches a report, a log, or a notification, which
  must never carry secrets.

## Response

A report is acknowledged as soon as possible. There is no fixed response or
fix time, and no published embargo policy yet. You are kept informed in the
private report thread.
