# Running a check

Part of the [keepwatch README](../README.md).

```sh
keepwatch check [--config FILE] [--format text|json|markdown] [--no-state] [--fail-on SEVERITY] [--notify]
```

`check` loads the configuration, runs every enabled check of the catalog,
compares the result with the previous run, prints a report and stores the
result as the new "previous run".

| Flag | Meaning |
|---|---|
| `--config FILE` | main configuration file (default `/etc/keepwatch/keepwatch.yaml`) |
| `--format` | `text` (default), `json` or `markdown` |
| `--no-state` | only check: the state of the last run is neither read nor written, and the report has no comparison |
| `--fail-on SEVERITY` | lowest severity that makes the exit code 1: `info`, `low`, `medium` (default), `high`, `critical` |
| `--notify` | send the changes worth an alert (and on a first run the open findings) to the ntfy topic, see [Notifications](#notifications); cannot be combined with `--no-state` |

The JSON report carries `schema_version` 2. Version 2 added the change kinds
`hidden_gone` and `set_changed` (with the fields `hidden_gone`, `old_total` and
`new_total`) and no longer produces `count_change`, which version 1 reports could
hold.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no result counts at `--fail-on` |
| 1 | at least one result counts at `--fail-on` |
| 2 | usage error (unknown flag, bad `--format` or `--fail-on`, extra argument) |
| 3 | keepwatch could not do its job: invalid configuration (also `--notify` without `notify.ntfy`), a state directory that cannot be trusted or a state that cannot be saved, a state of the run itself that contradicts itself (an internal error), an interrupted run, a failed write of the report |
| 4 | `--notify` (or `report --weekly --notify`) could not deliver the notification, see [Notifications](#notifications) |

What counts for exit code 1, per status, when the check's severity is at least
`--fail-on`:

| Status | Counts | Why |
|---|---|---|
| `fail` | yes | a deviation |
| `error` | yes | the check could not be evaluated; an unknown state must not look green |
| `warn` | only for the `authorized_keys` check | a warn there can stand for keys that were never examined; every other warn is a soft deviation and leaves the exit code at 0 |
| `pass`, `skipped`, `excepted` | no | an excepted failure is covered by a dated exception with a reason |

The expired-exception result (`exception_expired`) is a `fail` of severity low,
so it counts only with `--fail-on low` or `--fail-on info`.

The exit code depends on the current results only, never on the comparison with
the last run: a timer that runs `check` every few hours sees exit 1 for as long
as the host stays bad. The comparison decides what is worth a notification.
Precedence: 3 wins over 4, 4 wins over 1, 1 wins over 0. Exit code 3 wins over
everything: if the state could not be handled, the run is not reliable, even
when the report (which is still printed) shows findings, and nothing is sent.
Exit code 4 wins over 1: while the host stays bad, 1 is what every run exits
with and says nothing new, whereas 4 says that an alert did not arrive. The
report was printed in both cases, and the next run repeats the checks' verdict. The
`exit_code` in a report is the one decided before the state is saved; a state
that cannot be saved is found after the report was written (see "State"), so it
is told on stderr and the process exits 3 although the report says 1 or 0.

## The comparison with the last run

Per check the report lists, in the order of the checks:

- `new_failure`: the check fails now and did not before (from `pass`, `skipped`,
  `excepted`, `warn` or `error`);
- `fixed`: it failed and passes now;
- `status_change`: every other change of status (`pass` to `error`, `fail` to
  `warn`, `excepted` to `pass`, ...);
- `severity_change`: the check has the same status (`fail`, `warn` or `error`) in
  both runs and another severity, for example because a configuration override
  changed it; it is an alert when the severity went up and the status counts
  toward the exit code (see above), since a failure that was below `--fail-on`
  can have crossed it;
- `check_added` and `check_removed`: the catalog gained or lost the check;
- for a check that is `fail` (or `warn`) in both runs: `subject_new` and
  `subject_gone` for items that appeared or disappeared, `hidden_new` and
  `hidden_gone` for items that did but that the check does not list, and
  `set_changed` for a list too long to compare item by item (see below);
- the checks that keep failing or warning unchanged ("still failing", "still
  warning").

A change is marked as an alert (worth a notification) when a check starts to
fail or to be in `error`, when a new check is failing or in `error`, when a
failing check has a new item (named, or counted as `hidden_new`) or a changed list that is too long to compare (`set_changed`), when a failing check or one
in `error` gets a higher severity, and when an `authorized_keys` check starts to
warn, is new and warns, or has a new warn item.
Everything else (fixed, gone items, a status change to `skipped`, `excepted` or
a `warn` of another check) is reported without the alert mark.

Two rules keep the comparison honest:

- An `error` is a partial picture: the check could not see everything. Its
  evidence is never compared item by item; the change of status is reported once.
- A check that has more than 100 items lists the first 99 sorted by subject and a
  marker "(N more not shown)". The marker is not an item: a change of N never
  produces new or gone subjects. Besides the 99 items the state keeps the
  complete list as a set of keys (the SHA-256 of each subject as the check
  produced it, sorted, without duplicates) and a digest of that list, so two runs are compared as sets and not
  by what happened to be listed. The failing set of a check is its keys without
  the keys of the items an exception covers. A list that is not cut is its own
  set, so a cut and a complete list compare like any other pair:
  - Both sets have at most 10,000 keys: the difference is exact. A key that is
    new in the failing set is `subject_new` (an alert) when its subject is among
    the items listed, and otherwise counted in one `hidden_new` change with the
    exact number (also an alert); a key that left it is `subject_gone` or counted
    in one `hidden_gone` (no alert). For example, a listener below the cut stops
    and a new one starts above it: `subject_gone` for the first and `hidden_new` 1
    for the second, although the total is the same. A subject that the report
    has to escape, redact or cut for display is still compared by the subject the
    check produced, not by its display text (see below).
  - A set has more than 10,000 keys: its keys are not stored, only its total and
    the digest. Equal digests mean the same list. Different digests are one
    `set_changed` change with both totals, an alert: that something changed is
    certain, which items is not told.
  So the limits are: the report names up to 99 items, counts exactly up to
  10,000, and detects any change above that. An item that appeared and went away
  between two runs is invisible, as it is for any comparison of two runs. An
  exception only marks the items that are listed; an excepted item that falls out
  of the listed part (because new items sort before it) is a failing item again
  and is reported as new.

Items are compared by the SHA-256 of the subject the check produced, and every
check produces the raw subject: the listener address and port, the file path of
`cert_expiry`, the mount point of `disk_usage`, the TCP findings and container
names and ids of `docker_exposure`, the path, pattern and line warnings and key
fingerprints of `authorized_keys`, and the package names of `security_updates`.
Only what is shown is cleaned: the report, the state and the notifications
redact secrets, escape control characters and cut long names. So two subjects
that look the same after that (they differ in a control character, say, or only
past the length the report shows) are still two items, and swapping one for the
other is a change.

## State

The state is `state.json` in `state_dir` (default `/var/lib/keepwatch`): JSON
with `schema_version` (4; files of version 1 to 3 are not read), the time of the
run, the record of a failed delivery (see [Notifications](#notifications)) and, per check, its id, kind, status, severity and items (hash and cleaned,
redacted subject, and whether an exception covers it). For a check whose list was
cut it also holds the total, the sorted key list (up to 10,000 keys) and the
digest described above; the stored keys must be sorted, unique, hash-sized, match
the digest and include every stored item, otherwise the file is not used. It holds
no evidence detail text and no summaries, and nothing from a subject that is not
already in it as displayed. A key set costs 72 bytes per key in the file; the
largest state keepwatch can write (every one of the 18 checks capped, full and
with the longest subjects) is 15.3 MB, so the limit below is 16 MiB.

keepwatch runs as root and the state decides what the operator is told, so it is
checked:

- `state_dir` is cleaned with `filepath.Clean` and must be absolute. It is created
  with mode 0700 if it does not exist; otherwise it must be a real directory (not
  a symlink) owned by root or the running user that group and other cannot write
  to. Ancestors above it are not examined by `check` itself (known limit of a run by
  hand): they must be root-owned. `install` and `doctor` do examine them, see
  [Where the paths must lie](install.md#where-the-paths-must-lie).
- The state file is opened without following links and checked on the open
  descriptor: a regular file of at most 16 MiB, owned by root or the running user,
  not writable by group or other.
- It is written atomically: a temporary file in the same directory (created
  exclusively, mode 0600), flushed, renamed over `state.json`, then the directory
  is flushed. If a step fails, the previous file stays and the temporary file is
  removed.

Recovery. A missing state file is a first run: a baseline, no changes are
reported. A state file that is a symlink, foreign-owned, group- or
other-writable, too large, truncated, not valid JSON, of another schema version
or invalid is reported as a warning (stderr and in the report) and the run is a
new baseline (this includes a file of an older schema version, which has no key
sets to compare with: the first run after an upgrade is a baseline); it is never an abort and never a silent "nothing changed". The
file is replaced at the end of the run, so nothing needs repairing; to start from
scratch, delete `state.json`. A state directory that cannot be trusted (or a
state that cannot be saved) is different: the report is still printed, state is
not read or written, and the exit code is 3, because the next run could not be
compared reliably.

Before the comparison, keepwatch checks the state it built from this run for
consistency: for each check with a key set, the digest is hash-sized and no
more items are listed than the total; and (for sets small enough to list their
keys) the keys are sorted, unique and hash-sized, the total and the digest match
them and every listed item is in the set. This cannot fail on a correct
build; if it does, it is a defect in keepwatch, not a property of the host. The
run then takes the same path as an unusable state directory: the report is still
printed, no changes are reported, a warning names the check and the rule (never
a subject), the stored state is left as it was and the exit code is 3.

The report is built first, written to stdout, then (with `--notify`) the
notification is sent, and only then is the state saved. A report that could not
be written (a closed pipe, a full disk) therefore leaves the state as it was: the
next run reports the same changes again instead of losing them, and the exit code
is 3. A notification that could not be delivered leaves the snapshot as it was too
(see [Notifications](#notifications)). A failed save cannot be part of the
report any more; it is a warning on stderr and exit code 3.

The state is written after a successful run, never after an interrupted one. A
manual `keepwatch check` counts as a run: it moves the "previous run" forward,
so a scheduled run after it reports changes only since that manual run. Use
`--no-state` for a look that must not do that.

## Notifications

`keepwatch check --notify` sends one message per run to an
[ntfy](https://docs.ntfy.sh/) topic, and only when there is something to tell.
ntfy is the only channel of stage 0. Nothing else is ever contacted: keepwatch has
no telemetry, and the address comes from the configuration only.

```yaml
notify:
  ntfy:
    url: https://ntfy.example.com        # the server, not the topic
    topic: keepwatch-alerts              # 1-64 characters of A-Z a-z 0-9 _ -
    token_file: /etc/keepwatch/ntfy.token  # optional, an access token (tk_...)
```

The message is posted to `<url>/<topic>` (a path prefix in `url`, for a server behind a
reverse proxy at `/ntfy`, is kept). `url` must be https, or http for a loopback host,
and holds no credentials, query or fragment; a bad `url` or `topic` is a configuration error
(`config check` finds it), and `--notify` without `notify.ntfy` is exit code 3 before any check runs. The token is read from
`token_file` every time a message is sent (through the same checks as at load time:
regular file, mode 0600, owned by the running user, no symlink) and goes only into the
`Authorization: Bearer` header; a token with a space, a control or a non-ASCII
character is refused. `token_file` is optional for a server that accepts anonymous
publishing.

**What is sent when.** The decision is made from the comparison with the last run
(the report's counts), never from the exit code: the exit code says that something
fails now, not that something changed.

| Run | Sent |
|---|---|
| first run, or the previous state was not usable | one notice: the counts and the open findings (`fail`, `warn`, `error`; for `fail` and `warn` up to three subjects, for `error` none) |
| at least one change is an alert (see "The comparison") | one message with the alerts, then the other changes (fixes, items that are gone), then the checks that keep failing |
| only changes that are not alerts (a fix, an item that is gone), or none | nothing; the state moves forward |
| the last delivery failed, whatever else happened | one message that says so, with the changes since the last delivered report |
| the state could not be used (exit 3) | nothing |

At most one message per run, so a timer that runs every few hours sends at most that
many messages a day, however many things change. A check in `error` is one change of
status; the evidence of an `error` is never listed item by item. If the delivery
of a baseline notice fails, the first state is stored with a `delivery` record of kind
`baseline`; the next run with `--notify` sends the open findings of that run again as a
"first report" (not the changes since a snapshot, because nothing was ever delivered),
and keeps doing so until a delivery works.

**Every string of a message is cut at 200 characters** (whole characters, with `...`), so
that one long subject cannot use up the body, and the alerts are listed with the highest
severity first: when the body is too small for all of them it is the low ones that are
left out ("N more lines not shown"), never the critical one. The counts in the title and
heading are always the real ones.

**Use `--notify` for every run that is supposed to tell.** A run without `--notify`
(a manual `keepwatch check`, a script) moves the snapshot forward like any other run, so
the alert-worthy changes it finds are consumed: the next scheduled run with `--notify`
compares with that snapshot and does not send them. When `notify.ntfy` is configured, such
a run says so on stderr ("moved the state forward past N alert-worthy changes that no
notification will tell"). Use `--no-state` for a look that must not do that.

**A signal during the delivery of `check --notify`** (SIGINT, SIGTERM) is an interrupted run like
one during the checks: exit code 3, nothing is stored, the next run reports and sends the same
changes. If the message had already reached the server, it arrives twice; it is never lost.
For `report --weekly --notify` a signal during the delivery counts as a failed delivery (exit
code 4, a weekly failure is recorded).

**Priority and tags.** The priority is that of the highest severity among the alerts
(baseline: among the `fail` and `error` findings): critical 5 (urgent), high 4, medium
3 (default), low 2, info 1. The weekly report has priority 3 (2 when nothing is open).
Tags are fixed words: `keepwatch` plus `rotating_light` (high or critical),
`warning`, `information_source` (baseline) or `calendar` (weekly report). The title is
`keepwatch <host>: N alerts` and the like, in printable ASCII (anything else becomes
`?`, which also keeps a line break or a header out of the title).

**Markdown.** The body is Markdown and is sent with the header `Markdown: yes`. ntfy
renders it only then. Checked against the sources of ntfy (server main at
v2.37.2, web app, Android app): the server does not interpret the body; the web app
renders it with remark-parse 9 (CommonMark, micromark), without the GFM extensions
(so no tables and no autolinks) and without raw HTML (a tag in the source is not
rendered, links and images get a protocol check); the Android app uses Markwon 4.6.2
(commonmark-java) with the image, linkify, table and strikethrough plugins. The
argument of [Output safety](#output-safety) therefore holds for ntfy: everything that
comes from the host or the configuration is put into a code span whose fence is longer
than any run of backticks in it, and nothing outside a code span is anything but bold
words, list markers, numbers and fixed phrases; a link, an image, HTML, a heading, an
`@` or a line that starts a block cannot be made out of evidence. One thing stays:
the Android app's linkify plugin acts on running text only and not on a code span
(Markwon 4.6.2: the listener is fired by the text visitor, not by the code visitor), and
ntfy shows the text of a message
to everybody who can read the topic: on an open server the topic name is the only
secret, so use a long one or an access token. No table is used, because the web app
does not render them. A body is cut at 3,600 bytes (ntfy's limit is 4,096; a longer body
would be turned into an attachment) with a line that says how many lines were left
out; the numbers in the heading are always the real ones.

**Redaction.** Every string of a message, the title included, goes through the
redactor (built-in patterns plus `redact.patterns`, control characters escaped) before
it is sent, the same as in the report. A message holds names of checks, item subjects
as the report shows them, counts, statuses and severities; never evidence detail, a
summary, a file content or a command line.

**The HTTP client.** It uses no proxy from the environment (`HTTP_PROXY`, `HTTPS_PROXY`,
`ALL_PROXY` are ignored: the token would travel through whatever they name; there is
no proxy setting), verifies TLS certificates (TLS 1.2 or newer), does not follow
redirects (a redirect could take the token to another host: it is an error, and the
`url` in the configuration should be the final address), keeps no connection between
runs, times out after 15 seconds per request and reads at most 64 KiB of an answer.
There is one retry after 2 seconds, and only for a network error, a timeout, a 5xx or
a 429; a `Retry-After` of up to 30 seconds is waited for, a longer one means no retry
in this run. Other 4xx answers (a refused token, an unknown topic) are not retried.
Error messages name the status and ntfy's own error text, never the topic or the token
(a network error names the address and port that could not be reached, as the system
reports it, which is the server you configured).

**When a delivery fails.** The exit code is 4, and the snapshot in `state.json` is not
moved forward: it is stored again as it was, with a `delivery` record (time, number of
failed runs in a row, kind, a short redacted reason). The history is not written
either. The next run therefore compares with the last snapshot whose changes were
delivered and reports the same changes again, together with "last delivery failed",
in the report (a warning), on stderr and in the message. The record is cleared when a
message is delivered. Without `--notify`, a run does not move a snapshot that holds
undelivered changes forward either (it says so on stderr), because that would mark
changes as seen that nobody was told; `--no-state` is the way to look without
touching anything. If the state cannot be saved after a successful delivery (exit
3), the next run tells the same changes a second time. Delivery is at least once.

## Weekly report

```sh
keepwatch report --weekly [--config FILE] [--format text|markdown] [--notify]
```

The digest of the open findings of the last run (from `state.json`, per check: status,
severity and up to three subjects) and of the changes of the last 7 days (from the
history, newest first, at most 25 lines, alerts marked). It runs no checks. Without
`--notify` it is printed (text, or Markdown); with `--notify` it is sent to ntfy (the
Markdown form, priority 3) and the command prints one line. A state or history that
cannot be used is a warning on stderr and a note in the digest, never an abort (an
untrusted state directory is exit code 3). A weekly report that cannot be delivered
is exit code 4 and a `delivery` record of kind `weekly` in the state (unless there is
a record already: the one about undelivered changes is the more important); the next
`check --notify` mentions it. `report` without `--weekly` is not implemented (exit
code 3).

## History

`history.json` in `state_dir`, next to `state.json`, written by `check` when it moves
the state forward (not with `--no-state`, not when a delivery failed): the last 60
runs and per run the changes of the comparison (kind, check id, severities, statuses,
the cleaned and redacted subject, counts, alert mark; at most 100 per run, the rest
is counted), nothing from evidence or summaries. A baseline run is recorded without
changes. The file follows the rules of the state file (real directory owned by root or
the running user, no group or other write, no symlink, regular file of the right owner
and mode, written to a temporary file and renamed) with a limit of 8 MiB: an ordinary
full history (60 runs of 100 changes) is about 1.7 MB, and when hostile subjects would take it past the limit
the oldest runs are dropped. It is a convenience, not a source of truth: a history that
cannot be read or written is a warning on stderr and does not change the exit code; an
unusable file is replaced by the next write. A `check` and a `report` that run at the
same moment are not coordinated, for `history.json` and for `state.json` alike (known
limit, like two `check` runs; there is no lock). `report --notify` narrows the window for
the one write it makes: it reads the state again right after a failed delivery (which
can be a minute after it first read it) and records the failure only if the snapshot and
the record are still the ones it started with, otherwise it only warns. What remains is
the time between that read and the rename.

## Output safety

Text in a report comes from probes and can carry what a local user chose (a
container name, a mount point, a file path) or a secret that someone put in a
command line. Every string of a report is cleaned before it is printed, whatever
the format:

1. secrets are replaced with `[REDACTED]` (see [Redaction](#redaction));
2. control characters are escaped into visible sequences: C0 controls and DEL
   (`\n`, `\r`, `\t`, `\x1b`, ...), C1 controls (`\u0085`), Unicode format
   characters including the bidirectional overrides, zero-width characters and
   the byte order mark, line and paragraph separators (`\u2028`), the right-to-left override (`\u202e`), characters
   that draw nothing and could make two names look alike (the Hangul and Khmer
   fillers such as `\u3164`, the combining grapheme joiner `\u034f`, the braille
   blank `\u2800`, the variation selectors `\ufe0f` and `\U000e0100`), private-use and
   unassigned code points, and bytes that are not valid UTF-8 (`\xff`), so an
   escape sequence cannot move the cursor, set a window title, forge a line,
   reverse the text or hide a difference between two names;
3. the result is cut at 2000 characters.

JSON is produced by `encoding/json` only. In Markdown, untrusted text appears
only in code spans whose fence is longer than any run of backticks in the text,
so it cannot open a link, an image, HTML or a heading; pipes are escaped in table
cells. In the text format every field is one line built by keepwatch.

## Redaction

Built-in patterns, applied before escaping, so a multi-line private key is still
one block when it is matched:

- PEM private key blocks (also one cut off before its end line);
- `name=value`, `name: value` and `"name": "value"` when the name ends in
  `password`, `passwd`, `passphrase`, `secret`, `token`, `api_key`, `access_key`,
  `private_key`, `secret_key` (also `auth_`, `signing_`, `encryption_` and
  `master_` plus `key`), `credential` or `credentials`, when it is `pass` or
  `pwd` or ends in them after a separator (`DB_PASS=`, `MYSQL_PWD=`), and
  `NAME_KEY=value` environment style (`token_file`, `passwordauthentication`
  and `bypass` are left alone). A quoted value may hold escaped quotes
  (`"a\"b"`) and a quote that is never closed runs to the end of the text;
- `--password value` style flags (also when a NUL byte, as in a command line
  read from `/proc`, separates the flag from its value; a flag counts only at the
  start or after a separator, so a word such as `prohibit-password` or
  `x-token` is not a flag), `Authorization: ...`
  values, `Cookie:` and `Set-Cookie:` values (the rest of the line), bearer
  tokens;
- URLs with credentials (`scheme://user:password@host`, `scheme://token@host`);
  the credentials end at the last `@` before the host, so a password with an `@`
  in it is covered;
- AWS access key ids, GitHub tokens (`ghp_`, `github_pat_`, ...), GitLab tokens
  (`glpat-`), API keys of the `sk-` family (`sk-...`, `sk-ant-...`), ntfy tokens
  (`tk_`), Slack tokens, Google API keys, Stripe keys and JSON web tokens.

Redaction is best effort: it knows the shapes above and cannot know a secret that
has none. The probes keep secrets out of evidence in the first place (they print
fingerprints and counts, never file contents).

Extra patterns go in the configuration:

```yaml
redact:
  patterns:
    - 'corp-[0-9]{4}'          # the whole match is replaced
    - 'session=([a-z0-9]+)'    # a capturing group: only the group is replaced
```

Patterns use RE2 syntax (no backtracking, no lookahead). They are compiled when
the configuration is loaded: at most 32 patterns of at most 256 bytes, none may
match the empty string or compile to a program of more than 1000 instructions
(a large repeat such as `(a|b|c|d|e){1000}` does; the text of a pattern is
short, but its cost is paid on every byte of every field that is shown), and a
bad one is a configuration error with file and line. Lists in `conf.d` files are appended to the main file's list. The redaction
function (`redact.Redactor.Clean`) is what the notification code uses as well.
