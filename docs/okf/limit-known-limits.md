---
type: limit
title: What the guarantees do not cover
description: The known limits of the trust, redaction and coordination machinery, collected with the code or reference line that states each, so a reviewer can tell a gap from a promise.
tags: [limits, trust, redaction, concurrency]
timestamp: 2026-11-11T10:18:36Z
sources:
  - internal/cli/report.go
  - internal/config/walk.go
  - internal/install/trustedpath.go
  - internal/result/result.go
  - internal/redact/redact.go
  - internal/execx/execx.go
  - internal/probes/sshd.go
  - internal/probes/listeners.go
  - internal/execx/real.go
  - internal/doctor/doctor.go
  - internal/history/history.go
  - docs/running.md
  - docs/install.md
---

Each limit below is stated somewhere; what is missing from any single file is
that they compose: a reviewer reasoning about one guarantee should know which
adjacent ones stop short.

- **No lock, anywhere.** `check`, `report --weekly` and their files
  (`state.json`, `history.json`) are not coordinated
  (`docs/running.md:356-357#"not coordinated"`). The one place the code
  narrows the window is the weekly delivery failure record: the state is read
  again immediately before the write and the record lands only if nothing
  committed in between, leaving the read-to-rename gap
  (`internal/cli/report.go:139-140#"there is no lock"`).
- **Permissions are mode bits and owner, nothing more.** Neither the loader
  walk (`internal/config/walk.go:78#"POSIX ACLs and file capabilities are not examined"`)
  nor the placement walk (`internal/install/trustedpath.go:36#"POSIX ACLs and file capabilities are not examined"`)
  reads ACLs, file capabilities or the mount table, so a POSIX ACL or a
  writable bind mount over a checked directory passes
  (`docs/install.md:137#"bind mounts over a checked directory"`).
- **Trust is a photograph.** The placement walk says who can change a path
  now; it notices no later change, and a failing unit tells nobody until
  `doctor` or the next run looks   (`docs/install.md:139#"does not notice a change later"`).
- **`check` alone trusts fewer ancestors than `install` and `doctor`.** A
  manual run judges `state_dir` itself, not its ancestors; the two commands
  that plan the scheduled root runs do walk them
  (`docs/running.md:154-155#"not examined by"`). A hostile ancestor makes the
  manual and the scheduled answer differ, on purpose.
- **A probe's text is as long as the output it came from.** No probe cuts
  host text, so a summary or detail can hold up to the stream limit of the
  command it was taken from (1 MiB, or the larger limit a run asks for by
  name: `internal/execx/execx.go:19#"DefaultMaxOutput"`,
  `internal/probes/listeners.go:23#"trustedMaxOutput"`) until `Clean` cuts it
  at `MaxFieldRunes`. That is memory held for one run, not output.
- **Two parsers still tidy white space.** The sshd probe collapses the white
  space of a value (`internal/probes/sshd.go:147#"raw := strings.Join"`) and the
  listeners probe does the same for the process column of `ss -p`
  (`internal/probes/listeners.go:365#"strings.Join(f[5:]"`): a run of white
  space, including characters such as U+000B that the redactor does not count
  as white space, becomes one space before the text is shown.
- **Redaction is shape-matching.** It knows the listed shapes and "cannot
  know a secret that has none" (`internal/redact/redact.go:19-20#"it cannot know a secret"`);
  extra patterns are RE2 only, bounded and checked at load time
  (`internal/redact/redact.go:55-59#"func ValidatePattern"`). The first line
  of defense stays the probes printing fingerprints and counts, never file
  contents. The shapes it leaves out on purpose are pinned by
  `TestShapesLeftOutOnPurpose` in `internal/redact/redact_test.go`, because
  each would cost false positives in text that is no secret:
  - a token with a short or common prefix (AWS key id, `sk-`, ntfy `tk_`,
    Google, Stripe, JWT) glued to a letter, digit or underscore in front of it
    (the start rule is `internal/redact/redact.go:111#"const tokenStart"`; GitHub,
    GitLab and Slack tokens, and the scheme of a URL, are found after any
    character, and every token is found behind a terminal control sequence);
  - a token directly followed by a word character or an underscore, since the
    pattern ends at a word boundary;
  - URL user info behind host text and a separator
    (`tcp://host, user:password@host`) only in the form `user:password`:
    a token alone (`tcp://host, token@host`) cannot be told from a list of
    addresses, and user info behind two separators, a newline or a NUL byte is
    not looked for (the URL rule is
    `internal/redact/redact.go:118#"scheme://user:password@host and scheme://token@host"`);
  - a secret with no shape of its own, as before.
- **A check-then-exec gap remains.** Trust in execx rests on the trusted
  directories being root-owned; Go has no `fexecve`, so anyone who could
  write into those directories still races the final exec
  (`internal/execx/real.go:162-163#"Go has no fexecve"`).
- **Drop-ins are counted, not read.** `doctor` judges a drop-in's existence
  and location, never its content, and says so in the finding
  (`docs/install.md:371#"judged by its existence"`,
  `internal/doctor/doctor.go:694-699#"does not judge what they change"`).
- **History degrades under pressure.** `history.json` is capped; when
  unusually long subjects push it past its limit, the oldest runs are
  dropped before anything is refused (`internal/history/history.go:352-353#"until the file fits"`).
  It is a convenience for the weekly report, not a source of truth.
- **This bundle's own citations into Go code are not checked by CI.**
  okf-kit verifies structure and staleness, but its citation check skips
  `.go` files, so a moved line or anchor there goes unnoticed; re-check the
  cited ranges by hand when you edit a doc.
