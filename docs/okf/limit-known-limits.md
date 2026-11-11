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
- **Most probes pre-clean their own text.** The single-transformation rule
  names four kinds that hand raw host text to the report and the state; the
  others already escape or shape their texts before `Clean` ever sees them
  (`internal/result/result.go:63-65#"the other probes still clean some of"`).
  The rule protects subjects, detail and summaries of those four kinds and
  every future probe that follows the same hand-on-raw discipline.
- **Redaction is shape-matching.** It knows the listed shapes and "cannot
  know a secret that has none" (`internal/redact/redact.go:19-20#"it cannot know a secret"`);
  extra patterns are RE2 only, bounded and checked at load time
  (`internal/redact/redact.go:55-59#"func ValidatePattern"`). The first line
  of defense stays the probes printing fingerprints and counts, never file
  contents.
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
