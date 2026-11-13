---
type: invariant
title: Host text is transformed once, at the last moment
description: Probes hand on the raw host text; exactly one transformation (redact, escape, cut) is applied, and only where the text leaves the program or is stored. Which consumers apply it, and which deliberately do not.
tags: [redaction, output-safety, state, invariants]
timestamp: 2026-11-13T18:05:41Z
sources:
  - internal/result/result.go
  - internal/probes/run.go
  - internal/probes/sshd.go
  - internal/probes/listeners.go
  - internal/execx/execx.go
  - internal/redact/redact.go
  - internal/render/view.go
  - internal/render/render.go
  - internal/render/notice.go
  - internal/render/digest.go
  - internal/state/state.go
  - internal/cli/check.go
  - internal/cli/notify.go
  - internal/history/history.go
  - internal/diff/diff.go
  - internal/doctor/doctor.go
  - docs/running.md
---

The rule is stated once, on the `Evidence` type: the subject is the raw
identifier and is never changed by a probe
(`internal/result/result.go:60#"is the raw identifier"`), and the one
transformation is made "where the text leaves the program or is stored"
(`internal/result/result.go:66#"The one change is made where the"`). No
other stage may rewrite host text, in either direction: not cleaning early is
load-bearing (a cut before redaction splits a secret so its pattern no longer
matches; escaping early removes the word boundary a pattern needs), and
cleaning the stored comparison keys is worse still, because the diff would
then compare display forms instead of what the check saw.

Every probe obeys it. No probe escapes, replaces or cuts characters of host
text: the only helper in `internal/probes/run.go` that touches such text is
`quoted`, which wraps it in double quotes and changes nothing inside (the
quotes are no delimiter a reader can rely on; `internal/probes/run.go:96#"func quoted"`).
`firstLine` takes the first line of a command's output to quote it, which is a
choice of which text to show, not a change to it. The error texts that quote a
line of command output (`... does not look like a ... listener: "line"`) use
`quoted` instead of `%q`, because `%q` escapes quotes and backslashes and so
turns `password="x"` into `password=\"x\"`, where the value pattern no longer
sees the quoted value. A cut in a probe is wrong whatever its length: a long
match in front of a secret shrinks when `Clean` redacts it, so a cut that was
far beyond what a report shows moves into the shown text and splits a secret.
How much host text a probe holds is therefore bounded where the output is
read: `execx` keeps at most `DefaultMaxOutput` per stream
(`internal/execx/execx.go:19#"DefaultMaxOutput"`), and the three runs that need
more ask for it by name (`internal/probes/listeners.go:23#"trustedMaxOutput"`,
the nft and the docker inspect limits). A note that would otherwise be copied
into every item of an outcome stands once in the summary (the failed `ss -p`
run of the listeners probe). The sshd probe keeps the case of a value for
display and compares a lower case copy
(`internal/probes/sshd.go:147#"raw := strings.Join"`), since the AWS key id
pattern is case sensitive.

The single transformation is `redact.Redactor.Clean`: redact, then escape,
then cut to `MaxFieldRunes` (`internal/redact/redact.go:250-252#"func (r *Redactor) Clean"`).
Its order is itself an invariant, documented above the package
(`internal/redact/redact.go:13#"The order matters"`), and the escaping
step is specified in `docs/running.md` under "Output safety"; this bundle
does not repeat it.

Every consumer of untrusted text applies that one function, each at its own
boundary:

- the report builds one cleaned view and writes all three formats from it
  (`internal/render/view.go:169#"return red.Clean(s)"`,
  `internal/render/render.go:13-14#"passes through red.Clean"`);
- the notification and the weekly digest run the same function through
  `cutRunes` (`internal/render/notice.go:79#"red.Clean(s)"`,
  `internal/render/digest.go:72#"red.Clean(s)"`);
- the state stores the key from the raw subject (`result.SubjectKey`,
  `internal/state/state.go:349#"result.SubjectKey(ev.Subject)"`) and the
  display subject only after `clean` (`internal/state/state.go:356#"truncate(clean(ev.Subject)"`);
  the function arrives as a parameter, and `check` passes its own redactor
  (`internal/cli/check.go:174#"build(results, now, red.Clean)"`), so a run
  with extra `redact.patterns` stores exactly what it would show;
- the history is built the same way
  (`internal/history/history.go:105#"func FromReport"`, called with
  `red.Clean` at `internal/cli/notify.go:114#"history.FromReport"`);
- a result's `Summary` and `Detail` leave the program only through the report
  view (`internal/render/view.go:211#"Summary: c(r.Summary)"`), which cleans
  them; the notification, the weekly report, the state and the history carry
  subjects, counts and statuses, never a summary or a detail.

Two consequences live between files and belong to no single package:

1. The comparison and the storage of the run share one redactor instance, so
   report, state and notifications can never disagree about how a subject
   looks; the diff, which only ever sees the raw-key snapshots
   (`internal/diff/diff.go:169#"func Compute"`), cannot be poisoned by a
   display form at all.
2. `doctor` is deliberately outside this system. It prints host and systemd
   paths that never passed through a probe. Its output is escaped once, in
   `Report.Write` (`redact.Escape`, `internal/doctor/doctor.go:140-147#"redact.Escape(f.Message)"`),
   and `listPaths` stays only as the list delimiter
   (`internal/doctor/doctor.go:834#"func listPaths"`). It prints only
   `scheme://host` of a notification URL because "doctor's output does not go
   through the redactor" (`internal/doctor/doctor.go:913-914#"does not go through the redactor"`).
   Anything added to a doctor message must therefore stay free of secret
   material by construction, the way `origin` keeps the user info of a URL
   out of it.
