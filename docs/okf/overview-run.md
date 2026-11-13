---
type: overview
title: The life of one check run
description: The fixed order a `keepwatch check` moves through the packages, and what a failure at each stage deliberately leaves behind.
tags: [run-flow, state, notification, exit-codes]
timestamp: 2026-11-13T18:05:41Z
sources:
  - internal/cli/cli.go
  - internal/cli/check.go
  - internal/cli/notify.go
  - internal/cli/report.go
  - internal/engine/engine.go
  - internal/execx/execx.go
  - internal/diff/diff.go
  - internal/render/render.go
  - internal/redact/redact.go
  - internal/result/result.go
  - internal/result/evidenceset.go
  - internal/state/state.go
  - docs/running.md
---

The command line is a thin dispatcher (`internal/cli/cli.go:51#"func dispatch"`);
a whole run is assembled in one function (`internal/cli/check.go:76#"func runCheck"`).
What no single file states is why the stages come in this order: every
failure point is placed so that the stored state of the last run stays
trustworthy. The contract itself (flags, exit codes, comparison rules,
delivery) is `docs/running.md`; this note only maps it onto the code.

1. Configuration first, redactor before findings. `config.Load` runs
   (`internal/cli/check.go:111#"config.Load(cfgPath)"`), and the first thing
   built from it is the redactor: the built-in one prints the load errors
   themselves (`internal/cli/check.go:105#"red := redact.Default()"`), and it
   is replaced by the configured one before any probe starts
   (`internal/cli/check.go:122#"redact.New(cfg.Redact.Patterns)"`), so no
   finding can reach an output that the operator's extra patterns were not
   applied to. A `--notify` whose channel cannot even be built stops here,
   before any work.

2. Execution layer, then the plan. The program allowlist comes from the
   embedded catalog, never from the configuration
   (`internal/engine/engine.go:56#"func Programs"`); the runner is built from
   that list (`internal/cli/check.go:142#"execx.NewReal(engine.Programs(cat))"`)
   and handed to `engine.Prepare`, which validates configuration against
   catalog before any probe runs
   (`internal/cli/check.go:144#"engine.Prepare(cat, cfg"`). A configuration
   naming an unknown check id is therefore a broken run (exit 3), not a
   per-check error result.

3. Probes run in catalog order (`internal/cli/check.go:150#"results := plan.Run"`).
   A signal aborts the whole run on the spot: partial results are neither
   reported nor stored.

4. The comparison only sees snapshots. The exit code starts from this
   run's results alone (`internal/cli/check.go:163#"code := ExitCode"`) and
   is forced to 3 when the state could not be used
   (`internal/cli/check.go:211-213#"code = ExitInternal"`); a failed delivery
   later returns 4 instead (`internal/cli/check.go:306-308#"return ExitDelivery"`). This
   run's snapshot is built with the run's redactor as its only cleaner
   (`internal/cli/check.go:174#"build(results, now, red.Clean)"`); the state
   directory is opened (`internal/cli/check.go:180#"state.Open(cfg.StateDir"`),
   a snapshot that contradicts itself refuses the comparison
   (`internal/cli/check.go:184#"state.CheckConsistency(cur)"`), the old
   snapshot is loaded (`internal/cli/check.go:192#"store.Load()"`), and
   `diff.Compute` compares the two
   (`internal/cli/check.go:200#"diff.Compute(lr.State, cur)"`), by keys that
   are SHA-256 over the raw subjects (`internal/result/evidenceset.go:44#"func SubjectKey"`).
   The diff itself never feeds the exit code: the code says
   what is bad now, the diff says what changed, and only the second is worth
   a message.

5. Side effects, in the order that makes "never lost, possibly twice" true.
   The report is rendered into memory and written with one call
   (`internal/cli/check.go:242#"render.Render(&buf, format, in, red)"`,
   `internal/cli/check.go:245#"stdout.Write(buf.Bytes())"`); the notification
   goes out only after the report did
   (`internal/cli/check.go:253#"ntf.Send(e.ctx, toMessage(notice))"`); the
   state moves only after that
   (`internal/cli/check.go:294#"store.Save(toSave)"`), and the history only
   alongside a moved state
   (`internal/cli/check.go:303#"recordHistory(cfg.StateDir"`). Each failure
   leaves its own trace: an unwritable report leaves the state where it was
   and exits 3, so the next run says the same thing again; a failed delivery
   re-stores the previous snapshot with a delivery record instead of the new
   one; a save that fails is discovered after the report is out, so it can
   only be a stderr warning plus exit 3
   (`internal/cli/check.go:294-295#"the state could not be saved"`), which is why the `exit_code` printed
   inside a report can differ from the process exit code.

`report --weekly` takes a different path through the same packages: it runs
no probes at all and reads only what `check` stored
(`internal/cli/report.go:24#"func runReport"`), which is why a corrupt state
is a note there and never an abort.
