---
type: module
title: execx, the only seam that starts a program
description: The execution layer's contract as its callers must know it - fixed program table, its own pipe copies, the two incomplete-output signals, and the process-group kill that no os/exec default gives.
tags: [execx, probes, sandbox]
timestamp: 2026-11-11T10:18:36Z
sources:
  - internal/execx/execx.go
  - internal/execx/real.go
  - internal/execx/kill_unix.go
  - internal/engine/engine.go
  - internal/probes/probes.go
  - internal/doctor/doctor.go
---

Every program keepwatch starts goes through `execx` and nothing else: the
package is the single seam, never invokes a shell, and only runs allowlisted
programs (`internal/execx/execx.go:1#"single seam"`); `os/exec` is
imported nowhere else in the tree. The probe rule that rests on this is
stated in `internal/probes/probes.go` (read-only probes, programs only
through the injected Runner); what the engine and `doctor` must get right
when they build and question that seam is what this note collects.

**The table is fixed before any call.** Bare names resolve only against
`SearchPath`, and the inherited `PATH` is deliberately ignored
(`internal/execx/execx.go:20-21#"The inherited PATH is deliberately ignored"`).
The allowlist itself is derived from the catalog's kinds
(`internal/engine/engine.go:54-56#"func Programs"`), never from the
configuration, and children get a minimal fixed environment, not the
service's (`internal/execx/real.go:18#"var DefaultEnv = "`).
`resolve`'s invariant (`internal/execx/real.go:134#"the executed file's symlink-resolved location"`):
what runs lies directly in a trusted directory, or is a pinned extra; the
target's base name or the given base name must be allowlisted, which is what
lets a multi-call binary like busybox serve as `ss`
(`internal/execx/real.go:158#"multi-call"`). `doctor` calls the
same `resolve` through `Resolve` so that its program answers are exactly the
checks' (`internal/execx/real.go:207-210#"its answer is the one the"`,
`internal/doctor/doctor.go:65#"the execution layer would run"`).

**Output is copied by execx, on purpose.** `Run` wires the child's stdout
and stderr into pipes it creates and drains itself
(`internal/execx/real.go:301#"os.Pipe()"`), because `os/exec` reports a
cut pipe only after a successful exit, and a cut after a failing exit would
go unnoticed (`internal/execx/real.go:270-271#"os/exec reports a cut pipe"`).
Readers stop accepting bytes past `MaxOutput` without ever blocking the
child (`internal/execx/real.go:403-404#"so the child never blocks"`).

**Two incompleteness signals, and callers must read both.** If the pipes are
still open a grace period after the child exited (a grandchild holds them),
the copies are cut and `Result.IOIncomplete` is set for every exit status;
the output then holds what was read and may miss the tail
(`internal/execx/execx.go:53#"IOIncomplete is set"`,
`internal/execx/real.go:377-378#"closes the read ends"`). On a *successful*
exit the same condition also returns `ErrIOTimeout`
(`internal/execx/execx.go:31-35#"output pipes held open"`,
`internal/execx/real.go:340-342#"ErrIOTimeout"`); on a non-zero exit the
status comes back with a nil error, so a caller that parses output after a
failure must inspect `IOIncomplete` itself
(`internal/execx/real.go:266-268#"must check IOIncomplete"`). The grace
period is one variable (`internal/execx/execx.go:12-13#"A variable so tests can shorten it"`).

**Nothing outlives the call.** On unix the child gets its own process group;
both the timeout/cancel path and the path after `Run` returns SIGKILL the
whole group (`internal/execx/kill_unix.go:11-20#"kills the whole group"`,
`internal/execx/kill_unix.go:22-30#"never outlive the call"`), and the same
duration bounds `os/exec`'s own `WaitDelay` (`internal/execx/kill_unix.go:19`).
A timeout is distinguishable from parent cancellation: hitting `Opts.Timeout`
returns `ErrTimeout`, while a parent context ending first returns the
context's error, never `ErrTimeout` (`internal/execx/real.go:257-258#"never ErrTimeout"`).
`ErrNotFound` means "not installed" (the probe must skip), the typed errors
distinguish it from `ErrNotAllowed`, which means "refused" and must produce
an error result, never a skip (`internal/execx/execx.go:26-27#"ErrNotAllowed"`;
the skip rule is the package comment of `internal/probes/probes.go`).
