---
type: module
title: execx, the only seam that starts a program
description: The execution layer's contract as its callers must know it - fixed program table, its own pipe copies, the two incomplete-output signals, the process-group kill that no os/exec default gives, and the streaming sibling of Run for long-lived programs.
tags: [execx, probes, sandbox]
timestamp: 2026-11-13T18:05:41Z
sources:
  - internal/execx/execx.go
  - internal/execx/real.go
  - internal/execx/kill_unix.go
  - internal/execx/stream.go
  - internal/engine/engine.go
  - internal/probes/probes.go
  - internal/doctor/doctor.go
---

Every program keepwatch starts goes through `execx` and nothing else: the
package is the single seam, never invokes a shell, and only runs allowlisted
programs (`internal/execx/execx.go:1#"single seam"`); no production
package outside `execx` imports `os/exec`. The probe rule that rests on this is
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
`internal/doctor/doctor.go:66#"the execution layer would run"`).

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
whole group (`internal/execx/kill_unix.go:11-12#"kills the whole group"`,
`internal/execx/kill_unix.go:22-23#"never outlive the call"`), and the same
duration bounds `os/exec`'s own `WaitDelay` (`internal/execx/kill_unix.go:19#"cmd.WaitDelay = waitDelay"`).
A timeout is distinguishable from parent cancellation: hitting `Opts.Timeout`
returns `ErrTimeout`, while a parent context ending first returns the
context's error, never `ErrTimeout` (`internal/execx/real.go:257-258#"never ErrTimeout"`).
`ErrNotFound` means "not installed" (the probe must skip), the typed errors
distinguish it from `ErrNotAllowed`, which means "refused" and must produce
an error result, never a skip (`internal/execx/execx.go:26-27#"ErrNotAllowed"`;
the skip rule is the package comment of `internal/probes/probes.go`).

**Stream is Run's sibling for a program that does not end.** `Streamer`
(`internal/execx/execx.go:94#"type Streamer interface"`) hands the caller a
long-lived program's stdout line by line, on the caller's goroutine, while
`Run` and `Runner` stay as they were. `Real.Stream` goes through the same
`resolve` as `Run`, so the allowlist, the trusted directories and the typed
errors are identical (`internal/execx/stream.go:92#"r.resolve(argv[0])"`),
and it uses the same minimal environment, its own pipes and the same
process-group setup (`internal/execx/stream.go:121#"configureKill(cmd)"`). It
is not a way around the allowlist: a program that is not in the table cannot
be streamed either. What differs is the bound. There is no default timeout,
because a follow stream is meant to run until the caller cancels it; a total
`Timeout` (`ErrTimeout`) and an `IdleTimeout` (`ErrIdleTimeout`) exist but
only when asked for (`internal/execx/execx.go:114#"IdleTimeout, when positive"`).
The idle limit measures waiting for the program, not time inside the
callback, and it stays armed until the program has exited, also after it
closed its stdout. Memory is bounded per line, not per run: a line longer than
`MaxLine` (`DefaultMaxLine`, 64 KiB) is never delivered, not even cut, it is
dropped and counted in `StreamResult.DroppedLines` and the stream goes on
(`internal/execx/stream.go:396#"if len(acc)+len(data) > max"`). stderr is
drained concurrently into a buffer capped like `Run`'s output, so a chatty
child cannot block on a full pipe
(`internal/execx/stream.go:155#"errC := startCopy(errR, &stderr)"`).
The stream ends when the context ends (the context's error is returned, never
`ErrTimeout`), when the callback returns an error (that error is returned),
on an opt-in timeout, or after the program exited by itself. One deferred
cleanup then SIGKILLs the process group, once, and joins the reader, the
waiter and the stderr copy, also when the callback panics and the caller
recovers (`internal/execx/stream.go:179#"cleanup := func() {"`). Cancelling
kills only the direct child (`internal/execx/stream.go:124#"cmd.Cancel = func() error"`),
so the cleanup's signal is the only group signal. On an abort before the exit
was seen it is sent before the cleanup waits for the child, which as a rule is
not reaped yet; once the exit was seen, on the self-exit path and on an abort
that comes after it, the child is already reaped, as in `Run`. The kill
reaches everything left in the child's process group; a grandchild that
started a new session is outside it (see the known limit).
After the program exited, the stream keeps reading stdout while a leftover
child holds the pipe, but only inside a budget: it ends with
`StreamResult.IOIncomplete` (and `ErrIOTimeout` after a successful exit) when
the wall time since the exit minus the time spent inside the callback since
then reaches the grace period of `Run`, the same variable
(`internal/execx/stream.go:260#"left := waitDelay"`), or when more than
`postExitMaxBytes` bytes were read from the pipe after the exit was seen
(`internal/execx/stream.go:237#"rd.postExit.Load() > postExitMaxBytes"`).
That bound is what a linux pipe of the default size holds, 16 pages, which is
64 KiB with 4 KiB pages (`internal/execx/stream.go:28#"var postExitMaxBytes"`);
on a darwin host with 16 KiB pages it is four times what a pipe holds there.
Only reads that begin after the exit was seen count
(`internal/execx/stream.go:369#"counts := p.lr.exitSeen.Load()"`), so a long
line that was read while the program ran never does, however late the loop
gets to it. Lines do not restart the budget. What the program itself left in
such a pipe is within the bound and still reaches even a slow callback in
full; a program that enlarged its own stdout pipe can lose the rest of a
larger backlog, flagged the same way. The byte bound is a volume, not a time: a leftover that floods
stdout with short lines is cut after that many bytes, and a slow callback is
still called once for every line in them, so a caller that needs a time bound
sets `Timeout`.
Callers of a stream that ended by an error other
than their own must treat the lines they got as a prefix, not as a complete
log. Nothing in the engine or the probes streams yet: the check allowlist from
`engine.Programs` is untouched, and a streamed program such as `journalctl`
joins a runner only by being named in the allowlist of the runner that streams
it.
