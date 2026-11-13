---
type: invariant
title: One list, one rule for where the scheduled run's paths may lie
description: install and doctor share a single manifest of paths and a single placement check, and two tests pin the sandbox table that check uses to both the unit hardening and a measured real sandbox.
tags: [install, doctor, sandbox, systemd, invariants]
timestamp: 2026-11-12T14:30:28Z
sources:
  - internal/install/placement.go
  - internal/install/trustedpath.go
  - internal/install/units.go
  - internal/install/install.go
  - internal/install/stateprobe.go
  - internal/install/units_test.go
  - internal/config/walk.go
  - internal/install/measured_test.go
  - internal/doctor/doctor.go
  - docs/install.md
  - docs/development.md
---

The services are root processes in a sandbox, so a path they depend on must
be one the sandbox shows them and one nobody but root can redirect. `docs/install.md`
("Where the paths must lie") states the rule for operators; what belongs here
is that the rule exists exactly once in the code, and what pins its two
halves.

**One list.** `Manifest` builds every path the scheduled run depends on,
binary, configuration directory and file, `conf.d`, token file and
`state_dir`, directories before what is inside them
(`internal/install/placement.go:64#"func Manifest"`). `install` and `doctor`
feed it the same inputs; neither keeps a list of its own.

**One rule, two stages.** `CheckPlacement` asks, per entry, the sandbox table
first and the trusted-path walk second
(`internal/install/placement.go:160-163#"sandbox table comes first"`,
`internal/install/placement.go:186#"HiddenBy(e.Path, e.Role)"`), because for
`/var/run/x` "a reboot empties it" says more than "`/var/run` is a symlink".
The walk is `TrustedPath` (`internal/install/trustedpath.go:38#"func TrustedPath"`):
Lstat every component from `/`, no symlink, root-owned, never group- or
world-writable. Two cross-file contrasts give the rule its teeth:

- The loader accepts a sticky group-/other-writable ancestor
  (`internal/config/walk.go:206-207#"os.ModeSticky"`); the placement walk
  refuses any such component with no sticky exception and root as the only
  acceptable owner (`internal/install/trustedpath.go:80-81#"writable by group or other"`,
  `internal/install/trustedpath.go:23#"func RootOnly"`). A configuration that
  `check` loads happily is still refused by `install`, by design.
- `TrustedPath` needs no open-relative-to-descriptor descent, unlike the
  loader, and says why: a component only root can change cannot be swapped by
  anybody else between look and use
  (`internal/install/trustedpath.go:31#"The walk needs no openat-style descent"`).

`MayBeAbsent` entries (`conf.d`, `state_dir`) are checked through their
parent while missing (`internal/install/placement.go:190-196#"path.Dir(e.Path), KindDir"`),
and `install` re-runs the whole placement check right after creating
`state_dir`, before anything depends on it
(`internal/install/install.go:188-190#"CheckPlacement(d.FS, Manifest(o.paths()))"`).
Ordering within install is fixed: refusal before any write
(`internal/install/install.go:115#"CheckPlacement(fsys, Manifest(o.paths()))"`),
then the write probe
(`internal/install/install.go:201#"WriteProbe(d.FS, o.Spec.StateDir)"`),
which is the same one file `doctor` probes (`internal/install/stateprobe.go:9-10#"one file is created and removed"`),
so the two can never disagree about a read-only file system. `doctor` skips
the probe exactly when placement already blocked the directory, so it never
writes through a path it cannot vouch for
(`internal/doctor/doctor.go:232-234#"install.Blocks(main.placement"`), and it
judges an installed unit's `ExecStart` program with the same manifest
(`internal/doctor/doctor.go:582#"install.Paths{Binary: in.Binary}"`). Both
commands print the identical sentence, because both print
`PlacementProblem.Error()` verbatim
(`internal/install/placement.go:111#"install and doctor both print exactly"`).

**The table, pinned twice.** `sandboxPaths` maps each forbidden place to the
unit option that removes it, or to a reason no option owns (kernel file
systems, tmpfs a reboot empties)
(`internal/install/units.go:292#"var sandboxPaths"`); within the table the
most specific path wins (`internal/install/units.go:332-333#"longest path"`).
The table is text-matching, so it is only right because the walk refuses any
symlink in the path first. Two tests hold it honest from opposite sides:
`TestSandboxPathsFollowTheHardening` binds every entry to a line of
`serviceHardening` (the check and report services) or `watchHardening` (the
watch service, which shares the sandbox lines and is not installed yet) in
both directions (an option that hides paths needs an
entry, an entry needs an option that is actually set)
(`internal/install/units_test.go:522#"func TestSandboxPathsFollowTheHardening"`,
`internal/install/units.go:420#"serviceHardening = "`), and
`TestSandboxPathsFollowTheMeasuredSandbox` binds it to what a real sandbox
was measured to hide in `test/systemd/`, also both directions
(`internal/install/measured_test.go:114#"func TestSandboxPathsFollowTheMeasuredSandbox"`).
How that measurement is produced and refreshed is `docs/development.md`
("Sandbox measurement"); a new systemd that hides a new place fails CI before
the table gets to be wrong.
