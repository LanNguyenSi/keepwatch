---
type: invariant
title: doctor judges the unit systemd runs, not the file install wrote
description: The file-equals-rendering comparison plus four properties asked of systemd per service, and the classification rule that tells a hostile drop-in from a host-wide one.
tags: [doctor, systemd, units, invariants]
timestamp: 2026-11-13T20:55:21Z
sources:
  - internal/doctor/doctor.go
  - internal/install/units.go
  - internal/install/install.go
  - docs/install.md
---

`docs/install.md` lists what `doctor` reports; the invariant underneath is
one sentence in the package comment: doctor must not be green when a check
would not work (`internal/doctor/doctor.go:10#"doctor must not be green"`).
For the units, that forces two independent judgments that neither file
contains alone.

**The file must be what install renders.** `unitDrift` re-renders the unit
from the values the file itself holds (program, `--config`, `--notify`,
`ReadWritePaths`) and compares line by line
(`internal/doctor/doctor.go:849-850#"RenderInstalled(u.name, u.content)"`,
`internal/install/units.go:627#"func FirstDifference"`), naming the first
difference. Re-rendering from the file's own values, rather than from the
configuration, is what keeps a hand-edited option visible: `Inspect` reads
only the last `ExecStart` and a few values, so without this comparison a
second `ExecStart` line (which a oneshot service also runs) or an added
option would pass every other check
(`internal/doctor/doctor.go:845-847#"a second ExecStart line"`,
`internal/install/units.go:561#"func Inspect"`).

**Systemd gets the last word.** For each service whose file exists, `doctor`
asks `systemctl show` for eight properties at once
(`internal/doctor/doctor.go:649#"NeedDaemonReload"`): if the question
itself fails, that is a problem, because then none of the answers below
exists (`internal/doctor/doctor.go:652#"cannot ask systemd about"`); a file
that is simply missing is the only quiet case. For a loaded unit,
`loadedUnit` (`internal/doctor/doctor.go:678#"func (d Deps) loadedUnit"`)
judges:

- `FragmentPath` must be the file in the unit directory, or the service runs
  as some other file says
  (`internal/doctor/doctor.go:679-681#"which is the file doctor judges"`);
- `NeedDaemonReload=yes` is a problem: systemd still runs the old merged
  unit, which `install` does not fix by re-verifying, since it reloads only
  when it writes (`internal/doctor/doctor.go:682-684#"has not reloaded"`,
  `internal/install/install.go:230-231#"daemon-reload"`);
- `LoadState` other than `loaded` is a problem naming the state, because the
  timer cannot start it
  (`internal/doctor/doctor.go:656-658#"systemd has not loaded"`);
- every drop-in `DropInPaths` reports is classified by one rule: a drop-in
  whose directory is named `service.d` holds for every service on the host
  and may come from the system, an image or a generator, so it is a warning;
  every other drop-in aims at this unit, systemd merges it, and `doctor`
  does not judge what it changes, so it is a problem
  (`internal/doctor/doctor.go:693#"Base(filepath.Dir(p))"`,
  `internal/doctor/doctor.go:699-704#"does not judge what they change"`).

The paths systemd prints are hostile bytes (a drop-in file name is arbitrary
bytes), so the property value is un-quoted exactly the way `systemctl`
quotes it (`internal/doctor/doctor.go:732#"func splitQuoted"`) and re-quoted
with Go escapes where a path holds a space, a quote, a backslash or an
unprintable byte, so the end of each path in the list stays visible
(`internal/doctor/doctor.go:834#"func listPaths"`). Control bytes are
neutralized once, for every finding, when the report is written
(`internal/doctor/doctor.go:140-147#"redact.Escape(f.Message)"`). The two functions
exist so that a crafted file name cannot forge a `doctor` line; the failure
mode of a non-UTF-8 name (systemd itself refuses to answer) is documented in
`docs/install.md`, and lands in the cannot-ask branch above.

**Which configuration to believe.** Without `--config`, doctor examines the
file named by an absolute `--config` in the `ExecStart` of the first of our
installed services that has one, and falls back to the default path
otherwise; a service
running with another file is a problem naming both files, and is judged by
its own file too (`internal/doctor/doctor.go:290-292#"func (d Deps) configPath"`,
`internal/doctor/doctor.go:596-597#"but this doctor run examined"`). The
reason spans files: every other area of the report speaks about the examined
configuration, so the units area must say which one the scheduled runs will
actually load.
