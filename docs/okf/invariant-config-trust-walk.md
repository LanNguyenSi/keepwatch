---
type: invariant
title: The loader walks the path before it reads a byte
description: How config.Load turns a path into trusted bytes, via the os.Root descent with its swap check, the sticky-ancestor exception, and the merge rule that refuses a later file changing a key's YAML kind.
tags: [config, trust, filesystem, invariants]
timestamp: 2026-11-13T13:11:15Z
sources:
  - internal/config/config.go
  - internal/config/walk.go
  - internal/config/secure.go
  - internal/config/merge.go
  - internal/config/secrets.go
  - internal/install/trustedpath.go
  - docs/configuration.md
---

`docs/configuration.md` states the rules an operator must satisfy; this note
is about the mechanism that makes them hold against a moving file system,
which no single file documents.

**One descent, one handle.** `config.Load` does not open the configuration by
path. It calls `openCheckedDir` on the main file's directory
(`internal/config/config.go:244#"openCheckedDir(mainDir"`), which opens `/`
with `os.Root` (`internal/config/walk.go:91#"os.OpenRoot("`) and walks
down one component at a time, each step an `OpenRoot` on the descriptor of
the component just checked. The return value is a handle on the checked
directory, and every file (`config.go` and `conf.d` entries alike) is opened
relative to it, never by path again
(`internal/config/secure.go:94-95#"never through the path again"`). `conf.d`
itself is reached by the same descent continued on the main directory's
handle (`internal/config/config.go:271#"descend(dirRoot"`), so a swapped-in
`conf.d` symlink is caught by the walk, dangling or not.

**Look, open, compare.** For each component the walk Lstats the name in the
parent, opens it, Stats the opened descriptor and requires `os.SameFile`
(`internal/config/walk.go:172#"os.SameFile(li, ni)"`). A component replaced
between the look and the open yields `dirSwapped`
(`internal/config/walk.go:22#"the component changed while it was being opened"`)
instead of being followed. The window this closes is exactly testable:
`afterLstat` is a production-nil hook that tests use to swap a component
precisely there (`internal/config/walk.go:124-126#"swap the component in that window"`).
The same compare-after-open applies to the files themselves, together with
type, size, permission and ownership checks made on the open fd rather than
on a path (`internal/config/secure.go:129#"os.SameFile(li, fi)"`). A token is
re-read through the identical path at send time
(`internal/config/secrets.go:12-20#"func (c *Config) ReadToken"`), so "checked
at load time" is not a one-time promise.

**The sticky exception, and its limit.** An ancestor may be group- or
other-writable only when it carries the sticky bit, and even then its owner
must still be root or the running user
(`internal/config/walk.go:206-207#"os.ModeSticky"`); the directory that holds
the files never gets this exception, nor does any component owned by nobody
trusted. Relative paths are resolved against the physical working directory
before the walk (`internal/config/walk.go:82-83#"syscall.Getwd()"`), and the
path is `Clean`ed first, so `dir/link/../keepwatch.yaml` never even looks at
`link`.

**Kind changes between files are errors, nulls are absences.** Merging a
`conf.d` file that sets a key some earlier file set to a different YAML kind
is refused with "<key> in <file:line> changes the type set in <file:line>"
(`internal/config/merge.go:68-70#"changes the type set in"`), because
validation runs on the merged tree and the replaced value would never be
looked at again. A null is deliberately not a kind here: a null from the
later file contributes nothing where the key exists
(`internal/config/merge.go:63-64#"nothing to contribute"`), while a null in
the earlier file does not block a later value. The asymmetry between the two
directions is the invariant, and only merged-tree reading of `merge.go` plus
`docs/configuration.md` together shows why both halves are needed.

**Not the whole trust story.** This walk is the loader's rule (owner: root or
the running user; sticky ancestors allowed). `install` and `doctor` judge the
same paths by a stricter rule with no sticky exception and root as the only
acceptable owner (`internal/install/trustedpath.go:38#"func TrustedPath"`,
`internal/install/trustedpath.go:23#"func RootOnly"`); see
[the placement invariant](invariant-placement.md) for that side and
`docs/install.md` for where a path may lie at all.
