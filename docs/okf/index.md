# keepwatch knowledge bundle

## Overview

- [The life of one check run](overview-run.md) - the fixed order a `check` moves through the packages, and what a failure at each stage leaves behind.

## Modules

- [execx, the only seam that starts a program](module-execx.md) - the fixed program table, the self-copied pipes, and the two ways output arrives incomplete.

## Invariants

- [Host text is transformed once, at the last moment](invariant-single-transformation.md) - probes keep the raw subject; `redact.Clean` runs only at the output and storage boundaries.
- [The loader walks the path before it reads a byte](invariant-config-trust-walk.md) - the `os.Root` descent, the swap check, the sticky exception, and the kind-change merge rule.
- [One list, one rule for where the scheduled run's paths may lie](invariant-placement.md) - the manifest, the sandbox table, and the tests that pin both.
- [doctor judges the unit systemd runs](invariant-doctor-effective-unit.md) - the rendering comparison and the four questions asked of systemd per service.

## Limits

- [What the guarantees do not cover](limit-known-limits.md) - uncoordinated runs, unchecked ACLs and mounts, and the redactor's horizon.
