# Log

<!-- Add new entries at the top, newest first. -->

## 2026-11-12

- Re-verified `invariant-doctor-effective-unit.md`, `invariant-placement.md`,
  `invariant-single-transformation.md`, `limit-known-limits.md` and
  `module-execx.md` after doctor started to escape every printed line once in
  `Report.Write` and `disk.usage` gained the sibling-mount fallback. The
  doctor claims about quoting were corrected (escaping is done once at the
  output, `listPaths` only keeps the list delimiters visible), and the
  citations into `internal/doctor/doctor.go` moved by a few lines and were
  checked by script again (file, line range, anchor inside the range). No doc
  cites `disk.go` or `docs/checks.md`.
- Re-verified `invariant-single-transformation.md`, `limit-known-limits.md`
  and `overview-run.md` after probes stopped cutting, escaping and replacing
  host text, and the redactor learned the shapes behind a separator, glued to
  text or behind a terminal color sequence. The invariant now covers every
  probe (not four), the limits page lists what the redactor still leaves out
  (each pinned by a test), and the overview needed no change. The citations
  into `.go` files were checked by script again.

## 2026-11-11

- Created the bundle: one overview, one module note, four invariants and one
  limits page, all grounded at commit 8cf6698. okf-kit checked structure and
  staleness; it does not resolve citations into `.go` files, so those were
  checked by script (file, line range, anchor inside the range). The bundle only adds what lies
  between the files; the reference documentation in `docs/` is pointed at and
  not duplicated.
