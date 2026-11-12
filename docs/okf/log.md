# Log

<!-- Add new entries at the top, newest first. -->

## 2026-11-12

- okf-kit pin moved from 0.20.0 to 0.21.0 in `.github/workflows/okf-staleness.yml`. Measured on this bundle: 0.20.0 reports no findings with and without `--require-anchors`, because it does not collect citations into `.go` files at all; 0.21.0 resolves the bundle's 138 Go citations (no missing file, no range past the end) and, with `--require-anchors`, reported 13 anchor-position warnings (11 anchors not on the last line of their range, 2 anchors occurring twice in one range). Those 13 citations were narrowed so the anchor sits on the range's last line (one moved to a unique anchor); after that both modes report no findings. The workflow's Go deviation comment and the known-limits entry saying Go citations are not checked are removed, since they no longer hold.
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
