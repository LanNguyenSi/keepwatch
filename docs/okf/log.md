# Log

<!-- Add new entries at the top, newest first. -->

## 2026-11-24

- Re-verified and re-stamped `invariant-single-transformation.md`,
  `limit-known-limits.md` and `overview-run.md` after `Clean` became a fixed
  point (`internal/redact/redact.go`: a second `Redact` over the escaped text;
  `FuzzCleanIdempotent`). `invariant-single-transformation.md` was rewritten
  with that change (order redact, escape, redact, cut; the second posture
  cleaning is a no-op) and its anchors `redact.go:250-252` and `redact.go:13`
  still resolve. `limit-known-limits.md` (cut at `MaxFieldRunes`, redaction
  is shape-matching) and `overview-run.md` (`red.Clean` as the single
  transformation) stay true. Check: `npx -y okf-kit@0.22.0 check
  --require-anchors docs/okf`.

## 2026-11-22

- Re-verified `invariant-single-transformation.md`, `limit-known-limits.md` and
  `overview-run.md` after the notification retry change (`notify.Error` carries
  `Retry-After`, the watch daemon paces failed retries by it) changed
  `docs/running.md` (the HTTP client paragraph). None of the three describes
  notification retries; the "not coordinated" citation in the known limits was
  already moved to lines 360-361 and still says so. The older `docs/install.md`
  staleness on `limit-known-limits.md` also holds up: the only change since the
  last stamp was the version in the install example, and the cited lines 137,
  139 and 371 still say what the limits claim.

## 2026-11-13

- Re-stamped `invariant-doctor-effective-unit.md`, `invariant-placement.md` and
  `limit-known-limits.md` after the v0.2.0 release commit: `docs/install.md`
  changed only in the version of the install example; every cited line
  (137, 139, 371) is unchanged and still says what the docs claim.
- Re-verified `module-execx.md` and `limit-known-limits.md` after the line
  reader buffer size in `stream.go` became a named constant; no cited line
  moved and no claim changed.
- Re-verified `module-execx.md`, `limit-known-limits.md`,
  `invariant-single-transformation.md` and `overview-run.md` after
  `internal/execx` gained `Stream`: line-by-line delivery with a per-line cap,
  idle and total timeouts, a post-exit budget that counts only bytes read
  after the exit was seen (bounded by a pipe's worth, 16 pages) and only time
  outside the callback, and a single process-group signal. The cited lines
  in `stream.go` and `execx.go` were checked against the code; the new pipe
  size limit is recorded in the known limits.
- Re-verified `invariant-config-trust-walk.md` after `internal/config` gained
  the strictly validated `watch:` section and `docs/configuration.md` its
  reference. The section has no path keys, so the trust walk is unchanged;
  the cited lines in `config.go` (`openCheckedDir(mainDir`, `descend(dirRoot`)
  still match.
- Re-verified `invariant-placement.md` and `invariant-doctor-effective-unit.md`
  after `internal/install/units.go` split the shared hardening text into the
  sandbox part and per-unit process and resource lines and gained the watch
  service unit renderer. The claims hold: the sandbox table is still coupled
  to every hardening option through the classification test, which now runs
  over the watch unit too; the cited line ranges moved and were re-pinned.

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
