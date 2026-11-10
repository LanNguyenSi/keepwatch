# The part of a report that normalisation must never change: what was
# decided (check ids, statuses, severities, kinds), what changed and whether
# it alerts, the counts and the exit code.
{
  results: [.results[] | [.check_id, .kind, .status, .severity]],
  changes: [.changes[] | [.kind, .check_id, .alert, .from, .to, .subject]],
  still_failing: .still_failing,
  still_warning: .still_warning,
  counts: .counts,
  exit_code: .exit_code,
  fail_on: .fail_on
}
