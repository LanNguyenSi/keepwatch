# The part of a report that normalisation must never change: what was
# decided (check ids, statuses, severities, kinds), what changed and whether
# it alerts, the counts and the exit code.
# The summary without the words that normalisation may rewrite: tokens with a
# digit (versions, counts, percentages, package names such as fail2ban) and
# placeholders such as <version>. What is left is the wording, so a rewrite
# of summaries beyond those tokens is caught.
def summary_class:
  [.summary | split(" ")[] | select((test("[0-9]") | not) and (test("^<.*>$") | not))] | join(" ");

{
  results: [.results[] | [.check_id, .kind, .status, .severity, summary_class]],
  changes: [.changes[] | [.kind, .check_id, .alert, .from, .to, .subject]],
  still_failing: .still_failing,
  still_warning: .still_warning,
  counts: .counts,
  exit_code: .exit_code,
  fail_on: .fail_on
}
