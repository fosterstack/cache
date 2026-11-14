#!/usr/bin/env bash
# The required-check guard (register row 75; the #133 lesson). main's EFFECTIVE
# required-check set — contexts AND integration IDs — must equal the list in
# .github/policy/required-checks.json, exactly, in both directions. A missing
# check means the gate was weakened; an extra one means the list is stale.
# Either way a human (ruleset, owner) or a PR (list) fixes it; nothing guesses.
#
# Callers:
#   ci.yml                — every PR and every push to main (drift is red the day it happens)
#   dependabot-auto-merge.yml  — before arming auto-merge; fetches THIS script and the list
#                                from protected main via the API, never from a checkout
#
# Usage: required-check-guard.sh <required-checks.json> [<release-only-checks.json>]
#   With the second file, its seven entries (the checks release admission requires but the ruleset does not
#   list) must also equal PINNED below, whole. ci.yml runs main's copy of this script over a pull request's
#   files, so a pull request cannot move the pin it is judged by.
#   The ruleset side is read from `gh api repos/$GITHUB_REPOSITORY/rules/branches/main`
#   (effective rules aggregated across every ruleset), or from $GUARD_RULES_JSON (a file
#   holding that API response) when set — the offline test uses it.
# Exit: 0 match; 1 drift (the diff is printed, one JSON entry per line, `-` ruleset only,
#       `+` list only); 2 could not read either side (never a pass).
set -uo pipefail
PINNED='[{"context":"acceptance-gradle","integration_id":15368,"scope":"push"},
{"context":"acceptance-maven (1.2.0)","integration_id":15368,"scope":"push"},
{"context":"acceptance-maven (1.2.3)","integration_id":15368,"scope":"push"},
{"context":"allowlist-chain","integration_id":15368,"scope":"push"},
{"context":"allowlist-persona","integration_id":15368,"scope":"push"},
{"context":"auditor-review-gate","integration_id":5054756,"scope":"pull_request"},
{"context":"coverage","integration_id":15368,"scope":"push"}]'
list="${1:?usage: required-check-guard.sh <required-checks.json>}"

fail2() { echo "::error::required-check guard: $* — could not compare, not a pass" >&2; exit 2; }

if [ -n "${GUARD_RULES_JSON:-}" ]; then
  rules=$(cat "$GUARD_RULES_JSON" 2>/dev/null) || fail2 "cannot read ${GUARD_RULES_JSON}"
else
  rules=$(gh api "repos/${GITHUB_REPOSITORY:?GITHUB_REPOSITORY unset}/rules/branches/main" 2>&1) \
    || fail2 "cannot read main's rules: ${rules}"
fi
actual=$(jq -c '[.[] | select(.type=="required_status_checks")
                     | .parameters.required_status_checks[]
                     | {context, integration_id}] | sort_by(.context)' <<<"$rules" 2>/dev/null) \
  || fail2 "main's rules are not the expected JSON"
expected=$(jq -c '[.required_checks[] | {context, integration_id}] | sort_by(.context)' "$list" 2>/dev/null) \
  || fail2 "${list} is missing or has no required_checks array"
if [ -n "${2:-}" ]; then
  release_only=$(jq -c '[.required_checks[] | {context, integration_id, scope}] | sort_by(.context)' "$2" 2>/dev/null) \
    || fail2 "release-only list ${2} is missing or has no required_checks array"
fi
[ "$(jq length <<<"$actual")" -gt 0 ] || fail2 "main enforces NO required status checks"

echo "expected (${list}): $(jq -c '[.[].context]' <<<"$expected")"
echo "actual   (ruleset on main): $(jq -c '[.[].context]' <<<"$actual")"
status=0
if [ "$(jq -cS . <<<"$actual")" = "$(jq -cS . <<<"$expected")" ]; then
  echo "required-check guard: match ($(jq length <<<"$actual") checks, contexts and integration IDs)"
else
  echo "::error::required-check drift: the ruleset on main and ${list} differ (contexts and integration IDs must both match, exactly). Update the ruleset (owner) or the list (PR), whichever is wrong." >&2
  echo "diff (- ruleset on main only, + list only):"
  diff <(jq -cS '.[]' <<<"$actual") <(jq -cS '.[]' <<<"$expected") | grep -E '^[<>]' | sed -e 's/^</-/' -e 's/^>/+/'
  status=1
fi
if [ -n "${2:-}" ]; then
  if [ "$(jq -cS . <<<"$release_only")" = "$(jq -cS . <<<"$PINNED")" ]; then
    echo "required-check guard: release-only list match ($(jq length <<<"$PINNED") entries, whole)"
  else
    echo "::error::release-only drift: ${2} is not the seven entries pinned in this script (a change needs the pin changed on main first)." >&2
    echo "diff (- pinned only, + ${2} only):"
    diff <(jq -cS '.[]' <<<"$PINNED") <(jq -cS '.[]' <<<"$release_only") | grep -E '^[<>]' | sed -e 's/^</-/' -e 's/^>/+/'
    status=1
  fi
fi
exit $status
