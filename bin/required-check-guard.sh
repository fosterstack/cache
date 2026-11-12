#!/usr/bin/env bash
# The required-check guard (register row 75; the #133 lesson). main's EFFECTIVE
# required-check set — contexts AND integration IDs — must contain every entry of
# .github/policy/required-checks.json. A listed check the ruleset lacks, or has under
# another integration ID, means the gate was weakened. A ruleset with MORE checks than the list
# passes: an extra required check only makes the gate stricter. Either way a human (ruleset,
# owner) or a PR (list) fixes it; nothing guesses.
#
# Callers:
#   dependabot-auto-merge.yml  — before arming auto-merge; fetches THIS script and the list
#                                from protected main via the API, never from a checkout
#   dependabot-reviewer.yml    — before it heals or reviews a Dependabot PR (the list from main)
#
# Usage: required-check-guard.sh <required-checks.json>
#   The ruleset side is read from `gh api repos/$GITHUB_REPOSITORY/rules/branches/main`
#   (effective rules aggregated across every ruleset), or from $GUARD_RULES_JSON (a file
#   holding that API response) when set — the offline test uses it.
# Exit: 0 every listed check is in the ruleset; 1 a listed check is missing (printed, one JSON entry per line);
#       2 could not read either side (never a pass).
set -uo pipefail
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
[ "$(jq length <<<"$actual")" -gt 0 ] || fail2 "main enforces NO required status checks"
echo "expected (${list}): $(jq -c '[.[].context]' <<<"$expected")"
echo "actual   (ruleset on main): $(jq -c '[.[].context]' <<<"$actual")"
missing=$(jq -c --argjson have "$actual" '.[] | select(. as $e | any($have[]; . == $e) | not)' <<<"$expected")
if [ -z "$missing" ]; then
  echo "required-check guard: match ($(jq length <<<"$expected") listed checks are in the ruleset, contexts and integration IDs)"
  exit 0
fi
echo "::error::required-check drift: the ruleset on main lacks a check listed in ${list} (context and integration ID must both match). Update the ruleset (owner) or the list (PR), whichever is wrong." >&2
echo "missing from the ruleset on main:"
echo "$missing"
exit 1
