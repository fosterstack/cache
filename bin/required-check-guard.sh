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
#   With the second file, its eight entries (the checks release admission requires but the ruleset does not
#   list) must also equal PINNED below, whole, and every entry of the first file (context, integration ID and
#   scope) must equal PINNED_SCOPES. ci.yml runs main's copy of this script over a pull request's files, so a
#   pull request cannot move the pins it is judged by.
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
{"context":"allowlist-pins-auditor","integration_id":15368,"scope":"push"},
{"context":"auditor-review-gate","integration_id":5054756,"scope":"pull_request"},
{"context":"coverage","integration_id":15368,"scope":"push"}]'
# The ruleset has no scope, so the scope of each ruleset check is pinned here and compared with the list: a pull
# request that moves a ruleset check between push and pull_request is refused.
PINNED_SCOPES='[{"context":"test","integration_id":15368,"scope":"push"},
{"context":"lint","integration_id":15368,"scope":"push"},
{"context":"gosec","integration_id":15368,"scope":"push"},
{"context":"govulncheck","integration_id":15368,"scope":"push"},
{"context":"analyze (go)","integration_id":15368,"scope":"push"},
{"context":"allowlist","integration_id":15368,"scope":"push"},
{"context":"dependency-review","integration_id":15368,"scope":"pull_request"},
{"context":"fips140-only","integration_id":15368,"scope":"push"},
{"context":"requirements","integration_id":15368,"scope":"push"},
{"context":"reproducibility","integration_id":15368,"scope":"push"},
{"context":"scan","integration_id":15368,"scope":"push"},
{"context":"pin-age","integration_id":15368,"scope":"pull_request"},
{"context":"vendor","integration_id":15368,"scope":"push"}]'
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
  list_scopes=$(jq -c '[.required_checks[] | {context, integration_id, scope}] | sort_by(.context)' "$list" 2>/dev/null) \
    || fail2 "${list} is missing or has no required_checks array"
  pinned_scopes=$(jq -c 'sort_by(.context)' <<<"$PINNED_SCOPES")
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
    echo "::error::release-only drift: ${2} is not the eight entries pinned in this script (a change needs the pin changed on main first)." >&2
    echo "diff (- pinned only, + ${2} only):"
    diff <(jq -cS '.[]' <<<"$PINNED") <(jq -cS '.[]' <<<"$release_only") | grep -E '^[<>]' | sed -e 's/^</-/' -e 's/^>/+/'
    status=1
  fi
  if [ "$(jq -cS . <<<"$list_scopes")" != "$(jq -cS . <<<"$pinned_scopes")" ]; then
    echo "::error::scope drift: context, integration ID or scope in ${list} not pinned; pin on main first." >&2
    echo "diff (- pinned only, + ${list} only):"
    diff <(jq -cS '.[]' <<<"$pinned_scopes") <(jq -cS '.[]' <<<"$list_scopes") | grep -E '^[<>]' | sed -e 's/^</-/' -e 's/^>/+/'
    status=1
  fi
fi
exit $status
