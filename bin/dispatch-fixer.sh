#!/usr/bin/env bash
# Tell the fixer in the ops repository that an issue of ours needs an our-side fix (register
# row 76). A generic repository_dispatch: nothing here names what runs on the other side.
#
# Callers: dependabot-reviewer.yml after a HOLD (issue created/updated, check published) and
# hygiene.yml's drift dispatch on main. The issue is the record; the dispatch is best effort:
# a missing token (the App not installed on ops) or a failed call is a ::warning:: and exit 1,
# and every caller treats that as a warning, never as a failed hold. The fixer can always be
# dispatched by hand with the same payload.
#
# Usage: dispatch-fixer.sh <fix-held-bump|fix-required-check-drift> <issue-number> [pr-number]
# Env:   DISPATCH_TOKEN — an App installation token for the ops repository, contents: write only
#        (what POST /repos/{owner}/{repo}/dispatches needs); GITHUB_REPOSITORY — this repo.
set -uo pipefail
event="${1:-}"; issue="${2:-}"; pr="${3:-}"
warn() { echo "::warning::fixer dispatch ($event, issue #${issue:-?}): $* — the issue stands; dispatch by hand if needed"; exit 1; }
case "$event" in fix-held-bump|fix-required-check-drift) ;; *) warn "unknown event type" ;; esac
[[ "$issue" =~ ^[0-9]+$ ]] || warn "no issue number"
[ -z "$pr" ] || [[ "$pr" =~ ^[0-9]+$ ]] || warn "PR is not a number"
[ -n "${DISPATCH_TOKEN:-}" ] || warn "no token for the ops repository (is the App installed there?)"
if GH_TOKEN="$DISPATCH_TOKEN" gh api "repos/fosterstack/ops/dispatches" -f "event_type=$event" \
     -f "client_payload[issue]=$issue" -f "client_payload[pr]=$pr" \
     -f "client_payload[repo]=${GITHUB_REPOSITORY:-fosterstack/cache}" >/dev/null; then
  echo "fixer dispatched: $event, issue #$issue${pr:+, PR #$pr}"
else
  warn "the dispatch call failed"
fi
