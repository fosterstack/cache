#!/usr/bin/env bash
# Regression tests for bin/check-file-allowlist.sh — in particular the branch
# scoping of the daily CVE auditor's suppression outputs (.snyk,
# osv-scanner.toml, .auditor/accepted-items.json): allowed only on the auditor/
# lane and on main, blocked on any other branch, and never a hole through which
# private-side content can reach this PUBLIC repo.
set -uo pipefail
cd "$(dirname "$0")/.."
SCRIPT=./bin/check-file-allowlist.sh

pass=0; fail=0
# run <expect pass|fail> <branch-env> <description> <paths...>
run() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="$ref" GITHUB_REF_NAME="" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}
# same, but drive GITHUB_REF_NAME (the push path) instead of a PR head ref
run_ref() {
  local expect="$1"; local ref="$2"; local desc="$3"; shift 3
  local out rc
  out="$(printf '%s\n' "$@" | GITHUB_HEAD_REF="" GITHUB_REF_NAME="$ref" "$SCRIPT" 2>&1)"; rc=$?
  if { [ "$expect" = pass ] && [ "$rc" -eq 0 ]; } || { [ "$expect" = fail ] && [ "$rc" -ne 0 ]; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (expected $expect, rc=$rc)"; echo "$out" | sed 's/^/      /'; fail=$((fail+1))
  fi
}

SUPP=(".snyk" "osv-scanner.toml" ".auditor/accepted-items.json"
      # REQ-AUD-16: the generated knowledge doc (AC3) and merge-gated proposals (AC4) the auditor
      # carries in its own suppression PR.
      ".auditor/knowledge.md" ".auditor/proposals/adjudicator-proposals.json")

# The auditor lane may introduce/change its suppression outputs.
run pass "auditor/2026-09-24-abc123"      "auditor/ PR head: suppression outputs allowed"      "${SUPP[@]}"
run pass "auditor/proof-2026-09-24-abc12" "auditor/ proof PR head: suppression outputs allowed" "${SUPP[@]}"
# The merged state on main keeps them (scanners read them; release-authz reads the inventory).
run_ref pass "main" "push to main: suppression outputs allowed" "${SUPP[@]}"
# No other branch may add or edit a suppression (can't slip one past a scanner via a feature PR).
run fail "feature/x"        "feature PR head: suppression outputs blocked"      "${SUPP[@]}"
run fail "renovate/deps"    "bot PR head: suppression outputs blocked"          "${SUPP[@]}"
run fail "auditorX/nope"    "look-alike prefix (not auditor/): blocked"         ".snyk"
# The private-content guard is intact even on the auditor lane.
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT open a hole for ops/brief content" "ops/runbook.md"
run fail "auditor/2026-09-24-abc123" "auditor/ lane does NOT allow arbitrary root files"        "secrets.txt"
# Ordinary product files still pass regardless of branch.
run pass "feature/x" "product Go source still allowed off the auditor lane" "internal/cache/store.go"

# The reserved-branch guard: only the delivery App may push the auditor/* lane (the allowlist
# relaxes suppression paths there), so a dev branch can never use it to slip a suppression past.
GUARD=.github/workflows/reserved-branch-guard.yml
gp() { echo "ok:   $1"; pass=$((pass+1)); }
gf() { echo "FAIL: $1 — $2"; fail=$((fail+1)); }
if [ -f "$GUARD" ]; then
  gp "reserved-branch guard workflow present"
  if grep -qE "auditor/\*\*" "$GUARD" && grep -qE "^\s*push:" "$GUARD"; then
    gp "guard triggers on push to auditor/*"
  else gf "guard triggers on push to auditor/*" "missing push:auditor/** trigger"; fi
  if grep -q "fosterstack-automation" "$GUARD" && grep -qE "exit 1" "$GUARD"; then
    gp "guard rejects any pusher that is not the delivery App"
  else gf "guard gates on the App actor and fails closed" "missing App-actor check / exit 1"; fi
else
  gf "reserved-branch guard workflow present" "$GUARD missing"
fi

echo "----"
echo "check-file-allowlist: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
