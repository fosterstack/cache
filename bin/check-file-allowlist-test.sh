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

SUPP=(".snyk" "osv-scanner.toml" ".auditor/accepted-items.json")

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

echo "----"
echo "check-file-allowlist: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
