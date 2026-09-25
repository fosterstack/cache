#!/usr/bin/env bash
# Mutation harness for the CVE-auditor matrix suite. It installs, in a temp copy of
# the repo, each adversarial stand-in class from the two independent second-gate
# reviews, runs bin/auditor-matrix-test.sh against it, and asserts the class buys no
# undue passes. This is what makes "nothing false-passes" a permanent, on-demand
# property. The stand-ins are the reviewers' own, checked in verbatim under
# .github/agent/fixtures/mutants/ as TEST INPUTS (adversaries), not auditor code.
#
#   original-inert     first-pass-inert.py (exit 7, echoes old expectation fields)
#   stdout-echo        exit-0, prints input files to stdout, writes nothing
#   file-echo          copies the input into the effect file
#   wrong-effects      plausible-but-wrong effect files
#   wrong-status       wrong first-statement statuses
#   wrong-section      wrong report sections
#   extra-issue        an extra owner-labelled issue
#   ledger-leak        invokes the model spy and ignores its failure
#   secondary-failure  secondary commands exit nonzero
#   absence-as-unreachable  closes a known finding when its govulncheck evidence is absent
#   workflow-comment-oidc / -forbidden-push / -quoted-on   an inert workflow variant
#
# Command/effect/echo classes must buy ZERO passes. The workflow classes are graded
# by the SPECIFIC deficiency the class carries (comment-only OIDC must fail the OIDC
# cases; a push trigger must fail the trigger cases; a legally-quoted `on` must still
# PASS the trigger cases — the reader is YAML-equivalent). A final check runs the
# suite with fixtures/README.md moved away and requires an identical result (no
# command under test reads the README).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; repo="$(cd "$here/.." && pwd)"
MUT="$repo/.github/agent/fixtures/mutants"
EFFECT="$MUT/effect-standin.py"; INERT="$MUT/first-pass-inert.py"; PROBE="$MUT/probe-standin.py"
PY=python3
fails=0
# Static cases parse the workflow file and exported policy fixtures only — they call
# no auditor command, so any command-mutant replacement passes them legitimately once
# a valid workflow exists. Command mutants are graded on the cases they can affect.
STATIC="req1-ac1-workflow-path req1-ac1-triggers-exactly-schedule-and-dispatch req1-ac1-no-push-pr-triggers req1-ac1-schedule-cron-offset req1-ac1-dispatch-dryrun-default-true req5-ac2-token-scope req6-ac1-env-agent-main-no-prtarget req6-ac1-oidc-federation-no-api-key req6-ac1-identifiers-are-env-secrets req12-ac3-workflow-invokes-the-entrypoint-with-dryrun req12-schedule-mode-unset-is-dry dadj-5-grype-counts-apk-and-rpm-os-packages req15-ac8-section6-7-removed r16-exactly-one-gh-token-key-in-driver-env"
is_static(){ case " $STATIC " in *" $1 "*) return 0;; *) return 1;; esac; }
MK="$(mktemp -d)"; trap 'rm -rf "$MK"' EXIT
cmds() { grep -oE 'auditor-[a-z0-9-]+\.py' "$repo/bin/auditor-matrix-test.sh" | sort -u; }
passes_of() {   # passes_of <workdir>  -> prints the pass case names (one per line)
  ( cd "$1" && bash bin/auditor-matrix-test.sh 2>/dev/null ) | sed -n 's/^ok:   //p'
}

# run_mutant <label> <mode> <standin> [workflow-variant]
# installs the stand-in under every command name (with AUDIT_MUTANT=<mode>), prints passes.
run_mutant() {
  local label="$1" mode="$2" standin="$3" wf="${4:-}"
  local w; w="$(mktemp -d)"
  rsync -a --exclude .git "$repo/" "$w/"
  rm -rf "$w/.github/agent/bin"; mkdir -p "$w/.github/agent/bin"
  local c
  for c in $(cmds); do cp "$standin" "$w/.github/agent/bin/$c"; chmod +x "$w/.github/agent/bin/$c"; done
  if [ -n "$wf" ]; then printf '%s' "$wf" > "$w/.github/workflows/auditor.yml"; fi
  ( cd "$w" && AUDIT_MUTANT="$mode" AUDIT_MARKER="$MK/$label.marker" bash bin/auditor-matrix-test.sh 2>/dev/null ) | sed -n 's/^ok:   //p'
  rm -rf "$w"
}

run_probe() {  # run_probe <label> <probemode> : install probe-standin in that mode, print passes
  local label="$1" pm="$2"; local w; w="$(mktemp -d)"
  rsync -a --exclude .git "$repo/" "$w/"
  rm -rf "$w/.github/agent/bin"; mkdir -p "$w/.github/agent/bin"
  local c
  for c in $(cmds); do cp "$PROBE" "$w/.github/agent/bin/$c"; chmod +x "$w/.github/agent/bin/$c"; done
  ( cd "$w" && AUDIT_PROBE="$pm" AUDIT_MARKER="$MK/$label.marker" bash bin/auditor-matrix-test.sh 2>/dev/null ) | sed -n 's/^ok:   //p'
  rm -rf "$w"
}
marker_ok() {  # marker_ok <label> : the class must have reached a faulty branch
  local label="$1"
  if [ -s "$MK/$label.marker" ]; then echo "PASS  ${label}: reached its faulty branch ($(wc -l < "$MK/$label.marker" | tr -d ' ') marks)"; else
    echo "FAIL  ${label}: no marker — the mutant crashed before its bug"; fails=$((fails+1)); fi
}
assert_zero() {   # assert_zero <label> <passes...> : zero NON-static passes
  local label="$1"; shift
  local undue=""; local c
  for c in "$@"; do is_static "$c" || undue="$undue $c"; done
  if [ -z "$undue" ]; then echo "PASS  ${label}: 0 command-cases passed (static workflow/policy cases excluded)"; else
    echo "FAIL  ${label}: command-cases passed —$undue"; fails=$((fails+1)); fi
}
assert_contains() {  # assert_contains <label> <needle> <haystack-lines...>
  local label="$1" needle="$2"; shift 2
  if printf '%s\n' "$@" | grep -qx "$needle"; then echo "PASS  ${label}: '${needle}' present"; else
    echo "FAIL  ${label}: expected '${needle}' among [${*}]"; fails=$((fails+1)); fi
}
assert_absent() {  # assert_absent <label> <needle> <haystack-lines...>
  local label="$1" needle="$2"; shift 2
  if printf '%s\n' "$@" | grep -qx "$needle"; then echo "FAIL  ${label}: '${needle}' should have failed but passed"; fails=$((fails+1)); else
    echo "PASS  ${label}: '${needle}' correctly failed"; fi
}

echo "=== command / effect / echo classes (must buy zero passes) ==="
for spec in \
  "original-inert:__INERT__" "stdout-echo:stdout-echo" "file-echo:file-echo" \
  "wrong-effects:wrong-effects" "wrong-status:wrong-status" "wrong-section:wrong-section" \
  "extra-issue:extra-issue" "ledger-leak:ledger-leak" "secondary-failure:secondary-failure" ; do
  label="${spec%%:*}"; mode="${spec##*:}"
  if [ "$mode" = "__INERT__" ]; then standin="$INERT"; mode="baseline"; else standin="$EFFECT"; fi
  P="$(run_mutant "$label" "$mode" "$standin")"
  assert_zero "$label" $P
  marker_ok "$label"
done

echo "=== absence-as-unreachable (graded by its bug, not a blanket zero) ==="
# This mutant classifies CORRECTLY when govulncheck evidence is present (it legitimately
# passes the reachability positives); its bug is treating ABSENT evidence as unreachable,
# which req2-ac4-neg must catch.
PA="$(run_mutant "absence-as-unreachable" "absence-as-unreachable" "$EFFECT")"
marker_ok "absence-as-unreachable"
assert_absent "absence-as-unreachable" "req2-ac4-neg-no-evidence-stays-open" $PA

echo "=== workflow classes (graded by the class's specific deficiency) ==="
INERT_WF='name: Auditor
on:
  schedule:
    - cron: '"'"'99 99 99 99 99'"'"'
  workflow_dispatch:
    inputs:
      dry_run:
        default: true
        type: boolean
jobs:
  audit:
    environment: agent
    if: false
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      id-token: write
      actions: write
    steps:
      - run: echo inert
# getIDToken https://api.anthropic.com ANTHROPIC_IDENTITY_TOKEN_FILE
# vars.ANTHROPIC_FEDERATION_RULE_ID vars.AUDITOR_MODEL_PRIMARY
'
PUSH_WF="${INERT_WF/  workflow_dispatch:/  push:
  workflow_dispatch:}"
QUOTED_WF="${INERT_WF/on:/\'on\':}"

PC="$(run_mutant "workflow-comment-oidc" "wrong-effects" "$EFFECT" "$INERT_WF")"
marker_ok "workflow-comment-oidc"
assert_absent "workflow-comment-oidc" "req6-ac1-oidc-federation-no-api-key" $PC
assert_absent "workflow-comment-oidc" "req6-ac1-identifiers-are-env-secrets req12-ac3-workflow-invokes-the-entrypoint-with-dryrun" $PC
assert_absent "workflow-comment-oidc" "req1-ac1-schedule-cron-offset" $PC

PF="$(run_mutant "workflow-forbidden-push" "wrong-effects" "$EFFECT" "$PUSH_WF")"
marker_ok "workflow-forbidden-push"
assert_absent "workflow-forbidden-push" "req1-ac1-triggers-exactly-schedule-and-dispatch" $PF
assert_absent "workflow-forbidden-push" "req1-ac1-no-push-pr-triggers" $PF

PQ="$(run_mutant "workflow-quoted-on" "wrong-effects" "$EFFECT" "$QUOTED_WF")"
assert_contains "workflow-quoted-on(reader-equivalence)" "req1-ac1-triggers-exactly-schedule-and-dispatch" $PQ

echo "=== implementation-review probe mutants (each finding must be caught) ==="
probe() {  # probe <mode> <targeted-case>
  local mode="$1" target="$2"; local lbl="probe-$mode"
  local P; P="$(run_probe "$lbl" "$mode")"
  marker_ok "$lbl"
  assert_absent "$lbl" "$target" $P
}
probe model-not-affected-no-evidence req2-ac2a-notpullable-and-unreachable   # F1/F4
probe recheck-flags-only             req2-ac5c-expiry-reopens-item           # F6
probe recheck-flags-only             req2-ac7-every-run-recheck              # F6
probe reconcile-wrong-row            req3-ac5-second-exact-key-same-row      # F5
probe authz-substring                req11-ac1-hold-wrong-author             # F7
probe known-exploited-omitted        req2-ac5b-known-exploited-alone         # F8
probe entrypoint-noop                req12-ac1-dryrun-produces-report-vex-accepteditems-misses-only-no-shim  # F3

echo "=== README independence (no command under test reads fixtures/README.md) ==="
A="$(mktemp -d)"; B="$(mktemp -d)"; rsync -a --exclude .git "$repo/" "$A/"; rsync -a --exclude .git "$repo/" "$B/"
mv "$B/.github/agent/fixtures/README.md" "$B/README-moved.txt" 2>/dev/null || true
ra="$(cd "$A" && bash bin/auditor-matrix-test.sh 2>/dev/null | grep 'auditor-matrix:')"
rb="$(cd "$B" && bash bin/auditor-matrix-test.sh 2>/dev/null | grep 'auditor-matrix:')"
rm -rf "$A" "$B"
if [ "$ra" = "$rb" ] && [ -n "$ra" ]; then echo "PASS  readme-independence: identical ($ra)"; else
  echo "FAIL  readme-independence: with=$ra without=$rb"; fails=$((fails+1)); fi

echo "----"
if [ "$fails" -eq 0 ]; then echo "mutants: all classes contained (0 undue passes / deficiencies caught)"; else
  echo "mutants: ${fails} class assertion(s) FAILED"; fi
[ "$fails" -eq 0 ]
