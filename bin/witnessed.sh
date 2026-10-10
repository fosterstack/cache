#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one stage script under Witness (v0.3.0 rule 68; REQ-CHAIN-004-AC2).
# The one place that holds the Witness flags. STEP is one of a CLOSED list: apk, build, rapk, rebuild (a release) and snapshot-apk, snapshot-build,
# snapshot-rapk, snapshot-rebuild (the proof workflows' snapshot mode, REQ-CHAIN-004-AC12 and REQ-CHAIN-005-AC7). Anything else exits 2 before Witness runs.
# The record is witness-DIR/STEP-collection.json, where DIR is STEP without a leading snapshot-: a snapshot job uploads the same directory as a release job,
# and the snapshot marker is the step name inside the signed collection (every verifier refuses a snapshot- name, REQ-CHAIN-004-AC13).
#  - The job's identity token goes into a shell variable (masked in the log), then the request variables are unset, so the wrapped script
#    cannot ask for a second certificate; Witness gets the token through a one-read process substitution, so no file holds it.
#  - The command runs under `timeout 540`: Fulcio's keyless certificate lives ten minutes and Witness checks it at the timestamp's time.
#  - Attestors: environment, git, material and product only (never github, whose record embeds the raw token, and never slsa: Sign's alone).
#  - Witness runs from the repository root (no working-directory flag), so product subjects are named relative to it.
# The exact text of this file is judged by bin/chain-test-shape.py (helper); change both together.
set -euo pipefail
step="$1"
shift
case "$step" in apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
tok=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)
echo "::add-mask::$tok"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL
exec witness run --step "$step" \
  --signer-fulcio-url https://fulcio.sigstore.dev \
  --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \
  --signer-fulcio-oidc-client-id sigstore \
  --signer-fulcio-token-path <(printf %s "$tok") \
  -t https://timestamp.sigstore.dev/api/v1/timestamp \
  -a environment,git,material,product \
  --env-filter-sensitive-vars \
  --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' \
  --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \
  --env-add-sensitive-key GH_TOKEN \
  --env-add-sensitive-key GITHUB_TOKEN \
  -o "witness-${step#snapshot-}/$step-collection.json" -- timeout 540 bash "$@"
