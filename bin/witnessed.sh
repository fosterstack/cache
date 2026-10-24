#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one stage script under Witness (v0.3.0 rule 68; REQ-CHAIN-004-AC2).
# The one place that holds the Witness flags for the jobs that carry an identity token. STEP is one of a CLOSED list: Check's three steps scanners, acceptance and
# runtime and the arm64 job's arm64 (REQ-CHAIN-006-AC11, AC17), and Release's six steps release-verify, release-apks, release-publish, release-sign, release-assets and
# release-postverify (REQ-CHAIN-007-AC1). The building steps (apk, build, rapk, rebuild and their snapshot- forms) run under the local wrapper that sits beside this one, which holds no identity
# token (owner Oct 22 2026, REQ-CHAIN-004-AC2). Anything else exits 2 before Witness runs.
# The record is witness-DIR/STEP-collection.json, where DIR is STEP without a leading snapshot-: a snapshot job uploads the same directory as a release job,
# and the snapshot marker is the step name inside the signed collection (every verifier refuses a snapshot- name, REQ-CHAIN-004-AC13).
#  - The job's identity token goes into a shell variable (masked in the log), then the request variables are unset, so the wrapped script
#    cannot ask for a second certificate; Witness gets the token through a one-read process substitution, so no file holds it.
#  - The command runs under `timeout -k 20 540`: Fulcio's keyless certificate lives ten minutes and Witness checks it at the timestamp's time; a command that
#    ignores the TERM at 540 seconds is killed 20 seconds later, so it cannot hold the job past the certificate.
#  - Attestors: environment, git, material and product only (never github, whose record embeds the raw token, and never slsa: Sign's alone).
#  - The step release-sign ALONE also gets one more token, audience sigstore, masked, as SIGSTORE_ID_TOKEN (cosign's keyless signing reads it); the request
#    variables stay unset for every child, and a failed or empty fetch stops the helper before anything runs (REQ-CHAIN-007-AC15).
#  - The sensitive-key list keeps out of the record the identity-token variables, the job token and Release's three credential names (REQ-CHAIN-007-AC12).
#  - Witness runs from the repository root (no working-directory flag), so product subjects are named relative to it.
# The exact text of this file is judged by bin/chain-test-shape.py (helper), whose Check copy follows it; change both together together.
set -euo pipefail
step="$1"
shift
case "$step" in scanners|acceptance|runtime|arm64|release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
tok=$(sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)
echo "::add-mask::$tok"
unset SIGSTORE_ID_TOKEN
if [ "$step" = release-sign ]; then sig=$(sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value); [ -n "$sig" ] && [ "$sig" != null ] || { echo "witnessed: no identity token for release-sign" >&2; exit 1; }; echo "::add-mask::$sig"; export SIGSTORE_ID_TOKEN="$sig"; fi
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
  --env-add-sensitive-key APK_RELEASE_SIGNING_KEY \
  --env-add-sensitive-key DOCKERHUB_USERNAME \
  --env-add-sensitive-key DOCKERHUB_TOKEN \
  --env-add-sensitive-key SIGSTORE_ID_TOKEN \
  -o "witness-${step#snapshot-}/$step-collection.json" -- timeout -k 20 540 bash "$@"
