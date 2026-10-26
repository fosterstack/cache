#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one Release script under Witness (rule 68; REQ-CHAIN-004-AC2).
# The only place that holds the Witness flags for a job that carries an identity token. The building and Check steps
# run under the local wrapper beside this one, which holds no token (REQ-CHAIN-004-AC2).
# Any other STEP exits 2 before Witness runs.
# The record is witness-DIR/STEP-collection.json; DIR drops a leading "snapshot-" so a snapshot job uploads the same
# directory, and the marker stays in the step name (verifiers refuse it, REQ-CHAIN-004-AC13).
#  - The token stays in a shell variable (masked in the log) and reaches Witness by process substitution, so no file
#    holds it. The request variables are unset, so the wrapped script cannot ask for a second certificate.
#  - Fulcio's certificate lives ten minutes and Witness checks it at the timestamp's time, so the command gets 540
#    seconds and is killed 20 seconds after a TERM it ignores.
#  - Attestors: environment, git, material, product. Never github (its record embeds the raw token), never slsa
#    (Sign's alone).
#  - release-sign alone gets a second token, audience sigstore, as SIGSTORE_ID_TOKEN for cosign (REQ-CHAIN-007-AC15);
#    a failed, empty or null fetch stops the helper before anything runs.
#  - The sensitive-key list keeps the identity-token variables, job token and Release's credentials out of the record
#    (REQ-CHAIN-007-AC12).
#  - Witness runs from the repository root (no working-directory flag), so product subjects are named relative to it.
# bin/chain-test-shape.py (helper) judges the exact text of this file; its Check copy follows. Change them together.
set -euo pipefail
step="$1"
shift
case "$step" in release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify) ;; \
  *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
oidc_token() {
  sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value
}
tok=$(oidc_token)
echo "::add-mask::$tok"
unset SIGSTORE_ID_TOKEN
if [ "$step" = release-sign ]; then
  sig=$(oidc_token)
  [ -n "$sig" ] && [ "$sig" != null ] || { echo "witnessed: no identity token for release-sign" >&2; exit 1; }
  echo "::add-mask::$sig"
  export SIGSTORE_ID_TOKEN="$sig"
fi
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
