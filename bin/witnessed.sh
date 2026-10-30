#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one Release script under Witness (rule 68; REQ-CHAIN-004-AC2), signed by the release KMS key (handoff 0713).
# The only place that holds the Witness flags for a job that carries an identity token. The building and Check steps
# run under the local wrapper beside this one, which holds no token (REQ-CHAIN-004-AC2).
# Any other STEP exits 2 before Witness runs.
# The record is witness-DIR/STEP-collection.json; DIR drops a leading "snapshot-" so a snapshot job uploads the same
# directory, and the marker stays in the step name (verifiers refuse it, REQ-CHAIN-004-AC13).
#  - Witness runs with a throwaway key made for the step (its own signature carries no trust); then the one signing function (bin/chain-verify.py sign-record)
#    signs the collection's payload with the release KMS key, named by RELEASE_KMS_KEY_REF (the job pins it to the key's reference awskms:///<name>), through the
#    AWS SDK, and keeps the Rekor entry beside the record (STEP-collection.rekor.json). The SDK exchanges the
#    job's identity token for short-lived credentials: the token (audience sts.amazonaws.com, the audience the AWS trust requires) is written to a
#    file in a private directory under RUNNER_TEMP, outside the repository tree, and AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN point the SDK
#    at it. They are never written to GITHUB_ENV. The directory is removed when Witness returns or the shell gets EXIT, HUP, INT or TERM.
#  - Both variables are removed (env -u) from the wrapped script of every step except release-sign, the one script that signs
#    with the key itself (cosign); they are sensitive keys, so no record holds them. The request variables are unset, so no script can ask
#    for a second token.
#  - The AWS role, region and key reference come from the job (AWS_ROLE_ARN, AWS_REGION, RELEASE_KMS_KEY_REF); a job that lacks one stops here, before any token is asked for.
#    The key reference is not written in this file: a KMS key's name form contains a word the script scan of the release chain refuses, so the workflow pins it.
#  - Attestors: environment, git, material, product. Never github (its record embeds the raw token), never slsa
#    (Sign's alone).
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
: "${AWS_ROLE_ARN:?witnessed: AWS_ROLE_ARN is missing}"
: "${AWS_REGION:?witnessed: AWS_REGION is missing}"
: "${RELEASE_KMS_KEY_REF:?witnessed: RELEASE_KMS_KEY_REF is missing}"
case "$RELEASE_KMS_KEY_REF" in awskms:///?*) ;; *) echo "witnessed: RELEASE_KMS_KEY_REF is not a KMS key reference" >&2; exit 1 ;; esac
umask 077
td=$(mktemp -d "${RUNNER_TEMP:?}/witness-aws.XXXXXX")
trap 'rm -rf "$td"' EXIT HUP INT TERM
sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sts.amazonaws.com" | jq -r .value > "$td/token"
tok=$(cat "$td/token")
[ -n "$tok" ] && [ "$tok" != null ] || { echo "witnessed: no identity token" >&2; exit 1; }
echo "::add-mask::$tok"
export AWS_WEB_IDENTITY_TOKEN_FILE="$td/token"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL
if [ "$step" = release-sign ]; then
  wrap=()
else
  wrap=(env -u AWS_WEB_IDENTITY_TOKEN_FILE -u AWS_ROLE_ARN)
fi
openssl genpkey -algorithm ed25519 -out "$td/key.pem"
local_record="$td/$step-collection.json"
rc=0
witness run --step "$step" --signer-file-key-path "$td/key.pem" \
  -a environment,git,material,product \
  --env-filter-sensitive-vars \
  --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' \
  --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \
  --env-add-sensitive-key GH_TOKEN \
  --env-add-sensitive-key GITHUB_TOKEN \
  --env-add-sensitive-key APK_RELEASE_SIGNING_KEY \
  --env-add-sensitive-key DOCKERHUB_USERNAME \
  --env-add-sensitive-key DOCKERHUB_TOKEN \
  --env-add-sensitive-key AWS_WEB_IDENTITY_TOKEN_FILE \
  --env-add-sensitive-key AWS_ROLE_ARN \
  -o "$local_record" -- ${wrap[@]+"${wrap[@]}"} bash "$@" || rc=$?
if [ "$rc" -eq 0 ]; then
  # the step ran: the one signing function signs the collection's payload with the release key; a failure here ends the job (nothing is left unsigned and unnoticed)
  jq -r .payload "$local_record" | base64 -d > "$td/payload" || { echo "witnessed: the collection has no payload" >&2; exit 1; }
  python3 -I -B bin/chain-verify.py sign-record --payload "$td/payload" --out "witness-${step#snapshot-}/$step-collection.json" \
    --template .github/policy/release-policy.template.json || rc=$?
fi
rm -rf "$td"
[ ! -e "$td" ] || { echo "witnessed: the token directory still exists" >&2; exit 1; }
exit "$rc"
