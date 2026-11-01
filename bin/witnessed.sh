#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one Release script under Witness (rule 68; REQ-CHAIN-004-AC2), signed by the release KMS key (handoff 0713).
# The only place that holds the Witness flags for a job that carries an identity token. The building and Check steps
# run under the local wrapper beside this one, which holds no token (REQ-CHAIN-004-AC2).
# Any other STEP exits 2 before Witness runs.
# The record is witness-DIR/STEP-collection.json; DIR drops a leading "snapshot-" so a snapshot job uploads the same
# directory, and the marker stays in the step name (verifiers refuse it, REQ-CHAIN-004-AC13).
#  - Witness runs first, with a throwaway key made for the step (its own signature carries no trust), no identity token and no AWS variable in its environment or the
#    wrapped script's. Then a fresh identity token (audience sts.amazonaws.com, the audience the AWS trust requires) is written to a file in a private directory under
#    RUNNER_TEMP, outside the repository tree, and the one signing function (bin/chain-verify.py sign-record) signs the collection's payload with the release KMS key
#    (RELEASE_KMS_KEY_REF, checked there) through the AWS SDK, which exchanges the token for short-lived credentials: AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN point the SDK
#    at it for that one call, and the entries file of the Rekor entry stays beside the record (STEP-collection.rekor.json). Nothing goes to GITHUB_ENV. The directory is
#    removed when the shell gets EXIT, HUP, INT or TERM.
#  - release-sign is the one step whose wrapped script signs with the key itself (cosign): it alone gets the token and the AWS variables while it runs (the list of such steps is
#    this one name; release-apks joins it when the apk signer calls KMS). They are sensitive keys, so no record holds them. The request variables are plain shell variables
#    (never exported), so no script can ask for a token.
#  - The AWS role, region and key reference come from the job's step env (AWS_ROLE_ARN, AWS_REGION, RELEASE_KMS_KEY_REF); a job that lacks one stops here, before any token is asked for.
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
umask 077
td=$(mktemp -d "${RUNNER_TEMP:?}/witness-aws.XXXXXX")
trap 'rm -rf "$td"' EXIT HUP INT TERM
role=$AWS_ROLE_ARN region=$AWS_REGION kref=$RELEASE_KMS_KEY_REF
req_tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN req_url=$ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL
oidc_token() {
  sh bin/loopback-get.sh -sSf -H "Authorization: bearer $req_tok" "${req_url}&audience=sts.amazonaws.com" | jq -r .value > "$td/token"
  tok=$(cat "$td/token")
  [ -n "$tok" ] && [ "$tok" != null ] || { echo "witnessed: no identity token" >&2; exit 1; }
  echo "::add-mask::$tok"
}
if [ "$step" = release-sign ]; then
  oidc_token
  export AWS_WEB_IDENTITY_TOKEN_FILE="$td/token"
else
  unset AWS_ROLE_ARN AWS_REGION RELEASE_KMS_KEY_REF
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
  -o "$local_record" -- bash "$@" || rc=$?
if [ "$rc" -eq 0 ]; then
  # the step ran: the one signing function signs the collection's payload with the release key, with a token fetched now; a failure here ends the job (nothing is left unsigned and unnoticed)
  jq -er .payload "$local_record" | base64 -d > "$td/payload" && [ -s "$td/payload" ] || { echo "witnessed: the collection has no payload" >&2; exit 1; }
  oidc_token
  AWS_WEB_IDENTITY_TOKEN_FILE="$td/token" AWS_ROLE_ARN=$role AWS_REGION=$region RELEASE_KMS_KEY_REF=$kref \
    python3 -I -B bin/chain-verify.py sign-record --payload "$td/payload" --out "witness-${step#snapshot-}/$step-collection.json" \
    --template .github/policy/release-policy.template.json || rc=$?
fi
rm -rf "$td"
[ ! -e "$td" ] || { echo "witnessed: the token directory still exists" >&2; exit 1; }
exit "$rc"
