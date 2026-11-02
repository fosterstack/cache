#!/usr/bin/env bash
# bin/with-aws-token.sh sign-record|sign [ARG...]  --  run one signing call of the verifier (bin/chain-verify.py sign-record or sign, with ARG...) with a fresh identity token, for that one call only (#822 round 2: the one copy of the token fetch).
# The caller is a step whose own call signs with the release KMS key through the AWS SDK: Sign's staged-record helper (one call per record) and Sign's provenance signature.
# A fresh token (audience sts.amazonaws.com, the audience the AWS trust requires) is fetched now and written to a file of mode 0600 in a private directory under RUNNER_TEMP, outside the
# repository tree; AWS_WEB_IDENTITY_TOKEN_FILE points the SDK at it for that call and for nothing else (AWS_ROLE_ARN, AWS_REGION and RELEASE_KMS_KEY_REF come from the job's step environment and
# stay in the call's environment). The request variables are plain shell variables, never exported, so the call cannot ask for another token; nothing goes to GITHUB_ENV. The directory is removed
# the moment the call ends (success, failure or signal), and its exit status is the exit status of this script. A job that lacks the role, the region or the key reference, a missing
# RUNNER_TEMP, a failed, empty or null token, or nothing to run stops here, before the call runs.
set -euo pipefail
case "${1:-}" in sign-record|sign) ;; *) echo "with-aws-token: the first argument must be sign-record or sign" >&2; exit 2 ;; esac
: "${AWS_ROLE_ARN:?with-aws-token: AWS_ROLE_ARN is missing}"
: "${AWS_REGION:?with-aws-token: AWS_REGION is missing}"
: "${RELEASE_KMS_KEY_REF:?with-aws-token: RELEASE_KMS_KEY_REF is missing}"
umask 077
td=$(mktemp -d "${RUNNER_TEMP:?}/witness-aws.XXXXXX")
trap 'rm -rf "$td"' EXIT HUP INT TERM
req_tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN req_url=$ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL
sh bin/loopback-get.sh -sSf -H "Authorization: bearer $req_tok" "${req_url}&audience=sts.amazonaws.com" | jq -r .value > "$td/token"
tok=$(cat "$td/token")
[ -n "$tok" ] && [ "$tok" != null ] || { echo "with-aws-token: no identity token" >&2; exit 1; }
echo "::add-mask::$tok"
rc=0
AWS_WEB_IDENTITY_TOKEN_FILE="$td/token" python3 -I -B bin/chain-verify.py "$@" || rc=$?
rm -rf "$td"
[ ! -e "$td" ] || { echo "with-aws-token: the token directory still exists" >&2; exit 1; }
exit "$rc"
