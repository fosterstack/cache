#!/usr/bin/env bash
# bin/witnessed.sh STEP SCRIPT...  --  run one Release script under Witness (rule 68; REQ-CHAIN-004-AC2), the way the local wrapper runs a building one.
# The Release job holds no KMS role and no key (docs/ratify/2026-10-28-kms-signing-key-and-one-step-build.md:24): the signatures of the release are Sign's, made before anything is published
# (the Sign job's release signing step). The record of a Release step is evidence, not the trust (Q-T2; KMS:36-38): it is signed with a THROWAWAY ed25519 key made in the job, as Build's are, and
# nothing trusts it. The record leaves as witness-DIR/STEP-collection.local.json, where DIR is STEP without a leading snapshot-; the marker stays in the step name (verifiers refuse it, REQ-CHAIN-004-AC13).
# Any other STEP exits 2 before Witness runs.
#  - The key is key hygiene, not the trust boundary: it is made in a directory of mode 0700 under RUNNER_TEMP (umask 077), handed to Witness by path only, never printed, never copied, and removed when
#    Witness returns or the shell gets EXIT, HUP, INT or TERM; the helper then checks that the directory is gone.
#  - Witness runs with no identity token and no AWS role or token-path name in its environment, for every step, and the wrapped command is the plain `bash SCRIPT`.
#  - Attestors: environment, git, material, product. Never github (its record embeds the raw token), never slsa (Sign's alone).
#  - The sensitive-key list keeps the identity-token variables, job token and Release's credentials out of the record (REQ-CHAIN-007-AC12).
#  - Witness runs from the repository root (no working-directory flag), so product subjects are named relative to it.
# bin/chain-test-shape.py (helper) judges the exact text of this file; its Check copy follows. Change them together.
set -euo pipefail
step="$1"
shift
case "$step" in release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify) ;; \
  *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
umask 077
kd=$(mktemp -d "${RUNNER_TEMP:?}/witness-key.XXXXXX")
trap 'rm -rf "$kd"' EXIT HUP INT TERM
openssl genpkey -algorithm ed25519 -out "$kd/key.pem"
rc=0
witness run --step "$step" --signer-file-key-path "$kd/key.pem" \
  -a environment,git,material,product \
  --env-filter-sensitive-vars \
  --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' \
  --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN \
  --env-add-sensitive-key GH_TOKEN \
  --env-add-sensitive-key GITHUB_TOKEN \
  --env-add-sensitive-key DOCKERHUB_USERNAME \
  --env-add-sensitive-key DOCKERHUB_TOKEN \
  --env-add-sensitive-key AWS_WEB_IDENTITY_TOKEN_FILE \
  --env-add-sensitive-key AWS_ROLE_ARN \
  -o "witness-${step#snapshot-}/$step-collection.local.json" -- bash "$@" || rc=$?
rm -rf "$kd"
[ ! -e "$kd" ] || { echo "witnessed: the throwaway key directory still exists" >&2; exit 1; }
exit "$rc"
