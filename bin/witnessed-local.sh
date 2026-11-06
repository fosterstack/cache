#!/usr/bin/env bash
# bin/witnessed-local.sh STEP SCRIPT...  --  run one BUILDING stage script under Witness (v0.3.0 rule 68; REQ-CHAIN-004-AC2), the way the owner ratified on Oct 22 2026
# (ops/docs/ratify/2026-10-22-witness-signed-outside-build.md, option 1): the build job records its provenance with a THROWAWAY ed25519 key made in the job, which holds no
# identity token; the record leaves as <step>-collection.local.json, a file nothing trusts. The Sign stage checks the record's product digests against the artifacts it
# receives and re-signs the payload with the release key (signed with the KMS key; its Rekor entry is recorded); verifiers trust
# only the release key and refuse a record whose only signature is the throwaway one.
# STEP is one of a CLOSED list: apk, build, rapk, rebuild (a release), snapshot-apk, snapshot-build, snapshot-rapk, snapshot-rebuild (the snapshot mode) and Check's four steps
# scanners, acceptance, runtime and arm64 (they build and run workloads, so their jobs hold no identity token either; REQ-REL-011-AC1), and release-verify (its job holds no identity
# token and cannot assume the signing role). The other Release steps stay on the KMS helper, which signs in their own job.
#  - The record is witness-DIR/STEP-collection.local.json, where DIR is STEP without a leading snapshot-: a snapshot job uploads the same directory as a release job, and the
#    snapshot marker is the step name inside the record (every verifier refuses a snapshot- name, REQ-CHAIN-004-AC13).
#  - The key is key hygiene, not the trust boundary: it is made in a directory of mode 0700 under the runner temp folder (umask 077), handed to Witness by path only, never
#    printed, never copied, never written into a record or an upload directory, and removed when Witness returns or the shell gets EXIT, HUP, INT or TERM; the helper then
#    checks that the directory is gone. The wrapped build runs on the same runner as the same user, so nothing here claims it cannot read the key: the key carries no trust.
#  - The build runs under `timeout -k 20 540`: a bound on a hung build, as REQ-CHAIN-004-AC2 says (a program that ignores the TERM is killed 20 seconds
#    later). It is not a certificate lifetime: no certificate is involved any more.
#  - Attestors: environment, git, material and product only (never github, whose record embeds the raw token, and never slsa: Sign's alone). The sensitive-key list keeps the
#    token and credential variable names out of the record.
#  - Witness runs from the repository root (no working-directory flag), so product subjects are named relative to it.
# The exact text of this file is judged by bin/chain-test-shape.py (localhelper); change both together.
set -euo pipefail
step="$1"
shift
case "$step" in apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild|release-verify|scanners|acceptance|runtime|arm64) ;; *) echo "witnessed-local: unknown step $step" >&2; exit 2 ;; esac
mkdir -p "witness-${step#snapshot-}"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
umask 077
kd=$(mktemp -d "${RUNNER_TEMP:?}/witness-key.XXXXXX")
trap 'rm -rf "$kd"' EXIT HUP INT TERM
openssl genpkey -algorithm ed25519 -out "$kd/key.pem"
rc=0
witness run --step "$step" --signer-file-key-path "$kd/key.pem" -a environment,git,material,product --env-filter-sensitive-vars --env-add-sensitive-key 'ACTIONS_ID_TOKEN_REQUEST*' --env-add-sensitive-key ACTIONS_RUNTIME_TOKEN --env-add-sensitive-key GH_TOKEN --env-add-sensitive-key GITHUB_TOKEN --env-add-sensitive-key DOCKERHUB_USERNAME --env-add-sensitive-key DOCKERHUB_TOKEN --env-add-sensitive-key AWS_WEB_IDENTITY_TOKEN_FILE --env-add-sensitive-key AWS_ROLE_ARN -o "witness-${step#snapshot-}/$step-collection.local.json" -- timeout -k 20 540 bash "$@" || rc=$?
rm -rf "$kd"
[ ! -e "$kd" ] || { echo "witnessed-local: the throwaway key directory still exists" >&2; exit 1; }
exit "$rc"
