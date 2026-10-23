#!/usr/bin/env bash
# bin/witness-sign-staged.sh STAGED SIGNED  --  Sign's signing step for the building jobs' Witness records (REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC4).
# `bin/chain-verify.py sign-records` has already checked every local record against the artifacts Sign received and staged, under STAGED/<record-dir>/, each
# record's payload bytes (STEP-collection.payload) and its data files; it printed nothing to sign on any refusal. This helper signs each payload keyless
# (the job's identity token, audience sigstore, held in a shell variable and handed to Witness through a one-read process substitution; the request
# variables are unset first) into SIGNED/<record-dir>/STEP-collection.json with the Sigstore timestamp, copies the data files unchanged, and then runs the
# self-check `bin/chain-verify.py verify` on every signed record (identity stage-sign.yml, the committed template made for GITHUB_REF), so a signing that
# did not produce a valid Sign-identity record stops the job. It builds nothing and runs no stage script.
set -euo pipefail
staged="$1"
signed="$2"
tok=$(sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)
echo "::add-mask::$tok"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL SIGSTORE_ID_TOKEN
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --ref "$GITHUB_REF" --out policy.json
for payload in "$staged"/*/*-collection.payload; do
  dir=$(dirname "$payload")
  name=$(basename "$dir")
  base=$(basename "$payload" .payload)
  step=${base%-collection}
  mkdir -p "$signed/$name"
  for f in "$dir"/*; do case "$f" in *.payload) ;; *) cp "$f" "$signed/$name/" ;; esac; done
  witness sign -f "$payload" -t application/vnd.in-toto+json \
    --signer-fulcio-url https://fulcio.sigstore.dev \
    --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \
    --signer-fulcio-oidc-client-id sigstore \
    --signer-fulcio-token-path <(printf %s "$tok") \
    --timestamp-servers https://timestamp.sigstore.dev/api/v1/timestamp \
    -o "$signed/$name/$base.json"
  case "$step" in apk|build) stage=build ;; rapk|rebuild) stage=rebuild ;; *) echo "witness-sign-staged: unknown step $step" >&2; exit 1 ;; esac
  python3 -I -B bin/chain-verify.py verify --policy policy.json --stage "$stage" --record "$signed/$name/$base.json"
done
