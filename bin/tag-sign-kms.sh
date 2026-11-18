#!/usr/bin/env bash
# The one signing call of sign-tag: the release key signs the digest tag-sign.py prepare wrote.
set -euo pipefail
dg=$(cat tag-work/tag.digest)
bash bin/with-aws-token.sh kms-sign --aws "$RUNNER_TEMP/aws-cli/aws" --key-ref "$RELEASE_KMS_KEY_REF" --signing-config ".github/policy/cosign-signing-config.json" --public-key "build/keys/release.rsa.pub" --digest "$dg" --out "tag-work/tag.sig" --bundle "tag-work/tag.bundle"
