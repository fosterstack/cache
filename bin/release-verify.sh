#!/usr/bin/env bash
# Release, first witnessed step: checks the tag, makes the release policy for it, and verifies every earlier
# stage's signed record in the order of the release rules. A failure stops the run and the message starts with
# the stage. No credential is bound to this step: it has no environment block and no secret.
# After this step a release candidate ends: every later step of stage-promote.yml skips a tag with a hyphen.
set -euo pipefail
[[ "${GITHUB_REF_NAME:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || \
  { echo "refused at tag: ${GITHUB_REF_NAME:-} is not vX.Y.Z or vX.Y.Z-rcN" >&2; exit 1; }
# The signed key manifest and the root key that signs it must be there before any tool or credential step.
for f in release-key-manifest.json release-key-manifest.sig release-key-root.pub; do \
  [ -f ".github/policy/$f" ] || { echo "refused at key manifest: .github/policy/$f is missing" >&2; exit 1; }; \
done
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json \
  --tag "$GITHUB_REF_NAME" --out policy.json
python3 -I -B bin/chain-verify.py stage-start --stage release --previous build \
  --record witness-build/build-collection.json --digests witness-build/digests.json --policy policy.json
python3 -I -B bin/chain-verify.py bind-items --policy policy.json \
  --record witness-build/build-collection.json --items witness-build/items.json
python3 -I -B bin/chain-verify.py bind-items --policy policy.json \
  --record witness-build/build-collection.json --items witness-build/admission-baseline.json \
  --product admission-baseline.json
python3 -I -B bin/chain-verify.py stage-start --stage release --previous sign \
  --record provenance/provenance.json --digests witness-build/digests.json --policy policy.json \
  --rekor-entries provenance/provenance.rekor.json
python3 -I -B bin/chain-verify.py stage-start --stage release --previous rebuild \
  --record witness-rebuild/rebuild-collection.json --digests witness-build/digests.json --policy policy.json
# Rebuild's apks are compared with Build's in the compare job (no key, no token); this step reads only that
# job's small result file and accepts a pass for Build's attested apk digests.
python3 -I -B bin/chain-verify.py apk-compare --policy policy.json \
  --record witness-rebuild/rebuild-collection.json --file apk-compare/apk-compare.json --digests witness-build/digests.json
python3 -I -B bin/chain-verify.py check-list --policy policy.json --digests witness-build/digests.json \
  --dir witness-check
# The govulncheck stream release-sign hands the evidence step is a product of Check's verified scanners
# record, bound under Check's identity for Build's digests.
python3 -I -B bin/chain-verify.py bind-check --policy policy.json \
  --record witness-check/witness-scanners/scanners-collection.json --digests witness-build/digests.json \
  --file check-results/govulncheck.json --product check-results/govulncheck.json
