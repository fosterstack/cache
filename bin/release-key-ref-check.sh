#!/usr/bin/env bash
# Runs before anything is published: stops the release unless RELEASE_KMS_KEY_REF is a KMS key reference the signing step will accept.
set -euo pipefail
ref=${RELEASE_KMS_KEY_REF:-}
[ -n "$ref" ] || { echo "release-key-ref-check: RELEASE_KMS_KEY_REF is unset" >&2; exit 2; }
[[ "$ref" =~ ^awskms:///[A-Za-z0-9/_+=,.@:-]+$ ]] && [[ ! "$ref" =~ ^awskms:///[a]lias/?$ ]] ||
  { echo "release-key-ref-check: RELEASE_KMS_KEY_REF is not a KMS key reference" >&2; exit 1; }
