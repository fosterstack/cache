#!/usr/bin/env bash
# Parser unit tests (real fixtures + malformed variants). CI: ci.yml, required 'allowlist' job.
# Run as the coverage gate's parallel shards (unit-shards.sh, no coverage):
# unit-shard-sum.py proves every test finished exactly once.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../../.."
out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
UNIT_SHARD_RUNNER=python3 bash "$here/unit-shards.sh" "$out"
cat "$out"/shards.*/unit.[0-9]*.log
