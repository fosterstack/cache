#!/usr/bin/env bash
# The freeze job (rule 1 of the sandboxed build). The requirements tool is Go code of the tagged commit, so its
# freeze check runs here, in a job of its own with no token and no Witness step, never inside Build.
# Each baseline file of the tagged commit gets verify-freeze and one `freeze-ok COMMIT BASE` line in freeze/freeze.txt.
# Build's admission reads that file.
set -euo pipefail
[ -x /usr/local/bin/fscache-go/bin/go ] || { echo "build-freeze: the pinned Go is missing" >&2; exit 2; }
commit=$(git rev-parse HEAD)
mkdir -p freeze
: > freeze/freeze.txt
for file in requirements/releases/*.yaml; do
  base=$(basename "$file" .yaml)
  started=$SECONDS
  # an old baseline can be inconsistent (v0.2.0 has no fixed_at): it gets no line, and admission refuses a tag whose
  # base has none
  if GOTOOLCHAIN=local /usr/local/bin/fscache-go/bin/go -C tools/requirements run . verify-freeze "$base"; then
    echo "freeze-ok $commit $base" >> freeze/freeze.txt
  else
    echo "build-freeze: $base is not consistent, no freeze-ok line" >&2
  fi
  echo "build-freeze: $base took $((SECONDS - started)) s"
done
[ -s freeze/freeze.txt ] || { echo "build-freeze: no baseline passed" >&2; exit 1; }
