#!/usr/bin/env bash
# The freeze job (rule 1 of the sandboxed build): the requirements tool is Go source of the tagged commit, so its check runs here, in a job of its own, and never inside Build.
# For every baseline file of the tagged commit it runs verify-freeze, prints the seconds it took, and writes one `freeze-ok BASE` line to freeze/freeze.txt. Build's admission reads that file.
set -euo pipefail
GO=/usr/local/bin/fscache-go/bin/go      # the Go that `bash bin/install-scanner.sh go` installs; the runner's own go is never used
[ -x "$GO" ] || { echo "build-freeze: the pinned Go is not at $GO" >&2; exit 2; }
mkdir -p freeze
: > freeze/freeze.txt
for file in requirements/releases/*.yaml; do
  base=$(basename "$file" .yaml)
  started=$SECONDS
  GOTOOLCHAIN=local "$GO" -C tools/requirements run . verify-freeze "$base"
  echo "freeze-ok $base" >> freeze/freeze.txt
  echo "build-freeze: $base took $((SECONDS - started)) s"
done
