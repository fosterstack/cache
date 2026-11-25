#!/usr/bin/env bash
# Prints the version being built: the tag on a v* tag push, on a release/vX.Y push the next patch of that line.
set -euo pipefail
kind=${GITHUB_REF#refs/}
kind=${kind%%/*}
line=${GITHUB_REF_NAME#release/}
if [ "$kind" = tags ]; then
  echo "$GITHUB_REF_NAME"
elif [ "$kind" = heads ] && [ "$line" != "$GITHUB_REF_NAME" ]; then
  last=$(git tag --list "$line.*" | grep -E '^[v0-9.]+$' | sort -V | tail -n 1 || true)
  [ -n "$last" ] || { echo "$line.0"; exit; }
  patch=${last##*.}
  echo "$line.$((patch + 1))"
else
  echo "release-version: $GITHUB_REF is neither a tag nor a release branch" >&2
  exit 1
fi
