#!/usr/bin/env bash
# The reviewer's version: the sha256 of the sha256sum lines of the files that decide its verdict.
# The root folder is its argument (default: the current folder); --files prints the names instead. A file that
# cannot be read fails it.
set -euo pipefail
files=(
  bin/dependabot-reviewer.py
  .github/policy/dependabot-reviewer-prompt.txt
  .github/workflows/dependabot-reviewer.yml
  .github/policy/required-checks.json
  bin/required-check-guard.sh
)
if [ "${1:-}" = --files ]; then printf '%s\n' "${files[@]}"; exit 0; fi
cd "${1:-.}"
sha256sum "${files[@]}" | sha256sum | cut -d' ' -f1
