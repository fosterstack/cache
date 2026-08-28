#!/usr/bin/env bash
# Shared allowlist logic for public-repo hygiene, called by both
# .githooks/pre-commit (local, every commit) and
# .github/workflows/hygiene.yml (CI backstop, catches anything committed
# without the hook installed/enabled). One definition, so the two never
# drift apart. Mirrors the same mechanism in fosterstack/www.
#
# fosterstack/cache is PUBLIC. The specific thing this guards against is
# the private side of the company leaking into it — ops runbooks, sprint
# state, the brief, credential architecture, the owner's real identity —
# which hard_deny forbids but which nothing mechanical was checking on
# this repo until now. Making the repo private later does not undo a push.
#
# Reads file paths, one per line, on stdin. Exits 1 (with the offending
# paths listed) if any path doesn't match an allowed pattern.

set -euo pipefail

ALLOW_PATTERNS=(
  # Go source and module graph — the actual product.
  '^(cmd|internal)/[A-Za-z0-9._/-]+\.go$'
  '^go\.(mod|sum)$'

  # Repo-root documentation and policy.
  '^(README|SECURITY|CONTRIBUTING|RELEASING)\.md$'
  '^LICENSE$'

  # Published documentation.
  '^docs/[A-Za-z0-9._-]+\.md$'

  # Build, lint, scan and release configuration.
  '^\.(gitignore|golangci\.yml|goreleaser\.yaml|grype\.yaml|ko\.yaml)$'

  # CI/CD. Note these are ALSO gated in autoMode soft_deny — the allowlist
  # says a workflow file may live here, not that it may change freely.
  '^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$'
  '^\.github/dependabot\.yml$'

  # This mechanism itself.
  '^\.githooks/pre-commit$'
  '^bin/check-file-allowlist\.sh$'

  # The real Gradle project the benchmark builds against.
  '^bench/gradle-sample/gradlew(\.bat)?$'
  '^bench/gradle-sample/([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.(kts|java|properties|jar)$'
)

blocked=()
while IFS= read -r path; do
  [ -z "$path" ] && continue
  ok=0
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    if [[ "$path" =~ $pattern ]]; then
      ok=1
      break
    fi
  done
  if [ "$ok" -eq 0 ]; then
    blocked+=("$path")
  fi
done

if [ "${#blocked[@]}" -gt 0 ]; then
  echo "blocked — file(s) not on the public-repo allowlist:" >&2
  for f in "${blocked[@]}"; do
    echo "  $f" >&2
  done
  echo "" >&2
  echo "fosterstack/cache is a PUBLIC repo. If a file genuinely belongs here," >&2
  echo "add a pattern to ALLOW_PATTERNS in bin/check-file-allowlist.sh." >&2
  echo "If it is ops/sprint/brief content, it does not belong here at all." >&2
  exit 1
fi
