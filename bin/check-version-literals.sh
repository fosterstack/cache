#!/usr/bin/env bash
# Fails if a public Markdown file contains a concrete version literal.
#
# Version literals in prose and commands rot at the next release. The class
# this catches has bitten twice: a README "Release pipeline (v0.1.0)" line and
# an entire RELEASING.md verification section built around one tag. Owner
# doctrine is that "we need not forget" must resolve to a mechanical check,
# never to memory — so this is that check.
#
# Write ${VER} (resolved at the top of the section), X.Y.Z as a placeholder, or
# :latest. If a literal is genuinely correct, mark the line and say why:
#
#   <!-- pinned: historical -->   a fact about the past. "v0.1.0 was cut four
#                                 times" is true forever and must not be
#                                 rewritten by a future release.
#   <!-- pinned: upstream -->     someone else's version — GOFIPS140=v1.0.0,
#                                 a Maven extension release. Not our staleness.
#
# Exceptions are deliberate and visible in the diff, which is the point: this
# stays a hard fail with no judgment calls inside it.
set -euo pipefail

cd "$(dirname "$0")/.."

mapfile -t files < <(
  { ls -1 ./*.md 2>/dev/null || true
    ls -1 docs/*.md 2>/dev/null || true
    ls -1 .vex/*.md 2>/dev/null || true
  } | sed 's|^\./||' | sort -u
)

# v?N.N.N, but only when not part of a longer dotted run — so an IP address
# like 203.0.113.10 in an example URL is not mistaken for a version.
pattern='(^|[^0-9.])v?[0-9]+\.[0-9]+\.[0-9]+([^0-9.]|$)'

blocked=0
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    n="${line%%:*}"
    text="${line#*:}"

    # Deliberate, documented exception.
    case "$text" in *'<!-- pinned:'*) continue ;; esac

    # Inside a URL: shields.io badge paths, XML namespace URIs, upstream
    # release links. These are addresses, not our version claims.
    stripped=$(printf '%s' "$text" | sed -E 's|https?://[^[:space:])"'"'"']+||g')
    if ! printf '%s' "$stripped" | grep -qE "$pattern"; then
      continue
    fi

    if [ "$blocked" -eq 0 ]; then
      echo "blocked — concrete version literals in public docs:" >&2
      echo >&2
    fi
    printf '  %s:%s\n      %s\n' "$f" "$n" "$(printf '%s' "$text" | sed 's/^[[:space:]]*//')" >&2
    blocked=1
  done < <(grep -nE "$pattern" "$f" 2>/dev/null || true)
done

if [ "$blocked" -ne 0 ]; then
  cat >&2 <<'MSG'

These go stale at the next release. Use ${VER} (resolved at the top of the
section), X.Y.Z as a placeholder, or :latest.

If the literal is correct as written, mark the line and say which kind:

  <!-- pinned: historical -->   a fact about the past, true forever
  <!-- pinned: upstream -->     someone else's version, not ours

See bin/check-version-literals.sh.
MSG
  exit 1
fi

echo "No unmarked version literals in public docs."
