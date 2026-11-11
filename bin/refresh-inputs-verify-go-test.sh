#!/usr/bin/env bash
# proves: REQ-SUP-001-AC34, REQ-SUP-001-AC35
# refresh-inputs.sh checks the Go archive with bin/verify-go.sh after it downloads it from go.dev/dl and before the sha256 is pinned/used;
# and the requirement text names every download source (AC35).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
ri="$root/bin/refresh-inputs.sh"

# order: the go.dev curl, then the .asc fetch, then verify-go.sh, all inside the want-go loop (the python step that pins the sha256 only runs after that loop ends)
dl=$(grep -n 'https://go.dev/dl/\$f"' "$ri" | head -1 | cut -d: -f1 || true)
vg=$(grep -n 'verify-go\.sh' "$ri" | head -1 | cut -d: -f1 || true)
asc=$(grep -n 'go\.dev/dl/.*\.asc' "$ri" | head -1 | cut -d: -f1 || true)
end=$(grep -n 'done <"\$tmp/want-go"' "$ri" | head -1 | cut -d: -f1 || true)
[ -n "$dl" ] && [ -n "$end" ] && ok "found the Go download ($dl) and the end of its loop ($end)" || bad "found the Go download and the end of its loop"
if [ -n "$vg" ]; then ok "refresh-inputs.sh calls bin/verify-go.sh"; else bad "refresh-inputs.sh calls bin/verify-go.sh"; fi
if [ -n "$asc" ]; then ok "refresh-inputs.sh downloads the .asc from go.dev/dl"; else bad "refresh-inputs.sh downloads the .asc from go.dev/dl"; fi
if [ -n "$vg" ] && [ -n "$dl" ] && [ "$vg" -gt "$dl" ]; then ok "verify-go.sh comes after the archive download"; else bad "verify-go.sh comes after the archive download"; fi
if [ -n "$vg" ] && [ -n "$asc" ] && [ "$vg" -gt "$asc" ]; then ok "verify-go.sh comes after the .asc download"; else bad "verify-go.sh comes after the .asc download"; fi
if [ -n "$vg" ] && [ -n "$end" ] && [ "$vg" -lt "$end" ]; then ok "verify-go.sh runs inside the loop, before the sha256 is checked and recorded"; else bad "verify-go.sh runs inside the loop, before the sha256 is checked and recorded"; fi
# a failing verify must stop the run: the call is guarded by die or runs under set -e, not ignored with || true
vl=$(sed -n "${vg:-0}p" "$ri" 2>/dev/null || true)
if [ -n "$vg" ] && ! grep -q '|| *true' <<<"$vl"; then ok "the verify-go.sh call is not ignored"; else bad "the verify-go.sh call is not ignored"; fi

# AC35: the requirement text lists every source
req="$root/requirements/requirements.yaml"
txt=$(awk '/id: REQ-SUP-001-AC35/{f=1;next} f&&/- id: /{exit} f' "$req")
if [ -n "$txt" ]; then ok "REQ-SUP-001-AC35 exists"; else bad "REQ-SUP-001-AC35 exists"; fi
for s in go trivy grype syft gitsign melange apko osv-scanner crane snyk kind docker-scout inspector-sbomgen Wolfi; do
  pat=$s; [ "$s" = go ] && pat='go\.dev'
  if grep -qiE -- "(^|[^a-z])${pat}([^a-z]|$)" <<<"$txt"; then ok "AC35 names $s"; else bad "AC35 names $s"; fi
done

echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]
