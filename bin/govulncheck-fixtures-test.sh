#!/usr/bin/env bash
# Materialize the govulncheck FIXTURE modules and verify them — without ever letting
# GitHub's dependency graph index them.
#
# The tiny Go modules under .github/agent/fixtures/govulncheck/src/ deliberately require a
# VULNERABLE dependency (golang.org/x/text v0.3.0) — they are the provenance for the checked-in
# govulncheck JSON streams (reachable / imported-not-called; GO-2021-0113). If their manifests
# were named go.mod / go.sum, the dependency graph would index them and Dependency review /
# Dependabot would flag the deliberate vulnerable pin. So they are stored as go.mod.fixture /
# go.sum.fixture (names no ecosystem recognizes) and MATERIALIZED into a throwaway temp module
# here at test time. Nothing consumes these modules at runtime — tests read the JSON — this
# harness only proves the fixtures stay materializable and well-formed, and that no plain
# go.mod / go.sum is tracked under src/ (which would re-index them).
set -uo pipefail
cd "$(dirname "$0")/.."
SRC=.github/agent/fixtures/govulncheck/src

pass=0; fail=0
ok()  { echo "ok:   $1"; pass=$((pass+1)); }
no()  { echo "FAIL: $1 — $2"; fail=$((fail+1)); }

# 1) No plain go.mod / go.sum / *.go may be tracked under the fixture src tree. A go.mod/go.sum
#    would re-index the deliberate vulnerable pin in the dependency graph; a plain *.go (with the
#    manifests gone) would fold these package-main sources into the PARENT module and break
#    `go build/vet/test ./...` and gosec with type errors. Everything here must be a .fixture.
indexed="$(git ls-files "$SRC" | grep -E '/(go\.(mod|sum)|[^/]+\.go)$' || true)"
if [ -z "$indexed" ]; then ok "nothing indexable (go.mod/go.sum/*.go) tracked under $SRC — dirs are inert to Go tooling"
else no "an indexable file is tracked under $SRC (rename it to .fixture)" "$indexed"; fi

# 2) Every fixture module materializes into a temp module and is well-formed.
found=0
for mf in "$SRC"/*/go.mod.fixture; do
  [ -e "$mf" ] || continue
  found=$((found+1))
  dir="$(dirname "$mf")"; name="$(basename "$dir")"
  tmp="$(mktemp -d)"
  # materialize: every .fixture becomes its real name ONLY inside the throwaway module
  cp "$mf" "$tmp/go.mod"
  [ -e "$dir/go.sum.fixture" ] && cp "$dir/go.sum.fixture" "$tmp/go.sum"
  for gf in "$dir"/*.go.fixture; do
    [ -e "$gf" ] && cp "$gf" "$tmp/$(basename "${gf%.fixture}")"
  done
  goodmod="$(grep -c '^module ' "$tmp/go.mod")"; goodmod="${goodmod:-0}"
  hasdep="$(grep -c 'golang.org/x/text v0.3.0' "$tmp/go.mod")"; hasdep="${hasdep:-0}"
  hasgo="$(ls "$tmp"/*.go >/dev/null 2>&1 && echo 1 || echo 0)"
  # if the Go toolchain is present, `go mod edit -json` validates the materialized manifest
  # offline (no module download); skip cleanly when go is absent.
  goedit=1
  if command -v go >/dev/null 2>&1; then
    (cd "$tmp" && go mod edit -json >/dev/null 2>&1) || goedit=0
  fi
  if [ "$goodmod" -ge 1 ] 2>/dev/null && [ "$hasdep" -ge 1 ] 2>/dev/null && [ "$hasgo" = 1 ] && [ "$goedit" = 1 ]; then
    ok "materialized $name into a temp module (valid go.mod + deliberate vulnerable pin + sources)"
  else
    no "materialize $name" "module=$goodmod dep=$hasdep sources=$hasgo go_mod_edit=$goedit"
  fi
  rm -rf "$tmp"
done
[ "$found" -ge 1 ] && ok "found $found fixture module(s)" || no "at least one *.go.mod.fixture under $SRC" "found=0"

echo "----"
echo "govulncheck-fixtures: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
