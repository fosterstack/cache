#!/usr/bin/env bash
# persona-uat-decrypt.sh <run id> [key path, default ~/.config/fosterstack/persona-uat.key]
# Downloads a persona UAT run's encrypted artifact (gh run download, by its exact name) and decrypts it (openssl cms -decrypt) into a mode-700 directory it creates.
set -euo pipefail
run="${1:-}"
key="${2:-$HOME/.config/fosterstack/persona-uat.key}"
usage() { echo "usage: persona-uat-decrypt.sh <run id> [key path, default ~/.config/fosterstack/persona-uat.key]" >&2; exit 2; }
[[ "$run" =~ ^[0-9]+$ ]] || usage
[ -f "$key" ] || { echo "persona-uat-decrypt: no private key at $key" >&2; exit 2; }
out=$(mktemp -d "${TMPDIR:-/tmp}/persona-uat-XXXXXXXX")
chmod 700 "$out"
trap 'rc=$?; if [ "$rc" -ne 0 ]; then rm -rf "${out:?}"; fi' EXIT
art="$out/.artifact"
mkdir "$art"
gh run download "$run" -R "${GITHUB_REPOSITORY:-fosterstack/cache}" -n persona-uat-encrypted --dir "$art" >/dev/null
shopt -s nullglob
files=("$art"/*.cms)
[ "${#files[@]}" -gt 0 ] || { echo "persona-uat-decrypt: the run's artifact holds no .cms file" >&2; exit 1; }
for f in "${files[@]}"; do
  name=$(basename "$f" .cms)
  done_=""
  for inf in DER PEM SMIME; do
    if openssl cms -decrypt -inform "$inf" -inkey "$key" -in "$f" -out "$out/$name.txt" 2>/dev/null; then done_=1; break; fi
  done
  [ -n "$done_" ] || { echo "persona-uat-decrypt: $name.cms does not decrypt with the given key" >&2; exit 1; }
  # a wrong key can "succeed" with garbage: only a persona payload is accepted
  head -c 9 "$out/$name.txt" | grep -q '^VERDICT: ' && grep -q '^=== TRANSCRIPT ===$' "$out/$name.txt" || { echo "persona-uat-decrypt: $name.cms did not decrypt to a persona report" >&2; exit 1; }
  chmod 600 "$out/$name.txt"
done
rm -rf "${art:?}"
echo "decrypted into $out"
