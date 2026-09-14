#!/usr/bin/env bash
# Repeatable semantic regressions for the release authorization stage's
# acceptance-content policy (audit B02b). Runs the extracted validator
# against the FROZEN v0.2.0 baseline with fixtures mirroring the auditor's
# controls: valid, empty, missing-required, skip, invalid, fail,
# duplicate, unknown, and valid-with-publication. No network, no gh, no
# scanners - pure policy.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=v0.2.0
CHK=bin/authorize-acceptance-check.py
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# The complete required candidate set for the real frozen baseline.
mapfile -t REQ < <(python3 - <<'PY'
import yaml
f = yaml.safe_load(open("requirements/releases/v0.2.0.yaml"))
for b in f["release_blocking_acs"]:
    if b.get("phase") == "candidate" and str(b.get("method","")).startswith("acceptance"):
        print(b["id"])
PY
)
[ "${#REQ[@]}" -ge 1 ] || { echo "FAIL: no candidate ACs derived from the baseline"; exit 1; }

# Build a valid all-pass ac_results array from the real required set.
valid_json() { printf '%s\n' "${REQ[@]}" | python3 -c 'import sys,json; print(json.dumps([{"ac":a.strip(),"result":"pass"} for a in sys.stdin if a.strip()]))'; }

pass_count=0; fail_count=0
expect() { # description, expected-exit, file
  local desc="$1" want="$2" file="$3" got
  set +e
  python3 "$CHK" "$TAG" "$file" test >/dev/null 2>"$TMP/err"
  got=$?
  set -e
  if [ "$got" = "$want" ]; then
    pass_count=$((pass_count+1))
  else
    fail_count=$((fail_count+1))
    echo "FAIL: ${desc} (exit ${got}, want ${want}): $(cat "$TMP/err")"
  fi
}

valid_json > "$TMP/valid.json"
expect "valid all-pass" 0 "$TMP/valid.json"

# valid + publication deferral
python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); a+=[{"ac":"REQ-REL-001-AC1","result":"deferred-to-publication"},{"ac":"REQ-REL-002-AC1","result":"deferred-to-publication"}]; json.dump(a,open(sys.argv[1],"w"))' "$TMP/valid.json"
cp "$TMP/valid.json" "$TMP/valid-pub.json"; expect "valid + publication deferral" 0 "$TMP/valid-pub.json"

echo '[]' > "$TMP/empty.json"; expect "empty ac_results" 1 "$TMP/empty.json"

# missing one required
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); json.dump(a[1:],open(sys.argv[1],"w"))' "$TMP/missing.json"
expect "missing required AC" 1 "$TMP/missing.json"

# skip a required
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); a[0]["result"]="skip"; json.dump(a,open(sys.argv[1],"w"))' "$TMP/skip.json"
expect "required AC skip" 1 "$TMP/skip.json"

# invalid token
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); a[0]["result"]="banana"; json.dump(a,open(sys.argv[1],"w"))' "$TMP/invalid.json"
expect "invalid result token" 1 "$TMP/invalid.json"

# fail a required
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); a[0]["result"]="fail"; json.dump(a,open(sys.argv[1],"w"))' "$TMP/fail.json"
expect "required AC fail" 1 "$TMP/fail.json"

# duplicate id
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); a.append(a[0]); json.dump(a,open(sys.argv[1],"w"))' "$TMP/dup.json"
expect "duplicate AC id" 1 "$TMP/dup.json"

# unknown id
valid_json | python3 -c 'import sys,json; a=json.load(sys.stdin); a.append({"ac":"REQ-UNKNOWN-001-AC1","result":"pass"}); json.dump(a,open(sys.argv[1],"w"))' "$TMP/unknown.json"
expect "unknown AC id" 1 "$TMP/unknown.json"

echo "authorize-acceptance-check: ${pass_count} passed, ${fail_count} failed"
[ "$fail_count" -eq 0 ]
