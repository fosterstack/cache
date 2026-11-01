#!/usr/bin/env bash
# bin/witness-sign-staged.sh STAGED SIGNED  --  Sign's signing step for the records of the jobs that hold no identity token: Build's and Rebuild's (REQ-CHAIN-004-AC2, REQ-CHAIN-005-AC4) and Check's four steps (REQ-REL-011-AC1).
# the records step of the verifier (its sign-records subcommand) has already checked every local record against the artifacts Sign received and staged, under STAGED/<record-dir>/, each
# record's payload bytes (STEP-collection.payload) and its data files; it printed nothing to sign on any refusal; STAGED/plan.txt is that printed list (one line per record: staged payload path, TAB, signed record path). This helper signs exactly the payloads on that list, and refuses before any token request when the staged tree holds anything else or a PLAN line is not of the fixed form. It signs each payload keyless
# (the job's identity token, audience sigstore, held in a shell variable and handed to Witness through a one-read process substitution; the request
# variables are unset first) into SIGNED/<record-dir>/STEP-collection.json with the Sigstore timestamp, copies the data files unchanged, and then runs the
# self-check `bin/chain-verify.py verify` on every signed record (identity stage-sign.yml, the committed template made for GITHUB_REF), so a signing that
# did not produce a valid Sign-identity record stops the job. It builds nothing and runs no stage script.
set -euo pipefail
staged="$1"
signed="$2"
plan="$staged/plan.txt"
[ -f "$plan" ] && [ ! -L "$plan" ] || { echo "witness-sign-staged: no plan.txt in $staged" >&2; exit 1; }
n=0
while read -r line; do
  payload=$(printf '%s' "$line" | cut -f1)
  final=$(printf '%s' "$line" | cut -f2 -s)
  extra=$(printf '%s' "$line" | cut -f3- -s)
  case "$payload" in "$staged"/*/*-collection.payload) ;; *) echo "witness-sign-staged: plan line is not a staged payload: $payload" >&2; exit 1 ;; esac
  rest=${payload#"$staged"/}
  name=${rest%%/*}
  file=${rest#*/}
  step=${file%-collection.payload}
  printf '%s' "$name" | grep -Eq '^witness-[A-Za-z0-9.-]+$' || { echo "witness-sign-staged: bad record directory name in the plan: $payload" >&2; exit 1; }
  case "$file" in *[/]*) echo "witness-sign-staged: plan line is not a staged payload: $payload" >&2; exit 1 ;; esac
  case "$step" in apk|build|rapk|rebuild|scanners|acceptance|runtime|arm64) ;; *) echo "witness-sign-staged: unknown step in the plan: $payload" >&2; exit 1 ;; esac
  if [ -n "$extra" ] || [ "$final" != "$signed/$name/$step-collection.json" ] || [ ! -f "$payload" ] || [ -L "$payload" ]; then
    echo "witness-sign-staged: plan line does not match the staged tree: $payload" >&2; exit 1
  fi
  n=$((n + 1))
done < "$plan"
[ "$n" -gt 0 ] || { echo "witness-sign-staged: the plan is empty" >&2; exit 1; }
uniq_n=$(cut -f1 "$plan" | sort -u | wc -l | tr -d ' ')
[ "$uniq_n" -eq "$n" ] || { echo "witness-sign-staged: the plan lists a payload twice" >&2; exit 1; }
seen=0
dirs=0
for d in "$staged"/*; do
  [ "$d" = "$plan" ] && continue
  [ -d "$d" ] && [ ! -L "$d" ] || { echo "witness-sign-staged: staged tree holds a non-directory: $d" >&2; exit 1; }
  cut -f1 "$plan" | grep -Fq -- "$d/" || { echo "witness-sign-staged: staged directory not on the plan: $d" >&2; exit 1; }
  dirs=$((dirs + 1))
  files=0
  for f in "$d"/*; do
    [ -f "$f" ] && [ ! -L "$f" ] || { echo "witness-sign-staged: staged tree holds a non-file: $f" >&2; exit 1; }
    files=$((files + 1))
    case "$f" in *.payload) cut -f1 "$plan" | grep -Fxq -- "$f" || { echo "witness-sign-staged: staged payload not on the plan: $f" >&2; exit 1; }; seen=$((seen + 1)) ;; esac
  done
  listed=$(ls -A "$d" | wc -l | tr -d ' ')
  [ "$listed" -eq "$files" ] || { echo "witness-sign-staged: staged directory holds a hidden entry: $d" >&2; exit 1; }
done
top=$(ls -A "$staged" | wc -l | tr -d ' ')
want=$((dirs + 1))
[ "$top" -eq "$want" ] || { echo "witness-sign-staged: the staged root holds an entry that is neither a planned directory nor plan.txt" >&2; exit 1; }
[ "$seen" -eq "$n" ] || { echo "witness-sign-staged: the plan names a payload the staged tree lacks" >&2; exit 1; }
tok=$(sh bin/loopback-get.sh -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)
echo "::add-mask::$tok"
unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL
unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL SIGSTORE_ID_TOKEN
python3 -I -B bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --ref "$GITHUB_REF" --out policy.json
while read -r line; do
  payload=$(printf '%s' "$line" | cut -f1)
  final=$(printf '%s' "$line" | cut -f2 -s)
  dir=$(dirname "$payload")
  name=$(basename "$dir")
  base=$(basename "$payload" .payload)
  step=${base%-collection}
  mkdir -p "$signed/$name"
  for f in "$dir"/*; do case "$f" in *.payload) ;; *) cat "$f" > "$signed/$name/$(basename "$f")" ;; esac; done
  witness sign -f "$payload" -t application/vnd.in-toto+json \
    --signer-fulcio-url https://fulcio.sigstore.dev \
    --signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com \
    --signer-fulcio-oidc-client-id sigstore \
    --signer-fulcio-token-path <(printf %s "$tok") \
    --timestamp-servers https://timestamp.sigstore.dev/api/v1/timestamp \
    -o "$final"
  case "$step" in apk|build) stage=build ;; rapk|rebuild) stage=rebuild ;; scanners|acceptance|runtime|arm64) stage=check ;; *) echo "witness-sign-staged: unknown step $step" >&2; exit 1 ;; esac
  python3 -I -B bin/chain-verify.py verify --policy policy.json --stage "$stage" --record "$final"
done < "$plan"
