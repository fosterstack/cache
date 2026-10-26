#!/usr/bin/env bash
# bin/check-guide.sh --guide FILE --digests FILE --images DIR --out DIR
# Runs every command of the customer guide (rule 78) against the candidate, word for word (v0.3.0 rule 79; REQ-CHAIN-006-AC7).
# The guide's format (cache-3f's): every command is a line of a ```sh fenced block (a line ending in a backslash joins the next; lines
# starting with # are comments; other fenced blocks are prose), unattended, in customer order, at most ten in all. Placeholders are
# ALL-CAPS in angle brackets, each defined once in a list line before the first fence, as  - `<NAME>`: what it is. Check knows
# <IMAGE_REF> and <IMAGE_REF_FIPS> ($CANDIDATE_REPOSITORY@ the image-production / image-fips digest of the digest list), <TAG>
# ($GITHUB_REF_NAME) and <IDENTITY> (https://github.com/$GITHUB_REPOSITORY/.github/workflows/stage-sign.yml@$GITHUB_REF, Sign's
# keyless identity).
# A command RUNS only when it is a pipeline of the verify forms (cosign verify, cosign verify-attestation, cosign verify-blob,
# cosign verify-blob-attestation, gh attestation verify) and jq, with no other shell syntax ($ only inside single quotes), and every
# operand is a local file or a placeholder Check fills with a local value; a runnable command that exits non-zero fails the check.
# A verify command whose subject is an image reference (<IMAGE_REF>, <IMAGE_REF_FIPS>, a literal reference with a path and : or @, or
# oci://) needs a registry, which Check does not have (it holds the candidate as a file): it is NEVER run. It, and any other command the
# check cannot run, must be listed exactly, with its reason, in the cannot-run list beside the guide (GUIDE minus .md, plus
# .cannot-run.json: [{"command", "reason"}]); a listed command is not run and is recorded as not-run, else the check fails closed.
# Rule 79 (amended by the owner, Oct 10): a listed command is not run here; Release runs it right after publishing (its post-publish
# verification reads the same list) and fails the release run if it fails. So a listed entry is reported as not-run (exit 0) and AC7
# counts it covered; the list must be exact: a verify form, in the guide, once, with a reason. Writes OUT/guide-results.json.
set -euo pipefail
usage() { echo "usage: check-guide.sh --guide FILE --digests FILE --images DIR --out DIR" >&2; exit 2; }
fail() { echo "check-guide: $*" >&2; exit 1; }
guide="" digests="" images="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --guide) guide=$2 ;;
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$guide" ] && [ -n "$digests" ] && [ -n "$images" ] && [ -n "$out" ] || usage
[ -f "$guide" ] || fail "the guide $guide does not exist"
[ -d "$images" ] || fail "the image directory $images does not exist"
[ -f "$digests" ] || fail "the digest list $digests does not exist"
d=$(jq -r '."image-production" // empty' "$digests")
[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-production digest"
df=$(jq -r '."image-fips" // empty' "$digests")
[[ "$df" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-fips digest"
mkdir -p "$out"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# Read the guide and the cannot-run list, judge every command, substitute the candidate's values: one plan row per command, in order.
python3 bin/check-guide-plan.py "$guide" "${guide%.md}.cannot-run.json" "$d" "$tmp/plan.jsonl" "$df"

failed=0 n=0
: > "$tmp/results.jsonl"
while read -r row; do
  n=$((n + 1))
  cmd=$(jq -r .command <<< "$row"); run=$(jq -r '.run // empty' <<< "$row")
  if [ -z "$run" ]; then
    reason=$(jq -r .reason <<< "$row")
    echo "check-guide: NOT RUN (cannot run on a candidate: $reason): $cmd -- run right after publishing, in Release's post-publish verification"
    jq -cn --arg c "$cmd" --arg r "$reason" '{command: $c, exit: null, outcome: "not-run", reason: $r}' >> "$tmp/results.jsonl"
    continue
  fi
  echo "check-guide: \$ $run"
  rc=0; bash -o pipefail -c "$run" < /dev/null || rc=$?
  outcome=pass
  if [ "$rc" != 0 ]; then
    outcome=fail; failed=1; echo "check-guide: the guide command \`$cmd\` exited $rc against the candidate" >&2
  fi
  jq -cn --arg c "$cmd" --arg r "$run" --argjson e "$rc" --arg o "$outcome" '{command: $c, ran: $r, exit: $e, outcome: $o}' >> "$tmp/results.jsonl"
done < "$tmp/plan.jsonl"
jq -s --arg g "$guide" --arg d "$d" '{guide: $g, candidate: $d, commands: .}' "$tmp/results.jsonl" > "$out/guide-results.json"
[ "$failed" = 0 ] || exit 1
echo "check-guide: all $n guide commands passed or are listed as not runnable on a candidate"
