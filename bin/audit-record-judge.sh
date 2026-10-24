#!/usr/bin/env bash
# Gate 6 of the release process (REQ-REL-012, owner rule 6, Oct 23): the verdict job of agent-review-gate.yml, and its sweep, run this over the PR head with the
# DEFAULT branch checked out, so the judge and the writers policy are main's, never the pull request's.
#   audit-record-judge.sh HEAD_SHA BASE_REF       env: GH_TOKEN (read-only), GITHUB_REPOSITORY
# It reads the record branch audit/<HEAD_SHA> and its commit through the API (only when the base is main and the head is 40 lower-case hex, so nothing odd is ever put in
# a request path) and hands both answers, as data, to bin/audit-record.py. Exit 0: a base that is not main, or a good record. Exit 1: a missing or invalid record, with the reason.
# Exit 3: a GitHub API error (it says so; it is not a record defect and still fails closed). The writer treats only exit 1 as "no passing record" and never writes over a record it could not read.
set -uo pipefail
head=${1:-}; base=${2:-}; mode=${3:-}; rtag=${4:-}; rfile=${5:-}     # mode --release TAG TAG_OBJECT_FILE: gate 7, the tagged commit and the owner's approval line
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
args=()
patch=""
if [ "$mode" = --release ] && printf '%s' "$rtag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.[1-9][0-9]*$'; then patch=1; fi     # a patch tag needs no record: nothing is read
if [ "$base" = main ] && [ -z "$patch" ] && [[ "$head" =~ ^[0-9a-f]{40}$ ]]; then
  repo=${GITHUB_REPOSITORY:-}
  [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "audit-record: GITHUB_REPOSITORY is not owner/name" >&2; exit 1; }
  # read NAME URL: the answer in $tmp/NAME.json; 0 = read, 3 = not found (no such record), 4 = any other error
  read_api() {
    if gh api "$2" > "$tmp/$1.json" 2> "$tmp/err"; then return 0; fi
    rm -f "$tmp/$1.json"
    if grep -q -E 'HTTP 404|Not Found' "$tmp/err"; then return 3; fi
    echo "audit-record: could not read the record (GitHub API error on $2): $(tail -c 200 "$tmp/err" | tr '\n' ' ')" >&2
    return 4
  }
  read_api ref "repos/${repo}/git/ref/heads/audit/${head}"; rc=$?
  if [ "$rc" = 4 ]; then exit 3; fi
  if [ "$rc" = 0 ]; then
    args+=(--ref-json "$tmp/ref.json")
    rec=$(jq -r '.object.sha // empty' "$tmp/ref.json" 2>/dev/null || true)
    if [[ "$rec" =~ ^[0-9a-f]{40}$ ]]; then
      read_api commit "repos/${repo}/commits/${rec}"; rc=$?
      if [ "$rc" = 4 ]; then exit 3; fi
      [ "$rc" = 0 ] && args+=(--commit-json "$tmp/commit.json")
    fi
  fi
fi
if [ "$mode" = --release ]; then
  [ "$base" = main ] || { echo "audit-record: a release is judged against main" >&2; exit 1; }
  cd "$here" && exec python3 -I bin/audit-record.py release --tag "$rtag" --tag-object "$rfile" --tagged-sha "$head" --base-root . "${args[@]+"${args[@]}"}"
fi
cd "$here" && exec python3 -I bin/audit-record.py verify --head "$head" --base-ref "$base" --base-root . "${args[@]+"${args[@]}"}"
