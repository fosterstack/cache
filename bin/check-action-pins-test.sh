#!/usr/bin/env bash
# Proves bin/check-action-pins.py (row 78): one throwaway repo per case, each with one fixture workflow.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
SHA=3d3c42e5aac5ba805825da76410c181273ba90b1
DIG=sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

# case_ <name> <expect ok|bad> <workflow text> [setup commands, run in the fixture root]
case_() {
  local name=$1 expect=$2 d="$work/$1"
  mkdir -p "$d/.github/workflows"; printf '%s\n' "$3" > "$d/.github/workflows/w.yml"
  if [ -n "${4:-}" ]; then (cd "$d" && eval "$4"); fi
  if python3 "$here/check-action-pins.py" "$d" >/dev/null 2>&1; then got=ok; else got=bad; fi
  if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $name → $got"
  else failn=$((failn+1)); echo "FAIL $name → $got (want $expect)"; fi
  # VERBOSE=1: show why each case was judged (the first finding), to prove a red is the intended red
  if [ -n "${VERBOSE:-}" ]; then python3 "$here/check-action-pins.py" "$d" 2>&1 | head -1 | sed "s#^#     #" || true; fi
}
head='on: push
jobs:
  j:
    runs-on: ubuntu-latest'

# --- the forms that pass
case_ pinned               ok  "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ pinned-quoted        ok  "$head
    steps:
      - uses: 'actions/checkout@$SHA' # v7.0.1"
case_ pinned-subpath       ok  "$head
    steps:
      - uses: github/codeql-action/init@$SHA # v4.1.0"
case_ remote-reusable      ok  "on: push
jobs:
  j:
    uses: octo/repo/.github/workflows/x.yml@$SHA # v1.2.3"
case_ local-reusable       ok  "on: push
jobs:
  j:
    uses: ./.github/workflows/w.yml"
case_ docker-digest        ok  "$head
    steps:
      - uses: docker://alpine@$DIG"
case_ container-digest     ok  "$head
    container: alpine@$DIG
    steps:
      - run: true"
case_ service-digest       ok  "$head
    services:
      db:
        image: postgres@$DIG
    steps:
      - run: true"
case_ with-image-is-data   ok  "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          image: ghcr.io/x/y@\${{ env.D }}"

case_ job-named-image      ok  "on: push
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ env-image-is-data    ok  "$head
    env:
      image: alpine:3.20
    steps:
      - run: true"
case_ service-scalar-digest ok "$head
    services:
      db: postgres@$DIG
    steps:
      - run: true"

# --- the handoff's four: all red
case_ tag                  bad "$head
    steps:
      - uses: actions/checkout@v7"
case_ branch               bad "$head
    steps:
      - uses: actions/checkout@main"
case_ short-sha            bad "$head
    steps:
      - uses: actions/checkout@3d3c42e # v7.0.1"
case_ sha-no-comment       bad "$head
    steps:
      - uses: actions/checkout@$SHA"

# --- bypass attempts: all red
case_ uppercase-sha        bad "$head
    steps:
      - uses: actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1 # v7.0.1"
case_ sha-in-comment-only  bad "$head
    steps:
      - uses: actions/checkout@v7 # $SHA"
case_ comment-not-version  bad "$head
    steps:
      - uses: actions/checkout@$SHA # pinned"
case_ comment-next-line    bad "$head
    steps:
      - uses: actions/checkout@$SHA
        # v7.0.1"
case_ key-case             bad "$head
    steps:
      - Uses: actions/checkout@v7"
case_ key-whitespace       bad "$head
    steps:
      - \"uses \": actions/checkout@v7"
case_ flow-style           bad "$head
    steps: [{uses: actions/checkout@v7}]"
case_ anchor-alias         bad "x-step: &s
  uses: actions/checkout@v7
$head
    steps:
      - *s"
case_ merge-key            bad "x-step: &s
  uses: actions/checkout@v7
$head
    steps:
      - <<: *s"
case_ second-document      bad "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
---
$head
    steps:
      - uses: actions/checkout@v7"
case_ folded-scalar        bad "$head
    steps:
      - uses: >-
          actions/checkout@$SHA"
case_ templated            bad "$head
    steps:
      - uses: \${{ vars.ACTION }}"
case_ matrix-expression    bad "$head
    strategy:
      matrix:
        a: ['actions/checkout@v7']
    steps:
      - uses: \${{ matrix.a }}"
case_ not-a-string         bad "$head
    steps:
      - uses: [actions/checkout@v7]"
case_ docker-tag           bad "$head
    steps:
      - uses: docker://alpine:3.20"
case_ container-tag        bad "$head
    container: alpine:3.20
    steps:
      - run: true"
case_ container-map-tag    bad "$head
    container:
      image: alpine:3.20
    steps:
      - run: true"
case_ service-tag          bad "$head
    services:
      db:
        image: postgres:16
    steps:
      - run: true"
case_ local-escapes        bad "$head
    steps:
      - uses: ./../elsewhere" "mkdir -p ../elsewhere; printf 'runs:\n  using: composite\n  steps: []\n' > ../elsewhere/action.yml"
case_ local-missing        bad "$head
    steps:
      - uses: ./.github/actions/nope"
case_ nested-action-tag    bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > .github/actions/x/action.yml"
case_ action-yml-anywhere  bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > tools/a/action.yaml"
case_ docker-action-file   bad "$head
    steps:
      - run: true" "mkdir -p tools/d; printf 'runs:\n  using: docker\n  image: Dockerfile\n' > tools/d/action.yml"
case_ non-yml-in-workflows bad "$head
    steps:
      - run: true" "cp .github/workflows/w.yml .github/workflows/x.YML.txt"
case_ nested-workflow-dir  bad "$head
    steps:
      - run: true" "mkdir -p .github/workflows/sub; printf 'on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v7\n' > .github/workflows/sub/y.yml"
case_ unparsable           bad "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
     bad: [indent"


# --- adversarial round 1 (audits/2026-09-30/pins/round1): all red
case_ local-action-refused bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@$SHA # v7.0.1\n' > .github/actions/x/action.yml"
case_ local-action-upper   bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > .github/actions/x/ACTION.YML"
case_ upper-manifest-found bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > tools/a/Action.Yml"
case_ local-workflow-step  bad "$head
    steps:
      - uses: ./.github/workflows/w.yml"
case_ job-named-with-cont  bad "on: push
jobs:
  with:
    runs-on: ubuntu-latest
    container: alpine:3.20
    steps:
      - run: true"
case_ job-named-with-uses  bad "on: push
jobs:
  with:
    uses: octo/repo/.github/workflows/x.yml@main"
case_ job-named-env-cont   bad "on: push
jobs:
  env:
    runs-on: ubuntu-latest
    container: alpine:3.20
    steps:
      - run: true"
case_ service-named-with   bad "$head
    services:
      with:
        image: redis:7
    steps:
      - run: true"
case_ service-scalar-tag   bad "$head
    services:
      db: redis:7
    steps:
      - run: true"
case_ service-expression   bad "$head
    services:
      db: \${{ matrix.svc }}
    steps:
      - run: true"
case_ services-expression  bad "$head
    services: \${{ fromJSON('{\"db\":{\"image\":\"redis:7\"}}') }}
    steps:
      - run: true"
case_ service-no-image     bad "$head
    services:
      db:
        ports: ['5432']
    steps:
      - run: true"
case_ expression-key       bad "$head
    steps:
      - \"\${{ 'uses' }}\": actions/checkout@v7"
case_ expression-key-action bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - \"\${{ '\\''uses'\\'' }}\": actions/checkout@v7\n' > tools/a/action.yaml"
case_ comment-in-string    bad "$head
    steps:
      - {uses: actions/checkout@$SHA, name: \"hello # v7.0.1 \"} # v0.0.0"
case_ comment-after-other  bad "$head
    steps:
      - uses: actions/checkout@$SHA
        name: x # v7.0.1"
case_ anchor-only-pinned   bad "$head
    steps:
      - &s uses: actions/checkout@$SHA # v7.0.1"
case_ uses-odd-position    bad "on: push
uses: actions/checkout@v7
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: true"
case_ symlinked-workflow   bad "$head
    steps:
      - run: true" "printf 'on: push\n' > ../elsewhere-\$\$.yml; ln -s \"\$(cd .. && pwd)/elsewhere-\$\$.yml\" .github/workflows/s.yml"
case_ docker-action-image  bad "$head
    steps:
      - run: true" "mkdir -p tools/d; printf 'runs:\n  using: docker\n  image: docker://alpine:3.20\n' > tools/d/action.yml"

echo "check-action-pins: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
