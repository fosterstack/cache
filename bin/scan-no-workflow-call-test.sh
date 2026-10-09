#!/usr/bin/env bash
# proves: REQ-SCAN-015-AC1
# The two workflow files that carry the scanner cloud identities (scan.yml, main-candidate-rescan.yml) can never be
# called as reusable workflows: neither declares `on: workflow_call`, and no workflow or composite action names either
# one in a `uses:`. The cloud trust is pinned to the FILE (job_workflow_ref), not to its caller, so a callable file
# would let any other workflow run under that identity (ops#107; advisor-accepted Oct 9, serves the 0345 hardening).
# The judge is first proven on a known-good fixture tree and on each mutated copy (a judge that cannot fail proves
# nothing), then applied to the real repository, which must pass. Needs python3 with PyYAML (preinstalled on
# ubuntu-24.04 runners).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0

judge() { python3 - "$1" <<'PY'
import glob, os, re, sys, yaml

tree = sys.argv[1]
GUARDED = ("scan.yml", "main-candidate-rescan.yml")
NAMES = r"(scan|main-candidate-rescan)\.ya?ml"
CALLS_GUARDED = re.compile(r"(^|/)\.github/workflows/" + NAMES + r"(@|$)")
bad = []

def load(path):
    # BaseLoader keeps the key `on` as the string "on" (the default loader turns it into True)
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.BaseLoader) or {}

def declares_workflow_call(on):
    if isinstance(on, dict):
        return "workflow_call" in on
    if isinstance(on, list):
        return "workflow_call" in on
    return on == "workflow_call"

def uses_values(node):
    """Every value of a `uses` key anywhere in the document (job level, step level, composite action steps)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "uses" and isinstance(value, str):
                yield value
            else:
                yield from uses_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from uses_values(item)

for name in GUARDED:
    path = os.path.join(tree, ".github", "workflows", name)
    if not os.path.exists(path):
        bad.append("%s is missing" % name)
        continue
    if declares_workflow_call(load(path).get("on")):
        bad.append("%s declares workflow_call" % name)

files = []
for pattern in ("*.yml", "*.yaml"):
    files += glob.glob(os.path.join(tree, ".github", "workflows", pattern))
    files += glob.glob(os.path.join(tree, ".github", "actions", "**", pattern), recursive=True)
for path in sorted(files):
    for value in uses_values(load(path)):
        if CALLS_GUARDED.search(value.strip()):
            bad.append("%s calls %s" % (os.path.relpath(path, tree), value.strip()))

print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}

expect() { # expect ok|caught LABEL TREE
  local out rc=0
  out=$(judge "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: $out)"
  else failn=$((failn + 1)); echo "FAIL $2 -> $out"; fi
}

# a known-good tree: the two guarded files with ordinary triggers, a neighbour workflow and a composite action
fixture() { # fixture NAME  -> prints the tree path
  local t="$work/$1"
  mkdir -p "$t/.github/workflows" "$t/.github/actions/x"
  printf 'name: scan\non:\n  pull_request:\n  push:\n    branches: [main]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo scan\n' > "$t/.github/workflows/scan.yml"
  printf 'name: rescan\non:\n  schedule:\n    - cron: "41 7 * * *"\n  workflow_dispatch: {}\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo rescan\n' > "$t/.github/workflows/main-candidate-rescan.yml"
  printf 'name: other\non: push\njobs:\n  build:\n    uses: ./.github/workflows/stage-build.yml\n' > "$t/.github/workflows/other.yml"
  printf 'name: x\nruns:\n  using: composite\n  steps:\n    - run: echo x\n      shell: bash\n' > "$t/.github/actions/x/action.yml"
  echo "$t"
}
mutate() { # mutate NAME FILE 'content'  (replace the whole file in a fresh fixture)
  local t; t=$(fixture "$1")
  printf '%s\n' "$3" > "$t/$2"
  echo "$t"
}

expect ok "fixture: the known-good tree passes" "$(fixture good)"

# 1. the guarded files declare workflow_call (map, list, scalar and flow-map forms of `on:`)
expect caught "scan.yml: workflow_call as a key beside others" "$(mutate m1 .github/workflows/scan.yml $'on:\n  pull_request:\n  workflow_call:\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: on: [push, workflow_call]" "$(mutate m2 .github/workflows/scan.yml $'on: [push, workflow_call]\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: on: workflow_call (scalar)" "$(mutate m3 .github/workflows/scan.yml $'on: workflow_call\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: on: {workflow_call: {}} (flow map)" "$(mutate m4 .github/workflows/scan.yml $'on: {workflow_call: {}}\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "main-candidate-rescan.yml: workflow_call with inputs" "$(mutate m5 .github/workflows/main-candidate-rescan.yml $'on:\n  schedule:\n    - cron: "41 7 * * *"\n  workflow_call:\n    inputs:\n      x:\n        type: string\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "main-candidate-rescan.yml: on: [schedule, workflow_call]" "$(mutate m6 .github/workflows/main-candidate-rescan.yml $'on: [schedule, workflow_call]\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"

# 2. another workflow calls a guarded file (local path, other repository, job level, step level, odd spacing, composite action)
expect caught "job-level uses: ./.github/workflows/scan.yml" "$(mutate c1 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    uses: ./.github/workflows/scan.yml')"
expect caught "job-level uses: ./.github/workflows/main-candidate-rescan.yml" "$(mutate c2 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    uses: ./.github/workflows/main-candidate-rescan.yml')"
expect caught "uses: fosterstack/cache/.github/workflows/scan.yml@<sha>" "$(mutate c3 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    uses: fosterstack/cache/.github/workflows/scan.yml@3d3c42e5aac5ba805825da76410c181273ba90b1')"
expect caught "uses: another repository's main-candidate-rescan.yml@main" "$(mutate c4 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    uses: someone/else/.github/workflows/main-candidate-rescan.yml@main')"
expect caught "step-level uses of scan.yml" "$(mutate c5 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/workflows/scan.yml')"
expect caught "quoted uses with spaces around the path" "$(mutate c6 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    uses: "  ./.github/workflows/scan.yml  "')"
expect caught "a .yaml neighbour workflow calls scan.yml" "$(mutate c7 .github/workflows/other.yaml $'name: o2\non: push\njobs:\n  b:\n    uses: ./.github/workflows/scan.yml')"
expect caught "a composite action step names scan.yml" "$(mutate c8 .github/actions/x/action.yml $'name: x\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/workflows/scan.yml')"
expect caught "a nested composite action under .github/actions/a/b" "$(t=$(fixture c9); mkdir -p "$t/.github/actions/a/b"; printf 'name: y\nruns:\n  using: composite\n  steps:\n    - uses: ./.github/workflows/main-candidate-rescan.yml\n' > "$t/.github/actions/a/b/action.yaml"; echo "$t")"

# 3. the guarded files themselves must exist (a renamed file would silently escape the check)
expect caught "scan.yml is missing" "$(t=$(fixture r1); rm "$t/.github/workflows/scan.yml"; echo "$t")"
expect caught "main-candidate-rescan.yml is missing" "$(t=$(fixture r2); rm "$t/.github/workflows/main-candidate-rescan.yml"; echo "$t")"

# 4. things that must stay allowed: neighbours calling other stage files, a guarded name inside a run: string
expect ok "a neighbour that calls stage-build.yml and mentions scan.yml in a run: line" "$(mutate k1 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh run list --workflow scan.yml')"

# the real repository (green today)
expect ok "the real repository: neither file is callable and nothing calls them" "$root"

EXPECT=20
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
