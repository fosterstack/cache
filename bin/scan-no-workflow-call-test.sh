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
import os, sys, yaml

tree = sys.argv[1]
# The only triggers each guarded file may have. Anything else (workflow_call in any spelling or case, a merge key,
# a missing `on`) fails: the allowlist is the rule, workflow_call is just the case we care about most.
ALLOWED = {
    "scan.yml": {"pull_request", "push"},
    "main-candidate-rescan.yml": {"schedule", "workflow_dispatch"},
}
GUARDED_STEMS = ("scan", "main-candidate-rescan")
bad = []

def read(path):
    with open(path) as fh:
        return fh.read()

def triggers(on):
    if isinstance(on, dict):
        return set(on)
    if isinstance(on, list):
        return set(on)
    return {on} if isinstance(on, str) and on else None

def check_guarded(name, text):
    # No anchors, aliases or merge keys anywhere in a guarded file: they could hide a trigger from this reader.
    for ev in yaml.parse(text):
        if getattr(ev, "anchor", None) or isinstance(ev, yaml.AliasEvent):
            return "%s uses a YAML anchor or alias" % name
        if isinstance(ev, yaml.ScalarEvent) and ev.value == "<<":
            return "%s uses a YAML merge key" % name
    doc = yaml.load(text, Loader=yaml.BaseLoader) or {}
    if not isinstance(doc, dict) or "on" not in doc:
        return "%s has no literal top-level `on` key" % name
    found = triggers(doc["on"])
    if not found:
        return "%s has an empty `on`" % name
    extra = sorted(found - ALLOWED[name])
    if extra:
        return "%s has triggers outside its allowlist: %s" % (name, ", ".join(extra))
    return None

def calls_guarded(value):
    """True if a `uses:` value points at a guarded file. No normalisation at all: the path before `@` ends in
    /<file> or is the bare file name, compared case-insensitively, so every odd spelling of the path is caught."""
    path = value.strip().split("@", 1)[0].lower()
    for stem in GUARDED_STEMS:
        for ext in (".yml", ".yaml"):
            name = stem + ext
            if path == name or path.endswith("/" + name):
                return True
    return False

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

for name in ALLOWED:
    path = os.path.join(tree, ".github", "workflows", name)
    if not os.path.exists(path):
        bad.append("%s is missing" % name)
        continue
    problem = check_guarded(name, read(path))
    if problem:
        bad.append(problem)

# Every workflow file (dotfiles included: os.listdir, not glob) and every composite action under .github/actions.
files = []
wf_dir = os.path.join(tree, ".github", "workflows")
if os.path.isdir(wf_dir):
    files += [os.path.join(wf_dir, n) for n in os.listdir(wf_dir) if n.lower().endswith((".yml", ".yaml"))]
for dirpath, _dirs, names in os.walk(os.path.join(tree, ".github", "actions")):
    files += [os.path.join(dirpath, n) for n in names if n.lower() in ("action.yml", "action.yaml")]
for path in sorted(files):
    doc = yaml.load(read(path), Loader=yaml.BaseLoader) or {}
    for value in uses_values(doc):
        if calls_guarded(value):
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

# 2b. odd spellings of the path: no normalisation is applied, so each form is rejected on its ending alone
caller() { mutate "$1" .github/workflows/other.yml "name: other
on: push
jobs:
  b:
    uses: $2"; }
expect caught "path form: ./.github/workflows/../workflows/scan.yml" "$(caller p1 './.github/workflows/../workflows/scan.yml')"
expect caught "path form: /./scan.yml" "$(caller p2 '/./scan.yml')"
expect caught "path form: //scan.yml" "$(caller p3 '//scan.yml')"
expect caught "path form: Scan.yml (case)" "$(caller p4 'Scan.yml')"
expect caught "path form: sub/../scan.yml" "$(caller p5 'sub/../scan.yml')"
expect caught "path form: ./.github//workflows/scan.yml" "$(caller p6 './.github//workflows/scan.yml')"
expect caught "path form: bare scan.yml" "$(caller p7 'scan.yml')"
expect caught "path form: .yaml spelling of scan" "$(caller p8 './.github/workflows/scan.yaml')"
expect caught "path form: MAIN-CANDIDATE-RESCAN.YAML@main" "$(caller p9 'o/r/.github/workflows/MAIN-CANDIDATE-RESCAN.YAML@main')"
expect caught "path form: ./main-candidate-rescan.yml" "$(caller p10 './main-candidate-rescan.yml')"
expect caught "a dotfile workflow calls scan.yml" "$(mutate d1 .github/workflows/.hidden.yml $'name: h\non: push\njobs:\n  b:\n    uses: ./.github/workflows/scan.yml')"
expect ok "a name that only ends the same way is not a guarded file: other-scan.yml, rescan.yml" "$(t=$(caller n1 './.github/workflows/other-scan.yml'); printf 'name: o\non: push\njobs:\n  c:\n    uses: ./.github/workflows/rescan.yml\n' > "$t/.github/workflows/o2.yml"; echo "$t")"

# 2c. the on: allowlist (fail closed): each guarded file has a literal `on` with only its own triggers
expect caught "scan.yml: merge key in on" "$(mutate a1 .github/workflows/scan.yml $'x: &t {pull_request: {}}\non:\n  <<: *t\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: capitalised On: key" "$(mutate a2 .github/workflows/scan.yml $'On:\n  pull_request:\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: Workflow_Call (case)" "$(mutate a3 .github/workflows/scan.yml $'on:\n  pull_request:\n  Workflow_Call:\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: on: WORKFLOW_CALL (scalar, case)" "$(mutate a4 .github/workflows/scan.yml $'on: WORKFLOW_CALL\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: an unlisted extra event (release)" "$(mutate a5 .github/workflows/scan.yml $'on:\n  pull_request:\n  release:\n    types: [published]\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "main-candidate-rescan.yml: push is not one of its triggers" "$(mutate a6 .github/workflows/main-candidate-rescan.yml $'on:\n  schedule:\n    - cron: "41 7 * * *"\n  push:\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: no on key at all" "$(mutate a7 .github/workflows/scan.yml $'name: scan\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: empty on:" "$(mutate a8 .github/workflows/scan.yml $'on:\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"
expect caught "scan.yml: an anchor elsewhere in the file" "$(mutate a9 .github/workflows/scan.yml $'on:\n  pull_request:\nenv: &e\n  A: b\njobs:\n  s:\n    runs-on: ubuntu-latest\n    env: *e\n    steps:\n      - run: echo')"
expect ok "scan.yml: pull_request with a branch filter and push with tags stays allowed" "$(mutate a10 .github/workflows/scan.yml $'on:\n  pull_request:\n  push:\n    branches: [main]\n    tags: [\'v*\']\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo')"

# 3. the guarded files themselves must exist (a renamed file would silently escape the check)
expect caught "scan.yml is missing" "$(t=$(fixture r1); rm "$t/.github/workflows/scan.yml"; echo "$t")"
expect caught "main-candidate-rescan.yml is missing" "$(t=$(fixture r2); rm "$t/.github/workflows/main-candidate-rescan.yml"; echo "$t")"

# 4. things that must stay allowed: neighbours calling other stage files, a guarded name inside a run: string
expect ok "a neighbour that calls stage-build.yml and mentions scan.yml in a run: line" "$(mutate k1 .github/workflows/other.yml $'name: other\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: gh run list --workflow scan.yml')"

# the real repository (green today)
expect ok "the real repository: neither file is callable and nothing calls them" "$root"

EXPECT=42
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
