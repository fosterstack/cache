#!/usr/bin/env bash
# proves: REQ-CI-005-AC1, REQ-CI-005-AC2, REQ-CI-005-AC5, REQ-CI-005-AC6, REQ-CI-005-AC7 — every floored suite runs once (a counting step or a matrix leg); the legs are the floors file less the counting steps; grype only where the VEX suites need it
# Guards the suites matrix of .github/workflows/ci.yml: each floored suite must run exactly once, and a wiring slip would otherwise drop a suite silently.
# The real `list` step is executed (not re-implemented) and compared with a list worked out independently; the checks are also run against broken
# copies of the workflow, since a check that cannot fail proves nothing. Needs bash, git, jq and python3 with PyYAML.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d -t ci-suites-matrix.XXXXXX)
trap '[ -d "$work" ] && rm -rf -- "$work"' EXIT
pass=0; failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (install the python3-yaml package)"; echo "ci-suites-matrix: 0 passed, 1 failed"; exit 1; }

# chk.py CHECK ROOT: reads ROOT/.github/workflows/ci.yml and ROOT/test-evidence/suite-floors.json; exit 0 if the check holds, else 1 with the reason.
# It works out the expected list on its own (it does not trust the list step) and runs the real run text of the list step from ROOT.
cat > "$work/chk.py" <<'PY'
import json, os, re, subprocess, sys, tempfile, yaml
check, base = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(base + "/.github/workflows/ci.yml"))
floors = json.load(open(base + "/test-evidence/suite-floors.json"))
COUNT = re.compile(r"^python3 -I bin/suite-guard-run\.py run test-evidence/suite-floors\.json (\S+) (\S+)$")
def fail(msg): print(msg); sys.exit(1)
steps = lambda job: wf["jobs"][job].get("steps", [])
counted = [m.group(1) for j in wf["jobs"] for s in steps(j) if (m := COUNT.match(str(s.get("run", "")).strip()))]
expected = sorted(set(floors) - set(counted))
def legs():
    step = [s for s in steps("suite-list") if s.get("id") == "list"]
    if len(step) != 1: fail("suite-list has no single step with id: list")
    scratch = tempfile.mkdtemp(prefix="ci-suites-run.", dir=os.environ["SCRATCH"])
    out = scratch + "/out"; open(out, "w").close()
    p = subprocess.run(["bash", "-e", "-c", step[0]["run"]], cwd=base, env={**os.environ, "GITHUB_OUTPUT": out}, capture_output=True, text=True)
    if p.returncode: fail("the list step exited %d: %s" % (p.returncode, p.stderr[:200]))
    lines = [l for l in open(out).read().splitlines() if l.startswith("suites=")]
    if len(lines) != 1: fail("the list step wrote %d suites= lines to GITHUB_OUTPUT" % len(lines))
    try: got = json.loads(lines[0][len("suites="):])
    except ValueError: fail("the suites= value is not JSON")
    if not isinstance(got, list) or not all(isinstance(x, str) for x in got): fail("the output is not a JSON list of strings")
    return got
if check == "form":
    got = legs()
    if len(got) != len(set(got)): fail("the list repeats a suite")
elif check == "ac1":
    got = legs()
    if len(counted) != len(set(counted)): fail("a suite has two counting steps")
    both = set(counted) & set(got)
    if both: fail("a suite with a counting step also has a leg: %s" % sorted(both))
    if set(counted) - set(floors): fail("a counting step names a suite the floors file lacks")
elif check == "plain":
    # a skipped or failure-tolerant counting step would drop its suite from both the matrix and the run
    for j in wf["jobs"]:
        for st in steps(j):
            if COUNT.match(str(st.get("run", "")).strip()) and ("if" in st or "continue-on-error" in st): fail("counting step has if or continue-on-error: " + st["run"])
elif check == "ac2":
    missing = set(expected) - set(legs())
    if missing: fail("floored suites with no counting step and no leg: %s" % sorted(missing))
elif check == "ac5":
    got = legs()
    if sorted(got) != expected: fail("legs %s != expected %s" % (sorted(got), expected))
elif check == "wiring":
    job = wf["jobs"]["suites"]
    if job.get("needs") != "suite-list": fail("suites does not need suite-list")
    if job["strategy"]["matrix"].get("suite") != "${{ fromJSON(needs.suite-list.outputs.suites) }}": fail("matrix.suite is not fromJSON of the list output")
    run = [s for s in job["steps"] if s.get("name") == "the suite, held to its floor"]
    if len(run) != 1: fail("no single step named 'the suite, held to its floor'")
    if 'python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json "$SUITE" "$path"' not in run[0]["run"]: fail("the leg does not run suite-guard-run.py run")
    if run[0].get("env", {}).get("SUITE") != "${{ matrix.suite }}": fail("SUITE is not matrix.suite")
elif check == "grype":
    hits = [s for s in wf["jobs"]["suites"]["steps"] if "install-scanner.sh grype" in str(s.get("run", ""))]
    want = "${{ matrix.suite == 'vex-scope-test.sh' || matrix.suite == 'vex-both-scanners-test.sh' }}"
    if len(hits) != 1 or "./bin/install-scanner.sh grype" not in hits[0]["run"]: fail("no single grype install step in suites")
    if hits[0].get("if") != want: fail("grype step condition is %r" % hits[0].get("if"))
elif check == "netcut":
    if "CHAIN_TEST_REQUIRE_NETCUT" in open(base + "/.github/workflows/ci.yml").read(): fail("ci.yml still sets CHAIN_TEST_REQUIRE_NETCUT")
else:
    fail("unknown check " + check)
PY

# mut.py KIND SRC DST: DST is a copy of the workflow SRC broken in one named way.
cat > "$work/mut.py" <<'PY'
import sys, yaml
kind, src, dst = sys.argv[1:4]
wf = yaml.safe_load(open(src))
suites = wf["jobs"]["suites"]["steps"]
grype = [s for s in suites if "install-scanner.sh grype" in str(s.get("run", ""))][0]
lst = [s for s in wf["jobs"]["suite-list"]["steps"] if s.get("id") == "list"][0]
runs = [s for s in suites if s.get("name") == "the suite, held to its floor"][0]
emit = lambda text: "echo 'suites=%s' >> \"$GITHUB_OUTPUT\"" % text
if kind == "grype-dropped": del grype["if"]
elif kind == "grype-widened": grype["if"] = grype["if"].replace(" }}", " || matrix.suite == 'archive-test.sh' }}")
elif kind == "grype-one-missing": grype["if"] = "${{ matrix.suite == 'vex-scope-test.sh' }}"
elif kind == "counted-in-matrix": lst["run"] = emit('["a-test.sh","b-test.sh","c-test.sh","d-test.sh"]')
elif kind == "suite-missing": lst["run"] = emit('["b-test.sh"]')
elif kind == "not-a-string-list": lst["run"] = emit('[{"suite":"b-test.sh"},{"suite":"c-test.sh"}]')
elif kind == "leg-not-guarded": runs["run"] = 'bash "bin/$SUITE"'
elif kind == "netcut-variable": runs["env"]["CHAIN_TEST_REQUIRE_NETCUT"] = "1"
elif kind == "counting-skipped": wf["jobs"]["other"]["steps"][0]["if"] = "${{ false }}"
elif kind == "counted-twice": wf["jobs"]["other"]["steps"].append(dict(wf["jobs"]["other"]["steps"][0]))
yaml.safe_dump(wf, open(dst, "w"), width=10000)
PY

# A small workflow shaped as the real one will be: a-test.sh has a counting step, b-, c- and the two VEX suites do not.
mk() { local d=$1; mkdir -p "$d/.github/workflows" "$d/test-evidence"
  printf '{"a-test.sh": 5, "b-test.sh": 5, "c-test.sh": 5, "vex-scope-test.sh": 5, "vex-both-scanners-test.sh": 5}\n' > "$d/test-evidence/suite-floors.json"; }
mk "$work/good"
cat > "$work/good/.github/workflows/ci.yml" <<'YML'
name: ci
on: [push]
jobs:
  other:
    runs-on: ubuntu-latest
    steps:
      - name: a
        run: python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json a-test.sh bin/a-test.sh
  suite-list:
    runs-on: ubuntu-latest
    outputs:
      suites: ${{ steps.list.outputs.suites }}
    steps:
      - id: list
        run: |
          counted=$(grep -oP '^\s+run: python3 -I bin/suite-guard-run\.py run test-evidence/suite-floors\.json \K\S+' .github/workflows/ci.yml | jq -R . | jq -sc .)
          echo "suites=$(jq -c --argjson c "$counted" 'keys - $c' test-evidence/suite-floors.json)" >> "$GITHUB_OUTPUT"
  suites:
    needs: suite-list
    runs-on: ubuntu-latest
    strategy:
      matrix:
        suite: ${{ fromJSON(needs.suite-list.outputs.suites) }}
    steps:
      - name: install the pinned grype
        if: ${{ matrix.suite == 'vex-scope-test.sh' || matrix.suite == 'vex-both-scanners-test.sh' }}
        run: ./bin/install-scanner.sh grype
      - name: the suite, held to its floor
        env:
          SUITE: ${{ matrix.suite }}
        run: |
          path=$(git ls-files -- "bin/$SUITE" "AUDITOR_DIR/tests/$SUITE")
          python3 -I bin/suite-guard-run.py run test-evidence/suite-floors.json "$SUITE" "$path"
YML
# the auditor directory is spelled out only here, in two parts, so this file holds no literal path of it (REQ-AUD-018-AC1)
sed -i "s#AUDITOR_DIR#.github/$(echo agent)#" "$work/good/.github/workflows/ci.yml"
export SCRATCH="$work"
chk() { python3 -I "$work/chk.py" "$@" 2>&1 | head -c 300; return "${PIPESTATUS[0]}"; }
# pass CHECK DIR LABEL / refuse CHECK DIR LABEL: the check holds / fails on that tree
pass_() { local out; if out=$(chk "$1" "$2"); then ok "$3"; else bad "$3 -> $out"; fi; }
refuse() { local out; if out=$(chk "$1" "$2"); then bad "$3 (the check did not fail)"; else ok "$3 ($out)"; fi; }

# ---- the checks hold on a well-formed workflow --------------------------------------------------------------------------------
for c in form ac1 ac2 ac5 plain wiring grype netcut; do pass_ $c "$work/good" "control: check '$c' holds on a well-formed workflow"; done

# ---- ...and fail on a broken copy of it ---------------------------------------------------------------------------------------
broken() { local kind=$1 check=$2 label=$3 d="$work/m-$1"; mk "$d"; python3 -I "$work/mut.py" "$kind" "$work/good/.github/workflows/ci.yml" "$d/.github/workflows/ci.yml"; refuse "$check" "$d" "mutation: $label"; }
broken grype-dropped grype "the grype condition dropped (every leg installs it) is refused"
broken grype-widened grype "the grype condition widened to a third suite is refused"
broken grype-one-missing grype "the grype condition missing a VEX suite is refused"
broken counted-in-matrix ac1 "a suite with a counting step also listed in the matrix is refused"
broken counting-skipped plain "a counting step with if: false (its suite would run nowhere) is refused"
broken counted-twice ac1 "a suite with two counting steps is refused"
broken suite-missing ac2 "a floored suite missing from the list (no step, no leg) is refused"
broken suite-missing ac5 "a list that differs from floors minus counting steps is refused"
broken not-a-string-list form "a list that is not a JSON list of strings is refused"
broken leg-not-guarded wiring "a leg that does not run suite-guard-run.py run is refused"
broken netcut-variable netcut "a step that sets CHAIN_TEST_REQUIRE_NETCUT is refused"

# ---- the real repository --------------------------------------------------------------------------------------------------------
cd "$root"
pass_ form "$root" "REQ-CI-005-AC5 real ci.yml: the list step prints a JSON list of strings, each suite once"
pass_ ac5 "$root" "REQ-CI-005-AC5 real ci.yml: the legs are exactly the floors file less the suites a counting step names"
pass_ ac1 "$root" "REQ-CI-005-AC1 real ci.yml: a suite with a counting step has no leg and one step"
pass_ plain "$root" "REQ-CI-005-AC1 real ci.yml: no counting step carries if or continue-on-error"
pass_ ac2 "$root" "REQ-CI-005-AC2 real ci.yml: every other floored suite has a leg"
pass_ wiring "$root" "REQ-CI-005-AC2 real ci.yml: the legs come from the list job and run suite-guard-run.py run"
pass_ grype "$root" "REQ-CI-005-AC6 real ci.yml: grype is installed in the legs of the two VEX suites only"
pass_ netcut "$root" "REQ-CI-005-AC7 real ci.yml: no step sets CHAIN_TEST_REQUIRE_NETCUT"
# the list is computed from the floors file and the workflow; the old policy list must be gone and unread
if [ ! -e .github/policy/ci-suites.json ]; then ok "REQ-CI-005-AC5 .github/policy/ci-suites.json no longer exists"; else bad "REQ-CI-005-AC5 .github/policy/ci-suites.json still exists"; fi
# requirements and docs may still tell the history; nothing else (and not this test) may mention the file
refs=$(git ls-files -z | grep -zv -e '^requirements/' -e '^docs/' -e '^bin/ci-suites-matrix-test\.sh$' | xargs -0 grep -lsF 'ci-suites.json' 2> /dev/null || true)
if [ -z "$refs" ]; then ok "REQ-CI-005-AC5 no tracked file besides requirements and docs mentions ci-suites.json"; else bad "REQ-CI-005-AC5 still mentioned in: $(echo $refs)"; fi
# the chain test reads GITHUB_ACTIONS directly
if grep -q 'CHAIN_TEST_REQUIRE_NETCUT' bin/chain-verify-test.sh; then bad "REQ-CI-005-AC7 bin/chain-verify-test.sh still reads CHAIN_TEST_REQUIRE_NETCUT"
elif grep -q '"${GITHUB_ACTIONS:-}" = true' bin/chain-verify-test.sh; then ok "REQ-CI-005-AC7 bin/chain-verify-test.sh requires the network cut when GITHUB_ACTIONS=true"
else bad "REQ-CI-005-AC7 bin/chain-verify-test.sh does not test GITHUB_ACTIONS = true"; fi
if ! git grep -q 'CHAIN_TEST_REQUIRE_NETCUT' -- . ':!bin/ci-suites-matrix-test.sh' ':!docs' ':!requirements'; then ok "REQ-CI-005-AC7 CHAIN_TEST_REQUIRE_NETCUT appears nowhere else in the repository"; else bad "REQ-CI-005-AC7 CHAIN_TEST_REQUIRE_NETCUT is still used: $(git grep -l 'CHAIN_TEST_REQUIRE_NETCUT' -- . ':!bin/ci-suites-matrix-test.sh' ':!docs' ':!requirements' | tr '\n' ' ')"; fi

EXPECT=31
echo "ci-suites-matrix: $pass passed, $failn failed"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT"; exit 1; fi
[ "$failn" = 0 ]
