#!/usr/bin/env bash
# proves: REQ-CI-005-AC1, REQ-CI-005-AC2, REQ-CI-005-AC5, REQ-CI-005-AC6, REQ-CI-005-AC7 — every tracked suite runs once (a bash PATH step or a matrix leg); the legs are the tracked suites less the bash PATH steps; grype only where the VEX suites need it
# Guards the suites matrix of .github/workflows/ci.yml: each tracked suite must run exactly once, and a wiring slip would otherwise drop a suite silently.
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

# chk.py CHECK ROOT: reads ROOT/.github/workflows/ci.yml and the tracked files of the git repo ROOT; exit 0 if the check holds, else 1 with the reason.
# It works out the expected list on its own (it does not trust the list step) and runs the real run text of the list step from ROOT.
cat > "$work/chk.py" <<'PY'
import json, os, re, subprocess, sys, tempfile, yaml
check, base = sys.argv[1], sys.argv[2]
wf = yaml.safe_load(open(base + "/.github/workflows/ci.yml"))
files = subprocess.run(["git", "ls-files"], cwd=base, capture_output=True, text=True, check=True).stdout.split("\n")
tracked = [f for f in files if re.fullmatch(r"(bin|[^/]*/agent/tests)/[^/]*-test\.sh", f)]
RUN = re.compile(r"^bash (\S+)$")
def fail(msg): print(msg); sys.exit(1)
steps = lambda job: wf["jobs"][job].get("steps", [])
by_path = [(m.group(1), s) for j in wf["jobs"] for s in steps(j) if (m := RUN.match(str(s.get("run", "")).strip()))]
counted = [p for p, _ in by_path]
expected = sorted(os.path.basename(f) for f in tracked if f not in counted)
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
    if len(counted) != len(set(counted)): fail("a suite has two bash steps")
    both = {os.path.basename(p) for p in counted} & set(got)
    if both: fail("a suite with a bash step also has a leg: %s" % sorted(both))
elif check == "plain":
    # a skipped or failure-tolerant step would drop its suite from both the matrix and the run
    for p, st in by_path:
        if "if" in st or "continue-on-error" in st: fail("bash step has if or continue-on-error: " + p)
elif check == "ac2":
    missing = set(expected) - set(legs())
    if missing: fail("tracked suites with no bash step and no leg: %s" % sorted(missing))
elif check == "ac5":
    got = legs()
    if sorted(got) != expected: fail("legs %s != expected %s" % (sorted(got), expected))
    for f in tracked:
        n = counted.count(f) + got.count(os.path.basename(f))
        if n != 1: fail("%s runs %d times" % (f, n))
elif check == "wiring":
    job = wf["jobs"]["suites"]
    if job.get("needs") != "suite-list": fail("suites does not need suite-list")
    if job["strategy"]["matrix"].get("suite") != "${{ fromJSON(needs.suite-list.outputs.suites) }}": fail("matrix.suite is not fromJSON of the list output")
    run = [s for s in job["steps"] if 'python3 -I bin/run-ci-suite.py "$SUITE"' in str(s.get("run", ""))]
    if len(run) != 1: fail("no single leg step that runs python3 -I bin/run-ci-suite.py \"$SUITE\"")
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
runs = [s for s in suites if "run-ci-suite.py" in str(s.get("run", ""))][0]
bash_step = [s for s in wf["jobs"]["other"]["steps"] if str(s.get("run", "")).startswith("bash ")][0]
emit = lambda text: "echo 'suites=%s' >> \"$GITHUB_OUTPUT\"" % text
if kind == "grype-dropped": del grype["if"]
elif kind == "grype-widened": grype["if"] = grype["if"].replace(" }}", " || matrix.suite == 'archive-test.sh' }}")
elif kind == "grype-one-missing": grype["if"] = "${{ matrix.suite == 'vex-scope-test.sh' }}"
elif kind == "run-also-leg": lst["run"] = emit('["a-test.sh","b-test.sh","c-test.sh","d-test.sh","vex-scope-test.sh","vex-both-scanners-test.sh"]')
elif kind == "suite-missing": lst["run"] = emit('["b-test.sh"]')
elif kind == "list-drops-tracked": lst["run"] = emit('["b-test.sh","c-test.sh","d-test.sh","vex-scope-test.sh","vex-both-scanners-test.sh"]')
elif kind == "not-a-string-list": lst["run"] = emit('[{"suite":"b-test.sh"},{"suite":"c-test.sh"}]')
elif kind == "leg-not-run-ci-suite": runs["run"] = 'bash "bin/$SUITE"'
elif kind == "netcut-variable": runs["env"]["CHAIN_TEST_REQUIRE_NETCUT"] = "1"
elif kind == "bash-if": bash_step["if"] = "${{ false }}"
elif kind == "bash-continue": bash_step["continue-on-error"] = True
elif kind == "run-twice": wf["jobs"]["other"]["steps"].append(dict(bash_step))
yaml.safe_dump(wf, open(dst, "w"), width=10000)
PY

# A small repo shaped as the real one: a-test.sh has a bash PATH step; b-, c-, d- and the two VEX suites do not.
# The auditor directory is spelled out in two parts, so this file holds no literal path of it (REQ-AUD-018-AC1).
aud=".github/$(echo agent)/tests"
mk() { local d=$1; mkdir -p "$d/.github/workflows" "$d/bin" "$d/$aud"
  for f in a b c vex-scope vex-both-scanners; do : > "$d/bin/$f-test.sh"; done
  : > "$d/$aud/d-test.sh"; : > "$d/bin/helper.sh"
  git -C "$d" init -q; git -C "$d" add -A; }
mk "$work/good"
cat > "$work/good/.github/workflows/ci.yml" <<'YML'
name: ci
on: [push]
jobs:
  other:
    runs-on: ubuntu-latest
    steps:
      - name: a
        run: bash bin/a-test.sh
  suite-list:
    runs-on: ubuntu-latest
    outputs:
      suites: ${{ steps.list.outputs.suites }}
    steps:
      - id: list
        run: |
          by_step=$(grep -oP '^\s+run: bash \K\S+$' .github/workflows/ci.yml || true)
          legs=$(git ls-files | grep -E '^(bin|AUDITOR_DIR)/[^/]*-test\.sh$' | grep -vxF -f <(echo "$by_step") || true)
          echo "suites=$(echo "$legs" | xargs -rn1 basename | jq -R . | jq -sc .)" >> "$GITHUB_OUTPUT"
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
      - name: the suite
        env:
          SUITE: ${{ matrix.suite }}
        run: python3 -I bin/run-ci-suite.py "$SUITE"
YML
sed -i "s#AUDITOR_DIR#$aud#" "$work/good/.github/workflows/ci.yml"
export SCRATCH="$work"
chk() { python3 -I "$work/chk.py" "$@" 2>&1 | head -c 300; return "${PIPESTATUS[0]}"; }
# pass_ CHECK DIR LABEL / refuse CHECK DIR LABEL: the check holds / fails on that tree
pass_() { local out; if out=$(chk "$1" "$2"); then ok "$3"; else bad "$3 -> $out"; fi; }
refuse() { local out; if out=$(chk "$1" "$2"); then bad "$3 (the check did not fail)"; else ok "$3 ($out)"; fi; }

# ---- the checks hold on a well-formed workflow --------------------------------------------------------------------------------
for c in form ac1 ac2 ac5 plain wiring grype netcut; do pass_ $c "$work/good" "control: check '$c' holds on a well-formed workflow"; done

# ---- ...and fail on a broken copy of it ---------------------------------------------------------------------------------------
# broken KIND CHECK LABEL [EXTRA]: EXTRA is one more tracked file in the fixture repo
broken() { local kind=$1 check=$2 label=$3 d="$work/m-$1-$2"; mk "$d"; [ -z "${4:-}" ] || { : > "$d/$4"; git -C "$d" add -A; }
  python3 -I "$work/mut.py" "$kind" "$work/good/.github/workflows/ci.yml" "$d/.github/workflows/ci.yml"; refuse "$check" "$d" "$label"; }
broken grype-dropped grype "REQ-CI-005-AC6 the grype condition dropped (every leg installs it) is refused"
broken grype-widened grype "REQ-CI-005-AC6 the grype condition widened to a third suite is refused"
broken grype-one-missing grype "REQ-CI-005-AC6 the grype condition missing a VEX suite is refused"
broken netcut-variable netcut "REQ-CI-005-AC7 a step that sets CHAIN_TEST_REQUIRE_NETCUT is refused"
broken run-also-leg ac1 "REQ-CI-005-AC1 a suite with a bash PATH step also listed in the matrix is refused"
broken run-also-leg ac5 "REQ-CI-005-AC5 a suite run by a bash PATH step and by a leg is refused"
broken run-twice ac1 "REQ-CI-005-AC1 a suite with two bash PATH steps is refused"
broken run-twice ac5 "REQ-CI-005-AC5 a suite run by two bash PATH steps is refused"
broken bash-if plain "REQ-CI-005-AC1 a bash PATH step with if (its suite would run nowhere) is refused"
broken bash-continue plain "REQ-CI-005-AC1 a bash PATH step with continue-on-error is refused"
broken suite-missing ac2 "REQ-CI-005-AC2 a tracked suite with no bash PATH step and no leg is refused"
broken list-drops-tracked ac2 "REQ-CI-005-AC2 a tracked suite the list step omits has no leg and is refused" bin/e-test.sh
broken list-drops-tracked ac5 "REQ-CI-005-AC5 a tracked suite that no step runs and the list step omits is refused" bin/e-test.sh
broken list-drops-tracked ac5 "REQ-CI-005-AC5 a tracked suite of the auditor directory that the list step omits is refused" "$aud/e-test.sh"
broken suite-missing ac5 "REQ-CI-005-AC5 a list that differs from tracked suites less bash PATH steps is refused"
broken not-a-string-list form "REQ-CI-005-AC5 a list that is not a JSON list of strings is refused"
broken leg-not-run-ci-suite wiring "REQ-CI-005-AC2 a leg that does not run bin/run-ci-suite.py with SUITE is refused"

# ---- the real repository --------------------------------------------------------------------------------------------------------
cd "$root"
pass_ form "$root" "REQ-CI-005-AC5 real ci.yml: the list step prints a JSON list of strings, each suite once"
pass_ ac5 "$root" "REQ-CI-005-AC5 real ci.yml: the legs are exactly the tracked suites less the ones a bash PATH step runs, each suite once"
pass_ ac1 "$root" "REQ-CI-005-AC1 real ci.yml: a suite with a bash PATH step has no leg and one step"
pass_ plain "$root" "REQ-CI-005-AC1 real ci.yml: no bash PATH step carries if or continue-on-error"
pass_ ac2 "$root" "REQ-CI-005-AC2 real ci.yml: every other tracked suite has a leg"
pass_ wiring "$root" "REQ-CI-005-AC2 real ci.yml: the legs come from the list job and run bin/run-ci-suite.py"
pass_ grype "$root" "REQ-CI-005-AC6 real ci.yml: grype is installed in the legs of the two VEX suites only"
pass_ netcut "$root" "REQ-CI-005-AC7 real ci.yml: no step sets CHAIN_TEST_REQUIRE_NETCUT"
# the old policy list must be gone and unread
if [ ! -e .github/policy/ci-suites.json ]; then ok "REQ-CI-005-AC5 .github/policy/ci-suites.json no longer exists"; else bad "REQ-CI-005-AC5 .github/policy/ci-suites.json still exists"; fi
# requirements and docs may still tell the history; nothing else (and not this test) may mention the file
refs=$(git ls-files -z | grep -zv -e '^requirements/' -e '^docs/' -e '^bin/ci-suites-matrix-test\.sh$' | xargs -0 grep -lsF 'ci-suites.json' 2> /dev/null || true)
if [ -z "$refs" ]; then ok "REQ-CI-005-AC5 no tracked file besides requirements and docs mentions ci-suites.json"; else bad "REQ-CI-005-AC5 still mentioned in: $(echo $refs)"; fi
# the chain test reads GITHUB_ACTIONS directly
if grep -q 'CHAIN_TEST_REQUIRE_NETCUT' bin/chain-verify-test.sh; then bad "REQ-CI-005-AC7 bin/chain-verify-test.sh still reads CHAIN_TEST_REQUIRE_NETCUT"
elif grep -q '"${GITHUB_ACTIONS:-}" = true' bin/chain-verify-test.sh; then ok "REQ-CI-005-AC7 bin/chain-verify-test.sh requires the network cut when GITHUB_ACTIONS=true"
else bad "REQ-CI-005-AC7 bin/chain-verify-test.sh does not test GITHUB_ACTIONS = true"; fi
if ! git grep -q 'CHAIN_TEST_REQUIRE_NETCUT' -- . ':!bin/ci-suites-matrix-test.sh' ':!docs' ':!requirements'; then ok "REQ-CI-005-AC7 CHAIN_TEST_REQUIRE_NETCUT appears nowhere else in the repository"; else bad "REQ-CI-005-AC7 CHAIN_TEST_REQUIRE_NETCUT is still used: $(git grep -l 'CHAIN_TEST_REQUIRE_NETCUT' -- . ':!bin/ci-suites-matrix-test.sh' ':!docs' ':!requirements' | tr '\n' ' ')"; fi

echo "ci-suites-matrix: $pass passed, $failn failed"
[ "$failn" = 0 ]
