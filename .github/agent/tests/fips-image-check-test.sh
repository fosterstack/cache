#!/usr/bin/env bash
# proves: REQ-FIPS-002-AC2
# The candidate images by digest are started and asked what they report. Three parts:
#   A. wiring: stage-acceptance-k8s.yml has ONE unconditional step that, for production, debug and fips, pulls
#      ghcr.io/<owner>/cache-candidates@<digest from the stage's digests input>, starts it with docker, waits for
#      /healthz, reads /statusz .fips140_note, removes the container, and hands the answers to the comparison
#      script; the stage reports REQ-FIPS-002-AC2 in its results output; no new action reference, permission or
#      workflow file; every action reference is still a commit digest.
#   B. behaviour: the comparison script, offline, over fake /statusz bodies.
#   C. mutants: a script that passes B must also fail each of a small list of mutations of itself.
#
# Contract for the implementation (step 7) this test fixes:
#   script   bin/fips-image-posture.py   (needs a bin/ allowlist pattern in bin/check-file-allowlist.sh and its test)
#   CLI      python3 bin/fips-image-posture.py <dir>
#            <dir> holds the raw /statusz response body of each variant as production.json, debug.json, fips.json.
#            Exit 0 only when fips.json's .fips140_note is exactly
#              active (Go validated module v1.0.0, CMVP cert #5247)
#            and production.json's and debug.json's are exactly  off  . Any other value, a missing file, an empty or
#            unparsable body, a non-object body, a missing or non-string field, or a wrong argument count exits
#            non-zero and names the variant on stderr. The two strings appear in the script as literals.
#   The step writes each body with `curl -s .../statusz > "$dir/<variant>.json"` and calls the script once, after all
#   three variants were tried (a variant that failed to start leaves no file, so it is "missing").
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
pylib=$(mktemp -d); work=$(mktemp -d); trap 'rm -rf "$pylib" "$work"' EXIT
ln -s "$root/.github/agent/fixtures/testlib/pyyaml" "$pylib/yaml"
export PYTHONPATH="$pylib${PYTHONPATH:+:$PYTHONPATH}"
python3 - "$root" "$work" <<'PY'
import json, os, re, shutil, subprocess, sys, yaml
root, work = sys.argv[1], sys.argv[2]
passed = failed = 0
def check(name, ok, got=""):
    global passed, failed
    if ok: passed += 1; print("ok:", name)
    else: failed += 1; print("FAIL:", name, "->", got)

# ---------------------------------------------------------------- A. wiring
GOOD_FIPS = "active (Go validated module v1.0.0, CMVP cert #5247)"
FORCED = "active (fips140 mode forced at runtime; not the validated-module build)"
path = os.path.join(root, ".github/workflows/stage-acceptance-k8s.yml")
text = open(path).read()
wf = yaml.safe_load(text)
job = wf["jobs"]["k8s"]
steps = job["steps"]
hit = [i for i, s in enumerate(steps) if "/statusz" in (s.get("run") or "")]
check("exactly one step reads /statusz", len(hit) == 1, hit)
if len(hit) == 1:
    i = hit[0]; s = steps[i]; run = s["run"]
    check("the step is unconditional and cannot swallow failure",
          "if" not in s and not s.get("continue-on-error") and "|| true" not in run and "set -euo pipefail" in run, s)
    for v in ("production", "debug", "fips"):
        check("it takes the %s digest from the digests input" % v, re.search(r"jq -r '\.%s'" % v, run) is not None)
    check("it reads the stage's digests input", s.get("env", {}).get("DIGESTS") == "${{ inputs.digests }}", s.get("env"))
    check("it pulls the candidate by digest, from cache-candidates under the repository owner",
          re.search(r"ghcr\.io/\$\{\{ github\.repository_owner \}\}/cache-candidates@\$", run) is not None)
    check("it pulls and runs only that reference (no other image)",
          all(re.search(r"\$\{?ref\}?|\"\$ref\"", l) for l in run.splitlines() if re.search(r"docker (pull|run)\b", l))
          and "docker pull" in run and "docker run" in run, run)
    check("it starts with docker, unprivileged, not on the host network, without the docker socket",
          not re.search(r"--privileged|--network[= ]host|--net[= ]host|docker\.sock|--cap-add|--pid", run), run)
    check("it waits for /healthz then reads /statusz .fips140_note", "/healthz" in run and ".fips140_note" in run or "fips140_note" in run)
    check("it writes each body to <dir>/<variant>.json for the comparison script",
          re.search(r"/statusz[^\n]*>\s*\"?\$[^\n]*(json)", run) is not None, run)
    check("it removes the container (also when the read fails)", "docker rm -f" in run and ("trap" in run or run.count("docker rm -f") >= 2))
    check("it calls bin/fips-image-posture.py once", len(re.findall(r"python3 bin/fips-image-posture\.py\b", run)) == 1, run)
    check("it is a step of the k8s job that comes before the results step",
          steps.index(s) < [j for j, t in enumerate(steps) if t.get("id") == "results"][0])
    check("it does not print the registry token or use pull_request context", "secrets." not in run and "github.event" not in run)
res = [t for t in steps if t.get("id") == "results"]
check("the stage still has its results step", len(res) == 1)
if res:
    r = res[0]["run"]
    check("the results output keeps REQ-DEPLOY-003-AC1", "REQ-DEPLOY-003-AC1" in r, r)
    check("the results output reports REQ-FIPS-002-AC2", "REQ-FIPS-002-AC2" in r, r)
    m = re.search(r"results=(\[.*\])", r)
    try: ids = sorted(x["ac"] for x in json.loads(m.group(1)))
    except Exception as e: ids = repr(e)
    check("the results output is valid JSON naming both ACs as pass", ids == ["REQ-DEPLOY-003-AC1", "REQ-FIPS-002-AC2"], ids)
check("the results step is the last step", steps[-1].get("id") == "results")
check("the stage's output still carries the results", wf[True if True in wf else "on"]["workflow_call"]["outputs"]["results"]["value"] == "${{ jobs.k8s.outputs.results }}")

# no new action reference, permission or workflow file
uses = sorted(s["uses"] for s in steps if "uses" in s)
check("the stage's action references are the two it had, both commit digests",
      uses == ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "helm/kind-action@06c1ae10762d3b9c1644e7fe69596ae519e015a2"], uses)
every = re.findall(r"^\s*(?:-\s+)?uses:\s*(\S+)", text, re.M)
check("every action reference in the file is a 40-hex commit digest",
      every and all(re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", u) for u in every), every)
check("the job's permissions are unchanged (contents read, packages read)", job["permissions"] == {"contents": "read", "packages": "read"}, job["permissions"])
check("the workflow's permissions are unchanged (contents read)", wf["permissions"] == {"contents": "read"}, wf["permissions"])
check("the stage's inputs are unchanged (digests only)", list(wf[True if True in wf else "on"]["workflow_call"]["inputs"]) == ["digests"])
check("the job has no container or services image", "container" not in job and "services" not in job)
r = subprocess.run(["git", "-C", root, "rev-parse", "--verify", "-q", "origin/main"], capture_output=True, text=True)
if r.returncode == 0:
    new = subprocess.run(["git", "-C", root, "diff", "--name-status", "--diff-filter=AR", "origin/main", "--", ".github/workflows"],
                         capture_output=True, text=True).stdout.strip()
    check("no workflow file is added or renamed relative to origin/main", new == "", new)
else:
    print("note: origin/main not available; the no-new-workflow check is left to the diff review")
pred = subprocess.run(["git", "-C", root, "diff", "--stat", "origin/main", "--", ".github/workflows/stage-acceptance-predicate.yml"],
                      capture_output=True, text=True).stdout if r.returncode == 0 else ""
check("stage-acceptance-predicate.yml is not changed", pred.strip() == "", pred)

# ---------------------------------------------------------------- B. behaviour
script = os.path.join(root, "bin/fips-image-posture.py")
def body(note): return json.dumps({"fips140_note": note, "version": "x"})
GOOD = {"production": body("off"), "debug": body("off"), "fips": body(GOOD_FIPS)}
def run(bodies, script=script, args=None):
    d = os.path.join(work, "case"); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    for k, v in bodies.items():
        if v is not None: open(os.path.join(d, k + ".json"), "w").write(v)
    return subprocess.run([sys.executable, script] + (args if args is not None else [d]), capture_output=True, text=True)
def mut(**kw): b = dict(GOOD); b.update(kw); return b
exists = os.path.isfile(script)
check("the comparison script bin/fips-image-posture.py exists", exists)
def passes(name, bodies):
    p = run(bodies) if exists else None
    check("passes: " + name, p is not None and p.returncode == 0, p and (p.returncode, p.stderr[-200:]))
def fails(name, bodies, who=None):
    p = run(bodies) if exists else None
    ok = p is not None and p.returncode != 0 and (who is None or who in p.stderr)
    check("fails: " + name, ok, p and (p.returncode, p.stderr[-200:]))
passes("the exact good strings", GOOD)
passes("extra fields and whitespace around the JSON", mut(fips=' {"a":1, "fips140_note": "%s"}\n' % GOOD_FIPS, production='{"fips140_note":"off","x":[1]}\n'))
fails("-fips reports off", mut(fips=body("off")), "fips")
fails("-fips reports the wrong certificate", mut(fips=body(GOOD_FIPS.replace("5247", "5248"))), "fips")
fails("-fips reports the wrong module version", mut(fips=body(GOOD_FIPS.replace("v1.0.0", "v1.0.1"))), "fips")
fails("-fips reports the forced-mode line", mut(fips=body(FORCED)), "fips")
fails("-fips string with a trailing space", mut(fips=body(GOOD_FIPS + " ")), "fips")
fails("-fips string in another case", mut(fips=body(GOOD_FIPS.upper())), "fips")
fails("-fips string only as a prefix of the report", mut(fips=body(GOOD_FIPS + "; extra")), "fips")
fails("production reports the fips string", mut(production=body(GOOD_FIPS)), "production")
fails("debug reports the fips string", mut(debug=body(GOOD_FIPS)), "debug")
fails("production reports the forced-mode line", mut(production=body(FORCED)), "production")
fails("debug reports the forced-mode line", mut(debug=body(FORCED)), "debug")
fails("production reports 'off ' (trailing space)", mut(production=body("off ")), "production")
fails("debug reports 'Off'", mut(debug=body("Off")), "debug")
fails("production reports 'off (x)'", mut(production=body("off (x)")), "production")
for v in ("production", "debug", "fips"):
    fails("the %s variant is missing" % v, mut(**{v: None}), v)
    fails("the %s body is empty" % v, mut(**{v: ""}), v)
    fails("the %s body is not JSON" % v, mut(**{v: "<html>not json</html>"}), v)
    fails("the %s body is truncated JSON" % v, mut(**{v: '{"fips140_note": "off"'}), v)
    fails("the %s body is a JSON array" % v, mut(**{v: '["off"]'}), v)
    fails("the %s body has no fips140_note" % v, mut(**{v: '{"version":"x"}'}), v)
    fails("the %s fips140_note is null" % v, mut(**{v: '{"fips140_note": null}'}), v)
    fails("the %s fips140_note is not a string" % v, mut(**{v: '{"fips140_note": 0}'}), v)
fails("all three variants are missing", {k: None for k in GOOD})
fails("a note in a nested object only", mut(fips='{"x":{"fips140_note":"%s"}}' % GOOD_FIPS), "fips")
p = run(GOOD, args=[]) if exists else None
check("fails: no argument", p is not None and p.returncode != 0, p and p.returncode)
p = run(GOOD, args=[os.path.join(work, "case"), "extra"]) if exists else None
check("fails: an extra argument", p is not None and p.returncode != 0, p and p.returncode)
p = run(GOOD, args=[os.path.join(work, "no-such-dir")]) if exists else None
check("fails: a directory that does not exist", p is not None and p.returncode != 0, p and p.returncode)

# ---------------------------------------------------------------- C. mutants
src = open(script).read() if exists else ""
MUTANTS = [
    ("the validated-module string loses its certificate number", lambda s: s.replace("CMVP cert #5247", "CMVP cert #5248")),
    ("the validated-module string loses its module version", lambda s: s.replace("v1.0.0", "v1.0.1")),
    ("the standard variants expect 'on' instead of 'off'", lambda s: s.replace('"off"', '"on"')),
    ("every failing exit becomes a success", lambda s: s.replace("sys.exit(1)", "sys.exit(0)")),
]
for name, f in MUTANTS:
    m = f(src)
    if not exists or m == src:
        check("mutant is caught: " + name, False, "script missing" if not exists else "mutation did not apply (the contract literal is absent)")
        continue
    mp = os.path.join(work, "mutant.py"); open(mp, "w").write(m)
    caught = False
    for bodies in [GOOD, mut(fips=body("off")), mut(production=body(GOOD_FIPS)), mut(production=None), mut(debug=body(FORCED)), mut(fips="")]:
        pass_good = run(bodies, script=mp).returncode == 0
        if bodies is GOOD and not pass_good: caught = True; break
        if bodies is not GOOD and pass_good: caught = True; break
    check("mutant is caught: " + name, caught)
print("fips-image-check: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
