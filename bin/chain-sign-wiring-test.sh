#!/usr/bin/env bash
# proves: REQ-CHAIN-001-AC1, REQ-CHAIN-001-AC2, REQ-CHAIN-001-AC3, REQ-CHAIN-002-AC4
# The Sign boundary (v0.3.0 rules 50, 50a, 52, 52a, 53a; owner RATIFIED Oct 9), static half: stage-sign.yml is a reusable
# workflow of exactly one job on a GitHub-hosted runner, takes only Build's digest list, runs nothing Build produced,
# never writes the identity token anywhere, and references no secret. The judge is first proven on a known-good fixture
# and on each mutated copy of it (a judge that cannot fail proves nothing), then applied to the real file, which must pass.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" "$root" <<'PY'
import os, re, sys, yaml
path, root = sys.argv[1], sys.argv[2]
bad = []
if not os.path.exists(path):
    print("missing: " + path); sys.exit(1)
text = open(path).read()
d = yaml.load(text, Loader=yaml.BaseLoader)
on = d.get("on") or {}
call = on.get("workflow_call") if isinstance(on, dict) else None
if call is None or (isinstance(on, dict) and set(on) != {"workflow_call"}):
    bad.append("AC1: not a reusable workflow only (on: must be exactly workflow_call): %s" % on)
jobs = d.get("jobs") or {}
if len(jobs) != 1:
    bad.append("AC1: exactly one job required, found %d" % len(jobs))
for name, j in jobs.items():
    ro = j.get("runs-on")
    if not isinstance(ro, str) or "self-hosted" in ro or not re.fullmatch(r"ubuntu-[0-9.]+(-arm)?|ubuntu-latest", ro):
        bad.append("AC1: job %s must run on a GitHub-hosted ubuntu runner, got %r" % (name, ro))
    if j.get("container") or j.get("services"):
        bad.append("AC2: job %s runs in a container or has services" % name)
    if j.get("uses"):
        bad.append("AC2: job %s calls another workflow" % name)
inputs = (call or {}).get("inputs") or {}
if set(inputs) != {"digests"} or (inputs.get("digests") or {}).get("type") != "string":
    bad.append("AC2: the only input must be `digests` (string), found %s" % sorted(inputs))
if (call or {}).get("secrets"):
    bad.append("AC3: the workflow declares secrets")
if re.search(r"\bsecrets\s*\.|secrets\[|\bsecrets:\s*inherit", text):
    bad.append("AC3/002-AC4: a secrets reference appears in the file")
steps = [s for j in jobs.values() for s in (j.get("steps") or [])]
for s in steps:
    u = s.get("uses", "") or ""
    if re.search(r"download-artifact|cache/restore|cache/save|cache@", u):
        bad.append("AC2: step %r brings build output in through an artifact or cache" % s.get("name"))
    if "upload-artifact" in u:
        up = str((s.get("with") or {}).get("path", "")).strip()
        if not re.fullmatch(r"provenance(/[A-Za-z0-9._-]*)?", up):
            bad.append("AC3 (artifact sink): step %r uploads %r; only the provenance bundle may leave Sign" % (s.get("name"), up))
    run = s.get("run") or ""
    # every sink rule 52a names (file, artifact, log, step output): Sign's steps never touch the token request at all;
    # the signing tool asks for the token inside its own process
    if re.search(r"ACTIONS_ID_TOKEN|ACTIONS_RUNTIME_TOKEN|id-token|oidc|\bsigstore/.*(key|token)", run, re.I):
        sinks = [n for n, rx in (("file", r">>?\s*\S|\btee\b|\bcp\b|\bmv\b"), ("log", r"\becho\b|\bprintf\b|\bcat\b|set\s+-\w*x|--verbose|-v\b"),
                                 ("step output", r"GITHUB_(OUTPUT|ENV|STEP_SUMMARY|PATH)"), ("artifact", r"upload"))
                 if re.search(rx, run)]
        bad.append("AC3: step %r touches the identity token request (sinks reachable: %s)" % (s.get("name"), ", ".join(sinks) or "none, but no step may touch it"))
    for k in ("env", "with"):
        for ek, ev in (s.get(k) or {}).items():
            if re.search(r"ACTIONS_ID_TOKEN_REQUEST|id-token|\$\{\{\s*(github\.token|secrets)", str(ev)):
                bad.append("AC3: step %r passes the token or a secret through %s.%s" % (s.get("name"), k, ek))
    if re.search(r"(?i)\b(bash|sh|python3?|node|source|\.)\s+(\./)?(dist|out|build|artifacts?|\$RUNNER_TEMP|\$\{\{\s*inputs)", run):
        bad.append("AC2: step %r runs something from a build output path" % s.get("name"))
perm = (d.get("permissions") or {}) if isinstance(d.get("permissions"), dict) else None
jp = [j.get("permissions") for j in jobs.values()][0] if jobs else None
eff = jp if isinstance(jp, dict) else perm
if not isinstance(eff, dict) or eff.get("id-token") != "write" or any(v == "write" for k, v in eff.items() if k != "id-token"):
    bad.append("AC3: Sign's permissions must be id-token: write and no other write: %s" % eff)
print("; ".join(bad) or "ok")
sys.exit(1 if bad else 0)
PY
}
expect() { # expect ok|caught label file
  local out rc=0
  out=$(judge "$3") || rc=$?
  if [ "$1" = ok ] && [ "$rc" = 0 ]; then pass=$((pass + 1)); echo "ok   $2"
  elif [ "$1" = caught ] && [ "$rc" != 0 ]; then pass=$((pass + 1)); echo "ok   $2 (caught: $out)"
  else failn=$((failn + 1)); echo "FAIL $2 -> $out"; fi
}
good="$work/good.yml"
cat > "$good" <<'EOF'
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
      - name: sign the provenance
        env:
          DIGESTS: ${{ inputs.digests }}
        run: |
          set -euo pipefail
          python3 bin/chain-verify.py sign --digests "$DIGESTS" --out provenance
      - name: hand the provenance bundle to Release
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: provenance
          path: provenance
EOF
mutate() { # label  python-regex-sub  replacement
  python3 - "$good" "$work/$1.yml" "$2" "$3" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
n = re.sub(sys.argv[3], sys.argv[4], t, count=1, flags=re.S)
assert n != t, "mutation did not change the fixture"
open(sys.argv[2], "w").write(n)
PY
}
expect ok "fixture: known-good passes the judge" "$good"
mutate m_self 'ubuntu-24.04' 'self-hosted'            && expect caught "AC1 self-hosted runner" "$work/m_self.yml"
mutate m_push 'workflow_call:' 'push:\n  workflow_call:' && expect caught "AC1 extra trigger" "$work/m_push.yml"
mutate m_job2 'steps:' 'steps: []\n  other:\n    runs-on: ubuntu-24.04\n    steps: []\n  extra:\n    steps:' && expect caught "AC1 second job" "$work/m_job2.yml"
mutate m_in 'digests:' 'digests:\n        type: string\n      script:\n        type: string\n      digests2:' && expect caught "AC2 extra input" "$work/m_in.yml"
mutate m_dl 'steps:' 'steps:\n      - uses: actions/download-artifact@0000000000000000000000000000000000000000 # v1\n        with: {name: dist}' && expect caught "AC2 downloads build output" "$work/m_dl.yml"
mutate m_run 'python3 bin/chain-verify.py sign --digests "\$DIGESTS"' 'bash dist/run.sh' && expect caught "AC2 runs a build output" "$work/m_run.yml"
mutate m_sec 'DIGESTS: \$\{\{ inputs.digests \}\}' 'DIGESTS: ${{ inputs.digests }}\n          K: ${{ secrets.KEY }}' && expect caught "AC3 secret reference" "$work/m_sec.yml"
mutate m_tok 'set -euo pipefail' 'set -euo pipefail\n          echo "tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN" >> "$GITHUB_OUTPUT"' && expect caught "AC3 sink step output" "$work/m_tok.yml"
mutate m_tokf 'set -euo pipefail' 'set -euo pipefail\n          curl -s "$ACTIONS_ID_TOKEN_REQUEST_URL" > "$RUNNER_TEMP/tok"' && expect caught "AC3 sink file" "$work/m_tokf.yml"
mutate m_tokl 'set -euo pipefail' 'set -euo pipefail\n          set -x; t=$ACTIONS_ID_TOKEN_REQUEST_TOKEN; echo "$t"' && expect caught "AC3 sink log" "$work/m_tokl.yml"
mutate m_toka 'path: provenance' 'path: ${{ runner.temp }}/tok' && expect caught "AC3 sink artifact" "$work/m_toka.yml"
mutate m_tokv 'set -euo pipefail' 'set -euo pipefail\n          export T=$(oidc-token)' && expect caught "AC3 token helper in a run step" "$work/m_tokv.yml"
mutate m_perm 'id-token: write' 'id-token: write\n      packages: write' && expect caught "AC3 extra write permission" "$work/m_perm.yml"
mutate m_noid 'id-token: write' 'id-token: none' && expect caught "AC3 no id-token" "$work/m_noid.yml"
real="$root/.github/workflows/stage-sign.yml"
expect ok "the real stage-sign.yml passes" "$real"
# AC1: stage-sign.yml is the only workflow file added since v0.2.2 (the v0.2.2 set is committed in the list below)
python3 - "$root" <<'PY' && { pass=$((pass + 1)); echo "ok   AC1 only stage-sign.yml is new"; } || { failn=$((failn + 1)); echo "FAIL AC1 workflow file set"; }
import os, sys
known = set("""acceptance.yml agent-review-gate.yml auditor.yml ci.yml codeql.yml dependabot-auto-merge.yml dependabot-reviewer.yml
go-freshness.yml main-candidate-rescan.yml release.yml reserved-branch-guard.yml scan.yml scorecard.yml
stage-acceptance-artifacts.yml stage-acceptance-egress.yml stage-acceptance-k8s.yml stage-acceptance-predicate.yml
stage-admission.yml stage-authorize.yml stage-build.yml stage-image.yml stage-promote.yml stage-reproducibility.yml
stage-verify.yml supply-chain.yml""".split())
have = set(os.listdir(os.path.join(sys.argv[1], ".github/workflows")))
new = sorted(have - known)
print("new workflow files:", new)
sys.exit(0 if new == ["stage-sign.yml"] else 1)
PY
# AC1: no other stage file signs provenance (the SLSA provenance is Sign's alone)
if grep -l -E 'slsa|provenance' "$root"/.github/workflows/stage-{build,reproducibility,verify,promote}.yml 2>/dev/null | xargs -r grep -l -E 'cosign (sign|attest)|witness run.*provenance|attest-build-provenance' >/dev/null 2>&1; then
  failn=$((failn + 1)); echo "FAIL AC1 another stage signs provenance"
else pass=$((pass + 1)); echo "ok   AC1 no other stage signs provenance"; fi
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
