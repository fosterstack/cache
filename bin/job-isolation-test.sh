#!/usr/bin/env bash
# proves: REQ-REL-011-AC1, REQ-REL-011-AC2
# The owner's isolation rule (ratified Oct 21 2026, ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): on GitHub-hosted runners
# the separate job is the isolation unit. AC1: a job that holds a credential (a secrets.* reference, an environment, id-token: write or
# packages: write) never compiles or builds; govulncheck, which publishes no release binary, is built in a job with no credential and
# reaches auditor.yml's audit job as an artifact whose sha256 the audit job compares first. AC2: no job runs two builds.
# AC2 scope: builds of what we ship or run as a tool. The acceptance/bench jobs that run a sample project's own Gradle/Maven build as the
# workload under test are not release builds and are outside it. The real workflows must pass (the four release-chain jobs the chain-v030 landing replaces are listed exclusions with their reason);
# each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import glob, os, re, sys, yaml
wf = sys.argv[1]
# a step that builds or compiles (commands and actions; comment lines never count)
COMPILE = re.compile(r"\bgo\s+(?:install|build)\b|goreleaser/goreleaser-action|\bgoreleaser\s+(?:build|release)\b|\bdocker\s+(?:buildx\s+)?build\b|\bbuildx\s+(?:build|bake)\b|docker/build-push-action|docker/bake-action"
                     r"|\binstall-scanner\.sh\s+govulncheck\b"          # govulncheck is built from source by this installer arm: the build the workflow text does not show
                     r"|\bmelange\s+build\b|\bapko\s+(?:build|publish)\b|\bcargo\s+(?:build|install)\b|\bmake\b|\bnpm\s+(?:run\s+)?build\b")
# Exclusions: none on the release-chain branch (cache#561 ruling B2). On main the table named the old release-chain jobs (stage-build build, stage-image assemble, stage-promote promote,
# stage-reproducibility reproduce, stage-acceptance-artifacts artifacts) that the chain landing replaces; those jobs do not exist here, so the rows are gone (the requirement's own note
# says the list shrinks to nothing at the landing). The stale-row check below stays: a row added later must name a job that exists.
EXCLUDED_AC1 = {}
EXCLUDED_AC2 = {}
def steps_text(s):
    t = (s.get("run") or "") + " " + (s.get("uses") or "") + " " + yaml.safe_dump(s.get("env") or {})
    return "\n".join(l for l in t.split("\n") if not l.strip().startswith("#"))
def holds(d, j):
    perms = j.get("permissions", d.get("permissions"))
    why = []
    wf_level = yaml.safe_dump({k: v for k, v in d.items() if k not in ("jobs", "on", True)})   # workflow-level env/defaults every job inherits
    if re.search(r"\bsecrets\s*(?:\.|\[)|secrets:\s*inherit", yaml.safe_dump(j) + wf_level):
        why.append("a secret")
    if perms == "write-all":
        why.append("write-all")
    if j.get("environment"):
        why.append("an environment")
    if isinstance(perms, dict):
        why += [k + ": write" for k in ("id-token", "packages") if perms.get(k) == "write"]
    return why
bad = []
jobs_seen = {}
for f in sorted(glob.glob(os.path.join(wf, "*.y*ml"))):
    d = yaml.safe_load(open(f)) or {}
    for jn, j in (d.get("jobs") or {}).items():
        if not isinstance(j, dict):
            continue
        key = (os.path.basename(f), jn)
        jobs_seen[key] = j
        comp = []                                                  # one entry per build invocation (a step with two `go build` counts twice)
        for s in (j.get("steps") or []):
            txt = steps_text(s)
            n = len(COMPILE.findall(txt))
            for body in re.findall(r"\b(?:for|while|until)\b[^\n]*?;?\s*\bdo\b(.*?)\bdone\b", txt, re.S):
                n += len(COMPILE.findall(body))              # a build inside a loop runs more than once
            comp += [s.get("name") or s.get("uses") or "?"] * n
        w = holds(d, j)
        if w and comp and key not in EXCLUDED_AC1:
            bad.append("%s/%s holds %s and builds in the step %r" % (key[0], jn, ", ".join(w), comp[0]))
        if len(comp) >= 2 and key not in EXCLUDED_AC2:
            bad.append("%s/%s runs two builds: %r and %r" % (key[0], jn, comp[0], comp[1]))
# an exclusion must still name a job that exists (a stale row hides nothing but must not rot)
for key in list(EXCLUDED_AC1) + list(EXCLUDED_AC2):
    if key not in jobs_seen:
        bad.append("the exclusion %s/%s names a job that does not exist (remove the row)" % key)
# govulncheck: built in its own credential-free job, checked by digest before the audit job uses it
a = yaml.safe_load(open(os.path.join(wf, "auditor.yml"))) or {}
b = (a.get("jobs") or {}).get("govulncheck-build")
audit = (a.get("jobs") or {}).get("audit") or {}
if not b:
    bad.append("auditor.yml has no govulncheck-build job")
else:
    if holds(a, b) or b.get("environment"):
        bad.append("govulncheck-build holds a credential: %s" % holds(a, b))
    if not any("govulncheck" in steps_text(s) and "go install" in steps_text(s) for s in b.get("steps") or []):
        bad.append("govulncheck-build does not build govulncheck")
    if not (isinstance(b.get("outputs"), dict) and "sha256" in b["outputs"]):
        bad.append("govulncheck-build has no sha256 output")
needs = audit.get("needs")
needs = [needs] if isinstance(needs, str) else (needs or [])
if "govulncheck-build" not in needs:
    bad.append("the audit job does not need govulncheck-build")
atxt = "\n".join(steps_text(s) for s in audit.get("steps") or [])
if "needs.govulncheck-build.outputs.sha256" not in atxt or "sha256sum" not in atxt:
    bad.append("the audit job does not compare the downloaded govulncheck with the build job's sha256 output")
GATE = (r'if \[ -n "\$\{GOVULNCHECK_SHA256\}" \] && \[ -f "[^"]*govulncheck-dl/govulncheck" \]\s*\\\n\s*&& \[ "\$\(sha256sum "[^"]*govulncheck-dl/govulncheck" \| cut -d\' \' -f1\)" = "\$\{GOVULNCHECK_SHA256\}" \]; then\n\s+install -m 0755 "[^"]*govulncheck-dl/govulncheck"')
if not re.search(GATE, atxt):
    bad.append("the audit job's install of govulncheck is not gated by an equality of the downloaded file's sha256 with the build job's output")
g = re.search(GATE, atxt)
if g:
    allowed = len(re.findall(r"govulncheck-dl", g.group(0))) + sum(1 for l in atxt.split("\n") if re.fullmatch(r'\s*gh run download "\$\{GITHUB_RUN_ID\}" -n govulncheck -D "\$\{RUNNER_TEMP\}/govulncheck-dl" \\', l))
    if atxt.count("govulncheck-dl") > allowed:
        bad.append("the downloaded govulncheck is referenced outside the digest-gated install")
if re.search(r"go\s+install\s+golang\.org/x/vuln", atxt):
    bad.append("the audit job still builds govulncheck itself")
# the Check stage (stage-verify.yml): govulncheck is built by `install-scanner.sh govulncheck` (a Go module, no release binary), so its build gets its own job with no
# credential; the `check` job (id-token: write, for Witness) downloads it and installs it only after its sha256 equals the build job's output. The output proves
# the artifact arrived intact; the guarantee is that no build runs in a job that holds a credential (AC1 above, which now sees this installer arm as a build).
sv = yaml.safe_load(open(os.path.join(wf, "stage-verify.yml"))) or {}
sj = sv.get("jobs") or {}
gb = sj.get("govulncheck-build")
chk = sj.get("check") or {}
if not gb:
    bad.append("stage-verify.yml has no govulncheck-build job")
else:
    if holds(sv, gb):
        bad.append("stage-verify.yml govulncheck-build holds a credential: %s" % holds(sv, gb))
    if not any("install-scanner.sh govulncheck" in steps_text(st) for st in gb.get("steps") or []):
        bad.append("stage-verify.yml govulncheck-build does not build govulncheck")
    if not (isinstance(gb.get("outputs"), dict) and "sha256" in gb["outputs"]):
        bad.append("stage-verify.yml govulncheck-build has no sha256 output")
cneeds = chk.get("needs")
cneeds = [cneeds] if isinstance(cneeds, str) else (cneeds or [])
if "govulncheck-build" not in cneeds:
    bad.append("stage-verify.yml check does not need govulncheck-build")
csteps = chk.get("steps") or []
ctxt = "\n".join(steps_text(st) for st in csteps)
if "needs.govulncheck-build.outputs.sha256" not in ctxt or "sha256sum" not in ctxt:
    bad.append("stage-verify.yml check does not compare the downloaded govulncheck with the build job's sha256 output")
GATE2 = (r'\[ "\$\(sha256sum govulncheck-dl/govulncheck \| cut -d\' \' -f1\)" = "\$\{GOVULNCHECK_SHA256\}" \] \|\| [^\n]*exit 1[^\n]*\n\s*'
         r'install -m 0755 govulncheck-dl/govulncheck /usr/local/bin/govulncheck')
if not re.search(GATE2, ctxt):
    bad.append("stage-verify.yml check installs govulncheck without the equality gate (sha256 of the downloaded file against the build job's output, then install)")
else:
    inst = [st for st in csteps if "govulncheck-dl/govulncheck" in (st.get("run") or "")]
    if len(inst) != 1 or (inst[0].get("env") or {}) != {"GOVULNCHECK_SHA256": "${{ needs.govulncheck-build.outputs.sha256 }}"}:
        bad.append("stage-verify.yml check: the downloaded govulncheck is used outside the one gated step, or the gate's expected digest is not the build job's output")
print("\n".join(bad)); sys.exit(1 if bad else 0)
PY
}
check() { local name=$1 want=$2 dir=$3 out rc=0
  out=$(judge "$dir" 2>&1) || rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } || { [ "$want" = bad ] && [ $rc -ne 0 ]; }; then pass=$((pass+1)); echo "ok   $name"
  else failn=$((failn+1)); echo "FAIL $name (want $want, rc=$rc): $out"; fi; }
mutate() { local name=$1 py=$2 dir="$work/$1"
  rm -rf "$dir"; mkdir -p "$dir"; cp "$root"/.github/workflows/*.y*ml "$dir/"
  python3 - "$dir" <<PY
import os, re, sys, yaml
wf = sys.argv[1]
def edit(fname, fn):
    p = os.path.join(wf, fname); s = open(p).read(); s2 = fn(s); assert s2 != s, "mutation did not apply"; open(p, "w").write(s2)
$py
PY
  check "$name" bad "$dir"; }

check "the real workflows" ok "$root/.github/workflows"
# AC1: a build added to a job that holds a credential
mutate "go install added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: s.replace("./bin/install-scanner.sh crane\n\n      - name: log in", "GOBIN=/usr/local/bin go install github.com/google/go-containerregistry/cmd/crane@v0.22.1\n\n      - name: log in", 1))'
mutate "go build added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: s.replace("  panel-probe:\n", "  panel-probe:\n", 1).replace("    environment: agent\n", "    environment: agent\n    # mutated\n", 1))
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: go build ./...\n", s, count=1, flags=re.S))'
mutate "make added to a job with id-token: write (stage-verify check)" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: make all\n", s, count=1, flags=re.S))'
mutate "docker build added to a job that reads a secret (release.yml decide)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: docker build -t x .\n", s, count=1, flags=re.S))'
mutate "id-token: write granted to a job that builds (ci.yml gosec)" '
edit("ci.yml", lambda s: re.sub(r"(  gosec:.*?    permissions:\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
# AC2: a second build in one job
mutate "a second build step in one job (ci.yml gosec)" '
edit("ci.yml", lambda s: re.sub(r"(  gosec:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant one\n        run: go build ./a\n      - name: mutant two\n        run: go build ./b\n", s, count=1, flags=re.S))'
# the govulncheck hand-over
mutate "audit job builds govulncheck itself again" '
edit("auditor.yml", lambda s: s.replace("      - name: Install syft and govulncheck and build the validated run manifest\n", "      - name: mutant\n        run: GOBIN=x go install golang.org/x/vuln/cmd/govulncheck@v1.1.4\n      - name: Install syft and govulncheck and build the validated run manifest\n", 1))'
mutate "digest comparison inverted (!= instead of =)" '
edit("auditor.yml", lambda s: s.replace("cut -d\x27 \x27 -f1)\" = \"${GOVULNCHECK_SHA256}\"", "cut -d\x27 \x27 -f1)\" != \"${GOVULNCHECK_SHA256}\""))'
mutate "install no longer gated by the digest" '
edit("auditor.yml", lambda s: re.sub(r"if \[ -n \"\$\{GOVULNCHECK_SHA256\}\" \].*?; then\n(\s+install -m 0755 \"\$\{RUNNER_TEMP\}/govulncheck-dl)", lambda m: "if true; then\n" + m.group(1), s, count=1, flags=re.S))'
mutate "audit job no longer compares the sha256" '
edit("auditor.yml", lambda s: s.replace("needs.govulncheck-build.outputs.sha256", "needs.govulncheck-build.outputs.other"))'
mutate "govulncheck-build gets a secret" '
edit("auditor.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\n        run: echo x\n", s, count=1, flags=re.S))'
mutate "govulncheck-build gets an environment" '
edit("auditor.yml", lambda s: re.sub(r"(  govulncheck-build:\n)", lambda m: m.group(1) + "    environment: agent\n", s, count=1))'
mutate "write-all on a job that builds (ci.yml gosec)" '
edit("ci.yml", lambda s: re.sub(r"(  gosec:.*?)    permissions:\n", lambda m: m.group(1) + "    permissions: write-all\n    xperm:\n", s, count=1, flags=re.S))'
mutate "a workflow-level secret next to the govulncheck build" '
edit("auditor.yml", lambda s: re.sub(r"(\njobs:\n)", lambda m: "\nenv:\n  K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}" + m.group(1), s, count=1))'
mutate "an ungated copy of the install after the gate" '
edit("auditor.yml", lambda s: s.replace("          # syft: a pinned, checksum-verified", "          install -m 0755 \"${RUNNER_TEMP}/govulncheck-dl/govulncheck\" \"${RUNNER_TEMP}/gobin/govulncheck\"\n          # syft: a pinned, checksum-verified", 1))'
mutate "a go build loop in one job (ci.yml gosec)" '
edit("ci.yml", lambda s: re.sub(r"(  gosec:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant loop\n        run: |\n          for t in ./a ./b; do go build \"$t\"; done\n", s, count=1, flags=re.S))'
mutate "a bracket-form secret in the govulncheck build" '
edit("auditor.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets[\x27AUDITOR_APP_PRIVATE_KEY\x27] }}\n        run: echo x\n", s, count=1, flags=re.S))'
mutate "an ungated install appended to the download line" '
edit("auditor.yml", lambda s: s.replace("-D \"${RUNNER_TEMP}/govulncheck-dl\" \\\n", "-D \"${RUNNER_TEMP}/govulncheck-dl\"; install -m 0755 \"${RUNNER_TEMP}/govulncheck-dl/govulncheck\" \"${RUNNER_TEMP}/gobin/govulncheck\" \\\n", 1))'
mutate "the audit job stops needing the build job" '
edit("auditor.yml", lambda s: s.replace("needs: [govulncheck-build]", "needs: []"))'

# the hidden build (install-scanner.sh govulncheck compiles from source) in a credential-holding job: the one that lost it, and any other
mutate "install-scanner.sh govulncheck put back in the Check job (id-token: write)" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to the arm64 Check job (id-token: write)" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check-arm64:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: s.replace("./bin/install-scanner.sh crane\n\n      - name: log in", "./bin/install-scanner.sh crane\n          bash bin/install-scanner.sh govulncheck\n\n      - name: log in", 1))'
mutate "install-scanner.sh govulncheck added to a job that reads a secret (release.yml decide)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
# the Check stage hand-over
mutate "the Check job stops needing govulncheck-build" '
edit("stage-verify.yml", lambda s: s.replace("    needs: govulncheck-build\n", "", 1))'
mutate "the Check job no longer compares the sha256" '
edit("stage-verify.yml", lambda s: s.replace("needs.govulncheck-build.outputs.sha256", "needs.govulncheck-build.outputs.other"))'
mutate "the Check job installs the downloaded govulncheck with the comparison inverted" '
edit("stage-verify.yml", lambda s: s.replace("cut -d\x27 \x27 -f1)\" = \"${GOVULNCHECK_SHA256}\"", "cut -d\x27 \x27 -f1)\" != \"${GOVULNCHECK_SHA256}\""))'
mutate "govulncheck-build is granted id-token: write" '
edit("stage-verify.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    permissions:\n      contents: read\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
mutate "govulncheck-build reads a secret" '
edit("stage-verify.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\n        run: echo x\n", s, count=1, flags=re.S))'
mutate "govulncheck-build has no sha256 output" '
edit("stage-verify.yml", lambda s: s.replace("    outputs:\n      sha256: ${{ steps.build.outputs.sha256 }}\n", "", 1))'
mutate "the downloaded govulncheck is installed a second time without the gate" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: install -m 0755 govulncheck-dl/govulncheck /usr/local/bin/govulncheck\n", s, count=1, flags=re.S))'


echo "job-isolation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
