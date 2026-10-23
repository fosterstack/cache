#!/usr/bin/env bash
# proves: REQ-REL-011-AC1, REQ-REL-011-AC2
# The owner's isolation rule (ratified Oct 21 2026, ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): on GitHub-hosted runners
# the separate job is the isolation unit. AC1: a job that holds a credential (a secrets.* reference, an environment, id-token: write or
# packages: write) never compiles or builds; govulncheck, which publishes no release binary, is built in a job with no credential and
# reaches auditor.yml's audit job as an artifact whose sha256 the audit job compares first, and stage-verify.yml's Check job as an artifact whose download keeps download-artifact's own
# digest check on (no override). The build that `install-scanner.sh govulncheck` hides inside a script counts: the installer word is read after quotes and continuations are
# normalized, and a word the judge cannot read is refused in a credential job. AC2: no job runs two builds.
# AC2 scope: builds of what we ship or run as a tool. The acceptance/bench jobs that run a sample project's own Gradle/Maven build as the
# workload under test are not release builds and are outside it. The real workflows must pass (the four release-chain jobs the chain-v030 landing replaces are listed exclusions with their reason);
# each mutated copy must be caught.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
judge() { python3 - "$1" <<'PY'
import glob, json, os, re, sys, yaml
wf = sys.argv[1]
# a step that builds or compiles (commands and actions; comment lines never count)
COMPILE = re.compile(r"\bgo\s+(?:install|build)\b|goreleaser/goreleaser-action|\bgoreleaser\s+(?:build|release)\b|\bdocker\s+(?:buildx\s+)?build\b|\bbuildx\s+(?:build|bake)\b|docker/build-push-action|docker/bake-action"
                                          r"|\bmelange\s+build\b|\bapko\s+(?:build|publish)\b|\bcargo\s+(?:build|install)\b|\bmake\b|\bnpm\s+(?:run\s+)?build\b")
# Exclusions: none on the release-chain branch (cache#561 ruling B2). On main the table named the old release-chain jobs (stage-build build, stage-image assemble, stage-promote promote,
# stage-reproducibility reproduce, stage-acceptance-artifacts artifacts) that the chain landing replaces; those jobs do not exist here, so the rows are gone (the requirement's own note
# says the list shrinks to nothing at the landing). The stale-row check below stays: a row added later must name a job that exists.
EXCLUDED_AC1 = {}
EXCLUDED_AC2 = {}
# govulncheck is a Go module built from source by the installer arm `install-scanner.sh govulncheck`: a build the workflow text does not show. The tool argument is read after the
# line continuations are joined and the quote and backslash characters are dropped from the word. A word that begins with a variable is resolved only through a literal
# `for VAR in WORDS; do` in the same step (a govulncheck among the words is the build); any other leading-variable word is unresolved and refused in a credential job unless it is a
# listed exclusion with its reason. A word with a literal prefix (docker-scout-$v) names a different arm, except a govulncheck prefix, which is the build.
INSTALLER = re.compile(r"\binstall-scanner\.sh[ \t]+([^\s;&|)]+)")
def installer_args(txt):
    t = re.sub(r"\\\n[ \t]*", "", txt)
    out = []
    for m in INSTALLER.finditer(t):
        a = re.sub(r"['\"\\]", "", m.group(1))
        v = re.fullmatch(r"\$\{?(\w+)\}?", a)
        if v:
            loops = re.findall(r"\bfor\s+" + v.group(1) + r"\s+in\s+([^;\n]*?)\s*;\s*do\b", t)
            if loops:
                out += [re.sub(r"['\"\\]", "", w) for w in loops[0].split()]
                continue
        out.append(a)
    return out
def builds_govulncheck(a):
    return a == "govulncheck" or a.startswith("govulncheck")
# In a job that holds a credential, a line that names install-scanner.sh passes ONLY as exactly `bash bin/install-scanner.sh TOOL` (or `./bin/install-scanner.sh TOOL`), optionally
# followed by one quoted destination word (no command substitution) and a trailing comment, where TOOL is a literal word that is not govulncheck, or a literal prefix ending in a dash and
# a variable (docker-scout-$v: a word with a dash cannot be govulncheck). Every other form is refused: a quoted or backslash-continued path or word, a tool word from a variable,
# a loop or stdin, a redirection, a pipe, a wrapper (bash -c, xargs, env), a second command on the line. The few real lines outside the grammar are listed below, each exact, with the
# lines the same step must also carry; a new line outside the grammar needs a new row here, in review.
ALLOWED = re.compile(r'(?:bash bin/|\./bin/)install-scanner\.sh (?P<tool>[a-z0-9][a-z0-9.-]*|"?[a-z0-9][a-z0-9.-]*-\$\{?[A-Za-z_]\w*\}?"?)(?: "(?:[^"`\\$]|\$(?!\())*")?(?:[ \t]+#.*)?')
EXCLUDED_INSTALLER = {
    ("auditor.yml", "audit"): {"lines": ['./bin/install-scanner.sh syft "${RUNNER_TEMP}/gobin" \\', './bin/install-scanner.sh syft "${RUNNER_TEMP}/gobin" || echo "::warning::could not install syft; the package inventory falls back to matched packages"'], "needs": [], "why": "the syft install whose failure is a warning (the line continues on the next line)"},
    ("main-candidate-rescan.yml", "scout-root-cause"): {"lines": ['./bin/install-scanner.sh "$t" "$RUNNER_TEMP/$t"'], "needs": ["for t in docker-scout docker-scout-1.25.0 docker-scout-1.24.0; do"], "forbid": r"(?<![\w$])t=", "why": "a loop over three literal docker-scout names, t assigned nowhere else in the step"},
}
def names_installer(line):
    """True when the line could name bin/install-scanner.sh: the name with its quote and backslash characters removed (install-"scanner".sh is the same word to the shell), or an
    install-* word built with a variable, a glob or a substitution (fail closed: such a line is outside the grammar and is refused in a credential job)."""
    norm = re.sub(r"[\"'\\]", "", line)
    return "install-scanner" in norm or re.search(r"install-[^\s/]*[$*?\[{`]", norm) is not None
def installer_problems(txt, key):
    """Lines of this step text that name install-scanner but are outside the grammar and the listed exceptions."""
    out = []
    exc = EXCLUDED_INSTALLER.get(key)
    joined = re.sub(r"\\\n[ \t]*", "", txt)    # a backslash-newline continuation is one logical line: bin/install-\<newline>scanner.sh is the installer
    for raw in txt.split("\n") + (joined.split("\n") if joined != txt else []):
        line = raw.strip()
        if not names_installer(line) or line.startswith("#"):
            continue
        head = re.split(r"\s#", line, maxsplit=1)[0]   # a name only in a trailing comment (quotes balanced before it) is prose, not a command
        if not names_installer(head) and head.count('"') % 2 == 0 and head.count("'") % 2 == 0:
            continue
        m = ALLOWED.fullmatch(line)
        if m:
            tool = re.sub(r'["\\]', "", m.group("tool"))
            if builds_govulncheck(tool):
                out.append(line)
            continue
        if exc and line in exc["lines"] and all(n in txt for n in exc["needs"]) and not (exc.get("forbid") and re.search(exc["forbid"], txt.replace(exc["needs"][0], "") if exc["needs"] else txt)):
            continue
        out.append(line)
    return out
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
        unresolved = []                                            # steps that hand install-scanner.sh a tool name the judge cannot read
        for s in (j.get("steps") or []):
            txt = steps_text(s)
            n = len(COMPILE.findall(txt))
            for body in re.findall(r"\b(?:for|while|until)\b[^\n]*?;?\s*\bdo\b(.*?)\bdone\b", txt, re.S):
                n += len(COMPILE.findall(body))              # a build inside a loop runs more than once
            for a in installer_args(txt):
                if builds_govulncheck(a):
                    n += 1
            if holds(d, j) and key not in EXCLUDED_AC1:
                unresolved += [(s.get("name") or "?", l) for l in installer_problems(s.get("run") or "", key)]
            comp += [s.get("name") or s.get("uses") or "?"] * n
        w = holds(d, j)
        if w and comp and key not in EXCLUDED_AC1:
            bad.append("%s/%s holds %s and builds in the step %r" % (key[0], jn, ", ".join(w), comp[0]))
        if w and unresolved:
            bad.append("%s/%s holds %s and runs the line %r in the step %r: a credential job may name install-scanner.sh only as exactly `bash bin/install-scanner.sh TOOL` (TOOL a literal word, not govulncheck) or a listed exception" % (key[0], jn, ", ".join(w), unresolved[0][1], unresolved[0][0]))
        if len(comp) >= 2 and key not in EXCLUDED_AC2:
            bad.append("%s/%s runs two builds: %r and %r" % (key[0], jn, comp[0], comp[1]))
# a listed installer exception must name a job that exists, and scan.yml's matrix (the one tool word read from a list) must be exactly the pr_gate-driven shape
for key in EXCLUDED_INSTALLER:
    if key not in jobs_seen:
        bad.append("the installer exception %s/%s names a job that does not exist (remove the row)" % key)
sc = json.load(open(os.environ.get("ISO_SCANNERS") or os.path.join(os.path.dirname(os.path.abspath(wf)), "policy", "scanners.json")))
if "govulncheck" in (sc.get("pr_gate") or []):
    bad.append("scanners.json pr_gate holds govulncheck: scan.yml's matrix job would build it (it holds no credential now, but the list is still the scanner set)")
scan_d = yaml.safe_load(open(os.path.join(wf, "scan.yml"))) or {}
scan_txt = open(os.path.join(wf, "scan.yml")).read()
if "jq -c '.pr_gate' .github/policy/scanners.json" not in scan_txt:
    bad.append("scan.yml no longer reads its matrix list from scanners.json pr_gate")
sj_ = ((scan_d.get("jobs") or {}).get("scanner") or {})
if (sj_.get("strategy") or {}).get("matrix") != {"scanner": "${{ fromJSON(needs.scanners.outputs.list) }}"}:
    bad.append("scan.yml scanner: the matrix must be exactly scanner from the scanners job's list (no include, exclude or other axis): %s" % (sj_.get("strategy") or {}).get("matrix"))
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
# the Check stage (stage-verify.yml): govulncheck is built by `install-scanner.sh govulncheck` (a Go module, no release binary), so its build gets its own job with no credential;
# the `check` job (id-token: write, for Witness) downloads the artifact with download-artifact's own digest check left on (it fails the step when the digest differs from the one GitHub
# recorded at upload) and installs it. The download is by the artifact id the build job exports, not by name, so a same-name artifact another job uploads is not the one it gets. The check
# and the id prove only that the artifact arrived intact and is the one that job uploaded; the guarantee is that no build runs in a job
# that holds a credential (AC1 above, which sees this installer arm as a build).
sv = yaml.safe_load(open(os.path.join(wf, "stage-verify.yml"))) or {}
sj = sv.get("jobs") or {}
gb = sj.get("govulncheck-build")
chk = sj.get("check") or {}
if not gb:
    bad.append("stage-verify.yml has no govulncheck-build job")
else:
    if holds(sv, gb):
        bad.append("stage-verify.yml govulncheck-build holds a credential: %s" % holds(sv, gb))
    if not any("govulncheck" in installer_args(steps_text(st)) for st in gb.get("steps") or []):
        bad.append("stage-verify.yml govulncheck-build does not build govulncheck")
    if gb.get("outputs") != {"artifact-id": "${{ steps.upload.outputs.artifact-id }}"}:
        bad.append("stage-verify.yml govulncheck-build must expose exactly the output artifact-id, the artifact-id of its upload step: %s" % gb.get("outputs"))
    ups = [st for st in gb.get("steps") or [] if str(st.get("uses") or "").startswith("actions/upload-artifact@")]
    if len(ups) != 1 or ups[0].get("id") != "upload" or ups[0].get("with") != {"name": "govulncheck", "path": "govulncheck-out/govulncheck"}:
        bad.append("stage-verify.yml govulncheck-build must have exactly one upload-artifact step, with id: upload, carrying the artifact govulncheck from govulncheck-out/govulncheck")
    packs = [st for st in gb.get("steps") or [] if "pack-govulncheck" in (st.get("run") or "")]
    if len(packs) != 1 or (packs[0].get("run") or "").strip() != "bash bin/pack-govulncheck.sh":
        bad.append("stage-verify.yml govulncheck-build must place the binary with exactly one plain step, `run: bash bin/pack-govulncheck.sh`")
cneeds = chk.get("needs")
cneeds = [cneeds] if isinstance(cneeds, str) else (cneeds or [])
if "govulncheck-build" not in cneeds:
    bad.append("stage-verify.yml check does not need govulncheck-build")
csteps = chk.get("steps") or []
dls = [st for st in csteps if str(st.get("uses") or "").startswith("actions/download-artifact@") and ("artifact-ids" in (st.get("with") or {}) or (st.get("with") or {}).get("name") == "govulncheck")]
if len(dls) != 1:
    bad.append("stage-verify.yml check must download the govulncheck artifact exactly once, by the artifact id of govulncheck-build")
else:
    # the digest check of download-artifact stays on: the step carries only uses and with {name, path} (no digest-mismatch input, no continue-on-error, no if), and nothing in the file sets digest-mismatch
    if set(dls[0]) - {"name", "uses", "with"} or (dls[0].get("with") or {}) != {"artifact-ids": "${{ needs.govulncheck-build.outputs.artifact-id }}", "path": "govulncheck-dl"}:
        bad.append("stage-verify.yml check: the govulncheck download must carry only uses and with exactly artifact-ids ${{ needs.govulncheck-build.outputs.artifact-id }} and path govulncheck-dl (no name, no digest-mismatch input, no continue-on-error, no if): %s" % sorted(dls[0]))
if "digest-mismatch" in open(os.path.join(wf, "stage-verify.yml")).read():
    bad.append("stage-verify.yml sets digest-mismatch (download-artifact's default, error, must stand untouched)")
HAND = "bash bin/unpack-govulncheck.sh"
inst = [st for st in csteps if "unpack-govulncheck" in (st.get("run") or "")]
if len(inst) != 1 or (inst[0].get("run") or "").strip() != HAND or set(inst[0]) - {"name", "run"}:
    bad.append("stage-verify.yml check: the downloaded govulncheck must be used by exactly one plain step, `run: %s` (no env, if or continue-on-error)" % HAND)
if chk.get("continue-on-error") or gb and gb.get("continue-on-error"):
    bad.append("stage-verify.yml: continue-on-error on the Check job or its build job")
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

export ISO_SCANNERS="$root/.github/policy/scanners.json"   # the policy file the pr_gate check reads (mutated copies of the workflows keep the real one)
check "the real workflows" ok "$root/.github/workflows"
# AC1: a build added to a job that holds a credential
mutate "go install added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: s.replace("./bin/install-scanner.sh crane\n", "GOBIN=/usr/local/bin go install github.com/google/go-containerregistry/cmd/crane@v0.22.1\n", 1))'
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

# the same hidden build written in the other ordinary shell forms, in a credential-holding job that is not the Check job (go-freshness refresh: App key, packages: write)
gf() { local name=$1; GFLINE=$2 mutate "$name" '
edit("go-freshness.yml", lambda s: s.replace("./bin/install-scanner.sh crane\n", "./bin/install-scanner.sh crane\n          " + os.environ["GFLINE"] + "\n", 1))'; }
gf "install-scanner.sh \"govulncheck\" (double-quoted tool word)" 'bash bin/install-scanner.sh "govulncheck"'
gf "install-scanner.sh 'govulncheck' (single-quoted tool word)" "bash bin/install-scanner.sh 'govulncheck'"
gf "install-scanner.sh govu\"\"lncheck (quotes inside the word)" 'bash bin/install-scanner.sh govu""lncheck'
gf "install-scanner.sh with a backslash-continued tool word" 'bash bin/install-scanner.sh \
            govulncheck'
gf "install-scanner.sh with a variable tool word (T=govulncheck)" 'T=govulncheck; bash bin/install-scanner.sh "$T"'
gf "install-scanner.sh with a tool word from a loop that names govulncheck" 'for t in grype govulncheck; do bash bin/install-scanner.sh "$t"; done'
gf "install-scanner.sh with an unresolved tool word in a credential job" 'bash bin/install-scanner.sh "${TOOL}"'
gf "install-scanner.sh govulncheck with extra spaces" 'bash bin/install-scanner.sh     govulncheck'
gf "install-scanner.sh govulncheck inside a bash -c wrapper" "bash -c 'bash bin/install-scanner.sh govulncheck'"
gf "install-scanner.sh with a govulncheck-prefixed tool word" 'bash bin/install-scanner.sh govulncheck-x'
gf "install-scanner.sh with a quoted script path" 'bash "bin/install-scanner.sh" govulncheck'
gf "install-scanner.sh with a single-quoted script path" "bash 'bin/install-scanner.sh' govulncheck"
gf "install-scanner.sh fed the tool word on stdin through xargs" 'echo govulncheck | xargs bash bin/install-scanner.sh'
gf "install-scanner.sh with a redirection before the tool word" 'bash bin/install-scanner.sh >/dev/null govulncheck'
gf "install-scanner.sh with a command substitution in the tool word" 'bash bin/install-scanner.sh gov$(echo ulncheck)'
gf "install-scanner.sh with a brace-expanded tool word" 'bash bin/install-scanner.sh {govulncheck,crane}'
gf "install-scanner.sh after a second loop that assigns govulncheck" 'for t in grype; do bash bin/install-scanner.sh "$t"; done; for t in govulncheck; do bash bin/install-scanner.sh "$t"; done'
gf "install-scanner.sh reading a variable assigned after an unrelated loop" 'for tool in crane; do echo "$tool"; done; tool=govulncheck; bash bin/install-scanner.sh "$tool"'
gf "install-scanner.sh with a second command on the line" 'bash bin/install-scanner.sh crane && bash bin/install-scanner.sh govulncheck'
gf "install-scanner.sh run through env" 'env bash bin/install-scanner.sh govulncheck'
gf "install-scanner.sh with a command substitution in the destination" 'bash bin/install-scanner.sh crane "$(echo /tmp)"'
gf "install-scanner.sh with a trailing comment that hides nothing (still the build)" 'bash bin/install-scanner.sh govulncheck # crane'
gf "install-scanner.sh in a bash -c string with the build" "bash -c 'bash bin/install-scanner.sh crane; bash bin/install-scanner.sh govulncheck'"
gf "install-scanner.sh written with a quoted fragment in its name (install-\"scanner\".sh)" 'bash bin/install-"scanner".sh govulncheck'
gf "install-scanner.sh written with a single-quoted fragment in its name" "bash bin/inst'all-scan'ner.sh govulncheck"
gf "install-scanner.sh written with an empty quoted pair in its name" 'bash bin/install-scan""ner.sh govulncheck'
gf "install-scanner.sh written with a backslash in its name" 'bash bin/install\-scanner.sh govulncheck'
gf "install-scanner.sh name built from a variable (install-\$x.sh)" 'x=scanner; bash "bin/install-$x.sh" govulncheck'
gf "install-scanner.sh name built from a glob (install-s*.sh)" 'bash bin/install-s*.sh govulncheck'
gf "install-scanner.sh name split by a backslash-newline continuation with a variable tool word" 'T=govulncheck; bash bin/install-\
scanner.sh "$T"'
gf "install-scanner.sh name held in a variable" 'S=install-scanner; bash bin/$S.sh govulncheck'
mutate "an extra installer line with a quoted name inside the scout-root-cause exception step" '
edit("main-candidate-rescan.yml", lambda s: s.replace("          for t in docker-scout docker-scout-1.25.0 docker-scout-1.24.0; do\n", "          bash bin/install-\"scanner\".sh govulncheck\n          for t in docker-scout docker-scout-1.25.0 docker-scout-1.24.0; do\n", 1))'
mutate "an extra installer line in the auditor syft exception step" '
edit("auditor.yml", lambda s: s.replace("          ./bin/install-scanner.sh syft \"${RUNNER_TEMP}/gobin\" \\\n", "          bash bin/install-\"scanner\".sh govulncheck\n          ./bin/install-scanner.sh syft \"${RUNNER_TEMP}/gobin\" \\\n", 1))'
mutate "scan.yml inspector job (the credential holder) gets a second installer line with a variable" '
edit("scan.yml", lambda s: s.replace("        run: ./bin/install-scanner.sh inspector-sbomgen\n", "        run: ./bin/install-scanner.sh inspector-sbomgen\n      - name: extra\n        run: |\n          tool=govulncheck\n          bash bin/install-scanner.sh \"$tool\"\n", 1))'
mutate "scan.yml scanner job adds a matrix.include entry naming govulncheck" '
edit("scan.yml", lambda s: s.replace("        scanner: ${{ fromJSON(needs.scanners.outputs.list) }}\n", "        scanner: ${{ fromJSON(needs.scanners.outputs.list) }}\n        include:\n          - scanner: govulncheck\n", 1))'
mutate "scan.yml inspector job (the credential holder) gets a pinned Go install and a variable installer line" '
edit("scan.yml", lambda s: s.replace("        run: ./bin/install-scanner.sh inspector-sbomgen\n", "        run: ./bin/install-scanner.sh inspector-sbomgen\n      - name: go\n        run: bash bin/install-scanner.sh go\n      - name: extra\n        run: |\n          TOOL=govulncheck; bash bin/install-scanner.sh \"$TOOL\"\n", 1))'
mutate "scan.yml matrix list taken from another key of scanners.json (scanners)" '
edit("scan.yml", lambda s: s.replace("jq -c \x27.pr_gate\x27 .github/policy/scanners.json", "jq -c \x27.source_scanners\x27 .github/policy/scanners.json", 1))'
mutate "pr_gate-driven matrix job loses its exclusion (scan.yml reads another key)" '
edit("scan.yml", lambda s: s.replace("jq -c \x27.pr_gate\x27 .github/policy/scanners.json", "jq -c \x27.scanners\x27 .github/policy/scanners.json", 1))'
echo '{"scanners": ["grype"], "source_scanners": ["govulncheck"], "pr_gate": ["grype", "govulncheck"]}' > "$work/sc-bad.json"
out=$(ISO_SCANNERS="$work/sc-bad.json" judge "$root/.github/workflows" 2>&1) && rc=0 || rc=$?
if [ "$rc" != 0 ] && grep -Fq "pr_gate holds govulncheck" <<< "$out"; then pass=$((pass+1)); echo "ok   a pr_gate list that holds govulncheck is refused (the matrix job would build it)"; else failn=$((failn+1)); echo "FAIL a pr_gate list holding govulncheck passed or was mis-reported: rc=$rc $out"; fi
# the Check stage hand-over: the build job, the output, and download-artifact's digest check left on
mutate "the Check job stops needing govulncheck-build" '
edit("stage-verify.yml", lambda s: s.replace("    needs: govulncheck-build\n", "", 1))'
mutate "govulncheck-build is granted id-token: write" '
edit("stage-verify.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    permissions:\n      contents: read\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
mutate "govulncheck-build reads a secret" '
edit("stage-verify.yml", lambda s: re.sub(r"(  govulncheck-build:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\n        run: echo x\n", s, count=1, flags=re.S))'
mutate "govulncheck-build has no artifact-id output" '
edit("stage-verify.yml", lambda s: s.replace("    outputs:\n      artifact-id: ${{ steps.upload.outputs.artifact-id }}\n", "", 1))'
mutate "govulncheck-build's output is not the upload's artifact-id" '
edit("stage-verify.yml", lambda s: s.replace("steps.upload.outputs.artifact-id", "steps.upload.outputs.artifact-digest", 1))'
mutate "the upload step has no id (the output would be empty)" '
edit("stage-verify.yml", lambda s: s.replace("      - id: upload\n        uses:", "      - uses:", 1))'
mutate "the Check job turns the digest check off (digest-mismatch: ignore)" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: ignore\n", 1))'
mutate "the Check job only warns on a digest mismatch (digest-mismatch: warn)" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: warn\n", 1))'
mutate "the Check job sets digest-mismatch even to the default (error): the default must stand untouched" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: error\n", 1))'
mutate "the Check job's govulncheck download may fail without stopping the job (continue-on-error)" '
edit("stage-verify.yml", lambda s: s.replace("        with:\n          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          path: govulncheck-dl\n", "        continue-on-error: true\n        with:\n          name: govulncheck\n          path: govulncheck-dl\n", 1))'
mutate "the Check job's govulncheck download is conditional (if: always())" '
edit("stage-verify.yml", lambda s: s.replace("        with:\n          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          path: govulncheck-dl\n", "        if: always()\n        with:\n          name: govulncheck\n          path: govulncheck-dl\n", 1))'
mutate "the Check job's govulncheck download goes to another path" '
edit("stage-verify.yml", lambda s: s.replace("path: govulncheck-dl\n", "path: dl\n", 1))'
mutate "the Check job downloads by name again (no artifact-ids)" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n", "          name: govulncheck\n", 1))'
mutate "the Check job's artifact-ids is another expression" '
edit("stage-verify.yml", lambda s: s.replace("needs.govulncheck-build.outputs.artifact-id }}", "needs.govulncheck-build.outputs.other }}", 1))'
mutate "the Check job's artifact-ids is a literal number" '
edit("stage-verify.yml", lambda s: s.replace("artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}", "artifact-ids: 123456", 1))'
mutate "the Check job adds the name beside artifact-ids" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n", "          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          name: govulncheck\n", 1))'
mutate "the Check job adds a pattern beside artifact-ids" '
edit("stage-verify.yml", lambda s: s.replace("          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n", "          artifact-ids: ${{ needs.govulncheck-build.outputs.artifact-id }}\n          pattern: govulncheck*\n", 1))'
mutate "govulncheck-build has no id on its upload (the output would be empty)" '
edit("stage-verify.yml", lambda s: s.replace("      - id: upload\n        uses:", "      - uses:", 1))'
mutate "govulncheck-build's upload overwrites an existing artifact" '
edit("stage-verify.yml", lambda s: s.replace("          path: govulncheck-out/govulncheck\n", "          path: govulncheck-out/govulncheck\n          overwrite: true\n", 1))'
mutate "the upload carries another path than govulncheck-out/govulncheck" '
edit("stage-verify.yml", lambda s: s.replace("path: govulncheck-out/govulncheck\n", "path: govulncheck-out\n", 1))'
mutate "govulncheck-build no longer places the binary (pack step removed)" '
edit("stage-verify.yml", lambda s: s.replace("      - name: place the built govulncheck for upload\n        run: bash bin/pack-govulncheck.sh\n", "", 1))'
mutate "a second install of the downloaded govulncheck is added to the Check job" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/unpack-govulncheck.sh\n", s, count=1, flags=re.S))'
mutate "the install of the downloaded govulncheck may fail silently (continue-on-error)" '
edit("stage-verify.yml", lambda s: s.replace("        run: bash bin/unpack-govulncheck.sh\n", "        run: bash bin/unpack-govulncheck.sh\n        continue-on-error: true\n", 1))'
mutate "the install of the downloaded govulncheck gets an env" '
edit("stage-verify.yml", lambda s: s.replace("        run: bash bin/unpack-govulncheck.sh\n", "        env:\n          X: y\n        run: bash bin/unpack-govulncheck.sh\n", 1))'
mutate "the Check job's whole job may fail without stopping the run (continue-on-error)" '
edit("stage-verify.yml", lambda s: s.replace("    needs: govulncheck-build\n", "    needs: govulncheck-build\n    continue-on-error: true\n", 1))'
# the hidden build in the jobs that hold id-token in the Check stage and elsewhere
mutate "install-scanner.sh govulncheck put back in the Check job (id-token: write)" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to the arm64 Check job (id-token: write)" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check-arm64:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job that reads a secret (release.yml decide)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: s.replace("./bin/install-scanner.sh crane\n", "./bin/install-scanner.sh crane\n          bash bin/install-scanner.sh govulncheck\n", 1))'

echo "job-isolation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
