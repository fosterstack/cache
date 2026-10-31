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
mkdir "$work/r"; seq=0
judge() { python3 - "$1" <<'PY'
import glob, json, os, re, sys, yaml
wf = sys.argv[1]
# a step that builds or compiles (commands and actions; comment lines never count)
COMPILE = re.compile(r"\bgo\s+(?:install|build)\b|goreleaser/goreleaser-action|\bgoreleaser\s+(?:build|release)\b|\bdocker\s+(?:buildx\s+)?build\b|\bbuildx\s+(?:build|bake)\b|docker/build-push-action|docker/bake-action"
                                          r"|\bmelange\s+build\b|\bapko\s+(?:build|publish)\b|\bcargo\s+(?:build|install)\b|\bmake\b|\bnpm\s+(?:run\s+)?build\b")
# Exclusions: none on the release-chain branch (cache#561 ruling B2). On main the table named the old release-chain jobs (stage-build build, stage-image assemble, stage-promote promote,
# stage-reproducibility reproduce, stage-acceptance-artifacts artifacts) that the chain landing replaces; those jobs do not exist here, so the rows are gone (the requirement's own note
# says the list shrinks to nothing at the landing). The stale-row check below stays: a row added later must name a job that exists.
CREDENTIAL_CALLEES = ("stage-sign.yml", "stage-promote.yml")   # the only reusable workflows a credential-holding job may call (Sign and Release)
BUILD_SIDE_FILES = ("stage-build.yml", "stage-reproducibility.yml", "stage-verify.yml")   # the release chain's Build, Rebuild and Check workflows (owner Oct 21 separate jobs, Oct 22 Witness)
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
    ("auditor.yml", "audit"): {"lines": ['./bin/install-scanner.sh syft "${RUNNER_TEMP}/gobin" \\', './bin/install-scanner.sh syft "${RUNNER_TEMP}/gobin" || echo "::warning::could not install syft; the package inventory falls back to matched packages"', './bin/install-scanner.sh go \\', './bin/install-scanner.sh go || echo "::warning::could not install the pinned Go toolchain; a bump PR will not regenerate its dependency provenance"'], "needs": [], "why": "the syft install and the pinned Go toolchain install (REQ-VEND-001-AC15), each of which fails as a warning (the line continues on the next line); govulncheck is built in its own credential-free job, never here"},
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
        # the release chain's build-side workflows (Build, Rebuild, Check): a caller grants them no credential, and every job declares its own permissions (undeclared, it would inherit the caller's)
        if os.path.basename(f) in BUILD_SIDE_FILES and j.get("permissions", d.get("permissions")) is None:
            bad.append("%s/%s declares no permissions (neither the job nor the workflow): a build-side job would inherit its caller's, credentials included" % (key[0], jn))
        callee = os.path.basename(str(j.get("uses") or ""))
        if j.get("uses") and w and not (str(j.get("uses")).startswith("./.github/workflows/") and callee in CREDENTIAL_CALLEES):
            bad.append("%s/%s holds %s and calls a reusable workflow that is not Sign's or Release's local file (%s): the callee could build with the caller's credentials" % (key[0], jn, ", ".join(w), j.get("uses")))
        if str(j.get("uses") or "").startswith("./.github/workflows/") and callee in BUILD_SIDE_FILES and w:
            bad.append("%s/%s calls the build-side workflow %s and holds %s: only Sign's calls hold an identity token" % (key[0], jn, callee, ", ".join(w)))
        # a job that records a step with bin/witnessed-local.sh (Build, Rebuild, Check: the throwaway-key Witness records, owner Oct 22) is a build-side job whatever its scripts hide: no credential, and never the keyless bin/witnessed.sh
        stext = "\n".join(steps_text(s_) for s_ in (j.get("steps") or []))
        stext = re.sub(r"['\"\\]", "", re.sub(r"\\\n[ \t]*", "", stext))   # quotes, backslashes and continuations are not part of the word the shell runs (bin/witnessed-"local".sh is witnessed-local.sh)
        if re.search(r"\bwitnessed-local\.sh\b", stext):
            if w:
                bad.append("%s/%s records its steps with witnessed-local.sh (a build-side job) and holds %s: only Sign holds an identity token" % (key[0], jn, ", ".join(w)))
            if re.search(r"\bwitnessed\.sh\b", stext):
                bad.append("%s/%s records its steps with witnessed-local.sh (a build-side job) and also runs the keyless witnessed.sh: a build-side job signs with the throwaway key only" % (key[0], jn))
        if w:   # fail closed: a credential job never names a script through a variable: a path word with a variable or a substitution after bash/sh/source/./, a variable assigned a path under bin/, or an env value under bin/ (any of them could hide the wrapper or a build from the rules above)
            for s_ in (j.get("steps") or []):
                for l_ in re.sub(r"\\\n[ \t]*", "", steps_text(s_)).split("\n"):   # a backslash-newline continuation is one logical line
                    n_ = re.sub(r"['\"\\]", "", l_)
                    n_ = re.sub(r"\$\{?(?:RUNNER_TEMP|GITHUB_WORKSPACE)\}?", "/runner", n_)   # the runner's own fixed directories are not a hidden path
                    if re.search(r"\bbin/[^\s;&|)]*[$`]", n_) or re.search(r"(?:(?<![\w./-])(?:bash|sh|source|exec)\s+|(?<![\w.])\.\s+|(?<![\w.])\./)[^\s;&|)]*[$`]", n_) or re.search(r"\b\w+=[^\s$(`]*\bbin/", n_) or re.search(r"^\s*\w+:\s+\S*\bbin/", n_):
                        bad.append("%s/%s holds %s and names a script path under bin/ through a variable: %r" % (key[0], jn, ", ".join(w), l_.strip()[:100]))
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
# rc-5a F: a matrix leg whose scanner is not one the job scans with fails before it installs anything (a leg that scans nothing must never read as a pass)
sst = sj_.get("steps") or []
refuse = [i for i, st_ in enumerate(sst) if isinstance(st_, dict) and str(st_.get("if", "")).replace(" ", "") == "matrix.scanner!='grype'" and [l_.strip() for l_ in str(st_.get("run", "")).splitlines() if l_.strip()][-1:] == ["exit 1"] and len(re.findall(r"\bexit\b", str(st_.get("run", "")))) == 1]
install_i = [i for i, st_ in enumerate(sst) if isinstance(st_, dict) and "install-scanner.sh" in str(st_.get("run", ""))]
if sj_.get("continue-on-error") is not None and str(sj_.get("continue-on-error")).strip().lower() != "false":
    bad.append("scan.yml scanner: the job has continue-on-error, so a refused matrix leg would not fail the job")
if "defaults" in scan_d or "defaults" in sj_:
    bad.append("scan.yml scanner: a defaults block (a custom run shell) could make the refusal step exit 0 without any other key")
for i_ in refuse:
    if set(sst[i_]) - {"name", "if", "run"}:
        bad.append("scan.yml scanner: the refusal step holds keys other than name, if and run (%s): continue-on-error or an env could keep it from failing the leg" % sorted(set(sst[i_]) - {"name", "if", "run"}))
if not refuse:
    bad.append("scan.yml scanner: no step `if: matrix.scanner != 'grype'` whose run ends in the only `exit`, `exit 1` (a pr_gate name other than grype would scan nothing and the aggregate would pass)")
elif install_i and refuse[0] > install_i[0]:
    bad.append("scan.yml scanner: the refusal of a non-grype matrix leg must come before the scanner install step")
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
# the `check` job (no identity token: Sign signs its records) downloads the artifact with download-artifact's own digest check left on (it fails the step when the digest differs from the one GitHub
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
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } ||
     { [ "$want" = bad ] && [ $rc -ne 0 ] && { [ -z "${want_msg:-}" ] || grep -Fq "$want_msg" <<< "$out"; }; }
  then echo "ok   $name"
  else echo "FAIL $name (want $want, rc=$rc): $out"; fi; }
# The cases do not depend on each other (each mutates its own copy), so they run four at a time. A case writes its one
# result file; the end prints the files in call order and counts each once, so a case that died without a line failed.
slot() { seq=$((seq+1)); "$@" > "$work/r/$(printf %04d "$seq")" 2>&1 &
  while [ "$(jobs -r | wc -l)" -ge "${JI_JOBS:-4}" ]; do sleep 0.2; done; }
mutate() { slot mutate_one "$@"; }
mutate_one() { local name=$1 py=$2 dir="$work/$1"
  rm -rf "$dir"; mkdir -p "$dir"; cp "$root"/.github/workflows/*.y*ml "$dir/"
  python3 - "$dir" <<PY
import os, re, sys, yaml
wf = sys.argv[1]
def edit(fname, fn):
    p = os.path.join(wf, fname); s = open(p).read(); s2 = fn(s); assert s2 != s, "mutation did not apply"; open(p, "w").write(s2)
def in_refresh(s, old, new):   # the first match inside the refresh job (go-freshness.yml has the same installer lines in other jobs)
    i = s.index("\n  refresh:"); return s[:i] + s[i:].replace(old, new, 1)
$py
PY
  check "$name" "${mwant:-bad}" "$dir"; }

export ISO_SCANNERS="$root/.github/policy/scanners.json"   # the policy file the pr_gate check reads (mutated copies of the workflows keep the real one)
slot check "the real workflows" ok "$root/.github/workflows"
# AC1: a build added to a job that holds a credential
# rc-5a F: a non-grype matrix leg must fail
mutate "scan.yml scanner job: the refusal of a non-grype matrix leg removed (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("        if: matrix.scanner != \"grype\"\n".replace("\"", "\x27"), "        if: matrix.scanner == \x27grype\x27\n", 1))'
mutate "scan.yml scanner job: continue-on-error on the refusal step (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("        if: matrix.scanner != \x27grype\x27\n", "        if: matrix.scanner != \x27grype\x27\n        continue-on-error: true\n", 1))'
mutate "scan.yml scanner job: continue-on-error on the whole job (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("    name: scan (${{ matrix.scanner }})\n", "    name: scan (${{ matrix.scanner }})\n    continue-on-error: true\n", 1))'
mutate "scan.yml scanner job: an exit 0 ahead of the refusal's exit 1 (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("          exit 1\n\n      # grype reads", "          exit 0\n          exit 1\n\n      # grype reads", 1))'
mutate "scan.yml: a workflow-level custom run shell (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("\njobs:\n", "\ndefaults:\n  run:\n    shell: true {0}\njobs:\n", 1))'
mutate "scan.yml scanner job: the refusal step placed after the installer (rc-5a F)" '
edit("scan.yml", lambda s: s.replace("      - name: refuse a scanner this job cannot run\n", "      - name: install ${{ matrix.scanner }} (pinned by checksum; a scanner that can\x27t run is a pipeline failure, not a finding)\n        run: ./bin/install-scanner.sh \x27${{ matrix.scanner }}\x27\n\n      - name: refuse a scanner this job cannot run\n", 1))'
mutate "go install added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: in_refresh(s, "./bin/install-scanner.sh crane\n", "GOBIN=/usr/local/bin go install github.com/google/go-containerregistry/cmd/crane@v0.22.1\n"))'
mutate "go build added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: s.replace("  panel-probe:\n", "  panel-probe:\n", 1).replace("    environment: agent\n", "    environment: agent\n    # mutated\n", 1))
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: go build ./...\n", s, count=1, flags=re.S))'
mutate "make added to the Check job given id-token: write back" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    permissions:\n      contents: read\n)(.*?    steps:\n)", lambda m: m.group(1) + "      id-token: write\n" + m.group(2) + "      - name: mutant\n        run: make all\n", s, count=1, flags=re.S))'
mutate "docker build added to a job that reads a secret (release.yml decide)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: docker build -t x .\n", s, count=1, flags=re.S))'
mutate "id-token: write granted to a job that builds (ci.yml gosec)" '
edit("ci.yml", lambda s: re.sub(r"(  gosec:.*?    permissions:\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
# the build-side jobs of the release chain hold no identity token and sign with the throwaway key only (owner Oct 21 separate jobs; Oct 22 Witness: only Sign signs keyless; cache-2a, handoff 0671).
# The judge finds a build-side job by the word witnessed-local.sh in its step text; a job that stops naming it (a reusable-workflow call, the script through a variable) escapes THIS rule. The fail-closed backstop for the
# identity token is bin/chain-sign-wiring-test.sh, which refuses any job with id-token: write that is not in .github/policy/id-token-jobs.json (only the Sign and release jobs are).
# Each of these mutations must be refused BY this rule, not by another one: want_msg names the refusal text.
for spec in stage-build.yml:apk stage-build.yml:assemble stage-reproducibility.yml:rapk stage-reproducibility.yml:rapk-arm stage-reproducibility.yml:assemble stage-verify.yml:check stage-verify.yml:check-arm64; do
  wf=${spec%%:*} job=${spec##*:}
  want_msg="records its steps with witnessed-local.sh (a build-side job) and holds id-token: write"
  mutate "$wf job $job is granted id-token: write" '
edit("'$wf'", lambda s: re.sub(r"(\n  '$job':\n.*?    permissions:\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
  want_msg="also runs the keyless witnessed.sh"
  mutate "$wf job $job runs bin/witnessed.sh (keyless) instead of witnessed-local.sh" '
edit("'$wf'", lambda s: re.sub(r"(\n  '$job':\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed.sh x bin/x.sh\n", s, count=1, flags=re.S))'
done
want_msg=""
# fail closed (round 2, reviewer A): a job that holds a credential never runs a script whose path is built from a variable under bin/ (bash "bin/${helper}-local.sh" would hide the wrapper and the build from the rules above)
want_msg="names a script path under bin/ through a variable"
mutate "a credential job runs bash \"bin/\${helper}-local.sh\" (the wrapper named through a variable)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          helper=witnessed\n          bash \"bin/${helper}-local.sh\" build bin/build-stage-assemble.sh\n", s, count=1, flags=re.S))'
mutate "a credential job runs bash \"bin/\${helper}.sh\" (the keyless wrapper named through a variable)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash \"bin/${helper}.sh\" x bin/x.sh\n", s, count=1, flags=re.S))'
want_msg="names a script path under bin/ through a variable"
mutate "a credential job assigns the wrapper's path to a variable (h=bin/witnessed; bash \"\${h}-local.sh\")" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          h=bin/witnessed\n          bash \"${h}-local.sh\" build bin/build-stage-assemble.sh\n", s, count=1, flags=re.S))'
mutate "a credential job runs a script whose directory is a variable (bash \"\$P/witnessed-\${K}.sh\")" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        env:\n          P: bin\n          K: local\n        run: bash \"$P/witnessed-${K}.sh\" build x.sh\n", s, count=1, flags=re.S))'
# quote and backslash spellings of the wrapper names are the same word to the shell (round 4, reviewer A): the judge reads the step text with quotes and backslashes removed
want_msg="records its steps with witnessed-local.sh (a build-side job) and holds"
mutate "a credential job runs bash bin/witnessed-\"local\".sh (quote fragment inside the wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed-\"local\".sh build bin/build-stage-assemble.sh\n", s, count=1, flags=re.S))'
mutate "a credential job runs bash bin/witnessed-lo\\cal.sh (backslash inside the wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed-lo\\cal.sh build bin/build-stage-assemble.sh\n", s, count=1, flags=re.S))'
want_msg="also runs the keyless witnessed.sh"
mutate "the Check job runs bash bin/witnessed\"\".sh (empty quotes inside the keyless wrapper name)" '
edit("stage-verify.yml", lambda s: re.sub(r"(\n  check:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed\"\".sh x bin/x.sh\n", s, count=1, flags=re.S))'
mutate "the Check job runs bash bin/witn\\essed.sh (backslash inside the keyless wrapper name)" '
edit("stage-verify.yml", lambda s: re.sub(r"(\n  check:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witn\\essed.sh x bin/x.sh\n", s, count=1, flags=re.S))'
# the pinned Go toolchain install in the audit job (cache#687): accepted exactly as listed; govulncheck through the same installer stays refused
mwant=ok
mutate "the audit job's pinned Go toolchain install is accepted (a comment added ahead of it)" '
edit("auditor.yml", lambda s: s.replace("          ./bin/install-scanner.sh go \\\n", "          # accepted as listed\n          ./bin/install-scanner.sh go \\\n", 1))'
mwant=bad
want_msg="install-scanner.sh"
mutate "the audit job installs govulncheck through install-scanner.sh in the Go toolchain step" '
edit("auditor.yml", lambda s: s.replace("          ./bin/install-scanner.sh go \\\n", "          ./bin/install-scanner.sh govulncheck \\\n", 1))'
# round 5 (reviewers A and B): a continuation split inside a variable-built path; a caller that grants a credential to a build-side workflow; a build-side job that declares no permissions (it would inherit its caller's)
want_msg="names a script path under bin/ through a variable"
mutate "a credential job splits a variable-built wrapper path over a backslash-newline continuation" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          k=local\n          bash bin/witnessed-\\\n          ${k}.sh build x.sh\n", s, count=1, flags=re.S))'
want_msg="calls the build-side workflow"
mutate "release.yml rebuild (a caller of stage-reproducibility.yml) is granted id-token: write" '
edit("release.yml", lambda s: re.sub(r"(  rebuild:\n    needs: \[build, sign\]\n    permissions:\n      contents: read\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1))'
want_msg="declares no permissions"
mutate "stage-reproducibility.yml rapk declares no permissions and neither does the workflow (it would inherit its caller's)" '
edit("stage-reproducibility.yml", lambda s: s.replace("permissions:\n  contents: read\njobs:", "jobs:", 1))
edit("stage-reproducibility.yml", lambda s: re.sub(r"(\n  rapk:\n.*?)    permissions:\n      contents: read\n", lambda m: m.group(1), s, count=1, flags=re.S))'
# round 6 (reviewer A): a credential-holding job that calls a reusable workflow may call only Sign's or Release's local workflow files (a remote or any other callee could build with the caller's credentials)
want_msg="calls a reusable workflow that is not"
mutate "release.yml sign calls a remote reusable workflow with id-token: write" '
edit("release.yml", lambda s: s.replace("    uses: ./.github/workflows/stage-sign.yml\n", "    uses: someone/else/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567\n", 1))'
mutate "release.yml sign calls a local workflow other than Sign's or Release's with id-token: write" '
edit("release.yml", lambda s: s.replace("    uses: ./.github/workflows/stage-sign.yml\n", "    uses: ./.github/workflows/stage-verify.yml\n", 1))'
want_msg=""
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
edit("go-freshness.yml", lambda s: in_refresh(s, "./bin/install-scanner.sh crane\n", "./bin/install-scanner.sh crane\n          " + os.environ["GFLINE"] + "\n"))'; }
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
prgate_case() { local out rc
  out=$(ISO_SCANNERS="$work/sc-bad.json" judge "$root/.github/workflows" 2>&1) && rc=0 || rc=$?
  if [ "$rc" != 0 ] && grep -Fq "pr_gate holds govulncheck" <<< "$out"; then
    echo "ok   a pr_gate list that holds govulncheck is refused (the matrix job would build it)"
  else echo "FAIL a pr_gate list holding govulncheck passed or was mis-reported: rc=$rc $out"; fi
}
slot prgate_case
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
mutate "install-scanner.sh govulncheck put back in the Check job given id-token: write back" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check:.*?    permissions:\n      contents: read\n)(.*?    steps:\n)", lambda m: m.group(1) + "      id-token: write\n" + m.group(2) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to the arm64 Check job given id-token: write back" '
edit("stage-verify.yml", lambda s: re.sub(r"(  check-arm64:.*?    permissions:\n      contents: read\n)(.*?    steps:\n)", lambda m: m.group(1) + "      id-token: write\n" + m.group(2) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job that reads a secret (release.yml decide)" '
edit("release.yml", lambda s: re.sub(r"(  decide:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: in_refresh(s, "./bin/install-scanner.sh crane\n", "./bin/install-scanner.sh crane\n          bash bin/install-scanner.sh govulncheck\n"))'

wait
pass=0 failn=0
for f in "$work"/r/*; do
  cat "$f"
  case $(head -n 1 "$f") in "ok   "*) pass=$((pass+1)) ;; *) failn=$((failn+1)) ;; esac
done
files=$(ls "$work/r" | wc -l)
[ "$files" -eq "$seq" ] || { echo "FAIL $files result files for $seq cases"; failn=$((failn+1)); }
echo "job-isolation: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
