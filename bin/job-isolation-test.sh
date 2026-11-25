#!/usr/bin/env bash
# proves: REQ-REL-011-AC1, REQ-REL-011-AC2, REQ-REL-011-AC3
# The owner's isolation rule (ratified Oct 21 2026, ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): on GitHub-hosted runners
# the separate job is the isolation unit. AC1: a job that holds a credential (a secrets.* reference, an environment, id-token: write or
# packages: write) never compiles or builds; govulncheck, which publishes no release binary, is built in a job with no credential and
# reaches auditor.yml's audit job as an artifact whose sha256 the audit job compares first, and release.yml's check job as an artifact whose download keeps download-artifact's own
# digest check on (no override). The build that `install-scanner.sh govulncheck` hides inside a script counts: the installer word is read after quotes and continuations are
# normalized, and a word the judge cannot read is refused in a credential job. AC2: no job runs two builds.
# AC2 scope: builds of what we ship or run as a tool. The acceptance/bench jobs that run a sample project's own Gradle/Maven build as the
# workload under test are not release builds and are outside it. The real workflows must pass (no exclusion names a job of the release chain: the Build, Rebuild, Check, Sign and Release jobs of release.yml each satisfy AC1 through
# their own permissions, REQ-REL-011-AC1); each mutated copy must be caught.
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
# Exclusions: none (REQ-REL-011-AC1). The jobs of the release chain are the Build, Rebuild, Check, Sign and Release jobs of release.yml; stage-build.yml, stage-reproducibility.yml, stage-verify.yml,
# stage-sign.yml and stage-promote.yml no longer exist, so no row names any of them. The stale-row check below stays: a row added later must name a job that exists, and none may name a job of release.yml.
# The only reusable workflows a credential-holding job may call: release.yml in snapshot mode (the callers' static ceiling, REQ-CHAIN-004-AC14: the sign environment, not the caller's grant, decides what can sign)
# and persona-uat.yml (release.yml's one call of the release-candidate persona leg, REQ-UAT-001-AC6: identity token for the persona federation only).
CREDENTIAL_CALLEES = ("release.yml", "persona-uat.yml")
# the build side of release.yml (REQ-CHAIN-004-AC1, REQ-CHAIN-005-AC1, REQ-CHAIN-006-AC1): each its own job, each declaring its OWN permissions block (the workflow-level block is empty) and holding no credential
BUILD_SIDE_JOBS = ("build-apk", "build-assemble", "rebuild-apk", "rebuild-assemble", "check-govulncheck", "check")
# the sign jobs of release.yml (REQ-CHAIN-001-AC9): the only jobs that may hold the sign environment; they build nothing (AC1 above applies to them like to every credential holder)
SIGN_JOBS = ("sign", "sign-rebuild", "sign-check")
SIGN_ENV_JOBS = SIGN_JOBS + ("sign-tag",)      # the four jobs of release.yml in the environment sign; sign-tag (REQ-REL-009) holds contents read and id-token write, no secret
EXCLUDED_AC1 = {}
# ci.yml test: the one required Go test job builds twice, without a credential, to /dev/null and to /tmp (neither is shipped): the static build and the -fips variant build, which had
# their own jobs until the test, coverage, vendor and fips140-only jobs became one (audit row C-F7). Neither build is a release artifact.
EXCLUDED_AC2 = {("ci.yml", "test"): "two throwaway builds in the one job without a credential"}
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
RELEASE_SECRETS = {"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"}   # ruling R5: the release job that pushes images holds exactly these, nothing else
# AC3 (b): DOCKERHUB_USERNAME, DOCKERHUB_TOKEN and packages: write live in the release job of release.yml alone. The only exceptions are three probe holders, each keyed on the triple
# (workflow file, job, environment): a same-named job whose environment changed or went away is not the holder. None holds packages: write or runs a signature or an attach; two of them (panel-scout,
# live-test-release) also run no login for a push and no push. One further job holds packages: write, go-freshness.yml/refresh (environment agent, same triple key): it stores the package archive by digest with the run's own token.
PROBE_HOLDERS = {("main-candidate-rescan.yml", "panel-scout", "agent"), ("release.yml", "live-test-release", "live-test")}
PUSH_WORDS = re.compile(r"\bcrane\s+auth\s+login\b|\bcosign\s+login\b|\bcrane\s+(?:push|copy|cp|append|mutate|tag)\b|\bdocker\s+(?:push|buildx\s+imagetools\s+create)\b|\bcosign\s+(?:sign|sign-blob|attach|attest|copy)\b|\boras\s+(?:login|push)\b|\bskopeo\s+(?:login|copy)\b|\bregctl\s+(?:registry\s+login|image\s+copy)\b")
ARCHIVE_WRITER = ("go-freshness.yml", "refresh", "agent")   # the one further job that holds packages: write
READ_ONLY_LOGIN = re.compile(r"\bdocker\s+login\b")   # a docker login passes only in a step that carries a read-only token (DOCKERHUB_SCOUT_TOKEN or the job's own GH_TOKEN with packages: read)
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
LEVEL = {"none": 0, "read": 1, "write": 2}
def ceiling(callee_file):
    """The most the called workflow's own jobs declare, permission by permission (REQ-CHAIN-004-AC14); None when the file cannot be read."""
    if not os.path.isfile(callee_file):
        return None
    cd = yaml.safe_load(open(callee_file)) or {}
    top = {}
    for cj in (cd.get("jobs") or {}).values():
        cp = cj.get("permissions", cd.get("permissions")) if isinstance(cj, dict) else None
        if cp == "write-all":
            return "write-all"
        for k, v in (cp.items() if isinstance(cp, dict) else []):
            top[k] = max(top.get(k, "none"), v, key=lambda x: LEVEL.get(x, 0))
    return top
def caller_excess(d, j, wf):
    """For a caller (a job with uses and no steps): the permissions it grants beyond its callee's ceiling; None when the callee is not a local file the judge can read."""
    u = str(j.get("uses") or "")
    top = ceiling(os.path.join(wf, os.path.basename(u))) if u.startswith("./.github/workflows/") else None
    perms = j.get("permissions", d.get("permissions"))
    if top is None:
        return None
    if top == "write-all":
        return []
    if perms == "write-all":
        return ["write-all"]
    return [k + ": " + v for k, v in (perms.items() if isinstance(perms, dict) else []) if LEVEL.get(v, 0) > LEVEL[top.get(k, "none")]]
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
        wf_lv = yaml.safe_dump({k: v for k, v in d.items() if k not in ("jobs", "on", True)})
        if w and comp and key not in EXCLUDED_AC1:
            bad.append("%s/%s holds %s and builds in the step %r" % (key[0], jn, ", ".join(w), comp[0]))
        if w and unresolved:
            bad.append("%s/%s holds %s and runs the line %r in the step %r: a credential job may name install-scanner.sh only as exactly `bash bin/install-scanner.sh TOOL` (TOOL a literal word, not govulncheck) or a listed exception" % (key[0], jn, ", ".join(w), unresolved[0][1], unresolved[0][0]))
        # the build-side jobs of release.yml (Build, Rebuild, Check): each declares its own permissions (undeclared, it would inherit nothing but also prove nothing) and holds no credential
        if key[0] == "release.yml" and jn in BUILD_SIDE_JOBS:
            if "permissions" not in j:
                bad.append("%s/%s declares no permissions of its own: every job of the release chain keeps its own minimal block" % (key[0], jn))
            if w:
                bad.append("%s/%s is a build-side job of release.yml and holds %s: only the sign jobs hold a credential" % (key[0], jn, ", ".join(w)))
        # the sign environment belongs to the four sign jobs of release.yml alone
        if j.get("environment") == "sign" and not (key[0] == "release.yml" and jn in SIGN_ENV_JOBS):
            bad.append("%s/%s is in the environment sign but is not one of the four sign jobs of release.yml" % key)
        callee = os.path.basename(str(j.get("uses") or ""))
        if j.get("uses") and w and not (str(j.get("uses")).startswith("./.github/workflows/") and callee in CREDENTIAL_CALLEES):
            bad.append("%s/%s holds %s and calls a reusable workflow that is not release.yml's local file (%s): the callee could build with the caller's credentials" % (key[0], jn, ", ".join(w), j.get("uses")))
        if j.get("uses") and w and callee == "release.yml" and (j.get("with") or {}) != {"mode": "snapshot"}:
            bad.append("%s/%s holds %s and calls release.yml in a mode other than snapshot: %s" % (key[0], jn, ", ".join(w), j.get("with")))
        if str(j.get("uses") or "").split("/")[-1].startswith("stage-"):
            bad.append("%s/%s calls %s: no stage-*.yml file exists" % (key[0], jn, j.get("uses")))
        # a job that records a step with bin/witnessed-local.sh (Build, Rebuild, Check: the throwaway-key Witness records, owner Oct 22) is a build-side job whatever its scripts hide: no credential, and never the keyless bin/witnessed.sh
        stext = "\n".join(steps_text(s_) for s_ in (j.get("steps") or []))
        stext = re.sub(r"['\"\\]", "", re.sub(r"\\\n[ \t]*", "", stext))   # quotes, backslashes and continuations are not part of the word the shell runs (bin/witnessed-"local".sh is witnessed-local.sh)
        if re.search(r"\bwitnessed-local\.sh\b", stext):
            # ruling Q-e: the release job publishes under witnessed-local.sh, so it keeps its environment release and packages write, but never an identity token or a KMS role
            # ruling R5: and it holds the stored registry secret (Docker Hub username and token), by name, in this job alone; any other stored secret is refused here
            ok_ = ("an environment", "packages: write")
            if key == ("release.yml", "release"):
                names_ = set(re.findall(r"\bsecrets\.(\w+)", yaml.safe_dump(j)))
                if names_ <= RELEASE_SECRETS and not re.search(r"secrets\s*\[|secrets:\s*inherit", yaml.safe_dump(j) + yaml.safe_dump({k: v for k, v in d.items() if k not in ("jobs", "on", True)})):
                    ok_ += ("a secret",)
            wl = [x for x in w if x not in ok_] if key == ("release.yml", "release") else w
            if wl:
                bad.append("%s/%s records its steps with witnessed-local.sh (a build-side job) and holds %s: only Sign holds an identity token" % (key[0], jn, ", ".join(wl)))
            if re.search(r"\bwitnessed\.sh\b", stext):
                bad.append("%s/%s records its steps with witnessed-local.sh (a build-side job) and also runs the keyless witnessed.sh: a build-side job signs with the throwaway key only" % (key[0], jn))
        if w:   # fail closed: a credential job never names a script through a variable: a path word with a variable or a substitution after bash/sh/source/./, a variable assigned a path under bin/, or an env value under bin/ (any of them could hide the wrapper or a build from the rules above)
            for s_ in (j.get("steps") or []):
                for l_ in re.sub(r"\\\n[ \t]*", "", steps_text(s_)).split("\n"):   # a backslash-newline continuation is one logical line
                    n_ = re.sub(r"['\"\\]", "", l_)
                    n_ = re.sub(r"\$\{?(?:RUNNER_TEMP|GITHUB_WORKSPACE)\}?", "/runner", n_)   # the runner's own fixed directories are not a hidden path
                    if re.search(r"\bbin/[^\s;&|)]*[$`]", n_) or re.search(r"(?:(?<![\w./-])(?:bash|sh|source|exec)\s+|(?<![\w.])\.\s+|(?<![\w.])\./)[^\s;&|)]*[$`]", n_) or re.search(r"\b\w+=[^\s$(`]*\bbin/", n_) or re.search(r"^\s*\w+:\s+\S*\bbin/", n_):
                        bad.append("%s/%s holds %s and names a script path under bin/ through a variable: %r" % (key[0], jn, ", ".join(w), l_.strip()[:100]))
        # AC3 (a): the sign jobs reference no secrets.* at all, GITHUB_TOKEN/GH_TOKEN/github.token included, and its permissions are exactly contents: read and id-token: write
        if key[0] == "release.yml" and key[1] in SIGN_JOBS:
            jt_ = yaml.safe_dump(j) + wf_lv
            if re.search(r"\bsecrets\b|\bGH_TOKEN\b|\bGITHUB_TOKEN\b|\bgithub\s*\.\s*token\b", jt_) or j.get("permissions") != {"contents": "read", "id-token": "write"}:
                bad.append("%s/%s references a secret or a token, or its permissions are not exactly contents: read and id-token: write: the sign jobs hand signatures over as artifacts and hold no credential" % key)
        # AC3 (b): the registry secret and packages: write, in every job but the release job of release.yml, except the three probe holders (keyed on workflow, job and environment)
        if key != ("release.yml", "release"):
            perms_ = j.get("permissions", d.get("permissions"))
            pw_ = perms_ == "write-all" or (isinstance(perms_, dict) and perms_.get("packages") == "write")
            # a caller (uses, no steps) is judged by its callee's ceiling, not as a job holding packages: write of its own: within the ceiling it passes, beyond it it is refused
            excess_ = caller_excess(d, j, wf) if j.get("uses") and not j.get("steps") else None
            if excess_ is not None:
                pw_ = False
                if excess_:
                    bad.append("%s/%s is a caller that grants more than its callee's ceiling (%s): %s" % (key[0], jn, j.get("uses"), ", ".join(excess_)))
            hit_ = re.search(r"\bDOCKERHUB_(?:USERNAME|TOKEN)\b|\bsecrets\s*\[|secrets:\s*inherit", yaml.safe_dump(j) + wf_lv)
            if (key[0], jn, j.get("environment")) == ARCHIVE_WRITER:
                pw_ = False
            if (key[0], jn, j.get("environment")) not in PROBE_HOLDERS:
                if hit_ or pw_:
                    bad.append("%s/%s holds the registry secret or packages: write: only the release job of release.yml does, whatever script the step runs" % key)
            else:
                if pw_:
                    bad.append("%s/%s is a read-only probe holder and holds packages: write" % key)
                for s_ in (j.get("steps") or []):
                    st_ = re.sub(r"\\\n[ \t]*", "", steps_text(s_))
                    if PUSH_WORDS.search(st_) or (READ_ONLY_LOGIN.search(st_) and not re.search(r"\bDOCKERHUB_SCOUT_TOKEN\b|\bGH_TOKEN\b", st_)):
                        bad.append("%s/%s is a read-only probe holder and runs a login for a push, a push, a signature or an attach in the step %r" % (key[0], jn, s_.get("name") or "?"))
        if len(comp) >= 2 and key not in EXCLUDED_AC2:
            bad.append("%s/%s runs two builds: %r and %r" % (key[0], jn, comp[0], comp[1]))
# a listed installer exception must name a job that exists, and scan.yml's scanner jobs must be the two the policy file names
for key in EXCLUDED_INSTALLER:
    if key not in jobs_seen:
        bad.append("the installer exception %s/%s names a job that does not exist (remove the row)" % key)
sc = json.load(open(os.environ.get("ISO_SCANNERS") or os.path.join(os.path.dirname(os.path.abspath(wf)), "policy", "scanners.json")))
if sc.get("pr_gate") != ["grype", "inspector"]:
    bad.append("scanners.json pr_gate is %s, not [grype, inspector]: scan.yml has one job for each and builds nothing else" % sc.get("pr_gate"))
scan_d = yaml.safe_load(open(os.path.join(wf, "scan.yml"))) or {}
sj_ = ((scan_d.get("jobs") or {}).get("scanner") or {})
if "strategy" in sj_ or "scanners" in (scan_d.get("jobs") or {}):
    bad.append("scan.yml scanner: the grype job is one plain job (no matrix, no scanner list job)")
if sj_.get("name") != "scan (grype)":
    bad.append("scan.yml scanner: the job is not named scan (grype)")
# an exclusion must still name a job that exists (a stale row hides nothing but must not rot)
for key in list(EXCLUDED_AC1) + list(EXCLUDED_AC2):
    if key not in jobs_seen:
        bad.append("the exclusion %s/%s names a job that does not exist (remove the row)" % key)
    if key[0] == "release.yml":
        bad.append("the exclusion %s/%s names a job of the release chain: the list holds no such row (REQ-REL-011-AC1)" % key)
if EXCLUDED_AC1:
    bad.append("EXCLUDED_AC1 is not empty: no job is exempt from AC1 (REQ-REL-011-AC1: there is no exclusion)")
# the release chain's jobs all exist under the names the English gives them, and release.yml reaches no reusable workflow
rel_jobs = {k[1] for k in jobs_seen if k[0] == "release.yml"}
for need in BUILD_SIDE_JOBS + SIGN_JOBS + ("release-compare", "release-verify", "release"):
    if need not in rel_jobs:
        bad.append("release.yml has no job %s" % need)
for k_, j_ in jobs_seen.items():
    if k_[0] == "release.yml" and j_.get("uses") and j_.get("uses") != "./.github/workflows/persona-uat.yml":
        bad.append("release.yml/%s calls a reusable workflow (%s): the release is one file (its one call is persona-uat.yml)" % (k_[1], j_.get("uses")))
for gone in ("stage-build.yml", "stage-sign.yml", "stage-verify.yml", "stage-promote.yml", "stage-reproducibility.yml"):
    if os.path.exists(os.path.join(wf, gone)):
        bad.append("%s still exists" % gone)
# govulncheck: built in its own credential-free job, checked by digest before the audit job uses it
a = yaml.safe_load(open(os.path.join(wf, "auditor.yml"))) or {}
b = (a.get("jobs") or {}).get("govulncheck-build")
audit = (a.get("jobs") or {}).get("audit") or {}
if not b:
    bad.append("auditor.yml has no govulncheck-build job")
else:
    if holds(a, b) or b.get("environment"):
        bad.append("govulncheck-build holds a credential: %s" % holds(a, b))
    if not any("govulncheck" in installer_args(steps_text(s)) for s in b.get("steps") or []):
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
# the Check jobs of release.yml (check-govulncheck, check): govulncheck is built by `install-scanner.sh govulncheck` (a Go module, no release binary), so its build gets its own job with no credential;
# the `check` job (no identity token: Sign signs its records) downloads the artifact with download-artifact's own digest check left on (it fails the step when the digest differs from the one GitHub
# recorded at upload) and installs it. The download is by the artifact id the build job exports, not by name, so a same-name artifact another job uploads is not the one it gets. The check
# and the id prove only that the artifact arrived intact and is the one that job uploaded; the guarantee is that no build runs in a job
# that holds a credential (AC1 above, which sees this installer arm as a build).
sv = yaml.safe_load(open(os.path.join(wf, "release.yml"))) or {}
sj = sv.get("jobs") or {}
gb = sj.get("check-govulncheck")
chk = sj.get("check") or {}
if not gb:
    bad.append("release.yml has no check-govulncheck job")
else:
    if holds(sv, gb):
        bad.append("release.yml check-govulncheck holds a credential: %s" % holds(sv, gb))
    if not any("govulncheck" in installer_args(steps_text(st)) for st in gb.get("steps") or []):
        bad.append("release.yml check-govulncheck does not build govulncheck")
    if gb.get("outputs") != {"artifact-id": "${{ steps.upload.outputs.artifact-id }}"}:
        bad.append("release.yml check-govulncheck must expose exactly the output artifact-id, the artifact-id of its upload step: %s" % gb.get("outputs"))
    ups = [st for st in gb.get("steps") or [] if str(st.get("uses") or "").startswith("actions/upload-artifact@")]
    if len(ups) != 1 or ups[0].get("id") != "upload" or ups[0].get("with") != {"name": "govulncheck", "path": "govulncheck-out/govulncheck"}:
        bad.append("release.yml check-govulncheck must have exactly one upload-artifact step, with id: upload, carrying the artifact govulncheck from govulncheck-out/govulncheck")
    packs = [st for st in gb.get("steps") or [] if "pack-govulncheck" in (st.get("run") or "")]
    if len(packs) != 1 or (packs[0].get("run") or "").strip() != "bash bin/pack-govulncheck.sh":
        bad.append("release.yml check-govulncheck must place the binary with exactly one plain step, `run: bash bin/pack-govulncheck.sh`")
cneeds = chk.get("needs")
cneeds = [cneeds] if isinstance(cneeds, str) else (cneeds or [])
if "check-govulncheck" not in cneeds:
    bad.append("release.yml check does not need check-govulncheck")
csteps = chk.get("steps") or []
dls = [st for st in csteps if str(st.get("uses") or "").startswith("actions/download-artifact@") and ("artifact-ids" in (st.get("with") or {}) or (st.get("with") or {}).get("name") == "govulncheck")]
if len(dls) != 1:
    bad.append("release.yml check must download the govulncheck artifact exactly once, by the artifact id of check-govulncheck")
else:
    # the digest check of download-artifact stays on: the step carries only uses and with {name, path} (no digest-mismatch input, no continue-on-error, no if), and nothing in the file sets digest-mismatch
    if set(dls[0]) - {"name", "uses", "with"} or (dls[0].get("with") or {}) != {"artifact-ids": "${{ needs.check-govulncheck.outputs.artifact-id }}", "path": "govulncheck-dl"}:
        bad.append("release.yml check: the govulncheck download must carry only uses and with exactly artifact-ids ${{ needs.check-govulncheck.outputs.artifact-id }} and path govulncheck-dl (no name, no digest-mismatch input, no continue-on-error, no if): %s" % sorted(dls[0]))
if "digest-mismatch" in open(os.path.join(wf, "release.yml")).read():
    bad.append("release.yml sets digest-mismatch (download-artifact's default, error, must stand untouched)")
HAND = "bash bin/unpack-govulncheck.sh"
inst = [st for st in csteps if "unpack-govulncheck" in (st.get("run") or "")]
if len(inst) != 1 or (inst[0].get("run") or "").strip() != HAND or set(inst[0]) - {"name", "run"}:
    bad.append("release.yml check: the downloaded govulncheck must be used by exactly one plain step, `run: %s` (no env, if or continue-on-error)" % HAND)
if chk.get("continue-on-error") or gb and gb.get("continue-on-error"):
    bad.append("release.yml: continue-on-error on the Check job or its build job")
print("\n".join(bad)); sys.exit(1 if bad else 0)
PY
}
check() { local name=$1 want=$2 dir=$3 out rc=0
  out=$(judge "$dir" 2>&1) || rc=$?
  if { [ "$want" = ok ] && [ $rc -eq 0 ]; } ||
     { [ "$want" = bad ] && [ $rc -ne 0 ] && { [ -z "${want_msg:-}" ] || grep -Fq "$want_msg" <<< "$out"; }; }
  then echo "ok   $name"
  else echo "FAIL $name (want $want, rc=$rc): $out"; fi; }
# a caller case judges one added job (scan.yml/probe-caller) alone: the real workflows carry other findings, so the verdict is read from the lines that name this job
check_job() { local name=$1 want=$2 dir=$3 out rc=0 mine
  out=$(judge "$dir" 2>&1) || rc=$?
  mine=$(grep -F "${mjob:-scan.yml/probe-caller }" <<< "$out" || true)
  if { [ "$want" = ok ] && [ -z "$mine" ]; } ||
     { [ "$want" = bad ] && [ -n "$mine" ] && grep -Fq "$want_msg" <<< "$mine"; }
  then echo "ok   $name"
  else echo "FAIL $name (want $want): ${mine:-no line names the job}"; fi; }
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
def job_span(s, job):   # the text of one job of a workflow file: from its header to the next job (two-space indent) or the end
    m = re.search(r"^  " + re.escape(job) + r":[ \t]*\n", s, re.M); assert m, "no job " + job
    n = re.search(r"^  [A-Za-z0-9_-]+:[ \t]*\n", s[m.end():], re.M)
    return m.start(), (m.end() + n.start() if n else len(s))
def in_job(s, job, old, new, regex=False):   # the first match inside one job only (release.yml holds many jobs with the same step text)
    a, b = job_span(s, job); seg = s[a:b]
    seg2 = re.sub(old, new, seg, count=1, flags=re.S) if regex else seg.replace(old, new, 1)
    return s[:a] + seg2 + s[b:]
def in_refresh(s, old, new):   # the first match inside the refresh job (go-freshness.yml has the same installer lines in other jobs)
    i = s.index("\n  refresh:"); return s[:i] + s[i:].replace(old, new, 1)
$py
PY
  ${mcheck:-check} "$name" "${mwant:-bad}" "$dir"; }

export ISO_SCANNERS="$root/.github/policy/scanners.json"   # the policy file the pr_gate check reads (mutated copies of the workflows keep the real one)
slot check "the real workflows" ok "$root/.github/workflows"
# AC1: a build added to a job that holds a credential
mutate "scan.yml scanner job: a matrix back in the grype job" '
edit("scan.yml", lambda s: s.replace("    needs: [build]\n    runs-on: ubuntu-latest\n    # Amazon Inspector runs in its own job below", "    needs: [build]\n    strategy:\n      matrix:\n        scanner: [grype]\n    runs-on: ubuntu-latest\n    # Amazon Inspector runs in its own job below", 1))'
mutate "go install added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: in_refresh(s, "./bin/install-scanner.sh crane\n", "GOBIN=/usr/local/bin go install github.com/google/go-containerregistry/cmd/crane@v0.22.1 \n"))'
mutate "go build added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: s.replace("  panel-probe:\n", "  panel-probe:\n", 1).replace("    environment: agent\n", "    environment: agent\n    # mutated\n", 1))
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: go build ./...\n", s, count=1, flags=re.S))'
mutate "make added to the Check job given id-token: write back" '
edit("release.yml", lambda s: re.sub(r"(\n  check:.*?    permissions:\n      contents: read\n)(.*?    steps:\n)", lambda m: m.group(1) + "      id-token: write\n" + m.group(2) + "      - name: mutant\n        run: make all\n", s, count=1, flags=re.S))'
mutate "docker build added to a job that holds a credential (release.yml sign)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: docker build -t x .\n", s, count=1, flags=re.S))'
mutate "id-token: write granted to a job that builds (ci.yml lint)" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?    permissions:\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
# the build-side jobs of the release chain hold no identity token and sign with the throwaway key only (owner Oct 21 separate jobs; Oct 22 Witness: only the Sign jobs sign keyless; cache-2a, handoff 0671).
# The judge finds a Witness job by the word witnessed-local.sh in its step text; a job that stops naming it (the script through a variable) escapes THIS rule, and is caught by the next one: every build-side job of
# release.yml (BUILD_SIDE_JOBS) holds no credential whatever its steps say. The fail-closed backstop for the identity token is bin/chain-sign-wiring-test.sh (.github/policy/id-token-jobs.json).
# Each of these mutations must be refused BY its rule, not by another one: want_msg names the refusal text.
for job in build-apk build-assemble rebuild-apk rebuild-assemble check; do
  want_msg="records its steps with witnessed-local.sh (a build-side job) and holds id-token: write"
  mutate "release.yml job $job is granted id-token: write (Witness job)" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    permissions:\n)", r"\1      id-token: write\n", regex=True))'
  want_msg="also runs the keyless witnessed.sh"
  mutate "release.yml job $job runs bin/witnessed.sh (keyless) instead of witnessed-local.sh" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    steps:\n)", r"\1      - name: mutant\n        run: bash bin/witnessed.sh x bin/x.sh\n", regex=True))'
done
for job in build-apk build-assemble rebuild-apk rebuild-assemble check-govulncheck check; do
  want_msg="is a build-side job of release.yml and holds"
  mutate "release.yml build-side job $job holds the environment sign" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    runs-on:)", "    environment: sign\n\\1", regex=True))'
  mutate "release.yml build-side job $job reads a secret" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    steps:\n)", r"\1      - name: leak\n        env:\n          K: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: echo x\n", regex=True))'
  want_msg="declares no permissions of its own"
  mutate "release.yml build-side job $job declares no permissions of its own (the workflow-level block is empty)" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"    permissions:\n(?:      [a-z-]+: [a-z]+\n)+", "", regex=True))'
done
for job in sign sign-rebuild sign-check; do
  want_msg="and builds in the step"
  mutate "release.yml sign job $job builds (go build): a credential holder never compiles" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    steps:\n)", r"\1      - name: mutant\n        run: go build ./...\n", regex=True))'
  mutate "release.yml sign job $job installs govulncheck (a hidden build)" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    steps:\n)", r"\1      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", regex=True))'
done
want_msg="is in the environment sign but is not one of the four sign jobs"
mutate "release.yml release job is placed in the environment sign" '
edit("release.yml", lambda s: in_job(s, "release", r"    environment: release\n", "    environment: sign\n", regex=True))'
want_msg="and builds in the step"
for job in release; do
  mutate "release.yml the $job job builds (go build): it holds the release environment and packages write" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    steps:\n)", r"\1      - name: mutant\n        run: go build ./...\n", regex=True))'
done
want_msg="is in the environment sign but is not one of the four sign jobs"
mutate "ci.yml lint is placed in the environment sign" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?)(    runs-on:)", lambda m: m.group(1) + "    environment: sign\n" + m.group(2), s, count=1, flags=re.S))'
for job in decide cut patch-notes; do
  want_msg="is in the environment sign but is not one of the four sign jobs"
  mutate "release.yml tag job $job is a fifth job in the environment sign" '
edit("release.yml", lambda s: in_job(s, "'$job'", r"(    runs-on:[^\n]*\n)(?:    environment: agent\n)?", r"\1    environment: sign\n", regex=True))'
done
want_msg="is in the environment sign but is not one of the four sign jobs"
mutate "release.yml gains a fifth job in the environment sign" '
edit("release.yml", lambda s: s.rstrip("\n") + "\n\n  fifth:\n    runs-on: ubuntu-24.04\n    environment: sign\n    permissions:\n      contents: read\n    steps:\n      - run: echo hi\n")'
want_msg=""
# fail closed (round 2, reviewer A): a job that holds a credential never runs a script whose path is built from a variable under bin/ (bash "bin/${helper}-local.sh" would hide the wrapper and the build from the rules above)
want_msg="names a script path under bin/ through a variable"
mutate "a credential job runs bash \"bin/\${helper}-local.sh\" (the wrapper named through a variable)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          helper=witnessed\n          bash \"bin/${helper}-local.sh\" build bin/build-stage-assemble.sh apk\n", s, count=1, flags=re.S))'
mutate "a credential job runs bash \"bin/\${helper}.sh\" (the keyless wrapper named through a variable)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash \"bin/${helper}.sh\" x bin/x.sh\n", s, count=1, flags=re.S))'
want_msg="names a script path under bin/ through a variable"
mutate "a credential job assigns the wrapper's path to a variable (h=bin/witnessed; bash \"\${h}-local.sh\")" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          h=bin/witnessed\n          bash \"${h}-local.sh\" build bin/build-stage-assemble.sh apk\n", s, count=1, flags=re.S))'
mutate "a credential job runs a script whose directory is a variable (bash \"\$P/witnessed-\${K}.sh\")" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        env:\n          P: bin\n          K: local\n        run: bash \"$P/witnessed-${K}.sh\" build x.sh\n", s, count=1, flags=re.S))'
# quote and backslash spellings of the wrapper names are the same word to the shell (round 4, reviewer A): the judge reads the step text with quotes and backslashes removed
want_msg="records its steps with witnessed-local.sh (a build-side job) and holds"
mutate "a credential job runs bash bin/witnessed-\"local\".sh (quote fragment inside the wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed-\"local\".sh build bin/build-stage-assemble.sh apk\n", s, count=1, flags=re.S))'
mutate "a credential job runs bash bin/witnessed-lo\\cal.sh (backslash inside the wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed-lo\\cal.sh build bin/build-stage-assemble.sh apk\n", s, count=1, flags=re.S))'
want_msg="also runs the keyless witnessed.sh"
mutate "the Check job runs bash bin/witnessed\"\".sh (empty quotes inside the keyless wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(\n  check:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witnessed\"\".sh x bin/x.sh\n", s, count=1, flags=re.S))'
mutate "the Check job runs bash bin/witn\\essed.sh (backslash inside the keyless wrapper name)" '
edit("release.yml", lambda s: re.sub(r"(\n  check:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/witn\\essed.sh x bin/x.sh\n", s, count=1, flags=re.S))'
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
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: |\n          k=local\n          bash bin/witnessed-\\\n          ${k}.sh build x.sh\n", s, count=1, flags=re.S))'
# a build-side job of release.yml declares its own permissions (the workflow-level block is empty, so an undeclared job proves nothing): covered above for every build-side job
# a credential-holding caller (the ceiling of scan.yml's and main-candidate-rescan.yml's job build, REQ-CHAIN-004-AC14) may call only release.yml, only in snapshot mode; a remote or any other callee could build with the caller's credentials
want_msg="calls a reusable workflow that is not"
for wfile in scan.yml main-candidate-rescan.yml; do
  mutate "$wfile build (holding the ceiling's id-token: write) calls a remote reusable workflow" '
edit("'$wfile'", lambda s: s.replace("    uses: ./.github/workflows/release.yml\n", "    uses: someone/else/.github/workflows/build.yml@0123456789abcdef0123456789abcdef01234567\n", 1))'
  mutate "$wfile build (holding the ceiling's id-token: write) calls a local workflow other than release.yml" '
edit("'$wfile'", lambda s: s.replace("    uses: ./.github/workflows/release.yml\n", "    uses: ./.github/workflows/ci.yml\n", 1))'
  want_msg="in a mode other than snapshot"
  mutate "$wfile build (holding the ceiling) calls release.yml in release mode" '
edit("'$wfile'", lambda s: s.replace("      mode: snapshot\n", "      mode: release\n", 1))'
  want_msg="calls a reusable workflow that is not"
done
# a caller (uses, no steps) is judged by its callee's ceiling (REQ-CHAIN-007-AC3, REQ-CHAIN-004-AC14): release.yml's own jobs declare contents, id-token, packages and issues write, so a caller inside that passes
# and a caller beyond it is refused; a job with steps and packages: write is still refused
mcheck=check_job
mwant=ok
mutate "a caller of release.yml whose packages: write is within the callee's ceiling passes" '
edit("scan.yml", lambda s: s.rstrip("\n") + "\n\n  probe-caller:\n    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    uses: ./.github/workflows/release.yml\n    with:\n      mode: snapshot\n")'
mwant=bad
want_msg="grants more than its callee's ceiling"
mutate "a caller of release.yml that also grants actions: write is refused" '
edit("scan.yml", lambda s: s.rstrip("\n") + "\n\n  probe-caller:\n    permissions:\n      contents: write\n      packages: write\n      actions: write\n    uses: ./.github/workflows/release.yml\n    with:\n      mode: snapshot\n")'
mutate "a caller of release.yml that grants write-all is refused" '
edit("scan.yml", lambda s: s.rstrip("\n") + "\n\n  probe-caller:\n    permissions: write-all\n    uses: ./.github/workflows/release.yml\n    with:\n      mode: snapshot\n")'
want_msg="holds the registry secret or packages: write"
mutate "a job with steps and packages: write is still refused" '
edit("scan.yml", lambda s: s.rstrip("\n") + "\n\n  probe-caller:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      packages: write\n    steps:\n      - run: echo x\n")'
mcheck=check
want_msg=""
want_msg="no stage-*.yml file exists"
mutate "scan.yml build calls a stage file again" '
edit("scan.yml", lambda s: s.replace("    uses: ./.github/workflows/release.yml\n", "    uses: ./.github/workflows/stage-build.yml\n", 1))'
want_msg="calls a reusable workflow"
mutate "release.yml sign job calls a reusable workflow (the release is one file)" '
edit("release.yml", lambda s: in_job(s, "sign", r"(    runs-on:[^\n]*\n)", r"    uses: ./.github/workflows/ci.yml\n", regex=True))'
want_msg=""
# AC2: a second build in one job
mutate "a second build step in one job (ci.yml lint)" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant one\n        run: go build ./a\n      - name: mutant two\n        run: go build ./b\n", s, count=1, flags=re.S))'
# the govulncheck hand-over
mutate "audit job builds govulncheck itself again" '
edit("auditor.yml", lambda s: s.replace("      - name: Install syft and govulncheck and build the validated run manifest\n", "      - name: mutant\n        run: GOBIN=x go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 \n      - name: Install syft and govulncheck and build the validated run manifest\n", 1))'
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
mutate "write-all on a job that builds (ci.yml lint)" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?)    permissions:\n", lambda m: m.group(1) + "    permissions: write-all\n    xperm:\n", s, count=1, flags=re.S))'
mutate "a workflow-level secret next to the govulncheck build" '
edit("auditor.yml", lambda s: re.sub(r"(\njobs:\n)", lambda m: "\nenv:\n  K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}" + m.group(1), s, count=1))'
mutate "an ungated copy of the install after the gate" '
edit("auditor.yml", lambda s: s.replace("          # syft: a pinned, checksum-verified", "          install -m 0755 \"${RUNNER_TEMP}/govulncheck-dl/govulncheck\" \"${RUNNER_TEMP}/gobin/govulncheck\"\n          # syft: a pinned, checksum-verified", 1))'
mutate "a go build loop in one job (ci.yml lint)" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant loop\n        run: |\n          for t in ./a ./b; do go build \"$t\"; done\n", s, count=1, flags=re.S))'
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
mutate "an extra installer line in the auditor syft exception step" '
edit("auditor.yml", lambda s: s.replace("          ./bin/install-scanner.sh syft \"${RUNNER_TEMP}/gobin\" \\\n", "          bash bin/install-\"scanner\".sh govulncheck\n          ./bin/install-scanner.sh syft \"${RUNNER_TEMP}/gobin\" \\\n", 1))'
mutate "scan.yml inspector job (the credential holder) gets a second installer line with a variable" '
edit("scan.yml", lambda s: s.replace("        run: ./bin/install-scanner.sh inspector-sbomgen\n", "        run: ./bin/install-scanner.sh inspector-sbomgen\n      - name: extra\n        run: |\n          tool=govulncheck\n          bash bin/install-scanner.sh \"$tool\"\n", 1))'
mutate "scan.yml inspector job (the credential holder) gets a pinned Go install and a variable installer line" '
edit("scan.yml", lambda s: s.replace("        run: ./bin/install-scanner.sh inspector-sbomgen\n", "        run: ./bin/install-scanner.sh inspector-sbomgen\n      - name: go\n        run: bash bin/install-scanner.sh go\n      - name: extra\n        run: |\n          TOOL=govulncheck; bash bin/install-scanner.sh \"$TOOL\"\n", 1))'
echo '{"scanners": ["grype"], "source_scanners": ["govulncheck"], "pr_gate": ["grype", "govulncheck"]}' > "$work/sc-bad.json"
prgate_case() { local out rc
  out=$(ISO_SCANNERS="$work/sc-bad.json" judge "$root/.github/workflows" 2>&1) && rc=0 || rc=$?
  if [ "$rc" != 0 ] && grep -Fq "pr_gate is" <<< "$out"; then
    echo "ok   a pr_gate list other than grype and inspector is refused"
  else echo "FAIL a pr_gate list holding govulncheck passed or was mis-reported: rc=$rc $out"; fi
}
slot prgate_case
# the Check stage hand-over: the build job, the output, and download-artifact's digest check left on
mutate "the Check job stops needing check-govulncheck" '
edit("release.yml", lambda s: in_job(s, "check", r"    needs:.*?\n(?=    [a-z])", "    needs: [build-assemble, sign]\n", regex=True))'
mutate "check-govulncheck is granted id-token: write" '
edit("release.yml", lambda s: re.sub(r"(  check-govulncheck:.*?    permissions:\n      contents: read\n)", lambda m: m.group(1) + "      id-token: write\n", s, count=1, flags=re.S))'
mutate "check-govulncheck reads a secret" '
edit("release.yml", lambda s: re.sub(r"(  check-govulncheck:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.AUDITOR_APP_PRIVATE_KEY }}\n        run: echo x\n", s, count=1, flags=re.S))'
mutate "check-govulncheck has no artifact-id output" '
edit("release.yml", lambda s: s.replace("    outputs:\n      artifact-id: ${{ steps.upload.outputs.artifact-id }}\n", "", 1))'
mutate "check-govulncheck's output is not the upload's artifact-id" '
edit("release.yml", lambda s: s.replace("steps.upload.outputs.artifact-id", "steps.upload.outputs.artifact-digest", 1))'
mutate "the upload step has no id (the output would be empty)" '
edit("release.yml", lambda s: s.replace("      - id: upload\n        uses:", "      - uses:", 1))'
mutate "the Check job turns the digest check off (digest-mismatch: ignore)" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: ignore\n", 1))'
mutate "the Check job only warns on a digest mismatch (digest-mismatch: warn)" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: warn\n", 1))'
mutate "the Check job sets digest-mismatch even to the default (error): the default must stand untouched" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          path: govulncheck-dl\n", "          name: govulncheck\n          path: govulncheck-dl\n          digest-mismatch: error\n", 1))'
mutate "the Check job's govulncheck download may fail without stopping the job (continue-on-error)" '
edit("release.yml", lambda s: s.replace("        with:\n          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          path: govulncheck-dl\n", "        continue-on-error: true\n        with:\n          name: govulncheck\n          path: govulncheck-dl\n", 1))'
mutate "the Check job's govulncheck download is conditional (if: always())" '
edit("release.yml", lambda s: s.replace("        with:\n          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          path: govulncheck-dl\n", "        if: always()\n        with:\n          name: govulncheck\n          path: govulncheck-dl\n", 1))'
mutate "the Check job's govulncheck download goes to another path" '
edit("release.yml", lambda s: s.replace("path: govulncheck-dl\n", "path: dl\n", 1))'
mutate "the Check job downloads by name again (no artifact-ids)" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n", "          name: govulncheck\n", 1))'
mutate "the Check job's artifact-ids is another expression" '
edit("release.yml", lambda s: s.replace("needs.check-govulncheck.outputs.artifact-id }}", "needs.check-govulncheck.outputs.other }}", 1))'
mutate "the Check job's artifact-ids is a literal number" '
edit("release.yml", lambda s: s.replace("artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}", "artifact-ids: 123456", 1))'
mutate "the Check job adds the name beside artifact-ids" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n", "          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          name: govulncheck\n", 1))'
mutate "the Check job adds a pattern beside artifact-ids" '
edit("release.yml", lambda s: s.replace("          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n", "          artifact-ids: ${{ needs.check-govulncheck.outputs.artifact-id }}\n          pattern: govulncheck*\n", 1))'
mutate "check-govulncheck has no id on its upload (the output would be empty)" '
edit("release.yml", lambda s: s.replace("      - id: upload\n        uses:", "      - uses:", 1))'
mutate "check-govulncheck's upload overwrites an existing artifact" '
edit("release.yml", lambda s: s.replace("          path: govulncheck-out/govulncheck\n", "          path: govulncheck-out/govulncheck\n          overwrite: true\n", 1))'
mutate "the upload carries another path than govulncheck-out/govulncheck" '
edit("release.yml", lambda s: s.replace("path: govulncheck-out/govulncheck\n", "path: govulncheck-out\n", 1))'
mutate "check-govulncheck no longer places the binary (pack step removed)" '
edit("release.yml", lambda s: s.replace("      - name: place the built govulncheck for upload\n        run: bash bin/pack-govulncheck.sh\n", "", 1))'
mutate "a second install of the downloaded govulncheck is added to the Check job" '
edit("release.yml", lambda s: re.sub(r"(\n  check:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/unpack-govulncheck.sh\n", s, count=1, flags=re.S))'
mutate "the install of the downloaded govulncheck may fail silently (continue-on-error)" '
edit("release.yml", lambda s: s.replace("        run: bash bin/unpack-govulncheck.sh\n", "        run: bash bin/unpack-govulncheck.sh\n        continue-on-error: true\n", 1))'
mutate "the install of the downloaded govulncheck gets an env" '
edit("release.yml", lambda s: s.replace("        run: bash bin/unpack-govulncheck.sh\n", "        env:\n          X: y\n        run: bash bin/unpack-govulncheck.sh\n", 1))'
mutate "the Check job's whole job may fail without stopping the run (continue-on-error)" '
edit("release.yml", lambda s: in_job(s, "check", r"(    needs:.*?\n)(?=    [a-z])", r"\1    continue-on-error: true\n", regex=True))'
# the hidden build in the jobs that hold id-token in the Check stage and elsewhere
mutate "install-scanner.sh govulncheck put back in the Check job given id-token: write back" '
edit("release.yml", lambda s: re.sub(r"(\n  check:.*?    permissions:\n      contents: read\n)(.*?    steps:\n)", lambda m: m.group(1) + "      id-token: write\n" + m.group(2) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job that holds a credential (release.yml sign)" '
edit("release.yml", lambda s: re.sub(r"(\n  sign:\n.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to a job with an environment (auditor panel-probe)" '
edit("auditor.yml", lambda s: re.sub(r"(  panel-probe:.*?    steps:\n)", lambda m: m.group(1) + "      - name: mutant\n        run: bash bin/install-scanner.sh govulncheck\n", s, count=1, flags=re.S))'
mutate "install-scanner.sh govulncheck added to go-freshness refresh (App key, packages: write)" '
edit("go-freshness.yml", lambda s: in_refresh(s, "./bin/install-scanner.sh crane\n", "./bin/install-scanner.sh crane\n          bash bin/install-scanner.sh govulncheck\n"))'

# AC3: the sign jobs hold no registry credential, no GH_TOKEN and no packages write; a stored secret in any other job is refused whatever the script, under witnessed-local.sh or not
want_msg="the sign jobs hand signatures over as artifacts"
mutate "release.yml sign-check names DOCKERHUB_TOKEN" '
edit("release.yml", lambda s: in_job(s, "sign-check", r"(    steps:\n)", r"\1      - name: leak\n        env:\n          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: echo x\n", regex=True))'
mutate "release.yml sign-check names GH_TOKEN" '
edit("release.yml", lambda s: in_job(s, "sign-check", r"(    steps:\n)", r"\1      - name: leak\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: echo x\n", regex=True))'
mutate "release.yml sign-check is granted packages: write" '
edit("release.yml", lambda s: in_job(s, "sign-check", r"(    permissions:\n)", r"\1      packages: write\n", regex=True))'
want_msg="holds the registry secret"
mutate "ci.yml lint reads secrets.DOCKERHUB_TOKEN under a plain script" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: bash bin/release-publish.sh\n", s, count=1, flags=re.S))'
mutate "ci.yml lint reads secrets.DOCKERHUB_USERNAME under bin/witnessed-local.sh" '
edit("ci.yml", lambda s: re.sub(r"(  lint:.*?    steps:\n)", lambda m: m.group(1) + "      - name: leak\n        env:\n          K: ${{ secrets.DOCKERHUB_USERNAME }}\n        run: bash bin/witnessed-local.sh release-publish bin/release-publish.sh\n", s, count=1, flags=re.S))'
# AC3 (a): the sign jobs name no secrets.* at all and its permissions are exactly contents: read and id-token: write
want_msg="the sign jobs hand signatures over as artifacts"
mutate "release.yml sign-check references secrets.GITHUB_TOKEN" '
edit("release.yml", lambda s: in_job(s, "sign-check", r"(    steps:\n)", r"\1      - name: leak\n        env:\n          T: ${{ secrets.GITHUB_TOKEN }}\n        run: echo x\n", regex=True))'
mutate "release.yml sign-check is granted an extra permission (actions: read)" '
edit("release.yml", lambda s: in_job(s, "sign-check", r"(    permissions:\n)", r"\1      actions: read\n", regex=True))'
# AC3 (b): the three probe holders are keyed on (workflow, job, environment); each holds no packages: write and runs no login for a push, push, signature or attach
want_msg="holds the registry secret or packages: write"
mutate "release.yml live-test-release (a probe holder) has its environment switched to release" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"    environment: live-test[^\n]*\n", "    environment: release\n", regex=True))'
mutate "release.yml live-test-release (a probe holder) has its environment removed" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"    environment: live-test[^\n]*\n", "", regex=True))'
mutate "main-candidate-rescan.yml panel-scout (a probe holder) has its environment switched to release" '
edit("main-candidate-rescan.yml", lambda s: in_job(s, "panel-scout", r"    environment: agent[^\n]*\n", "    environment: release\n", regex=True))'
mutate "a new job in scan.yml references secrets.DOCKERHUB_TOKEN" '
edit("scan.yml", lambda s: s.rstrip("\n") + "\n\n  leak:\n    runs-on: ubuntu-latest\n    steps:\n      - name: leak\n        env:\n          K: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: echo x\n")'
want_msg="is a read-only probe holder and holds packages: write"
mutate "release.yml live-test-release (a probe holder) is granted packages: write" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"(    permissions:\n      contents: read\n)", r"\1      packages: write\n", regex=True))'
mutate "main-candidate-rescan.yml panel-scout (a probe holder) is granted packages: write" '
edit("main-candidate-rescan.yml", lambda s: in_job(s, "panel-scout", r"(    permissions:\n      contents: read\n)", r"\1      packages: write\n", regex=True))'
want_msg="holds the registry secret or packages: write"
# go-freshness.yml/refresh (environment agent) is the one further job that holds packages: write; keyed on (workflow, job, environment)
mutate "go-freshness.yml refresh has its environment switched to release" '
edit("go-freshness.yml", lambda s: in_job(s, "refresh", r"    environment: agent[^\n]*\n", "    environment: release\n", regex=True))'
mutate "go-freshness.yml refresh has its environment removed" '
edit("go-freshness.yml", lambda s: in_job(s, "refresh", r"    environment: agent[^\n]*\n", "", regex=True))'
mutate "go-freshness.yml check (another job of the file) is granted packages: write" '
edit("go-freshness.yml", lambda s: in_job(s, "check", r"(    permissions:\n      contents: read\n)", r"\1      packages: write\n", regex=True))'
mutate "go-freshness.yml refresh reads secrets.DOCKERHUB_TOKEN" '
edit("go-freshness.yml", lambda s: in_job(s, "refresh", r"(    steps:\n)", r"\1      - name: leak\n        env:\n          K: ${{ secrets.DOCKERHUB_TOKEN }}\n        run: echo x\n", regex=True))'
want_msg="is a read-only probe holder and runs a login for a push"
mutate "release.yml live-test-release (a probe holder) attaches with cosign attach" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"(    steps:\n)", r"\1      - name: mutant\n        run: cosign attach sbom --sbom s docker.io/x/y@sha256:0\n", regex=True))'
mutate "main-candidate-rescan.yml panel-scout (a probe holder) pushes with crane push" '
edit("main-candidate-rescan.yml", lambda s: in_job(s, "panel-scout", r"(    steps:\n)", r"\1      - name: mutant\n        run: crane push img.tar docker.io/x/y:z\n", regex=True))'
mutate "release.yml live-test-release (a probe holder) runs docker login with no read-only token" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"(    steps:\n)", r"\1      - name: mutant\n        run: docker login -u x -p y\n", regex=True))'
mutate "release.yml live-test-release (a probe holder) signs with cosign sign" '
edit("release.yml", lambda s: in_job(s, "live-test-release", r"(    steps:\n)", r"\1      - name: mutant\n        run: cosign sign --key k docker.io/x/y@sha256:0\n", regex=True))'
want_msg=""
# the judge's own rows: DOCKERHUB_* is bound at the release job alone and GH_TOKEN is not bound at a sign job
rows_case() { local out rc=0
  out=$(CHAIN_ROOT="$root" python3 - <<'PY' 2>&1
import importlib.util, os, sys
sp = importlib.util.spec_from_file_location("chain_test_signers", os.path.join(os.environ["CHAIN_ROOT"], "bin/chain-test-signers.py"))
m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
R = m.SECRET_ROWS; rel = m._R
bad = []
for n in ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"):
    if set(R.get(n, {})) != {(rel, "release")}:
        bad.append("%s rows are %s, not the release job alone" % (n, sorted(j for _f, j in R.get(n, {}))))
if any((rel, j) in R.get("GH_TOKEN", {}) for j in ("sign", "sign-rebuild", "sign-check")):
    bad.append("GH_TOKEN is bound at a sign job")
print("; ".join(bad)); sys.exit(1 if bad else 0)
PY
  ) || rc=$?
  if [ "$rc" = 0 ]; then echo "ok   the judge's secret rows list the release job alone for DOCKERHUB_* and no sign job for GH_TOKEN"
  else echo "FAIL the judge's secret rows: $out"; fi; }
slot rows_case

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
