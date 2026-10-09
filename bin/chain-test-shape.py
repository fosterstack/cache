"""Test infrastructure (not product code), shared by bin/chain-build-wiring-test.sh and bin/chain-rebuild-test.sh: the judges
for the shape of the Build and Rebuild stage files, the order of bin/build-stage.sh, the job graph of release.yml and the
environment record of a Witness collection. Each judge prints `ok` or the list of faults and exits 1 on any fault; the two
tests first prove every judge on a known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then
apply it to the real repository (RED until PR 2 is implemented).

  stage FILE build|rebuild     REQ-CHAIN-004-AC1, AC2 / REQ-CHAIN-005-AC1, AC4: an ALLOWLIST. The stage file is a reusable workflow (on: workflow_call
                               only) with EXACTLY two jobs and one identity (advisor 0341 reading): `apk` (a matrix over both native runners) and
                               `assemble` (the ubuntu-24.04 VM, needs apk); each directly on a GitHub-hosted VM, permissions exactly contents read +
                               id-token write, no container, services, env, defaults, secrets or packages write, whose steps are EXACTLY, in order:
                                 1. actions/checkout (full commit digest, persist-credentials: false)
                                 2. run: ./bin/install-scanner.sh witness      (checksum-pinned, like the other tools)
                                 3. digest-pinned actions/download-artifact steps with names from the per-job allowlist (before Witness starts, rule 68)
                                 4. ONE run step: the token fetch and ONE `witness run` with only the allowed flags (the github and slsa attestors are
                                    refused), ending `-- ./bin/build-stage.sh KIND`
                                 5. only upload-artifact steps with allowed artifact names
                               in-toto-witness docs/attestors/environment.md ("Filter instead of obfuscate"); docs/commands.md; harness spike
                               2026-10-09-harness-witness-spikes-a-c.md:20-30 (the token fetch and fulcio flags).
  script FILE apk|assemble|rebuild-apk|rebuild-assemble   REQ-CHAIN-004-AC3, AC6 / REQ-CHAIN-005-AC2: the commands of bin/build-stage.sh KIND in order.
  graph FILE                   REQ-CHAIN-005-AC5: release.yml job graph.
  recordenv FILE               REQ-CHAIN-004-AC8: no token variable in a Witness collection (used by the fixtures test of the judge; the
                               product check is chain-verify.py record-env, which the tests assert separately)."""
import json, re, shlex, sys, yaml

# advisor 0341 (reading, Oct 9; put to the owner): ONE stage = ONE workflow file and ONE identity. Each stage file holds exactly two jobs:
# `apk` (a matrix over the two native runners: melange per architecture) and `assemble` (ONE job on the VM: apko for both architectures,
# rule 33). Artifact names that carry the runner use the literal expression ${{ matrix.runner }} in the upload and the two literal
# runner names in the download, so a download can never name anything outside this list.
UP = {("build", "apk"): {"apk-${{ matrix.runner }}", "witness-apk-${{ matrix.runner }}"},
      ("build", "assemble"): {"witness-build", "digests", "dist", "locks"},
      ("rebuild", "apk"): {"rapk-${{ matrix.runner }}", "witness-rapk-${{ matrix.runner }}"},
      ("rebuild", "assemble"): {"witness-rebuild"}}
DOWN = {("build", "apk"): set(),
        ("build", "assemble"): {"apk-ubuntu-24.04", "apk-ubuntu-24.04-arm", "witness-apk-ubuntu-24.04", "witness-apk-ubuntu-24.04-arm"},
        ("rebuild", "apk"): {"witness-build"},
        ("rebuild", "assemble"): {"rapk-ubuntu-24.04", "rapk-ubuntu-24.04-arm", "witness-rapk-ubuntu-24.04", "witness-rapk-ubuntu-24.04-arm", "witness-build"}}
KIND = {("build", "apk"): "apk", ("build", "assemble"): "assemble", ("rebuild", "apk"): "rebuild-apk", ("rebuild", "assemble"): "rebuild-assemble"}
STEP = {("build", "apk"): "apk", ("build", "assemble"): "build", ("rebuild", "apk"): "rebuild-apk", ("rebuild", "assemble"): "rebuild"}
RUNNERS = {"ubuntu-24.04", "ubuntu-24.04-arm"}
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
FLAGS = {  # flag -> exact value, None = any value (checked separately), False = takes no value
    "--step": None, "--signer-fulcio-url": "https://fulcio.sigstore.dev",
    "--signer-fulcio-oidc-issuer": "https://token.actions.githubusercontent.com", "--signer-fulcio-oidc-client-id": "sigstore",
    "--signer-fulcio-token-path": '"$RUNNER_TEMP/tok"', "-t": "https://timestamp.sigstore.dev/api/v1/timestamp",
    "-a": None, "--env-filter-sensitive-vars": False, "--env-add-sensitive-key": None, "-d": None, "-o": None,
}
# the `github` attestor is NOT allowed (advisor 0341): it embeds the raw OIDC token (rules 52a, 68); run and job identity come from the
# Fulcio certificate extensions that PR 1's policy pins (advisor 0334). `slsa` is not allowed either: provenance is Sign's alone.
ATTESTORS = {"environment", "git", "material", "product", "command-run"}
REQUIRED_KEYS = {"ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN"}
TOKEN_LINES = [
    r'curl -sSf -H "Authorization: bearer \$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\}&audience=sigstore" -o "\$RUNNER_TEMP/tok\.json"',
    r'jq -r \.value "\$RUNNER_TEMP/tok\.json" > "\$RUNNER_TEMP/tok"',
    r'echo "::add-mask::\$\(cat "\$RUNNER_TEMP/tok"\)"',
    r'set -euo pipefail',
]
OUT = {("build", "apk"): "witness-apk/apk-collection.json", ("build", "assemble"): "witness-build/build-collection.json",
       ("rebuild", "apk"): "witness-rapk/rapk-collection.json", ("rebuild", "assemble"): "witness-rebuild/rebuild-collection.json"}


def stage(path, family):
    bad = []
    d = yaml.load(open(path).read(), Loader=yaml.BaseLoader)
    text = open(path).read()
    if set(d) - {"name", "on", "permissions", "jobs"}:
        bad.append("top-level keys beyond name/on/permissions/jobs: %s" % sorted(set(d) - {"name", "on", "permissions", "jobs"}))
    on = d.get("on")
    if not isinstance(on, dict) or set(on) != {"workflow_call"}:
        bad.append("on: must be exactly workflow_call, got %s" % on)
    if (on or {}).get("workflow_call", {}) and ((on or {}).get("workflow_call") or {}).get("secrets"):
        bad.append("the workflow declares secrets")
    if re.search(r"\bsecrets\s*\.|secrets\[|secrets:\s*inherit|packages:\s*write", text):
        bad.append("a secrets reference or packages: write appears")
    jobs = d.get("jobs") or {}
    if set(jobs) != {"apk", "assemble"}:
        bad.append("exactly two jobs required, apk and assemble (one stage = one file = one identity), found %s" % sorted(jobs)); return bad
    for name in ("apk", "assemble"):
        bad += ["%s: %s" % (name, m) for m in job(jobs[name], family, name)]
    nd = jobs["assemble"].get("needs")
    if nd not in ("apk", ["apk"]):
        bad.append("assemble must need exactly apk, got %s" % nd)
    return bad


def job(j, family, name):
    bad = []
    allowed = {"name", "runs-on", "permissions", "steps", "timeout-minutes"} | ({"strategy"} if name == "apk" else {"needs"})
    if set(j) - allowed:
        bad.append("job keys outside the allowlist: %s" % sorted(set(j) - allowed))
    for k in ("container", "services", "env", "defaults", "environment", "outputs", "if", "continue-on-error"):
        if k in j: bad.append("job has %s" % k)
    ro = j.get("runs-on")
    if name == "apk":
        mr = (((j.get("strategy") or {}).get("matrix") or {}).get("runner")) or []
        if not (isinstance(ro, str) and re.fullmatch(r"\$\{\{\s*matrix\.runner\s*\}\}", ro)):
            bad.append("the apk job must run on matrix.runner, got %r" % ro)
        if sorted(mr) != sorted(RUNNERS) or set((j.get("strategy") or {}).keys()) - {"matrix", "fail-fast"} \
           or set(((j.get("strategy") or {}).get("matrix") or {}).keys()) != {"runner"}:
            bad.append("matrix must be exactly runner: both of %s (native runners, no emulation)" % sorted(RUNNERS))
    else:
        if ro != "ubuntu-24.04":
            bad.append("the assemble job must run directly on the ubuntu-24.04 VM (rule 62), got %r" % ro)
        if "strategy" in j: bad.append("the assemble job has a strategy")
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("permissions must be exactly contents: read + id-token: write, got %s" % j.get("permissions"))
    steps = j.get("steps") or []
    if len(steps) < 3:
        bad.append("fewer than three steps"); return bad
    s0, s1 = steps[:2]
    if set(s0) - {"uses", "with", "name"} or not PIN.match((s0.get("uses") or "").split(" ")[0]) or not (s0.get("uses") or "").startswith("actions/checkout@") \
       or (s0.get("with") or {}).get("persist-credentials") != "false":
        bad.append("step 1 must be actions/checkout pinned by full digest with persist-credentials: false")
    if set(s1) - {"run", "name"} or (s1.get("run") or "").strip() != "./bin/install-scanner.sh witness":
        bad.append("step 2 must be exactly: run ./bin/install-scanner.sh witness (checksum-pinned Witness install)")
    i = 2
    while i < len(steps) and "uses" in steps[i] and (steps[i].get("uses") or "").startswith("actions/download-artifact@"):
        s = steps[i]; u = s["uses"].split(" ")[0]
        nm = (s.get("with") or {}).get("name")
        if set(s) - {"uses", "with", "name"} or not PIN.match(u) or set(s.get("with") or {}) - {"name", "path"}:
            bad.append("download step %r must be a digest-pinned actions/download-artifact with only name and path" % s.get("name"))
        if nm not in DOWN[(family, name)]:
            bad.append("download of %r is not allowed for the %s stage's %s job: %s" % (nm, family, name, sorted(DOWN[(family, name)])))
        i += 1
    if i >= len(steps) or "run" not in steps[i]:
        bad.append("the Witness step (a run step) must follow the checkout, the install and the downloads"); return bad
    s2 = steps[i]
    if set(s2) - {"run", "name"}:
        bad.append("the Witness step may carry only run and name (no env, if, shell, working-directory)")
    bad += witness_step(s2.get("run") or "", family, name)
    for s in steps[i + 1:]:
        u = s.get("uses") or ""
        if set(s) - {"uses", "with", "name", "if"} or not u.startswith("actions/upload-artifact@") or not PIN.match(u.split(" ")[0]):
            bad.append("step %r after the Witness step must be a digest-pinned actions/upload-artifact and nothing else" % s.get("name"))
            continue
        nm = (s.get("with") or {}).get("name")
        if nm not in UP[(family, name)]:
            bad.append("upload of %r is not an allowed artifact for the %s stage's %s job: %s" % (nm, family, name, sorted(UP[(family, name)])))
    return bad


def witness_step(run, family, name):
    kind = KIND[(family, name)]
    bad = []
    run = re.sub(r"\\\n\s*", " ", run)
    cmds = [l.strip() for l in run.splitlines() if l.strip() and not l.strip().startswith("#")]
    wit = [c for c in cmds if re.match(r"(\./)?witness\s+run\b", c)]
    if len(wit) != 1:
        bad.append("the Witness step must contain exactly one `witness run` (found %d)" % len(wit)); return bad
    for c in cmds:
        if c in wit: continue
        if not any(re.fullmatch(p, c) for p in TOKEN_LINES):
            bad.append("command outside the token fetch and witness run in the Witness step: %r" % c[:80])
    try:
        w = shlex.split(wit[0])
    except ValueError:
        return bad + ["witness run line does not parse"]
    if "--" not in w:
        return bad + ["witness run has no `--` command"]
    i = w.index("--"); flags, cmd = w[2:i], w[i + 1:]
    if cmd != ["./bin/build-stage.sh", kind]:
        bad.append("the command under Witness must be exactly ./bin/build-stage.sh %s, got %s" % (kind, cmd))
    seen = {}
    k = 0
    while k < len(flags):
        f = flags[k]
        if f not in FLAGS:
            bad.append("flag %s is not allowed" % f); k += 1; continue
        if FLAGS[f] is False:
            seen.setdefault(f, []).append(True); k += 1; continue
        if k + 1 >= len(flags):
            bad.append("flag %s has no value" % f); break
        v = flags[k + 1]; seen.setdefault(f, []).append(v); k += 2
        want = FLAGS[f]
        if want is not None and v != want.strip('"') and v != want:
            bad.append("flag %s must be %s, got %s" % (f, want, v))
    for f in ("--step", "--signer-fulcio-url", "--signer-fulcio-oidc-issuer", "--signer-fulcio-oidc-client-id", "--signer-fulcio-token-path", "-t",
              "--env-filter-sensitive-vars", "-o", "-a"):
        if f not in seen: bad.append("required flag %s is missing" % f)
    if seen.get("--step") and seen["--step"] != [STEP[(family, name)]]:
        bad.append("--step must be %s" % STEP[(family, name)])
    if seen.get("-o") and seen["-o"] != [OUT[(family, name)]]:
        bad.append("-o must be %s" % OUT[(family, name)])
    for v in seen.get("-a", []):
        if not set(v.split(",")) <= ATTESTORS:
            bad.append("attestor list %s contains a name outside %s (provenance is Sign's alone)" % (v, sorted(ATTESTORS)))
    if not REQUIRED_KEYS <= set(seen.get("--env-add-sensitive-key", [])):
        bad.append("--env-add-sensitive-key must name %s" % sorted(REQUIRED_KEYS))
    return bad


def script(path, kind):
    bad = []
    lines = []
    for l in re.sub(r"\\\n\s*", " ", open(path).read()).splitlines():
        l = l.strip()
        if l and not l.startswith("#") and not l.startswith("#!"):
            lines.append(l)
    text = "\n".join(lines)
    for pat, why in ((r"\b(curl|wget|pip3?\s+install|go\s+get|git\s+clone|git\s+fetch|npm\s+install|apt(-get)?\s+install)\b", "a network fetch"),
                     (r"\bset\s+\+e\b|\|\|\s*(true|:)\b", "a failure-ignoring step"),
                     (r"\b(sudo|sysctl|unshare|melange|apko)\b", "a sudo/sysctl/unshare of its own or a direct melange/apko call (cache's scripts do those)"),
                     (r"\b(HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy|GOPROXY|GOFLAGS|GOTOOLCHAIN|APK_RELEASE_SIGNING_KEY)\b|--signing-key|--ignore-signatures|--allow-untrusted|--insecure",
                      "a variable or flag cache's scripts refuse (or a proxy or module-fetch setting)")):
        if re.search(pat, text):
            bad.append("%s appears in bin/build-stage.sh" % why)
    if not lines or lines[0] != "set -euo pipefail":
        bad.append("the first command must be set -euo pipefail")
    cmds = lines[1:]
    SDE = r'export SOURCE_DATE_EPOCH="\$\(\./bin/build-apk\.sh --print-source-date-epoch --source-dir \.\)"'
    POLICY = r'python3 bin/chain-verify\.py policy make .*--tag "\$GITHUB_REF_NAME".*--out policy\.json'
    APKS = [r'\./bin/build-apk\.sh --variant standard .*', r'\./bin/build-apk\.sh --variant fips .*']
    IMGS = [r'\./bin/assemble-image\.sh --variant production .*', r'\./bin/assemble-image\.sh --variant fips .*']
    def ver(stage, prefix):
        return [r'python3 bin/chain-verify\.py verify --stage %s --record %s-ubuntu-24\.04/%s-collection\.json --policy policy\.json( .*)?' % (stage, "witness-" + prefix, prefix),
                r'python3 bin/chain-verify\.py verify --stage %s --record %s-ubuntu-24\.04-arm/%s-collection\.json --policy policy\.json( .*)?' % (stage, "witness-" + prefix, prefix)]
    START = (r'python3 bin/chain-verify\.py stage-start --stage rebuild --previous build --record witness-build/build-collection\.json '
             r'--digests witness-build/digests\.json --policy policy\.json')
    if kind == "apk":
        want = [r'python3 bin/build-admit\.py run', SDE] + APKS + [r'python3 bin/build-version-check\.py --binary \S+ --tag "\$GITHUB_REF_NAME" --sha "\$GITHUB_SHA"']
    elif kind == "assemble":
        # the per-architecture records are verified BEFORE any image is assembled from the downloaded apks (rule 58)
        want = [POLICY] + ver("build", "apk") + [SDE] + IMGS + [r'.*> witness-build/digests\.json', r'.*> witness-build/items\.json']
    elif kind == "rebuild-apk":
        want = [POLICY, START, SDE] + APKS
    else:
        want = [POLICY] + ver("rebuild", "rapk") + [START, SDE] + IMGS + [r'.*> items\.json',
                r'python3 bin/chain-verify\.py rebuild-compare --build-record witness-build/build-collection\.json --expected witness-build/items\.json '
                r'--actual items\.json --out verdict\.json']
    pos = 0
    for w in want:
        hit = next((n for n in range(pos, len(cmds)) if re.fullmatch(w, cmds[n])), None)
        if hit is None:
            bad.append("command %r is missing or out of order" % re.sub(r"\\(.)", r"\1", w)[:120])
        else:
            pos = hit + 1
    if kind == "apk" and cmds and not re.fullmatch(want[0], cmds[0]):
        bad.append("the FIRST command after set must be the admission script, got %r" % cmds[0][:60])
    return bad


def graph(path):
    bad = []
    d = yaml.load(open(path).read(), Loader=yaml.BaseLoader)
    jobs = d.get("jobs") or {}
    def needs(n):
        v = (jobs.get(n) or {}).get("needs")
        return None if v is None else sorted([v] if isinstance(v, str) else v)
    for n in ("build", "rebuild", "check"):
        if n not in jobs: bad.append("job %s is missing" % n)
    if needs("rebuild") != ["build"]: bad.append("rebuild must need only build, got %s" % needs("rebuild"))
    if needs("check") != ["build"]: bad.append("check must need only build, got %s" % needs("check"))
    if needs("sign") is None or "build" not in needs("sign"): bad.append("sign must need build, got %s" % needs("sign"))
    rel = next((n for n in ("release", "promotion") if n in jobs), None)
    if rel is None: bad.append("no release job")
    elif not {"rebuild", "check", "sign"} <= set(needs(rel) or []): bad.append("release must need rebuild, check and sign, got %s" % needs(rel))
    for n in ("rebuild",):
        j = jobs.get(n) or {}
        if "if" in j and "always()" in str(j["if"]): bad.append("%s must not run when build failed (always())" % n)
    return bad


def recordenv(path):
    d = json.load(open(path))
    txt = json.dumps(d)
    bad = []
    for v in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL"):
        if v in txt: bad.append("the record names %s" % v)
    if re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", txt): bad.append("the record holds a compact JWT")
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    try:
        _p = sys.argv[2]
        open(_p).close()
    except FileNotFoundError:
        print("missing file: %s" % sys.argv[2]); sys.exit(1)
    bad = {"stage": lambda: stage(sys.argv[2], sys.argv[3]), "script": lambda: script(sys.argv[2], sys.argv[3]),
           "graph": lambda: graph(sys.argv[2]), "recordenv": lambda: recordenv(sys.argv[2])}[cmd]()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
