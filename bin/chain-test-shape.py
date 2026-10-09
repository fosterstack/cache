"""Test infrastructure (not product code), shared by bin/chain-build-wiring-test.sh and bin/chain-rebuild-test.sh: the judges
for the shape of the Build and Rebuild stage files, the order of bin/build-stage.sh, the job graph of release.yml and the
environment record of a Witness collection. Each judge prints `ok` or the list of faults and exits 1 on any fault; the two
tests first prove every judge on a known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then
apply it to the real repository (RED until PR 2 is implemented).

  stage FILE build|rebuild     REQ-CHAIN-004-AC1, AC2 / REQ-CHAIN-005-AC1, AC4: an ALLOWLIST. The stage file is a reusable workflow
                               (on: workflow_call only) of ONE job (a matrix over the native runners is one job) directly on a
                               GitHub-hosted ubuntu VM, with permissions exactly contents read + id-token write, no container,
                               services, env, defaults, secrets or packages write, whose steps are EXACTLY, in order:
                                 1. actions/checkout (full commit digest, persist-credentials: false)
                                 2. run: ./bin/install-scanner.sh witness      (Witness, pinned by version and checksum like the other
                                                                                tools; the implementation adds witness to the script)
                                 3. ONE run step: the token fetch (curl to $ACTIONS_ID_TOKEN_REQUEST_URL, jq, ::add-mask::) and ONE
                                    `witness run` with only the allowed flags (fixed Fulcio and Sigstore timestamp addresses, the
                                    environment filter flag and the token-variable key patterns), ending `-- ./bin/build-stage.sh KIND`
                                 4. only upload-artifact steps with allowed artifact names (build: witness-build digests dist locks;
                                    rebuild: witness-rebuild)
                               in-toto-witness docs/attestors/environment.md ("Filter instead of obfuscate": --env-filter-sensitive-vars,
                               --env-add-sensitive-key); docs/commands.md (witness run flags); harness spike
                               2026-10-09-harness-witness-spikes-a-c.md:20-30 (the token fetch and fulcio flags).
  script FILE build|rebuild    REQ-CHAIN-004-AC3, AC6 / REQ-CHAIN-005-AC2: the commands of bin/build-stage.sh in order.
  graph FILE                   REQ-CHAIN-005-AC5: release.yml job graph.
  recordenv FILE               REQ-CHAIN-004-AC8: no token variable in a Witness collection (used by the fixtures test of the judge; the
                               product check is chain-verify.py record-env, which the tests assert separately)."""
import json, re, shlex, sys, yaml

ARTIFACTS = {"build": {"witness-build", "digests", "dist", "locks"}, "rebuild": {"witness-rebuild"}}
RUNNERS = {"ubuntu-24.04", "ubuntu-24.04-arm"}
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
FLAGS = {  # flag -> exact value, None = any value (checked separately), False = takes no value
    "--step": None, "--signer-fulcio-url": "https://fulcio.sigstore.dev",
    "--signer-fulcio-oidc-issuer": "https://token.actions.githubusercontent.com", "--signer-fulcio-oidc-client-id": "sigstore",
    "--signer-fulcio-token-path": '"$RUNNER_TEMP/tok"', "-t": "https://timestamp.sigstore.dev/api/v1/timestamp",
    "-a": None, "--env-filter-sensitive-vars": False, "--env-add-sensitive-key": None, "-d": None, "-o": None,
}
ATTESTORS = {"environment", "git", "github", "material", "product", "command-run"}
REQUIRED_KEYS = {"ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN"}
TOKEN_LINES = [
    r'curl -sSf -H "Authorization: bearer \$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\}&audience=sigstore" -o "\$RUNNER_TEMP/tok\.json"',
    r'jq -r \.value "\$RUNNER_TEMP/tok\.json" > "\$RUNNER_TEMP/tok"',
    r'echo "::add-mask::\$\(cat "\$RUNNER_TEMP/tok"\)"',
    r'set -euo pipefail',
]
OUT = {"build": "witness-build/build-collection.json", "rebuild": "witness-rebuild/rebuild-collection.json"}


def stage(path, kind):
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
    jobs = d.get("jobs") or {}
    if len(jobs) != 1:
        bad.append("exactly one job required, found %d" % len(jobs)); return bad
    j = list(jobs.values())[0]
    if set(j) - {"name", "runs-on", "permissions", "steps", "strategy", "outputs", "timeout-minutes"}:
        bad.append("job keys outside the allowlist: %s" % sorted(set(j) - {"name", "runs-on", "permissions", "steps", "strategy", "outputs", "timeout-minutes"}))
    for k in ("container", "services", "env", "defaults", "environment"):
        if k in j: bad.append("job has %s" % k)
    ro = j.get("runs-on")
    if ro in RUNNERS: pass
    elif isinstance(ro, str) and re.fullmatch(r"\$\{\{\s*matrix\.runner\s*\}\}", ro):
        mr = (((j.get("strategy") or {}).get("matrix") or {}).get("runner")) or []
        if not mr or not set(mr) <= RUNNERS or set((j.get("strategy") or {}).keys()) - {"matrix", "fail-fast"} \
           or set(((j.get("strategy") or {}).get("matrix") or {}).keys()) != {"runner"}:
            bad.append("matrix must be exactly runner: a subset of %s" % sorted(RUNNERS))
    else:
        bad.append("runs-on must be a GitHub-hosted ubuntu-24.04 runner (or the matrix.runner of two), got %r" % ro)
    perm = j.get("permissions")
    if perm != {"contents": "read", "id-token": "write"}:
        bad.append("permissions must be exactly contents: read + id-token: write, got %s" % perm)
    if re.search(r"\bsecrets\s*\.|secrets\[|secrets:\s*inherit|packages:\s*write", text):
        bad.append("a secrets reference or packages: write appears")
    steps = j.get("steps") or []
    if len(steps) < 3:
        bad.append("fewer than three steps"); return bad
    s0, s1, s2 = steps[:3]
    if set(s0) - {"uses", "with", "name"} or not PIN.match((s0.get("uses") or "").split(" ")[0]) or not (s0.get("uses") or "").startswith("actions/checkout@") \
       or (s0.get("with") or {}).get("persist-credentials") != "false":
        bad.append("step 1 must be actions/checkout pinned by full digest with persist-credentials: false")
    if set(s1) - {"run", "name"} or (s1.get("run") or "").strip() != "./bin/install-scanner.sh witness":
        bad.append("step 2 must be exactly: run ./bin/install-scanner.sh witness (checksum-pinned Witness install)")
    if set(s2) - {"run", "name"}:
        bad.append("step 3 (the Witness step) may carry only run and name (no env, if, shell, working-directory)")
    bad += witness_step(s2.get("run") or "", kind)
    for s in steps[3:]:
        u = s.get("uses") or ""
        if set(s) - {"uses", "with", "name", "if"} or not u.startswith("actions/upload-artifact@") or not PIN.match(u.split(" ")[0]):
            bad.append("step %r after the Witness step must be a digest-pinned actions/upload-artifact and nothing else" % s.get("name"))
            continue
        nm = (s.get("with") or {}).get("name")
        if nm not in ARTIFACTS[kind]:
            bad.append("upload of %r is not an allowed artifact for %s: %s" % (nm, kind, sorted(ARTIFACTS[kind])))
    return bad


def witness_step(run, kind):
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
    if seen.get("--step") and seen["--step"] != [kind]:
        bad.append("--step must be %s" % kind)
    if seen.get("-o") and seen["-o"] != [OUT[kind]]:
        bad.append("-o must be %s" % OUT[kind])
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
    if kind == "build":
        want = [r'python3 bin/build-admit\.py run',
                r'export SOURCE_DATE_EPOCH="\$\(\./bin/build-apk\.sh --print-source-date-epoch --source-dir \.\)"',
                r'\./bin/build-apk\.sh --variant standard .*', r'\./bin/build-apk\.sh --variant fips .*',
                r'\./bin/assemble-image\.sh --variant production .*', r'\./bin/assemble-image\.sh --variant fips .*',
                r'python3 bin/build-version-check\.py --binary \S+ --tag "\$GITHUB_REF_NAME" --sha "\$GITHUB_SHA"',
                r'.*> digests\.json', r'.*> items\.json']
    else:
        want = [r'python3 bin/chain-verify\.py policy make .*--tag "\$GITHUB_REF_NAME".*--out policy\.json',
                r'python3 bin/chain-verify\.py stage-start --stage rebuild --previous build --record witness-build/build-collection\.json '
                r'--digests witness-build/digests\.json --policy policy\.json',
                r'export SOURCE_DATE_EPOCH="\$\(\./bin/build-apk\.sh --print-source-date-epoch --source-dir \.\)"',
                r'\./bin/build-apk\.sh --variant standard .*', r'\./bin/build-apk\.sh --variant fips .*',
                r'\./bin/assemble-image\.sh --variant production .*', r'\./bin/assemble-image\.sh --variant fips .*',
                r'.*> items\.json',
                r'python3 bin/chain-verify\.py rebuild-compare --build-record witness-build/build-collection\.json --expected witness-build/items\.json '
                r'--actual items\.json --out verdict\.json']
    pos = 0
    for w in want:
        hit = next((n for n in range(pos, len(cmds)) if re.fullmatch(w, cmds[n])), None)
        if hit is None:
            bad.append("command %r is missing or out of order" % w[:70])
        else:
            pos = hit + 1
    if kind == "build" and cmds and not re.fullmatch(want[0], cmds[0]):
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
