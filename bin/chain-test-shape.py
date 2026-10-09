"""Test infrastructure (not product code), shared by bin/chain-build-wiring-test.sh and bin/chain-rebuild-test.sh: the judges for
the shape of the Build and Rebuild stage files, the four stage scripts, the job graph of release.yml and the environment record of
a Witness collection. Each judge prints `ok` or the list of faults and exits 1 on any fault; the tests first prove every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then apply it to the real repository (RED until
PR 2 is implemented).

DESIGN RULE (PR 1's ten lost rounds): NO denylists, NO shell analysis, NO subsequence checks. Every judge below is a FINITE EXACT
GRAMMAR over an allowlist: a stage file is exactly the steps in JOBS, a stage script is exactly the lines of expected_lines(KIND),
the job graph is exactly the keys and targets in CHAIN. Anything else is a fault by construction.

  helper FILE                               REQ-CHAIN-004-AC2 (the Witness seam): bin/witnessed.sh is exactly the canonical helper, `timeout 540` included
  directwitness FILE...                     REQ-CHAIN-004-AC2: no `witness run` in any stage file or stage script (every call goes through the helper)
  stage FILE build|rebuild [ALLOWED.json]   REQ-CHAIN-004-AC1, AC2 / REQ-CHAIN-005-AC1, AC4
  script FILE KIND                          REQ-CHAIN-004-AC3, AC6, AC11 / REQ-CHAIN-005-AC2: FILE is exactly expected_lines(KIND)
  lockflow BUILD_ASM REBUILD_ASM STAGE_YML...   REQ-CHAIN-004-AC11 / REQ-CHAIN-005-AC6: Build and Rebuild assemble identically; no stage file names apko
  listed CHAIN_SCRIPTS.json ROOT            the four scripts are rows of .github/policy/chain-scripts.json with their real sha256 (PR 1's design)
  graph FILE                                REQ-CHAIN-005-AC5: the chain jobs of release.yml
  recordenv FILE                            REQ-CHAIN-004-AC8: no token variable or token in a Witness collection (a DSSE envelope)

=== Rule 68 seam (advisor ruling, Oct 9; owner's amendment of rule 68: every command run under Witness is wrapped in `timeout 540`) ===========
Fulcio's keyless certificate lives 10 minutes and Witness verifies it at the timestamp's time (harness spike (d)), so no witnessed command may
outlive it. The wrapping lives in ONE place: the committed helper bin/witnessed.sh `witnessed <step> <script>`, which holds ALL the Witness flags
(keyless Fulcio, the timestamp authority, the attestors, the output path, `timeout 540`). Every stage calls it; no stage file and no listed script
names `witness run`. The seam in this file is exactly three functions: witness_seam (the stage's one run line), helper (the helper's exact lines)
and directwitness (nothing else runs Witness). If harness spike (d) changes the wrapping (witness wraps only short steps; or a second witness run
signs a record of the first), only those three functions and the fixture generators (witness_block, witnessed_text in
bin/chain-build-wiring-test.sh) change; the per-kind script grammar (expected_lines) never names Witness.
READABILITY FOR A HUMAN IS AN EXPLICIT REVIEW ITEM (owner, Oct 9): the judges accept the plain form and reject variants rather than growing clever.
==============================================================================================================================

PROPOSED/UNVERIFIED layout constants (cache's archive layout and the items layout are not fixed by any cache test; each is ONE
constant here, so a cache amendment changes one line): ARCHIVE, GO_ARCHIVE, KEYRING_WOLFI, MELANGE_LOCK, ASSEMBLY_PUB.
"""
import hashlib, json, re, shlex, sys, yaml

ARCHIVE, GO_ARCHIVE = "archive", "archive/go"
KEYRING_WOLFI, MELANGE_LOCK, ASSEMBLY_PUB = "archive/keys/wolfi-signing.rsa.pub", "build/locks/melange.lock", "build/keys/assembly.rsa.pub"
VER = '"${GITHUB_REF_NAME#v}"'
RUNNERS = [("ubuntu-24.04", "x86_64"), ("ubuntu-24.04-arm", "aarch64")]
H = "set -euo pipefail"
POLICY = 'python3 bin/chain-verify.py policy make --template .github/policy/release-policy.template.json --tag "$GITHUB_REF_NAME" --out policy.json'
SDE = ['SOURCE_DATE_EPOCH="$(./bin/build-apk.sh --print-source-date-epoch --source-dir .)"', "export SOURCE_DATE_EPOCH"]


def apk_cmd(v):
    return ('./bin/build-apk.sh --variant %s --arch "$(uname -m)" --version %s --source-dir . --repo %s --keyring %s --go-archive %s '
            "--melange-lock %s --out out" % (v, VER, ARCHIVE, KEYRING_WOLFI, GO_ARCHIVE, MELANGE_LOCK))


def img_cmd(v):
    return ("./bin/assemble-image.sh --variant %s --version %s --archive %s --melange-repo melange-repo --keyring-dir keyring --out out"
            % (v, VER, ARCHIVE))


def apk_file(v):
    return "fscache-%s-r0.apk" % VER[1:-1] if v == "standard" else "fscache-fips-%s-r0.apk" % VER[1:-1]


def q(s):
    return '"%s"' % s if "$" in s else s


def bind(stage, recdir, recname, indir, runner, arch, fname, as_name):
    return ("python3 bin/chain-verify.py bind --stage %s --record %s/%s/%s --policy policy.json --file %s --as %s"
            % (stage, recdir, runner, recname, q("%s/%s/%s/%s" % (indir, runner, arch, fname)), q(as_name)))


def bind_frag(stage, recdir, recname, indir, runner):
    return ("python3 bin/chain-verify.py bind --stage %s --record %s/%s/%s --policy policy.json --file %s/%s/items-apk.json --as items-apk.json"
            % (stage, recdir, runner, recname, indir, runner))


def verify_rec(stage, recdir, recname, runner):
    return "python3 bin/chain-verify.py verify --stage %s --record %s/%s/%s --policy policy.json" % (stage, recdir, runner, recname)


def binds(stage, recdir, recname, indir):
    out = []
    for r, a in RUNNERS:
        for f in (apk_file("standard"), apk_file("fips"), "APKINDEX.tar.gz"):
            out.append(bind(stage, recdir, recname, indir, r, a, f, "out/%s/%s" % (a, f)))
        out.append(bind_frag(stage, recdir, recname, indir, r))
    return out


def repo_lines(indir):
    return ["mkdir -p melange-repo"] + ["cp -R %s/%s/%s melange-repo/%s" % (indir, r, a, a) for r, a in RUNNERS] \
        + ["mkdir -p keyring", "cp %s keyring/wolfi-signing.rsa.pub" % KEYRING_WOLFI, "cp %s keyring/assembly.rsa.pub" % ASSEMBLY_PUB]


def merge_cmd(indir, extra):
    return ("python3 bin/chain-verify.py items-merge " + " ".join("--fragment %s/%s/items-apk.json" % (indir, r) for r, a in RUNNERS)
            + " --images out --archive %s %s" % (ARCHIVE, extra))


def expected_lines(kind):
    """The exact lines (shebang, comments and blank lines aside) of bin/build-stage-KIND.sh. Nothing else is allowed in the file."""
    items_apk = 'python3 bin/chain-verify.py items-apk --out-dir out --arch "$(uname -m)" --version %s --result items-apk.json' % VER
    if kind == "apk":
        out = [H, "python3 bin/build-admit.py run"] + SDE + [apk_cmd("standard"), apk_cmd("fips")]
        for v in ("standard", "fips"):
            out += ['python3 bin/apk-tool.py cat "out/$(uname -m)/%s" usr/bin/fscache > out/fscache-%s.bin' % (apk_file(v), v),
                    'python3 bin/build-version-check.py --binary out/fscache-%s.bin --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA"' % v]
        return out + [items_apk]
    if kind == "assemble":
        return ([H, POLICY] + [verify_rec("build", "witness-apk-in", "apk-collection.json", r) for r, a in RUNNERS]
                + binds("build", "witness-apk-in", "apk-collection.json", "apk-in") + repo_lines("apk-in") + SDE
                + [img_cmd("production"), img_cmd("fips"), merge_cmd("apk-in", "--digests digests.json --items items.json"),
                   "python3 bin/build-archives.py --melange-repo melange-repo --version %s --out dist" % VER])
    if kind == "rebuild-apk":
        start = ("python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record witness-build/build-collection.json "
                 "--digests build-in/digests.json --policy policy.json")
        return [H, POLICY, start] + SDE + [apk_cmd("standard"), apk_cmd("fips"), items_apk]
    if kind == "rebuild-assemble":
        start = ("python3 bin/chain-verify.py stage-start --stage rebuild --previous build --record witness-build/build-collection.json "
                 "--digests build-in/digests.json --policy policy.json")
        return ([H, POLICY] + [verify_rec("rebuild", "witness-rapk-in", "rapk-collection.json", r) for r, a in RUNNERS] + [start]
                + binds("rebuild", "witness-rapk-in", "rapk-collection.json", "rapk-in") + repo_lines("rapk-in") + SDE
                + [img_cmd("production"), img_cmd("fips"), merge_cmd("rapk-in", "--items items.json"), "mkdir -p witness-rebuild",
                   "python3 bin/chain-verify.py rebuild-compare --build-record witness-build/build-collection.json "
                   "--expected build-in/items.json --actual items.json --out witness-rebuild/verdict.json"])
    raise KeyError(kind)


SCRIPTS = {"witnessed": "bin/witnessed.sh", "apk": "bin/build-stage-apk.sh", "assemble": "bin/build-stage-assemble.sh",
           "rebuild-apk": "bin/build-stage-rebuild-apk.sh", "rebuild-assemble": "bin/build-stage-rebuild-assemble.sh"}


def script(path, kind):
    bad = []
    raw = open(path).read()
    if "\\\n" in raw:
        bad.append("a line continuation (every command is ONE physical line)")
    lines = [l.rstrip("\n") for l in raw.splitlines()]
    cmds = [l for l in lines if l.strip() and not l.lstrip().startswith("#")]
    for l in cmds:
        if l != l.strip():
            bad.append("indented or space-padded line %r (exact lines only)" % l[:60])
    want = expected_lines(kind)
    got = [l.strip() for l in cmds]
    for i in range(max(len(want), len(got))):
        w = want[i] if i < len(want) else None
        g = got[i] if i < len(got) else None
        if w != g:
            bad.append("command %d: expected %r, found %r" % (i + 1, (w or "<end of file>")[:150], (g or "<end of file>")[:150]))
            break
    if len(got) != len(want):
        bad.append("the script has %d commands, the grammar has %d (no extra command, no missing command)" % (len(got), len(want)))
    return bad


# ---- the stage files -----------------------------------------------------------------------------------------------------------
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
CHECKOUT_WITH = {"persist-credentials": "false", "fetch-depth": "0", "fetch-tags": "true"}
PERM_PLAIN = {"contents": "read", "id-token": "write"}
PERM_ADMIT = {"contents": "read", "checks": "read", "statuses": "read", "pull-requests": "read", "id-token": "write"}
MAT = "${{ matrix.runner }}"
JOBS = {  # (family, job) -> spec; every step list is EXACT and in this order
    ("build", "apk"): dict(kind="apk", step="apk", perm=PERM_ADMIT, gh=True, matrix=True,
        down=[], up=[("apk-" + MAT, ("out", "items-apk.json")), ("witness-apk-" + MAT, ("witness-apk",))]),
    ("build", "assemble"): dict(kind="assemble", step="build", perm=PERM_PLAIN, gh=False, matrix=False,
        down=[("apk-" + r, "apk-in/" + r) for r, a in RUNNERS] + [("witness-apk-" + r, "witness-apk-in/" + r) for r, a in RUNNERS],
        up=[("witness-build", ("witness-build",)), ("digests", ("digests.json",)), ("items", ("items.json",)), ("dist", ("dist",)),
            ("locks", ("out/production.full.lock.json", "out/fips.full.lock.json")), ("images", ("out/production.tar", "out/fips.tar"))]),
    ("rebuild", "apk"): dict(kind="rebuild-apk", step="rapk", perm=PERM_PLAIN, gh=False, matrix=True,
        down=[("witness-build", "witness-build"), ("digests", "build-in")],
        up=[("rapk-" + MAT, ("out", "items-apk.json")), ("witness-rapk-" + MAT, ("witness-rapk",))]),
    ("rebuild", "assemble"): dict(kind="rebuild-assemble", step="rebuild", perm=PERM_PLAIN, gh=False, matrix=False,
        down=[("witness-build", "witness-build"), ("digests", "build-in"), ("items", "build-in")]
              + [("rapk-" + r, "rapk-in/" + r) for r, a in RUNNERS] + [("witness-rapk-" + r, "witness-rapk-in/" + r) for r, a in RUNNERS],
        up=[("witness-rebuild", ("witness-rebuild",))]),
}


def lines_of(v):
    return [l.strip() for l in str(v).strip().splitlines() if l.strip()]


def stage(path, family, allowed_path=None):
    bad = []
    text = open(path).read()
    d = yaml.load(text, Loader=yaml.BaseLoader)
    if not isinstance(d, dict) or set(d) - {"name", "on", "permissions", "jobs"}:
        return ["top-level keys beyond name/on/permissions/jobs: %s" % (sorted(set(d) - {"name", "on", "permissions", "jobs"}) if isinstance(d, dict) else d)]
    on = d.get("on")
    if not isinstance(on, dict) or set(on) != {"workflow_call"} or (on.get("workflow_call") or {}) not in ({}, None, ""):
        bad.append("on: must be exactly workflow_call with no inputs or secrets, got %s" % on)
    if d.get("permissions") != {"contents": "read"}:
        bad.append("workflow permissions must be exactly contents: read, got %s" % d.get("permissions"))
    if re.search(r"\bwitness\s+run\b", text): bad.append("the stage file names `witness run` directly (every stage goes through bin/witnessed.sh)")
    jobs = d.get("jobs") or {}
    if set(jobs) != {"apk", "assemble"}:
        return bad + ["exactly two jobs required, apk and assemble (one stage = one file = one identity), found %s" % sorted(jobs)]
    allowed = None
    if allowed_path:
        try:
            allowed = set(json.load(open(allowed_path)).get("actions", []))
        except (OSError, ValueError):
            bad.append("the allowed-actions list %s is unreadable (fail closed)" % allowed_path)
    for name in ("apk", "assemble"):
        bad += ["%s: %s" % (name, m) for m in job(jobs[name], family, name, allowed)]
    return bad


def pinned(uses, prefix, allowed):
    u = (uses or "").split(" ")[0]
    if not u.startswith(prefix + "@") or not PIN.match(u):
        return False
    return allowed is None or u in allowed


def job(j, family, name, allowed):
    spec = JOBS[(family, name)]
    bad = []
    keys = {"runs-on", "permissions", "steps", "timeout-minutes"} | ({"strategy"} if spec["matrix"] else {"needs"})
    if set(j) - keys:
        bad.append("job keys outside the allowlist: %s" % sorted(set(j) - keys))
    if {"runs-on", "permissions", "steps"} - set(j):
        bad.append("job lacks %s" % sorted({"runs-on", "permissions", "steps"} - set(j)))
    for k in ("container", "services", "env", "defaults", "environment", "outputs", "if", "continue-on-error", "uses", "secrets"):
        if k in j: bad.append("job has %s" % k)
    if spec["matrix"]:
        st = j.get("strategy") or {}
        if j.get("runs-on") != MAT:
            bad.append("the apk job must run on matrix.runner, got %r" % j.get("runs-on"))
        if set(st) - {"matrix", "fail-fast"} or set(st.get("matrix") or {}) != {"runner"} or sorted((st.get("matrix") or {}).get("runner") or []) != sorted(r for r, a in RUNNERS):
            bad.append("strategy must be exactly matrix.runner: both of %s (native runners, no emulation, no include/exclude)" % [r for r, a in RUNNERS])
    else:
        if j.get("runs-on") != "ubuntu-24.04": bad.append("the assemble job must run directly on the ubuntu-24.04 VM (rule 62), got %r" % j.get("runs-on"))
        if j.get("needs") not in ("apk", ["apk"]): bad.append("assemble must need exactly apk, got %s" % j.get("needs"))
    if j.get("permissions") != spec["perm"]:
        bad.append("permissions must be exactly %s, got %s" % (spec["perm"], j.get("permissions")))
    steps = j.get("steps") or []
    if len(steps) < 3: return bad + ["fewer than three steps"]
    if allowed is not None:
        for s_ in steps:
            u_ = (s_.get("uses") or "").split(" ")[0]
            if PIN.match(u_) and u_ not in allowed: bad.append("action %s is not on the allowed-actions list" % u_)
    i = 0
    s = steps[i]; i += 1
    if set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/checkout", allowed) or (s.get("with") or {}) != CHECKOUT_WITH:
        bad.append("step 1 must be a digest-pinned actions/checkout (on the allowed list) with exactly %s" % CHECKOUT_WITH)
    s = steps[i] if i < len(steps) else {}; i += 1
    if set(s) - {"run", "name"} or str(s.get("run") or "").strip() != "./bin/install-scanner.sh witness":
        bad.append("step 2 must be exactly: run ./bin/install-scanner.sh witness (checksum-pinned Witness install)")
    for nm, path_ in spec["down"]:
        s = steps[i] if i < len(steps) else {}; i += 1
        if set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/download-artifact", allowed) or (s.get("with") or {}) != {"name": nm, "path": path_}:
            bad.append("step %d must be a pinned actions/download-artifact with exactly name %s and path %s (a fresh named directory, never . or bin/ or .github/)" % (i, nm, path_))
    s = steps[i] if i < len(steps) else {}; i += 1
    want_keys = {"run", "name"} | ({"env"} if spec["gh"] else set())
    if set(s) - want_keys: bad.append("the Witness step may carry only %s (no if, shell, working-directory)" % sorted(want_keys))
    if spec["gh"] and s.get("env") != {"GH_TOKEN": "${{ github.token }}"}:
        bad.append("the admission job's Witness step must carry env exactly GH_TOKEN: ${{ github.token }} (PROPOSED, advisor-confirmed default)")
    if not spec["gh"] and "env" in s: bad.append("the Witness step has env")
    bad += witness_seam(s.get("run") or "", spec, family)
    for nm, paths in spec["up"]:
        s = steps[i] if i < len(steps) else {}; i += 1
        w = s.get("with") or {}
        if set(s) - {"uses", "with", "name"} or not pinned(s.get("uses"), "actions/upload-artifact", allowed) or w.get("name") != nm \
           or set(w) - {"name", "path", "if-no-files-found"} or tuple(lines_of(w.get("path"))) != paths or w.get("if-no-files-found", "error") != "error":
            bad.append("step %d must be a pinned actions/upload-artifact named %s with path exactly %s (and if-no-files-found error)" % (i, nm, list(paths)))
    if i != len(steps):
        bad.append("%d steps, the grammar has %d (no extra step)" % (len(steps), i))
    return bad


# ---- THE RULE 68 SEAM (three functions) -----------------------------------------------------------------------------------------------
STEPS = ("apk", "build", "rapk", "rebuild")      # the closed list of step names; the record is witness-STEP/STEP-collection.json
TOKEN = [
    'curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" -o "$RUNNER_TEMP/tok.json"',
    'jq -r .value "$RUNNER_TEMP/tok.json" > "$RUNNER_TEMP/tok"',
    'echo "::add-mask::$(cat "$RUNNER_TEMP/tok")"',
]
SENSITIVE = ["ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]   # never github (raw OIDC token) or slsa (Sign's alone)


def witnessed_lines():
    """The exact lines of bin/witnessed.sh (backslash continuations are joined before comparing: the committed file may break the long line)."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in apk|build|rapk|rebuild) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac',
            'mkdir -p "witness-$step"'] + TOKEN + [
            'exec witness run --step "$step" --signer-fulcio-url https://fulcio.sigstore.dev '
            "--signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com --signer-fulcio-oidc-client-id sigstore "
            '--signer-fulcio-token-path "$RUNNER_TEMP/tok" -t https://timestamp.sigstore.dev/api/v1/timestamp '
            "-a environment,git,material,product --env-filter-sensitive-vars %s "
            '-o "witness-$step/$step-collection.json" -- timeout 540 bash "$@"' % keys]


def witness_seam(run, spec, family):
    """1/3: the stage's Witness step is exactly ONE line through the helper, with the step name of its job and the committed script of its kind."""
    want = "bash bin/witnessed.sh %s bin/build-stage-%s.sh" % (spec["step"], spec["kind"])
    got = str(run).strip()
    return [] if got == want else ["the Witness step must be exactly the one line `%s`, found %r" % (want, got[:120])]


def helper(path):
    """2/3: bin/witnessed.sh is exactly the canonical helper: the only place the Witness flags and `timeout 540` live."""
    raw = open(path).read()
    lines = [re.sub(r"[ \t]+", " ", l.strip()) for l in re.sub(r"\\\n\s*", " ", raw).splitlines() if l.strip() and not l.lstrip().startswith("#")]
    want = witnessed_lines()
    bad = []
    for i in range(max(len(want), len(lines))):
        w = want[i] if i < len(want) else None
        g = lines[i] if i < len(lines) else None
        if w != g:
            bad.append("helper command %d: expected %r, found %r" % (i + 1, (w or "<end of file>")[:170], (g or "<end of file>")[:170])); break
    if len(want) != len(lines): bad.append("the helper has %d commands, the canonical form has %d" % (len(lines), len(want)))
    return bad


def directwitness(files):
    """3/3: nothing but the helper runs Witness: no `witness run` in a stage file or a stage script."""
    bad = []
    for f in files:
        try:
            if re.search(r"\bwitness\s+run\b", open(f).read()): bad.append("%s names `witness run` directly (every stage goes through bin/witnessed.sh)" % f)
        except FileNotFoundError:
            bad.append("missing file: %s" % f)
    return bad


# ---- Build vs Rebuild --------------------------------------------------------------------------------------------------------------
def lockflow(files):
    bad = []
    if len(files) < 2: return ["lockflow needs the Build and Rebuild assemble scripts"]
    asm = []
    for f in files[:2]:
        try:
            asm.append([l.strip() for l in open(f).read().splitlines() if l.strip().startswith("./bin/assemble-image.sh")])
        except FileNotFoundError:
            bad.append("missing file: %s" % f); asm.append([])
    if not bad and (not asm[0] or asm[0] != asm[1]):
        bad.append("Build and Rebuild assemble-image.sh lines are not identical (same script, same arguments, same lock flow): %s vs %s" % (asm[0], asm[1]))
    for f in files[2:]:
        try:
            d = yaml.load(open(f).read(), Loader=yaml.BaseLoader)
        except FileNotFoundError:
            bad.append("missing file: %s" % f); continue
        if re.search(r"\bapko\b", json.dumps(d)):
            bad.append("%s: names apko (only bin/assemble-image.sh may run it, always with the lock)" % f)
    return bad


def listed(path, root):
    bad = []
    try:
        rows = {r.get("path"): r for r in json.load(open(path)).get("scripts", [])}
    except (OSError, ValueError):
        return ["%s is unreadable" % path]
    for k, p in SCRIPTS.items():
        r = rows.get(p)
        if r is None: bad.append("%s is not a row of chain-scripts.json" % p); continue
        try:
            h = hashlib.sha256(open(root + "/" + p, "rb").read()).hexdigest()
        except OSError:
            bad.append("%s is listed but missing" % p); continue
        if r.get("sha256") != h: bad.append("%s: the listed sha256 is not the committed script's" % p)
    return bad


# ---- release.yml --------------------------------------------------------------------------------------------------------------------
CHAIN = {"build": "stage-build.yml", "sign": "stage-sign.yml", "rebuild": "stage-reproducibility.yml", "check": "stage-verify.yml", "release": "stage-promote.yml"}
NEEDS = {"build": [], "sign": ["build"], "rebuild": ["build"], "check": ["build"], "release": ["check", "rebuild", "sign"]}


def graph(path):
    bad = []
    d = yaml.load(open(path).read(), Loader=yaml.BaseLoader)
    jobs = d.get("jobs") or {}
    for n, f in CHAIN.items():
        j = jobs.get(n)
        if j is None: bad.append("chain job %s is missing (the job id is the stage name, so a failure names it)" % n); continue
        extra = set(j) - {"uses", "needs", "permissions", "with"}
        if extra: bad.append("%s: keys outside {uses, needs, permissions, with}: %s (no if, continue-on-error, secrets, strategy, env)" % (n, sorted(extra)))
        if j.get("uses") != "./.github/workflows/" + f: bad.append("%s must call exactly ./.github/workflows/%s, got %r" % (n, f, j.get("uses")))
        nd = j.get("needs"); nd = [] if nd is None else ([nd] if isinstance(nd, str) else list(nd))
        if sorted(nd) != NEEDS[n]: bad.append("%s must need exactly %s, got %s" % (n, NEEDS[n], sorted(nd)))
    return bad


# ---- the Witness record -------------------------------------------------------------------------------------------------------------
NAMES = ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL", "GH_TOKEN", "GITHUB_TOKEN")


def recordenv(path):
    import base64
    d = json.load(open(path))
    texts = [json.dumps(d)]
    if isinstance(d, dict) and "payload" in d:
        try:
            texts.append(base64.b64decode(d["payload"]).decode("utf-8", "replace"))
        except Exception:
            return ["the DSSE payload is not base64"]
    elif isinstance(d, dict) and "predicate" in d:
        return ["the record is a bare Statement, not a DSSE envelope (Witness -o writes {payloadType, payload, signatures})"]
    txt = "\n".join(texts)
    bad = []
    for v in NAMES:
        if v in txt: bad.append("the record names %s" % v)
    if re.search(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", txt): bad.append("the record holds a compact JWT")
    if re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}", txt): bad.append("the record holds a GitHub token")
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "expected":
        print("\n".join(expected_lines(sys.argv[2]))); sys.exit(0)
    try:
        for _p in sys.argv[2:3]:
            open(_p).close()
    except FileNotFoundError:
        print("missing file: %s" % sys.argv[2]); sys.exit(1)
    bad = {"stage": lambda: stage(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None), "script": lambda: script(sys.argv[2], sys.argv[3]),
           "lockflow": lambda: lockflow(sys.argv[2:]), "graph": lambda: graph(sys.argv[2]), "recordenv": lambda: recordenv(sys.argv[2]),
           "listed": lambda: listed(sys.argv[2], sys.argv[3]), "helper": lambda: helper(sys.argv[2]), "directwitness": lambda: directwitness(sys.argv[2:])}[cmd]()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
