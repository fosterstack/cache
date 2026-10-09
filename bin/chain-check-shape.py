"""Test infrastructure (not product code) for PR 3 "Check", shared by bin/chain-check-wiring-test.sh. Judges for the shape of the Check
stage file, the order of bin/check-stage.sh, the release.yml job graph, the plainness of the check scripts and the removal of the old
acceptance stages. Each judge prints `ok` or the list of faults and exits 1 on a fault. The test first proves every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then applies it to the real repository, which is
RED until PR 3 is implemented. Finite grammars and allowlists only; no shell analysis (final PR 1 design, advisor decision b).

  stage FILE            REQ-CHAIN-006-AC1: stage-verify.yml is an ALLOWLIST. on: workflow_call only; exactly ONE job `check`; runs-on
                        ubuntu-24.04; permissions exactly contents read + id-token write; no container, services, env, defaults, secrets,
                        strategy, needs, shell, working-directory, continue-on-error; steps EXACTLY, in order:
                          1. actions/checkout (full commit digest, persist-credentials: false, nothing else)
                          2. run: ./bin/install-scanner.sh witness
                          3. digest-pinned actions/download-artifact steps, names from DOWN, explicit path outside bin/ and .github/
                          4. THREE run steps, one line each, the only form `bash bin/witnessed.sh STEP bin/check-stage.sh STEP` with STEP
                             from the closed list scanners, acceptance, runtime, in that order (REQ-CHAIN-006-AC11: the stage never calls
                             `witness` or `timeout` itself; the helper is the one place for both)
                          5. only digest-pinned upload-artifact steps with names from UP (witness-check carries witness-records/)
  helper FILE           REQ-CHAIN-006-AC9, AC11 (the RULE 68 SEAM): bin/witnessed.sh, the one helper every stage calls, holds the token fetch,
                        ALL Witness flags and the 9-minute cap. THE HELPER ITSELF IS PR 2's: this judge is kept identical to PR 2's; when PR 2
                        lands, delete this copy and import PR 2's. Exactly one `witness run`, flags from the allowlist (no -d, never the github
                        or slsa attestor), the wrapped command preceded by exactly one `timeout 540` and nothing else repeats it.
                        If harness spike (d) leads the owner to change the wrapping again, only this function and its fixtures change.
  script FILE           REQ-CHAIN-006-AC3: bin/check-stage.sh is `set -euo pipefail`, the two verify commands, then ONE fixed `case "$1"` with
                        exactly the phases of PHASES (each with exactly its commands, in order) and nothing else.
  records JSON          REQ-CHAIN-006-AC13 (rule 66): .github/policy/chain-records.json has no row for the old acceptance record and has a row
                        for the Witness collection naming Check as a producer and `release` as consumer. [P: the table's shape is PR 1's]
  graph FILE            REQ-CHAIN-006-AC2: release.yml job graph (check beside rebuild).
  plain FILE...         REQ-CHAIN-006-AC8: the check scripts know nothing about signing (text scan, comments and quotes included).
  listed JSON ROOT      REQ-CHAIN-006-AC8: each check script is a row of .github/policy/chain-scripts.json with the sha256 the file has.
  removed ROOT          REQ-CHAIN-006-AC10 (rules 61, 65): the old acceptance stages and the custom authorization verifier are gone and
                        neither release.yml nor ci.yml calls them.
Modelled on: in-toto-witness docs/attestors/environment.md and docs/commands.md (the flags), docs/tutorials/artifact-policy.md:58-70 (what a
collection holds); PR 2's bin/chain-test-shape.py (the same flag allowlist, the same token-fetch lines)."""
import hashlib, json, os, re, sys, yaml

PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOWN = {"witness-build", "digests", "dist", "locks", "provenance"}     # Build's and Sign's artifacts; images travel as files (OCI tarballs)
UP = {"witness-check": "witness-records", "check-results": "check-results"}   # artifact name -> the one path it may carry
STEPS = ["scanners", "acceptance", "runtime"]                          # the closed list of Check's witnessed steps, in order
FLAGS = {"--step": '"$step"', "--signer-fulcio-url": "https://fulcio.sigstore.dev",
         "--signer-fulcio-oidc-issuer": "https://token.actions.githubusercontent.com", "--signer-fulcio-oidc-client-id": "sigstore",
         "--signer-fulcio-token-path": '"$RUNNER_TEMP/tok"', "-t": "https://timestamp.sigstore.dev/api/v1/timestamp",
         "-a": None, "--env-filter-sensitive-vars": False, "--env-add-sensitive-key": None, "-o": '"witness-records/$step.json"'}
ATTESTORS = {"environment", "git", "material", "product", "command-run"}
TOKEN_LINES = [
    r'curl -sSf -H "Authorization: bearer \$ACTIONS_ID_TOKEN_REQUEST_TOKEN" "\$\{ACTIONS_ID_TOKEN_REQUEST_URL\}&audience=sigstore" -o "\$RUNNER_TEMP/tok\.json"',
    r'jq -r \.value "\$RUNNER_TEMP/tok\.json" > "\$RUNNER_TEMP/tok"',
    r'echo "::add-mask::\$\(cat "\$RUNNER_TEMP/tok"\)"',
]
VERIFY = [  # bin/check-stage.sh after `set -euo pipefail`: the verify step first (rule 58), before any check (every phase re-verifies)
    r"python3 bin/chain-verify\.py stage-start --stage check --previous build --record witness-build/build-collection\.json --digests witness-build/digests\.json --policy policy\.json",
    r"python3 bin/chain-verify\.py verify --stage sign --record provenance/provenance\.json --policy policy\.json --rekor-stub provenance/provenance\.rekor\.json",
]
PHASES = {  # rules 55, 72, 79; the phases are split so that no witnessed command nears the 9-minute cap (rule 68, amended)
    "scanners": [r"bash bin/check-scan\.sh --scanners \.github/policy/scanners\.json --digests witness-build/digests\.json --images images --archives dist --out check-results"],
    "acceptance": [r"bash bin/check-acceptance\.sh gradle --digests witness-build/digests\.json --images images --out check-results",
                   r"bash bin/check-acceptance\.sh maven --digests witness-build/digests\.json --images images --out check-results"],
    "runtime": [r"bash bin/check-acceptance\.sh egress --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-fips\.sh --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-guide\.sh --guide docs/verify-release\.md --digests witness-build/digests\.json --images images --out check-results"],
}
SCRIPTS = ["bin/check-stage.sh", "bin/check-scan.sh", "bin/check-fips.sh", "bin/check-acceptance.sh", "bin/check-guide.sh"]
SIGNING = re.compile(r"cosign|witness|gitsign|sigstore|slsa|attest|in-toto|docker\s+login|ghcr\.io|secret|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|GITHUB_TOKEN|GH_TOKEN|SNYK", re.I)
OLD = ["stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml", "stage-authorize.yml"]
OLD_FILES = ["bin/authorize-acceptance-check.py", "bin/authorize-acceptance-check-test.sh"]   # the custom authorization verifier (rule 65)
COLLECTION = "https://witness.testifysec.com/attestation-collection/v0.1"


def load(path):
    return yaml.load(open(path), Loader=yaml.BaseLoader)


def stage(path):
    d, bad = load(path), []
    on = d.get("on") or {}
    if not (isinstance(on, dict) and set(on) == {"workflow_call"}):
        bad.append("on: must be exactly workflow_call: %s" % on)
    if set(d) - {"name", "on", "permissions", "jobs"}:
        bad.append("workflow keys not allowed: %s" % sorted(set(d) - {"name", "on", "permissions", "jobs"}))
    jobs = d.get("jobs") or {}
    if list(jobs) != ["check"]:
        bad.append("exactly one job named check is required, found %s" % list(jobs))
        return bad
    j = jobs["check"]
    if set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes"}:
        bad.append("job keys not allowed: %s" % sorted(set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes"}))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("check must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("permissions must be exactly contents read + id-token write: %s" % j.get("permissions"))
    steps = j.get("steps") or []
    text = open(path).read()
    if re.search(r"docker\s+login|\bsecrets\s*\.|secrets:|packages\s*:|attestations\s*:|ghcr\.io", text):
        bad.append("a registry login, a secret, a packages or attestations permission or a registry name appears in the file")
    kinds, names = [], []
    for s in steps:
        if set(s) - {"name", "uses", "with", "run"}:
            bad.append("step keys not allowed: %s" % sorted(set(s) - {"name", "uses", "with", "run"}))
        u = s.get("uses", "")
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down")
            w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".")):
                bad.append("download-artifact must be digest-pinned, name in %s, an explicit path outside bin/ and .github/: %s" % (sorted(DOWN), w))
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up")
            w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or UP.get(w.get("name")) != w.get("path") or set(w) != {"name", "path"}:
                bad.append("upload-artifact must be digest-pinned, name and path from %s (witness-check carries witness-records/): %s" % (UP, w))
        elif u:
            bad.append("uses not allowed in the Check stage: %s" % u)
        elif (s.get("run") or "").strip() == "./bin/install-scanner.sh witness":
            kinds.append("install")
        elif "run" in s:
            kinds.append("witnessed")
            m = re.fullmatch(r"bash bin/witnessed\.sh ([a-z]+) bin/check-stage\.sh ([a-z]+)", (s["run"] or "").strip())
            if not m or m.group(1) != m.group(2):
                bad.append("a run step must be exactly `bash bin/witnessed.sh STEP bin/check-stage.sh STEP` (no witness, timeout or other command in the stage): %r" % (s["run"] or "")[:80])
            else:
                names.append(m.group(1))
        else:
            bad.append("a step with neither uses nor run")
    want = ["checkout", "install"]
    got_down = [k for k in kinds if k == "down"]
    body = [k for k in kinds if k != "down"]
    if body[:2] != want or body[2:5] != ["witnessed"] * 3 or any(k != "up" for k in body[5:]) or len(body) < 6:
        bad.append("steps must be checkout, install Witness, downloads, THREE witnessed steps, uploads (in that order); got %s" % kinds)
    if not got_down:
        bad.append("no download of Build's artifacts")
    # downloads come after the install and before the first witnessed step
    if "witnessed" in kinds and "down" in kinds and max(i for i, k in enumerate(kinds) if k == "down") > kinds.index("witnessed"):
        bad.append("a download comes after Witness started (rule 68: third-party actions run before Witness or not at all)")
    if names != STEPS:
        bad.append("the witnessed steps must be exactly %s in that order, found %s" % (STEPS, names))
    return bad


def helper(path):
    """The rule 68 seam. bin/witnessed.sh STEP SCRIPT [ARGS]: the token fetch, one witness run, the 9-minute cap, nothing else."""
    bad = []
    lines = [l.rstrip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    text = "\n".join(lines)
    if not lines or lines[0].strip() != "set -euo pipefail":
        return ["the helper must start with set -euo pipefail"]
    if text.count("witness run") != 1:
        bad.append("exactly one `witness run` is required, found %d" % text.count("witness run"))
    if len(re.findall(r"\btimeout\b", text)) != 1 or not re.search(r"-- timeout 540 bash ", text):
        bad.append("the wrapped command must be preceded by exactly one `timeout 540` (rule 68, amended: a command that could outlive the ten-minute certificate fails the build)")
    for i, rx in enumerate(TOKEN_LINES):
        if not any(re.fullmatch(rx, l.strip()) for l in lines):
            bad.append("token-fetch line %d is not the pinned form" % (i + 1))
    cmd = " ".join(l.strip().rstrip("\\").strip() for l in text[text.find("witness run"):].split("\n")) if "witness run" in text else ""
    head = cmd[: cmd.index(" -- ")] if " -- " in cmd else cmd
    toks = head.split()[2:]
    i, seen = 0, set()
    while i < len(toks):
        f = toks[i]
        if f not in FLAGS:
            bad.append("witness flag not allowed: %s" % f); i += 1; continue
        seen.add(f)
        if FLAGS[f] is False:
            i += 1; continue
        v = toks[i + 1] if i + 1 < len(toks) else ""
        if f == "-a":
            names = set(v.split(","))
            if not names <= ATTESTORS:
                bad.append("attestor not allowed: %s (the github attestor embeds the raw token; slsa is Sign's alone)" % sorted(names - ATTESTORS))
        elif f == "--env-add-sensitive-key":
            if v.strip("'\"") not in ("ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN"):
                bad.append("sensitive key not allowed: %s" % v)
        elif FLAGS[f] is not None and v != FLAGS[f]:
            bad.append("flag %s must be %s, got %s" % (f, FLAGS[f], v))
        i += 2
    for must in ("--step", "--signer-fulcio-url", "--signer-fulcio-oidc-issuer", "--signer-fulcio-oidc-client-id", "--signer-fulcio-token-path", "-t",
                 "-a", "--env-filter-sensitive-vars", "-o"):
        if must not in seen:
            bad.append("witness flag missing: %s" % must)
    return bad


def script(path):
    """bin/check-stage.sh: set -euo pipefail, the two verify commands, then ONE fixed case "$1" with exactly the PHASES. Nothing else."""
    bad = []
    lines = [l.strip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    want = [("lit", "set -euo pipefail")] + [("rx", r) for r in VERIFY] + [("lit", 'case "$1" in')]
    for ph, cmds in PHASES.items():
        want += [("lit", ph + ")")] + [("rx", c) for c in cmds] + [("lit", ";;")]
    want += [("lit", '*) echo "unknown phase: $1" >&2; exit 2 ;;'), ("lit", "esac")]
    for i, (kind, w) in enumerate(want):
        got = lines[i] if i < len(lines) else "<missing>"
        if (kind == "lit" and got != w) or (kind == "rx" and not re.fullmatch(w, got)):
            bad.append("line %d is not the pinned form: %s" % (i + 1, got[:100]))
            break
    if len(lines) != len(want):
        bad.append("the script has %d lines, the fixed dispatcher has %d: nothing else is allowed (no swallowed failure, no extra command)" % (len(lines), len(want)))
    return bad


def graph(path):
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    def needs(n):
        v = (jobs.get(n) or {}).get("needs", [])
        return {v} if isinstance(v, str) else set(v)
    for n in ("build", "sign", "rebuild", "check", "promotion"):
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    if (jobs["check"].get("uses") or "") != "./.github/workflows/stage-verify.yml":
        bad.append("the check job must call ./.github/workflows/stage-verify.yml")
    if needs("check") != {"build", "sign"}:
        bad.append("check must need exactly build and sign, found %s" % sorted(needs("check")))
    if "check" in needs("rebuild") or "rebuild" in needs("check"):
        bad.append("check and rebuild must run side by side (rule 70)")
    if not {"build", "sign", "rebuild", "check"} <= needs("promotion"):
        bad.append("the release job must need build, sign, rebuild and check, found %s" % sorted(needs("promotion")))
    return bad


def plain(files):
    bad = []
    for f in files:
        if not os.path.exists(f):
            bad.append("missing: %s" % f); continue
        for n, l in enumerate(open(f).read().split("\n"), 1):
            m = SIGNING.search(l)
            if m:
                bad.append("%s:%d names %r: a check script knows nothing about signing, registries, secrets or tokens" % (f, n, m.group(0)))
    return bad


def listed(jsonpath, root):
    bad = []
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])}
    for s in SCRIPTS:
        r = rows.get(s)
        if r is None:
            bad.append("%s is not listed in chain-scripts.json" % s); continue
        f = os.path.join(root, s)
        if not os.path.exists(f):
            bad.append("%s is listed but missing" % s); continue
        if hashlib.sha256(open(f, "rb").read()).hexdigest() != r.get("sha256"):
            bad.append("%s: the sha256 in chain-scripts.json is not the file's" % s)
        if r.get("signs") not in (False, "false"):
            bad.append("%s must be listed with signs: false" % s)
    return bad


def records(jsonpath):
    """Rule 66: a record nobody consumes does not exist. The old custom acceptance record is gone; Check's Witness collection has a named consumer."""
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows = json.load(open(jsonpath)).get("records", [])
    bad = []
    if any(r.get("type", "").endswith("/attestations/acceptance/v1") for r in rows):
        bad.append("the old acceptance record type is still in chain-records.json")
    if not any(r.get("type") == COLLECTION and re.search(r"\bcheck\b", r.get("claim", ""), re.I) and r.get("consumer") == "release" for r in rows):
        bad.append("no row for the Witness collection naming Check in its claim with consumer release")
    return bad


def removed(root):
    bad = []
    for f in OLD_FILES:
        if os.path.exists(os.path.join(root, f)):
            bad.append("%s still exists (the custom authorization verifier is replaced by Release's verify step, rule 65)" % f)
    cp = os.path.join(root, ".github/workflows/ci.yml")
    if os.path.exists(cp) and re.search(r"authorize-acceptance-check", open(cp).read()):
        bad.append("ci.yml still runs the custom authorization verifier's test")
    for f in OLD:
        if os.path.exists(os.path.join(root, ".github/workflows", f)):
            bad.append("%s still exists" % f)
    rp = os.path.join(root, ".github/workflows/release.yml")
    if os.path.exists(rp):
        t = open(rp).read()
        for f in OLD + ["acceptance.yml"]:
            if re.search(r"uses:\s*\./\.github/workflows/" + re.escape(f), t):
                bad.append("release.yml still calls %s" % f)
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    for p in sys.argv[2:]:
        if cmd in ("stage", "script", "graph", "helper") and not os.path.exists(p):
            print("missing file: %s" % p); sys.exit(1)
        break
    fn = {"stage": lambda: stage(sys.argv[2]), "script": lambda: script(sys.argv[2]), "graph": lambda: graph(sys.argv[2]),
          "plain": lambda: plain(sys.argv[2:]), "helper": lambda: helper(sys.argv[2]), "records": lambda: records(sys.argv[2]), "listed": lambda: listed(sys.argv[2], sys.argv[3]), "removed": lambda: removed(sys.argv[2])}[cmd]
    bad = fn()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
