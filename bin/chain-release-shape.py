"""Test infrastructure (not product code) for PR 4 "Release", shared by bin/chain-release-wiring-test.sh. Judges for the shape of the Release
stage file, who may hold which credential, the job graph, the one script that verifies, the plainness of the other release scripts, the
list of scripts and the Witness record. Each judge prints `ok` or the list of faults and exits 1 on a fault. The test first proves every
judge on a known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then applies it to the real repository,
which is RED until PR 4 is implemented. Finite grammars and allowlists only, no shell analysis (final PR 1 design, advisor decision b).

  stage FILE          REQ-CHAIN-007-AC1  stage-promote.yml is an ALLOWLIST: on workflow_call only, ONE job `release`, environment release,
                      permissions exactly contents/packages/id-token write, steps exactly checkout, three installs, downloads, the five
                      witnessed steps, uploads.
  credentials FILE    REQ-CHAIN-007-AC2  no env up to and including release-verify; each credential only in the steps listed in WHO.
  others ROOT         REQ-CHAIN-007-AC3  nothing outside stage-promote.yml's release job holds packages write, a credential or the environment.
  graph FILE          REQ-CHAIN-007-AC11 release.yml: promotion needs exactly build, sign, rebuild, check; no skip, no secrets, no tag.
  verify FILE         REQ-CHAIN-007-AC4  bin/release-verify.sh is `set -euo pipefail` and then EXACTLY the commands of VERIFY, in order.
  scan FILE JSON      REQ-CHAIN-007-AC6..AC10  a release script is plain: only its listed tools, no other script, no build command, no tag
                      creation, no PATH-like setting, no credential printed (text scan, comments and quotes included; it over-reports).
  listed JSON ROOT    REQ-CHAIN-007-AC10 each release script is a row of chain-scripts.json with its sha256, its tools and its signs value.
  record FILE [VAL..] REQ-CHAIN-007-AC12 no credential name or value, no JWT, no token variable in a Witness envelope (payload decoded).
  removed ROOT        REQ-CHAIN-007-AC13 the old authorization machinery is gone.
Modelled on: in-toto-witness docs/attestors/environment.md (what the environment attestor records and what a filter removes) and
docs/tutorials/artifact-policy.md:58-70 (the envelope: base64 payload); PR 3's bin/chain-check-shape.py (the same stage grammar, the same
fixtures); PR 1's chain-scripts.json rows (tools, runs, signs)."""
import base64, hashlib, json, os, re, sys, yaml

PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
STEPS = ["release-verify", "release-apks", "release-publish", "release-sign", "release-assets"]
INSTALLS = ["witness", "cosign", "crane"]
DOWN = {"witness-build", "witness-rebuild", "witness-check", "provenance", "digests", "dist", "locks", "images", "apks", "sboms"}
UP = {"release-evidence", "witness-release"}
REGISTRY = ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN")
WHO = {"release-apks": {"APK_RELEASE_SIGNING_KEY"}, "release-publish": set(REGISTRY), "release-sign": set(REGISTRY), "release-assets": {"GH_TOKEN"}}
CREDS = {"APK_RELEASE_SIGNING_KEY", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN"}
GATE = "${{ !inputs.dry-run && startsWith(github.ref, 'refs/tags/v') }}"   # the exact conjunct PR 1 puts on every non-hostile job after Sign
CHAIN_JOBS = ["build", "sign", "rebuild", "check", "promotion"]
TAGLINE = (r'\[\[ "\$\{GITHUB_REF_NAME:-\}" =~ \^v\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\(-rc\\\.\[0-9\]\+\)\?\$ \]\] \|\| '
           r'\{ echo "refused at tag: \$\{GITHUB_REF_NAME:-\} is not vX\.Y\.Z or vX\.Y\.Z-rc\.N" >&2; exit 1; \}')
VERIFY = [   # bin/release-verify.sh after `set -euo pipefail`: rule 69's order, nothing else (PROPOSED: stage-start takes --rekor-stub for provenance)
    TAGLINE,
    r'python3 bin/chain-verify\.py policy make --template \.github/policy/release-policy\.template\.json --tag "\$GITHUB_REF_NAME" --out policy\.json',
    r"python3 bin/chain-verify\.py stage-start --stage release --previous build --record witness-build/build-collection\.json --digests witness-build/digests\.json --policy policy\.json",
    r"python3 bin/chain-verify\.py stage-start --stage release --previous sign --record provenance/provenance\.json --digests witness-build/digests\.json --policy policy\.json --rekor-stub provenance/provenance\.rekor\.json",
    r"python3 bin/chain-verify\.py stage-start --stage release --previous rebuild --record witness-rebuild/rebuild-collection\.json --digests witness-build/digests\.json --policy policy\.json",
    r"python3 bin/chain-verify\.py stage-start --stage release --previous check --record witness-check/check-collection\.json --digests witness-build/digests\.json --policy policy\.json",
]
# what each release script may use; `signs` says whether it signs anything; `runs` the other scripts it may start (the chain-scripts.json row)
ROWS = {
    "bin/release-verify.sh":  {"tools": ["python3"], "signs": False, "runs": ["bin/chain-verify.py"]},
    "bin/release-apks.sh":    {"tools": ["jq", "melange", "python3", "trap"], "signs": "other", "runs": ["bin/apk-tool.py"]},
    "bin/release-publish.sh": {"tools": ["crane", "jq"], "signs": False, "runs": []},
    "bin/release-sign.sh":    {"tools": ["cosign", "jq", "python3"], "signs": "other", "runs": ["bin/vendor-provenance.py"]},
    "bin/release-assets.sh":  {"tools": ["gh"], "signs": False, "runs": []},
}
# commands a plain release script must not use unless its row lists them
DENY = ("curl wget nc ncat ssh scp rsync git docker podman buildah buildx kaniko make xargs find eval source trap sudo bash sh dash zsh "
        "python python3 perl ruby node npm yarn pnpm go apko melange cosign crane gh witness jq skopeo oras ko goreleaser tar").split()
KEYWRITE = r'printf %s "\$APK_RELEASE_SIGNING_KEY" > "\$keyfile"'   # the one place the key is written: to a private file, never printed
OLD = ["bin/authorize-acceptance-check.py", "bin/authorize-acceptance-check-test.sh"]


def load(path):
    return yaml.load(open(path), Loader=yaml.BaseLoader)


def run_of(step):
    return (step.get("run") or "").strip()


def stage(path):
    d, bad = load(path), []
    on = d.get("on") or {}
    if not (isinstance(on, dict) and set(on) == {"workflow_call"}):
        bad.append("on: must be exactly workflow_call: %s" % on)
    if set(d) - {"name", "on", "permissions", "jobs"}:
        bad.append("workflow keys not allowed: %s" % sorted(set(d) - {"name", "on", "permissions", "jobs"}))
    jobs = d.get("jobs") or {}
    if list(jobs) != ["release"]:
        return bad + ["exactly one job named release is required, found %s" % list(jobs)]
    j = jobs["release"]
    if set(j) - {"runs-on", "permissions", "steps", "name", "environment", "timeout-minutes"}:
        bad.append("job keys not allowed: %s" % sorted(set(j) - {"runs-on", "permissions", "steps", "name", "environment", "timeout-minutes"}))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("release must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("environment") != "release":
        bad.append("the job must be in the environment named release, got %r" % j.get("environment"))
    if j.get("permissions") != {"contents": "write", "packages": "write", "id-token": "write"}:
        bad.append("permissions must be exactly contents, packages and id-token write: %s" % j.get("permissions"))
    kinds = []
    for s in j.get("steps") or []:
        if set(s) - {"name", "uses", "with", "run", "env"}:
            bad.append("step keys not allowed: %s" % sorted(set(s) - {"name", "uses", "with", "run", "env"}))
        u, r = s.get("uses", ""), run_of(s)
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".")):
                bad.append("download-artifact must be digest-pinned, name in %s, an explicit path outside bin/ and .github/: %s" % (sorted(DOWN), w))
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in UP:
                bad.append("upload-artifact must be digest-pinned with a name in %s: %s" % (sorted(UP), w))
        elif u:
            bad.append("uses not allowed in the Release stage: %s" % u)
        elif r in ["./bin/install-scanner.sh " + t for t in INSTALLS]:
            kinds.append("install:" + r.split()[-1])
        elif re.fullmatch(r"bash bin/witnessed\.sh (release-[a-z]+) bin/\1\.sh", r):
            kinds.append("W:" + r.split()[2])
        else:
            bad.append("a step that is none of checkout, install, download, witnessed or upload: %r" % (r or s.get("name")))
    want = ["checkout"] + ["install:" + t for t in INSTALLS]
    ds = [i for i, k in enumerate(kinds) if k == "down"]
    ws = [k for k in kinds if k.startswith("W:")]
    ups = [i for i, k in enumerate(kinds) if k == "up"]
    if kinds[:4] != want:
        bad.append("steps must start with checkout and the installs of witness, cosign, crane: got %s" % kinds[:4])
    if not ds or ds != list(range(4, 4 + len(ds))):
        bad.append("the downloads must follow the installs directly and all come before Witness starts (rule 68)")
    if ws != ["W:" + s for s in STEPS]:
        bad.append("the witnessed steps must be exactly %s, in this order, found %s" % (STEPS, [w[2:] for w in ws]))
    last_w = max((i for i, k in enumerate(kinds) if k.startswith("W:")), default=-1)
    if any(k != "up" for k in kinds[last_w + 1:]) or not ups:
        bad.append("only uploads may follow the witnessed steps, and there must be at least one")
    text = open(path).read()
    if re.search(r"docker\s+login|build-push|buildx|goreleaser|\bgo build\b", text):
        bad.append("a registry login or a build command appears in the stage file")
    return bad


def credentials(path):
    j = (load(path).get("jobs") or {}).get("release") or {}
    bad, seen_verify = [], False
    for s in j.get("steps") or []:
        r, env = run_of(s), s.get("env")
        name = r.split()[2] if r.startswith("bash bin/witnessed.sh ") and len(r.split()) > 3 else None
        blob = yaml.dump(s)
        if not seen_verify:
            if env is not None or re.search(r"secrets\.|github\.token|GH_TOKEN|DOCKERHUB|APK_RELEASE", blob):
                bad.append("a step up to release-verify has an env or names a secret or token: %s" % (r or s.get("uses", "")))
            seen_verify = name == "release-verify"
            continue
        if name is None:
            if env is not None or re.search(r"secrets\.|github\.token", blob):
                bad.append("only the witnessed steps may carry an env or a secret: %s" % (r or s.get("uses", "")))
            continue
        want = WHO.get(name, set())
        got = set((env or {}).keys())
        if got != want:
            bad.append("%s must get exactly the credentials %s, got %s" % (name, sorted(want), sorted(got)))
        for k, v in (env or {}).items():
            ok = v == ("${{ github.token }}" if k == "GH_TOKEN" else "${{ secrets.%s }}" % k)
            if k in CREDS and not ok:
                bad.append("%s in %s must be one whole read of its own secret, got %r" % (k, name, v))
    if not seen_verify:
        bad.append("no release-verify step found")
    return bad


def others(root):
    bad = []
    wd = os.path.join(root, ".github/workflows")
    for f in sorted(os.listdir(wd)):
        if not f.endswith((".yml", ".yaml")) or f == "stage-promote.yml":
            continue
        t = open(os.path.join(wd, f)).read()
        for pat, what in ((r"DOCKERHUB_TOKEN\b|APK_RELEASE_SIGNING_KEY", "a release credential"), (r"environment:\s*release\b", "the release environment")):
            if re.search(pat, t):
                bad.append("%s names %s" % (f, what))
        if f.startswith("stage-") and re.search(r"packages:\s*write|secrets\.|secrets:\s*inherit", t):
            bad.append("%s holds packages write or a secret: only the release job may" % f)
    rp = os.path.join(wd, "release.yml")
    if os.path.exists(rp):
        d = load(rp)
        wp = d.get("permissions")
        if isinstance(wp, dict) and any(v == "write" and k in ("packages", "id-token", "contents") for k, v in wp.items()):
            bad.append("release.yml grants write at the workflow level: %s" % wp)
        for n, j in (d.get("jobs") or {}).items():
            uses = j.get("uses", "")
            if "stage-" in uses and ("secrets" in j):
                bad.append("job %s passes secrets to a stage call" % n)
            p = j.get("permissions") or {}
            if "stage-" in uses and not uses.endswith("stage-promote.yml") and isinstance(p, dict) and p.get("packages") == "write":
                bad.append("job %s grants packages write: only the promotion job may" % n)
        if re.search(r"DOCKERHUB_TOKEN\b|APK_RELEASE_SIGNING_KEY", open(rp).read()):
            bad.append("release.yml names a release credential")
    return bad


def graph(path):
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    for n in CHAIN_JOBS:
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    p = jobs["promotion"]
    needs = p.get("needs", [])
    needs = {needs} if isinstance(needs, str) else set(needs)
    if needs != {"build", "sign", "rebuild", "check"}:
        bad.append("the release job must need exactly build, sign, rebuild and check, found %s" % sorted(needs))
    if p.get("uses") != "./.github/workflows/stage-promote.yml":
        bad.append("the promotion job must call ./.github/workflows/stage-promote.yml")
    if p.get("permissions") != {"contents": "write", "packages": "write", "id-token": "write"}:
        bad.append("the promotion job's permissions must be exactly contents, packages and id-token write: %s" % p.get("permissions"))
    for n in CHAIN_JOBS:
        j = jobs[n]
        if "if" in j and str(j["if"]).strip() != GATE:
            bad.append("job %s has an if that is not the one dry-run and tag gate: %r (a skip on a failed predecessor lets release run)" % (n, j["if"]))
        if "continue-on-error" in j or "secrets" in j:
            bad.append("job %s has continue-on-error or secrets" % n)
    if re.search(r"git tag|git push|create-release|gh release create", open(path).read()):
        bad.append("release.yml creates a tag or a release: Release creates no tag")
    return bad


def verify(path):
    bad = []
    lines = [l.rstrip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if not lines or lines[0].strip() != "set -euo pipefail":
        bad.append("the script must start with set -euo pipefail")
    lines = lines[1:] if lines else []
    if len(lines) != len(VERIFY):
        bad.append("the script has %d commands, %d are required: tag, policy, build, sign, rebuild, check (rule 69's order)" % (len(lines), len(VERIFY)))
    for i, rx in enumerate(VERIFY):
        if i < len(lines) and not re.fullmatch(rx, lines[i].strip()):
            bad.append("command %d is not the pinned form: %s" % (i + 1, lines[i].strip()[:110]))
    return bad


def scan(path, jsonpath):
    if not os.path.exists(path):
        return ["missing: %s" % path]
    rel = "bin/" + os.path.basename(path)
    row = ROWS.get(rel, {"tools": [], "runs": []})
    rows = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])} if os.path.exists(jsonpath) else {}
    tools = set(rows.get(rel, row).get("tools", row["tools"]))
    runs = set(rows.get(rel, row).get("runs", row["runs"]))
    text, bad = open(path).read(), []
    for n, l in enumerate(text.split("\n"), 1):
        if n == 1 and l.startswith("#!"):
            continue
        bare = re.sub(r"\b(docker\.io|ghcr\.io)\b|\bpolicy make\b", " ", l)   # registry host names and the one subcommand are not commands
        for w in DENY:
            if w not in tools and re.search(r"(?<![\w./$-])" + re.escape(w) + r"(?![\w-])", bare):
                bad.append("%s:%d uses %r which the row does not list" % (os.path.basename(path), n, w))
        for m in re.finditer(r"(?<![\w.$-])((?:\./)?(?:[\w.-]+/)+[\w.-]+\.(?:sh|py))\b", l):
            p = m.group(1).lstrip("./")
            if p != rel and p not in runs:
                bad.append("%s:%d starts another script: %s" % (os.path.basename(path), n, p))
        if re.search(r"\b(PATH|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*|NODE_OPTIONS)=", l):
            bad.append("%s:%d sets a PATH-like variable" % (os.path.basename(path), n))
        if re.search(r"\bset\s+-\w*x|xtrace", l):
            bad.append("%s:%d turns on tracing (it would print credentials)" % (os.path.basename(path), n))
        if re.search(r"\b(echo|printf|cat|tee)\b[^;&|]*\$\{?(%s)\b" % "|".join(sorted(CREDS)), l) and not re.fullmatch(KEYWRITE, l.strip()):
            bad.append("%s:%d prints a credential" % (os.path.basename(path), n))
        if re.search(r"melange\s+build|apko\s+build|go\s+build|docker\s+build|buildx", l):
            bad.append("%s:%d is a build command: Release builds nothing" % (os.path.basename(path), n))
        if re.search(r"git\s+(tag|push)|git/(refs|tags)", l) or (re.search(r"gh\s+release\s+create", l) and "--verify-tag" not in l):
            bad.append("%s:%d creates a tag (a release only with --verify-tag)" % (os.path.basename(path), n))
        if re.search(r"tlog-upload=false|--insecure-ignore-tlog|--skip-confirmation=false", l):
            bad.append("%s:%d turns the transparency log off" % (os.path.basename(path), n))
    return bad


def listed(jsonpath, root):
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows, bad = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])}, []
    for p, want in list(ROWS.items()) + [("bin/witnessed.sh", None)]:
        r = rows.get(p)
        if r is None:
            bad.append("%s is not listed in chain-scripts.json" % p); continue
        f = os.path.join(root, p)
        if not os.path.exists(f):
            bad.append("%s is listed but missing" % p); continue
        if hashlib.sha256(open(f, "rb").read()).hexdigest() != r.get("sha256"):
            bad.append("%s: the sha256 in chain-scripts.json is not the file's" % p)
        if want is None:
            continue
        if sorted(r.get("tools", [])) != sorted(want["tools"]):
            bad.append("%s must list exactly the tools %s, lists %s" % (p, want["tools"], r.get("tools")))
        if r.get("signs") != want["signs"]:
            bad.append("%s must be listed with signs: %s, is %r" % (p, want["signs"], r.get("signs")))
        if want["signs"] == "other" and not r.get("reason"):
            bad.append("%s signs and must carry a reason" % p)
        if sorted(r.get("runs", [])) != sorted(want["runs"]):
            bad.append("%s may start exactly %s, lists %s" % (p, want["runs"], r.get("runs")))
    return bad


def record(path, values):
    bad, raw = [], open(path).read()
    try:
        env = json.loads(raw)
        payload = base64.b64decode(env["payload"]).decode("utf8")
        json.loads(payload)
        text = raw + "\n" + payload
    except Exception:
        return ["not a DSSE envelope with a base64 payload"]
    for n in sorted(CREDS | {"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN"}):
        if n in text:
            bad.append("the record names %s" % n)
    for v in values:
        if v and v in text:
            bad.append("the record holds a credential value")
    if re.search(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*", text):
        bad.append("the record holds a compact JWT")
    return bad


def removed(root):
    bad = [f"{f} still exists" for f in OLD if os.path.exists(os.path.join(root, f))]
    pp = os.path.join(root, ".github/workflows/stage-promote.yml")
    if os.path.exists(pp) and re.search(r"release-authori[sz]ation|authorize-acceptance-check", open(pp).read()):
        bad.append("stage-promote.yml still reads or writes a release-authorization predicate")
    rp = os.path.join(root, ".github/workflows/release.yml")
    if os.path.exists(rp) and "authorization" in (load(rp).get("jobs") or {}):
        bad.append("release.yml still has an authorization job")
    return bad


if __name__ == "__main__":
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd in ("stage", "credentials", "graph", "verify") and not os.path.exists(a[0]):
        print("missing file: %s" % a[0]); sys.exit(1)
    fn = {"stage": lambda: stage(a[0]), "credentials": lambda: credentials(a[0]), "others": lambda: others(a[0]),
          "graph": lambda: graph(a[0]), "verify": lambda: verify(a[0]), "scan": lambda: scan(a[0], a[1]),
          "listed": lambda: listed(a[0], a[1]), "record": lambda: record(a[0], a[1:]), "removed": lambda: removed(a[0])}[cmd]
    bad = fn()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
