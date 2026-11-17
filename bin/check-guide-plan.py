"""bin/check-guide-plan.py GUIDE CANNOT_RUN_LIST DIGEST PLAN DIGEST_FIPS: the planner of bin/check-guide.sh
(REQ-CHAIN-006-AC7). Reads the customer guide and its cannot-run list, judges every command with
bin/guide_plan_judge.py (the judge Release uses), substitutes the candidate's values and writes one plan row per
command, in order, to PLAN; any fault exits 1."""
import json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import guide_plan_judge as judge_mod   # noqa: E402
from guide_plan_judge import IMAGE_MARKS, MARK, PH   # noqa: E402


def fail(m):
    print("check-guide: " + m, file=sys.stderr); sys.exit(1)


if len(sys.argv) != 6:
    fail("usage: check-guide-plan.py GUIDE CANNOT_RUN_LIST DIGEST PLAN DIGEST_FIPS")
guide, listpath, digest, planpath, digest_fips = sys.argv[1:6]
lines = open(guide).read().replace("\r", "").split("\n")
DEF = re.compile(r"^\s*[-*]\s+`?<([A-Z][A-Z0-9_]*)>`?\s*:")
first = next((i for i, l in enumerate(lines) if l.strip().startswith("```")), len(lines))
defined = set()
for l in lines[:first]:
    m = DEF.match(l)
    if m:
        if m.group(1) in defined:
            fail("the placeholder <%s> is defined twice" % m.group(1))
        defined.add(m.group(1))
cmds, why = judge_mod.guide_commands(lines)
if why:
    fail(why)
if not cmds:
    fail("no command was extracted from the guide %s (a vacuous pass is not a pass)" % guide)
if len(cmds) > 10:
    fail("the guide has %d commands; at most ten are allowed" % len(cmds))

LOCAL = {"TAG"}     # the placeholder Check fills with a local value
IMAGE = {"IMAGE_REF", "IMAGE_REF_FIPS"}
repo = os.environ.get("CANDIDATE_REPOSITORY", "")
values = {"IMAGE_REF": repo + "@" + digest if repo else "", "IMAGE_REF_FIPS": repo + "@" + digest_fips if repo else "",
          "TAG": os.environ.get("GITHUB_REF_NAME", "")}
# a filled value is one plain word: ghcr.io/fosterstack/cache@sha256:ab12 yes; "a b" and "$(id)" and "v1\n" no
SAFE = re.compile(r"[A-Za-z0-9._:/@+-]+")
# a tag: v0.3.0 and v0.3.0-rc1 yes; v0.3.0-rc.1 and v0.3.0-rc no
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?")


KEY = "release.rsa.pub"
KEY_PATH = "build/keys/" + KEY       # Check takes the release key from the tagged checkout, no new download
PROVENANCE = "provenance.bundle.json"   # Sign's output: release-apks verifies it before anything is published
# the four files release-sign makes after publishing: their commands run in postverify, which fails the run on a missing operand
AFTER_PUBLISH = {"production.sbom.json", "fips.sbom.json", "production.full.lock.json", "fips.full.lock.json"}


def fill(word):
    """The marker word with the local placeholders filled and the release key taken from build/keys/ (an operand is judged
    as the file it names in Check)."""
    word = KEY_PATH if word == KEY else word
    return MARK.sub(lambda m: values[m.group(1)] if m.group(1) in LOCAL else m.group(0), word)


def not_local(word):
    """True for a file operand that is not a local file: a URL is not a file operand at all."""
    return bool(word) and "://" not in word and not os.path.isfile(fill(word))


def file_words(segs, files):
    """Every file a judged command names: its --key and --bundle values, its verify operands and the files a jq reads, and the image marks."""
    names, registry = [], []
    for s in segs:
        if s[0] == "jq":
            continue
        flags, operands, _ = judge_mod.read_verify(s)
        names += [v for f, v in flags if f in ("--key", "--bundle")]
        for w in operands:
            (registry if w in IMAGE_MARKS else names).append(w)
    return names + list(files or []), registry


def after_publish(segs):
    """True for one verify-blob of a file in AFTER_PUBLISH against its own .bundle: the pair is named whole, so a lookalike is not one."""
    if len(segs) != 1:
        return False
    flags, operands, _ = judge_mod.read_verify(segs[0])
    bundles = [v for f, v in flags if f == "--bundle"]
    return len(bundles) == 1 and len(operands) == 1 and operands[0] in AFTER_PUBLISH and bundles[0] == operands[0] + ".bundle"


def classify(c, segs, files):
    """(place, why): "registry" for a command that needs a registry, else the place that runs it: "check", "release-apks" or "postverify".
    The commands on provenance.bundle.json, which Check does not hold, run in release-apks, and the four SBOM and lock verifications run in postverify;
    every other command runs here, so a file it names that is not a local file is a fault, never a later check."""
    names, registry = file_words(segs, files)
    if registry:
        return "registry", "it verifies the image reference %s" % ", ".join(registry)
    if PROVENANCE in names and not_local(PROVENANCE):
        return "release-apks", "its file %s is Sign's output, release-apks runs it before the first push" % PROVENANCE
    if after_publish(segs):
        return "postverify", "its files are made by release-sign after publishing"
    missing = [w for w in names if not w or not_local(w)]
    if missing:
        fail("the operand %s of the guide command `%s` is not a local file at Check, and no later stage is named for it"
             % (", ".join(sorted(set(missing))) or "(empty)", c))
    return "check", ""


excused = {}
if os.path.exists(listpath):
    try:
        rows = json.load(open(listpath))
    except ValueError as e:
        fail("the cannot-run list %s is not JSON: %s" % (listpath, e))
    if not isinstance(rows, list):
        fail("the cannot-run list %s is not a list" % listpath)
    for r in rows:
        if not (isinstance(r, dict) and set(r) == {"command", "reason"} and isinstance(r["command"], str)
                and isinstance(r["reason"], str) and r["command"].strip() and r["reason"].strip()):
            fail("a cannot-run entry must be exactly {command, reason}, both non-empty: %r" % (r,))
        if r["command"] in excused:
            fail("the cannot-run list names `%s` twice" % r["command"])
        excused[r["command"]] = r["reason"]
for c in excused:
    if c not in cmds:
        fail("the cannot-run entry `%s` is not in the guide (a stale list)" % c)

plan = []
for c in cmds:
    for u in PH.findall(c):
        if u not in defined:
            fail("the command `%s` is refused: it uses <%s>, which the guide does not define (undefined placeholder)" % (c, u))
    segs, files, why = judge_mod.judge(c)
    if why:
        fail("the command `%s` is refused: %s (Release runs every command, listed as not-run or not, unattended)"
             % (c, why))
    for u in sorted(set(PH.findall(c))):
        if u not in LOCAL and u not in IMAGE:
            fail("the command `%s` uses <%s>, a defined placeholder that neither Check nor Release can substitute "
                 "(unsupported placeholder; unsubstituted placeholder): listed as not-run or not, it is refused"
                 % (c, u))
    kind, why = classify(c, segs, files)
    if c in excused:
        if kind != "registry":
            fail("the cannot-run entry `%s` is not an image-reference command: a file command is run at its place "
                 "(%s); only an image-reference command is listed" % (c, kind))
        plan.append({"command": c, "run": None, "place": "postverify", "reason": excused[c]})
        continue
    if kind == "registry":
        fail("unlisted command needs a registry: `%s` (%s); Check holds the candidate as a file, so it is never run: "
             "list it exactly, with its reason, in %s" % (c, why, listpath))
    if kind != "check":
        plan.append({"command": c, "run": None, "place": kind, "reason": "run by %s: %s" % (kind, why)})
        continue
    run = c
    for u in sorted(set(PH.findall(c))):
        v = values[u]
        if not v:
            fail("Check has no value for <%s> in this run: `%s` cannot be substituted" % (u, c))
        if not SAFE.fullmatch(v) or (u == "TAG" and not TAG.fullmatch(v)):
            fail("the candidate value for <%s> is not a plain reference: %r" % (u, v))
        run = run.replace("<%s>" % u, v)
    run = re.sub(r"(?<![\w./-])%s(?![\w.-])" % re.escape(KEY), KEY_PATH, run)
    plan.append({"command": c, "run": run, "place": "check", "reason": None})
with open(planpath, "w") as f:
    for p in plan:
        f.write(json.dumps(p) + "\n")
