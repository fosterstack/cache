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
cmds, state, pending = [], None, None
for l in lines:
    s = l.strip()
    if state is None:
        if s == "```sh":
            state = "sh"
        elif s.startswith("```"):
            state = "other"
        continue
    if s == "```":
        if pending is not None:
            fail("a command ends in a line continuation")
        state = None
        continue
    if state == "other":
        continue
    if pending is not None:
        s, pending = pending + " " + s, None
    elif not s or s.startswith("#"):
        continue
    if s.endswith("\\"):
        pending = s[:-1].rstrip()
        continue
    cmds.append(s)
if state is not None:
    fail("the guide ends inside a fenced block")
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


def fill(word):
    """The marker word with the local placeholders filled (an operand is judged as the file it names in Check)."""
    return MARK.sub(lambda m: values[m.group(1)] if m.group(1) in LOCAL else m.group(0), word)


def not_local(word):
    """True for a file operand that is not a local file: a URL is not a file operand at all."""
    return bool(word) and "://" not in word and not os.path.isfile(fill(word))


def classify(segs, files):
    """("run", "") | ("registry", why) | ("no", why) for a judged command: it runs, needs a registry image, or has
    an operand that is not a local file (Release runs it with the downloaded files)."""
    registry, nonlocal_ = [], []
    for s in segs:
        if s[0] == "jq":
            continue
        flags, operands, _ = judge_mod.read_verify(s)
        nonlocal_ += [v for f, v in flags if f in ("--key", "--bundle") and not_local(v)]
        for w in operands:
            if w in IMAGE_MARKS:
                registry.append(w)
            elif not_local(w) or not w:
                nonlocal_.append(w)
    nonlocal_ += [w for w in files or [] if not_local(w)]
    if registry:
        return "registry", "it verifies the image reference %s" % ", ".join(registry)
    if nonlocal_:
        return "no", "its operand %s is not a local file" % ", ".join(nonlocal_)
    return "run", ""


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
            fail("the command `%s` uses <%s>, which the guide does not define (undefined placeholder)" % (c, u))
    segs, files, why = judge_mod.judge(c)
    if why:
        fail("the command `%s` is refused: %s (Release runs every command, listed as not-run or not, unattended)"
             % (c, why))
    for u in sorted(set(PH.findall(c))):
        if u not in LOCAL and u not in IMAGE:
            fail("the command `%s` uses <%s>, a defined placeholder that neither Check nor Release can substitute "
                 "(unsupported placeholder; unsubstituted placeholder): listed as not-run or not, it is refused"
                 % (c, u))
    kind, why = classify(segs, files)
    if c in excused:
        if kind == "run":
            fail("the cannot-run entry `%s` is runnable: a runnable command is run, never excused" % c)
        plan.append({"command": c, "run": None, "reason": excused[c]})
        continue
    if kind == "registry":
        fail("unlisted command needs a registry: `%s` (%s); Check holds the candidate as a file, so it is never run: "
             "list it exactly, with its reason, in %s" % (c, why, listpath))
    if kind != "run":
        fail("the command `%s` is not runnable on a candidate (%s) and the cannot-run list does not name it" % (c, why))
    run = c
    for u in sorted(set(PH.findall(c))):
        v = values[u]
        if not v:
            fail("Check has no value for <%s> in this run: `%s` cannot be substituted" % (u, c))
        if not SAFE.fullmatch(v) or (u == "TAG" and not TAG.fullmatch(v)):
            fail("the candidate value for <%s> is not a plain reference: %r" % (u, v))
        run = run.replace("<%s>" % u, v)
    plan.append({"command": c, "run": run, "reason": None})
with open(planpath, "w") as f:
    for p in plan:
        f.write(json.dumps(p) + "\n")
