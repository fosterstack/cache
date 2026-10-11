#!/usr/bin/env bash
# bin/check-guide.sh --guide FILE --digests FILE --images DIR --out DIR
# Runs every command of the customer guide (rule 78) against the candidate, word for word (v0.3.0 rule 79; REQ-CHAIN-006-AC7).
# The guide's format (cache-3f's): every command is a line of a ```sh fenced block (a line ending in a backslash joins the next; lines
# starting with # are comments; other fenced blocks are prose), unattended, in customer order, at most ten in all. Placeholders are
# ALL-CAPS in angle brackets, each defined once in a list line before the first fence, as  - `<NAME>`: what it is. Check knows
# <IMAGE_REF> and <IMAGE_REF_FIPS> ($CANDIDATE_REPOSITORY@ the image-production / image-fips digest of the digest list), <TAG>
# ($GITHUB_REF_NAME) and <IDENTITY> (https://github.com/$GITHUB_REPOSITORY/.github/workflows/stage-sign.yml@$GITHUB_REF, Sign's
# keyless identity).
# A command RUNS only when it is a pipeline of the verify forms (cosign verify, cosign verify-attestation, cosign verify-blob,
# cosign verify-blob-attestation, gh attestation verify) and jq, with no other shell syntax ($ only inside single quotes), and every
# operand is a local file or a placeholder Check fills with a local value; a runnable command that exits non-zero fails the check.
# A verify command whose subject is an image reference (<IMAGE_REF>, <IMAGE_REF_FIPS>, a literal reference with a path and : or @, or
# oci://) needs a registry, which Check does not have (it holds the candidate as a file): it is NEVER run. It, and any other command the
# check cannot run, must be listed exactly, with its reason, in the cannot-run list beside the guide (GUIDE minus .md, plus
# .cannot-run.json: [{"command", "reason"}]); a listed command is not run and is recorded as not-run, else the check fails closed.
# Rule 79 (amended by the owner, Oct 10): a listed command is not run here; Release runs it right after publishing (its post-publish
# verification reads the same list) and fails the release run if it fails. So a listed entry is reported as not-run (exit 0) and AC7
# counts it covered; the list must be exact: a verify form, in the guide, once, with a reason. Writes OUT/guide-results.json.
set -euo pipefail
usage() { echo "usage: check-guide.sh --guide FILE --digests FILE --images DIR --out DIR" >&2; exit 2; }
fail() { echo "check-guide: $*" >&2; exit 1; }
guide="" digests="" images="" out=""
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || usage
  case "$1" in
    --guide) guide=$2 ;;
    --digests) digests=$2 ;;
    --images) images=$2 ;;
    --out) out=$2 ;;
    *) usage ;;
  esac
  shift 2
done
[ -n "$guide" ] && [ -n "$digests" ] && [ -n "$images" ] && [ -n "$out" ] || usage
[ -f "$guide" ] || fail "the guide $guide does not exist"
[ -d "$images" ] || fail "the image directory $images does not exist"
[ -f "$digests" ] || fail "the digest list $digests does not exist"
d=$(jq -r '."image-production" // empty' "$digests")
[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-production digest"
df=$(jq -r '."image-fips" // empty' "$digests")
[[ "$df" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "the digest list has no image-fips digest"
mkdir -p "$out"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# Read the guide and the cannot-run list, judge every command, substitute the candidate's values: one plan row per command, in order.
python3 -I - "$guide" "${guide%.md}.cannot-run.json" "$d" "$tmp/plan.jsonl" "$df" <<'PY'
import json, os, re, shlex, sys
guide, listpath, digest, planpath, digest_fips = sys.argv[1:6]
def fail(m):
    print("check-guide: " + m, file=sys.stderr); sys.exit(1)
lines = open(guide).read().replace("\r", "").split("\n")
PH = re.compile(r"<([A-Z][A-Z0-9_]*)>")
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

FORMS2 = ("cosign verify", "cosign verify-attestation", "cosign verify-blob", "cosign verify-blob-attestation")
FORMS3 = ("gh attestation verify",)
# The flags of the verify forms that take a value (an unknown flag is taken as taking none, so its next word is judged as an operand:
# the safe direction, a command the check cannot place is not run).
VALUE_FLAGS = {"--certificate-identity", "--certificate-identity-regexp", "--certificate-oidc-issuer", "--certificate-oidc-issuer-regexp",
               "--type", "--key", "--bundle", "--signature", "--certificate", "--certificate-chain", "--trusted-root", "--output", "-o",
               "--owner", "--repo", "-R", "--predicate-type", "--signer-workflow", "--signer-repo", "--cert-identity",
               "--cert-identity-regex", "--cert-oidc-issuer", "--source-ref", "--source-digest", "--digest-alg", "--format", "--jq", "-q",
               "--template", "-t", "--hostname", "--custom-trusted-root", "--signer-digest"}
JQ_TWO = {"--arg", "--argjson", "--slurpfile", "--rawfile"}
LOCAL = {"TAG", "IDENTITY"}     # placeholders Check fills with a local value
IMAGE = {"IMAGE_REF", "IMAGE_REF_FIPS"}


def image_ref(word):
    """An image reference: an image placeholder, oci://..., or a literal with a path and a tag or digest (no URL scheme)."""
    if any(p in IMAGE for p in PH.findall(word)) or word.startswith("oci://"):
        return True
    w = PH.sub("X", word)
    return "://" not in w and "/" in w and (":" in w or "@" in w)


def classify(c):
    """("run", "") | ("registry", why) | ("no", why): the command runs, needs a registry, or cannot run on a candidate."""
    if "`" in c:
        return "no", "shell syntax: a backquote"
    quote = None
    for ch in c:
        if quote:
            if ch == quote:
                quote = None
            elif ch == "$" and quote == '"':
                return "no", "shell syntax: an expansion ($) inside double quotes"
        elif ch in "'\"":
            quote = ch
        elif ch == "$":
            return "no", "shell syntax: an expansion ($) outside single quotes"
    lx = shlex.shlex(PH.sub(lambda m: "PH_" + m.group(1), c), posix=True, punctuation_chars=True)
    lx.whitespace_split = True
    try:
        toks = [PH_BACK.sub(lambda m: "<%s>" % m.group(1), w) for w in lx]
    except ValueError as e:
        return "no", "unparseable: %s" % e
    segs = [[]]
    for w in toks:
        if w == "|":
            segs.append([])
        elif w and all(ch in "();<>|&" for ch in w):
            return "no", "shell syntax other than a pipe: %s" % w
        else:
            segs[-1].append(w)
    registry, nonlocal_ = [], []
    for s in segs:
        if not s:
            return "no", "shell syntax: an empty pipe segment"
        if s[0] == "jq":
            words, i, filt = s[1:], 0, False
            while i < len(words):
                w = words[i]
                if w in JQ_TWO:
                    i += 3; continue
                if w.startswith("-"):
                    i += 1; continue
                if not filt:
                    filt = True
                elif not os.path.isfile(fill(w)):
                    nonlocal_.append(w)
                i += 1
            continue
        if " ".join(s[:2]) in FORMS2:
            words = s[2:]
        elif " ".join(s[:3]) in FORMS3:
            words = s[3:]
        else:
            return "no", "`%s` is not one of the verify forms or jq" % " ".join(s[:3])
        i = 0
        while i < len(words):
            w = words[i]
            if w.startswith("-"):
                i += 2 if ("=" not in w and w in VALUE_FLAGS) else 1
                continue
            if image_ref(w):
                registry.append(w)
            elif not os.path.isfile(fill(w)):
                nonlocal_.append(w)
            i += 1
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
        if not (isinstance(r, dict) and set(r) == {"command", "reason"} and isinstance(r["command"], str) and isinstance(r["reason"], str)
                and r["command"].strip() and r["reason"].strip()):
            fail("a cannot-run entry must be exactly {command, reason}, both non-empty: %r" % (r,))
        if r["command"] in excused:
            fail("the cannot-run list names `%s` twice" % r["command"])
        excused[r["command"]] = r["reason"]
def verify_form(c):
    """Every pipe segment is a verify form or jq (what Release's post-publish step runs from this list)."""
    return all(s.strip().startswith(FORMS2 + FORMS3 + ("jq ",)) for s in c.split("|"))
for c in excused:
    if not verify_form(c):
        fail("the cannot-run entry `%s` is not a verify form (Release runs only the verify forms from this list)" % c)
    if c not in cmds:
        fail("the cannot-run entry `%s` is not in the guide (a stale list)" % c)

PH_BACK = re.compile(r"PH_([A-Z][A-Z0-9_]*)")
repo = os.environ.get("CANDIDATE_REPOSITORY", "")
gh_repo, gh_ref = os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_REF", "")
values = {"IMAGE_REF": repo + "@" + digest if repo else "", "IMAGE_REF_FIPS": repo + "@" + digest_fips if repo else "",
          "TAG": os.environ.get("GITHUB_REF_NAME", ""),
          "IDENTITY": "https://github.com/%s/.github/workflows/stage-sign.yml@%s" % (gh_repo, gh_ref) if gh_repo and gh_ref else ""}
SAFE = re.compile(r"^[A-Za-z0-9._:/@+-]+$")


def fill(word):
    """The word with the local placeholders filled (an operand is judged as the file it names in Check)."""
    return PH.sub(lambda m: values.get(m.group(1), m.group(0)) if m.group(1) in LOCAL else m.group(0), word)
plan = []
for c in cmds:
    for u in PH.findall(c):
        if u not in defined:
            fail("the command `%s` uses <%s>, which the guide does not define (undefined placeholder)" % (c, u))
    kind, why = classify(c)
    if c in excused:
        if kind == "run":
            fail("the cannot-run entry `%s` is runnable: a runnable command is run, never excused" % c)
        plan.append({"command": c, "run": None, "reason": excused[c]})
        continue
    if kind == "registry":
        fail("unlisted command needs a registry: `%s` (%s); Check holds the candidate as a file, so it is never run: list it exactly, "
             "with its reason, in %s" % (c, why, listpath))
    if kind != "run":
        fail("the command `%s` is not runnable on a candidate (%s) and the cannot-run list does not name it" % (c, why))
    run = c
    for u in sorted(set(PH.findall(c))):
        if u not in values:
            fail("the command `%s` keeps <%s>: Check has no candidate value for it (unsubstituted placeholder)" % (c, u))
        v = values[u]
        if not v:
            if u == "IMAGE_REF":
                fail("Check has no registry reference for the candidate (CANDIDATE_REPOSITORY is not set): <IMAGE_REF> in `%s` cannot be substituted" % c)
            fail("Check has no value for <%s> in this run: `%s` cannot be substituted" % (u, c))
        if not SAFE.match(v):
            fail("the candidate value for <%s> is not a plain reference: %r" % (u, v))
        run = run.replace("<%s>" % u, v)
    if PH.search(run):
        fail("the command `%s` keeps a placeholder after substitution (unsubstituted placeholder)" % c)
    plan.append({"command": c, "run": run, "reason": None})
with open(planpath, "w") as f:
    for p in plan:
        f.write(json.dumps(p) + "\n")
PY

failed=0 n=0
: > "$tmp/results.jsonl"
while IFS= read -r row; do
  n=$((n + 1))
  cmd=$(jq -r .command <<< "$row"); run=$(jq -r '.run // empty' <<< "$row")
  if [ -z "$run" ]; then
    reason=$(jq -r .reason <<< "$row")
    echo "check-guide: NOT RUN (cannot run on a candidate: $reason): $cmd -- run right after publishing, in Release's post-publish verification"
    jq -cn --arg c "$cmd" --arg r "$reason" '{command: $c, exit: null, outcome: "not-run", reason: $r}' >> "$tmp/results.jsonl"
    continue
  fi
  echo "check-guide: \$ $run"
  rc=0; bash -o pipefail -c "$run" < /dev/null || rc=$?
  outcome=pass
  if [ "$rc" != 0 ]; then
    outcome=fail; failed=1; echo "check-guide: the guide command \`$cmd\` exited $rc against the candidate" >&2
  fi
  jq -cn --arg c "$cmd" --arg r "$run" --argjson e "$rc" --arg o "$outcome" '{command: $c, ran: $r, exit: $e, outcome: $o}' >> "$tmp/results.jsonl"
done < "$tmp/plan.jsonl"
jq -s --arg g "$guide" --arg d "$d" '{guide: $g, candidate: $d, commands: .}' "$tmp/results.jsonl" > "$out/guide-results.json"
[ "$failed" = 0 ] || exit 1
echo "check-guide: all $n guide commands passed or are listed as not runnable on a candidate"
