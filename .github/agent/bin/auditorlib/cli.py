"""Command helpers: arg parsing, effect writing, adjudicator + fake-GitHub calls."""
import json, os, subprocess, sys

ARGS = sys.argv[1:]


def opt(k, default=None):
    return ARGS[ARGS.index(k) + 1] if k in ARGS else default


def flag(k):
    return k in ARGS


def positional(i):
    ps = [a for a in ARGS if not a.startswith("--")]
    return ps[i] if i < len(ps) else None


def writej(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    json.dump(obj, open(path, "w"), indent=1)


def writef(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w").write(text)


class Refused(Exception):
    pass


def ask_model(adjudicator, finding_id, attempt="primary", model="primary"):
    """Invoke the adjudicator (the model, in production; a stub/spy in tests). The
    caller uses this ONLY on a log miss. Returns the answer dict; raises Refused on
    a refusal and CalledProcessError-equivalent on a nonzero exit."""
    p = subprocess.run([sys.executable, adjudicator],
                       input=json.dumps({"finding_id": finding_id, "attempt": attempt, "model": model}),
                       text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("adjudicator exit %d: %s" % (p.returncode, p.stderr.strip()))
    ans = json.loads(p.stdout)
    if ans.get("refused"):
        raise Refused(finding_id)
    return ans


def gh(api, *cmd):
    p = subprocess.run([sys.executable, api, *[str(c) for c in cmd]],
                       text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("gh api exit %d: %s" % (p.returncode, p.stderr.strip()))
    return p.stdout.strip()
