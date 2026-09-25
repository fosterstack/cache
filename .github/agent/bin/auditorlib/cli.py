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


# ONE adjudicator client PROCESS for the whole run (not one per finding): the real client
# constructs the anthropic SDK client once, so the federated identity token is exchanged ONCE and
# the resulting access token is reused across every finding — a fresh exchange per subprocess
# reused the same identity-token `jti` and was rejected (jti_reused). The persistent process
# speaks newline-delimited JSON: one request line in, one answer line out. It is started lazily,
# reused, and closed at end of run via close_adjudicators().
_ADJ_PROCS = {}


def _adj_proc(adjudicator):
    p = _ADJ_PROCS.get(adjudicator)
    if p is not None and p.poll() is None:
        return p
    p = subprocess.Popen([sys.executable, adjudicator, "--serve"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, bufsize=1)
    _ADJ_PROCS[adjudicator] = p
    return p


def close_adjudicators():
    """Shut the persistent adjudicator process(es) down at end of run."""
    for p in list(_ADJ_PROCS.values()):
        try:
            if p.stdin:
                p.stdin.close()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    _ADJ_PROCS.clear()


def ask_model(adjudicator, finding_id, attempt="primary", model="primary", context=None):
    """Ask the adjudicator (the model, in production; a stub/spy in tests) to propose a
    disposition for ONE finding, over the run's single persistent client process. `context`
    carries the full finding evidence so the model reasons about THIS finding. Returns the
    answer dict; raises Refused on a refusal and RuntimeError when the client reports an error
    or the process dies. The identity-token exchange happens once inside that one process."""
    req = {"finding_id": finding_id, "attempt": attempt, "model": model}
    if context:
        req.update(context)
    p = _adj_proc(adjudicator)
    out = ""
    try:
        p.stdin.write(json.dumps(req) + "\n")
        p.stdin.flush()
        out = p.stdout.readline()
    except (BrokenPipeError, ValueError):
        out = ""
    if not out:
        # the client exited without answering (e.g. SDK import failure, or a one-shot spy that
        # exits): surface its last stderr line, masked by the client. Drop the dead process.
        _ADJ_PROCS.pop(adjudicator, None)
        err = ""
        try:
            err = (p.stderr.read() or "").strip()
        except Exception:
            err = ""
        last = err.splitlines()[-1] if err else "no output"
        raise RuntimeError("adjudicator exit %s: %s" % (p.returncode if p.returncode is not None else "?", last))
    ans = json.loads(out)
    if ans.get("error"):                                     # a per-request error the client stayed alive for
        raise RuntimeError(ans["error"])
    if ans.get("refused"):
        ex = Refused(finding_id)
        ex.token_usage = int(ans.get("token_usage") or 0)   # a refusal is still billed
        raise ex
    return ans


def gh(api, *cmd):
    p = subprocess.run([sys.executable, api, *[str(c) for c in cmd]],
                       text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("gh api exit %d: %s" % (p.returncode, p.stderr.strip()))
    return p.stdout.strip()
