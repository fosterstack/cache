#!/usr/bin/env python3
"""Dependabot major-bump reviewer (register row 75).

Three dependency lanes: the auditor opens CVE bumps (cron), Dependabot opens "latest" bumps,
and THIS reviewer judges Dependabot MAJORS so no human has to. It runs hourly from main
(dependabot-reviewer.yml), never on a PR event: Dependabot-triggered runs hold no repository
secrets, so the federation identity is only reachable from a scheduled run on main.

Subcommands (each one is small and testable on its own; the workflow strings them together):

  updates  --title T --body-file F           -> JSON list of {name, from, to, major}
  gather   --pr N --updates F --out DIR       -> DIR/bundle.md (diff + release notes + our usage)
  read     --bundle F --prompt F --model-env NAME --out F
                                              -> one reader's ranked findings (JSON)
  decide   --reader F [--reader F ...] --out F
                                              -> {"decision": "merge"|"hold"|"error", ...}

The DECISION is mechanical (row 75 d): zero `breaks-us` findings from every reader => merge;
any `breaks-us` => hold; a reader that failed or answered unparseably => error (no check is
posted; the next hourly run retries). Readers return RANKED FINDINGS, never a verdict
(row 51). No vendor or model name appears in any output (row 48): model ids are masked.
"""
import argparse, json, os, re, subprocess, sys

SEVERITIES = ("breaks-us", "check", "noise")
CAP_DIFF, CAP_NOTES, CAP_USAGE = 20000, 60000, 20000

_SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                "AUDITOR_MODEL_PRIMARY", "AUDITOR_MODEL_FALLBACK", "AUDITOR_APP_PRIVATE_KEY")


def mask(s):
    """Redact identifiers/model ids from anything that could reach a public surface."""
    s = str(s or "")
    for k in _SECRET_ENVS:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            s = s.replace(v, "<%s>" % k)
    s = re.sub(r"claude-[A-Za-z0-9._-]+", "<model-id>", s)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]{6,}", "Bearer <redacted>", s)
    return s


# ----------------------------------------------------------------------------- updates

_VER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_BUMPS = re.compile(r"(?:Bumps?|Updates)\s+\[?`?([A-Za-z0-9._/@-]+)`?\]?(?:\([^)]*\))?\s+from\s+`?([^\s`]+)`?\s+to\s+`?([^\s`.]+(?:\.[^\s`.]+)*?)`?\.?(?:\s|$)")


def _major(v):
    m = _VER.match(str(v).strip())
    return int(m.group(1)) if m else None


def is_major(old, new):
    """True when both look like versions and the major differs. Digests (`abc123`) and
    anything unparseable are NOT majors: they stay on the patch/minor lane, which is what
    Dependabot's own metadata action does for docker digest bumps."""
    a, b = _major(old), _major(new)
    return a is not None and b is not None and a != b


def parse_updates(title, body):
    """Every (name, from, to) Dependabot names in the PR body ("Bumps X from A to B." or, for a
    group, one "Updates `X` from A to B" line per member), falling back to the title."""
    found, seen = [], set()
    for src in (body or "", title or ""):
        for m in _BUMPS.finditer(src):
            name, old, new = m.group(1), m.group(2), m.group(3).rstrip(".")
            key = (name, old, new)
            if key in seen:
                continue
            seen.add(key)
            found.append({"name": name, "from": old, "to": new, "major": is_major(old, new)})
        if found:
            break
    return found


def cmd_updates(a):
    body = open(a.body_file).read() if a.body_file else ""
    json.dump(parse_updates(a.title, body), sys.stdout)


# ----------------------------------------------------------------------------- gather

def _run(cmd, cap=None):
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout if p.returncode == 0 else ""
    if cap and len(out) > cap:
        out = out[:cap] + "\n[... truncated at %d characters ...]\n" % cap
    return out, p.returncode


def _gh_json(args):
    out, rc = _run(["gh", "api"] + args)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _vertuple(v):
    m = _VER.match(str(v).strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None


def _upstream_repo(name):
    """The GitHub repo that publishes release notes for a dependency, or None.
    github-actions: `actions/checkout`, `github/codeql-action/init` -> owner/repo (first two
    segments). gomod: `github.com/x/y/v2` -> x/y. Anything else: no notes available."""
    parts = name.split("/")
    if name.startswith("github.com/") and len(parts) >= 3:
        return "%s/%s" % (parts[1], parts[2])
    if "." not in parts[0] and len(parts) >= 2:
        return "%s/%s" % (parts[0], parts[1])
    return None


def release_notes(name, old, new):
    """Upstream release notes for every release strictly after `old` and up to `new`,
    oldest first; a plain statement when none are available (never a guess)."""
    repo = _upstream_repo(name)
    if not repo:
        return "(no upstream release notes available for %s: not a GitHub-hosted dependency)\n" % name
    lo, hi = _vertuple(old), _vertuple(new)
    rels = []
    for page in (1, 2, 3):
        chunk = _gh_json(["repos/%s/releases?per_page=100&page=%d" % (repo, page)])
        if not chunk:
            break
        rels.extend(chunk)
        if len(chunk) < 100:
            break
    picked = []
    for r in rels:
        t = _vertuple(r.get("tag_name", ""))
        if t and lo and hi and lo < t <= hi:
            picked.append((t, r))
    if not picked:
        return ("(no upstream release notes found for %s between %s and %s on %s; "
                "the reader must say so and judge from the diff and our usage only)\n" % (name, old, new, repo))
    picked.sort(key=lambda x: x[0])
    out = []
    for _t, r in picked:
        out.append("### %s — %s\n\n%s\n" % (r.get("tag_name"), r.get("name") or "", (r.get("body") or "").strip()))
    text = "\n".join(out)
    if len(text) > CAP_NOTES:
        text = text[:CAP_NOTES] + "\n[... release notes truncated at %d characters ...]\n" % CAP_NOTES
    return text


def our_usage(name):
    """Every line of ours that names the dependency (workflows, go.mod, Dockerfiles, scripts)."""
    short = name.split("/")
    out, _rc = _run(["git", "grep", "-n", "-I", "--", name], cap=CAP_USAGE)
    if not out and len(short) >= 2 and "." not in short[0]:
        out, _rc = _run(["git", "grep", "-n", "-I", "--", "%s/%s" % (short[0], short[1])], cap=CAP_USAGE)
    return out or "(no line in this repository names %s)\n" % name


def cmd_gather(a):
    updates = json.load(open(a.updates))
    os.makedirs(a.out, exist_ok=True)
    diff, _rc = _run(["gh", "pr", "diff", str(a.pr)], cap=CAP_DIFF)
    parts = ["# Bundle for Dependabot PR #%s\n" % a.pr,
             "## Updates in this PR\n",
             "\n".join("- %s: %s -> %s (%s)" % (u["name"], u["from"], u["to"], "MAJOR" if u["major"] else "not major")
                       for u in updates) + "\n",
             "## The PR diff\n\n```diff\n%s```\n" % (diff or "(empty diff)\n")]
    for u in updates:
        if not u["major"]:
            continue
        parts.append("## Upstream release notes: %s %s -> %s\n\n%s" % (u["name"], u["from"], u["to"],
                                                                        release_notes(u["name"], u["from"], u["to"])))
        parts.append("## Every line of ours that uses %s\n\n```\n%s```\n" % (u["name"], our_usage(u["name"])))
    text = "\n".join(parts)
    open(os.path.join(a.out, "bundle.md"), "w").write(text)
    print("bundle: %d characters, %d update(s), %d major" % (len(text), len(updates), sum(1 for u in updates if u["major"])))


# ----------------------------------------------------------------------------- read

def _extract_json(text):
    s = str(text or "")
    dec = json.JSONDecoder()
    i = s.find("{")
    while i != -1:
        try:
            obj, _end = dec.raw_decode(s[i:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        i = s.find("{", i + 1)
    return None


def normalize_findings(obj):
    """A reader's answer, validated: a list of findings each with a known severity. Returns
    (findings, error). Unknown severity or a missing list is an ERROR, never a pass."""
    if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
        return None, "answer has no findings list"
    out = []
    for f in obj["findings"]:
        if not isinstance(f, dict):
            return None, "finding is not an object"
        sev = str(f.get("severity", "")).strip().lower()
        if sev not in SEVERITIES:
            return None, "unknown severity %r" % sev
        out.append({"severity": sev,
                    "title": mask(f.get("title", ""))[:200],
                    "release_note": mask(f.get("release_note", ""))[:1000],
                    "our_line": mask(f.get("our_line", ""))[:300],
                    "why": mask(f.get("why", ""))[:1000]})
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda f: rank[f["severity"]])
    return out, None


def cmd_read(a):
    bundle = open(a.bundle).read()
    prompt = open(a.prompt).read().replace("{bundle}", bundle)
    model = os.environ.get(a.model_env)
    result = {"reader": a.model_env, "findings": None, "error": None, "raw": None}
    if not model:
        result["error"] = "no model configured in %s" % a.model_env
    else:
        try:
            import anthropic  # the SDK exchanges the federated identity token for a scoped access token
            client = anthropic.Anthropic()
            msg = client.messages.create(model=model, max_tokens=2048,
                                         messages=[{"role": "user", "content": prompt}])
            text = "".join(getattr(b, "text", "") for b in msg.content)
            result["raw"] = mask(text)
            findings, err = normalize_findings(_extract_json(text))
            result["findings"], result["error"] = findings, err
        except Exception as e:  # federation, network, SDK — all "error", never a pass
            status = getattr(e, "status_code", None) or getattr(e, "status", None)
            step = "identity/federation" if status in (401, 403) else "model-call"
            result["error"] = "%s step failed: %s%s: %s" % (step, type(e).__name__,
                                                           (" status=%s" % status) if status else "", mask(str(e)))
    json.dump(result, open(a.out, "w"), indent=1)
    print("reader %s: %s" % (a.model_env, ("error: " + result["error"]) if result["error"]
                             else "%d finding(s)" % len(result["findings"])))


# ----------------------------------------------------------------------------- decide

def decide(readers):
    """Mechanical, in code, no model: every reader answered -> merge iff no breaks-us anywhere."""
    if not readers:
        return {"decision": "error", "reason": "no readers"}
    errors = [r for r in readers if r.get("error") or r.get("findings") is None]
    if errors:
        return {"decision": "error", "reason": "; ".join("%s: %s" % (r.get("reader"), r.get("error")) for r in errors)}
    breaks = [dict(f, reader=r.get("reader")) for r in readers for f in r["findings"] if f["severity"] == "breaks-us"]
    return {"decision": "hold" if breaks else "merge",
            "breaks_us": breaks,
            "readers": [{"reader": r.get("reader"), "findings": r["findings"]} for r in readers]}


def cmd_decide(a):
    readers = [json.load(open(p)) for p in a.reader]
    d = decide(readers)
    json.dump(d, open(a.out, "w"), indent=1)
    print("decision: %s%s" % (d["decision"], (" (%s)" % d.get("reason")) if d.get("reason") else ""))


# ----------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("updates"); p.add_argument("--title", default=""); p.add_argument("--body-file"); p.set_defaults(fn=cmd_updates)
    p = sub.add_parser("gather"); p.add_argument("--pr", required=True); p.add_argument("--updates", required=True); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_gather)
    p = sub.add_parser("read"); p.add_argument("--bundle", required=True); p.add_argument("--prompt", required=True); p.add_argument("--model-env", required=True); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_read)
    p = sub.add_parser("decide"); p.add_argument("--reader", action="append", required=True); p.add_argument("--out", required=True); p.set_defaults(fn=cmd_decide)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
