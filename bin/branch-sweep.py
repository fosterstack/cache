#!/usr/bin/env python3
"""Daily sweep of stale remote branches (REQ-REPO-001).

plan() is the pure decision (keep or delete, with a reason); main() lists through an injectable runner
(default: `gh api`), re-checks each branch right before deleting it, and fails closed on any listing it cannot trust.
Usage: branch-sweep.py [--apply|--dry-run] [--repo owner/name]   (dry run unless --apply)
"""
import base64, datetime as dt, json, os, re, subprocess, sys, urllib.parse

IDLE = dt.timedelta(days=14)
CAP = dt.timedelta(days=60)
PAGE_CAP = 200
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _utc(s):
    if isinstance(s, dt.datetime):
        return s
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def parse_keep(text, now):
    """-> (set of kept branch names, list of error strings)."""
    if text is None:
        return set(), []
    today = now.date()
    try:
        doc = json.loads(text)
    except ValueError as e:
        return set(), ["keep-file is not valid JSON: %s" % e]
    if not isinstance(doc, dict) or not isinstance(doc.get("keep"), list):
        return set(), ["keep-file must be an object with a keep list"]
    kept, errors, seen = set(), [], set()
    for i, e in enumerate(doc["keep"]):
        if not isinstance(e, dict):
            errors.append("entry %d is not an object" % i); continue
        b, x, r = e.get("branch"), e.get("expires"), e.get("reason")
        if not (isinstance(b, str) and b and isinstance(x, str) and isinstance(r, str) and r):
            errors.append("entry %d (%r) needs branch, expires and reason as strings" % (i, b)); continue
        if b in seen:
            errors.append("entry %d (%s) duplicates an earlier entry" % (i, b)); continue
        seen.add(b)
        if not DATE.match(x):
            errors.append("entry %d (%s) expires is not YYYY-MM-DD" % (i, b)); continue
        try:
            d = dt.date.fromisoformat(x)
        except ValueError:
            errors.append("entry %d (%s) expires is not a date" % (i, b)); continue
        if d > today + CAP:
            errors.append("entry %d (%s) expires more than 60 days from today" % (i, b)); continue
        if d < today:
            continue
        kept.add(b)
    return kept, errors


def _mine(prs, name, repo):
    return [p for p in prs if (((p.get("head") or {}).get("repo") or {}).get("full_name") or "").casefold() == repo.casefold()
            and p["head"]["ref"] == name]


def _tip_prs(prs, name, sha, repo):
    return [p for p in _mine(prs, name, repo) if (p["head"].get("sha") or "").lower() == sha.lower()]


def _protected_class(name, default_branch):
    low = name.casefold()
    if low == default_branch.casefold():
        return "default-branch"
    if low.startswith("release/"):
        return "release"
    if low.startswith("dependabot/"):
        return "dependabot"
    return None


def plan(branches, prs, keep, now, repo="o/r", default_branch="main"):
    out = []
    keep = set(keep)
    open_bases = {p["base"]["ref"] for p in prs if p.get("state") == "open"}
    for b in branches:
        name, sha = b["name"], b["sha"]
        mine = _mine(prs, name, repo)

        def d(action, reason):
            return {"branch": name, "sha": sha, "action": action, "reason": reason}
        cls = _protected_class(name, default_branch)
        if b.get("protected"):
            out.append(d("keep", "protected"))
        elif cls:
            out.append(d("keep", cls))
        elif any(p["state"] == "open" for p in mine):
            out.append(d("keep", "open-pr"))
        elif name in open_bases:
            out.append(d("keep", "base-of-open-pr"))
        elif name in keep:
            out.append(d("keep", "keep-file"))
        else:
            tip = sorted(_tip_prs(prs, name, sha, repo), key=lambda p: (p.get("created_at") or "", p["number"]))
            if tip and tip[-1].get("merged_at"):
                out.append(d("delete", "merged-pr"))
            elif tip and tip[-1]["state"] == "closed":
                out.append(d("delete", "closed-pr"))
            elif not b.get("committed"):
                out.append(d("keep", "unknown-age"))
            elif now - _utc(b["committed"]) >= IDLE:
                out.append(d("delete", "idle-14d"))
            else:
                out.append(d("keep", "recent"))
    return out


class ListingError(Exception):
    pass


def _enc(name):
    return urllib.parse.quote(name, safe="/")


def _pages(runner, path):
    sep = "&" if "?" in path else "?"
    items, page, prev = [], 1, None
    while True:
        if page > PAGE_CAP:
            raise ListingError("%s: more than %d pages" % (path, PAGE_CAP))
        st, body, hdr = runner("GET", "%s%sper_page=100&page=%d" % (path, sep, page))
        if st != 200:
            raise ListingError("%s page %d: HTTP %s" % (path, page, st))
        try:
            data = json.loads(body)
        except ValueError:
            raise ListingError("%s page %d: not JSON" % (path, page))
        if not isinstance(data, list):
            raise ListingError("%s page %d: not a list" % (path, page))
        nxt = 'rel="next"' in ((hdr or {}).get("link") or "")
        if nxt and prev is not None and data == prev:
            raise ListingError("%s page %d repeats the previous page" % (path, page))
        prev = data
        items += data
        if len(data) < 100 and not nxt:
            return items
        page += 1


def default_runner(method, path):
    p = subprocess.run(["gh", "api", "-i", "-X", method, path], capture_output=True, text=True)
    out = p.stdout
    if "\r\n\r\n" in out:
        head, _, body = out.partition("\r\n\r\n")
    else:
        head, _, body = out.partition("\n\n")
    lines = head.splitlines()
    if not lines or not lines[0].startswith("HTTP"):
        return 599, "", {}
    st = int(lines[0].split()[1])
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1); hdr[k.strip().lower()] = v.strip()
    return st, body, hdr


def main(argv=None, env=None, runner=None, now=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    runner = runner or default_runner
    now = now or dt.datetime.now(dt.timezone.utc)
    if any(a not in ("--apply", "--dry-run", "--repo") and not (i and argv[i - 1] == "--repo") for i, a in enumerate(argv)):
        print("ERROR usage: branch-sweep.py [--apply|--dry-run] [--repo o/r]", file=sys.stderr)
        return 2
    apply_ = "--apply" in argv
    repo = env.get("GITHUB_REPOSITORY")
    if "--repo" in argv:
        repo = argv[argv.index("--repo") + 1]
    lines = []
    log = env.get("BRANCH_SWEEP_LOG")

    def emit(s):
        lines.append(s)
        print(s)
        if log:  # appended and closed per line, so an interrupted run keeps what it already did
            with open(log, "a") as fh:
                fh.write(s + "\n")

    def finish(rc):
        if env.get("GITHUB_STEP_SUMMARY"):
            with open(env["GITHUB_STEP_SUMMARY"], "a") as fh:
                fh.write("\n".join(lines) + "\n")
        return rc
    rc = 0
    owner = repo.split("/")[0]
    try:
        st, body, _ = runner("GET", "repos/%s" % repo)
        if st != 200:
            raise ListingError("repo: HTTP %s" % st)
        default = json.loads(body)["default_branch"]
        branches = _pages(runner, "repos/%s/branches" % repo)
        prs = _pages(runner, "repos/%s/pulls?state=all" % repo)
        kst, kbody, _ = runner("GET", "repos/%s/contents/.github/branch-keep.json?ref=%s" % (repo, urllib.parse.quote(default, safe="")))
        if kst == 404:
            ktext = None
        elif kst == 200:
            try:
                ktext = base64.b64decode(json.loads(kbody)["content"]).decode()
            except Exception:
                ktext = "\0not-json"
        else:
            raise ListingError("keep-file: HTTP %s" % kst)
        keep, kerrs = parse_keep(ktext, now)
        nb = []
        for b in branches:
            name, sha = b["name"], b["commit"]["sha"]
            rec = {"name": name, "sha": sha, "committed": None, "protected": bool(b.get("protected"))}
            mine = _mine(prs, name, repo)
            needs_age = (not rec["protected"] and not _protected_class(name, default) and name not in keep
                         and not any(p["state"] == "open" for p in mine)
                         and not any(p["state"] == "open" and p["base"]["ref"] == name for p in prs)
                         and not _tip_prs(prs, name, sha, repo))
            if needs_age:
                cst, cbody, _ = runner("GET", "repos/%s/commits/%s" % (repo, sha))
                if cst == 200:
                    try:
                        rec["committed"] = json.loads(cbody)["commit"]["committer"]["date"]
                    except Exception:
                        pass
                if rec["committed"] is None:
                    emit("ERROR commit date unreadable for %s" % name); rc = max(rc, 1)
            nb.append(rec)
    except Exception as e:  # ListingError or a runner/parse failure before any delete: fail closed
        emit("ERROR listing: %s; nothing deleted" % e)
        return finish(2)
    for e in kerrs:
        emit("ERROR keep-file: %s" % e)
    if kerrs:
        rc = max(rc, 1)
    limited = 0  # consecutive 403/429 answers to a re-read or a delete
    stop = False

    def struck(st):
        nonlocal limited, stop
        limited = limited + 1 if st in (403, 429) else 0
        if limited >= 3:
            emit("ERROR rate limited: 3 consecutive 403/429; stopping")
            stop = True

    def reread(d):
        """-> 'ok', 'changed' or 'unverified' from the branch's ref and its open pull requests, just before a delete."""
        enc = _enc(d["branch"])
        rst, rbody, _ = runner("GET", "repos/%s/git/ref/heads/%s" % (repo, enc))
        if rst == 404:
            return "changed"
        if rst != 200:
            struck(rst)
            return "unverified"
        same = json.loads(rbody)["object"]["sha"] == d["sha"]
        opened = False
        for q in ("head=%s:%s" % (urllib.parse.quote(owner), urllib.parse.quote(d["branch"], safe="")),
                  "base=%s" % urllib.parse.quote(d["branch"], safe="")):
            ost, obody, _ = runner("GET", "repos/%s/pulls?state=open&%s&per_page=1" % (repo, q))
            if ost != 200 or not isinstance(json.loads(obody), list):
                struck(ost)
                return "unverified"
            opened = opened or bool(json.loads(obody))
        return "changed" if opened or not same else "ok"

    for d in plan(nb, prs, keep, now, repo=repo, default_branch=default):
        if d["action"] != "delete":
            continue
        if not apply_:
            emit("WOULD-DELETE %s %s %s" % (d["sha"], d["reason"], d["branch"])); continue
        if stop:
            continue
        try:
            verdict = reread(d)
        except Exception:
            verdict = "unverified"
        if verdict == "changed":
            limited = 0  # the answers were usable, so the run is not being throttled
        if verdict != "ok":
            emit("SKIPPED %s %s %s %s" % (verdict, d["sha"], d["reason"], d["branch"]))
            if verdict == "unverified":
                rc = max(rc, 1)
            continue
        try:
            st, _, _ = runner("DELETE", "repos/%s/git/refs/heads/%s" % (repo, _enc(d["branch"])))
        except Exception:
            st = 599
        if st == 204:
            limited = 0
            emit("DELETE %s %s %s" % (d["sha"], d["reason"], d["branch"]))
        else:
            emit("FAILED %s %s %s" % (d["sha"], d["reason"], d["branch"])); rc = max(rc, 1)
            struck(st)
    if not apply_:
        emit("dry-run: nothing deleted")
    return finish(rc)


if __name__ == "__main__":
    sys.exit(main())
