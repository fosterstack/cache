#!/usr/bin/env python3
"""The pin age check (REQ-SUP-001-AC2, AC3): a version a pull request moves must have been public 7 days, proven by a SERVER-SIDE time.

  pin-age-check.py --root REPO --base REV --head REV [--fixtures FILE] [--json FILE] [--now ISO] [--min-days N]

Exit 0: nothing moved, or every moved version is old enough. Exit 1: a moved version is too young or its age cannot be proven (never a pass).
Exit 2: the check could not run (unreadable input, a tree that does not parse).

Times that count (and nothing else): github-release (a release's publish time), pypi (the index's upload time), go-index (the Go module index's
timestamp), registry-push (the registry's push time), and the first time the exact version appeared in one of OUR pull requests. A commit date, a tag
date, a version-control time or an image's own "created" field is set by the publisher or builder and is never a proof.
Fixtures (offline tests): {"now": ISO, "times": {ITEM: {"time": ISO, "source": S}}, "first_seen": {ITEM: ISO}}.
"""
import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_SIDE = ("github-release", "pypi", "go-index", "registry-push", "observer", "pr-clock")
MIN_DAYS = 7.0


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inv = _load("pin-inventory")
tobs = _load("tag_observer")


def parse_time(s):
    """ISO 8601 -> aware datetime, or None when it is not one."""
    if not isinstance(s, str):
        return None
    t = s.strip()
    m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$", t)
    if not m:
        return None
    base, frac, tz = m.groups()
    try:
        d = dt.datetime.strptime(base.replace(" ", "T"), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        d = d - sign * dt.timedelta(hours=hh, minutes=mm)
    return d.replace(tzinfo=dt.timezone.utc)


_PIN = re.compile(r"^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64}|v?\d+(?:\.\d+)*(?:[-+._][0-9A-Za-z][0-9A-Za-z.\-+]*)?)$")


def is_pin(version):
    """An exact version: a commit, a digest, or dotted numbers (an optional suffix such as -rc.1). Never a name (main, nightly, lts/*), a wildcard (1.*, 3.x), a range or an expression."""
    return bool(version) and bool(_PIN.match(version)) and "*" not in version and not re.search(r"(?i)(^|[.\-_])(x|latest|main|master|nightly|stable|lts)($|[.\-_])", version)


def judge_item(item, proofs, now, min_days=MIN_DAYS):
    """(ok, reason, proof) from a list of (time-string, source). Only valid server-side proofs in the past count; the oldest decides."""
    if not is_pin(item.version):
        return False, f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, so it has no age", None
    best, seen = None, []
    for t, src in proofs:
        seen.append(src)
        if src not in SERVER_SIDE and src != "first-seen":
            continue
        if src == "github-release" and item.kind == "action":
            continue  # never alone for an action: the tag may point somewhere new (tj-actions); our observer or our PR clock must have seen the commit
        d = parse_time(t)
        if d is None or d > now:
            continue
        if best is None or d < best[0]:
            best = (d, src)
    if best is None:
        return False, "age not provable: no server-side publish time" + (f" (refused or unusable: {', '.join(seen)})" if seen else " found"), None
    age = (now - best[0]).total_seconds() / 86400
    proof = {"time": best[0].strftime("%Y-%m-%dT%H:%M:%SZ"), "source": best[1], "age_days": round(age, 2)}
    if age + 1e-9 < min_days:
        return False, f"too young: {age:.1f} days old by {best[1]} (needs {min_days:g})", proof
    return True, f"{age:.1f} days old by {best[1]}", proof


# ---------- live providers (a real run, no fixtures) ----------
class CouldNotLook(Exception):
    """The server could not be asked (rate limit, outage): the check cannot run. Never read as 'no proof', never a pass."""


def _gh_failed(r):
    """True for a plain miss (404 and friends); raises when the failure is the service's, not the answer's."""
    if not re.search(r"\b(404|410|422)\b", r.stderr + r.stdout):  # only "not there" is an answer; a 401/403, a rate limit or an outage means we could not look
        raise CouldNotLook(f"GitHub API: {(r.stderr or r.stdout).strip()[:120]}")
    return True


def _gh_pages(path):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line)."""
    r = subprocess.run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        return None


def _gh_api(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        return json.loads(r.stdout)
    except ValueError:
        return None


def _http_json(url, timeout=30):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except (OSError, ValueError):
        return None


TOOL_REPOS = {  # tool -> (github repo, tag prefix to try after the bare version)
    "trivy": "aquasecurity/trivy", "grype": "anchore/grype", "syft": "anchore/syft", "snyk": "snyk/cli", "osv": "google/osv-scanner",
    "scout": "docker/scout-cli", "gitsign": "sigstore/gitsign", "golangci-lint": "golangci/golangci-lint", "python": "actions/python-versions",
    "buildx": "docker/buildx", "goreleaser": "goreleaser/goreleaser", "cosign": "sigstore/cosign", "kind": "kubernetes-sigs/kind", "helm": "helm/helm", "node": "nodejs/node",
}


def _release_time(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}")
        if rel and rel.get("published_at") and not rel.get("draft"):
            return rel["published_at"]
    return None


_TAGS = {}


def _tag_refs(repo):
    """{tag: commit} for EVERY tag of a public repository, annotated tags peeled, from ONE `git ls-remote` (no REST call per tag: a repository with hundreds
    of annotated tags would otherwise exhaust the shared API budget)."""
    if repo not in _TAGS:
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise CouldNotLook(f"git ls-remote of {repo} failed: {type(e).__name__}")
        if r.returncode:
            raise CouldNotLook(f"git ls-remote of {repo} failed")
        refs = {}
        for line in r.stdout.splitlines():
            sha, _, ref = line.partition("\t")
            if not ref.startswith("refs/tags/"):
                continue
            name = ref[len("refs/tags/"):]
            if name.endswith("^{}"):
                refs[name[:-3]] = sha          # peeled: the commit an annotated tag points at
            else:
                refs.setdefault(name, sha)
        _TAGS[repo] = refs
    return _TAGS[repo]


def _tags_for_commit(repo, sha):
    """EVERY tag that points at the commit: v4 and v4.1.0 may both."""
    return sorted(t for t, c in _tag_refs(repo).items() if c == sha)


def _tag_for_commit(repo, sha):
    tags = _tags_for_commit(repo, sha)
    return tags[0] if tags else None


def _commit_date(repo, sha):
    c = _gh_api(f"repos/{repo}/commits/{sha}")
    return ((c or {}).get("commit", {}).get("committer") or {}).get("date")


def _go_module(path, version):
    parts = path.split("/")
    for n in range(len(parts), 0, -1):
        mod = "/".join(parts[:n])
        info = _http_json(f"https://proxy.golang.org/{urllib.parse.quote(mod, safe='/').lower()}/@v/{urllib.parse.quote(version)}.info")
        if info and info.get("Version"):
            return mod, info
    return None, None


def _go_index_time(mod, version, vcs_time):
    """The Go module index's timestamp for module@version: scan the index from the version-control time forward (the index entry follows it)."""
    since = vcs_time
    for _ in range(40):
        rows = []
        try:
            with urllib.request.urlopen(f"https://index.golang.org/index?since={urllib.parse.quote(since)}&limit=2000", timeout=30) as r:
                rows = [json.loads(line) for line in r.read().decode().splitlines() if line.strip()]
        except (OSError, ValueError):
            return None
        for row in rows:
            if row.get("Path", "").lower() == mod.lower() and row.get("Version") == version:
                return row["Timestamp"]
        if len(rows) < 2000:
            return None
        since = rows[-1]["Timestamp"]
    return None


_OBS = {}


def _gh_bytes(path):
    r = subprocess.run(["gh", "api", path], capture_output=True)
    if r.returncode:
        _gh_failed(type("R", (), {"stderr": r.stderr.decode("utf-8", "replace"), "stdout": ""})())
        return None
    return r.stdout


def observed():
    """The cumulative tag observations of OUR scheduled runs on main (None before the first one); loud if they exist and cannot be read.
    Only runs that are event=schedule, branch main, success, of this workflow's path are read, so a pull request can never forge them."""
    if "state" in _OBS:
        return _OBS["state"]
    repo = os.environ.get("GITHUB_REPOSITORY")
    state = None
    if repo:
        data = _gh_api(f"repos/{repo}/actions/workflows/supply-chain.yml/runs?event=schedule&branch=main&status=success&per_page=100") or {}
        runs = sorted((r for r in data.get("workflow_runs", []) if tobs.accept_run(r)), key=lambda r: r.get("created_at", ""), reverse=True)
        for run in runs[:30]:
            arts = (_gh_api(f"repos/{repo}/actions/runs/{run['id']}/artifacts") or {}).get("artifacts", [])
            art = next((x for x in arts if x.get("name") == tobs.STATE_NAME and not x.get("expired")), None)
            if art:
                raw = _gh_bytes(f"repos/{repo}/actions/artifacts/{art['id']}/zip")
                try:
                    state = tobs.unpack(raw)
                except Exception as e:  # a state that exists but cannot be read is loud, never "nothing observed"
                    raise CouldNotLook(f"the tag observations of a scheduled run cannot be read: {type(e).__name__}")
                break
    _OBS["state"] = state  # None: runs that predate the artifact, or none yet: nothing observed, so ages only get younger
    return state


def _pr_clock(item, root, base, head="HEAD"):
    """The PR clock: the earliest server-side time of a workflow run on the first commit of base..head whose INVENTORY holds this exact item
    (not a text match: a comment mentioning the version, or digits that happen to equal it, never start the clock)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo or not base or not item.version:
        return None
    r = subprocess.run(["git", "-C", root, "rev-list", "--reverse", f"{base}..{head}"], capture_output=True, text=True)
    first = None
    for c in r.stdout.split():
        try:
            if item.key in inv.load_at(root, c):
                first = c
                break
        except RuntimeError:
            continue
    if not first:
        return None
    runs = (_gh_api(f"repos/{repo}/actions/runs?head_sha={first}&per_page=100") or {}).get("workflow_runs", [])
    times = [x["created_at"] for x in runs if x.get("created_at")]
    return min(times) if times else None


def _release_with_assets(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}")
        if rel and rel.get("published_at") and not rel.get("draft"):
            return rel
    return None


def live_proofs(item, root, base=None, head="HEAD"):
    out = []
    if item.kind == "action":
        # the age of the EXACT commit: when our own scheduled run first saw the tag point at it (a release date proves nothing about a moved tag),
        # or the PR clock; the tag in the `# vX` label must itself resolve to the pinned commit
        tags = _tags_for_commit(item.name, item.version)
        want = [item.label] if item.label else tags
        if not item.label or item.label in tags:
            state = observed()
            for tag in want:
                t = tobs.first_seen(state, item.name, tag, item.version)
                if t:
                    out.append((t, "observer"))
    elif item.kind == "tool":
        repo = TOOL_REPOS.get(item.name) or (item.name if re.fullmatch(r"[\w.-]+/[\w.-]+", item.name) else None)  # owner/repo: a downloaded release asset
        if repo:
            bare = item.version.lstrip("v")
            rel = _release_with_assets(repo, [item.version, "v" + bare, bare])
            if rel:
                # the NEWEST of the release date and every asset's own created/updated time: a replaced asset in an old release is young again
                stamps = [rel["published_at"]] + [a[k] for a in rel.get("assets", []) for k in ("created_at", "updated_at") if a.get(k)]
                out.append((max(stamps, key=lambda x: parse_time(x) or dt.datetime.min.replace(tzinfo=dt.timezone.utc)), "github-release"))
    elif item.kind == "gotool":
        mod, info = _go_module(item.name, item.version)
        if mod:
            t = _go_index_time(mod, info["Version"], info["Time"])
            if t:
                out.append((t, "go-index"))
    elif item.kind == "package":
        name = item.name.split("/", 1)[1]
        d = _http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(item.version)}/json")
        ups = [u.get("upload_time_iso_8601") for u in (d or {}).get("urls", []) if u.get("upload_time_iso_8601")]
        if ups:
            out.append((max(ups), "pypi"))  # the newest file: a wheel added later to an old release is young
    elif item.kind == "image" and item.version:
        t = _registry_push(item)
        if t:
            out.append((t, "registry-push"))
    pc = _pr_clock(item, root, base, head)
    if pc:
        out.append((pc, "pr-clock"))
    return out


def _registry_push(item):
    name = item.name
    if name.startswith("ghcr.io/"):
        owner, _, pkg = name[len("ghcr.io/"):].partition("/")
        for scope in ("orgs", "users"):
            for page in (1, 2, 3):
                vs = _gh_api(f"{scope}/{owner}/packages/container/{urllib.parse.quote(pkg, safe='')}/versions?per_page=100&page={page}")
                if not vs:
                    break
                for v in vs:
                    if v.get("name") == item.version:
                        return v.get("created_at")
        return None
    parts = name.split("/")
    if len(parts) == 2 or (len(parts) == 3 and parts[0] == "docker.io"):
        ns, repo = parts[-2], parts[-1]
        url = f"https://hub.docker.com/v2/repositories/{ns}/{repo}/tags?page_size=100"
        for _ in range(5):
            d = _http_json(url)
            if not d:
                return None
            for tag in d.get("results", []):
                if tag.get("digest") == item.version or any(i.get("digest") == item.version for i in tag.get("images", [])):
                    return tag.get("tag_last_pushed")
            url = d.get("next")
            if not url:
                break
    return None


class Fixture:
    def __init__(self, fx):
        self.fx = fx

    def proofs(self, item):
        out = []
        t = (self.fx.get("times") or {}).get(item.key)
        if isinstance(t, dict):
            out.append((t.get("time"), t.get("source")))
        fs = (self.fx.get("first_seen") or {}).get(item.key)
        if fs:
            out.append((fs, "first-seen"))
        return out


class Live:
    def __init__(self, root, base=None, head="HEAD"):
        self.root, self.base, self.head = root, base, head

    def proofs(self, item):
        return live_proofs(item, self.root, self.base, self.head)


def check(moved_items, source, now, min_days):
    rows = []
    for it in moved_items:
        ok, reason, proof = judge_item(it, source.proofs(it), now, min_days)
        rows.append({"item": it.key, "label": it.label, "ok": ok, "reason": reason, "proof": proof})
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--fixtures")
    ap.add_argument("--json")
    ap.add_argument("--now")
    ap.add_argument("--min-days", type=float, default=MIN_DAYS)
    a = ap.parse_args(argv)
    try:
        fx = json.load(open(a.fixtures)) if a.fixtures else None
        now = parse_time(a.now) if a.now else (parse_time((fx or {}).get("now")) if fx and fx.get("now") else dt.datetime.now(dt.timezone.utc))
        if now is None:
            raise ValueError("--now is not an ISO time")
        base_items = inv.load_at(a.root, a.base)
        head_items = inv.load_at(a.root, a.head)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"pin-age: cannot run: {e}", file=sys.stderr)
        return 2
    moved = inv.moved(base_items, head_items)
    try:
        return _run(a, moved, fx, now)
    except CouldNotLook as e:
        print(f"pin-age: cannot run: {e} (not a pass: re-run the check)", file=sys.stderr)
        return 2


def _added_unmeasured(root, base, head):  # keys are (file, form, the normalised command line): an in-place swap of one line for another is an ADDITION
    """Install forms this check cannot measure that the head has MORE of than the base (per file and form): a PR that adds one is refused."""
    try:
        b = inv.unmeasured({**inv.tree_files(root, base), **inv.tree_scripts(root, base)})
        h = inv.unmeasured({**inv.tree_files(root, head), **inv.tree_scripts(root, head)})
    except RuntimeError:
        return []
    return sorted(k for k, n in h.items() if n > b.get(k, 0))


def _run(a, moved, fx, now):
    added = _added_unmeasured(a.root, a.base, a.head)
    if not moved and not added:
        print("pin-age: no pin moved (nothing to measure)")
        rows = []
    else:
        rows = check(moved, Fixture(fx) if fx is not None else Live(a.root, a.base, a.head), now, a.min_days)
        print(f"pin-age: {len(rows)} moved version(s), each must be public {a.min_days:g} days by a server-side time:")
        for r in rows:
            print(f"  {'ok  ' if r['ok'] else 'FAIL'} {r['item']}: {r['reason']}")
    for path, what, line in added:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False, "proof": None,
                     "reason": f"{what} was added to {path} ({line[:100]}): this check cannot measure it, so a pull request that adds one is refused (use a pinned form it can measure)"})
        print(f"  FAIL unmeasured:{path}: {what} added: not measurable, refused")
    failing = [r for r in rows if not r["ok"]]
    if a.json:
        json.dump({"min_days": a.min_days, "moved": rows}, open(a.json, "w"), indent=1)
    if failing:
        print(f"pin-age: FAIL: {len(failing)} of {len(rows)} moved version(s) too young or unprovable; the check turns green when each is {a.min_days:g} days old")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
