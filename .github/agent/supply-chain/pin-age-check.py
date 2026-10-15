#!/usr/bin/env python3
"""The pin age check (REQ-SUP-001-AC2, AC3): a version a pull request moves must have been public 7 days, proven by a SERVER-SIDE time.

  pin-age-check.py --root REPO --base REV --head REV [--fixtures FILE] [--json FILE] [--now ISO] [--min-days N] [--exceptions FILE]

Exit 0: nothing moved, or every moved version is old enough. Exit 1: a moved version is too young or its age cannot be proven (never a pass).
Exit 2: the check could not run (unreadable input, a tree that does not parse).

Times that count (and nothing else): github-release (a release's publish time), pypi (the index's upload time), go-index (the Go module index's
timestamp), registry-push (the registry's push time), and the first time the exact version appeared in one of OUR pull requests. A commit date, a tag
date, a version-control time or an image's own "created" field is set by the publisher or builder and is never a proof.
Fixtures (offline tests): {"now": ISO, "times": {ITEM: {"time": ISO, "source": S}}, "first_seen": {ITEM: ISO}}.
"""
import argparse
import base64
import hashlib
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


def parse_time(s, clock=False):
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
    d = d.replace(tzinfo=dt.timezone.utc)
    if frac and not clock:
        d += dt.timedelta(seconds=1)   # a publication time's fractional second is rounded UP, a clock's (clock=True) is truncated: an age is never over-counted (AC3)
    return d


_PIN = re.compile(r"^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64}|v?\d+(?:\.\d+)*(?:[-+._][0-9A-Za-z][0-9A-Za-z.\-+]*)?)$")


def is_pin(version):
    """An exact version: a commit, a digest, or dotted numbers (an optional suffix such as -rc.1). Never a name (main, nightly, lts/*), a wildcard (1.*, 3.x), a range or an expression."""
    return bool(version) and bool(_PIN.match(version)) and "*" not in version and not re.search(r"(?i)(^|[.\-_])(x|latest|main|master|nightly|stable|lts)($|[.\-_])", version)


def judge_item(item, proofs, now, min_days=MIN_DAYS):
    """(ok, reason, proof) from a list of (time-string, source). Only valid server-side proofs in the past count; the oldest decides."""
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or "")):
        return False, f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, or an action not named by its commit, so it has no age", None
    if item.kind == "tool" and item.name in ("python", "java", "node") and len(item.version.lstrip("v").split(".")) < 3:
        return False, f"not a pin: {item.version!r} is a series, not an exact release (the installer picks the newest patch), so it has no age", None
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


GH_TIMEOUT = 120


def _gh_run(cmd, **kw):
    """subprocess.run for the gh and git calls here, with a timeout: a call that hangs is CouldNotLook (the run stops), never an answer."""
    try:
        return subprocess.run(cmd, **dict({"timeout": GH_TIMEOUT}, **kw))
    except subprocess.TimeoutExpired:
        raise CouldNotLook(f"{cmd[0]} {' '.join(map(str, cmd[1:3]))} did not answer in {GH_TIMEOUT}s")


def _gh_failed(r):
    """True for a plain miss (404 and friends); raises when the failure is the service's, not the answer's."""
    if not re.search(r"\b(404|410|422)\b", r.stderr + r.stdout):  # only "not there" is an answer; a 401/403, a rate limit or an outage means we could not look
        raise CouldNotLook(f"GitHub API: {(r.stderr or r.stdout).strip()[:120]}")
    return True


def _gh_pages(path):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line)."""
    r = _gh_run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        return [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        return None


def _gh_api(path):
    r = _gh_run(["gh", "api", path], capture_output=True, text=True)
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
    r = _gh_run(["gh", "api", path], capture_output=True)
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
        data = _gh_api(f"repos/{repo}/actions/workflows/supply-chain.yml/runs?event=schedule&branch=main&status=completed&per_page=100") or {}
        runs = sorted((r for r in data.get("workflow_runs", []) if tobs.accept_run(dict(r, path=str(r.get("path") or "").split("@")[0]))), key=lambda r: r.get("created_at", ""), reverse=True)
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


_INV_CACHE = {}


def _pr_clock(item, root, base, head="HEAD"):
    """The PR clock: the earliest server-side time of a workflow run on the first commit of base..head whose INVENTORY holds this exact item
    (not a text match: a comment mentioning the version, or digits that happen to equal it, never start the clock)."""
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo or not base or not item.version:
        return None
    r = _gh_run(["git", "-C", root, "rev-list", "--reverse", f"{base}..{head}"], capture_output=True, text=True)
    first = None
    for c in r.stdout.split():
        try:
            if (root, c) not in _INV_CACHE:
                _INV_CACHE[(root, c)] = inv.load_at(root, c)     # one parse per commit, not one per moved item
            if item.key in _INV_CACHE[(root, c)]:
                first = c
                break
        except RuntimeError:
            continue
    if not first:
        return None
    runs = (_gh_api(f"repos/{repo}/actions/runs?head_sha={first}&per_page=100") or {}).get("workflow_runs", [])
    times = [x["created_at"] for x in runs if x.get("created_at")]
    r2 = _gh_run(["gh", "api", "--paginate", f"repos/{repo}/commits/{first}/check-suites?per_page=100", "--jq", ".check_suites[]"], capture_output=True, text=True)
    if r2.returncode:
        _gh_failed(r2)
    else:
        for line in r2.stdout.splitlines():
            try:
                c = json.loads(line).get("created_at")
            except ValueError:
                continue
            if c:
                times.append(c)    # a check from a non-Actions app counts too: the EARLIEST server-side sign of the commit
    return min(times) if times else None


def _release_with_assets(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}")
        if rel and rel.get("published_at") and not rel.get("draft"):
            return rel
    return None


def live_proofs(item, root, base=None, head="HEAD"):
    out = []
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or "")):
        return out    # a placeholder, a range, a variable or an action not named by its commit has no age: nothing is looked up (and nothing can pass)
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
            rel = _release_with_assets(repo, [item.label] if item.label else [item.version, "v" + bare, bare])   # a download names its EXACT tag: no twin tag lends its age
            if rel:
                # the NEWEST of the release date and every asset's own created/updated time: a replaced asset in an old release is young again
                assets = [a for a in rel.get("assets", []) if not item.path or a.get("name") == item.path.split("#")[0]]   # the asset we download: a missing one borrows no other asset's age
                if item.path.split("#")[0] and not assets:
                    return out
                stamps = [rel["published_at"]] + [a[k] for a in assets for k in ("created_at", "updated_at") if a.get(k)]
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
    ap.add_argument("--base-inputs", help="the base-inputs list (default: .github/policy/base-inputs.json beside this script's own checkout, the base branch in CI)")
    ap.add_argument("--exceptions", help="the rulings file (default: the one beside this script's own checkout, the base branch in CI)")
    a = ap.parse_args(argv)
    try:
        fx = json.load(open(a.fixtures)) if a.fixtures else None
        now = parse_time(a.now, True) if a.now else (parse_time((fx or {}).get("now"), True) if fx and fx.get("now") else dt.datetime.now(dt.timezone.utc))
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
    except RuntimeError as e:
        print(f"pin-age: cannot run: {e} (not a pass)", file=sys.stderr)
        return 2
    except CouldNotLook as e:
        print(f"pin-age: cannot run: {e} (not a pass: re-run the check)", file=sys.stderr)
        return 2


def _line_hash(flat):
    return hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()


def _occurrences(root, rev):
    """{key: {whole-line hash: occurrences}}. A line bash reads differently from the flattening (whitespace other than space or tab, a continuation) gets
    a group no row can name ('unruled:' + its hash)."""
    out = {}
    for k, flat, bashlike in inv.unmeasured_occurrences({**inv.tree_files(root, rev), **inv.tree_scripts(root, rev)}):   # a read error propagates (exit 2)
        lh = _line_hash(flat) if bashlike else "unruled:" + _line_hash(flat)
        per = out.setdefault(k, {})
        per[lh] = per.get(lh, 0) + 1
    return out


def _unmeasured_counts(root, base, head):
    """{key: {whole-line hash: head occurrences}} for every (key, whole line) the head has MORE of than the base: an occurrence is identified by its key
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one (REQ-SUP-001-AC16)."""
    b, h = _occurrences(root, base), _occurrences(root, head)
    added = {}
    for k, per in h.items():
        for lh, n in per.items():
            if n > b.get(k, {}).get(lh, 0):
                added.setdefault(k, {})[lh] = n
    return added


def _added_unmeasured(root, base, head):  # keys are (file, form, the normalised command): an in-place swap or an edit of the line around it is an ADDITION
    """Install forms this check cannot measure that the head has MORE of than the base (per file, form and whole line): a PR that adds one is refused."""
    return sorted(_unmeasured_counts(root, base, head))


# REQ-SUP-001-AC16: the advisor's rulings on lines that only MENTION a download tool (a comment, an echo string, a stub written as data). They are read from
# the exceptions file beside the checkout this script runs from: in CI that is trusted/ (the base branch), never the pull request's tree (--root).
DEFAULT_EXCEPTIONS = os.path.normpath(os.path.join(HERE, "..", "..", "supply-chain-exceptions.json"))
_RULED_FIELDS = ("file", "form", "key", "line", "ruling")
MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; this file must not hold them)")


def load_ruled_text(path, required=False):
    """{(file, form, 64-hex segment hash, 64-hex whole-line hash): (ruling, count)} from the file's unmeasured_text list. A missing default file is no rulings; anything malformed
    raises RuntimeError (the check cannot run, exit 2): never 'nothing ruled' and never 'everything ruled'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} (unmeasured_text) does not exist")
        return {}
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)   # a repeated key would let a later copy silently win
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} (unmeasured_text) is unreadable: {e}")
    rows = d.get("unmeasured_text", []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: unmeasured_text is not a list")
    out = {}
    for i, r in enumerate(rows):
        bad = lambda why: RuntimeError(f"{path}: unmeasured_text row {i} {why}")
        if not isinstance(r, dict) or set(r) - set(_RULED_FIELDS) - {"count"} or not set(_RULED_FIELDS) <= set(r):
            raise bad("must be an object with exactly file, form, key, line, ruling (and an optional count)")
        if not all(isinstance(r[k], str) and r[k].strip() for k in _RULED_FIELDS):
            raise bad("has an empty or non-text file, form, key, line or ruling")
        if not re.fullmatch(r"[0-9a-f]{64}", r["key"]):
            raise bad("key is not the scan's 64 lowercase hex hash")
        if not re.fullmatch(r"[0-9a-f]{64}", r["line"]):
            raise bad("line is not the 64 lowercase hex hash of the whole flattened line")
        count = r.get("count", 1)
        if type(count) is not int or not 1 <= count <= MAX_RULED_COUNT:
            raise bad(f"count is not a whole number from 1 to {MAX_RULED_COUNT}")
        k = (r["file"], r["form"], r["key"], r["line"])
        if k in out:
            raise bad("repeats an earlier row (file, form, key and line)")
        out[k] = (r["ruling"].strip(), count)
    return out


DEFAULT_BASE_INPUTS = os.path.normpath(os.path.join(HERE, "..", "..", "policy", "base-inputs.json"))


def load_base_inputs(path, required=False):
    """REQ-SUP-001-AC21: the set of paths .github/policy/base-inputs.json lists (read from the base branch's copy beside this script, never the pull request's tree).
    A missing default file lists nothing; anything malformed raises RuntimeError (exit 2): never 'nothing exempted' and never 'everything'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the base-inputs list {path} does not exist")
        return set()
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the base-inputs list {path} is unreadable: {e}")
    lst = d.get("base_inputs") if isinstance(d, dict) else None
    if not isinstance(lst, list) or not all(isinstance(x, str) and x for x in lst):
        raise RuntimeError(f"{path}: base_inputs is not a list of non-empty paths")
    return set(lst)


def split_base_inputs(moved, paths):
    """A (file) item whose repository path the list names is no item: its content is the repository's own base record. Exact equality with the path as git
    names it (Item.raw), never with the display name, which _hide() rewrites."""
    keep, ruled = [], []
    for m in moved:
        (ruled if (m.kind == "tool" and m.version == "(file)" and m.raw is not None and m.raw in paths) else keep).append(m)
    return keep, ruled


UNPINNED_FORM = "an unpinned package install"
LOCAL_CALL_FORM = "a local reusable workflow call"


def _item_hash(item):
    return hashlib.sha256(item.key.encode("utf-8", "replace")).hexdigest()


def unresolved_call_rows(root, rev, exceptions_path):
    """The local-call rows of the exceptions file that would rule NO item of the tree at rev, judged by the very tuple split_ruled_local_calls() looks up
    ((file, form, h, h) for an eligible item: kind action, version (local), with an origin file): [] when every row resolves to exactly one item."""
    rows = [k for k in load_ruled_text(exceptions_path, required=True) if k[1] == LOCAL_CALL_FORM]
    have = {}
    for it in inv.load_at(root, rev).values():
        if it.kind == "action" and it.version == "(local)" and it.src:
            h = _item_hash(it)
            have.setdefault((it.src[0], LOCAL_CALL_FORM, h, h), []).append(it.key)
    return [k for k in rows if len(have.get(k, [])) != 1]


def split_ruled_local_calls(moved, rulings):
    """REQ-SUP-001-AC19: a local reusable-workflow call that keeps a with: block is an item that cannot pass, unless a base-branch row names it: file, form
    "a local reusable workflow call", key and line both the 64-hex hash of the item's whole identity (its path and the hash of its with: block), so an edited
    with: block is another item. Returns (still moved, [(item, ruling)])."""
    keep, ruled = [], []
    for m in moved:
        r = None
        if m.kind == "action" and m.version == "(local)" and m.src:
            h = _item_hash(m)
            r = rulings.get((m.src[0], LOCAL_CALL_FORM, h, h))
        (ruled if r else keep).append((m, r[0]) if r else m)
    return keep, ruled


def drop_ruled_unpinned(items, ruled_lines):
    """REQ-SUP-001-AC20: an unpinned package item leaves the list only when the script line that made it (its own path and line id) is a ruled occurrence."""
    return [m for m in items if not (m.kind == "package" and m.version == "(unpinned)" and m.src and tuple(m.src) in ruled_lines)]


def ruled_unpinned_lines(root, base, head, exceptions_path):
    """The (script path, line id) pairs of the unpinned-package occurrences the head ADDS that a base-branch row rules, within the row's count. Shared by this check and
    pin-audit.py, so the one required job judges a ruled line once."""
    rulings = load_ruled_text(exceptions_path, required=False)
    in_base = _occurrences(root, base)
    out = set()
    for k, per in _unmeasured_counts(root, base, head).items():
        if k[1] != UNPINNED_FORM:
            continue
        rs = [rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in per]
        # a line the base already holds is never ruled here: an item of that line may have moved because an assignment it reads changed, and a copy of
        # the line cannot be told from it (the occurrence is still reported; the item keeps failing)
        if all(r and n <= r[1] and not in_base.get(k, {}).get(lh) for r, (lh, n) in zip(rs, per.items())):
            out.update((k[0], lh) for lh in per)
    return out


def _run(a, moved, fx, now):
    rulings = load_ruled_text(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))   # before the scan: a malformed list stops the check
    lines = _unmeasured_counts(a.root, a.base, a.head)
    added, ruled = [], []
    for k in sorted(lines):
        # ruled only when EVERY added (key, whole line) is named by a row and its head occurrences are within that row's count (1 unless it says more):
        # the same segment inside any other line, an edited line, or one copy too many leaves the item refused
        rs = [rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in lines[k]]
        if all(r and n <= r[1] for r, n in zip(rs, lines[k].values())):
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in rs))))
        else:
            added.append(k)
    moved = drop_ruled_unpinned(moved, ruled_unpinned_lines(a.root, a.base, a.head, a.exceptions or DEFAULT_EXCEPTIONS))   # REQ-SUP-001-AC20
    moved, base_files = split_base_inputs(moved, load_base_inputs(a.base_inputs or DEFAULT_BASE_INPUTS, required=bool(a.base_inputs)))   # REQ-SUP-001-AC21
    moved, ruled_calls = split_ruled_local_calls(moved, rulings)                                                       # REQ-SUP-001-AC19: judged by the ruled row of ITS OWN line, never by another line's
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
    for it in base_files:
        rows.append({"item": it.key, "label": "", "ok": True, "proof": None, "reason": f"base input: {it.name[5:]} is listed in .github/policy/base-inputs.json"})
        print(f"  ok   {it.key}: base input (REQ-SUP-001-AC21)")
    for it, ruling in ruled_calls:
        rows.append({"item": it.key, "label": "", "ok": True, "proof": None, "reason": f"ruled text: a local reusable workflow call in {it.src[0]}: {ruling[:200]}"})
        print(f"  ok   {it.key}: ruled text (REQ-SUP-001-AC19): {ruling[:200]}")
    for (path, what, line), ruling in ruled:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": True, "proof": None,
                     "reason": f"ruled text: {what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_text: {ruling[:200]}"})
        print(f"  ok   unmeasured:{path}: {what} ({line[:60]}): ruled text (REQ-SUP-001-AC16): {ruling[:200]}")
    failing = [r for r in rows if not r["ok"]]
    if a.json:
        json.dump({"min_days": a.min_days, "moved": rows}, open(a.json, "w"), indent=1)
    if failing:
        print(f"pin-age: FAIL: {len(failing)} of {len(rows)} moved version(s) too young or unprovable; the check turns green when each is {a.min_days:g} days old")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
