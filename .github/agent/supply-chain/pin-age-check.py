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
import shlex
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
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or not is_pin(item.version):
        return False, f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, so it has no age", None
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
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or not is_pin(item.version):
        return out    # a placeholder, a range or a variable has no age: nothing is looked up (and nothing can pass)
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
    ap.add_argument("--exceptions", help="the rulings file (default: the one beside this script's own checkout, the base branch in CI)")
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
    except RuntimeError as e:
        print(f"pin-age: cannot run: {e} (not a pass)", file=sys.stderr)
        return 2
    except CouldNotLook as e:
        print(f"pin-age: cannot run: {e} (not a pass: re-run the check)", file=sys.stderr)
        return 2


def _line_hash(flat):
    return hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()[:16]


def _occurrences(root, rev, flats=None):
    """{key: {whole-line hash: occurrences}}. A line bash reads differently from the flattening (whitespace other than space or tab, a continuation) gets
    a group no row can name ('unruled:' + its hash). flats (optional) receives {(key, whole-line hash): the flattened line} for the lines a row can name."""
    out = {}
    for k, flat, bashlike in inv.unmeasured_occurrences({**inv.tree_files(root, rev), **inv.tree_scripts(root, rev)}):   # a read error propagates (exit 2)
        lh = _line_hash(flat) if bashlike else "unruled:" + _line_hash(flat)
        per = out.setdefault(k, {})
        per[lh] = per.get(lh, 0) + 1
        if flats is not None and bashlike:
            flats[(k, lh)] = flat
    return out


def _unmeasured_counts(root, base, head, held=None, flats=None):
    """{key: {whole-line hash: head occurrences}} for every (key, whole line) the head has MORE of than the base: an occurrence is identified by its key
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one (REQ-SUP-001-AC16).
    held (optional) receives every head occurrence and flats the head's flattened lines (REQ-SUP-001-AC19 re-checks a ruled fetch still in the head)."""
    b, h = _occurrences(root, base), _occurrences(root, head, flats)
    if held is not None:
        held.update(h)
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
# REQ-SUP-001-AC19: the advisor's rulings on INPUT FETCHES (a download whose address comes from a lock or the registry), read the same way and bound the
# same way, each also naming its host, the step that verifies the bytes and the test that proves failing bytes are rejected before use.
DEFAULT_EXCEPTIONS = os.path.normpath(os.path.join(HERE, "..", "..", "supply-chain-exceptions.json"))
_RULED_FIELDS = ("file", "form", "key", "line", "ruling")
_FETCH_FIELDS = _RULED_FIELDS + ("host", "verifier", "test")
_LISTS = "unmeasured_text, unmeasured_input_fetch"
MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; this file must not hold them)")


def _load_rows(path, name, fields, required=False, check=None):
    """{(file, form, 16-hex segment hash, 16-hex whole-line hash): (ruling, count, row)} from the file's list NAME (one reader for AC16 and AC19). A missing
    default file is no rows; anything malformed raises RuntimeError (the check cannot run, exit 2): never 'nothing ruled' and never 'everything ruled'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} ({_LISTS}) does not exist")
        return {}
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)   # a repeated key would let a later copy silently win
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} ({_LISTS}) is unreadable: {e}")
    rows = d.get(name, []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: {name} is not a list")
    out = {}
    for i, r in enumerate(rows):
        bad = lambda why, i=i: RuntimeError(f"{path}: {name} row {i} {why}")
        if not isinstance(r, dict) or set(r) - set(fields) - {"count"} or not set(fields) <= set(r):
            raise bad(f"must be an object with exactly {', '.join(fields)} (and an optional count)")
        if not all(isinstance(r[k], str) and r[k].strip() for k in _RULED_FIELDS):
            raise bad("has an empty or non-text file, form, key, line or ruling")
        if not re.fullmatch(r"[0-9a-f]{16}", r["key"]):
            raise bad("key is not the scan's 16 lowercase hex hash")
        if not re.fullmatch(r"[0-9a-f]{16}", r["line"]):
            raise bad("line is not the 16 lowercase hex hash of the whole flattened line")
        count = r.get("count", 1)
        if type(count) is not int or not 1 <= count <= MAX_RULED_COUNT:
            raise bad(f"count is not a whole number from 1 to {MAX_RULED_COUNT}")
        if check:
            check(r, bad)
        k = (r["file"], r["form"], r["key"], r["line"])
        if k in out:
            raise bad("repeats an earlier row (file, form, key and line)")
        out[k] = (r["ruling"].strip(), count, r)
    return out


def load_ruled_text(path, required=False):
    """The unmeasured_text rows (REQ-SUP-001-AC16)."""
    return _load_rows(path, "unmeasured_text", _RULED_FIELDS, required)


REPO_SELF = "repo:self"
GH_FORM = "a gh release or extension download"
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_FUNC = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,127}")
_TEST_FILE = re.compile(r"(?:^|/)(?:[^/]+-test\.sh|[^/]+_test\.go|[^/]+_test\.py|test_[^/]+\.py)$")
MIN_CASE = 12


def _rel_path(p):
    """A relative path inside the repository: no leading /, no empty, . or .. component, no backslash, whitespace or control character."""
    return (isinstance(p, str) and 0 < len(p) <= 512 and not p.startswith("/") and "\\" not in p
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in p) and all(c not in ("", ".", "..") for c in p.split("/")))


def _check_fetch_row(r, bad):
    """The AC19 fields, beyond AC16's: form, host, verifier and test, each strict."""
    h = r["host"]
    if h == REPO_SELF:
        if r["form"] != GH_FORM or r["key"] != r["line"]:
            raise bad(f"host {REPO_SELF} is only for the form '{GH_FORM}' (whose key is the whole-line hash, so key equals line)")
    elif r["form"] != "a download":
        raise bad(f"form is not 'a download' (a curl or wget download), nor '{GH_FORM}' with host {REPO_SELF}")
    elif not isinstance(h, str) or not (_rel_path(h[5:]) if h.startswith("lock:") else _HOST.fullmatch(h)):
        raise bad(f"host is neither a lower-case DNS name with a dot (no scheme, port, path or user), nor lock:<relative path of a committed lock>, nor {REPO_SELF}")
    v = r["verifier"]
    if not isinstance(v, dict) or set(v) not in ({"file", "function"}, {"file", "line"}):
        raise bad("verifier must be an object with file and exactly one of function or line")
    if not _rel_path(v["file"]):
        raise bad("verifier file is not a relative path in the repository")
    if "function" in v and not (isinstance(v["function"], str) and _FUNC.fullmatch(v["function"])):
        raise bad("verifier function is not a function name")
    if "line" in v and not (isinstance(v["line"], str) and v["line"].strip() and not any(c in v["line"] for c in "\r\n")):
        raise bad("verifier line is not one non-empty line of text")
    t = r["test"]
    if not isinstance(t, dict) or set(t) != {"file", "case"}:
        raise bad("test must be an object with exactly file and case")
    if not _rel_path(t["file"]) or not _TEST_FILE.search(t["file"]):
        raise bad("test file is not a relative path to a test (*-test.sh, *_test.go, *_test.py or test_*.py)")
    if not isinstance(t["case"], str) or len(t["case"].strip()) < MIN_CASE or any(c in t["case"] for c in "\r\n"):
        raise bad(f"test case is not one line naming a case (at least {MIN_CASE} characters)")


def load_input_fetch(path, required=False):
    """The unmeasured_input_fetch rows (REQ-SUP-001-AC19): AC16's row plus host, verifier and test."""
    return _load_rows(path, "unmeasured_input_fetch", _FETCH_FIELDS, required, _check_fetch_row)


def _covered(rows, k, per):
    """The rows of one list that rule item k: one per added whole line, when EVERY added (key, whole line) is named by a row and its head occurrences are
    within that row's count (1 unless it says more); else None. The same segment inside any other line, an edited line, or one copy too many leaves the
    item refused (REQ-SUP-001-AC16; the same rule for AC19)."""
    rs = [rows.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in per]
    return rs if all(r and n <= r[1] for r, n in zip(rs, per.values())) else None


# --- REQ-SUP-001-AC19: what the head must hold for a ruled input fetch ---------------------------------------------------------------------------------
_SEGMENTS = re.compile(r"\s*(?:;|&&|\|\||\|)\s*")      # the scan's own split of a line into commands (pin-inventory.unmeasured_occurrences)
_LEAD = {"if", "!", "then", "do", "else", "elif", "while", "until"}
_TOOLS = {   # the only words a ruled download may hold: flags, and options whose value is a number, =https or an output file
    "curl": {"letters": set("fsSLq"), "flags": {"--fail", "--fail-with-body", "--silent", "--show-error", "--location", "--compressed", "--create-dirs",
                                                 "--retry-all-errors", "--retry-connrefused", "--disable", "--http1.1", "--http2", "--tlsv1.2", "--tlsv1.3"},
             "output": {"-o", "--output"}, "number": {"--retry", "--retry-delay", "--retry-max-time", "--max-time", "-m", "--connect-timeout"},
             "proto": {"--proto", "--proto-redir"}},
    "wget": {"letters": set("q"), "flags": {"--quiet", "--no-verbose", "-nv", "--https-only"}, "output": {"-O", "--output-document"},
             "number": {"-t", "--tries", "-T", "--timeout"}, "proto": set()},
}
_REDIR = re.compile(r"(?:[12]?>>?|&>>?)")
_DUP = re.compile(r"[12]?>&[12]")


def _plain(w):
    """A word that names no address and expands nothing but $NAME or ${NAME}."""
    return "://" not in w and not re.search(r"[{}\\<>|&;()`]", re.sub(r"\$\{[A-Za-z_]\w*\}", "", w))


def _address_unruled(seg, host):
    """None when the download command takes its address only as the row allows (REQ-SUP-001-AC19 (b)), else why not. Fail closed: a word this reader does
    not know is refused, never skipped."""
    if re.search(r"\$\(|`|<\(|>\(", seg):
        return "a command substitution in the download command"
    try:
        lex = shlex.shlex(seg, posix=True)
        lex.whitespace_split, lex.commenters = True, ""
        words = list(lex)
    except ValueError:
        return "the download command cannot be read as words"
    i = 0
    while i < len(words) and words[i] in _LEAD:
        i += 1
    if i == len(words) or words[i] not in _TOOLS:
        return "the download command does not start with curl or wget (an assignment, a wrapper or a path in front of it)"
    tool, i, urls = _TOOLS[words[i]], i + 1, []
    while i < len(words):
        w = words[i]
        i += 1
        if _DUP.fullmatch(w):
            continue
        m = re.match(_REDIR.pattern + r"(.*)$", w)
        if m:
            target = m.group(1)
            if not target:
                if i == len(words):
                    return "an output redirect with no target"
                target, i = words[i], i + 1
            if target.startswith("-") or not _plain(target):
                return f"an output redirect to {target[:60]!r}"
            continue
        name, eq, val = w.partition("=") if w.startswith("--") else (w, "", "")
        if not eq and (w in tool["flags"] or re.fullmatch(r"-[A-Za-z]+", w) and set(w[1:]) <= tool["letters"]):
            continue
        if name in tool["output"] | tool["number"] | tool["proto"]:
            if not eq:
                if i == len(words):
                    return f"{name} has no value"
                val, i = words[i], i + 1
            if name in tool["number"] and not re.fullmatch(r"\d{1,5}", val):
                return f"{name} takes a number"
            if name in tool["proto"] and val != "=https":
                return f"{name} must be =https"
            if name in tool["output"] and (not val or val.startswith("-") or not _plain(val)):
                return f"{name} names {val[:60]!r}, not an output file"
            continue
        if w.startswith("-") or w[:1] in "<>|&;(){}":
            return f"the word {w[:40]!r} is not one this check reads in a ruled download (a flag, --retry N, --proto =https, an output file)"
        urls.append(w)
    if not urls:
        return "the download command names no address"
    if host.startswith("lock:") and len(urls) != 1:
        return f"a lock row's download takes exactly ONE address, the variable read from {host[5:]}: it names {len(urls)}"
    for u in urls:
        if host.startswith("lock:"):
            if not re.fullmatch(r"\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}", u):
                return f"a lock row's address must be ONE variable read from {host[5:]} ($url), with no host on the line: {u[:80]!r}"
        else:
            pre = f"https://{host}/"
            if not u.startswith(pre) or not _plain(u[len(pre):]):
                return f"every address must start with {pre} and expand only $NAME in its path (no variable host, no other host, no http://): {u[:80]!r}"
    return None


# --- the authenticated draft download (host repo:self; the AC19 amendment, advisor Oct 10 step 5) ---------------------------------------------------------
_GH_PREFIX = 'gh release download "$ver" '
_GH_REPO = '"$GITHUB_REPOSITORY"'
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")     # a literal exact asset name: no glob (* ? [ ] { }), no variable, no quote
_ASSET_VER = re.compile(r'"(?:[A-Za-z0-9._+-]|\$\{ver\})*\$\{ver\}(?:[A-Za-z0-9._+-]|\$\{ver\})*"')   # "...${ver}...": ${ver} the ONLY expansion
_LITPATH = re.compile(r"[A-Za-z0-9._/][A-Za-z0-9._/-]*")  # a literal path: no glob, no variable, no quote, no ~
_TAG_RES = (r"^v[0-9]+\.[0-9]+\.[0-9]+$", r"^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$")
_TAG_RE = "(?:" + "|".join(re.escape(x) for x in _TAG_RES) + ")"
_VER = r'(?:"\$ver"|\$ver)'
_MSG = r"(?:(?:echo|printf) [^;{}|&`()<>\\]*(?: >&2)?; )?"
_VER_CHECK = re.compile(rf"\[\[ {_VER} =~ {_TAG_RE} \]\] \|\| (?:exit [1-9][0-9]?|\{{ {_MSG}exit [1-9][0-9]?; \}})"
                        rf"|if \[\[ ! {_VER} =~ {_TAG_RE} \]\]; then {_MSG}exit [1-9][0-9]?; fi")


def _gh_unruled(flat):
    """None when the line is EXACTLY gh release download "$ver" --repo "$GITHUB_REPOSITORY" with one or more -p NAME and at most one -D PATH (literal), else why
    not. The words it accepts hold no space or quote but the repository's, so the flattened line splits into them exactly."""
    if not flat.startswith(_GH_PREFIX):
        return 'the line is not gh release download "$ver" ... (another tag variable, an unquoted tag or another command)'
    words, i, n = flat[len(_GH_PREFIX):].split(" "), 0, {"--repo": 0, "-p": 0, "-D": 0}
    while i < len(words):
        w, v = words[i], (words[i + 1] if i + 1 < len(words) else "")
        if w not in n:
            return f"the word {w[:40]!r} is not one of --repo \"$GITHUB_REPOSITORY\", -p NAME, -D PATH"
        if w == "--repo" and v != _GH_REPO:
            return f'--repo must be the literal text "$GITHUB_REPOSITORY" (this repository), not {v[:60]!r}'
        if w == "-p" and not (_ASSET.fullmatch(v) or v[:1] == v[-1:] == '"' and _ASSET.fullmatch(v[1:-1]) or _ASSET_VER.fullmatch(v) and not v.startswith('"-')):
            return f'-p takes a literal exact asset name, or one whose only expansion is ${{ver}} inside double quotes (no glob, other variable or substitution), not {v[:60]!r}'
        if w == "-D" and not _LITPATH.fullmatch(v):
            return f"-D takes a literal path (no glob, variable or quote), not {v[:60]!r}"
        n[w] += 1
        i += 2
    if n["--repo"] != 1 or n["-p"] < 1 or n["-D"] > 1:
        return f'the line needs exactly one --repo "$GITHUB_REPOSITORY", at least one -p and at most one -D (has {n["--repo"]}, {n["-p"]}, {n["-D"]})'
    return None


def _run_texts(doc):
    """Every run: script in a parsed workflow or action (the steps)."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == "run" and isinstance(v, str):
                yield v
            else:
                yield from _run_texts(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from _run_texts(v)


def _ver_unchecked(root, head, path, flat):
    """None when, in every step that holds the line (the file for a .sh script, the run: block for a workflow or action), the line IMMEDIATELY before it is
    a check of $ver against the release tag pattern that exits on a mismatch, that check line continues no line, and the step text before it holds no
    heredoc and no unbalanced quote; else why not."""
    text = _head_text(root, head, path)
    if text is None:
        return f"{path} is not a file in the head tree"
    if path.endswith(".sh"):
        steps = [text]
    elif path.endswith((".yml", ".yaml")):
        try:
            steps = list(_run_texts(inv.yaml.safe_load(text)))
        except inv.yaml.YAMLError:
            return f"{path} does not parse"
    else:
        return f"{path} is neither a shell script nor a workflow or action"
    seen = 0
    for step in steps:
        lines = step.split("\n")
        for pos, line in enumerate(lines):
            if " ".join(line.split()) != flat:
                continue
            seen += 1
            if pos == 0 or not _VER_CHECK.fullmatch(" ".join(lines[pos - 1].split())):
                return "the line before the download is not a check of $ver against the release tag pattern that exits on a mismatch"
            if pos >= 2 and lines[pos - 2].rstrip().endswith("\\"):
                return "the tag check continues the line before it"
            before = "\n".join(lines[:pos - 1])
            if "<<" in before:
                return "the step holds a heredoc before the tag check (the check could be data)"
            try:
                lex = shlex.shlex(before, posix=True)
                lex.whitespace_split = True
                list(lex)
            except ValueError:
                return "the step text before the tag check does not read as shell words (an unbalanced quote)"
    return None if seen else f"the line is not in a run: step of {path}"


def _head_text(root, head, path):
    """The text of a regular file in the head tree, or None (missing, a link, a directory, unreadable or too large: never a pass)."""
    try:
        r = subprocess.run(["git", "-C", root, "ls-tree", "-z", head, "--", path], capture_output=True, text=True, timeout=GH_TIMEOUT)
        meta, _, name = r.stdout.rstrip("\0").partition("\t")
        if r.returncode or name != path or "\0" in name or meta.split()[:2] not in (["100644", "blob"], ["100755", "blob"]):
            return None
        b = subprocess.run(["git", "-C", root, "cat-file", "blob", meta.split()[2]], capture_output=True, text=True, errors="replace", timeout=GH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None
    return None if b.returncode or len(b.stdout) > inv.MAX_FILE else b.stdout


def _defines(text, name):
    """True when TEXT defines function NAME: shell (name() or function name), Python (def name() or Go (func name( / func (r T) name()."""
    n = re.escape(name)
    return bool(re.search(rf"(?m)^[ \t]*(?:function[ \t]+{n}(?![\w-])|{n}[ \t]*\([ \t]*\)|(?:async[ \t]+)?def[ \t]+{n}[ \t]*\(|"
                          rf"func[ \t]+(?:\([^)\n]*\)[ \t]*)?{n}[ \t]*[\[(])", text))


def _fetch_unverified(root, head, row, flat):
    """None when the head satisfies an input-fetch row (REQ-SUP-001-AC19), else why not: the address rule (b) on the download command and on the whole
    line, the lock (a lock row), the verifier and the test (a), all read from the head tree."""
    seg = next((s for s in _SEGMENTS.split(flat) if hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16] == row["key"]), None)
    if not flat or seg is None:
        return "the ruled download command is not on the line"
    host = row["host"]
    for m in re.finditer(r"([A-Za-z0-9+.-]*)://", flat):
        if host.startswith(("lock:", "repo:")) or m.group(1) != "https" or not flat[m.end():].startswith(host + "/"):
            return f"the line names an address other than https://{host}/" if not host.startswith(("lock:", "repo:")) else f"a {host.split(':')[0]} row's line names an address"
    why = (_gh_unruled(flat) or _ver_unchecked(root, head, row["file"], flat)) if host == REPO_SELF else _address_unruled(seg, host)
    if why:
        return why
    if host.startswith("lock:"):
        lock = _head_text(root, head, host[5:])
        if lock is None:
            return f"the lock {host[5:]} is not a file in the head tree"
        schemes = re.findall(r"([A-Za-z0-9+.-]*)://", lock)
        if not schemes or any(s != "https" for s in schemes):
            return f"the lock {host[5:]} holds an address that is not https:// (or none)"
    v, t = row["verifier"], row["test"]
    vt = _head_text(root, head, v["file"])
    if vt is None:
        return f"the verifier file {v['file']} is not a file in the head tree"
    if "function" in v and not _defines(vt, v["function"]):
        return f"the verifier file {v['file']} does not define {v['function']}"
    if "line" in v and " ".join(v["line"].split()) not in {" ".join(x.split()) for x in vt.split("\n")}:
        return f"the verifier file {v['file']} holds no line {v['line'][:80]!r}"
    tt = _head_text(root, head, t["file"])
    if tt is None:
        return f"the test file {t['file']} is not a file in the head tree"
    if t["case"] not in tt:
        return f"the test file {t['file']} has no case {t['case'][:80]!r}"
    return None


def _verifier_label(row):
    v = row["verifier"]
    return f"{v['file']}:{v.get('function') or v.get('line', '')[:60]}"


def _run(a, moved, fx, now):
    path = a.exceptions or DEFAULT_EXCEPTIONS
    rulings = load_ruled_text(path, required=bool(a.exceptions))   # before the scan: a malformed list stops the check
    fetches = load_input_fetch(path, required=bool(a.exceptions))
    both = sorted(set(rulings) & set(fetches))
    if both:
        raise RuntimeError(f"{path}: the row {both[0]} is in both unmeasured_text and unmeasured_input_fetch: an item is ruled by exactly one list")
    held, flats = {}, {}
    lines = _unmeasured_counts(a.root, a.base, a.head, held, flats)
    added, ruled, fetched = [], [], []
    for k in sorted(lines):
        text = _covered(rulings, k, lines[k])
        fetch = None if text else _covered(fetches, k, lines[k])    # an item is ruled by ONE list: lines split between the two lists are not ruled
        if text:
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in text))))
        elif fetch:
            why = next((w for w in (_fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), "")) for lh, r in zip(lines[k], fetch)) if w), None)
            if why:
                added.append((k, why))
            else:
                fetched.append((k, "; ".join(dict.fromkeys(r[0] for r in fetch)), ", ".join(dict.fromkeys(_verifier_label(r[2]) for r in fetch))))
        else:
            added.append((k, None))
    # a ruled fetch the head still holds must still be verified, though this pull request adds nothing to it (one that removes its verifier or test fails)
    named = {k for k, _ in added}
    for k, per in sorted(held.items()):
        for lh in per:
            r = fetches.get((k[0], k[1], k[2].split(":", 1)[0], lh))
            if k in named or lh in lines.get(k, {}) or not r:
                continue
            why = _fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), ""))
            if why:
                added.append((k, why))
                named.add(k)
    if not moved and not added:
        print("pin-age: no pin moved (nothing to measure)")
        rows = []
    else:
        rows = check(moved, Fixture(fx) if fx is not None else Live(a.root, a.base, a.head), now, a.min_days)
        print(f"pin-age: {len(rows)} moved version(s), each must be public {a.min_days:g} days by a server-side time:")
        for r in rows:
            print(f"  {'ok  ' if r['ok'] else 'FAIL'} {r['item']}: {r['reason']}")
    for (path, what, line), why in added:
        if why is None:
            rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False, "proof": None,
                         "reason": f"{what} was added to {path} ({line[:100]}): this check cannot measure it, so a pull request that adds one is refused (use a pinned form it can measure)"})
            print(f"  FAIL unmeasured:{path}: {what} added: not measurable, refused")
        else:
            rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False, "proof": None,
                         "reason": f"{what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_input_fetch, but the head does not hold what the row requires: {why}"})
            print(f"  FAIL unmeasured:{path}: {what} ({line[:60]}): input fetch not verified (REQ-SUP-001-AC19): {why}")
    for (path, what, line), ruling in ruled:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": True, "proof": None,
                     "reason": f"ruled text: {what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_text: {ruling[:200]}"})
        print(f"  ok   unmeasured:{path}: {what} ({line[:60]}): ruled text (REQ-SUP-001-AC16): {ruling[:200]}")
    for (path, what, line), ruling, verifier in fetched:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": True, "proof": None,
                     "reason": f"ruled input fetch: {what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_input_fetch, verified by {verifier}: {ruling[:200]}"})
        print(f"  ok   unmeasured:{path}: {what} ({line[:60]}): ruled input fetch (REQ-SUP-001-AC19), verified by {verifier}: {ruling[:200]}")
    failing = [r for r in rows if not r["ok"]]
    if a.json:
        json.dump({"min_days": a.min_days, "moved": rows}, open(a.json, "w"), indent=1)
    if failing:
        print(f"pin-age: FAIL: {len(failing)} of {len(rows)} moved version(s) too young or unprovable; the check turns green when each is {a.min_days:g} days old")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
