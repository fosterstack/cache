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


def _load_rows(path, name, fields, required=False, check=None, optional=("count",)):
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
        if not isinstance(r, dict) or set(r) - set(fields) - set(optional) or not set(fields) <= set(r):
            raise bad(f"must be an object with exactly {', '.join(fields)} (and optionally {', '.join(optional)})")
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
_CODE_FILE = (".sh", ".py", ".go")
_WF_FILE = (".yml", ".yaml")
MIN_CASE = 12


def _rel_path(p):
    """A relative path inside the repository: no leading /, no empty, . or .. component, no backslash, whitespace or control character."""
    return (isinstance(p, str) and 0 < len(p) <= 512 and not p.startswith("/") and "\\" not in p
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in p) and all(c not in ("", ".", "..") for c in p.split("/")))


def _check_fetch_row(r, bad):
    """The AC19 fields, beyond AC16's: form, host, verifier, test and the optional redirects, each strict."""
    h = r["host"]
    if h == REPO_SELF:
        if r["form"] != GH_FORM or r["key"] != r["line"]:
            raise bad(f"host {REPO_SELF} is only for the form '{GH_FORM}' (whose key is the whole-line hash, so key equals line)")
    elif r["form"] != "a download":
        raise bad(f"form is not 'a download' (a curl download), nor '{GH_FORM}' with host {REPO_SELF}")
    elif not isinstance(h, str) or not _HOST.fullmatch(h):
        raise bad(f"host is neither a lower-case DNS name with a dot (no scheme, port, path or user) nor {REPO_SELF} (a lock: host is not accepted)")
    if "redirects" in r and (r["redirects"] is not True or h == REPO_SELF):
        raise bad("redirects, when present, is the value true, on a curl row (a download that follows redirects)")
    v = r["verifier"]
    if not isinstance(v, dict) or set(v) not in ({"file", "function"}, {"file", "line"}):
        raise bad("verifier must be an object with file and exactly one of function or line")
    if not _rel_path(v["file"]) or not (v["file"].endswith(_CODE_FILE) or "line" in v and v["file"].endswith(_WF_FILE)):
        raise bad("verifier file is not a relative path to a shell, Python or Go file (or, for the line form only, a workflow or action)")
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
    """The unmeasured_input_fetch rows (REQ-SUP-001-AC19): AC16's row plus host, verifier, test and the optional redirects."""
    return _load_rows(path, "unmeasured_input_fetch", _FETCH_FIELDS, required, _check_fetch_row, optional=("count", "redirects"))


def _covered(rows, k, per):
    """The rows of one list that rule item k: one per added whole line, when EVERY added (key, whole line) is named by a row and its head occurrences are
    within that row's count (1 unless it says more); else None. The same segment inside any other line, an edited line, or one copy too many leaves the
    item refused (REQ-SUP-001-AC16; the same rule for AC19)."""
    rs = [rows.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in per]
    return rs if all(r and n <= r[1] for r, n in zip(rs, per.values())) else None


# --- REQ-SUP-001-AC19: what the head must hold for a ruled input fetch. Everything is CLOSED: a shape, a word or a context this reader does not know
# is refused, never skipped (fail closed). ---------------------------------------------------------------------------------------------------------------
_SEGMENTS = re.compile(r"\s*(?:;|&&|\|\||\|)\s*")      # the scan's own split of a line into commands (pin-inventory.unmeasured_occurrences)
_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_DENIED = re.compile(r"(?:GITHUB_ENV|GITHUB_PATH|GITHUB_OUTPUT|GITHUB_STEP_SUMMARY|GITHUB_STATE|GITHUB_WORKSPACE|RUNNER_TEMP|IFS|CDPATH|PS4|PROMPT_COMMAND|SHELLOPTS|BASHOPTS"
                     r"|HOME|PATH|BASH_ENV|ENV|CURL_HOME|XDG_CONFIG_HOME|SSL_CERT_FILE|NODE_OPTIONS"
                     r"|LD_\w*|PYTHON\w*)", re.I)
_SHELL_KEYS = {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"}
_ENV_PREFIX_DENY = ("GH_", "GIT_", "SSL_", "SIGSTORE_", "TUF_", "OPENSSL_", "CURL_", "PYTHON", "LD_", "DYLD_")
_TOKEN_VALUES = {"${{ github.token }}", "${{ secrets.GITHUB_TOKEN }}"}
_SELF_ENV = {"GH_TOKEN": _TOKEN_VALUES, "VER": {"${{ github.ref_name }}"}}   # the ONLY env: of a repo:self step, with these values only
_ENV_VALUES = _TOKEN_VALUES | {"${{ github.ref_name }}"}                    # the only ${{ }} an env: value of a ruled step may hold
_ENV_DENY = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "CURL_CA_BUNDLE", "SSL_CERT_FILE",
             "SSL_CERT_DIR", "CURL_HOME", "XDG_CONFIG_HOME", "GH_HOST", "GH_REPO", "GH_ENTERPRISE_TOKEN", "BASH_ENV", "ENV", "PATH", "LD_PRELOAD",
             "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE"}
_CURL = {"letters": set("fsSLg"), "flags": {"--fail", "--fail-with-body", "--silent", "--show-error", "--location", "--globoff", "--compressed",
                                             "--create-dirs", "--retry-all-errors", "--retry-connrefused", "--http1.1", "--http2", "--tlsv1.2", "--tlsv1.3"},
         "output": {"-o", "--output"}, "number": {"--retry", "--retry-delay", "--retry-max-time", "--max-time", "-m", "--connect-timeout", "--max-filesize"},
         "proto": {"--proto", "--proto-redir"}, "redirs": {"--max-redirs"}}
_LITWORD = re.compile(r"[A-Za-z0-9_./:=+,%@-]+")
_RELPATH = r"[A-Za-z0-9_.][A-Za-z0-9_./-]*"
_URLCH = r"[A-Za-z0-9._~/%+,=:@-]"


def _names_ok(word):
    """Every $NAME or ${NAME} in WORD is a plain name that is not denied; no other expansion form remains."""
    rest = re.sub(r"\$\{(" + _NAME + r")\}|\$(" + _NAME + ")", lambda m: "\0" if not _DENIED.fullmatch(m.group(1) or m.group(2)) else "$", word)
    return "$" not in rest


def _no_dotdot(path):
    return ".." not in path.split("/")


def _output_ok(raw):
    """An output path: a literal relative path, or "$NAME", "${NAME}", "$NAME/lit", "${NAME}/lit" (NAME plain, not denied); no glob, no .., not absolute."""
    if re.fullmatch(_RELPATH, raw):
        return _no_dotdot(raw)
    m = re.fullmatch(r'"\$(?:\{(' + _NAME + r')\}|(' + _NAME + r'))(/[A-Za-z0-9_.-][A-Za-z0-9_./-]*)?"', raw)
    return bool(m) and not _DENIED.fullmatch(m.group(1) or m.group(2)) and _no_dotdot(m.group(3) or "")


def _address_ok(raw, host):
    """An address: https://<host>/ then a path of URL characters, unquoted (all literal) or in double quotes with $NAME / ${NAME} in the path only."""
    pre = f"https://{host}/"
    if raw.startswith(pre):
        return bool(re.fullmatch(_URLCH + "*", raw[len(pre):]))
    if raw.startswith('"' + pre) and raw.endswith('"') and len(raw) > len(pre) + 1:
        path = raw[len(pre) + 1:-1]
        return _names_ok(path) and bool(re.fullmatch(r"(?:" + _URLCH + r"|\$\{" + _NAME + r"\}|\$" + _NAME + ")*", path))
    return False


def _curl_unruled(words, host, row):
    """None when the curl command (raw words) is one this check reads, else why not: curl, -q or --disable FIRST (no ~/.curlrc), -g (no URL globbing),
    then only listed flags, a number, --proto/--proto-redir =https, -o with an output path, and addresses on the row's host; -L only with the row's
    redirects: true and --proto-redir =https."""
    if len(words) < 2 or words[0] != "curl" or words[1] not in ("-q", "--disable"):
        return "a ruled download is curl with -q (or --disable) as its FIRST argument, so no ~/.curlrc is read"
    i, urls, glob_off, follows, redir_https, max_redirs, proto_https = 2, [], False, False, False, False, False
    while i < len(words):
        w = words[i]
        i += 1
        if w in _CURL["flags"] or re.fullmatch(r"-[A-Za-z]+", w) and set(w[1:]) <= _CURL["letters"]:
            glob_off |= w == "--globoff" or (not w.startswith("--") and "g" in w)
            follows |= w == "--location" or (not w.startswith("--") and "L" in w)
            continue
        if w in _CURL["output"] | _CURL["number"] | _CURL["proto"] | _CURL["redirs"]:
            if i == len(words):
                return f"{w} has no value"
            v, i = words[i], i + 1
            if w in _CURL["number"] and not re.fullmatch(r"[0-9]{1,12}", v):
                return f"{w} takes a number"
            if w in _CURL["proto"] and v != "=https":
                return f"{w} must be =https"
            if w in _CURL["redirs"] and v != "3":
                return f"{w} must be exactly 3"
            max_redirs |= w in _CURL["redirs"]
            if w in _CURL["output"] and not _output_ok(v):
                return f"{w} names {v[:60]!r}: an output is a literal relative path or \"$NAME[/path]\" (no glob, no .., not absolute, not a denied name)"
            redir_https |= w == "--proto-redir"
            proto_https |= w == "--proto"
            continue
        if w.startswith("-"):
            return f"the option {w[:40]!r} is not one this check reads in a ruled download"
        if not _address_ok(w, host):
            return f"every address must start with https://{host}/ and expand only \"$NAME\" in its quoted path (no variable or other host, no glob): {w[:80]!r}"
        urls.append(w)
    if not urls:
        return "the download command names no address"
    if not glob_off:
        return "a ruled curl download needs -g (--globoff): no URL globbing"
    if not proto_https:
        return "a ruled curl download needs --proto =https"
    if follows and not (row.get("redirects") is True and redir_https and max_redirs):
        return "a download that follows redirects (-L) needs redirects: true on the row and --proto-redir =https and --max-redirs 3 on the line"
    if (row.get("redirects") is True or max_redirs) and not follows:
        return "the row says redirects: true, or the line says --max-redirs, but the line does not follow redirects"
    return None


def _shell_tokens(flat):
    """The raw words and operators of a shell line ([word | ('op', text)]), or a str saying why it cannot be read: single quotes, backslashes, backticks,
    command substitution, comments and unbalanced double quotes are refused."""
    out, i, cur = [], 0, None
    while i < len(flat):
        c = flat[i]
        if c in "'\\`" or flat.startswith("$(", i) or (c == "#" and cur is None):
            return "a single quote, backslash, backtick, command substitution or comment on the line"
        if c == '"':
            j = flat.find('"', i + 1)
            if j < 0:
                return "an unbalanced double quote"
            if any(x in flat[i + 1:j] for x in ("\\", "`", "$(")):
                return "a backslash, backtick or command substitution in double quotes"
            cur = (cur or "") + flat[i:j + 1]
            i = j + 1
            continue
        if c == " ":
            if cur is not None:
                out.append(cur)
                cur = None
            i += 1
            continue
        if c in ";&|<>()":
            if cur is not None:
                out.append(cur)
                cur = None
            op = flat[i:i + 2] if flat[i:i + 2] in ("||", "&&", ";;", ">>") else c
            out.append(("op", op))
            i += len(op)
            continue
        cur = (cur or "") + c
        i += 1
    if cur is not None:
        out.append(cur)
    return out


def _shell_shape(flat):
    """(the command's raw words, None) when the WHOLE line is one of the closed shapes: CMD | CMD || exit N | CMD || die "MSG" [N] |
    if CMD; then ok=1; break; fi (MSG without $); else (None, why not)."""
    toks = _shell_tokens(flat)
    if isinstance(toks, str):
        return None, toks
    semi = ("op", ";")
    if toks[:1] == ["if"]:
        if toks[-7:] != [semi, "then", "ok=1", semi, "break", semi, "fi"]:
            return None, "an if line must be exactly: if CMD; then ok=1; break; fi"
        cmd, tail = toks[1:-7], []
    else:
        n = next((j for j, t in enumerate(toks) if isinstance(t, tuple)), len(toks))
        cmd, tail = toks[:n], toks[n:]
    if any(isinstance(t, tuple) for t in cmd) or not cmd:
        return None, "the line holds another command, a pipe, a redirect or a subshell"
    num = lambda t: isinstance(t, str) and re.fullmatch(r"[1-9]", t)   # a failed fetch never exits 0
    msg = lambda t: isinstance(t, str) and re.fullmatch(r'"[A-Za-z0-9 .,:_-]*"', t)
    if tail and not (tail[0] == ("op", "||") and (len(tail) == 3 and tail[1] == "exit" and num(tail[2])
                                                    or tail[1:2] == ["die"] and (len(tail) == 3 and msg(tail[2]) or len(tail) == 4 and msg(tail[2]) and num(tail[3])))):
        return None, 'after the command the line may hold only || exit N or || die "MSG" [N] (no pipe, &&, ;, redirect or second command)'
    return cmd, None


def _python_words(flat):
    """The curl words of the closed Python form [NAME =] subprocess.run(["curl", "LIT", ..., NAME, "https://HOST/..%s.." % (NAMES)], stdout=sys.stderr,
    stderr=sys.stderr) as shell-like raw words, or a str saying why not. A NAME becomes "${NAME}"; a format string %s becomes ${NAME} in the quoted path."""
    import ast
    try:
        mod = ast.parse(flat)
    except (SyntaxError, ValueError):
        return "the line is not one Python statement"
    if len(mod.body) != 1:
        return "the line is not ONE Python statement"
    st = mod.body[0]
    call = st.value if isinstance(st, (ast.Expr, ast.Assign)) else None
    if isinstance(st, ast.Assign) and not (len(st.targets) == 1 and isinstance(st.targets[0], ast.Name)):
        return "the call is assigned to something other than one name"
    attr = lambda n, a, b: isinstance(n, ast.Attribute) and n.attr == b and isinstance(n.value, ast.Name) and n.value.id == a
    if not (isinstance(call, ast.Call) and attr(call.func, "subprocess", "run") and len(call.args) == 1 and isinstance(call.args[0], ast.List)):
        return "the line is not subprocess.run([...]) with one list"
    kws = [k.arg for k in call.keywords]
    if sorted(kws) != ["stderr", "stdout"] or not all(attr(k.value, "sys", "stderr") for k in call.keywords):
        return "subprocess.run takes exactly stdout=sys.stderr and stderr=sys.stderr here"
    words = []
    for e in call.args[0].elts:
        if isinstance(e, ast.Constant) and isinstance(e.value, str) and _LITWORD.fullmatch(e.value):
            words.append(e.value)
        elif isinstance(e, ast.Name):
            words.append('"${' + e.id + '}"')
        elif (isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mod) and isinstance(e.left, ast.Constant) and isinstance(e.left.value, str)
              and isinstance(e.right, (ast.Name, ast.Tuple))):
            names = [e.right] if isinstance(e.right, ast.Name) else e.right.elts
            fmt = e.left.value
            if not all(isinstance(n, ast.Name) for n in names) or "%" in fmt.replace("%s", "") or fmt.count("%s") != len(names) or "$" in fmt or '"' in fmt:
                return "a formatted address takes only %s, one plain name per %s"
            parts = fmt.split("%s")
            words.append('"' + "".join(p + ("${" + n.id + "}" if j < len(names) else "") for j, (p, n) in enumerate(zip(parts, names + [None]))) + '"')
        else:
            return "a list element is not a literal word, a name or a formatted address"
    return words


_PY_OPENER = re.compile(r'python3(?: -)?(?: (?:"\$' + _NAME + r'"|"\$\(cd "\$\(dirname "\$0"\)" && pwd\)"))* <<\'(' + _NAME + r')\'(?: \|\| exit \$\?)?')


def _heredocs(lines):
    """(shell line numbers, python line numbers) of a shell file, or None. The ONLY heredoc read is the exact opener python3 [-] ["$NAME" |
    "$(cd "$(dirname "$0")" && pwd)"]... <<'TAG' [|| exit $?] as a whole line (a quoted tag: no expansion in the body), whose body runs to a line that is
    exactly TAG; any other << anywhere outside such a body (a data heredoc, a here-string, a shift, a << in a comment or a string) makes the file
    unreadable (None): fail closed."""
    shell, py, i = [], [], 0
    while i < len(lines):
        m = _PY_OPENER.fullmatch(_flat(lines[i]))
        if m:
            shell.append(i)
            i += 1
            while i < len(lines) and lines[i] != m.group(1):
                py.append(i)
                i += 1
            if i == len(lines):
                return None
            i += 1
            continue
        if "<<" in lines[i]:
            return None
        shell.append(i)
        i += 1
    return shell, py


def _contexts(text, path):
    """{"shell": [list of step line lists], "python": [line list]} : where a line runs. A .sh file is one shell step (outside heredocs) and the python3
    heredoc bodies; a workflow or action gives one shell step per run: block, and is refused when anything there changes the shell (a shell: other than
    bash, or a BASH_ENV, ENV, SHELLOPTS or BASHOPTS key anywhere). Else a str saying why not."""
    lines = text.split("\n")
    if path.endswith(".sh"):
        hd = _heredocs(lines)
        if hd is None:
            return f"{path} holds a << this check does not read (only the exact python3 - ... <<'TAG' opener is read): it rules nothing"
        if "${{" in text:
            return f"{path} holds ${{{{: it rules nothing"
        shell, py = hd
        return {"shell": [[lines[i] for i in shell]], "python": [lines[i] for i in py], "raw": [lines]}
    if path.endswith(_WF_FILE):
        try:
            doc = inv.yaml.safe_load(text)
        except inv.yaml.YAMLError:
            return f"{path} does not parse"
        bad = []

        def walk(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    if k in _SHELL_KEYS or (k == "shell" and v != "bash"):
                        bad.append(k)
                    if k == "env":
                        if not isinstance(v, dict):
                            bad.append("a non-mapping env:")
                        else:
                            bad.extend(x for x, y in v.items() if not isinstance(x, str) or x in _ENV_DENY
                                       or x.startswith(_ENV_PREFIX_DENY) and not (x == "GH_TOKEN" and y in _TOKEN_VALUES))
                    walk(v)
            elif isinstance(d, list):
                for v in d:
                    walk(v)
        walk(doc)
        if bad:
            return f"{path} sets {bad[0]} (only bash run: steps are read; every env: is a mapping and none sets a proxy, CA, gh, git, ssl, sigstore, shell, PATH or loader variable)"
        steps = list(_steps(doc))
        runs = [s["run"].split("\n") for s in steps]
        return {"shell": runs, "python": [], "raw": runs, "steps": steps, "doc": doc}
    return f"{path} is neither a shell script nor a workflow or action"


def _off(d):
    """True when a step or job never runs or never fails the job: if: false (literal), or continue-on-error other than false."""
    return d.get("if") in (False, "false", "${{ false }}") or d.get("continue-on-error", False) not in (False, "false")


def _steps(doc):
    """The run: steps that bash runs: jobs.<id>.steps[*] of a workflow (shell: absent or bash, on a job whose runs-on is literal and names no windows
    runner unless the step says shell: bash) and runs.steps[*] of a composite action (shell: bash, required); never a step or job that is off (_off)."""
    if not isinstance(doc, dict):
        return
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict) or _off(job) or not isinstance(job.get("steps"), list):
                continue
            ro = job.get("runs-on")
            ro = ro if isinstance(ro, list) else [ro]
            linux = all(isinstance(x, str) and "${{" not in x and "windows" not in x.lower() and "macos" not in x.lower() for x in ro)
            for s in job["steps"]:
                if isinstance(s, dict) and isinstance(s.get("run"), str) and not _off(s) and (s.get("shell") == "bash" or "shell" not in s and linux):
                    yield s
    runs = doc.get("runs")
    if isinstance(runs, dict) and runs.get("using") == "composite" and isinstance(runs.get("steps"), list):
        for s in runs["steps"]:
            if isinstance(s, dict) and isinstance(s.get("run"), str) and not _off(s) and s.get("shell") == "bash":
                yield s


def _step_exprs_bad(step):
    """Why a ruled step may not be read, or None: ${{ }} anywhere outside its env: values (expanded by GitHub before bash), or an env: value holding
    an expression other than ${{ github.token }}, ${{ secrets.GITHUB_TOKEN }} or ${{ github.ref_name }}."""
    def strings(d):
        if isinstance(d, dict):
            for k, v in d.items():
                yield str(k)
                yield from strings(v)
        elif isinstance(d, list):
            for v in d:
                yield from strings(v)
        elif isinstance(d, str):
            yield d
    if any("${{" in x for k, v in step.items() if k != "env" for x in strings({k: v})):
        return "the ruled step holds ${{ outside its env: values (expanded by GitHub before bash)"
    env = step.get("env") or {}
    if any(isinstance(v, str) and "${{" in v and v not in _ENV_VALUES for v in env.values()):
        return "an env: value of the ruled step holds an expression other than ${{ github.token }}, ${{ secrets.GITHUB_TOKEN }} or ${{ github.ref_name }}"
    return None


def _run_texts(doc):
    """The run: scripts that bash runs in a parsed workflow or action (see _steps)."""
    for s in _steps(doc):
        yield s["run"]


_flat = lambda s: " ".join(s.split())

# --- the authenticated draft download (host repo:self; the AC19 amendment, advisor Oct 10 step 5) ---------------------------------------------------------
_GH_PREFIX = 'gh release download "$ver" '
_GH_REPO = '"$GITHUB_REPOSITORY"'
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")     # a literal exact asset name: no glob (* ? [ ] { }), no variable, no quote
_ASSET_VER = re.compile(r'"(?:[A-Za-z0-9._+-]|\$\{ver\})*\$\{ver\}(?:[A-Za-z0-9._+-]|\$\{ver\})*"')   # "...${ver}...": ${ver} the ONLY expansion
_DIR = re.compile(r"(?:/tmp/)?[A-Za-z0-9_][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_][A-Za-z0-9_.-]*)*")   # /tmp/<name> or a relative name: every segment starts with a letter, digit or _ (no ., .., -, ~)
_TAG_RES = (r"^v[0-9]+\.[0-9]+\.[0-9]+$", r"^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$")
_TAG_RE = "(?:" + "|".join(re.escape(x) for x in _TAG_RES) + ")"
_VER = r'(?:"\$ver"|\$ver)'
_MSGTEXT = r'(?:"[A-Za-z0-9 .,:_-]*"|[A-Za-z0-9.,:_-]+(?: [A-Za-z0-9.,:_-]+)*)'   # letters, digits, space and . , : _ - only (no #, quote, $, ...)
_MSG = rf"(?:(?:echo|printf) {_MSGTEXT}(?: >&2)?; )?"
_VER_CHECK = re.compile(rf"\[\[ {_VER} =~ {_TAG_RE} \]\] \|\| (?:exit [1-9][0-9]?|\{{ {_MSG}exit [1-9][0-9]?; \}})"
                        rf"|if \[\[ ! {_VER} =~ {_TAG_RE} \]\]; then {_MSG}exit [1-9][0-9]?; fi")
_PRE_LINES = re.compile(r"|#.*[^\\]|#|set -eu|set -euo pipefail|ver=\"\$(?:\{(" + _NAME + r")\}|(" + _NAME + r"))\"|mkdir (?:-p )?(" + _DIR.pattern + ")")


def _gh_unruled(flat):
    """None when the line is EXACTLY gh release download "$ver" --repo "$GITHUB_REPOSITORY" with one or more -p NAME and at most one -D PATH, else why
    not. -p NAME: a literal exact asset name, or one in double quotes whose only expansion is ${ver}; -D PATH: /tmp/<name> or a relative name."""
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
        if w == "-D" and not _DIR.fullmatch(v):
            return f"-D takes /tmp/<name> or a relative name (no variable, glob, . or ..), not {v[:60]!r}"
        n[w] += 1
        i += 2
    if n["--repo"] != 1 or n["-p"] < 1 or n["-D"] > 1:
        return f'the line needs exactly one --repo "$GITHUB_REPOSITORY", at least one -p and at most one -D (has {n["--repo"]}, {n["-p"]}, {n["-D"]})'
    return None


def _ver_unchecked(steps, flat):
    """None when, in every step that holds the download line, the line IMMEDIATELY before it checks $ver against the release tag pattern and exits on
    a mismatch, and EVERY line before that check is one of the closed list: blank, a comment (not ending in a backslash), set -eu, set -euo pipefail,
    ver="$NAME" (NAME plain, not denied), mkdir [-p] PATH (/tmp/<name> or a relative name); else why not."""
    seen = 0
    for lines in steps:
        for pos, line in enumerate(lines):
            if _flat(line) != flat:
                continue
            seen += 1
            if pos == 0 or not _VER_CHECK.fullmatch(_flat(lines[pos - 1])):
                return "the line before the download is not a check of $ver against the release tag pattern that exits on a mismatch"
            for before in lines[:pos - 1]:
                m = _PRE_LINES.fullmatch(_flat(before))
                if not m or (m.group(1) or m.group(2) or "") and _DENIED.fullmatch(m.group(1) or m.group(2)) or "\r" in before:
                    return f"the step holds {_flat(before)[:60]!r} before the tag check: only blank lines, comments, set -eu[o pipefail], ver=\"$NAME\" and mkdir [-p] PATH may"
    return None if seen else "the line is not in a step that runs it"


def _head_bytes(root, head, path):
    """The bytes of a regular file in the head tree, or None (missing, a link, a directory, unreadable or too large: never a pass)."""
    try:
        r = subprocess.run(["git", "-C", root, "ls-tree", "-z", head, "--", path], capture_output=True, timeout=GH_TIMEOUT)
        meta, _, name = r.stdout.rstrip(b"\0").partition(b"\t")
        if r.returncode or name != path.encode() or meta.split()[:2] not in ([b"100644", b"blob"], [b"100755", b"blob"]):
            return None
        b = subprocess.run(["git", "-C", root, "cat-file", "blob", meta.split()[2].decode()], capture_output=True, timeout=GH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return None
    return None if b.returncode or len(b.stdout) > inv.MAX_FILE else b.stdout


def _raw_refusal(root, head, path):
    """Why a file can rule nothing (REQ-SUP-001-AC16 and AC19), or None: it must be a regular UTF-8 file with no carriage return (a lone CR splits a line
    for this reader but not for bash)."""
    data = _head_bytes(root, head, path)
    if data is None:
        return f"{path} is not a regular file in the head tree"
    if b"\r" in data:
        return f"{path} holds a carriage return (a lone CR hides text from the line split; CRLF too): it rules nothing"
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return f"{path} is not UTF-8: it rules nothing"
    return None


def _head_text(root, head, path):
    data = _head_bytes(root, head, path)
    if data is None or b"\r" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


_TRIVIAL = {"", ":", "true", "return", "return 0", "return None", "return True", "return nil", "pass", "..."}


def _body_real(lines):
    """True when a function body holds a statement other than :, true, pass, ..., a bare return, a comment or a string."""
    for x in lines:
        s = x.split("#", 1)[0] if not x.lstrip().startswith(("'", '"')) else ""
        for part in s.split(";"):
            if part.strip() not in _TRIVIAL:
                return True
    return False


def _bodies(text, path, name):
    """[(language, body lines)] for every definition of function NAME as CODE with a real body: a shell function outside heredocs (.sh), a Python def
    at column 0 in a .py file or in the body of a python3 heredoc with a quoted tag (.sh), a Go func at column 0 (.go)."""
    lines, n, out = text.split("\n"), re.escape(name), []
    if path.endswith(".sh"):
        hd = _heredocs(lines)
        if hd is None:
            return []
        shell, py = hd
        sl = [lines[i] for i in shell]
        for j, x in enumerate(sl):
            m = re.match(rf"[ \t]*(?:function[ \t]+{n}(?:[ \t]*\([ \t]*\))?|{n}[ \t]*\([ \t]*\))[ \t]*\{{(.*)$", x)
            if not m:
                continue
            rest = m.group(1)
            if rest.rstrip().endswith("}"):
                body = [rest.rstrip()[:-1]]
            else:
                body = [rest]
                for y in sl[j + 1:]:
                    if y.strip() == "}":
                        break
                    body.append(y)
            if _body_real(body):
                out.append(("sh", body))
        return out + _py_bodies([lines[i] for i in py], n)
    if path.endswith(".py"):
        return _py_bodies(lines, n)
    if path.endswith(".go"):
        for j, x in enumerate(lines):
            if re.match(rf"func (?:\([^)\n]*\) )?{n}[\[(]", x):
                body = []
                for y in lines[j + 1:]:
                    if y.startswith("}"):
                        break
                    body.append(y)
                if _body_real(body):
                    out.append(("go", body))
    return out


def _py_bodies(lines, n):
    out = []
    for j, x in enumerate(lines):
        if re.match(rf"(?:async )?def {n}\(", x):
            body = []
            for y in lines[j + 1:]:
                if y.strip() and not y[:1].isspace():
                    break
                body.append(y)
            if _body_real(body):
                out.append(("py", [x] + body))
    return out


def _defines(text, path, name):
    return bool(_bodies(text, path, name))


_IDENT = ("--certificate-identity", "--certificate-identity-regexp")
_ISSUER = ("--certificate-oidc-issuer",)


def _has_flags(words):
    has = lambda names: any(w in names or w.split("=", 1)[0] in names and "=" in w for w in words)
    return has(_IDENT) and has(_ISSUER)


_INSECURE = ("--insecure-ignore-tlog", "--insecure-ignore-sct")


def _sh_signature(lines):
    """True when the shell lines run cosign verify-blob with --certificate-identity[-regexp] and --certificate-oidc-issuer as the COMMAND words of a
    simple command (after if, !, then, {, elif, while, until, do or else only), read with the quote-aware tokenizer: never text in a string, an
    assignment value or an echo argument. Continuations are joined and comment lines dropped; a line the tokenizer cannot read (a quote spanning lines,
    a single quote, a backslash, a substitution, an inline comment) makes the whole body no signature (fail closed). --insecure-ignore-tlog and
    --insecure-ignore-sct are never a signature check."""
    joined = re.sub(r"\\\n[ \t]*", " ", "\n".join(lines))
    found = False
    for line in joined.split("\n"):
        flat = _flat(line)
        if not flat or flat.startswith("#"):
            continue
        toks = _shell_tokens(flat)
        if isinstance(toks, str):
            return False
        cmds, cur = [], []
        for tk in toks:
            if isinstance(tk, tuple):
                cmds.append(cur)
                cur = []
            else:
                cur.append(tk)
        cmds.append(cur)
        for words in cmds:
            while words and words[0] in ("if", "!", "then", "{", "}", "elif", "while", "until", "do", "else", "fi", "done"):
                words = words[1:]
            if (words[:2] == ["cosign", "verify-blob"] and _has_flags(words)
                    and not any(w.split("=", 1)[0] in _INSECURE for w in words)):
                found = True
    return found


_PY_RUNNERS = ("run", "check_call", "check_output", "call")


def _py_signature(lines):
    """True when the Python def CALLS subprocess.run|check_call|check_output|call (that exact name, no alias) on a list whose first items are the
    literals "cosign", "verify-blob" and that holds both identity and issuer flags (and no --insecure-ignore-*), the call not nested in a lambda, an
    inner def or a class, and not an argument of another call."""
    import ast, textwrap
    try:
        tree = ast.parse(textwrap.dedent("\n".join(lines)))
    except (SyntaxError, ValueError):
        return False
    fn = next((n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
    if fn is None:
        return False

    def visit(node, in_arg):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)) and node is not fn:
            return False
        if isinstance(node, ast.Call):
            f = node.func
            if (not in_arg and isinstance(f, ast.Attribute) and f.attr in _PY_RUNNERS and isinstance(f.value, ast.Name) and f.value.id == "subprocess"
                    and node.args and isinstance(node.args[0], ast.List)):
                elts = node.args[0].elts
                words = [e.value for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if (len(elts) >= 2 and all(isinstance(e, ast.Constant) and e.value == w for e, w in zip(elts[:2], ("cosign", "verify-blob"))) and _has_flags(words)
                        and not any(w.split("=", 1)[0] in _INSECURE for w in words)):
                    return True
            return any(visit(c, True) for c in list(node.args) + [k.value for k in node.keywords]) or visit(node.func, in_arg)
        return any(visit(c, in_arg) for c in ast.iter_child_nodes(node))
    return any(visit(s, False) for s in fn.body)


def _signature_unverified(vt, v):
    """None when the verifier of a redirects row is a SIGNATURE check (advisor ruling 3b), else why not: a function whose body runs cosign verify-blob
    with the certificate identity and issuer (shell or Python), or a line verifier that is such a shell command; checksum-only checks are not enough."""
    why = (f"a redirects row needs a signature check: the verifier {v['file']}:{v.get('function') or 'line'} does not run cosign verify-blob with"
           " --certificate-identity[-regexp] and --certificate-oidc-issuer as code (a checksum, a comment, a heredoc or an echo string is not enough)")
    if "function" in v:
        ok = any(_sh_signature(b) if lang == "sh" else _py_signature(b) if lang == "py" else False for lang, b in _bodies(vt, v["file"], v["function"]))
    else:   # a line verifier of a redirects row: a shell command, in a .sh file or a run: line of a workflow or action only
        ok = v["file"].endswith((".sh",) + _WF_FILE) and _sh_signature([v["line"]]) and not _flat(v["line"]).startswith("#")
    return None if ok else why


def _code_lines(text, path):
    """The lines a verifier LINE may be: code, never a comment. A .sh file: outside heredocs, or in a python3 heredoc (none at all if the file holds
    a << this reader does not read); a workflow or action: the lines of its bash run: blocks that hold no << and no ${{ (none if the file sets a shell,
    a shell variable or a denied env: key); .py and .go: every line."""
    lines = text.split("\n")
    if path.endswith(".sh"):
        hd = _heredocs(lines)
        out = [] if hd is None else [lines[i] for i in sorted(hd[0] + hd[1])]
    elif path.endswith(_WF_FILE):
        ctx = _contexts(text, path)
        out = [] if isinstance(ctx, str) else [x for s in ctx["steps"] if "<<" not in s["run"] and "${{" not in s["run"] and not _step_exprs_bad(s)
                                               for x in s["run"].split("\n")]
    else:
        out = lines
    return [x for x in out if not _flat(x).startswith(("#", "//"))]


def _fetch_unverified(root, head, row, flat, held_n):
    """None when the head satisfies an input-fetch row (REQ-SUP-001-AC19), else why not: the closed line shapes and words, the contexts every copy of
    the line sits in (all held_n of them), the verifier and the test, all read from the head tree."""
    H = lambda s: hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]
    seg = (flat if H(flat) == row["key"] else None) if row["form"] == GH_FORM else next((s for s in _SEGMENTS.split(flat) if H(s) == row["key"]), None)
    if not flat or seg is None:
        return "the ruled download command is not on the line"
    if held_n > row.get("count", 1):
        return f"the head holds the line {held_n} times, more than the row's count {row.get('count', 1)}"
    host, path = row["host"], row["file"]
    text = _head_text(root, head, path)
    if text is None:
        return f"{path} is not a readable regular file in the head tree"
    ctx = _contexts(text, path)
    if isinstance(ctx, str):
        return ctx
    if host != REPO_SELF:
        for m in re.finditer(r"([A-Za-z0-9+.-]*)://", flat):
            if m.group(1) != "https" or not flat[m.end():].startswith(host + "/"):
                return f"the line names an address other than https://{host}/"
    pyform = re.match(r"(?:" + _NAME + r" = )?subprocess\.run\(", flat)
    kind = "python" if pyform else "shell"
    where = ctx["python"] if pyform else [x for step in ctx["shell"] for x in step]
    if path.endswith(_WF_FILE):
        holding = [s for s in ctx["steps"] if any(_flat(x) == flat for x in s["run"].split("\n"))]
        if any("${{" in s["run"] or "<<" in s["run"] for s in holding):
            return "a run: block holding the line holds ${{ (expanded by GitHub before bash) or a <<: it rules nothing"
        why = next((w for w in map(_step_exprs_bad, holding) if w), None)
        if why:
            return why
        if host == REPO_SELF:
            for s in holding:
                env = s.get("env") or {}
                if any(k not in _SELF_ENV or v not in _SELF_ENV[k] for k, v in env.items()):
                    return "a repo:self step's env: holds only GH_TOKEN (${{ github.token }} or ${{ secrets.GITHUB_TOKEN }}) and VER (${{ github.ref_name }})"
            if re.search(r"(?m)^\s*GITHUB_[A-Za-z0-9_]*\s*:", text):
                return f"{path} sets a GITHUB_* variable: it rules no repo:self download"
    elif host == REPO_SELF and _flat(text.split("\n", 1)[0]) not in ("#!/bin/bash", "#!/usr/bin/env bash"):
        return f"{path} must start with #!/bin/bash or #!/usr/bin/env bash: the tag check [[ ... ]] is bash"
    if sum(1 for x in where if _flat(x) == flat) != held_n:
        return (f"every copy of the line must be {'in the body of a python3 heredoc with a quoted tag' if pyform else 'shell text: a run: step of bash, or a .sh file outside heredocs'}"
                f" ({kind} form)")
    if host == REPO_SELF:
        why = _gh_unruled(flat) or _ver_unchecked(ctx["raw"], flat)
    elif pyform:
        words = _python_words(flat)
        why = words if isinstance(words, str) else _curl_unruled(words, host, row)
    else:
        cmd, why = _shell_shape(flat)
        why = why or _curl_unruled(cmd, host, row)
    if why:
        return why
    v, t = row["verifier"], row["test"]
    vt = _head_text(root, head, v["file"])
    if vt is None:
        return f"the verifier file {v['file']} is not a readable regular file in the head tree"
    if "function" in v and not _defines(vt, v["file"], v["function"]):
        return f"the verifier file {v['file']} does not define {v['function']} as code with a real body"
    if "line" in v and _flat(v["line"]) not in {_flat(x) for x in _code_lines(vt, v["file"])}:
        return f"the verifier file {v['file']} holds no code line {v['line'][:80]!r}"
    if row.get("redirects") is True:
        why = _signature_unverified(vt, v)
        if why:
            return why
    tt = _head_text(root, head, t["file"])
    if tt is None:
        return f"the test file {t['file']} is not a readable regular file in the head tree"
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
        raw = _raw_refusal(a.root, a.head, k[0]) if text or fetch else None   # a file with a carriage return, or not UTF-8, rules nothing (AC16 and AC19)
        if raw:
            added.append((k, raw))
        elif text:
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in text))))
        elif fetch:
            why = next((w for w in (_fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), ""), held.get(k, {}).get(lh, 0))
                                    for lh, r in zip(lines[k], fetch)) if w), None)
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
            why = _raw_refusal(a.root, a.head, k[0]) or _fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), ""), per[lh])
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
                         "reason": f"{what} in {path} ({line[:100]}) is listed in the base branch's rulings, but the head does not hold what the row requires: {why}"})
            print(f"  FAIL unmeasured:{path}: {what} ({line[:60]}): input fetch not verified, or ruling not applied (REQ-SUP-001-AC16, AC19): {why}")
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
