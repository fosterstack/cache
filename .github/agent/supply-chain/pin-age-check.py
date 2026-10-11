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
import keyword
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
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--print-context"]:
        if len(argv) not in (3, 4):
            print("usage: pin-age-check.py --print-context FILE LINE [COUNT]", file=sys.stderr)
            return 2
        return print_context(*argv[1:])
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
    a group no row can name ('unruled:' + its hash)."""
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
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one (REQ-SUP-001-AC16)."""
    b, h = _occurrences(root, base), _occurrences(root, head, flats)   # held/flats (AC19): every head occurrence and its flattened line
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


def _load_rows(path, name, fields, required=False, check=None):
    """{(file, form, 16-hex segment hash, 16-hex whole-line hash): (ruling, count, row)} from the file's list NAME (one reader for AC16 and AC19). A missing
    default file is no rows; anything malformed raises RuntimeError (the check cannot run, exit 2): never 'nothing ruled' and never 'everything ruled'."""
    lists = "unmeasured_text, unmeasured_input_fetch"
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} ({lists}) does not exist")
        return {}
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)   # a repeated key would let a later copy silently win
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} ({lists}) is unreadable: {e}")
    rows = d.get(name, []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: {name} is not a list")
    out = {}
    for i, r in enumerate(rows):
        bad = lambda why, i=i: RuntimeError(f"{path}: {name} row {i} {why}")
        if not isinstance(r, dict) or set(r) - set(fields) - {"count"} or not set(fields) <= set(r):
            raise bad(f"must be an object with exactly {', '.join(fields)} (count optional for unmeasured_text)")
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


def _covered(rows, k, per):
    """The rows of one list that rule item k: one per added whole line, when EVERY added (key, whole line) is named by a row and its head occurrences are
    within that row's count; else None. The same segment inside any other line, an edited line, or one copy too many leaves the item refused (AC16)."""
    rs = [rows.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in per]
    return rs if all(r and n <= r[1] for r, n in zip(rs, per.values())) else None


# --- REQ-SUP-001-AC19 (AC19', the literal design; advisor step 5, Oct 11). A row names its line, the line's enclosing block (context), the literal host,
# ONE literal verifier line and a test case. Nothing is parsed as shell: the rows' reviewers read the lines; this check guarantees none of them changes.
_FETCH_FIELDS = _RULED_FIELDS + ("count", "context", "host", "verifier", "test")
REPO_SELF, GH_FORM = "repo:self", "a gh release or extension download"
_GH_SELF = 'gh release download "$ver" --repo "$GITHUB_REPOSITORY"'
_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
_TEST_FILE = re.compile(r"(?:^|/)(?:[^/]+-test\.sh|[^/]+_test\.go|[^/]+_test\.py|test_[^/]+\.py)$")
_WORKFLOW = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$|(?:^|/)action\.ya?ml$")
_SHEBANGS = ("#!/bin/bash", "#!/usr/bin/env bash")
_IDENT, _ISSUER = ("--certificate-identity", "--certificate-identity-regexp"), ("--certificate-oidc-issuer",)
_flat = lambda s: " ".join(s.split())


def _rel_path(p):
    return (isinstance(p, str) and 0 < len(p) <= 512 and not p.startswith("/") and "\\" not in p
            and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in p) and all(c not in ("", ".", "..") for c in p.split("/")))


def _check_fetch_row(r, bad):
    if not (isinstance(r["context"], str) and re.fullmatch(r"[0-9a-f]{64}", r["context"])):
        raise bad("context is not a 64 lowercase hex sha256")
    if not ((r["host"] == REPO_SELF and r["form"] == GH_FORM and r["key"] == r["line"])
            or (r["form"] == "a download" and isinstance(r["host"], str) and _HOST.fullmatch(r["host"]))):
        raise bad(f"host is not a lower-case DNS name on 'a download', nor {REPO_SELF} on '{GH_FORM}' (key equal to line)")
    v, t = r["verifier"], r["test"]
    if not (isinstance(v, dict) and set(v) == {"file", "line"} and _rel_path(v["file"]) and (v["file"].endswith((".sh", ".py", ".go")) or _WORKFLOW.search(v["file"]))
            and isinstance(v["line"], str) and v["line"].strip() and not any(c in v["line"] for c in "\r\n")):
        raise bad("verifier must be {file, line}: a .sh, .py, .go, workflow or action file and one non-empty line")
    if not (isinstance(t, dict) and set(t) == {"file", "case"} and _rel_path(t["file"]) and _TEST_FILE.search(t["file"])
            and isinstance(t["case"], str) and len(t["case"].strip()) >= 12 and not any(c in t["case"] for c in "\r\n")):
        raise bad("test must be {file, case}: a test file (*-test.sh, *_test.go, *_test.py, test_*.py) and one line of at least 12 characters")


def load_input_fetch(path, required=False):
    """The unmeasured_input_fetch rows (REQ-SUP-001-AC19)."""
    return _load_rows(path, "unmeasured_input_fetch", _FETCH_FIELDS, required, _check_fetch_row)


def _head_bytes(root, head, path):
    """The bytes of a REGULAR file in the head tree (head None: the working tree), or None (missing, a link, a directory, unreadable). The size is
    checked BEFORE the content is read: a file larger than the inventory's limit raises RuntimeError (the check cannot run, exit 2)."""
    too_large = lambda size: RuntimeError(f"{path} is too large to read safely ({size} bytes by its size, more than {inv.MAX_FILE})")
    read_past = RuntimeError(f"{path} read past the {inv.MAX_FILE}-byte limit")
    if head is None:
        p = os.path.join(root, path)
        try:
            if os.path.islink(p) or not os.path.isfile(p):
                return None
            if os.path.getsize(p) > inv.MAX_FILE:
                raise too_large(os.path.getsize(p))
            with open(p, "rb") as f:
                data = f.read(inv.MAX_FILE + 1)
        except OSError:
            return None
        if len(data) > inv.MAX_FILE:
            raise read_past
        return data
    try:
        r = subprocess.run(["git", "-C", root, "ls-tree", "-l", "-z", head, "--", path], capture_output=True, timeout=GH_TIMEOUT)
        meta, _, name = r.stdout.rstrip(b"\0").partition(b"\t")
        if r.returncode or name != path.encode() or meta.split()[:2] not in ([b"100644", b"blob"], [b"100755", b"blob"]):
            return None
        if int(meta.split()[3]) > inv.MAX_FILE:     # ls-tree -l: the blob's size, read before its content
            raise too_large(int(meta.split()[3]))
        b = subprocess.run(["git", "-C", root, "cat-file", "blob", meta.split()[2].decode()], capture_output=True, timeout=GH_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired, IndexError, ValueError):
        return None
    if b.returncode:
        return None
    if len(b.stdout) > inv.MAX_FILE:
        raise read_past
    return b.stdout


def _text(data, path):
    """(text, None), or (None, why): a regular UTF-8 file with no carriage return."""
    if data is None:
        return None, f"{path} is not a regular file in the head tree"
    if b"\r" in data:
        return None, f"{path} holds a carriage return"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, f"{path} is not UTF-8"
    bad = next((c for c in ("\u0085", "\u2028", "\u2029") if c in text), None)   # line breaks to YAML 1.1, not to the line split
    return (None, f"{path} holds U+{ord(bad):04X}") if bad else (text, None)


def _repeats_key(node):
    """True when a composed YAML node holds a mapping that repeats a key (a later copy would silently win)."""
    if isinstance(node, inv.yaml.MappingNode):
        keys = [k.value for k, _ in node.value]
        return len(set(map(str, keys))) != len(keys) or any(_repeats_key(v) for _, v in node.value)
    if isinstance(node, inv.yaml.SequenceNode):
        return any(_repeats_key(v) for v in node.value)
    return False


def _steps(text, path):
    """The steps of a workflow (jobs.<id>.steps[*]) or composite action (runs.steps[*]), every scalar a string; or why not: a YAML document holding an
    anchor, an alias or a merge key is not read."""
    try:
        for ev in inv.yaml.parse(text):
            if isinstance(ev, inv.yaml.AliasEvent) or getattr(ev, "anchor", None) or isinstance(ev, inv.yaml.ScalarEvent) and ev.value == "<<" and ev.style is None:
                return f"{path} holds a YAML anchor, alias or merge key"
        if _repeats_key(inv.yaml.compose(text, Loader=inv.yaml.BaseLoader)):
            return f"{path} repeats a YAML key"
        doc = inv.yaml.load(text, Loader=inv.yaml.BaseLoader)
    except inv.yaml.YAMLError:
        return f"{path} does not parse"
    if not isinstance(doc, dict):
        return f"{path} is not a workflow or action"
    if isinstance(doc.get("jobs"), dict):
        return [s for j in doc["jobs"].values() if isinstance(j, dict) and isinstance(j.get("steps"), list) for s in j["steps"] if isinstance(s, dict)]
    runs = doc.get("runs")
    return [s for s in runs["steps"] if isinstance(s, dict)] if isinstance(runs, dict) and isinstance(runs.get("steps"), list) else []


def _run_nodes(text):
    """The run: value node (or None) of each step, in the order _steps lists them (the same filters, on the composed nodes)."""
    Map, Seq = inv.yaml.MappingNode, inv.yaml.SequenceNode
    get = lambda m, key: next((v for k, v in m.value if k.value == key), None) if isinstance(m, Map) else None
    root = inv.yaml.compose(text, Loader=inv.yaml.BaseLoader)
    jobs, runs = get(root, "jobs"), get(root, "runs")
    groups = [get(j, "steps") for _, j in jobs.value if isinstance(j, Map)] if isinstance(jobs, Map) else [get(runs, "steps")]
    return [get(s, "run") for g in groups if isinstance(g, Seq) for s in g.value if isinstance(s, Map)]


def _odd(line):
    """True when a physical line holds a control character or whitespace other than a space or a tab."""
    return any((ord(c) < 32 and c != "\t") or ord(c) == 127 or (c.isspace() and c not in " \t") for c in line)


def _in_block(node, i):
    """True when physical line i (0-based) lies inside the source lines of the block scalar NODE (after its indicator line, up to its end)."""
    a, b = node.start_mark, node.end_mark
    return a.line < i and (i < b.line or (i == b.line and b.column > 0))


def _context(data, path, flat):
    """(context hash, copies of the line inside the block) or a str why the block cannot be isolated in exactly one way. A .sh file: the sha256 of the whole
    file (its first line a bash shebang), the copies counted over the whole file; a workflow or action: the sha256 of the ONE step whose run: holds the
    line, as canonical JSON, and that run: a literal block (run: |) holding EVERY physical copy of the line in the file, so the row is bound to physical
    lines, not to a parsed value another place in the file can repeat (Codex round 4: an inline run:, or a copy in env:, with: or after a continuation,
    is refused)."""
    text, why = _text(data, path)
    if why:
        return why
    lines = text.split("\n")
    physical = [i for i, x in enumerate(lines) if _flat(x) == flat]
    odd = next((i for i in physical if _odd(lines[i])), None)
    if odd is not None:    # bash reads such a copy differently from the flattening; the scan gives it an unruled hash (Codex A round 5 P3)
        return f"the copy of the line at {path}:{odd + 1} holds a control character or whitespace other than a space or a tab"
    if path.endswith(".sh"):
        if text.split("\n", 1)[0] not in _SHEBANGS:
            return f"{path} does not start with #!/bin/bash or #!/usr/bin/env bash"
        return hashlib.sha256(data).hexdigest(), len(physical)
    if _WORKFLOW.search(path):
        steps = _steps(text, path)
        if isinstance(steps, str):
            return steps
        nodes = _run_nodes(text)
        if len(nodes) != len(steps):
            return f"the steps of {path} cannot be paired with their source lines"
        hits = [(s, n, node) for s, node in zip(steps, nodes) if isinstance(s.get("run"), str) for n in [sum(1 for x in s["run"].split("\n") if _flat(x) == flat)] if n]
        if len(hits) != 1:
            return f"the line is in the run: of {len(hits)} steps of {path} (exactly one is needed)"
        step, n, node = hits[0]
        if not (isinstance(node, inv.yaml.ScalarNode) and node.style == "|"):
            return f"the step's run: in {path} is not a literal block (run: |): its lines cannot be bound to the file's lines"
        inside = [i for i in physical if _in_block(node, i)]
        if not (len(inside) == len(physical) == n):
            return (f"a copy of the line lies outside its enclosing step's run: ({len(physical)} in {path}, {len(inside)} in the run: block's lines, "
                    f"{n} in its value)")
        return hashlib.sha256(json.dumps(step, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(), n
    return f"{path} is neither a .sh file nor a workflow or action"


_DOWNLOADER = re.compile(r"\b(?:curl|wget)\b")    # the inventory's own recogniser of "a download" (pin-inventory.unmeasured_occurrences)
_STR_PREFIX = re.compile(r"^[bBrRuUfFtT]{1,2}(?=[\"'])")
# REQ-SUP-001-AC19 (0) (AC19'', advisor step 5, Oct 11, AC19 positive list): a row binds only a line in one of the LISTED plain forms; any other form is
# refused, whatever it does (a cosign verifier does not admit it). The WHOLE line is read and every word on it must be positively plain (OPEN-2: nothing
# after a ; is looser than the command). A shape this reader does not list is refused, fail closed (advisor 0080): a new shape the list does not refuse
# is a defect in the list. The forms: (a) a plain shell line whose download is the command word curl with arguments from the curl option list;
# (b) "curl" first in the list that is the whole first argument of a subprocess call that IS the line; (c) for repo:self, the gh release download prefix
# followed by plain words, never -R or --repo and no later gh in ANY command segment of the line (OPEN-1, OPEN-2; Codex round 6). wget is not listed (OPEN-3).
_SH_KEYWORDS = {"if", "then", "do", "else", "elif", "while", "until", "!", "time", "fi", "done"}
_SH_SEP = {";", "&&", "||", "|"}
_SH_WORD = re.compile(r"""(?:"[^"]*"|'[^']*'|[^\s"'])+""")
_SH_LIT = re.compile(r"[A-Za-z0-9_./:%+@,=][A-Za-z0-9_./:%+@,=-]*")    # no ~ ? * [ ] { } $ ` \ ! # & ; | < > ( ) or quote: nothing bash expands
_SH_SQ = re.compile(r"'([^']*)'")
_SH_DQ = re.compile(r'"((?:[^"\\`$]|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)*)"')
# an option of a command other than curl (and after the repo:self prefix), spelled plainly: -x (exactly ONE letter: a cluster, a digit or a glued value
# such as -Cforeign, -xvf, -j4, -o/tmp/x is not listed; only curl has listed clusters) or --name, nothing glued (Codex A round 7 P2)
_SH_OPTION = re.compile(r"-[A-Za-z]|--[a-z0-9][a-z0-9-]*")
# outside quotes, none of: a group, a subscript, a brace, a redirection, a quote left open, a tilde, a glob, a comment, an expansion, a backtick, a backslash
_SH_UNQUOTED = set("()[]{}<>\"'~*?#$`\\")
_PY_WORDS = {"and", "or", "not", "is", "in", "if", "else", "for", "as", "lambda"}   # after curl, a Python operator word: curl is a name, not a command
# the curl option list (nothing else is listed: -K, --config, --expand-*, --proto, -g, -4, --connect-timeout, ... are not): a cluster of -f -s -S -L that
# may end in o (its FILE is the next word) or O; --fail --silent --show-error --location; --output FILE; --retry N; --max-time N
_CURL_SHORT = re.compile(r"-[fsSL]*[oO]?")
_CURL_FLAGS = {"--fail", "--silent", "--show-error", "--location"}
_CURL_VALUED = {"--output": "file", "--retry": "count", "--max-time": "count"}
_COUNT = re.compile(r"[0-9]+")                                        # N digits, as many as written (Codex B round 6 P3)
_GLOB = set("[]{}")                                                   # curl's own URL globbing: never in a curl argument, quoted or not
_REDIRECT_LONG = ("--location", "--location-trusted", "--follow", "--config")
# the Python form: the WHOLE line is one subprocess call (optionally assigned to a plain name), its first argument a list whose first element is "curl"
_PY_HEAD = re.compile(r"(?:([A-Za-z_][A-Za-z0-9_]*) ?= ?)?subprocess\.(?:run|call|check_call|check_output|Popen) ?")
# a list element: a plain string literal with an optional ONE-letter r, b or u prefix (rr, bu, rb, f, t are not listed: Codex round 6 P3), or a NAME
# (never an attribute, a subscript or a call: Codex A round 6 P2) only as the FILE after "-o" or "--output"
_PY_STR = re.compile(r"""\s*([rRbBuU]?)("[^"\\]*"|'[^'\\]*')\s*(?:,|$)""")
_PY_NAME = re.compile(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|$)")
# a plain NAME (the FILE after "-o"/"--output", an assignment target): an ASCII identifier that is not a keyword and not None, True or False (Codex B
# round 6 P3: class, lambda, None, x\u00b2 are not names a reader can take as a variable); a builtin such as print is a plain name
_PY_NOT_NAME = frozenset(keyword.kwlist) | {"None", "True", "False"}    # kwlist holds None, True, False; named for the reader
_PY_KWARGS = re.compile(r"(?:\s*,\s*(?:stdout|stderr|check|timeout|capture_output|text)\s*=\s*[A-Za-z0-9_.]+)*\s*,?\s*")


def _sh_word(w, dollar=False):
    """The text of a plain shell word, or None: a literal (nothing bash expands), a single-quoted word, or a double-quoted word whose only expansions are
    $name or ${name}; never a word whose text starts with - (an option is read by its command's own rule), and a double-quoted word starts with $ only
    where DOLLAR allows it (an option's value)."""
    if _SH_LIT.fullmatch(w):
        return w
    m = _SH_SQ.fullmatch(w)
    if m and not m.group(1).startswith("-"):
        return m.group(1)
    m = _SH_DQ.fullmatch(w)
    if m and not m.group(1).startswith("-") and (dollar or not m.group(1).startswith("$")):
        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", r"$\1", m.group(1))     # ${name} is an expansion, not a brace curl could glob
    return None


def _option_list(items):
    """None when curl's arguments are all on the curl option list or plain addresses, else why not. ITEMS, one per argument: ("opt", spelling) for an
    option, ("word", text) for a plain word, ("value", text) for a word allowed only as a file name after -o or --output (a double-quoted word starting
    with $, a Python name), ("bad", word) for anything else. One reader for the shell and the Python form."""
    i = 0
    while i < len(items):
        k, a = items[i]
        i += 1
        if k == "opt":
            kind = _CURL_VALUED.get(a) or ("file" if not a.startswith("--") and a.endswith("o") else None)
            if not (a in _CURL_FLAGS or a in _CURL_VALUED or (not a.startswith("--") and len(a) > 1 and _CURL_SHORT.fullmatch(a))):
                return f"the curl option {a} is not on the curl option list"
            if kind:
                vk, v = items[i] if i < len(items) else ("bad", "")
                i += 1
                if not ((vk == "word" or (vk == "value" and kind == "file")) and (kind != "count" or _COUNT.fullmatch(v))) or _GLOB & set(v) or _DOWNLOADER.search(v):
                    return f"the curl option {a} has no plain {'number' if kind == 'count' else 'file name'} after it"
            continue
        if k != "word" or _GLOB & set(a) or _DOWNLOADER.search(a):
            return f"the curl argument {a} is not a plain address (an option inside quotes, an expansion, a bracket or brace curl would glob, a downloader word)"
    return None


def _sh_items(args):
    """The items of curl's shell words (see _option_list)."""
    out = []
    for a in args:
        t, v = _sh_word(a), _sh_word(a, True)
        out.append(("opt", a) if a.startswith("-") else ("word", t) if t is not None else ("value", v) if v is not None else ("bad", a))
    return out


_GH_WORD = re.compile(r"\bgh\b")


# the options of the repo:self prefix's gh release download whose next word is a value (a pattern, a directory, a file, an archive format): a gh word
# there is data, never a command (Codex A round 7 P3); after any other word, and in every later segment, a gh word is refused
_GH_VALUED = {"-p", "--pattern", "-D", "--dir", "-O", "--output", "-A", "--archive"}


def _repo_selector(t, value=False):
    """Why the word T (its quotes removed) names a repository or runs gh after the repo:self prefix, else None. OPEN-1: -R (any single-dash word holding
    R, glued -Rfoo too) and --repo (--r, --re, --rep, --repo, --repo=..., --repository) are refused by name; OPEN-2 (Codex round 6, A P1 and B P2): in EVERY
    command segment of the line, not only the first, and no word after the prefix holds gh (the prefix is the only listed gh: a later gh release download,
    gh api, env GH_REPO=x gh, bash -c 'gh ...' is not pinned to the repository itself). VALUE: T is the value of a _GH_VALUED option of the prefix's own
    command, where a gh word is data (--pattern gh); -R and --repo are refused there too."""
    a = t.replace('"', "").replace("'", "")
    name = a.split("=", 1)[0]
    if a.startswith("-") and not a.startswith("--") and "R" in a:
        return f"{t} names a repository after the repo:self prefix (-R is refused by name, in every command of the line)"
    if a.startswith("--") and len(name) > 2 and ("--repo".startswith(name) or name.startswith("--repo")):
        return f"{t} names a repository after the repo:self prefix (--repo is refused by name, any abbreviation too, in every command of the line)"
    if not value and _GH_WORD.search(a):
        return f"{t} runs gh after the repo:self prefix (the prefix is the only listed gh on a repo:self line)"
    return None


def _gh_options(args):
    """None when the words after the repo:self prefix are plain (options spelled plainly, never -R or --repo or any spelling of them: OPEN-1), else why."""
    after_option = False
    for a in args:
        if a.startswith("-"):
            if _repo_selector(a):
                return _repo_selector(a)
            if not _SH_OPTION.fullmatch(a):
                return f"the option {a} is not spelled plainly"
            after_option = True
            continue
        if _sh_word(a, after_option) is None or _DOWNLOADER.search(a):
            return f"the word {a} is not a plain word"
        after_option = False
    return None


def _shell_listed(flat, gh=False):
    """None when FLAT is a plain shell line of form (a), or with GH of form (c), else why not: the whole line, every word positively plain."""
    if "$(" in flat or any(c in flat for c in "`\\"):
        return "the line holds $(, a backtick or a backslash"
    bare = set(re.sub(r'"[^"]*"|\'[^\']*\'', " ", flat)) & _SH_UNQUOTED
    if bare:
        return f"outside quotes the line holds {''.join(sorted(bare))}"
    if gh:
        if not (flat == _GH_SELF or flat.startswith(_GH_SELF + " ")):
            return f"a repo:self line begins with {_GH_SELF}"
        flat = flat[len(_GH_SELF):]
    toks = []
    for w in _SH_WORD.findall(flat):
        if w.endswith(";") and w != ";":
            if w[:-1] in _SH_SEP or w[:-1].endswith(";"):
                return f"{w} is not a plain separator"
            toks += [w[:-1], ";"]
        else:
            toks.append(w)
    (state, cmd, args), curls = (("args", "gh", []) if gh else ("start", None, [])), 0
    finish = lambda: (_option_list(_sh_items(args)) if args else "curl with no argument") if cmd == "curl" else _gh_options(args) if cmd == "gh" else None
    prev = None
    for t in toks:
        value = cmd == "gh" and prev in _GH_VALUED          # the value of a value option of the prefix's own gh release download (Codex A round 7 P3)
        if gh and t not in _SH_SEP and _repo_selector(t, value):    # OPEN-1 and OPEN-2: every segment of a repo:self line, not only the first (Codex round 6)
            return _repo_selector(t, value)
        prev = t
        if t in _SH_SEP:
            if state == "start":
                return f"an empty command before {t}"
            why = finish()
            if why:
                return why
            state, cmd, args = "start", None, []
        elif state == "start":
            if t in _SH_KEYWORDS:
                continue
            if t == "curl":
                state, cmd, args, curls = "args", "curl", [], curls + 1
                continue
            if _DOWNLOADER.search(t):
                return f"the downloader word in {t} is not the command word curl"
            if _sh_word(t) is None:
                return f"the command word {t} is not a plain word"
            state, cmd = "args", "other"
        elif cmd in ("curl", "gh"):
            if cmd == "curl" and not args and t in _PY_WORDS:
                return f"curl is followed by the Python word {t}: a name, not a command"
            args.append(t)
        elif _DOWNLOADER.search(t) or not (_sh_word(t) is not None or _SH_OPTION.fullmatch(t)):
            return f"the word {t} is not a plain word (or holds a downloader word that is not a command word curl)"
    if not toks and not gh:
        return "no command"
    if state == "start" and toks and toks[-1] in ("&&", "||", "|"):
        return f"the line ends in {toks[-1]}: the command continues on the next line"
    why = finish() if state == "args" else None
    if why:
        return why
    return None if gh or curls else "no command word curl"


def _brackets(flat):
    """The brackets of a line read as Python: {open index: (char, close index or None, parent open index or None)}, strings skipped, a # outside a string
    ends the line. None when the line cannot be read that simply (a backslash, a triple quote, an f- or t-string, which can hold quotes and brackets, an
    unterminated string, a mismatched bracket)."""
    out, stack, i = {}, [], 0
    while i < len(flat):
        c = flat[i]
        if c == "\\":
            return None
        if c in "\"'":
            j = flat.find(c, i + 1)
            if flat.startswith(c * 3, i) or j < 0 or re.search(r"(?<![\w.])[rRbB]?[fFtT][rRbB]?$", flat[:i]):
                return None
            i = j + 1
            continue
        if c == "#":
            break
        if c in "([{":
            out[i] = [c, None, stack[-1] if stack else None]
            stack.append(i)
        elif c in ")]}":
            if not stack or out[stack[-1]][0] != "([{"[")]}".index(c)]:
                return None
            out[stack.pop()][1] = i
        i += 1
    return out


def _python_listed(flat):
    """None when FLAT is form (b), else why not: the WHOLE line is one call of subprocess.run, call, check_call, check_output or Popen (optionally assigned
    to a plain name), closed at the end of the line; its first argument is a list closed on the line whose first element is "curl" (double-quoted, no
    prefix), every later element a plain string literal on the curl option list or a plain address (a name only right after "-o" or "--output"); and
    nothing between the list and the call's ) but the keyword arguments stdout, stderr, check, timeout, capture_output or text with a plain value."""
    ms = list(_DOWNLOADER.finditer(flat))
    if len(ms) != 1 or ms[0].group() != "curl":
        return "the line's downloader words are not exactly one curl"
    s, e = ms[0].span()
    br = _brackets(flat)
    if br is None or not (s >= 1 and flat[s - 1] == '"' and flat[e:e + 1] == '"'):
        return "curl is not a double-quoted list element on a line read as Python"
    j = len(flat[:s - 1].rstrip()) - 1
    if j < 0 or j not in br or br[j][0] != "[" or br[j][1] is None:
        return '"curl" is not the first element of a list closed on the line'
    p, close = br[j][2], br[j][1]
    head = _PY_HEAD.fullmatch(flat[:p]) if p is not None else None
    if p is None or br[p][0] != "(" or br[p][1] != len(flat) - 1 or flat[p + 1:j].strip() or not head:
        return "the list is not the first argument of a subprocess call that is the whole line"
    if head.group(1) in _PY_NOT_NAME:
        return f"the assignment target {head.group(1)} is not a plain name (a keyword, None, True or False)"
    if not _PY_KWARGS.fullmatch(flat[close + 1:br[p][1]]):
        return "the call holds an argument other than the plain keyword arguments"
    rest, items = flat[e + 1:close], []
    if rest.strip():
        first = re.match(r"\s*,", rest)
        if not first:
            return '"curl" is not a whole list element'
        rest = rest[first.end():]
    while rest.strip():
        m = _PY_STR.match(rest)
        if m:
            c = m.group(2)[1:-1]
            items.append(("opt", c) if c.startswith("-") else ("word", c))
        else:
            m = _PY_NAME.match(rest)
            if not m or m.group(1) in _PY_NOT_NAME:
                return "a list element is not a plain string literal or name (an ASCII identifier, not a keyword, None, True or False)"
            items.append(("value", m.group(1)))
        rest = rest[m.end():]
    return _option_list(items)


def _unlisted(flat, repo_self=False):
    """None when the flattened line is in one of the listed plain forms (REQ-SUP-001-AC19 (0)), else why not: for a host row form (a) or (b), for a
    repo:self row form (c). A control character, or whitespace other than a space, is in no form."""
    if any(ord(c) < 32 or ord(c) == 127 or (c.isspace() and c != " ") for c in flat):
        return "the line holds a control character or whitespace other than a space"
    if repo_self:
        return _shell_listed(flat, gh=True)
    sh = _shell_listed(flat)
    if sh is None:
        return None
    py = _python_listed(flat)
    return None if py is None else f"as a shell line: {sh}; as a subprocess call: {py}"


# a word of a line for (6): a quoted string whole (a Python string prefix allowed), or an unquoted run up to whitespace, a quote, ;, | or &; an address is
# ONE word, never split at a comma, a ; or a ? inside it (Codex A round 7 P2)
_REDIRECT_WORD = re.compile(r"""[rRbBuU]{0,2}"[^"]*"|[rRbBuU]{0,2}'[^']*'|[^\s"';|&]+""")


def _redirect_words(flat):
    """True when a word of the line (_REDIRECT_WORD: a quoted word or a Python list element whole, its prefix and quotes stripped; an unquoted word whole)
    starts with a single - and holds an L or a K, or is, begins with or abbreviates --location, --location-trusted, --follow or --config (AC19 (6)). Only
    a word that STARTS with - is read: -L inside an address (a,-L, "a;-L", "a?x=-L") is not an option."""
    words = [_STR_PREFIX.sub("", x).strip("\"'") for x in _REDIRECT_WORD.findall(flat)]
    long = lambda w: w.split("=", 1)[0]
    return any((w.startswith("-") and not w.startswith("--") and ("L" in w or "K" in w))
               or (w.startswith("--") and len(long(w)) > 2 and any(o.startswith(long(w)) or long(w).startswith(o) for o in _REDIRECT_LONG)) for w in words)


def _follows_redirects(flat):
    """True for a line that is not in a listed plain form (refused by (0) whatever it does) or that holds a redirect word (_redirect_words): False only
    for a listed line with no redirect word."""
    return _unlisted(flat) is not None or _redirect_words(flat)


def _cosign(line):
    words = [w.strip("\"'") for w in line.split()]
    has = lambda names: any(w.split("=", 1)[0] in names for w in words)
    return any(words[i:i + 2] == ["cosign", "verify-blob"] for i in range(len(words))) and has(_IDENT) and has(_ISSUER)


def _repeated_segment(path, flat):
    """None, or why the line cannot be counted by lines: the scanner reads one copy of it as more than one occurrence of a key (a download segment
    repeated on the line), so a row's count would not be a count of lines and a repeat could stand in for a copy the scanner does not count; such a line
    is refused, fail closed (Codex round 3)."""
    try:
        per = {}
        for k, f, _ in inv.unmeasured_occurrences({path: flat + "\n"}):
            if f == flat:
                per[k] = per.get(k, 0) + 1
    except RuntimeError as e:
        return str(e)
    return "the line repeats its download segment: its copies cannot be counted as lines" if any(n != 1 for n in per.values()) else None


def _fetch_unverified(root, head, row, flat, held_n):
    """None when the head holds what an input-fetch row requires (REQ-SUP-001-AC19), else why not."""
    repeats = _repeated_segment(row["file"], flat)
    if repeats:
        return repeats
    if held_n != row["count"]:
        return f"the head holds the line {held_n} times, the row counts {row['count']} (exactly)"
    ctx = _context(_head_bytes(root, head, row["file"]), row["file"], flat)
    if isinstance(ctx, str):
        return ctx
    if ctx[1] != held_n:
        return "a copy of the line lies outside its enclosing step's run:"
    if ctx[0] != row["context"]:
        return "the enclosing block changed (the context hash differs): the rows PR re-reads it and writes a new context"
    if row["host"] == REPO_SELF:
        if not (flat == _GH_SELF or flat.startswith(_GH_SELF + " ")):
            return f"a repo:self line begins with {_GH_SELF}"
    elif f"https://{row['host']}/" not in flat:
        return f"the line does not name https://{row['host']}/ literally"
    why = _unlisted(flat, row["host"] == REPO_SELF)
    if why:
        return (f"the line is not in one of the listed plain forms (REQ-SUP-001-AC19 (0)): {why}; a row binds only a listed line, any other form is "
                "refused whatever it does, a cosign verifier included")
    v, t = row["verifier"], row["test"]
    vt, why = _text(_head_bytes(root, head, v["file"]), v["file"])
    if why:
        return f"the verifier file: {why}"
    if v["file"].endswith(".sh") and vt.split("\n", 1)[0] not in _SHEBANGS:
        return f"the verifier file {v['file']} does not start with a bash shebang"
    vlines = vt.split("\n")      # (3) the verifier line is matched against PHYSICAL lines, never a parsed value (AC19'')
    vphys = [i for i, x in enumerate(vlines) if _flat(x) == _flat(v["line"])]
    if len(vphys) != 1:
        return f"the verifier line is not exactly one physical line of {v['file']} ({len(vphys)} physical lines flatten to it)"
    if _odd(vlines[vphys[0]]):
        return f"the verifier line in {v['file']} holds a control character or whitespace other than a space or a tab"
    if _WORKFLOW.search(v["file"]):
        steps = _steps(vt, v["file"])
        if isinstance(steps, str):
            return f"the verifier file: {steps}"
        nodes = _run_nodes(vt)
        if len(nodes) != len(steps):
            return f"the verifier file: the steps of {v['file']} cannot be paired with their source lines"
        blocks = [n for n in nodes if isinstance(n, inv.yaml.ScalarNode) and n.style == "|" and _in_block(n, vphys[0])]
        if len(blocks) != 1:
            return (f"the verifier line in {v['file']} is not inside the literal-block run: (run: |, |- or |+) of exactly one step: it is matched against "
                    "physical lines of a literal block, never a parsed value (a folded, plain or quoted run:, an escape, env: or with: is not a verifier line)")
    if _redirect_words(flat) and not _cosign(v["line"]):
        return "the line follows redirects: its verifier line must be cosign verify-blob with --certificate-identity[-regexp] and --certificate-oidc-issuer"
    tt, why = _text(_head_bytes(root, head, t["file"]), t["file"])
    if why or t["case"] not in tt:
        return f"the test file {t['file']} does not hold the case"
    return None


def print_context(path, line, count="1"):
    """--print-context FILE LINE [COUNT] (run from the repository root): the context a rows author writes for LINE in FILE (the working tree); exit 2
    and nothing on stdout unless the line is present exactly COUNT times (default 1) in one block that can be isolated."""
    flat = _flat(line)
    try:
        data = _head_bytes(".", None, path)
    except RuntimeError as e:
        data, ctx = None, str(e)
    else:
        ctx = _context(data, path, flat)
    if not isinstance(ctx, str):
        text = data.decode("utf-8")
        per, unruled = {}, 0
        try:
            for k, f, bashlike in inv.unmeasured_occurrences({path: text}):    # EVERY scanner copy of the line, a continuation-joined one too (Codex round 4)
                if f == flat:
                    per[k] = per.get(k, 0) + 1
                    unruled += not bashlike
        except RuntimeError as e:
            per = {None: -1}
            print(f"pin-age: {e}", file=sys.stderr)
        counts = sorted(per.values())                 # EVERY per-key count must agree with the block count and COUNT (Codex round 3): never the largest
        repeats = _repeated_segment(path, flat)
        unlisted = _unlisted(flat) and _unlisted(flat, repo_self=True)
        if unruled:       # the checker gives such a copy an 'unruled:' hash no row can name (Codex A round 5 P3, B round 4 P3): no context is printed
            ctx = (f"{unruled} scanner copies of the line are ones no row can rule (joined from a continuation, or whitespace other than a space or a "
                   f"tab; the scanner's per-key counts of the line are {counts})")
        elif unlisted:
            ctx = f"the line is not in one of the listed plain forms (REQ-SUP-001-AC19 (0)): {unlisted}"
        elif repeats or not (re.fullmatch(r"[1-9][0-9]?|100", count) and counts and set(counts) == {ctx[1]} == {int(count)}):
            ctx = (f"the scanner's per-key counts of the line are {counts or [0]}, its block holds it {ctx[1]} times: they do not all equal {count}"
                   + (f" ({repeats})" if repeats else ""))
    if isinstance(ctx, str):
        print(f"pin-age: cannot isolate the context: {ctx}", file=sys.stderr)
        return 2
    print(ctx[0])
    return 0


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
        fetch = None if text else _covered(fetches, k, lines[k])    # an item is ruled by ONE list
        if text:
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in text))))
        elif fetch:
            why = next((w for w in (_fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), ""), held[k][lh]) for lh, r in zip(lines[k], fetch)) if w), None)
            if why:
                added.append((k, why))
            else:
                fetched.append((k, "; ".join(dict.fromkeys(r[0] for r in fetch)), ", ".join(dict.fromkeys(r[2]["verifier"]["file"] for r in fetch))))
        else:
            added.append((k, None))
    named = {k for k, _ in added}
    for k, per in sorted(held.items()):     # a ruled fetch still in the head is re-checked though nothing is added (its verifier, test, count, context)
        for lh, n in per.items():
            r = fetches.get((k[0], k[1], k[2].split(":", 1)[0], lh))
            why = r and k not in named and lh not in lines.get(k, {}) and _fetch_unverified(a.root, a.head, r[2], flats.get((k, lh), ""), n)
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
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False, "proof": None,
                     "reason": (f"{what} was added to {path} ({line[:100]}): this check cannot measure it, so a pull request that adds one is refused (use a pinned form it can measure)"
                                if why is None else f"{what} in {path} ({line[:100]}) is listed in the base branch's unmeasured_input_fetch, but: {why}")})
        print(f"  FAIL unmeasured:{path}: {what} added: not measurable, refused" if why is None else f"  FAIL unmeasured:{path}: {what} ({line[:60]}): input fetch not verified (REQ-SUP-001-AC19): {why}")
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
