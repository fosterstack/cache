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
import http.client
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.error
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


FILE_PIN_SOURCE = "file-pin-ruling"


def is_file_item(item):
    """A checksum or version FILE item (its identity is the file's content), the only kind a file_pins row can date."""
    path = getattr(item, "raw", None) or ""
    return item.kind == "tool" and (item.name or "").startswith("file:") and item.version == "(file)" and (getattr(item, "step", "") or "").startswith("content:") \
        and bool(re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1])) and path.rsplit("/", 1)[-1] not in inv.VERSION_FILES   # a checksum file only: never a version file (.python-version ...)


def judge_item(item, proofs, now, min_days=MIN_DAYS):
    """(ok, reason, proof) from a list of (time-string, source). Only valid server-side proofs in the past count; the oldest decides."""
    ruled_file = is_file_item(item) and any(src == FILE_PIN_SOURCE for _, src in proofs)    # REQ-SUP-001-AC34: a file pin the base branch's file_pins row dates
    if ruled_file:
        proofs = [p for p in proofs if p[1] == FILE_PIN_SOURCE]    # the row's published time decides, never an earlier clock of the pull request
    if not ruled_file and (re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or ""))):
        return False, f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, or an action not named by its commit, so it has no age", None
    if item.kind == "tool" and item.name in ("python", "java", "node") and len(item.version.lstrip("v").split(".")) < 3:
        return False, f"not a pin: {item.version!r} is a series, not an exact release (the installer picks the newest patch), so it has no age", None
    bad = next((src[len("bad-label:"):] for _, src in proofs if str(src).startswith("bad-label:")), None)
    if bad is not None:
        return False, f"age not provable: the label '# {bad}' does not name the pinned commit (the label is wrong; this is not a missing clock)", None
    if item.kind in ("tool", "package") and any(src in SERVER_SIDE and src not in ("pr-clock", "observer") for t, src in proofs):
        proofs = [(t, src) for t, src in proofs if src not in ("pr-clock", "first-seen")]   # a registry's or a release's own time beats the PR clock: a replaced asset is not out-aged by the version's old clock (rc-5b item 6)
    best, seen = None, []
    for t, src in proofs:
        seen.append(src)
        if src not in SERVER_SIDE and src != "first-seen" and not (src == FILE_PIN_SOURCE and ruled_file):
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


_NULL = type(None)


def _shaped(value, need, what):
    """The one way to read a JSON object answer: `need` is ((key, type or tuple of types), ...), given by every caller (no default). An answer that is not an object,
    or lacks a needed key, or holds it as another type, is an answer we cannot read (CouldNotLook): never 'nothing there'. Keys a caller reads with .get are the
    optional ones; each of those is type-checked where it is used."""
    if not isinstance(value, dict):
        raise CouldNotLook(f"{what} is not a JSON object")
    for key, typ in need:
        types = typ if isinstance(typ, tuple) else (typ,)
        got = value.get(key, _FAILED)
        if got is _FAILED or not isinstance(got, types) or (isinstance(got, bool) and bool not in types):
            raise CouldNotLook(f"{what} lacks {key!r} of the expected type")
    return value


def _dicts(value, what, need):
    """A list of JSON objects each holding every key of `need` (CouldNotLook otherwise): an element of another shape is an answer we cannot read."""
    if not isinstance(value, list):
        raise CouldNotLook(f"{what} is not a list of JSON objects")
    for x in value:
        _shaped(x, need, what)
    return value


def _gh_pages(path, rows):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line); every row must hold the keys of `rows`."""
    r = _gh_run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")
    return _dicts(got, f"GitHub API {path.split('?')[0]}", rows)


def _gh_api(path, need):
    """A GitHub object answer holding every key of `need`; None only for a plain miss (404)."""
    r = _gh_run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        got = json.loads(r.stdout)
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")
    return _shaped(got, need, f"GitHub API {path.split('?')[0]}")


def _gh_list(path, rows):
    """One page of a GitHub list answer, every row holding the keys of `rows`; None only for a plain miss (404)."""
    r = _gh_run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        got = json.loads(r.stdout)
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")
    return _dicts(got, f"GitHub API {path.split('?')[0]}", rows)


_FAILED = object()      # the server could not be asked (lenient mode)
_GONE = object()        # strict mode: the server said 404 or 410, the one answer that means "not there"


def _fetch_json(url, timeout=30, strict=False):
    """The raw decoded answer. PRIVATE: its one caller is _http_dict, which shapes it before anyone else sees it (a test enforces the single caller).
    Lenient: _FAILED when the server could not be asked or its body is not JSON. strict: only a 404/410 is an answer (_GONE); a network error, a timeout, a 5xx
    or a body that is not JSON means we could not look (CouldNotLook)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if not strict:
            return _FAILED
        if e.code in (404, 410):
            return _GONE
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} answered HTTP {e.code}")
    except (OSError, ValueError, http.client.HTTPException) as e:
        if not strict:
            return _FAILED
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} could not be asked ({type(e).__name__})")


def _http_dict(url, need, timeout=30, strict=False):
    """An endpoint that answers with a JSON object holding every key of `need` (no default: the caller says what it reads). None only when the server could not be asked
    (strict: when it said 404/410); valid JSON of another shape, a JSON null or a missing key is an answer we cannot read (CouldNotLook), never 'nothing there'."""
    d = _fetch_json(url, timeout, strict)
    if d is _FAILED or d is _GONE:
        return None
    return _shaped(d, need, urllib.parse.urlsplit(url).netloc + " answer")


def _http_json_strict(url, need, timeout=30):
    """_http_dict where only "not there" (404/410) is an answer (None); a network error, a timeout, a 5xx or a body that is not JSON means we could not look."""
    return _http_dict(url, need, timeout, strict=True)


TOOL_REPOS = {  # tool -> (github repo, tag prefix to try after the bare version)
    "trivy": "aquasecurity/trivy", "grype": "anchore/grype", "syft": "anchore/syft", "snyk": "snyk/cli", "osv": "google/osv-scanner",
    "scout": "docker/scout-cli", "golangci-lint": "golangci/golangci-lint", "python": "actions/python-versions",
    "buildx": "docker/buildx", "goreleaser": "goreleaser/goreleaser", "cosign": "sigstore/cosign", "kind": "kubernetes-sigs/kind", "helm": "helm/helm", "node": "nodejs/node",
}


_RELEASE = (("published_at", (str, _NULL)), ("draft", bool))      # a release answer holds both (published_at is null on a draft): a missing key is no release, it is an unreadable answer


def _release_time(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}", _RELEASE)
        if rel and rel["published_at"] and not rel["draft"]:
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
    c = _gh_api(f"repos/{repo}/commits/{sha}", (("commit", dict),))
    if c is None:
        return None
    committer = c["commit"].get("committer")      # optional: a commit without a committer has no date
    if committer is None:
        return None
    date = _shaped(committer, (), "the commit's committer").get("date")
    if date is not None and not isinstance(date, str):
        raise CouldNotLook("GitHub API commit answered with a committer date that is not text")
    return date


def _go_escape(path):
    """The Go module proxy's case encoding: each upper-case letter is written "!" and its lower-case form."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


_MODINFO = (("Version", str),)      # a module info answer holds its version


def _go_module(path, version, strict=False):
    parts = path.split("/")
    for n in range(len(parts), 0, -1):
        mod = "/".join(parts[:n])
        url = f"https://proxy.golang.org/{urllib.parse.quote(_go_escape(mod), safe='/!')}/@v/{urllib.parse.quote(version)}.info"
        info = _http_json_strict(url, _MODINFO) if strict else _http_dict(url, _MODINFO)
        if info is None:
            continue      # not there (strict) or the proxy could not be asked (lenient): try the shorter module path
        if not info["Version"]:
            raise CouldNotLook("proxy.golang.org answered with something that is not a module info object")      # a 200 we cannot read is not "module not found", in either mode
        return mod, info
    return None, None


def _go_index_time(mod, version, vcs_time):
    """The Go module index's timestamp for module@version: scan the index from the version-control time forward (the index entry follows it).
    Every row of a page is validated before any is used: an unreadable row is CouldNotLook, never 'not this module'."""
    since = vcs_time
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"https://index.golang.org/index?since={urllib.parse.quote(since)}&limit=2000", timeout=30) as r:
                lines = [ln for ln in r.read().decode().splitlines() if ln.strip()]
        except (OSError, ValueError, http.client.HTTPException):
            return None
        rows = []
        for ln in lines:
            try:
                row = json.loads(ln)
            except ValueError:
                raise CouldNotLook("index.golang.org answered with a line that is not JSON")
            if not (isinstance(row, dict) and all(isinstance(row.get(k), str) and row.get(k) for k in ("Path", "Version", "Timestamp"))):
                raise CouldNotLook("index.golang.org answered with a row that is not {Path, Version, Timestamp}")
            rows.append(row)
        for row in rows:
            if row["Path"] == mod and row["Version"] == version:      # exact (the module path is case-sensitive); every row was validated above
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
        data = _gh_api(f"repos/{repo}/actions/workflows/supply-chain.yml/runs?event=schedule&branch=main&status=completed&per_page=100", (("workflow_runs", list),)) or {"workflow_runs": []}
        wruns = _dicts(data["workflow_runs"], "the scheduled workflow runs", (("id", int),))
        runs = sorted((r for r in wruns if tobs.accept_run(dict(r, path=str(r.get("path") or "").split("@")[0]))), key=lambda r: r.get("created_at", ""), reverse=True)
        for run in runs[:30]:
            adata = _gh_api(f"repos/{repo}/actions/runs/{run['id']}/artifacts", (("artifacts", list),)) or {"artifacts": []}
            arts = _dicts(adata["artifacts"], "the artifacts of a scheduled run", (("id", int), ("name", str)))
            art = next((x for x in arts if x["name"] == tobs.STATE_NAME and not x.get("expired")), None)
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
    commits = r.stdout.split()
    first = None
    for i, c in enumerate(commits):
        try:
            if (root, c) not in _INV_CACHE:
                _INV_CACHE[(root, c)] = inv.load_at(root, c)     # one parse per commit, not one per moved item
            got = _INV_CACHE[(root, c)].get(item.key)
            if got is not None and got.sum == item.sum:
                first = i
                break
        except RuntimeError:
            continue
    if first is None:
        return None
    intro = commits[first]
    for c in commits[first:]:      # the earliest run whose head CONTAINS the commit: a commit that was never a pushed head has no run of its own (base..head bounds the walk)
        if c != intro and _gh_run(["git", "-C", root, "merge-base", "--is-ancestor", intro, c], capture_output=True).returncode != 0:
            continue      # a sibling in a merge does not contain the introducing commit: its runs lend no clock
        times = _run_times(repo, c)
        if times:
            return min(times)
    return None


def _run_times(repo, commit):
    rdata = _gh_api(f"repos/{repo}/actions/runs?head_sha={commit}&per_page=100", (("workflow_runs", list),)) or {"workflow_runs": []}
    runs = _dicts(rdata["workflow_runs"], "the workflow runs of a commit", (("created_at", (str, _NULL)),))
    times = [x["created_at"] for x in runs if x["created_at"]]
    r2 = _gh_run(["gh", "api", "--paginate", f"repos/{repo}/commits/{commit}/check-suites?per_page=100", "--jq", ".check_suites[]"], capture_output=True, text=True)
    if r2.returncode:
        _gh_failed(r2)
    else:
        for line in r2.stdout.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                raise CouldNotLook("GitHub API check-suites answered with a line that is not JSON")
            c = _shaped(row, (("created_at", (str, _NULL)),), "a check suite of the first commit")["created_at"]
            if c:
                times.append(c)    # a check from a non-Actions app counts too: the EARLIEST server-side sign of the commit
    return times


def _release_with_assets(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}", _RELEASE + (("assets", list),))
        if rel and rel["published_at"] and not rel["draft"]:
            _dicts(rel["assets"], "the assets of a release", ())      # name, created_at and updated_at are optional: an asset without a name matches no download, so the release lends no proof (the pin then fails as unprovable)
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
        if item.label and item.label not in tags:
            return [(None, "bad-label:" + item.label)]    # the label Dependabot bumps does not resolve to this commit: age not provable, with no PR clock to lean on
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
            t = _go_index_time(mod, info["Version"], info["Time"]) if isinstance(info.get("Time"), str) else None      # no readable version-control time: no go-index proof (the pin then fails as unprovable)
            if t:
                out.append((t, "go-index"))
    elif item.kind == "package":
        name = item.name.split("/", 1)[1]
        d = _http_dict(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(item.version)}/json", (("urls", list),))
        ups = [u.get("upload_time_iso_8601") for u in _dicts((d or {"urls": []})["urls"], "pypi urls", ()) if u.get("upload_time_iso_8601")]      # the upload time is optional, text when there
        if not all(isinstance(x, str) for x in ups):
            raise CouldNotLook("pypi.org answered with an upload time that is not text")
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
                vs = _gh_list(f"{scope}/{owner}/packages/container/{urllib.parse.quote(pkg, safe='')}/versions?per_page=100&page={page}", (("name", str), ("created_at", (str, _NULL))))
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
            d = _http_dict(url, (("results", list),))
            if d is None:
                return None
            for tag in _dicts(d["results"], "hub.docker.com results", ()):
                if tag.get("digest") == item.version or any(i.get("digest") == item.version for i in _dicts(tag.get("images", []), "hub.docker.com images", ())):      # digest, images and tag_last_pushed are optional
                    pushed = tag.get("tag_last_pushed")
                    if pushed is not None and not isinstance(pushed, str):
                        raise CouldNotLook("hub.docker.com answered with a push time that is not text")
                    return pushed
            url = d.get("next")
            if not url:
                break
            if not (isinstance(url, str) and url.startswith("https://hub.docker.com/")):
                raise CouldNotLook("hub.docker.com answered with a next link that is not a hub.docker.com URL")
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
        note = getattr(source, "notes", {}).get(it.key)
        if note:
            reason += f" ({note})"
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
    except (AttributeError, KeyError, TypeError, IndexError, ValueError) as e:      # an answer of a shape nobody guarded: the check cannot run, it is never a pass and never a traceback
        print(f"pin-age: cannot run: an answer could not be read ({type(e).__name__}) (not a pass)", file=sys.stderr)
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
    for k, flat, bashlike in inv.unmeasured_occurrences({**inv.tree_surfaces(root, rev), **inv.tree_files(root, rev), **inv.tree_scripts(root, rev)}):   # a read error propagates (exit 2)
        lh = _line_hash(flat) if bashlike else "unruled:" + _line_hash(flat)
        _LINE_TEXT[lh] = flat
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
TEXT_RULING = "text, not a command: "      # the convention: a line that only MENTIONS a download tool
LIVE_RULING = "live fetch, owner ratified (Oct 9 rule 48 / Oct 15 exception 2): "   # a real fetch, honored only for https on packages.wolfi.dev (see _live_fetch_line_ok)
GO_RULING = "pinned toolchain fetch, advisor reading Oct 16 (rule 12, the recipe pin is verified before storing): "   # the Go toolchain tarball (REQ-SUP-001-AC23): honored only for https://go.dev/dl/ plus one variable
LOOPBACK_RULING = "loopback fetch, advisor reading Oct 17 (REQ-SUP-001-AC25): "   # the one line of the loopback helper that starts the fetch program (REQ-SUP-001-AC24): honored for that file and that line's sha256 only
LOOPBACK_FILE = "bin/loopback-get.sh"
LOOPBACK_LINE = """curl -q -g --noproxy '*' --proto "=$proto" --max-redirs 0 "$@" "$url" || exit $?"""    # the raw text of the line, byte for byte (no indent, no trailing space, no carriage return)
LOOPBACK_LINE_SHA256 = "7dd5872cd29aa6ff52be7b831d287c5d72b58507d90b3a39489c70a5f8f58ccd"   # sha256 of that line as the scan hashes it (whitespace collapsed); the raw text above is what the head file must hold
DOWNLOAD_FORM = "a download"
_LIVE_URL = re.compile(r"https://packages\.wolfi\.dev(?:/[A-Za-z0-9._+~/-]*)?")
# the per-package fetch (advisor, Oct 15, owner rule 48): the literal https://packages.wolfi.dev/os/ (trailing slash included, so the host cannot change) followed by
# exactly ONE variable and nothing else
_LIVE_URL_VAR = re.compile(r"https://packages\.wolfi\.dev/os/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_GO_OUT = re.compile(r"(?:[A-Za-z0-9_./-]|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})+")
_GO_URL_VAR = re.compile(r"https://go\.dev/dl/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_ANY_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"]+")
_LINE_TEXT = {}                              # whole-line hash -> the flattened line, filled by _occurrences


_LIVE_FLAG_PLAIN = {"-f", "-s", "-S", "-L", "-fsSL", "-fsS", "-fSL", "-sSL", "-g", "--globoff", "--fail", "--silent", "--show-error", "--location", "--tlsv1.2"}
_LIVE_FLAG_VALUE = {"--max-filesize": r"[0-9]+", "--max-time": r"[0-9]+", "--proto": r"=https", "-o": r"[A-Za-z0-9_./${}-]+", "--output": r"[A-Za-z0-9_./${}-]+"}


def _live_fetch_line_ok(flat, toolchain=False):
    """The bound line is exactly ONE curl command: curl or /usr/bin/curl, then only flags from a fixed list (with a plain value where one is taken), then exactly one
    URL operand that is https on the host packages.wolfi.dev (with toolchain=True instead: exactly https://go.dev/dl/ followed by ONE variable, REQ-SUP-001-AC23); optionally followed by `|| die "plain text" [digit]` or `|| exit N`. The line is split into shell words,
    so quote concatenation cannot change a word after the check; a variable may appear only as part of the -o file name; no second command, pipe, redirection,
    substitution, other operand or schemeless host is accepted."""
    import shlex
    left, sep, right = flat.partition("||")
    if sep and not re.fullmatch(r'\s*(?:die(?: "[^"$`\\]*")?(?: [0-9]+)?|exit [1-9][0-9]*)\s*', right):
        return False
    if re.search(r"[;&|<>`]|\$\(", left):
        return False
    try:
        w = shlex.split(left, posix=True)
    except ValueError:
        return False
    if len(w) < 3 or w[0] not in ("curl", "/usr/bin/curl") or w[1] not in (("-q",) if toolchain else ("-q", "--disable")):
        return False                                   # -q first: no default .curlrc (CURL_HOME) can add a URL or an option (the Go shape takes only the spelling -q)
    raw = re.findall(r"""(?:"[^"]*"|'[^']*'|[^\s"']+)+""", left)
    if len(raw) != len(w):
        return False
    if toolchain and "'" in left:
        return False                                   # the Go shape has no single quote anywhere: a single-quoted $name is a literal dollar sign, never a variable
    for rt in raw:
        # an expansion, brace, glob or tilde may appear only inside double quotes: unquoted, the shell splits it into several words
        if re.search(r"[$`{}*?\[\]~]", re.sub(r'"[^"]*"|\'[^\']*\'', "", rt)):
            return False
    i, operands, globoff, op_raw = 2, [], False, []
    while i < len(w):
        t = w[i]
        if t in _LIVE_FLAG_PLAIN:
            globoff = globoff or t in (("-g",) if toolchain else ("-g", "--globoff"))
            i += 1
        elif t in _LIVE_FLAG_VALUE:
            if i + 1 >= len(w) or not re.fullmatch(_LIVE_FLAG_VALUE[t], w[i + 1]) or (t not in ("-o", "--output") and "$" in w[i + 1]):
                return False
            if toolchain and t in ("-o", "--output") and not _GO_OUT.fullmatch(w[i + 1]):
                return False                           # the Go shape: an output value is literal characters and plain $name / ${name} references only
            i += 2
        elif t.startswith("-"):
            return False                               # an option outside the list (-x, -K, --resolve, --url, an attached value, a cluster not listed)
        else:
            operands.append(t)
            op_raw.append(raw[i])
            i += 1
    if len(operands) != 1:
        return False
    if toolchain:
        # the variable form only, only with -g, and the operand must be double-quoted or bare: a single-quoted $f is a literal dollar sign, not a variable
        return globoff and "'" not in op_raw[0] and _GO_URL_VAR.fullmatch(operands[0]) is not None
    if _LIVE_URL_VAR.fullmatch(operands[0]) is not None:
        return globoff                                  # curl itself expands {a,b} and [1-2] in a URL: a variable operand is one transfer only with -g
    return _LIVE_URL.fullmatch(operands[0]) is not None


# REQ-SUP-001-AC16, the optional row field `context` (advisor, Oct 16; the owner's plain-forms rule): a ruled row may name WHY its line is inert, and the checker then
# PROVES that from the head file at scan time. A context only ever NARROWS: a row whose context does not hold rules nothing (it never falls back to the plain row), and a
# row without a context behaves exactly as before. comment: the line is a comment. assignment: the line is ONE plain NAME=word assignment (no substitution, no second
# command). heredoc: the line lies in a here-document with a QUOTED delimiter (the shell expands nothing in it), opened by no interpreter or shell and by no function that
# runs its input, whose output is not piped or substituted into one, and whose file (if written) is never later run. pystring: the same for a Python program read from a
# quoted heredoc, and the ruled text lies only inside string constants or comments of that program (Python's own tokenizer and parser decide). A program that can run
# something (exec, eval, subprocess, os.system ..., or that writes files) is "impure": its rows must say in `proof` that they rest on review ("attested by review"),
# so a reader of the file sees that this is not a proof.
CONTEXTS = ("comment", "assignment", "heredoc", "pystring")
_INTERP_WORDS = frozenset("sh bash dash zsh ksh ash csh tcsh fish eval source . exec xargs python python2 python3 node nodejs perl ruby awk gawk mawk nawk php lua".split())
_USE_WORDS = frozenset("chmod mv cp ln install source exec eval".split())
_PY_FORBIDDEN_NAMES = frozenset("exec eval compile __import__ getattr setattr globals locals vars breakpoint importlib runpy code pkgutil ctypes cffi subprocess pty commands "
                                "system popen startfile posix_spawn posix_spawnp fork forkpty execl execle execlp execlpe execv execve execvp execvpe spawnl spawnle spawnlp spawnlpe "
                                "spawnv spawnve spawnvp spawnvpe write_text write_bytes chmod shutil touch mkdir makedirs unlink remove rmdir rename symlink link symlink_to hardlink_to "
                                "write writelines truncate fdopen copy copyfile copytree move rmtree".split())
_DATA_CONSUMERS = frozenset("cat grep egrep fgrep sort head tail wc cut tr diff cmp jq base64 sha256sum shasum md5sum od".split())
_PURE_IMPORTS = frozenset("json re sys os.path time datetime hashlib base64 collections itertools functools math string textwrap copy struct binascii "
                          "unicodedata urllib.parse shlex enum dataclasses".split())
_DEF_FUNC = re.compile(r"^[ \t]*(?:function[ \t]+([A-Za-z_][\w.-]*)|([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\))", re.M)


def _norm_word(w):
    """A versioned interpreter (python3.11, perl5.36, ruby3.2, bash5, sh.exe) is the interpreter."""
    b = re.sub(r"(?:\.exe)?$", "", w)
    b = re.sub(r"[\d.]+$", "", b)
    for cand in (w, b, re.sub(r"\d+$", "", b)):
        if cand in _INTERP_WORDS:
            return cand
    return w


def _words(text):
    return [_norm_word(w) for w in re.findall(r"[A-Za-z_][\w.+-]*|(?<![\w.])\.(?=\s)", text.replace("/", " "))]


def _unquote(raw):
    """Shell quote removal of one word (single quotes literal, double quotes with a backslash only before dollar, backtick, double quote and backslash, a backslash escapes the next character): the text bash compares a heredoc terminator with."""
    out, i = [], 0
    while i < len(raw):
        c = raw[i]
        if c == "'":
            k = raw.find("'", i + 1)
            if k < 0: return None
            out.append(raw[i + 1:k]); i = k + 1
        elif c == '"':
            k, buf = i + 1, []
            while k < len(raw) and raw[k] != '"':
                if raw[k] == "\\" and k + 1 < len(raw) and raw[k + 1] in '$`"\\': k += 1
                buf.append(raw[k]); k += 1
            if k >= len(raw): return None
            out.append("".join(buf)); i = k + 1
        elif c == "\\":
            if i + 1 < len(raw): out.append(raw[i + 1])
            i += 2
        else:
            out.append(c); i += 1
    return "".join(out)


def _shell_lex(lines):
    """Walk the script once, quote-aware across lines. Returns (heredocs, sane, state): state[i] is the quote/substitution stack at the START of line i as a tuple (() = plain code
    position) or None when line i lies inside a here-document body; each heredoc is {open, start, end (the terminator's index; None if there is none), quoted, nested, bad, opener (the
    command line, continuation lines joined), targets (files its output goes to), ops (how many heredocs the line opens)}. A `<<` counts only in code position (not inside quotes, a
    comment, arithmetic or a here-string). sane is False when the walk ends inside an open quote or substitution: then nothing in the file is proved."""
    hds, stack, i, n = [], [], 0, len(lines)
    insane = False
    state = [None] * n
    while i < n:
        state[i] = tuple(stack)
        line, j, ops, cmt = lines[i], 0, [], False
        while j < len(line) and not cmt:
            c, top = line[j], (stack[-1] if stack else "")
            if top == "'":
                if c == "'": stack.pop()
            elif top == '"':
                if c == "\\": j += 1
                elif c == '"': stack.pop()
                elif c == "`": stack.append("`")
                elif c == "$" and line[j + 1:j + 2] == "{":
                    k, d = j + 2, 1
                    while k < len(line) and d: d += (line[k] == "{") - (line[k] == "}"); k += 1
                    if d: insane = True                 # a parameter expansion that does not close on its line: its word can hold substitutions the walk does not follow
                    else: j = k - 1
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
            else:                                   # code position: top level, $( ), $(( )), (( )), backticks, ( )
                if c == "$" and line[j + 1:j + 2] == "{":
                    k, d = j + 2, 1
                    while k < len(line) and d: d += (line[k] == "{") - (line[k] == "}"); k += 1
                    if d: insane = True
                    else: j = k - 1
                elif c == "\\": j += 1
                elif c == "'": stack.append("'")
                elif c == '"': stack.append('"')
                elif c == "`":
                    if top == "`": stack.pop()
                    else: stack.append("`")
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
                elif c.isalpha() and (j == 0 or line[j - 1] in " \t;&|({") and re.match(r"(?:if|while|until|for|select|case)(?![\w.-])", line[j:]) and re.search(r"(?:^|[;&|({]|\bthen|\bdo|\belse|\belif)[ \t]*$", line[:j]):
                    stack.append("kw")                      # a compound command: what follows its fi / done / esac (a pipe to a shell) decides what a heredoc inside it feeds
                elif c.isalpha() and top == "kw" and (j == 0 or line[j - 1] in " \t;&|({") and re.match(r"(?:fi|done|esac)(?![\w.-])", line[j:]):
                    stack.pop()
                elif c == "{" and (j == 0 or line[j - 1] in " \t;&|(") and (j + 1 == len(line) or line[j + 1] in " \t"):
                    stack.append("{")                       # a brace group: what a heredoc inside it feeds is decided by what follows the closing brace
                elif c == "}" and top == "{" and (j == 0 or line[j - 1] in " \t;&|"):
                    stack.pop()
                elif c == "(":
                    if top == "(" and line[j - 1:j] == "(": stack[-1] = "(("
                    else: stack.append("(")
                elif c == ")" and top in ("$(", "(", "$((", "(("):
                    if top == "$(" and re.match(r"[ \t]*\(?[^\s()]+(?:\|[^\s()]+)*$", line[:j]):
                        insane = True                   # a bare word, then `)`, at the start of a line inside $( ): a case pattern, not the end of the substitution; not followed
                    stack.pop()
                    if top in ("$((", "((") and line[j + 1:j + 2] == ")": j += 1
                elif c == "#" and (j == 0 or line[j - 1] in " \t;&|(") : cmt = True
                elif c == "<" and line[j:j + 3] == "<<<":
                    j += 2                          # a here-string, not a heredoc
                elif c == "<" and line[j:j + 2] == "<<" and top not in ("$((", "(("):
                    m = re.match(r"<<(-?)[ \t]*((?:'[^']*'|\"[^\"]*\"|\\.|[^\s;&|()<>'\"\\])+)", line[j:])
                    if m:
                        raw = m.group(2)
                        quoted = bool(re.search(r"['\"\\]", raw))
                        delim = _unquote(raw)
                        ops.append((m.group(1) == "-", quoted, delim, any(s in ("$(", "`", '"', "(", "((", "{", "kw") for s in stack)))
                        j += m.end() - 1
            j += 1
        i += 1
        if not ops:
            continue
        o = i - 1                                   # the opener line
        first = o
        while first > 0 and lines[first - 1].rstrip().endswith("\\"):
            first -= 1
        opener = " ".join(lines[first:o + 1])
        bad = lines[o].rstrip().endswith("\\")      # the command goes on after the operator: where the body starts is not something this walk claims
        stripped = re.sub(r"<<-?[ \t]*(?:'[^']*'|\"[^\"]*\"|\\.|\w+)", " ", opener)
        tee_ops = []
        for m in re.finditer(r"\btee\b((?:[ \t]+(?:-\w+|\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+))+)", opener):
            tee_ops += re.findall(r"\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+", re.sub(r"(?:^|[ \t])-\w+", " ", m.group(1)))
        targets = [t.strip("'\"") for t in re.findall(r"(?:^|[^\d<>&])(?:\d*>>?|&>>?)[ \t]*(\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)", stripped) + tee_ops]
        targets = [t for t in targets if t and not t.startswith("&") and t not in ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty") and not t.startswith("/dev/fd/")]
        for tab, quoted, delim, nested in ops:
            start, k = i, i
            if delim is None:
                hds.append({"open": o, "start": start, "end": None, "quoted": quoted, "nested": nested, "bad": True, "opener": opener, "targets": targets, "ops": len(ops)})
                continue
            while k < n and (lines[k].lstrip("\t") if tab else lines[k]) != delim:
                state[k] = None
                k += 1
            hds.append({"open": o, "start": start, "end": k if k < n else None, "quoted": quoted, "nested": nested, "bad": bad, "opener": opener, "targets": targets, "ops": len(ops)})
            i = (k + 1) if k < n else n
            if k >= n:
                break
    return hds, not stack and not insane, state


def _func_bodies(lines):
    """{name: body text} of the shell functions the file defines (both `name() {` and `function name {`, the brace on the same or the next line)."""
    out = {}
    for idx, ln in enumerate(lines):
        m = _DEF_FUNC.match(ln)
        if not m:
            continue
        name = m.group(1) or m.group(2)
        if "{" not in ln and not (idx + 1 < len(lines) and lines[idx + 1].lstrip().startswith("{")):
            continue
        depth, body, k, seen = 0, [], idx, False
        while k < len(lines):
            bare = re.sub(r"(?:^|(?<=\s))#.*$", "", re.sub(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", "", lines[k]))        # a brace inside a quoted string or a comment does not open or close the function
            body.append(lines[k]); depth += bare.count("{") - bare.count("}"); seen = seen or "{" in bare
            if seen and depth <= 0: break
            k += 1
        out[name] = "\n".join(body)
    return out


def _runs_input(words, funcs, seen=None):
    """True when any of `words` is, or (through the functions the file defines, to any depth) calls, an interpreter, a shell or a command that runs or moves a file."""
    seen = seen if seen is not None else set()
    for w in words:
        if w in _INTERP_WORDS or w in _USE_WORDS:
            return True
        if w in funcs and w not in seen:
            seen.add(w)
            if _runs_input(_words(funcs[w]), funcs, seen):
                return True
    return False


# Functions that may receive a written file's CONTENT as an argument ("$(cat FILE)"), by the sha256 of the whitespace-flattened definition (a new one is a change here: a human gate).
_REVIEWED_FUNCS = {"run": frozenset((
    "ab708ea8cb3a371d0f922e905fed2a26e73c83657149c621e6c47c479d5792d5",   # pin-age-check-test.sh fixture
    "004f644d043348ed9bf307882a5ffe652f7fb62628cf16b2cc1508b957796d46",   # bin/persona-uat-test.sh run()
))}


def _strip_comment(ln):
    """The line without a trailing shell comment: a # starts one only outside quotes, at the start or after whitespace or ; & | ( ."""
    sq = dq = False
    i = 0
    while i < len(ln):
        c = ln[i]
        if sq:
            sq = c != "'"
        elif c == "\\" and not sq:
            i += 1
        elif c == "'" and not dq:
            sq = True
        elif c == '"':
            dq = not dq
        elif c == "#" and not dq and (i == 0 or ln[i - 1] in " \t;&|("):
            return ln[:i]
        i += 1
    return ln


def _reads_only(seg):
    """True when the (already comment-free) segment writes nothing: no output redirection except to /dev/null or a descriptor, no -o / --output option (also clustered, e.g. -uo)."""
    flat = re.sub(r"\d*>&\d+|&>[ \t]*/dev/null|\d*>>?[ \t]*/dev/null(?![^\s;&|<>()])", " ", seg)
    if re.search(r"\d*>|&>", flat):
        return False
    flat = re.sub(r"[\"'\\]", "", flat)                       # judged on the option WORDS: "-o", '--output=x' and -\o spell the same options
    return not re.search(r"(?:^|[ \t])(?:-[A-Za-z]*o\S*|--output\S*)(?=[ \t=]|$)", flat)


def _written_file_used_later(lines, hd):
    """True when a file the heredoc's output goes to (or a variable the script sets to its name) is later named anywhere except: as the argument of a data consumer on a line that is
    nothing but data consumers; in a plain assignment; or read through $(cat FILE) as an argument of a reviewed content-taking function. A closed rule: running, sourcing, copying,
    chmod'ing, a pipe to anything else, a substitution that is evaluated, a program or function the checker does not know all refuse."""
    later = lines[(hd["end"] or hd["start"]) + 1:]
    names = set(hd["targets"])
    for _ in range(4):                                          # a variable that holds the name (set before or after the heredoc; one assignment at a time, a few levels)
        for ln in lines:
            for var, val in re.findall(r"(?:^|[;&|\s])([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)", ln):
                if val.strip("'\"") in names or any(t in val for t in names):
                    names |= {"$" + var, "${" + var + "}"}
    spell = set(names)
    for t in list(names):
        if not t.startswith("$"):
            spell |= {t.lstrip("./") or t, os.path.basename(t.rstrip("/")) or t}
    rxs = [re.compile(r"(?<![\w.$-])" + re.escape(t) + r"(?![\w-])") if not t.startswith("$") else re.compile(re.escape(t)) for t in spell if t]
    funcs = _func_bodies(lines)
    reviewed = {n for n, body in funcs.items() if n in _REVIEWED_FUNCS and _line_hash(" ".join(body.split())) in _REVIEWED_FUNCS[n]}
    readcat = re.compile(r"\$\([ \t]*cat[ \t]+(?:\"(?:[^\"`()]|\$\{?\w+\}?)*\"|'[^']*'|[^\s`$()|;&]+)[ \t]*\)")
    for ln in later:
        ln = _strip_comment(ln)
        if not any(rx.search(ln) for rx in rxs):
            continue
        if "`" in ln:
            return True
        stripped = readcat.sub(" ", ln)
        content = stripped != ln                                  # some mention is a $(cat FILE) read: its content goes to the command
        rest = any(rx.search(stripped) for rx in rxs)
        if "$(" in stripped:
            return True
        segs = [sg for sg in re.split(r"\|\||&&|[|;&]", stripped) if sg.strip()]
        for seg in segs:
            toks = re.findall(r"""(?:[^\s'"]|'[^']*'|"[^"]*")+""", seg)
            if toks and all(re.fullmatch(r"[A-Za-z_]\w*=.*", t) for t in toks):
                continue                                          # a plain assignment (the alias rule above follows the name)
            toks = [t for t in toks if not re.fullmatch(r"[A-Za-z_]\w*=.*", t)]
            first = [t for t in toks if not re.fullmatch(r"\d*[<>]+.*", t)]
            cmd = (_unquote(first[0]) or "").split("/")[-1] if first else ""
            if content and not rest and len(segs) == 1 and cmd in reviewed:
                continue                                          # the content goes to a reviewed function, once, with nothing else on the line
            if cmd not in _DATA_CONSUMERS or content or not _reads_only(seg):
                return True
    return False


_PY_SAFE_BUILTINS = frozenset("print len range str int float bool list dict set tuple frozenset sorted enumerate zip min max sum any all repr isinstance issubclass ord chr abs round "
                              "format map filter reversed bytes bytearray type hash hex bin oct divmod pow iter next slice object id callable chr super property staticmethod classmethod "
                              "Exception BaseException ValueError KeyError TypeError AssertionError RuntimeError SystemExit IndexError StopIteration AttributeError NotImplementedError "
                              "ZeroDivisionError UnicodeDecodeError UnicodeEncodeError LookupError ArithmeticError OverflowError FileNotFoundError".split())
_PY_PURE_MODULES = frozenset("json re sys time datetime hashlib base64 collections itertools functools math string textwrap copy struct binascii unicodedata shlex enum "
                             "dataclasses".split())
_PY_PURE_DOTTED = frozenset(("os.path", "urllib.parse"))
_PY_MODULE_NAMES = frozenset("os sys io builtins posix nt shutil subprocess importlib pathlib tempfile socket ctypes".split())
_PY_SYS_OK = frozenset("argv exit stdin stdout stderr version_info platform maxsize".split())
_PY_SAFE_METHODS = frozenset("""capitalize casefold center count decode encode endswith expandtabs find format format_map index isalnum isalpha isascii isdecimal isdigit isidentifier
    islower isnumeric isprintable isspace istitle isupper join ljust lower lstrip maketrans partition removeprefix removesuffix replace rfind rindex rjust rpartition rsplit rstrip split
    splitlines startswith strip swapcase title translate upper zfill append extend insert pop remove clear sort reverse copy get items keys values setdefault update add discard union
    intersection difference symmetric_difference issubset issuperset popitem fromkeys hex fromhex group groups groupdict start end span sub subn match search fullmatch findall finditer
    pattern hexdigest digest strftime isoformat timestamp date time utcoffset total_seconds astimezone most_common elements total""".split())


def _py_dotted(nd):
    import ast
    parts = []
    while isinstance(nd, ast.Attribute):
        parts.append(nd.attr); nd = nd.value
    if isinstance(nd, ast.Name):
        return ".".join([nd.id] + parts[::-1])
    return None


def _py_program_flags(body):
    """(tree, impure reasons) for the Python source `body`, or (None, ...) when it does not parse. A POSITIVE subset: a program is pure only when every call is to a builtin on the safe
    list, to a function or class the program itself defines, to a pure module's function, or to a method whose name is not a writer; there is no unpacked argument, no name that runs or
    reaches code (exec, eval, compile, __import__, getattr ...) and every import is from the pure list. Anything else is an impurity reason (its rows then need the review label)."""
    import ast
    try:
        tree = ast.parse(body)
    except (SyntaxError, ValueError, RecursionError):
        return None, ["does not parse"]
    why = set()
    mods, defined = {}, set()
    for nd in ast.walk(tree):
        if isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): defined.add(nd.name)
        elif isinstance(nd, ast.Import):
            for a in nd.names:
                if a.name in _PY_PURE_MODULES or a.name in _PY_PURE_DOTTED: mods[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]    # `import os.path` binds os, not os.path
                else: why.add("import " + a.name)
        elif isinstance(nd, ast.ImportFrom):
            if nd.level or (nd.module or "") not in (_PY_PURE_MODULES | _PY_PURE_DOTTED): why.add("import " + (nd.module or "."))
            else:
                for a in nd.names:
                    if a.name in _PY_FORBIDDEN_NAMES or a.name == "open": why.add(a.name)
                    if nd.module == "sys" and a.name not in _PY_SYS_OK: why.add("sys." + a.name)      # an imported member of sys is judged like the attribute
                    mods[a.asname or a.name] = (nd.module or "") + "." + a.name
        elif isinstance(nd, ast.Assign):
            for t in nd.targets:
                if isinstance(t, ast.Name) and isinstance(nd.value, ast.Lambda): defined.add(t.id)
    called = {id(nd.func) for nd in ast.walk(tree) if isinstance(nd, ast.Call)}
    roots = {id(nd.value) for nd in ast.walk(tree) if isinstance(nd, ast.Attribute)}
    for nd in ast.walk(tree):
        if isinstance(nd, ast.Name) and nd.id in mods and nd.id not in defined and id(nd) not in roots and id(nd) not in called:
            why.add("module " + nd.id + " used as a value")
        if isinstance(nd, ast.Attribute) and nd.attr in _PY_MODULE_NAMES and id(nd) not in roots:
            why.add("module " + nd.attr + " reached through an attribute")      # `x = os.path.os`: a module re-exported under a plain name      # `x = sys` then x.modules[...]: an alias the walk below would not follow
    for nd in ast.walk(tree):
        if isinstance(nd, ast.Name) and nd.id in _PY_FORBIDDEN_NAMES and nd.id not in defined: why.add(nd.id)
        if isinstance(nd, ast.Name) and nd.id == "open" and nd.id not in defined: why.add("open")
        if isinstance(nd, ast.Attribute) and nd.attr in _PY_FORBIDDEN_NAMES: why.add(nd.attr)
        if isinstance(nd, ast.Attribute) and nd.attr == "open": why.add("open")
        if isinstance(nd, ast.Attribute):
            dd = _py_dotted(nd)
            if dd and dd.split(".")[0] in mods and mods[dd.split(".")[0]] == "sys" and len(dd.split(".")) > 1 and dd.split(".")[1] not in _PY_SYS_OK: why.add("sys." + dd.split(".")[1])
        if isinstance(nd, ast.Call):
            if any(isinstance(a, ast.Starred) for a in nd.args) or any(k.arg is None for k in nd.keywords): why.add("unpacked arguments")
            f = nd.func
            if isinstance(f, ast.Name):
                if f.id not in _PY_SAFE_BUILTINS and f.id not in defined and f.id not in mods: why.add("call of " + f.id)
            elif isinstance(f, ast.Attribute):
                dotted = _py_dotted(f)
                root = dotted.split(".")[0] if dotted else None
                if root in mods:
                    full = mods[root] + dotted[len(root):] if dotted else ""
                    ms = [m for m in _PY_PURE_MODULES | _PY_PURE_DOTTED if full == m or full.startswith(m + ".")]
                    if not ms: why.add("call of " + full)
                    elif "." in full[len(max(ms, key=len)):].lstrip("."): why.add("call of " + full)      # a name reached THROUGH the module (os.path.os.replace): only the module's own functions pass
                elif root == "os": why.add("call of " + dotted)
                elif f.attr not in _PY_SAFE_METHODS and f.attr not in defined: why.add("method " + f.attr)      # a method on some other object: a closed list of names
            else:
                why.add("a call of a computed function")
    return tree, sorted(why)


def _py_code_part(body, lineno):
    """The 1-based line `lineno` of `body` with its string constants and comments blanked (what is left is the program's CODE on that line, f-string expressions included), or None
    on a tokenizer error."""
    import io, tokenize
    FS, FM, FE = (getattr(tokenize, k, None) for k in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"))
    rows = body.split("\n")
    mask = [[False] * len(r) for r in rows]
    def blank(tk):
        (sr, sc), (er, ec) = tk.start, tk.end
        for r in range(sr, er + 1):
            a = sc if r == sr else 0
            b = ec if r == er else len(rows[r - 1])
            for c in range(a, min(b, len(rows[r - 1]))): mask[r - 1][c] = True
    try:
        for tk in tokenize.generate_tokens(io.StringIO(body).readline):
            if tk.type == tokenize.COMMENT or tk.type == FM or tk.type == FS or tk.type == FE:
                blank(tk)                         # an f-string's literal pieces are text; the expressions between its braces stay code
            elif tk.type == tokenize.STRING:
                if re.match(r"(?i)[a-z]*f", tk.string): return None        # an f-string the tokenizer does not split (before 3.12): not judged
                blank(tk)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return None
    if not 1 <= lineno <= len(rows): return None
    return "".join(" " if m else ch for ch, m in zip(rows[lineno - 1], mask[lineno - 1]))


def _plain_value(s):
    """True when the assignment text has no substitution that RUNS: no $( or backtick outside single quotes, no <( or >( outside every quote, no old-style $[ arithmetic."""
    sq = dq = False
    i = 0
    while i < len(s):
        c = s[i]
        if sq:
            sq = c != "'"
        elif c == "\\":
            i += 1
        elif c == "'" and not dq:
            sq = True
        elif c == '"':
            dq = not dq
        elif c == "`" or (c == "$" and s[i + 1:i + 2] in ("(", "[")):
            return False
        elif not dq and c in "<>" and s[i + 1:i + 2] == "(":
            return False
        i += 1
    return not (sq or dq)


_Q = r"""(?:"(?:[^"`$\\]|\$\{?\w+\}?|\$@|\\.)*"|'[^']*'|[A-Za-z0-9_./:=+,@%^~-]+|\$\{?\w+\}?|"\$\(out (?:[A-Za-z0-9_-]+|"\$\{?\w+\}?")\)")"""
_WORD = r"""(?:"(?:[^"`$\\]|\$\{?\w+\}?)*"|'[^']*'|[A-Za-z0-9_./${}-]+)"""
_REDIR = r"\d*>>?[ \t]*" + _WORD
_DELIMQ = r"""(?:'[^'\s]+'|"[^"\s]+"|\\\w+)"""
_CAT_OPENER = re.compile(r"[ \t]*cat(?:[ \t]+" + _REDIR + r")*[ \t]*<<-?[ \t]*" + _DELIMQ + r"(?:[ \t]+" + _REDIR + r")*[ \t]*")
_ENV_ASSIGN = r"""[A-Za-z_]\w*=(?:"(?:[^"`$\\]|\$\{?\w+\}?)*"|'[^']*'|[A-Za-z0-9_./${}:-]*)"""
_PY_OPENER = re.compile(r"[ \t]*(?:" + _ENV_ASSIGN + r"[ \t]+)*(check[ \t]+)?python3?(?:\.\d+)?[ \t]+-(?:[ \t]+" + _Q + r")*(?:[ \t]+" + _REDIR + r")*[ \t]*<<-?[ \t]*" + _DELIMQ
                        + r"(?:[ \t]+" + _REDIR + r")*[ \t]*")
# Wrapper functions an opener may use (`check python3 - ...`), by the sha256 of the whitespace-flattened definition line. A new wrapper is a change to this list: a human gate.
_REVIEWED_WRAPPERS = {
    "check": frozenset((
        "d9f0551a0eefa0c75ab77d72fe9446ac100bf33458d956b500c865ccf33f2b43",   # persona-uat-agent-test.sh
        "0eeb4484c724571050ef124103472beb31a6983886cd15e2f00c6e6e1a1f2629",   # persona-uat-test.sh
        "9d447de27fa81cc5ba86eada6ef1be1830accd4258ebd950e1e1255ef6ce881d",   # pin-age-check-test.sh (fixture)
    )),
}


# Helper functions an opener's argument may call as "$(NAME arg)": by the sha256 of the whitespace-flattened definition line (a new helper is a change here: a human gate).
_REVIEWED_SUBST = {"out": frozenset(("613b579188d1c362ee67b847f36a06f68538c58197899586022d932ed1bea047",))}


def _opener_form(opener, lines):
    """"cat" or "python" when the opener is exactly one of the closed forms (nothing before, between or after: no pipe, list, substitution, function or continuation), else None."""
    if _CAT_OPENER.fullmatch(opener):
        return "cat"
    m = _PY_OPENER.fullmatch(opener)
    if not m:
        return None
    if re.search(r"\$\(out ", opener):                         # the `out` helper: its definition must be a reviewed line
        defs = [_line_hash(" ".join(l.split())) for l in lines if re.match(r"\s*out\(\)", l)]
        if not defs or not all(d in _REVIEWED_SUBST["out"] for d in defs):
            return None
    if m.group(1):                                            # the `check` wrapper: its definition must be a reviewed line
        defs = [_line_hash(" ".join(l.split())) for l in lines if re.match(r"\s*check\(\)", l)]
        if not defs or not all(d in _REVIEWED_WRAPPERS["check"] for d in defs):
            return None
    return "python"


def _heredoc_ok(hd, lines, funcs, python=False):
    """The here-document is terminated and quoted, is opened by exactly one operator in a closed opener form (a plain `cat [>file] <<'X'`, or for python a `[check] python3 - args [>file]
    <<'X'`), is not nested in a substitution, and its file (if any) is later named only as an argument of a data consumer."""
    if hd is None or not hd["quoted"] or hd["nested"] or hd["bad"] or hd["end"] is None or hd["ops"] != 1:
        return False
    form = _opener_form(hd["opener"], lines)
    if form != ("python" if python else "cat"):
        return False
    return not _written_file_used_later(lines, hd)


def _context_holds(context, proof, text, line_hash):
    """True only when EVERY single-line occurrence of the ruled line (by the hash of its whole flattened text) in `text` has the named context. None found: False."""
    lines = text.split("\n")
    hits = [i for i, l in enumerate(lines)
            if " ".join(l.split()) and all(c in " \t" or not c.isspace() for c in l) and _line_hash(" ".join(l.split())) == line_hash and not (i and lines[i - 1].rstrip().endswith("\\"))]
    if not hits:
        return False
    hds, sane, state = _shell_lex(lines)
    if not sane:
        return False
    trusted = "|".join(re.escape(w) for w in sorted(_DATA_CONSUMERS | _INTERP_WORDS | {"echo", "printf", "true", "test", "tee", "uniq", "xxd"})) + r"|python[\d.]*"
    if (set(_func_bodies(lines)) & (_DATA_CONSUMERS | _INTERP_WORDS | {"python", "python3", "echo", "printf", "true", "test"})) or re.search(r"(?m)^[ \t]*(?:alias[ \t]+[^\s=]|shopt[ \t]+-s[ \t]+expand_aliases)", text) \
            or re.search(r"(?m)(?<![\w.$-])(?:function[ \t]+(?:" + trusted + r")(?![\w.-])|(?:" + "|".join(w for w in trusted.split("|") if w[:1].isalpha()) + r")[ \t]*\(\s*\))", text):
        return False                           # a command the grammar trusts is redefined (or aliases are on): its name proves nothing here
    def in_quoted_heredoc(i):                  # a body line of an inert here-document (a plain quoted `cat <<'X'`, its file never run): text, whatever it says
        return any(h["start"] <= i < h["end"] and _heredoc_ok(h, lines, None) for h in hds if h["end"] is not None)
    if context == "assignment" and re.search(r"\b(?:declare|typeset|integer|(?:local|readonly|export)[ \t]+-\w+)\b", text):
        return False                           # a variable with attributes (integer, array, nameref ...) evaluates or redirects its assignment: nothing in this file is judged plain
    if context in ("comment", "assignment"):
        import shlex
        for i in hits:
            if not (state[i] == () or in_quoted_heredoc(i)):                          # not in plain code position: the shell state around the line decides what it is
                return False
            s = lines[i].strip()
            if context == "comment":
                if not s.startswith("#"): return False
            else:
                if not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", s) or s.endswith("\\") or not _plain_value(s): return False
                lx = shlex.shlex(s, posix=True, punctuation_chars=True); lx.whitespace_split = True; lx.commenters = ""
                try:
                    toks = list(lx)
                except ValueError:
                    return False
                if len(toks) != 1 or not re.match(r"[A-Za-z_][A-Za-z0-9_]*=", toks[0]): return False
        return True
    for i in hits:
        hd = next((h for h in hds if h["start"] <= i < (h["end"] if h["end"] is not None else -1)), None)
        if not _heredoc_ok(hd, lines, None, python=(context == "pystring")):
            return False
        if context == "heredoc":
            continue
        body = "\n".join(lines[hd["start"]:hd["end"]])
        tree, why = _py_program_flags(body)
        if tree is None:
            return False
        if why and "attested by review" not in proof.lower():
            return False
        code = _py_code_part(body, i - hd["start"] + 1)
        if code is None or list(inv.unmeasured_occurrences({"x.sh": code})) or (re.search(r"\b(?:curl|wget)\b", code)):
            return False
    return True


_HEAD_SCRIPTS = {}


def _scripts_at(root, rev):
    return _HEAD_SCRIPTS.setdefault((root, rev), inv.tree_scripts(root, rev))


_RAW_CR = {}


def _has_cr(root, rev, path):
    """True when the file's real bytes hold a carriage return (the scan reads text with universal newlines, which hides one: bash would see a different line). Unreadable: True."""
    key = (root, rev, path)
    if key not in _RAW_CR:
        try:
            raw = subprocess.run(["git", "-C", root, "show", f"{rev}:{path}"], capture_output=True, check=True, timeout=120).stdout if rev is not None else open(os.path.join(root, path), "rb").read()
            _RAW_CR[key] = b"\r" in raw
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            _RAW_CR[key] = True
    return _RAW_CR[key]


_LOOPBACK_OK = {}


PINNED_FETCH_RULING = "pinned fetch, advisor reading Oct 17 (REQ-SUP-001-AC26): "   # nineteen script lines, each honored for its file and its whole-line sha256 only (see PINNED_FETCH)
PINNED_FETCH = {   # file -> the raw text of each pinned line, byte for byte (no trailing space, no carriage return); the head file must hold each exactly once
    'bin/release-assets.sh': [
        'gh release download "$rel" -D release-published',
    ],
    'bin/acceptance-k8s.sh': [
        'docker pull -q curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 && docker tag curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 "$CLIENT_LOCAL"',
    ],
    'bin/acceptance-gradle.sh': [
        '  code=$(curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18095/${key}")',
        'curl -s localhost:18095/metrics > /tmp/metrics-cold.txt',
        'curl -s localhost:18095/metrics > /tmp/metrics-warm.txt',
    ],
    'bin/acceptance-gradle-capped.sh': [
        'head_code() { curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18096/$1"; }',
        'curl -s localhost:18096/metrics > /tmp/capped-metrics.txt',
        'hdr=$(curl -s -D - -o /dev/null -X PUT --data-binary @/tmp/oversized-probe.bin http://localhost:18096/oversizedprobe)',
        "code=$(curl -s -o /dev/null -w '%{http_code}' -I http://localhost:18096/oversizedprobe)",
    ],
    'bin/acceptance-maven.sh': [
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-cold.txt',
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-warm.txt',
        'before_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk \'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
        'after_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk \'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
    ],
    'bin/acceptance-maven-capped.sh': [
        'app_code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w \'%{http_code}\' -I "http://localhost:18099/maven/v1.1/com.fosterstack.bench/app/${app_key}/app.jar")',
        'hdr=$(curl -s -u mvn:acceptance-secret -D - -o /dev/null -X PUT --data-binary @/tmp/mvn-oversized-probe.bin http://localhost:18099/maven/oversizedprobe)',
        "code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w '%{http_code}' -I http://localhost:18099/maven/oversizedprobe)",
    ],
    'bin/install-scanner.sh': [
        '    curl -q -fsSL -g -o "$tmp/go.tgz" "https://go.dev/dl/${gofile}" || die "download failed: go toolchain"',
    ],
    'bin/go-bump-open-pr.sh': [
        '  curl -q -fsSL -g -o "${dl}/published.json" "https://go.dev/dl/${jsonq}" || die "go.dev is unreachable: cannot read the published checksums" 1',
        '    curl -q -fsSL -g -o "${dl}/${tarball}" "https://go.dev/dl/${tarball}" || die "cannot download the Go tarball from go.dev" 1',
    ],
}
_PINNED_FETCH_SHA = {f: {hashlib.sha256(" ".join(l.split()).encode("utf-8", "replace")).hexdigest(): l for l in ls} for f, ls in PINNED_FETCH.items()}
_PINNED_OK = {}


def _pinned_line_ok(root, head, f, lh):
    """True only when the pinned line of file f whose whole-line sha256 is lh is held by the head file byte for byte exactly once, the file is a regular file (not a link),
    there is no carriage return in it and no other line that differs from the pinned one only in whitespace (the scan hashes with whitespace collapsed, so the raw
    text is compared here). Unreadable, or a line the checker does not pin: False. The same shape as the loopback ruling (AC25), for the nineteen lines of AC26."""
    key = (root, head, f, lh)
    if key not in _PINNED_OK:
        ok = False
        raw_line = _PINNED_FETCH_SHA.get(f, {}).get(lh)
        try:
            if raw_line is not None:
                if head is None:
                    path = os.path.join(root, f)
                    ok = os.path.isfile(path) and not os.path.islink(path)
                    raw = open(path, "rb").read() if ok else b""
                else:
                    ent = subprocess.run(["git", "-C", root, "ls-tree", head, "--", f], capture_output=True, check=True, timeout=120).stdout.decode("utf-8", "replace").split()
                    ok = len(ent) >= 4 and ent[0] in ("100644", "100755") and ent[1] == "blob"
                    raw = subprocess.run(["git", "-C", root, "show", f"{head}:{f}"], capture_output=True, check=True, timeout=120).stdout if ok else b""
                if ok:
                    lines = raw.split(b"\n")
                    same = [ln for ln in lines if " ".join(ln.decode("utf-8", "replace").split()) == " ".join(raw_line.split())]
                    ok = b"\r" not in raw and lines.count(raw_line.encode()) == 1 and len(same) == 1
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            ok = False
        _PINNED_OK[key] = ok
    return _PINNED_OK[key]


def _loopback_line_ok(root, head):
    """True only when the head file bin/loopback-get.sh is a regular file (not a link) holding the pinned line byte for byte exactly once, no carriage return anywhere
    and no other line that differs from it only in whitespace (the scan hashes with whitespace collapsed, so the raw text is compared here). Unreadable: False."""
    key = (root, head)
    if key not in _LOOPBACK_OK:
        ok = False
        try:
            if head is None:
                path = os.path.join(root, LOOPBACK_FILE)
                ok = os.path.isfile(path) and not os.path.islink(path)
                raw = open(path, "rb").read() if ok else b""
            else:
                ent = subprocess.run(["git", "-C", root, "ls-tree", head, "--", LOOPBACK_FILE], capture_output=True, check=True, timeout=120).stdout.decode("utf-8", "replace").split()
                ok = len(ent) >= 4 and ent[0] in ("100644", "100755") and ent[1] == "blob"
                raw = subprocess.run(["git", "-C", root, "show", f"{head}:{LOOPBACK_FILE}"], capture_output=True, check=True, timeout=120).stdout if ok else b""
            if ok:
                lines = raw.split(b"\n")
                same = [ln for ln in lines if " ".join(ln.decode("utf-8", "replace").split()) == " ".join(LOOPBACK_LINE.split())]
                ok = b"\r" not in raw and lines.count(LOOPBACK_LINE.encode()) == 1 and len(same) == 1
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            ok = False
        _LOOPBACK_OK[key] = ok
    return _LOOPBACK_OK[key]


def _context_proved(root, head, path, line_hash, row):
    """A row without a context is as it always was; a row with one rules its line only when the context is proved from the head file."""
    ruling, count, context, proof = row
    if context is None:
        return True
    if not path.endswith(".sh"):
        return False
    text = _scripts_at(root, head).get(path)
    return text is not None and not _has_cr(root, head, path) and _context_holds(context, proof, text, line_hash)


def _context_regressions(root, base, head, rulings):
    """{(key, line hash)} of lines a context row rules that held their context in the base and no longer do in the head. Such a line is not "added" (its count is unchanged),
    so the delta never looks at it: without this, a ruled line could be moved out of its heredoc and stay ruled."""
    out = {}
    for k, per in _occurrences(root, head).items():
        for lh, n in per.items():
            row = rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh))
            if not row or row[2] is None or not k[0].endswith(".sh"):
                continue
            was = _scripts_at(root, base).get(k[0])
            if was is not None and not _has_cr(root, base, k[0]) and _context_holds(row[2], row[3], was, lh) and not _context_proved(root, head, k[0], lh, row):
                out.setdefault(k, {})[lh] = n
    return out

MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; this file must not hold them)")


def load_ruled_text(path, required=False):
    """{(file, form, 64-hex segment hash, 64-hex whole-line hash): (ruling, count, context or None, proof)} from the file's unmeasured_text list. A missing default file is no rulings; anything malformed
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
        if not isinstance(r, dict) or set(r) - set(_RULED_FIELDS) - {"count", "context", "proof"} or not set(_RULED_FIELDS) <= set(r):
            raise bad("must be an object with exactly file, form, key, line, ruling (and an optional count, context and proof)")
        if not all(isinstance(r[k], str) and r[k].strip() for k in _RULED_FIELDS):
            raise bad("has an empty or non-text file, form, key, line or ruling")
        if not re.fullmatch(r"[0-9a-f]{64}", r["key"]):
            raise bad("key is not the scan's 64 lowercase hex hash")
        if not re.fullmatch(r"[0-9a-f]{64}", r["line"]):
            raise bad("line is not the 64 lowercase hex hash of the whole flattened line")
        count = r.get("count", 1)
        if type(count) is not int or not 1 <= count <= MAX_RULED_COUNT:
            raise bad(f"count is not a whole number from 1 to {MAX_RULED_COUNT}")
        if r["form"] == LOCAL_CALL_FORM and ("context" in r or "proof" in r):
            raise bad("is a local-call row, which does not take a context or a proof")
        if "context" in r and (type(r["context"]) is not str or r["context"] not in CONTEXTS):
            raise bad("has a context that is not one of " + ", ".join(CONTEXTS))
        if "proof" in r and ("context" not in r or type(r["proof"]) is not str or not r["proof"].strip()):
            raise bad("has a proof that is empty, not text, or has no context to go with")
        k = (r["file"], r["form"], r["key"], r["line"])
        if k in out:
            raise bad("repeats an earlier row (file, form, key and line)")
        out[k] = (r["ruling"].strip(), count, r.get("context"), r.get("proof", "").strip())
    return out


DEFAULT_BASE_INPUTS = os.path.normpath(os.path.join(HERE, "..", "..", "policy", "base-inputs.json"))


_STRICT_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)?")   # a time with a real zone or none (UTC, as parse_time reads it); nothing parse_time would bend (a +99:99 offset)


def load_file_pins(path, required=False):
    """REQ-SUP-001-AC34: {(file, content hash): (published, upstream, version)} from the exceptions file's file_pins list (the BASE branch's copy: rows a pull request brings
    do nothing until merged). A row missing a field, with a content that is not 64 lowercase hex or a published time that is not a time rules nothing. Two rows for
    one (file, content), a list that is not a list or an unreadable file stop the check (RuntimeError, exit 2): never 'nothing ruled' by guesswork and never the older of two."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} (file_pins) does not exist")
        return {}
    try:
        with open(path) as f:
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} (file_pins) is unreadable: {e}")
    rows = d.get("file_pins", []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: file_pins is not a list")
    out, seen = {}, set()
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            raise RuntimeError(f"{path}: file_pins row {i} is not an object")
        f_, c_ = r.get("file"), r.get("content")
        if isinstance(f_, str) and isinstance(c_, str):
            if (f_, c_) in seen:
                raise RuntimeError(f"{path}: file_pins repeats the row for {f_} with content {c_}")
            seen.add((f_, c_))
        fields = [r.get(k) for k in ("file", "content", "upstream", "version", "published")]
        if not all(isinstance(x, str) and x.strip() for x in fields) or not re.fullmatch(r"[0-9a-f]{64}", c_) or not r["upstream"].startswith("https://") \
                or not _STRICT_TIME.fullmatch(r["published"]) or parse_time(r["published"]) is None:
            continue
        out[(f_, c_)] = (r["published"], r["upstream"], r["version"])
    return out


class FilePinSource:
    """Wraps a proof source: a file item the base branch's file_pins names (same file AND same content) gets the row's published time as its proof."""

    def __init__(self, inner, pins):
        self.inner, self.pins, self.notes = inner, pins, {}

    def proofs(self, item, *args):
        out = list(self.inner.proofs(item, *args))
        if is_file_item(item):
            row = self.pins.get((item.raw, item.step[len("content:"):]))
            if row:
                out.append((row[0], FILE_PIN_SOURCE))
                self.notes[item.key] = f"file pin ruled by the base branch: {row[1]} version {row[2]}"
        return out


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
        rs = [r if r is None or _context_proved(root, head, k[0], lh, r) else None for r, lh in zip(rs, per)]
        # a line the base already holds is never ruled here: an item of that line may have moved because an assignment it reads changed, and a copy of
        # the line cannot be told from it (the occurrence is still reported; the item keeps failing)
        if all(r and n <= r[1] and not in_base.get(k, {}).get(lh) for r, (lh, n) in zip(rs, per.items())):
            out.update((k[0], lh) for lh in per)
    return out


GO_EXEMPT_REASON = "exempt from the 7-day hold: Go's own release, downloaded from go.dev and verified against its pinned sha256 (owner ratified Oct 21 2026, REQ-SUP-001-AC27); the advisory check still applies"
_GO_VER_LINE = re.compile(r"^GO_VER=(\d+\.\d+\.\d+)$")
_GO_FILE = re.compile(r'^[ \t]*gofile="go\$\{GO_VER\}\.\$\{A_GO\}\.tar\.gz"[ \t]*$')
_GO_CURL = re.compile(r'^[ \t]*curl -q -fsSL -g -o "\$tmp/go\.tgz" "https://go\.dev/dl/\$\{gofile\}" \|\| die "download failed: go toolchain"[ \t]*$')
_GO_VERIFY = ["verify() { # file", "  local got", "  got=$(sha256sum \"$1\" | cut -d' ' -f1)",
              '  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - refusing to run an unverified scanner"', "}"]
_GO_EXTRACT = re.compile(r'^[ \t]*mkdir -p "\$tmp/x" && tar -xzf "\$tmp/go\.tgz" -C "\$tmp/x" \|\| pipeline_fail "extract failed for go"[ \t]*$')
_GO_MSG = r'"(?:[^"$`\\]|\$\{[A-Za-z_]+\})*"'
_GO_WANT = re.compile(r'^[ \t]*\[ "\$want" = "\$GO_VER" \] \|\| pipeline_fail ' + _GO_MSG + r'[ \t]*$')
_GO_SHOW = re.compile(r'^[ \t]*"\$\{DEST\}/fscache-go/bin/go" version \| grep -q "go\$\{GO_VER\} " \|\| pipeline_fail ' + _GO_MSG + r'[ \t]*$')
_GO_FAIL = ['pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; exit 1; }']
_SUM_ROW = re.compile(r"^[ \t]*[A-Za-z0-9_.:|-]+\) SUM=[0-9a-f]{64} ;;[ \t]*$")
_SUM_MODULE = re.compile(r'^[ \t]*govulncheck:\*\) SUM="" ;;[ \t]*(?:#.*)?$')   # a module pinned by go.sum: its own key, empty sum
_GO_SUM = {a: re.compile(r"^[ \t]*go:" + a + r"\) SUM=[0-9a-f]{64} ;;[ \t]*$") for a in (r"x86_64\|go:amd64", r"aarch64\|go:arm64")}


def go_exemption(root, head):
    """The pinned Go version when the head's bin/install-scanner.sh fetches Go ONLY from https://go.dev/dl/ at its pinned GO_VER, pins the sha256 of both
    architectures (64 hex each) and verifies the file right after the download; otherwise None (the 7-day hold applies). Any other line that downloads
    something Go-shaped (curl or wget naming go.tgz, GO_VER, go.dev or golang) voids it."""
    try:
        text = inv.tree_files(root, head).get("bin/install-scanner.sh")
    except (OSError, ValueError, RuntimeError):
        return None
    if not text:
        return None
    lines = text.split("\n")
    joined = re.sub(r"\\[ \t]*\n", " ", text).split("\n")   # a shell continuation is one command: a download written over two lines is still one
    vers = [m.group(1) for m in (_GO_VER_LINE.match(l) for l in lines) if m]
    if len(vers) != 1 or sum(1 for l in lines if re.match(r"^[ \t]*(?:export[ \t]+)?GO_VER=", l)) != 1:
        return None
    fetch = [i for i, l in enumerate(joined) if re.search(r"\b(curl|wget)\b", l) and re.search(r"go\.tgz|GO_VER|gofile|go\.dev|golang|go\$\{|go[0-9]+\.[0-9]", l)]
    if len(fetch) != 1 or not _GO_CURL.match(joined[fetch[0]]):
        return None
    names = [l for l in joined if re.match(r"^[ \t]*(?:export[ \t]+|readonly[ \t]+|local[ \t]+)?gofile=", l)]
    if len(names) != 1 or not _GO_FILE.match(names[0]):
        return None
    nxt = next((l.strip() for l in joined[fetch[0] + 1:] if l.strip()), "")
    if nxt != 'verify "$tmp/go.tgz"':
        return None
    if any(sum(1 for l in lines if rx.match(l)) != 1 for rx in _GO_SUM.values()) or sum(1 for l in lines if re.search(r"\bgo:", l) and re.search(r"\bSUM", l)) != 2:
        return None
    # the verifier and the failure helper are the reviewed ones, each defined once in ANY spelling (verify() / verify () / function verify)
    for name, want in (("verify", _GO_VERIFY), ("pipeline_fail", _GO_FAIL)):
        if len(re.findall(r"\bfunction[ \t]+" + name + r"\b|\b" + name + r"[ \t]*\([ \t]*\)", text)) != 1:
            return None
        starts = [i for i, l in enumerate(lines) if re.match(r"^" + name + r"\(\)", l)]
        if len(starts) != 1 or [l.rstrip() for l in lines[starts[0]:starts[0] + len(want)]] != want:
            return None
    # the installer defines only the reviewed helpers (a redefined sha256sum, cut or echo would change what verify() computes) and aliases nothing
    defs = set()
    for l in joined:
        if not l.lstrip().startswith("#"):
            q = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l)
            defs.update(re.findall(r"([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\)", q) + re.findall(r"\bfunction[ \t]+([\w.-]+)", q))
            if re.search(r"(?:^|[;&|{(]|\bthen|\bdo|\belse)[ \t]*(?:alias|enable|builtin|unalias)\b", q):
                return None
    if defs - {"verify", "pipeline_fail", "die"}:
        return None
    # the download and its verify call sit at the top level of the go arm of the one tool dispatch: counted from the START of the file, the only open construct at the
    # download is that dispatch `case` (a wrapper around it, a group or loop or condition around the arm, an inline `; (` all raise the depth: refused)
    arm = [i for i, l in enumerate(joined[:fetch[0]]) if re.match(r"^[ \t]*go\)[ \t]*$", l)]
    if len(arm) != 1:
        return None
    depth = 0
    for l in joined[:fetch[0]]:
        t = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l.strip())
        if t.startswith("#"):
            continue
        depth += (len(re.findall(r"(?:^|[;&|)][ \t]*|\bthen[ \t]+|\bdo[ \t]+|\belse[ \t]+)(?:if|while|until|for|select|case)\b", t)) + (1 if t[:1] in "({" else 0)
                 + len(re.findall(r"[;&|][ \t]*[({]", t)) + (1 if re.search(r"\)[ \t]*\{[ \t]*(?:#.*)?$", t) else 0))
        depth -= len(re.findall(r"(?:^|[;&|)][ \t]*)(?:fi|done|esac)\b", t)) + (1 if t[:1] in ")}" else 0)
    if depth != 1:
        return None
    # outside the reviewed lines the Go names appear ONLY in the two reviewed read shapes (a version comparison and the installed-version grep, each ending in a
    # pipeline_fail whose message holds no command substitution); ANY other mention of GO_VER, gofile, go.tgz, go.dev or a Go archive name (go<N>.<N>) in a
    # non-comment line voids the exemption: a write in any form, a second transfer by any command, a URL variable, a read in another command
    for i, l in enumerate(joined):
        if i == fetch[0] or l.lstrip().startswith("#") or _GO_FILE.match(l) or _GO_VER_LINE.match(l) or l.strip() == 'verify "$tmp/go.tgz"' or _GO_EXTRACT.match(l) \
                or _GO_WANT.match(l) or _GO_SHOW.match(l):
            continue
        if re.search(r"GO_VER|gofile|go\.tgz|go\.dev|\bgo[0-9]+\.[0-9]", l):
            return None
    # every SUM assignment, anywhere on any line, is a pinned row: a literal pattern (no glob), `) SUM=<64 hex> ;;`; any other mention of SUM must only read it
    for l in joined:
        rest = re.sub(r"\$\{SUM\}|\$SUM\b", "", l)
        if re.search(r"\bSUM\b", rest) and not (_SUM_ROW.match(l) or _SUM_MODULE.match(l)):
            return None
    return vers[0]


def split_go_exempt(moved, root, head):
    """(the moved items without the exempt Go release, the exempt ones): only `tool:go` at the installer's own pinned version."""
    ver = go_exemption(root, head) if any(it.kind == "tool" and it.name == "go" for it in moved) else None
    keep = [it for it in moved if not (ver and it.kind == "tool" and it.name == "go" and it.version == ver)]
    return keep, [it for it in moved if it not in keep]


def _run(a, moved, fx, now):
    rulings = load_ruled_text(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))   # before the scan: a malformed list stops the check
    lines = _unmeasured_counts(a.root, a.base, a.head)
    for k, per in _context_regressions(a.root, a.base, a.head, rulings).items():
        lines.setdefault(k, {}).update(per)
    added, ruled = [], []
    for k in sorted(lines):
        # ruled only when EVERY added (key, whole line) is named by a row and its head occurrences are within that row's count (1 unless it says more):
        # the same segment inside any other line, an edited line, or one copy too many leaves the item refused
        rs = [rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in lines[k]]
        rs = [r if r is None or _context_proved(a.root, a.head, k[0], lh, r) else None for r, lh in zip(rs, lines[k])]    # a row with a context that does not hold rules nothing
        if k[1] == DOWNLOAD_FORM and any(r and not r[0].startswith((TEXT_RULING, LIVE_RULING, GO_RULING, LOOPBACK_RULING, PINNED_FETCH_RULING)) for r in rs):
            rs = [None]                                  # a download row rules a line only with one of the two rulings the owner's rules name
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(LIVE_RULING) and not _live_fetch_line_ok(_LINE_TEXT.get(lh, "")) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # a live-fetch ruling on a line that is not wholly https on packages.wolfi.dev rules nothing
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(GO_RULING) and not (k[0].endswith(".sh") and not k[0].startswith(".github/") and _live_fetch_line_ok(_LINE_TEXT.get(lh, ""), toolchain=True)) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # a Go-toolchain ruling on a line that is not exactly the one go.dev/dl/ shape rules nothing (AC23)
        if any(r and r[0].startswith(LOOPBACK_RULING) and not (k[0] == LOOPBACK_FILE and lh == LOOPBACK_LINE_SHA256 and _loopback_line_ok(a.root, a.head)) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # the loopback ruling on any line but the helper's one pinned line rules nothing (AC25)
        if any(r and r[0].startswith(PINNED_FETCH_RULING) and not _pinned_line_ok(a.root, a.head, k[0], lh) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # the pinned-fetch ruling on any line but one of the nineteen pinned lines of its own file rules nothing (AC26)
        if all(r and n <= r[1] for r, n in zip(rs, lines[k].values())):
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in rs))))
        else:
            added.append(k)
    moved = drop_ruled_unpinned(moved, ruled_unpinned_lines(a.root, a.base, a.head, a.exceptions or DEFAULT_EXCEPTIONS))   # REQ-SUP-001-AC20
    moved, base_files = split_base_inputs(moved, load_base_inputs(a.base_inputs or DEFAULT_BASE_INPUTS, required=bool(a.base_inputs)))   # REQ-SUP-001-AC21
    moved, ruled_calls = split_ruled_local_calls(moved, rulings)                                                       # REQ-SUP-001-AC19: judged by the ruled row of ITS OWN line, never by another line's
    moved, go_free = split_go_exempt(moved, a.root, a.head)
    if not moved and not added and not go_free:
        print("pin-age: no pin moved (nothing to measure)")
        rows = []
    else:
        rows = check(moved, FilePinSource(Fixture(fx) if fx is not None else Live(a.root, a.base, a.head), load_file_pins(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))), now, a.min_days)
        print(f"pin-age: {len(rows)} moved version(s), each must be public {a.min_days:g} days by a server-side time:")
        for r in rows:
            print(f"  {'ok  ' if r['ok'] else 'FAIL'} {r['item']}: {r['reason']}")
        for it in go_free:
            rows.append({"item": it.key, "label": it.label, "ok": True, "reason": GO_EXEMPT_REASON, "proof": None})
            print(f"  ok   {it.key}: {GO_EXEMPT_REASON}")
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
