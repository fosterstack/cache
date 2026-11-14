#!/usr/bin/env python3
"""The pin age check (REQ-SUP-001-AC2, AC3): a version a pull request moves must have been public 7 days, proven by a
SERVER-SIDE time.

  pin-age-check.py --root REPO --base REV --head REV [--fixtures FILE] [--json FILE] [--now ISO] [--min-days N]
  [--exceptions FILE]

Exit 0: nothing moved, or every moved version is old enough. Exit 1: a moved version is too young or its age cannot be
proven (never a pass).
Exit 2: the check could not run (unreadable input, a tree that does not parse).

Times that count (and nothing else): github-release (a release's publish time), pypi (the index's upload time), go-index
(the Go module index's
timestamp), registry-push (the registry's push time), and the first time the exact version appeared in one of OUR pull
requests. A commit date, a tag
date, a version-control time or an image's own "created" field is set by the publisher or builder and is never a proof.
Fixtures (offline tests): {"now": ISO, "times": {ITEM: {"time": ISO, "source": S}}, "first_seen": {ITEM: ISO}}.
"""
import argparse
import hashlib
import http.client
import datetime as dt
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
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
        if hh > 23 or mm > 59:
            return None
        d = d - sign * dt.timedelta(hours=hh, minutes=mm)
    d = d.replace(tzinfo=dt.timezone.utc)
    if frac and not clock:
        # a publication time's fractional second is rounded UP, a clock's (clock=True) is truncated: an age is never
        # over-counted (AC3)
        d += dt.timedelta(seconds=1)
    return d


# the one predicate lives in pin-inventory.py (its kernel-lock reader needs it); the names stay here for every caller
# and test
_PIN = inv._PIN
is_pin = inv.is_pin


INSTALLER_TOOLS = {tool for inputs in inv.INSTALLER_INPUTS.values() for _, tool in inputs if tool}
FILE_PIN_SOURCE = "file-pin-ruling"


def is_file_item(item):
    """A checksum or version FILE item (its identity is the file's content), the only kind a file_pins row can date."""
    path = getattr(item, "raw", None) or ""
    # a checksum file only: never a version file (.python-version ...)
    return item.kind == "tool" and (item.name or "").startswith("file:") and item.version == "(file)" \
        and (getattr(item, "step", "") or "").startswith("content:") \
        and bool(re.search(r"(?i)(sha256|checksums?)", path.rsplit("/", 1)[-1])) \
        and path.rsplit("/", 1)[-1] not in inv.VERSION_FILES


def judge_item(item, proofs, now, min_days=MIN_DAYS):
    """(ok, reason, proof) from a list of (time-string, source). Only valid server-side proofs in the past count; the
    oldest decides."""
    # REQ-SUP-001-AC34: a file pin the base branch's file_pins row dates
    ruled_file = is_file_item(item) and any(src == FILE_PIN_SOURCE for _, src in proofs)
    if ruled_file:
        # the row's published time decides, never an earlier clock of the pull request
        proofs = [p for p in proofs if p[1] == FILE_PIN_SOURCE]
    if not ruled_file and (re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") \
        or "$" in (item.path or "") or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or ""))):
        return False, (f"not a pin: {item.version!r} is a range, a moving name, a wildcard or an expression, "
                       "or an action not named by its commit, so it has no age"), None
    if item.kind == "tool" and item.name in INSTALLER_TOOLS and len(item.version.lstrip("v").split(".")) < 3:
        return False, (f"not a pin: {item.version!r} is a series, not an exact release "
                       "(the installer picks the newest patch), so it has no age"), None
    bad = next((src[len("bad-label:"):] for _, src in proofs if str(src).startswith("bad-label:")), None)
    if bad is not None:
        return False, (f"age not provable: the label '# {bad}' does not name the pinned commit "
                       "(the label is wrong; this is not a missing clock)"), None
    if item.kind == "image":
        host = _image_registry(item.name)
        if host not in ("ghcr.io", "docker.io"):
            entry = _publisher_entry(item.name)
            if entry is None:
                return False, f"registry {host} is not in image-publishers.json, so nothing vouches for the image", None
            if "unsigned" in entry:
                return True, f"no age asked of an image on {host}: no signature published", None
            return True, f"no age asked of an image on {host}: its signature is checked by cosign-verify", None
        proofs = [p for p in proofs if p[1] == "registry-push"]    # the PR clock never dates an image
    if item.kind in ("tool", "package", "gotool") and any(src in SERVER_SIDE and src not in ("pr-clock", "observer")
            for t, src in proofs):
        # a registry's or a release's own time beats the PR clock: a replaced asset is not out-aged by the version's old
        # clock
        proofs = [(t, src) for t, src in proofs if src not in ("pr-clock", "first-seen")]
    best, seen = None, []
    for t, src in proofs:
        seen.append(src)
        if src not in SERVER_SIDE and src != "first-seen" and not (src == FILE_PIN_SOURCE and ruled_file):
            continue
        if src == "github-release" and item.kind == "action":
            # never alone for an action: the tag may point somewhere new (tj-actions); our observer or our PR clock must
            # have seen the commit
            continue
        d = parse_time(t)
        if d is None or d > now:
            continue
        if best is None or d < best[0]:
            best = (d, src)
    if best is None:
        return False, "age not provable: no server-side publish time" + (f" (refused or unusable: {', '.join(seen)})"
            if seen else " found"), None
    age = (now - best[0]).total_seconds() / 86400
    proof = {"time": best[0].strftime("%Y-%m-%dT%H:%M:%SZ"), "source": best[1], "age_days": round(age, 2)}
    if age + 1e-9 < min_days:
        return False, f"too young: {age:.1f} days old by {best[1]} (needs {min_days:g})", proof
    return True, f"{age:.1f} days old by {best[1]}", proof


# ---------- live providers (a real run, no fixtures) ----------
class CouldNotLook(Exception):
    """The server could not be asked (rate limit, outage): the check cannot run. Never read as 'no proof', never a
    pass."""


GH_TIMEOUT = 120


def _gh_run(cmd, **kw):
    """subprocess.run for the gh and git calls here, with a timeout: a call that hangs is CouldNotLook (the run
    stops), never an answer."""
    try:
        return subprocess.run(cmd, **dict({"timeout": GH_TIMEOUT}, **kw))
    except subprocess.TimeoutExpired:
        raise CouldNotLook(f"{cmd[0]} {' '.join(map(str, cmd[1:3]))} did not answer in {GH_TIMEOUT}s")


def _gh_status(r):
    """The status gh reports: the token "(HTTP 404)" that ends the last line of its error text, else None. A URL or a
    body that mentions a token earlier in the text is not read."""
    lines = r.stderr.strip().splitlines()
    m = re.search(r"\(HTTP (\d{3})\)$", lines[-1].strip()) if lines else None
    return int(m.group(1)) if m else None


def _gh_failed(r):
    """True for a plain miss; raises when the failure is the service's, not the answer's."""
    if _gh_status(r) not in (404, 410, 422):
        raise CouldNotLook(f"GitHub API: {(r.stderr or r.stdout).strip()[:120]}")
    return True


_NULL = type(None)


def _shaped(value, need, what):
    """The one way to read a JSON object answer: `need` is ((key, type or tuple of types), ...), given by every caller
    (no default). An answer that is not an object,
    or lacks a needed key, or holds it as another type, is an answer we cannot read (CouldNotLook): never 'nothing
    there'. Keys a caller reads with .get are the
    optional ones; each of those is type-checked where it is used."""
    if not isinstance(value, dict):
        raise CouldNotLook(f"{what} is not a JSON object")
    for key, typ in need:
        types = typ if isinstance(typ, tuple) else (typ,)
        got = value.get(key)
        if key not in value or not isinstance(got, types) or (isinstance(got, bool) and bool not in types):
            raise CouldNotLook(f"{what} lacks {key!r} of the expected type")
    return value


def _dicts(value, what, need):
    """A list of JSON objects each holding every key of `need` (CouldNotLook otherwise): an element of another shape
    is an answer we cannot read."""
    if not isinstance(value, list):
        raise CouldNotLook(f"{what} is not a list of JSON objects")
    for x in value:
        _shaped(x, need, what)
    return value


def _gh_pages(path, rows):
    """Every page of a list endpoint (gh --paginate with --jq '.[]' prints one JSON object per line); every row must
    hold the keys of `rows`."""
    r = _gh_run(["gh", "api", "--paginate", path, "--jq", ".[]"], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return None
    try:
        got = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")
    return _dicts(got, f"GitHub API {path.split('?')[0]}", rows)


_MISS = object()


def _gh_json(path):
    """The JSON a `gh api path` call prints; _MISS only for a plain miss (404)."""
    r = _gh_run(["gh", "api", path], capture_output=True, text=True)
    if r.returncode:
        _gh_failed(r)
        return _MISS
    try:
        return json.loads(r.stdout)
    except ValueError:
        raise CouldNotLook(f"GitHub API {path.split('?')[0]} did not return JSON")


def _gh_api(path, need):
    """A GitHub object answer holding every key of `need`; None only for a plain miss (404)."""
    got = _gh_json(path)
    return None if got is _MISS else _shaped(got, need, f"GitHub API {path.split('?')[0]}")


def _gh_list(path, rows):
    """One page of a GitHub list answer, every row holding the keys of `rows`; None only for a plain miss (404)."""
    got = _gh_json(path)
    return None if got is _MISS else _dicts(got, f"GitHub API {path.split('?')[0]}", rows)


_GONE = object()        # the server said 404 or 410, the one answer that means "not there"


def _fetch_json(url, timeout=30):
    """The raw decoded answer, or _GONE for a 404/410. A network error, a timeout, a 5xx or a body that is not JSON
    means we could not look (CouldNotLook).
    PRIVATE: its one caller is _http_dict, which shapes it before anyone else sees it (a test enforces the single
    caller)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return _GONE
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} answered HTTP {e.code}")
    except (OSError, ValueError, http.client.HTTPException) as e:
        raise CouldNotLook(f"{urllib.parse.urlsplit(url).netloc} could not be asked ({type(e).__name__})")


def _http_dict(url, need, timeout=30):
    """An endpoint that answers with a JSON object holding every key of `need` (no default: the caller says what it
    reads). None only when the server said 404/410;
    valid JSON of another shape, a JSON null or a missing key is an answer we cannot read (CouldNotLook), never 'nothing
    there'."""
    d = _fetch_json(url, timeout)
    if d is _GONE:
        return None
    return _shaped(d, need, urllib.parse.urlsplit(url).netloc + " answer")


TOOL_REPOS = {  # tool -> (github repo, tag prefix to try after the bare version)
    "trivy": "aquasecurity/trivy", "grype": "anchore/grype", "syft": "anchore/syft", "snyk": "snyk/cli",
        "osv": "google/osv-scanner",
    "scout": "docker/scout-cli", "golangci-lint": "golangci/golangci-lint", "python": "actions/python-versions",
    "buildx": "docker/buildx", "goreleaser": "goreleaser/goreleaser", "cosign": "sigstore/cosign",
        "kind": "kubernetes-sigs/kind", "helm": "helm/helm", "node": "nodejs/node",
}


# a release answer holds both (published_at is null on a draft): a missing key is no release, it is an unreadable answer
_RELEASE = (("published_at", (str, _NULL)), ("draft", bool))


_TAGS = {}


def _tag_refs(repo):
    """{tag: commit} for EVERY tag of a public repository, annotated tags peeled, from ONE `git ls-remote` (no REST call
    per tag: a repository with hundreds
    of annotated tags would otherwise exhaust the shared API budget)."""
    if repo not in _TAGS:
        try:
            r = subprocess.run(["git", "ls-remote", "--tags", f"https://github.com/{repo}.git"], capture_output=True,
                text=True, timeout=180)
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


def _go_escape(path):
    """The Go module proxy's case encoding: each upper-case letter is written "!" and its lower-case form."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


_MODINFO = (("Version", str),)      # a module info answer holds its version


def _go_module(path, version):
    parts = path.split("/")
    for n in range(len(parts), 0, -1):
        mod = "/".join(parts[:n])
        url = (f"https://proxy.golang.org/{urllib.parse.quote(_go_escape(mod), safe='/!')}"
               f"/@v/{urllib.parse.quote(version)}.info")
        info = _http_dict(url, _MODINFO)
        if info is None:
            continue      # not there: try the shorter module path
        if not info["Version"]:
            # a 200 we cannot read is not "module not found", in either mode
            raise CouldNotLook("proxy.golang.org answered with something that is not a module info object")
        return mod, info
    return None, None


def _go_index_time(mod, version, vcs_time):
    """The Go module index's timestamp for module@version: scan the index from the version-control time forward (the
    index entry follows it).
    Every row of a page is validated before any is used: an unreadable row is CouldNotLook, never 'not this module'."""
    since = vcs_time
    for _ in range(40):
        try:
            with urllib.request.urlopen(f"https://index.golang.org/index?since={urllib.parse.quote(since)}&limit=2000",
                    timeout=30) as r:
                lines = [ln for ln in r.read().decode().splitlines() if ln.strip()]
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise CouldNotLook(f"index.golang.org could not be asked ({type(e).__name__})")
        rows = []
        for ln in lines:
            try:
                row = json.loads(ln)
            except ValueError:
                raise CouldNotLook("index.golang.org answered with a line that is not JSON")
            if not (isinstance(row, dict)
                    and all(isinstance(row.get(k), str) and row.get(k) for k in ("Path", "Version", "Timestamp"))):
                raise CouldNotLook("index.golang.org answered with a row that is not {Path, Version, Timestamp}")
            rows.append(row)
        for row in rows:
            # exact (the module path is case-sensitive); every row was validated above
            if row["Path"] == mod and row["Version"] == version:
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
    """The cumulative tag observations of OUR scheduled runs on main (None before the first one); loud if they exist and
    cannot be read.
    Only runs of this workflow's path with event=schedule, branch main and conclusion success or failure are read
    (tag_observer.accept_run: a failed daily run still wrote its state), so a pull request can never forge them."""
    if "state" in _OBS:
        return _OBS["state"]
    repo = os.environ.get("GITHUB_REPOSITORY")
    state = None
    if repo:
        data = _gh_api(
            f"repos/{repo}/actions/workflows/supply-chain.yml/runs"
            f"?event=schedule&branch=main&status=completed&per_page=100", (("workflow_runs", list),)
        ) or {"workflow_runs": []}
        wruns = _dicts(data["workflow_runs"], "the scheduled workflow runs", (("id", int),))
        runs = sorted((r for r in wruns if tobs.accept_run(dict(r, path=str(r.get("path") or "").split("@")[0]))),
            key=lambda r: r.get("created_at", ""), reverse=True)
        for run in runs[:30]:
            adata = _gh_api(f"repos/{repo}/actions/runs/{run['id']}/artifacts", (("artifacts", list),
                )) or {"artifacts": []}
            arts = _dicts(adata["artifacts"], "the artifacts of a scheduled run", (("id", int), ("name", str)))
            art = next((x for x in arts if x["name"] == tobs.STATE_NAME and not x.get("expired")), None)
            if art:
                raw = _gh_bytes(f"repos/{repo}/actions/artifacts/{art['id']}/zip")
                try:
                    state = tobs.unpack(raw)
                except Exception as e:  # a state that exists but cannot be read is loud, never "nothing observed"
                    raise CouldNotLook(f"the tag observations of a scheduled run cannot be read: {type(e).__name__}")
                break
    # None: runs that predate the artifact, or none yet: nothing observed, so ages only get younger
    _OBS["state"] = state
    return state


_INV_CACHE = {}


def _pr_clock(item, root, base, head="HEAD"):
    """The PR clock: the earliest server-side time of a workflow run on the first commit of base..head whose INVENTORY
    holds this exact item
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
    # the earliest run whose head CONTAINS the commit: a commit that was never a pushed head has no run of its own
    # (base..head bounds the walk)
    for c in commits[first:]:
        if c != intro and _gh_run(["git", "-C", root, "merge-base", "--is-ancestor", intro, c],
                capture_output=True).returncode != 0:
            continue      # a sibling in a merge does not contain the introducing commit: its runs lend no clock
        times = _run_times(repo, c)
        if times:
            return min(times)
    return None


def _run_times(repo, commit):
    rdata = _gh_api(f"repos/{repo}/actions/runs?head_sha={commit}&per_page=100", (("workflow_runs", list),
        )) or {"workflow_runs": []}
    runs = _dicts(rdata["workflow_runs"], "the workflow runs of a commit", (("created_at", (str, _NULL)),))
    times = [x["created_at"] for x in runs if x["created_at"]]
    r2 = _gh_run(["gh", "api", "--paginate", f"repos/{repo}/commits/{commit}/check-suites?per_page=100", "--jq",
        ".check_suites[]"], capture_output=True, text=True)
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
                # a check from a non-Actions app counts too: the EARLIEST server-side sign of the commit
                times.append(c)
    return times


def _release_with_assets(repo, tags):
    for tag in tags:
        rel = _gh_api(f"repos/{repo}/releases/tags/{urllib.parse.quote(tag)}", _RELEASE + (("assets", list),))
        if rel and rel["published_at"] and not rel["draft"]:
            # name, created_at and updated_at are optional: an asset without a name matches no download, so the release
            # lends no proof (the pin then fails as unprovable)
            _dicts(rel["assets"], "the assets of a release", ())
            return rel
    return None


def live_proofs(item, root, base=None, head="HEAD"):
    out = []
    if re.search(r"\$\{|\(variable\)|\(expression\)|\(unmeasured", item.name or "") or "$" in (item.path or "") \
        or "`" in (item.path or "") or not is_pin(item.version) \
            or (item.kind == "action" and not re.fullmatch(r"[0-9a-f]{40}", item.version or "")):
        # a placeholder, a range, a variable or an action not named by its commit has no age: nothing is looked up (and
        # nothing can pass)
        return out
    if item.kind == "action":
        # the age of the EXACT commit: when our own scheduled run first saw the tag point at it (a release date proves
        # nothing about a moved tag),
        # or the PR clock; the tag in the `# vX` label must itself resolve to the pinned commit
        tags = _tags_for_commit(item.name, item.version)
        want = [item.label] if item.label else tags
        if item.label and item.label not in tags:
            # the label Dependabot bumps does not resolve to this commit: age not provable, with no PR clock to lean on
            return [(None, "bad-label:" + item.label)]
        state = observed()
        for tag in want:
            t = tobs.first_seen(state, item.name, tag, item.version)
            if t:
                out.append((t, "observer"))
    elif item.kind == "tool":
        # owner/repo: a downloaded release asset
        repo = TOOL_REPOS.get(item.name) or (item.name if re.fullmatch(r"[\w.-]+/[\w.-]+", item.name) else None)
        if repo:
            bare = item.version.lstrip("v")
            # a download names its EXACT tag: no twin tag lends its age
            rel = _release_with_assets(repo, [item.label] if item.label else [item.version, "v" + bare, bare])
            if rel:
                # the NEWEST of the release date and every asset's own created/updated time: a replaced asset in an old
                # release is young again
                # the asset we download: a missing one borrows no other asset's age
                assets = [a for a in rel.get("assets", []) if not item.path or a.get("name") == item.path.split("#")[0]]
                if item.path.split("#")[0] and not assets:
                    return out
                stamps = [rel["published_at"]] + [a[k] for a in assets for k in ("created_at", "updated_at")
                    if a.get(k)]
                out.append((max(stamps, key=lambda x: parse_time(x)
                    or dt.datetime.min.replace(tzinfo=dt.timezone.utc)), "github-release"))
    elif item.kind == "gotool":
        mod, info = _go_module(item.name, item.version)
        if mod:
            # no readable version-control time: no go-index proof (the pin then fails as unprovable)
            t = _go_index_time(mod, info["Version"], info["Time"]) if isinstance(info.get("Time"), str) else None
            if t:
                out.append((t, "go-index"))
    elif item.kind == "package":
        name = item.name.split("/", 1)[1]
        d = _http_dict(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(item.version)}/json",
            (("urls", list),))
        # the upload time is optional, text when there
        ups = [u.get("upload_time_iso_8601")
               for u in _dicts((d or {"urls": []})["urls"], "pypi urls", ()) if u.get("upload_time_iso_8601")]
        if not all(isinstance(x, str) for x in ups):
            raise CouldNotLook("pypi.org answered with an upload time that is not text")
        if ups:
            out.append((max(ups), "pypi"))  # the newest file: a wheel added later to an old release is young
    elif item.kind == "image" and item.version:
        if _image_registry(item.name) in ("ghcr.io", "docker.io"):
            t = _registry_push(item)
            return [(t, "registry-push")] if t else []
        return []
    pc = _pr_clock(item, root, base, head)
    if pc:
        out.append((pc, "pr-clock"))
    return out


HUB_HOSTS = ("docker.io", "index.docker.io", "registry-1.docker.io")


def _split_image(name):
    """(registry, path) of an image name. A first part with a dot, a colon or localhost is the registry, lowercase,
    without :443, Docker Hub's hosts as docker.io; else Docker Hub (a name of three parts without a host has no
    registry we know, so its first part stands)."""
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        host = first.lower().removesuffix(":443")
        return ("docker.io" if host in HUB_HOSTS else host), rest
    return ("docker.io" if name.count("/") <= 1 else first), name


def _image_registry(name):
    return _split_image(name)[0]


DOCKER_SECONDS = 600


def _json_file(path):
    """The JSON in a local file (OSError or ValueError if it cannot be read)."""
    with open(path) as f:
        return json.load(f)


POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "policy")
PUBLISHER_PINS_FILE = os.path.join(POLICY_DIR, "image-publishers.json")     # pinned by hand, never discovered


def _registry_push(item):
    host = _image_registry(item.name)
    if host == "ghcr.io":
        owner, _, pkg = _split_image(item.name)[1].partition("/")
        for scope in ("orgs", "users"):
            for page in (1, 2, 3):
                vs = _gh_list(
                    f"{scope}/{owner}/packages/container/{urllib.parse.quote(pkg, safe='')}"
                    f"/versions?per_page=100&page={page}",
                    (("name", str), ("created_at", (str, _NULL))))
                if not vs:
                    break
                for v in vs:
                    if v.get("name") == item.version:
                        return v.get("created_at")
        return None
    if host == "docker.io":
        path = _split_image(item.name)[1].split("/")
        ns, repo = ("library", path[0]) if len(path) == 1 else path
        url = f"https://hub.docker.com/v2/repositories/{ns}/{repo}/tags?page_size=100"
        for _ in range(5):
            d = _http_dict(url, (("results", list),))
            if d is None:
                return None
            for tag in _dicts(d["results"], "hub.docker.com results", ()):
                # digest, images and tag_last_pushed are optional
                if tag.get("digest") == item.version or any(
                        i.get("digest") == item.version
                        for i in _dicts(tag.get("images", []), "hub.docker.com images", ())):
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


PIN_FIELDS = ("key", "keyless", "unsigned", "source", "key_source")


def _is_identity(i):
    return isinstance(i, dict) and all(isinstance(i.get(k), str) and i[k] for k in ("issuer", "subject"))


def _checked_pins(pins):
    """The publisher entries of the pins file (names starting with _ are notes). ValueError unless each entry has a key
    or
    keyless identities and every field it has is well formed."""
    entries = {k: v for k, v in pins.items() if not k.startswith("_")} if isinstance(pins, dict) else None
    if not entries:
        raise ValueError("image-publishers.json pins no image")
    for name, pin in entries.items():
        if not isinstance(pin, dict) or not ({"key", "keyless", "unsigned"} & set(pin)) or set(pin) - set(PIN_FIELDS):
            raise ValueError(f"image-publishers.json: {name} has no key, keyless identity or unsigned reason, "
                             "or a field that is not known")
        if "unsigned" in pin and ({"key", "keyless"} & set(pin) or not (isinstance(pin["unsigned"], str)
                                                                         and pin["unsigned"].strip())):
            raise ValueError(f"image-publishers.json: {name} has an unsigned that is not text, or beside a key")
        if "key" in pin and not (isinstance(pin["key"], str) and pin["key"].strip()):
            raise ValueError(f"image-publishers.json: {name} has a key that is not text")
        for note in ("source", "key_source"):
            if note in pin and not (isinstance(pin[note], str) and pin[note].strip()):
                raise ValueError(f"image-publishers.json: {name} has a {note} that is not text")
        idents = pin.get("keyless", [])
        if "keyless" in pin and not (isinstance(idents, list) and idents and all(_is_identity(i) for i in idents)):
            raise ValueError(f"image-publishers.json: {name} has keyless identities that are not a list of "
                             "issuer and subject")
    return entries


def _publisher_entry(name, pins=None):
    """The image-publishers.json entry for an image: its own name, else its registry; None when neither is enrolled."""
    try:
        pins = pins or _checked_pins(_json_file(PUBLISHER_PINS_FILE))
    except (OSError, ValueError) as e:
        raise RuntimeError(f"cannot read image-publishers.json: {e}")
    host, path = _split_image(name)
    return pins.get(f"{host}/{path}") or pins.get(host)


def cosign_verify_images(root, rev, cosign_image, run):
    """For each image the tree at `rev` names by digest, run `cosign verify` once per pinned identity.
    An image passes when any run succeeds. An image on a registry not in image-publishers.json fails, and one whose
    entry says the publisher signs nothing is reported as "no signature published", never as verified. Images on
    ghcr.io and Docker Hub are dated by their registry time and left to that check unless enrolled.
    `run(cmd)` returns the exit code. Only `verify` is run, never a write."""
    pins = _checked_pins(_json_file(PUBLISHER_PINS_FILE))
    results, seen = [], set()
    with tempfile.TemporaryDirectory() as d:
        for it in inv.load_at(root, rev).values():
            by_digest = (it.version or "").startswith("sha256:")
            if it.kind != "image" or not by_digest or (it.name, it.version) in seen:
                continue
            seen.add((it.name, it.version))
            pin = _publisher_entry(it.name, pins)
            if pin is None and _image_registry(it.name) in ("ghcr.io", "docker.io"):
                continue
            if pin is None or "unsigned" in pin:
                reason = "no signature published" if pin else f"registry {_image_registry(it.name)} is not enrolled"
                results.append({"name": it.name, "digest": it.version, "ok": pin is not None, "reason": reason,
                                "verified": False})
                continue
            ref, cmds, docker_run = f"{it.name}@{it.version}", [], ["docker", "run", "--rm"]
            if "key" in pin:
                key_file = os.path.join(d, f"key{len(seen)}.pub")
                with open(key_file, "w") as f:
                    f.write(pin["key"])
                mount = f"{key_file}:/pin/key.pub:ro"
                cmds.append(docker_run + ["-v", mount, cosign_image, "verify", "--key", "/pin/key.pub", ref])
            for ident in pin.get("keyless", []):
                cmds.append(docker_run + [cosign_image, "verify", "--certificate-identity", ident["subject"],
                                          "--certificate-oidc-issuer", ident["issuer"], ref])
            codes = [run(c) for c in cmds]                      # every pinned identity is tried, so the log shows each
            ok = any(c == 0 for c in codes)
            reason = "" if ok else f"cosign verify found no pinned identity that signed it ({len(cmds)} tried)"
            results.append({"name": it.name, "digest": it.version, "ok": ok, "reason": reason, "verified": ok})
    return results


def _run_docker(cmd):
    """The exit code of one `docker run ... cosign verify` command."""
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, timeout=DOCKER_SECONDS).returncode
    except subprocess.TimeoutExpired:
        raise RuntimeError("docker timed out") from None


def _one_line(error):
    """An error as one line. Its text can hold a pull request's file path, and a path may contain newlines;
    a log line that starts with :: is an Actions command, and the runner reads ##[command] anywhere in a line."""
    text = " ".join("".join(c if c.isprintable() else " " for c in str(error)).split())
    return text.replace("##[", "## [")


def _cosign_verify_main(argv):
    ap = argparse.ArgumentParser(prog="pin-age-check.py cosign-verify")
    ap.add_argument("--root", default=".")
    ap.add_argument("--head", required=True)
    ap.add_argument("--cosign-image", help="the pinned cosign image, by digest")
    ap.add_argument("--tools-file", help="the file whose \"cosign\" entry pins it (bin/persona-uat-tools.json)")
    a = ap.parse_args(argv)
    try:
        if bool(a.cosign_image) == bool(a.tools_file):
            raise ValueError("give exactly one of --cosign-image and --tools-file")
        if a.tools_file:
            tools = _json_file(a.tools_file)
            if not isinstance(tools, dict):
                raise ValueError("the tools file is not an object")
            a.cosign_image = tools["cosign"]
        by_digest = r"[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}"
        if not isinstance(a.cosign_image, str) or not re.fullmatch(by_digest, a.cosign_image):
            raise ValueError("the cosign image must be named by digest")
    except (OSError, ValueError, KeyError) as e:
        print(f"pin-age: cannot run: {_one_line(e)} (not a pass)", file=sys.stderr)
        return 2
    try:
        results = cosign_verify_images(a.root, a.head, a.cosign_image, _run_docker)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"pin-age: cannot run: {_one_line(e)} (not a pass)", file=sys.stderr)
        return 2
    if not results:
        print("pin-age: no pinned image in the tree, nothing to verify")
    for r in results:
        status = "ok   " if r["verified"] else "none " if r["ok"] else "FAIL "
        print(f"{status}{r['name']}@{r['digest']}" + ("" if r["verified"] else f": {r['reason']}"))
    return 0 if all(r["ok"] for r in results) else 1


def main(argv=None):
    if (argv if argv is not None else sys.argv[1:])[:1] == ["cosign-verify"]:
        return _cosign_verify_main((argv if argv is not None else sys.argv[1:])[1:])
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--fixtures")
    ap.add_argument("--json")
    ap.add_argument("--now")
    ap.add_argument("--min-days", type=float, default=MIN_DAYS)
    ap.add_argument("--base-inputs",
        help="the base-inputs list (default: .github/policy/base-inputs.json beside this script's own checkout, the "
            "base branch in CI)")
    ap.add_argument("--exceptions",
        help="the rulings file (default: the one beside this script's own checkout, the base branch in CI)")
    a = ap.parse_args(argv)
    try:
        fx = json.load(open(a.fixtures)) if a.fixtures else None
        if a.fixtures and not isinstance(fx, dict):
            raise ValueError("--fixtures is not a JSON object")
        now = parse_time(a.now, True) if a.now else (parse_time((fx or {}).get("now"), True) if fx and fx.get("now")
            else dt.datetime.now(dt.timezone.utc))
        if now is None:
            raise ValueError("--now is not an ISO time")
        base_items = inv.load_at(a.root, a.base)
        head_items = inv.load_at(a.root, a.head)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"pin-age: cannot run: {_one_line(e)}", file=sys.stderr)
        return 2
    moved = inv.moved(base_items, head_items)
    try:
        return _run(a, moved, fx, now)
    except RuntimeError as e:
        print(f"pin-age: cannot run: {_one_line(e)} (not a pass)", file=sys.stderr)
        return 2
    # an answer of a shape nobody guarded: the check cannot run, it is never a pass and never a traceback
    except (AttributeError, KeyError, TypeError, IndexError, ValueError) as e:
        print(f"pin-age: cannot run: an answer could not be read ({type(e).__name__}) (not a pass)", file=sys.stderr)
        return 2
    except CouldNotLook as e:
        print(f"pin-age: cannot run: {_one_line(e)} (not a pass: re-run the check)", file=sys.stderr)
        return 2


def _line_hash(flat):
    return hashlib.sha256(flat.encode("utf-8", "replace")).hexdigest()


def _occurrences(root, rev):
    """{key: {whole-line hash: occurrences}}. A line bash reads differently from the flattening (whitespace other than
    space or tab, a continuation) gets
    a group no row can name ('unruled:' + its hash)."""
    out = {}
    # a read error propagates (exit 2)
    for k, flat, bashlike in inv.unmeasured_occurrences(
            {**inv.tree_surfaces(root, rev), **inv.tree_files(root, rev), **inv.tree_scripts(root, rev)}):
        lh = _line_hash(flat) if bashlike else "unruled:" + _line_hash(flat)
        _LINE_TEXT[lh] = flat
        per = out.setdefault(k, {})
        per[lh] = per.get(lh, 0) + 1
    return out


def _unmeasured_counts(root, base, head):
    """{key: {whole-line hash: head occurrences}} for every (key, whole line) the head has MORE of than the base: an
    occurrence is identified by its key
    AND the whole line it sits in, so an edited line that keeps its download segment is an addition, like a new one
    (REQ-SUP-001-AC16)."""
    b, h = _occurrences(root, base), _occurrences(root, head)
    added = {}
    for k, per in h.items():
        for lh, n in per.items():
            if n > b.get(k, {}).get(lh, 0):
                added.setdefault(k, {})[lh] = n
    return added


# keys are (file, form, the normalised command): an in-place swap or an edit of the line around it is an ADDITION
def _added_unmeasured(root, base, head):
    """Install forms this check cannot measure that the head has MORE of than the base (per file, form and whole
    line): a PR that adds one is refused."""
    return sorted(_unmeasured_counts(root, base, head))


# REQ-SUP-001-AC16: the advisor's rulings on lines that only MENTION a download tool (a comment, an echo string, a stub
# written as data). They are read from
# the exceptions file beside the checkout this script runs from: in CI that is trusted/ (the base branch), never the
# pull request's tree (--root).
DEFAULT_EXCEPTIONS = os.path.normpath(os.path.join(HERE, "..", "..", "supply-chain-exceptions.json"))
_RULED_FIELDS = ("file", "form", "key", "line", "ruling")
TEXT_RULING = "text, not a command: "      # the convention: a line that only MENTIONS a download tool
# a real fetch, honored only for https on packages.wolfi.dev (see _live_fetch_line_ok)
LIVE_RULING = "live fetch, owner ratified (Oct 9 rule 48 / Oct 15 exception 2): "
# the Go toolchain tarball (REQ-SUP-001-AC23): honored only for https://go.dev/dl/ plus one variable
GO_RULING = "pinned toolchain fetch, advisor reading Oct 16 (rule 12, the recipe pin is verified before storing): "
DOWNLOAD_FORM = "a download"
_LIVE_URL = re.compile(r"https://packages\.wolfi\.dev(?:/[A-Za-z0-9._+~/-]*)?")
# the per-package fetch (advisor, Oct 15, owner rule 48): the literal https://packages.wolfi.dev/os/ (trailing slash
# included, so the host cannot change) followed by
# exactly ONE variable and nothing else
_LIVE_URL_VAR = re.compile(r"https://packages\.wolfi\.dev/os/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_GO_OUT = re.compile(r"(?:[A-Za-z0-9_./-]|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})+")
_GO_URL_VAR = re.compile(r"https://go\.dev/dl/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_LINE_TEXT = {}                              # whole-line hash -> the flattened line, filled by _occurrences


_LIVE_FLAG_PLAIN = {"-f", "-s", "-S", "-L", "-fsSL", "-fsS", "-fSL", "-sSL", "-g", "--globoff", "--fail", "--silent",
    "--show-error", "--location", "--tlsv1.2"}
_LIVE_FLAG_VALUE = {"--max-filesize": r"[0-9]+", "--max-time": r"[0-9]+", "--proto": r"=https",
    "-o": r"[A-Za-z0-9_./${}-]+", "--output": r"[A-Za-z0-9_./${}-]+"}


def _live_fetch_line_ok(flat, toolchain=False):
    """The bound line is exactly ONE curl command: curl or /usr/bin/curl, then only flags from a fixed list (with a
    plain value where one is taken), then exactly one
    URL operand that is https on the host packages.wolfi.dev (with toolchain=True instead: exactly https://go.dev/dl/
    followed by ONE variable, REQ-SUP-001-AC23); optionally followed by `|| die "plain text" [digit]` or `|| exit N`.
    The line is split into shell words,
    so quote concatenation cannot change a word after the check; a variable may appear only as part of the -o file name;
    no second command, pipe, redirection,
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
    if len(w) < 3 or w[0] not in ("curl", "/usr/bin/curl") or w[1] not in (("-q",) if toolchain
            else ("-q", "--disable")):
        # -q first: no default .curlrc (CURL_HOME) can add a URL or an option (the Go shape takes only the spelling -q)
        return False
    raw = re.findall(r"""(?:"[^"]*"|'[^']*'|[^\s"']+)+""", left)
    if len(raw) != len(w):
        return False
    if toolchain and "'" in left:
        # the Go shape has no single quote anywhere: a single-quoted $name is a literal dollar sign, never a variable
        return False
    for rt in raw:
        # an expansion, brace, glob or tilde may appear only inside double quotes: unquoted, the shell splits it into
        # several words
        if re.search(r"[$`{}*?\[\]~]", re.sub(r'"[^"]*"|\'[^\']*\'', "", rt)):
            return False
    i, operands, globoff, op_raw = 2, [], False, []
    while i < len(w):
        t = w[i]
        if t in _LIVE_FLAG_PLAIN:
            globoff = globoff or t in (("-g",) if toolchain else ("-g", "--globoff"))
            i += 1
        elif t in _LIVE_FLAG_VALUE:
            if i + 1 >= len(w) or not re.fullmatch(_LIVE_FLAG_VALUE[t], w[i + 1]) or (t not in ("-o", "--output")
                    and "$" in w[i + 1]):
                return False
            if toolchain and t in ("-o", "--output") and not _GO_OUT.fullmatch(w[i + 1]):
                # the Go shape: an output value is literal characters and plain $name / ${name} references only
                return False
            i += 2
        elif t.startswith("-"):
            # an option outside the list (-x, -K, --resolve, --url, an attached value, a cluster not listed)
            return False
        else:
            operands.append(t)
            op_raw.append(raw[i])
            i += 1
    if len(operands) != 1:
        return False
    if toolchain:
        # the variable form only, only with -g, and the operand must be double-quoted or bare: a single-quoted $f is a
        # literal dollar sign, not a variable
        return globoff and "'" not in op_raw[0] and _GO_URL_VAR.fullmatch(operands[0]) is not None
    if _LIVE_URL_VAR.fullmatch(operands[0]) is not None:
        # curl itself expands {a,b} and [1-2] in a URL: a variable operand is one transfer only with -g
        return globoff
    return _LIVE_URL.fullmatch(operands[0]) is not None


# REQ-SUP-001-AC16, the optional row field body-sha256: the row is a review of one whole file (and of the files it
# sources by a literal path), so any edit to them stops the row matching.
_SOURCE = re.compile(r"(?:^|[;&|({]|\b(?:then|do|else)[ \t])[ \t]*(?:source|\.)[ \t]+([^\s;&|)]+)", re.M)   # matches "x; . lib.sh", refuses "echo source lib.sh"
_NON_LITERAL = re.compile(r"[$`\"'\\*?\[{~]")


def _sourced(text):
    """The operands of the source commands in text, or None when one is not a plain path."""
    lines = [ln for ln in text.split("\n") if not ln.lstrip().startswith("#")]
    ops = _SOURCE.findall("\n".join(lines))
    return None if any(_NON_LITERAL.search(o) for o in ops) else ops


def _files_hash(root, head, path):
    """The sha256 of one line '<path> <sha256 of its bytes>' (or '<path> absent') per file: path first, then the files
    it sources by literal path to any depth, in path order. None when a file cannot be read or a source operand is
    not a plain path."""
    lines, todo, seen = {}, [path], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        raw = _head_file(root, head, f)
        if raw is None:
            if f == path:
                return None
            lines[f] = f + " absent"
            continue
        lines[f] = f + " " + hashlib.sha256(raw).hexdigest()
        ops = _sourced(raw.decode("utf-8", "replace"))
        if ops is None:
            return None
        todo += [os.path.normpath(o) for o in ops]
    text = "".join(lines[f] + "\n" for f in [path] + sorted(set(lines) - {path}))
    return hashlib.sha256(text.encode()).hexdigest()


# the pinned script lines, each honored for its file and its whole-line sha256 only (see PINNED_FETCH)
PINNED_FETCH_RULING = "pinned fetch, advisor reading Oct 17 (REQ-SUP-001-AC26): "
# file -> the raw text of each pinned line, byte for byte (no trailing space, no carriage return); the head file must
# hold each exactly once
PINNED_FETCH = {
    "bin/loopback-get.sh": [
        """curl -q -g --noproxy '*' --proto "=$proto" --max-redirs 0 "$@" "$url" || exit $?""",
    ],
    'bin/release-assets.sh': [
        'gh release download "$rel" -D release-published',
    ],
    'bin/acceptance-k8s.sh': [
        'docker pull -q curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 '
            '&& docker tag '
                'curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 '
                    '"$CLIENT_LOCAL"',
    ],
    'bin/acceptance-gradle.sh': [
        '  code=$(curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18095/${key}")',
        'curl -s localhost:18095/metrics > /tmp/metrics-cold.txt',
        'curl -s localhost:18095/metrics > /tmp/metrics-warm.txt',
    ],
    'bin/acceptance-gradle-capped.sh': [
        'head_code() { curl -s -o /dev/null -w \'%{http_code}\' -I "localhost:18096/$1"; }',
        'curl -s localhost:18096/metrics > /tmp/capped-metrics.txt',
        'hdr=$(curl -s -D - -o /dev/null -X PUT --data-binary @/tmp/oversized-probe.bin '
            'http://localhost:18096/oversizedprobe)',
        "code=$(curl -s -o /dev/null -w '%{http_code}' -I http://localhost:18096/oversizedprobe)",
    ],
    'bin/acceptance-maven.sh': [
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-cold.txt',
        'curl -s -u mvn:acceptance-secret localhost:18098/metrics > /tmp/m-warm.txt',
        'before_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk '
            '\'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
        'after_puts=$(curl -s -u mvn:acceptance-secret localhost:18098/metrics | awk '
            '\'/^fscache_http_requests_total\\{method="PUT",status="201"\\}/ {print $2}\')',
    ],
    'bin/acceptance-maven-capped.sh': [
        'app_code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w \'%{http_code}\' -I '
            '"http://localhost:18099/maven/v1.1/com.fosterstack.bench/app/${app_key}/app.jar")',
        'hdr=$(curl -s -u mvn:acceptance-secret -D - -o /dev/null -X PUT --data-binary @/tmp/mvn-oversized-probe.bin '
            'http://localhost:18099/maven/oversizedprobe)',
        "code=$(curl -s -u mvn:acceptance-secret -o /dev/null -w '%{http_code}' -I "
            "http://localhost:18099/maven/oversizedprobe)",
    ],
    'bin/install-scanner.sh': [
        '    curl -q -fsSL -g -o "$tmp/go.tgz" "https://go.dev/dl/${gofile}" || die "download failed: go toolchain"',
    ],
    'bin/go-bump-open-pr.sh': [
        '  curl -q -fsSL -g -o "${dl}/published.json" "https://go.dev/dl/${jsonq}" || die "go.dev is unreachable: '
            'cannot read the published checksums" 1',
        '    curl -q -fsSL -g -o "${dl}/${tarball}" "https://go.dev/dl/${tarball}" || die "cannot download the Go '
            'tarball from go.dev" 1',
    ],
}
_PINNED_FETCH_SHA = {f: {hashlib.sha256(" ".join(l.split()).encode("utf-8", "replace")).hexdigest(): l for l in ls}
    for f, ls in PINNED_FETCH.items()}
_PINNED_OK = {}


def _held_once(root, head, f, line):
    """True only when the head file f (a regular file, not a link) holds `line` byte for byte exactly once, has no
    carriage return, and holds no other line that differs
    from it only in whitespace (the scan hashes with whitespace collapsed, so the raw text is compared here).
    Unreadable: False."""
    raw = _head_file(root, head, f)
    if raw is None or b"\r" in raw:
        return False
    rows = raw.split(b"\n")
    flat = " ".join(line.split())
    return rows.count(line.encode()) == 1 and sum(" ".join(r.decode("utf-8", "replace").split()) == flat
        for r in rows) == 1


def _pinned_line_ok(root, head, f, lh):
    """True only when the pinned line of file f whose whole-line sha256 is lh is held by the head file as _held_once
    says. A line the checker does not pin: False."""
    key = (root, head, f, lh)
    if key not in _PINNED_OK:
        raw_line = _PINNED_FETCH_SHA.get(f, {}).get(lh)
        _PINNED_OK[key] = raw_line is not None and _held_once(root, head, f, raw_line)
    return _PINNED_OK[key]


def _head_file(root, rev, f):
    """The bytes of the regular file f (not a link) in the tree of rev (the working tree when rev is None); None when
    it is missing, a link or unreadable."""
    try:
        if rev is None:
            path = os.path.join(root, f)
            return open(path, "rb").read() if os.path.isfile(path) and not os.path.islink(path) else None
        ent = subprocess.run(["git", "-C", root, "ls-tree", rev, "--", f], capture_output=True, check=True,
            timeout=120).stdout.decode("utf-8", "replace").split()
        if len(ent) < 4 or ent[0] not in ("100644", "100755") or ent[1] != "blob":
            return None
        return subprocess.run(["git", "-C", root, "show", f"{rev}:{f}"], capture_output=True, check=True,
            timeout=120).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def _body_proved(root, head, path, line_hash, row):
    """A row without a body hash rules its line as it always did; a row with one rules it only while the head's file
    (and the files it sources) hash to it."""
    return row[2] is None or _files_hash(root, head, path) == row[2]


def _body_regressions(root, head, rulings):
    """{(key, line hash): count} of head lines whose body-bound row no longer matches the body they sit in. Such a line
    is not "added" (its count is unchanged), so the delta
    never looks at it: without this, an edit inside a reviewed body would stay ruled."""
    out = {}
    for k, per in _occurrences(root, head).items():
        for lh, n in per.items():
            row = rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh))
            if row and not _body_proved(root, head, k[0], lh, row):
                out.setdefault(k, {})[lh] = n
    return out


MAX_RULED_COUNT = 100


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"a JSON object repeats a key ({sorted(k for k in set(keys) if keys.count(k) > 1)})")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(f"{name} is not JSON (Python's reader accepts NaN, Infinity and -Infinity; "
                     "this file must not hold them)")


def load_ruled_text(path, required=False):
    """{(file, form, 64-hex segment hash, 64-hex whole-line hash):
    (ruling, count, body sha256 or None)} from the file's unmeasured_text list. A missing default
    file is no rulings; anything malformed
    raises RuntimeError (the check cannot run, exit 2): never 'nothing ruled' and never 'everything ruled'."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"the exceptions file {path} (unmeasured_text) does not exist")
        return {}
    try:
        with open(path) as f:
            # a repeated key would let a later copy silently win
            d = json.load(f, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"the exceptions file {path} (unmeasured_text) is unreadable: {e}")
    rows = d.get("unmeasured_text", []) if isinstance(d, dict) else None
    if not isinstance(rows, list):
        raise RuntimeError(f"{path}: unmeasured_text is not a list")
    out = {}
    for i, r in enumerate(rows):
        bad = lambda why: RuntimeError(f"{path}: unmeasured_text row {i} {why}")
        if (not isinstance(r, dict) or set(r) - set(_RULED_FIELDS) - {"count", "body-sha256"}
                or not set(_RULED_FIELDS) <= set(r)):
            raise bad("must be an object with exactly file, form, key, line, ruling (and an optional count, "
                "and body-sha256)")
        if not all(isinstance(r[k], str) and r[k].strip() for k in _RULED_FIELDS):
            raise bad("has an empty or non-text file, form, key, line or ruling")
        if not re.fullmatch(r"[0-9a-f]{64}", r["key"]):
            raise bad("key is not the scan's 64 lowercase hex hash")
        if not re.fullmatch(r"[0-9a-f]{64}", r["line"]):
            raise bad("line is not the 64 lowercase hex hash of the whole flattened line")
        count = r.get("count", 1)
        if type(count) is not int or not 1 <= count <= MAX_RULED_COUNT:
            raise bad(f"count is not a whole number from 1 to {MAX_RULED_COUNT}")
        body = r.get("body-sha256")
        if body is not None and (r["form"] == LOCAL_CALL_FORM or not re.fullmatch(r"[0-9a-f]{64}", str(body))):
            raise bad("has a body-sha256 that is not 64 lowercase hex, or is a local-call row")
        k = (r["file"], r["form"], r["key"], r["line"])
        if k in out:
            raise bad("repeats an earlier row (file, form, key and line)")
        out[k] = (r["ruling"].strip(), count, body)
    return out


DEFAULT_BASE_INPUTS = os.path.normpath(os.path.join(HERE, "..", "..", "policy", "base-inputs.json"))




def load_file_pins(path, required=False):
    """REQ-SUP-001-AC34: {(file, content hash): (published, upstream, version)} from the exceptions file's file_pins
    list (the BASE branch's copy: rows a pull request brings
    do nothing until merged). A row missing a field, with a content that is not 64 lowercase hex or a published time
    that is not a time rules nothing. Two rows for
    one (file, content), a list that is not a list or an unreadable file stop the check (RuntimeError, exit 2): never
    'nothing ruled' by guesswork and never the older of two."""
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
        if not all(isinstance(x, str) and x.strip() for x in fields) or not re.fullmatch(r"[0-9a-f]{64}", c_) \
            or not r["upstream"].startswith("https://") \
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", r["published"]) \
                    or parse_time(r["published"]) is None:
            continue
        out[(f_, c_)] = (r["published"], r["upstream"], r["version"])
    return out


class FilePinSource:
    """Wraps a proof source: a file item the base branch's file_pins names (same file AND same content) gets the row's
    published time as its proof."""

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
    """REQ-SUP-001-AC21: the set of paths .github/policy/base-inputs.json lists (read from the base branch's copy beside
    this script, never the pull request's tree).
    A missing default file lists nothing; anything malformed raises RuntimeError (exit 2): never 'nothing exempted' and
    never 'everything'."""
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
    """A (file) item whose repository path the list names is no item: its content is the repository's own base record.
    Exact equality with the path as git
    names it (Item.raw), never with the display name, which _hide() rewrites."""
    keep, ruled = [], []
    for m in moved:
        (ruled if (m.kind == "tool" and m.version == "(file)" and m.raw is not None and m.raw in paths)
            else keep).append(m)
    return keep, ruled


UNPINNED_FORM = "an unpinned package install"
LOCAL_CALL_FORM = "a local reusable workflow call"


def _item_hash(item):
    return hashlib.sha256(item.key.encode("utf-8", "replace")).hexdigest()


def unresolved_call_rows(root, rev, exceptions_path):
    """The local-call rows of the exceptions file that would rule NO item of the tree at rev, judged by the very tuple
    split_ruled_local_calls() looks up
    ((file, form, h, h) for an eligible item: kind action, version (local), with an origin file): [] when every row
    resolves to exactly one item."""
    rows = [k for k in load_ruled_text(exceptions_path, required=True) if k[1] == LOCAL_CALL_FORM]
    have = {}
    for it in inv.load_at(root, rev).values():
        if it.kind == "action" and it.version == "(local)" and it.src:
            h = _item_hash(it)
            have.setdefault((it.src[0], LOCAL_CALL_FORM, h, h), []).append(it.key)
    return [k for k in rows if len(have.get(k, [])) != 1]


def split_ruled_local_calls(moved, rulings):
    """REQ-SUP-001-AC19: a local reusable-workflow call that keeps a with: block is an item that cannot pass, unless a
    base-branch row names it: file, form
    "a local reusable workflow call", key and line both the 64-hex hash of the item's whole identity (its path and the
    hash of its with: block), so an edited
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
    """REQ-SUP-001-AC20: an unpinned package item leaves the list only when the script line that made it (its own path
    and line id) is a ruled occurrence."""
    return [m for m in items
        if not (m.kind == "package" and m.version == "(unpinned)" and m.src and tuple(m.src) in ruled_lines)]


def ruled_unpinned_lines(root, base, head, exceptions_path):
    """The (script path, line id) pairs of the unpinned-package occurrences the head ADDS that a base-branch row rules,
    within the row's count. Shared by this check and
    pin-audit.py, so the one required job judges a ruled line once."""
    rulings = load_ruled_text(exceptions_path, required=False)
    in_base = _occurrences(root, base)
    out = set()
    for k, per in _unmeasured_counts(root, base, head).items():
        if k[1] != UNPINNED_FORM:
            continue
        rs = [rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in per]
        rs = [r if r is None or _body_proved(root, head, k[0], lh, r) else None for r, lh in zip(rs, per)]
        # a line the base already holds is never ruled here: an item of that line may have moved because an assignment
        # it reads changed, and a copy of
        # the line cannot be told from it (the occurrence is still reported; the item keeps failing)
        if all(r and n <= r[1] and not in_base.get(k, {}).get(lh) for r, (lh, n) in zip(rs, per.items())):
            out.update((k[0], lh) for lh in per)
    return out


GO_EXEMPT_REASON = (
    "exempt from the 7-day hold: Go's own release, "
    "downloaded from go.dev and verified against its pinned sha256 "
    "(owner ratified Oct 21 2026, REQ-SUP-001-AC27); the advisory check still applies")
_GO_VER_LINE = re.compile(r"^GO_VER=(\d+\.\d+\.\d+)$")
_GO_FILE = re.compile(r'^[ \t]*gofile="go\$\{GO_VER\}\.\$\{A_GO\}\.tar\.gz"[ \t]*$')
_GO_CURL = re.compile(r'^[ \t]*curl -q -fsSL -g -o "\$tmp/go\.tgz" "https://go\.dev/dl/\$\{gofile\}" \|\| die '
    r'"download failed: go toolchain"[ \t]*$')
_GO_VERIFY = ["verify() { # file", "  local got", "  got=$(sha256sum \"$1\" | cut -d' ' -f1)",
              '  [ "$got" = "$SUM" ] || pipeline_fail "${TOOL} checksum mismatch (got ${got}, pinned ${SUM}) - '
                  'refusing to run an unverified scanner"', "}"]
_GO_EXTRACT = re.compile(r'^[ \t]*mkdir -p "\$tmp/x" && tar -xzf "\$tmp/go\.tgz" -C "\$tmp/x" \|\| pipeline_fail '
    r'"extract failed for go"[ \t]*$')
_GO_MSG = r'"(?:[^"$`\\]|\$\{[A-Za-z_]+\})*"'
_GO_WANT = re.compile(r'^[ \t]*\[ "\$want" = "\$GO_VER" \] \|\| pipeline_fail ' + _GO_MSG + r'[ \t]*$')
_GO_SHOW = re.compile(
    r'^[ \t]*"\$\{DEST\}/fscache-go/bin/go" version \| grep -q "go\$\{GO_VER\} " \|\| pipeline_fail '
    + _GO_MSG + r'[ \t]*$')
_GO_FAIL = ['pipeline_fail() { echo "::error::scanner installer: $*  (PIPELINE failure - not a scan finding)" >&2; '
    'exit 1; }']
_SUM_ROW = re.compile(r"^[ \t]*[A-Za-z0-9_.:|-]+\) SUM=[0-9a-f]{64} ;;[ \t]*$")
# a module pinned by go.sum: its own key, empty sum
_SUM_MODULE = re.compile(r'^[ \t]*govulncheck:\*\) SUM="" ;;[ \t]*(?:#.*)?$')
_GO_SUM = {a: re.compile(r"^[ \t]*go:" + a + r"\) SUM=[0-9a-f]{64} ;;[ \t]*$")
    for a in (r"x86_64\|go:amd64", r"aarch64\|go:arm64")}


def go_exemption(root, head):
    """The pinned Go version when the head's bin/install-scanner.sh fetches Go ONLY from https://go.dev/dl/ at its
    pinned GO_VER, pins the sha256 of both
    architectures (64 hex each) and verifies the file right after the download; otherwise None (the 7-day hold applies).
    Any other line that downloads
    something Go-shaped (curl or wget naming go.tgz, GO_VER, go.dev or golang) voids it."""
    try:
        text = inv.tree_files(root, head).get("bin/install-scanner.sh")
    except (OSError, ValueError, RuntimeError):
        return None
    if not text:
        return None
    lines = text.split("\n")
    # a shell continuation is one command: a download written over two lines is still one
    joined = re.sub(r"\\[ \t]*\n", " ", text).split("\n")
    vers = [m.group(1) for m in (_GO_VER_LINE.match(l) for l in lines) if m]
    if len(vers) != 1 or sum(1 for l in lines if re.match(r"^[ \t]*(?:export[ \t]+)?GO_VER=", l)) != 1:
        return None
    fetch = [i for i, l in enumerate(joined) if re.search(r"\b(curl|wget)\b", l)
        and re.search(r"go\.tgz|GO_VER|gofile|go\.dev|golang|go\$\{|go[0-9]+\.[0-9]", l)]
    if len(fetch) != 1 or not _GO_CURL.match(joined[fetch[0]]):
        return None
    names = [l for l in joined if re.match(r"^[ \t]*(?:export[ \t]+|readonly[ \t]+|local[ \t]+)?gofile=", l)]
    if len(names) != 1 or not _GO_FILE.match(names[0]):
        return None
    nxt = next((l.strip() for l in joined[fetch[0] + 1:] if l.strip()), "")
    if nxt != 'verify "$tmp/go.tgz"':
        return None
    if any(sum(1 for l in lines if rx.match(l)) != 1 for rx in _GO_SUM.values()) or sum(1 for l in lines
            if re.search(r"\bgo:", l) and re.search(r"\bSUM", l)) != 2:
        return None
    # the verifier and the failure helper are the reviewed ones, each defined once in ANY spelling (verify() / verify ()
    # / function verify)
    for name, want in (("verify", _GO_VERIFY), ("pipeline_fail", _GO_FAIL)):
        if len(re.findall(r"\bfunction[ \t]+" + name + r"\b|\b" + name + r"[ \t]*\([ \t]*\)", text)) != 1:
            return None
        starts = [i for i, l in enumerate(lines) if re.match(r"^" + name + r"\(\)", l)]
        if len(starts) != 1 or [l.rstrip() for l in lines[starts[0]:starts[0] + len(want)]] != want:
            return None
    # the installer defines only the reviewed helpers (a redefined sha256sum, cut or echo would change what verify()
    # computes) and aliases nothing
    defs = set()
    for l in joined:
        if not l.lstrip().startswith("#"):
            q = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l)
            defs.update(re.findall(r"([A-Za-z_][\w.-]*)[ \t]*\([ \t]*\)", q) + re.findall(r"\bfunction[ \t]+([\w.-]+)",
                q))
            if re.search(r"(?:^|[;&|{(]|\bthen|\bdo|\belse)[ \t]*(?:alias|enable|builtin|unalias)\b", q):
                return None
    if defs - {"verify", "pipeline_fail", "die"}:
        return None
    # the download and its verify call sit at the top level of the go arm of the one tool dispatch: counted from the
    # START of the file, the only open construct at the
    # download is that dispatch `case` (a wrapper around it, a group or loop or condition around the arm, an inline `;
    # (` all raise the depth: refused)
    arm = [i for i, l in enumerate(joined[:fetch[0]]) if re.match(r"^[ \t]*go\)[ \t]*$", l)]
    if len(arm) != 1:
        return None
    depth = 0
    for l in joined[:fetch[0]]:
        t = re.sub(r"'[^']*'|\"[^\"]*\"", '""', l.strip())
        if t.startswith("#"):
            continue
        depth += (len(re.findall(r"(?:^|[;&|)][ \t]*|\bthen[ \t]+|\bdo[ \t]+|\belse[ "
            r"\t]+)(?:if|while|until|for|select|case)\b", t)) + (1 if t[:1] in "({" else 0)
                 + len(re.findall(r"[;&|][ \t]*[({]", t)) + (1 if re.search(r"\)[ \t]*\{[ \t]*(?:#.*)?$", t) else 0))
        depth -= len(re.findall(r"(?:^|[;&|)][ \t]*)(?:fi|done|esac)\b", t)) + (1 if t[:1] in ")}" else 0)
    if depth != 1:
        return None
    # outside the reviewed lines the Go names appear ONLY in the two reviewed read shapes (a version comparison and the
    # installed-version grep, each ending in a
    # pipeline_fail whose message holds no command substitution); ANY other mention of GO_VER, gofile, go.tgz, go.dev or
    # a Go archive name (go<N>.<N>) in a
    # non-comment line voids the exemption: a write in any form, a second transfer by any command, a URL variable, a
    # read in another command
    for i, l in enumerate(joined):
        if i == fetch[0] or l.lstrip().startswith("#") or _GO_FILE.match(l) or _GO_VER_LINE.match(l) \
            or l.strip() == 'verify "$tmp/go.tgz"' or _GO_EXTRACT.match(l) \
                or _GO_WANT.match(l) or _GO_SHOW.match(l):
            continue
        if re.search(r"GO_VER|gofile|go\.tgz|go\.dev|\bgo[0-9]+\.[0-9]", l):
            return None
    # every SUM assignment, anywhere on any line, is a pinned row: a literal pattern (no glob), `) SUM=<64 hex> ;;`; any
    # other mention of SUM must only read it
    for l in joined:
        rest = re.sub(r"\$\{SUM\}|\$SUM\b", "", l)
        if re.search(r"\bSUM\b", rest) and not (_SUM_ROW.match(l) or _SUM_MODULE.match(l)):
            return None
    return vers[0]


def split_go_exempt(moved, root, head):
    """(the moved items without the exempt Go release, the exempt ones): only `tool:go` at the installer's own pinned
    version."""
    ver = go_exemption(root, head) if any(it.kind == "tool" and it.name == "go" for it in moved) else None
    keep = [it for it in moved if not (ver and it.kind == "tool" and it.name == "go" and it.version == ver)]
    return keep, [it for it in moved if it not in keep]


def _run(a, moved, fx, now):
    # before the scan: a malformed list stops the check
    rulings = load_ruled_text(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))
    lines = _unmeasured_counts(a.root, a.base, a.head)
    for k, per in _body_regressions(a.root, a.head, rulings).items():
        lines.setdefault(k, {}).update(per)
    added, ruled = [], []
    for k in sorted(lines):
        # ruled only when EVERY added (key, whole line) is named by a row and its head occurrences are within that row's
        # count (1 unless it says more):
        # the same segment inside any other line, an edited line, or one copy too many leaves the item refused
        rs = [rulings.get((k[0], k[1], k[2].split(":", 1)[0], lh)) for lh in lines[k]]
        # a row whose body hash does not hold rules nothing
        rs = [r if r is None or _body_proved(a.root, a.head, k[0], lh, r) else None for r, lh in zip(rs, lines[k])]
        if k[1] == DOWNLOAD_FORM and any(r
                and not r[0].startswith((TEXT_RULING, LIVE_RULING, GO_RULING, PINNED_FETCH_RULING))
                    for r in rs):
            # a download row rules a line only with one of the four rulings named above (text, live, Go, pinned)
            rs = [None]
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(LIVE_RULING)
                and not _live_fetch_line_ok(_LINE_TEXT.get(lh, "")) for r, lh in zip(rs, lines[k])):
            # a live-fetch ruling on a line that is not wholly https on packages.wolfi.dev rules nothing
            rs = [None]
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(GO_RULING)
                and not (k[0].endswith(".sh") and not k[0].startswith(".github/")
                    and _live_fetch_line_ok(_LINE_TEXT.get(lh, ""), toolchain=True)) for r, lh in zip(rs, lines[k])):
            # a Go-toolchain ruling on a line that is not exactly the one go.dev/dl/ shape rules nothing (AC23)
            rs = [None]
        if any(r and r[0].startswith(PINNED_FETCH_RULING) and not _pinned_line_ok(a.root, a.head, k[0], lh) for r,
                lh in zip(rs, lines[k])):
            # the pinned-fetch ruling on any line but one of the pinned lines of its own file rules nothing (AC26)
            rs = [None]
        if all(r and n <= r[1] for r, n in zip(rs, lines[k].values())):
            ruled.append((k, "; ".join(dict.fromkeys(r[0] for r in rs))))
        else:
            added.append(k)
    # REQ-SUP-001-AC20
    moved = drop_ruled_unpinned(moved, ruled_unpinned_lines(a.root, a.base, a.head, a.exceptions or DEFAULT_EXCEPTIONS))
    # REQ-SUP-001-AC21
    moved, base_files = split_base_inputs(
        moved, load_base_inputs(a.base_inputs or DEFAULT_BASE_INPUTS, required=bool(a.base_inputs)))
    # REQ-SUP-001-AC19: judged by the ruled row of ITS OWN line, never by another line's
    moved, ruled_calls = split_ruled_local_calls(moved, rulings)
    moved, go_free = split_go_exempt(moved, a.root, a.head)
    if not moved and not added and not go_free:
        print("pin-age: no pin moved (nothing to measure)")
        rows = []
    else:
        rows = check(moved, FilePinSource(Fixture(fx) if fx is not None else Live(a.root, a.base, a.head),
            load_file_pins(a.exceptions or DEFAULT_EXCEPTIONS, required=bool(a.exceptions))), now, a.min_days)
        print(f"pin-age: {len(rows)} moved version(s), each must be public {a.min_days:g} days by a server-side time:")
        for r in rows:
            print(f"  {'ok  ' if r['ok'] else 'FAIL'} {_one_line(r['item'])}: {_one_line(r['reason'])}")
        for it in go_free:
            rows.append({"item": it.key, "label": it.label, "ok": True, "reason": GO_EXEMPT_REASON, "proof": None})
            print(f"  ok   {it.key}: {GO_EXEMPT_REASON}")
    for path, what, line in added:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": False, "proof": None,
                     "reason": f"{what} was added to {path} ({line[:100]}): this check cannot measure it, so a "
                                f"pull request that adds one is refused (use a pinned form it can measure)"})
        print(f"  FAIL unmeasured:{_one_line(path)}: {what} added: not measurable, refused")
    for it in base_files:
        rows.append({"item": it.key, "label": "", "ok": True, "proof": None,
            "reason": f"base input: {it.name[5:]} is listed in .github/policy/base-inputs.json"})
        print(f"  ok   {it.key}: base input (REQ-SUP-001-AC21)")
    for it, ruling in ruled_calls:
        rows.append({"item": it.key, "label": "", "ok": True, "proof": None,
            "reason": f"ruled text: a local reusable workflow call in {it.src[0]}: {ruling[:200]}"})
        print(f"  ok   {_one_line(it.key)}: ruled text (REQ-SUP-001-AC19): {ruling[:200]}")
    for (path, what, line), ruling in ruled:
        rows.append({"item": f"unmeasured:{path}", "label": "", "ok": True, "proof": None,
                     "reason": f"ruled text: {what} in {path} ({line[:100]}) is listed in the base branch's "
                                f"unmeasured_text: {ruling[:200]}"})
        print(f"  ok   unmeasured:{path}: {what} ({line[:60]}): ruled text (REQ-SUP-001-AC16): {ruling[:200]}")
    failing = [r for r in rows if not r["ok"]]
    if a.json:
        json.dump({"min_days": a.min_days, "moved": rows}, open(a.json, "w"), indent=1)
    if failing:
        print(f"pin-age: FAIL: {len(failing)} of {len(rows)} moved version(s) too young or unprovable; "
              f"the check turns green when each is {a.min_days:g} days old")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
