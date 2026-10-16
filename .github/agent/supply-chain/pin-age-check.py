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
DOWNLOAD_FORM = "a download"
_LIVE_URL = re.compile(r"https://packages\.wolfi\.dev(?:/[A-Za-z0-9._+~/-]*)?")
# the per-package fetch (advisor, Oct 15, owner rule 48): the literal https://packages.wolfi.dev/os/ (trailing slash included, so the host cannot change) followed by
# exactly ONE variable and nothing else
_LIVE_URL_VAR = re.compile(r"https://packages\.wolfi\.dev/os/\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)")
_ANY_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"]+")
_LINE_TEXT = {}                              # whole-line hash -> the flattened line, filled by _occurrences


_LIVE_FLAG_PLAIN = {"-f", "-s", "-S", "-L", "-fsSL", "-fsS", "-fSL", "-sSL", "-g", "--globoff", "--fail", "--silent", "--show-error", "--location", "--tlsv1.2"}
_LIVE_FLAG_VALUE = {"--max-filesize": r"[0-9]+", "--max-time": r"[0-9]+", "--proto": r"=https", "-o": r"[A-Za-z0-9_./${}-]+", "--output": r"[A-Za-z0-9_./${}-]+"}


def _live_fetch_line_ok(flat):
    """The bound line is exactly ONE curl command: curl or /usr/bin/curl, then only flags from a fixed list (with a plain value where one is taken), then exactly one
    URL operand that is https on the host packages.wolfi.dev; optionally followed by `|| die "plain text" [digit]` or `|| exit N`. The line is split into shell words,
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
    if len(w) < 3 or w[0] not in ("curl", "/usr/bin/curl") or w[1] not in ("-q", "--disable"):
        return False                                   # -q first: no default .curlrc (CURL_HOME) can add a URL or an option
    raw = re.findall(r"""(?:"[^"]*"|'[^']*'|[^\s"']+)+""", left)
    if len(raw) != len(w):
        return False
    for rt in raw:
        # an expansion, brace, glob or tilde may appear only inside double quotes: unquoted, the shell splits it into several words
        if re.search(r"[$`{}*?\[\]~]", re.sub(r'"[^"]*"|\'[^\']*\'', "", rt)):
            return False
    i, operands, globoff = 2, [], False
    while i < len(w):
        t = w[i]
        if t in _LIVE_FLAG_PLAIN:
            globoff = globoff or t in ("-g", "--globoff")
            i += 1
        elif t in _LIVE_FLAG_VALUE:
            if i + 1 >= len(w) or not re.fullmatch(_LIVE_FLAG_VALUE[t], w[i + 1]) or (t not in ("-o", "--output") and "$" in w[i + 1]):
                return False
            i += 2
        elif t.startswith("-"):
            return False                               # an option outside the list (-x, -K, --resolve, --url, an attached value, a cluster not listed)
        else:
            operands.append(t)
            i += 1
    if len(operands) != 1:
        return False
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
_DEF_FUNC = re.compile(r"^[ \t]*(?:function[ \t]+([A-Za-z_][\w.-]*)|([A-Za-z_][\w.-]*)[ \t]*\(\))", re.M)


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
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
            else:                                   # code position: top level, $( ), $(( )), (( )), backticks, ( )
                if c == "\\": j += 1
                elif c == "'": stack.append("'")
                elif c == '"': stack.append('"')
                elif c == "`":
                    if top == "`": stack.pop()
                    else: stack.append("`")
                elif c == "$" and line[j + 1:j + 2] == "(":
                    if line[j + 2:j + 3] == "(": stack.append("$(("); j += 2
                    else: stack.append("$("); j += 1
                elif c == "(":
                    if top == "(" and line[j - 1:j] == "(": stack[-1] = "(("
                    else: stack.append("(")
                elif c == ")" and top in ("$(", "(", "$((", "(("):
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
                        ops.append((m.group(1) == "-", quoted, delim, any(s in ("$(", "`", '"') for s in stack)))
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
        targets = [t.strip("'\"") for t in re.findall(r"(?:^|[^\d<>&])(?:\d*>>?|&>>?)[ \t]*(\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)", stripped)
                   + re.findall(r"\btee\b(?:[ \t]+-\w+)*[ \t]+(\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)", opener)]
        targets = [t for t in targets if t and not t.startswith(("&", "/dev/"))]
        for tab, quoted, delim, nested in ops:
            start, k = i, i
            if delim is None:
                hds.append({"open": o, "start": start, "end": None, "quoted": quoted, "nested": nested, "bad": True, "opener": opener, "targets": targets, "ops": len(ops)})
                continue
            while k < n and (lines[k].lstrip("\t") if tab else lines[k]).rstrip("\r") != delim:
                state[k] = None
                k += 1
            hds.append({"open": o, "start": start, "end": k if k < n else None, "quoted": quoted, "nested": nested, "bad": bad, "opener": opener, "targets": targets, "ops": len(ops)})
            i = (k + 1) if k < n else n
            if k >= n:
                break
    return hds, not stack, state


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
            body.append(lines[k]); depth += lines[k].count("{") - lines[k].count("}"); seen = seen or "{" in lines[k]
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


def _written_file_used_later(lines, hd):
    """True when a file the heredoc's output goes to (or a variable the script sets to its name) is later run, sourced, interpreted, copied or chmod'ed in the same script
    (conservative: any later line that names it next to such a word, or starts with it, counts)."""
    later = lines[(hd["end"] or hd["start"]) + 1:]
    names = set(hd["targets"])
    for _ in range(4):                                          # a variable that holds the name (one assignment at a time, a few levels)
        for ln in later:
            for var, val in re.findall(r"(?:^|[;&|\s])([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)", ln):
                if val.strip("'\"") in names or any(t in val for t in names):
                    names |= {"$" + var, "${" + var + "}"}
    for t in names:
        for ln in later:
            if t in ln:
                st = ln.strip().strip("'\"")
                if st.startswith(t) or (_INTERP_WORDS | _USE_WORDS) & set(_words(ln)):
                    return True
    return False


def _py_program_flags(body):
    """(tree, impure reasons) for the Python source `body`, or (None, ...) when it does not parse. Names are read from the syntax tree (a word inside a string counts for nothing)."""
    import ast
    try:
        tree = ast.parse(body)
    except (SyntaxError, ValueError, RecursionError):
        return None, ["does not parse"]
    why = set()
    for nd in ast.walk(tree):
        if isinstance(nd, ast.Name) and nd.id in _PY_FORBIDDEN_NAMES: why.add(nd.id)
        elif isinstance(nd, ast.Attribute) and nd.attr in _PY_FORBIDDEN_NAMES: why.add(nd.attr)
        elif isinstance(nd, ast.Import): why |= {a.name.split(".")[0] for a in nd.names} & _PY_FORBIDDEN_NAMES
        elif isinstance(nd, ast.ImportFrom) and (nd.module or "").split(".")[0] in _PY_FORBIDDEN_NAMES: why.add(nd.module)
        elif isinstance(nd, ast.Call) and isinstance(nd.func, ast.Name) and nd.func.id == "open":
            mode = nd.args[1] if len(nd.args) > 1 else next((k.value for k in nd.keywords if k.arg == "mode"), None)
            if mode is not None and not (isinstance(mode, ast.Constant) and isinstance(mode.value, str) and not set(mode.value) & set("wax+")):
                why.add("open for writing")
        elif isinstance(nd, ast.Call) and isinstance(nd.func, ast.Attribute) and nd.func.attr == "open":      # Path.open(mode), io.open(file, mode), gzip.open ...: read-only only if every argument is a plain read mode
            vals = list(nd.args) + [k.value for k in nd.keywords]
            if not all(isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value in ("r", "rb", "rt", "br", "tr") for v in vals):
                why.add("open for writing")
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
    def in_quoted_heredoc(i):                  # a body line of a terminated quoted heredoc: text, whatever it says
        return any(h["start"] <= i < h["end"] and h["quoted"] and not h["bad"] for h in hds if h["end"] is not None)
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
    funcs = _func_bodies(lines)
    for i in hits:
        hd = next((h for h in hds if h["start"] <= i < (h["end"] if h["end"] is not None else -1)), None)
        if hd is None or not hd["quoted"] or hd["nested"] or hd["bad"] or hd["end"] is None or hd["ops"] != 1:
            return False
        words = _words(hd["opener"])
        if re.search(r"\$\(|`|<\(|>\(", re.sub(r"<<-?[ \t]*(?:'[^']*'|\"[^\"]*\"|\\.|\w+)", " ", hd["opener"])):
            return False
        if _runs_input([w for w in words if w in funcs], funcs):                 # a function the file defines that (through others) runs its input
            return False
        if _written_file_used_later(lines, hd):
            return False
        if context == "heredoc":
            if set(words) & _INTERP_WORDS: return False
            continue
        # pystring: python / python3 reading the program from stdin ("-"), no other interpreter or shell on the command line
        pyw = {"python", "python3"}
        if not (set(words) & pyw) or (set(words) & _INTERP_WORDS) - pyw or not re.search(r"\bpython[\d.]*[ \t]+(?:-[a-zA-Z]+[ \t]+)*-(?=[ \t]|$)", hd["opener"]) or re.search(r"[ \t]-[a-zA-Z]*[cm]\b", hd["opener"]):
            return False
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


def _context_proved(root, head, path, line_hash, row):
    """A row without a context is as it always was; a row with one rules its line only when the context is proved from the head file."""
    ruling, count, context, proof = row
    if context is None:
        return True
    if not path.endswith(".sh"):
        return False
    text = _scripts_at(root, head).get(path)
    return text is not None and _context_holds(context, proof, text, line_hash)


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
            if was is not None and _context_holds(row[2], row[3], was, lh) and not _context_proved(root, head, k[0], lh, row):
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
        if k[1] == DOWNLOAD_FORM and any(r and not r[0].startswith((TEXT_RULING, LIVE_RULING)) for r in rs):
            rs = [None]                                  # a download row rules a line only with one of the two rulings the owner's rules name
        if k[1] == DOWNLOAD_FORM and any(r and r[0].startswith(LIVE_RULING) and not _live_fetch_line_ok(_LINE_TEXT.get(lh, "")) for r, lh in zip(rs, lines[k])):
            rs = [None]                                  # a live-fetch ruling on a line that is not wholly https on packages.wolfi.dev rules nothing
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
