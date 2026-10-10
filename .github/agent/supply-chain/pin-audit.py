#!/usr/bin/env python3
"""The supply-chain audit (REQ-SUP-001-AC5 to AC10): advisories, malicious-package reports, upstream reachability, disputed hits, held-PR re-runs.

  pin-audit.py --root REPO [--base REV] [--fixtures FILE] [--now ISO] [--gh CMD] [--exceptions FILE] [--rerun-held]

Daily mode (no --base): every item in today's inventory AND in the workflow history of the last 90 days. Pull request mode (--base REV): only the
items the head moved. A hit becomes ONE issue (found again later: updated, never a second issue) labelled supply-chain-hit, naming the version,
the advisory id and the rollback; it is also labelled owner-decision when no clean version at least 7 days old exists or the version ran in the last
90 days. A disputed hit (the two lists disagree about the same incident) is reported without rolling back unless a checked-in exception applies.
--rerun-held does only the re-run of held pull requests whose moved versions have turned 7 days old; it never touches issues.
Exit 0: clean (or only excepted disputes); 1: a hit or an unexcepted disputed hit; 2: it could not do its job.
Only public facts go in an issue: versions, advisory ids, dates. It never produces run, environment or secret names.
"""
import argparse
import base64
import concurrent.futures
import datetime as dt
import functools
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LOOKBACK_DAYS = 90
WAIT_DAYS = 7
HIT_LABEL, OWNER_LABEL = "supply-chain-hit", "owner-decision"


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inv = _load("pin-inventory")
age = _load("pin-age-check")
tobs = age.tobs


class Fail(Exception):
    """The audit could not do its job (exit 2)."""


# ---------- versions and ranges (OSV events, GitHub's comma-separated comparators) ----------
_PRE = re.compile(r"(?i)^(a|b|c|rc|alpha|beta|pre|preview|dev)")
_POST = re.compile(r"(?i)^(post|p|rev|r)(?=\d|\.|-|_|$)")


def _norm_name(n):
    return re.sub(r"[-_.]+", "-", str(n)).lower()


SUBPROCESS_TIMEOUT = 120


def _run(cmd, **kw):
    """subprocess.run with a timeout (the gh and git calls of this file); a hung one stops the run (a Fail: never reported as a clean day).
    The gh helpers shared with pin-age-check.py have their own timeout there."""
    try:
        return subprocess.run(cmd, **dict({"timeout": SUBPROCESS_TIMEOUT}, **kw))
    except subprocess.TimeoutExpired:
        raise Fail(f"{cmd[0]} {' '.join(map(str, cmd[1:3]))} did not answer in {SUBPROCESS_TIMEOUT}s")


def _vt(v):
    """(release numbers without trailing zeros, class, suffix parts): class 0 = pre-release (before the final), 1 = final, 2 = post-release.
    1.0.0-rc.1 and 1.0.0rc1 are BEFORE 1.0.0; 1.0.post1 is AFTER 1.0; 1.2 equals 1.2.0.
    A suffix of any other kind raises ValueError (callers read it as affected)."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)(.*)$", str(v).split("+", 1)[0].strip(), re.I)  # build metadata (+build.1) does not order versions
    if not m:
        raise ValueError(f"not a version: {v}")
    nums = [int(x) for x in m.group(1).split(".")]
    while nums and nums[-1] == 0:
        nums.pop()
    rest = m.group(2).lstrip("-_.+")
    if not rest:
        return (nums, 1, [])
    cls = 0 if _PRE.match(rest) else 2 if _POST.match(rest) else None
    if cls is None:
        raise ValueError(f"unrecognised version suffix: {v}")
    parts = [int(p) if p.isdigit() else p.lower() for p in re.split(r"[.\-_+]|(?<=\D)(?=\d)", rest) if p]
    return (nums, cls, parts)


def _cmp(a, b):
    x, y = _vt(a), _vt(b)
    if x[0] != y[0]:
        return (x[0] > y[0]) - (x[0] < y[0])
    if x[1] != y[1]:
        return (x[1] > y[1]) - (x[1] < y[1])
    kx = [(0, p) if isinstance(p, int) else (1, p) for p in x[2]]
    ky = [(0, p) if isinstance(p, int) else (1, p) for p in y[2]]
    return (kx > ky) - (kx < ky)


_SEMVER = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def _semver_key(v):
    """Strict semver 2.0 ordering key (Go versions, pseudo-versions and +incompatible included): a pre-release is below its release, its identifiers
    compare numerically when numeric and lexically otherwise (numeric below alphanumeric), build metadata is ignored. Identifiers that
    SemVer 2.0.0 forbids (empty, or numeric with a leading zero) make the value unparsable, which callers read as affected. The OSV value "0" is the minimum."""
    if str(v) == "0":
        return (-1,)
    m = _SEMVER.fullmatch(str(v))
    if not m:
        raise ValueError(f"not a semver version: {v}")
    pre = m.group(4)
    if pre and any(x.isdigit() and len(x) > 1 and x[0] == "0" for x in pre.split(".")):
        raise ValueError(f"SemVer forbids a numeric pre-release identifier with a leading zero: {v}")
    ids = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ids)


def _semver_cmp(a, b):
    ka, kb = _semver_key(a), _semver_key(b)
    return (ka > kb) - (ka < kb)


def covered_by_events(version, events, semver=False):
    """Is the version inside the OSV range described by the events? semver=True compares strictly as semver (Go); the default also reads the
    post-release forms of other ecosystems. A value that cannot be ordered is never read as unaffected."""
    try:
        return _covered_by_events(version, events, _semver_cmp if semver else _cmp)
    except ValueError:
        return True


def _covered_by_events(version, events, cmp):
    """OSV range events: sort by version (introduced "0" is the minimum element; at one version introduced comes before fixed, so the fixed wins), then
    introduced switches affected on, fixed and last_affected (after it) switch it off. A limit is an upper bound: the version must be below ANY limit."""
    order = {"introduced": 0, "fixed": 1, "last_affected": 1}
    kinds = [(k, e[k]) for e in events for k in order if k in e]
    kinds.sort(key=lambda ke: (ke != ("introduced", "0"), functools.cmp_to_key(cmp)(ke[1]), order[ke[0]]))
    state = False
    for kind, value in kinds:
        if kind == "introduced":
            state = state or value == "0" or cmp(version, value) >= 0
        elif kind == "fixed":
            state = state and cmp(version, value) < 0
        else:
            state = state and cmp(version, value) <= 0
    limits = [e["limit"] for e in events if "limit" in e]
    return state and (not limits or any(cmp(version, x) < 0 for x in limits))


def in_range(version, rng):
    try:
        return _in_range(version, rng)
    except ValueError:
        return True


def _in_range(version, rng):
    """GitHub vulnerable_version_range: '>= 1.0, < 2.0' or '= 0.69.4'; several ranges may be joined by '|'."""
    for alt in str(rng).split("|"):
        ok = True
        for part in alt.split(","):
            m = re.match(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$", part)
            if not m:
                return True  # a range we cannot read is never taken as "not affected"
            c = _cmp(version, m.group(2))
            ok &= {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0}[m.group(1)]
        if ok:
            return True
    return False


# ---------- sources: fixtures (tests) and the live databases ----------
class FixtureNet:
    def __init__(self, fx):
        self.fx = fx

    def lists(self, item):
        d = (self.fx.get("lists") or {}).get(item.key) or {}
        return list(d.get("github") or []), list(d.get("osv") or [])

    def covered(self, item):
        return item.key not in (self.fx.get("uncovered") or [])

    def version_of(self, item):
        return version_of(item)

    def open_pr_items(self):
        return [(p["number"], [inv.Item(*_split_key(k)) for k in p.get("items", [])]) for p in (self.fx.get("open_prs") or [])]

    def live_ranges(self, item, source, advisory_id):
        return (self.fx.get("live_ranges") or {}).get(advisory_id)

    def upstream(self, item):
        return ((self.fx.get("upstream") or {}).get(f"{item.name}@{item.version}") or {}).get("reachable")

    def nested(self, item):
        return (self.fx.get("nested") or {}).get(f"{item.name}@{item.version}") or []

    def versions(self, item):
        return (self.fx.get("versions") or {}).get(item.name) or []

    def prs(self):
        return self.fx.get("prs") or []

    def proofs(self, item, base=None, head="HEAD"):
        return age.Fixture(self.fx).proofs(item)

    def tag_map(self, items):
        return dict(self.fx.get("tags") or {})

    def observed(self):
        return self.fx.get("observed")

    def modified(self, advisory_id):
        return None


GO_TOOLS = {"trivy": "github.com/aquasecurity/trivy", "grype": "github.com/anchore/grype", "syft": "github.com/anchore/syft",
            "osv": "github.com/google/osv-scanner/v2", "gitsign": "github.com/sigstore/gitsign", "golangci-lint": "github.com/golangci/golangci-lint/v2",
            "goreleaser": "github.com/goreleaser/goreleaser/v2", "scout": "github.com/docker/scout-cli", "cosign": "github.com/sigstore/cosign/v3",
            "kind": "sigs.k8s.io/kind", "helm": "helm.sh/helm/v3"}
NPM_TOOLS = {"snyk": "snyk"}

# REQ-SUP-001-AC14: Go gives a module of major N >= 2 the path ending in /vN, and majors 0 and 1 the bare path. The table above holds the path of the
# major we pin; a pin that moves to another major must move its table entry in the same change (the audit fails closed, a hit, until it does).
_PLAIN_VERSION = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
IGNORED_NOTE = "ignored advisory entry"


class GoRule:
    """AC14: the module paths of one pinned tool. major and right are None for a non-empty version that is not plain MAJOR.MINOR.PATCH."""

    def __init__(self, item, version):
        self.table = GO_TOOLS[item.name]
        self.bare = re.sub(r"/v[0-9]+$", "", self.table)
        m = _PLAIN_VERSION.fullmatch(version)
        self.major = int(m.group(1)) if m else None
        self.right = None if m is None else self.bare if self.major <= 1 else f"{self.bare}/v{self.major}"

    @property
    def paths(self):
        """Every path OSV and GitHub are asked for: the table path, the path of the pinned major and the bare path (AC14: queried by /vMAJOR as well)."""
        return list(dict.fromkeys([self.table, self.right, self.bare] if self.right else [self.table, self.bare]))


def _without_paths(record):
    """The record with every affected entry's package removed, so that one name filter (_osv_says) takes all entries into account."""
    return dict(record, affected=[dict(a, package={}) for a in record["affected"]])


# AC14: the allow-schema of a well-formed OSV Go record, as the Go vulnerability database writes it. The keys are the ones real records carry (see
# the fixtures) plus the OSV schema's versions and severity. Anything else, a wrong type or an empty string is not trusted: the record is a hit.
_ENTRY_KEYS = {"package", "ranges", "versions", "ecosystem_specific", "database_specific", "severity"}
_PACKAGE_KEYS = {"ecosystem", "name", "purl"}
_RANGE_KEYS = {"type", "events", "repo", "database_specific"}
_EVENT_KEYS = ("introduced", "fixed", "last_affected", "limit")


def _text(x):
    return isinstance(x, str) and x != ""


def _readable_record(v):
    """AC14: the metadata read from a record (OSV schema: id and modified are required strings; aliases is a list of strings, absent or null)."""
    aliases = v.get("aliases") if isinstance(v, dict) else None
    return (isinstance(v, dict) and _text(v.get("id")) and _text(v.get("modified"))
            and (aliases is None or (isinstance(aliases, list) and all(isinstance(a, str) for a in aliases))))


def _well_formed_event(event, allow_limit):
    """One of the OSV event keys, alone, with a non-empty string value that has no v prefix (Go records have none). A limit event belongs to GIT ranges."""
    if not (isinstance(event, dict) and len(event) == 1):
        return False
    (key, value), = event.items()
    return (key in _EVENT_KEYS and (allow_limit or key != "limit") and _text(value) and not value.lower().startswith("v"))


def _well_formed_range(rg):
    """Every range lists events with an introduced among them (their order is free, the evaluator sorts) and not both fixed and last_affected;
    a GIT range also names its repo and is never read for a version; a SEMVER or ECOSYSTEM range has no limit."""
    if not (isinstance(rg, dict) and set(rg) <= _RANGE_KEYS and rg.get("type") in ("SEMVER", "ECOSYSTEM", "GIT")):
        return False
    events, git = rg.get("events"), rg["type"] == "GIT"
    if not (isinstance(events, list) and events and all(_well_formed_event(e, git) for e in events)):
        return False
    kinds = {k for e in events for k in e}
    return ("introduced" in kinds and not {"fixed", "last_affected"} <= kinds and isinstance(rg.get("repo", ""), str)
            and (not git or _text(rg.get("repo"))) and isinstance(rg.get("database_specific", {}), dict))


def _well_formed_package(package):
    return (isinstance(package, dict) and set(package) <= _PACKAGE_KEYS and _text(package.get("name"))
            and _text(package.get("ecosystem")) and isinstance(package.get("purl", ""), str))


def _well_formed_severity(severity):
    return isinstance(severity, list) and all(isinstance(x, dict) and _text(x.get("type")) and _text(x.get("score")) for x in severity)


def _well_formed_entry(entry):
    """One affected entry: only the keys of the schema, each of its type."""
    if not (isinstance(entry, dict) and set(entry) <= _ENTRY_KEYS and _well_formed_package(entry.get("package"))):
        return False
    ranges, versions = entry.get("ranges", []), entry.get("versions", [])
    return (isinstance(ranges, list) and all(_well_formed_range(rg) for rg in ranges)
            and isinstance(versions, list) and all(_text(v) for v in versions)
            and _well_formed_severity(entry.get("severity", []))
            and all(isinstance(entry.get(k, {}), dict) for k in ("ecosystem_specific", "database_specific")))


def _well_formed_record(record):
    """AC14: every OSV entry the Go rule reads matches the schema above, checked once before any branch."""
    return isinstance(record.get("affected"), list) and all(_well_formed_entry(a) for a in record["affected"])


def _reads_git(entry):
    return any(rg["type"] == "GIT" for rg in entry.get("ranges", []))


def _decidable(entry):
    """AC14: an exact-path entry may clear a version only if it is Go and its ranges are all SEMVER or ECOSYSTEM (a GIT range cannot be judged by version)."""
    return entry["package"].get("ecosystem") == "Go" and bool(entry.get("ranges")) and all(rg["type"] != "GIT" for rg in entry["ranges"])


def _go_rule(item, version):
    """The AC14 rule for this pin, or None where the old audit applies unchanged: not a tool of the table, other kinds of item, an empty version."""
    return GoRule(item, version) if item.kind == "tool" and item.name in GO_TOOLS and version else None


class LiveNet:
    def __init__(self, gh, root):
        self.gh, self.root = gh, root
        self._memo, self._lock = {}, threading.Lock()
        self.incomplete_prs = []
        self.ignored_entries, self._reported = [], 0   # AC14: every OSV entry the rule did not use, {"id", "path", "reason"}, each once

    def _gh_json(self, path, strict=False):
        """JSON from gh api. A 404 is None; with strict=True nothing else may be None either (a 422 or bad JSON is not 'absent')."""
        with self._lock:
            if (path, strict) in self._memo:
                return self._memo[(path, strict)]
        r = _run([*self.gh, "api", path], capture_output=True, text=True)
        if r.returncode:
            try:
                age._gh_failed(r)
            except age.CouldNotLook as e:
                raise Fail(str(e))
        try:
            val = None if r.returncode else json.loads(r.stdout)
        except ValueError:
            val = None
            if strict:
                raise Fail(f"gh api {path.split('?')[0]} did not return JSON")
        if strict and r.returncode and not re.search(r"\b404\b", r.stderr + r.stdout):
            raise Fail(f"gh api {path.split('?')[0]} failed: {(r.stderr or r.stdout).strip()[:100]}")
        if strict and val is None and r.returncode:
            val = [] if "?" in path else None  # a 404 on a LIST endpoint: no entries; on a record: absent
        elif strict and val is None:
            raise Fail(f"gh api {path.split('?')[0]} returned null")
        with self._lock:
            self._memo[(path, strict)] = val
        return val

    def _osv_post(self, q):
        vulns, token = [], None
        for _ in range(20):
            body = dict(q, **({"page_token": token} if token else {}))
            req = urllib.request.Request("https://api.osv.dev/v1/query", json.dumps(body).encode(), {"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    d = json.load(r)
            except (OSError, ValueError) as e:
                raise Fail(f"the OSV query failed: {e}")
            vulns += d.get("vulns", [])
            token = d.get("next_page_token")
            if not token:
                return vulns
        raise Fail("the OSV query has more than 20 pages")

    def _osv_get(self, advisory_id):
        try:
            with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(advisory_id)}", timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # OSV does not hold this incident
            raise Fail(f"the OSV lookup of {advisory_id} failed: HTTP {e.code}")
        except (OSError, ValueError) as e:
            raise Fail(f"the OSV lookup of {advisory_id} failed: {type(e).__name__}")

    def version_of(self, item):
        return self._version_of(item)

    def resolve_ref(self, repo, tag):
        """The commit a (moving) tag points at right now, annotated tags peeled; None when it cannot be resolved."""
        ref = self._gh_json(f"repos/{repo}/git/ref/tags/{urllib.parse.quote(tag)}")
        obj = (ref or {}).get("object") or {}
        for _ in range(3):
            if obj.get("type") != "tag":
                break
            obj = (self._gh_json(f"repos/{repo}/git/tags/{obj['sha']}") or {}).get("object") or {}
        return obj.get("sha") if obj.get("type") == "commit" else None

    @staticmethod
    def _bounded(tags):
        if len(tags) > 200:
            raise Fail("a commit carries %d version tags: refusing to check only some of them" % len(tags))
        return tags

    def versions_of(self, item):
        """Every version-like tag at an action's commit (an exception must clear them ALL), else the single version."""
        if item.kind == "action" and inv.SHA40.match(item.version):
            return self._bounded([t for t in age._tags_for_commit(item.name, item.version) if re.match(r"^v?\d", t)])
        v = self._version_of(item)
        return [v] if v else []

    def _version_of(self, item):
        if item.kind == "action" and inv.SHA40.match(item.version):
            tags = [t for t in age._tags_for_commit(item.name, item.version) if re.match(r"^v?\d", t)]
            if tags:  # the most specific tag at the commit (v4.1.5 over v4): a coarse label must not move the commit out of a range
                return sorted(tags, key=lambda t: (t.count("."), len(t)), reverse=True)[0]
            return None  # no tag at the commit resolves to a version: even a # label is only a comment, so the commit is UNRESOLVED
        return item.version  # a tag/branch ref, or a tool/package version

    def _query(self, item, version):
        if item.kind == "action":
            return {"package": {"name": item.name, "ecosystem": "GitHub Actions"}}
        if item.kind == "package":
            return {"package": {"name": item.name.split("/", 1)[1], "ecosystem": "PyPI"}, "version": version}
        if item.kind == "tool" and item.name in NPM_TOOLS:
            return {"package": {"name": NPM_TOOLS[item.name], "ecosystem": "npm"}, "version": version}
        mod = None
        if item.kind == "gotool":
            # the module root, resolved through the proxy; unresolved: not covered (never the raw command path)
            mod = age._go_module(item.name, item.version)[0]
        elif item.kind == "tool":
            mod = GO_TOOLS.get(item.name) or (f"github.com/{item.name}" if re.fullmatch(r"[\w.-]+/[\w.-]+", item.name) else None)
        return {"package": {"name": mod, "ecosystem": "Go"}, "version": version} if mod else None

    def live_ranges(self, item, source, advisory_id):
        """The authoritative advisory's affected ranges for this package, read live (GitHub only: the rulings so far name GitHub)."""
        if str(source).lower() != "github":
            return None
        adv = self._gh_json(f"advisories/{advisory_id}", strict=True)
        q = self._query(item, self._version_of(item) or "")
        names = {_norm_name(package_of(item)), _norm_name(item.name)} | ({_norm_name(q["package"]["name"])} if q else set())
        rule = _go_rule(item, self._version_of(item) or "")
        names |= {_norm_name(p) for p in (rule.paths if rule else [])}   # AC14: GitHub files some Go ranges under the bare path
        rngs = [x["vulnerable_version_range"] for x in (adv or {}).get("vulnerabilities",
            []) if x.get("vulnerable_version_range") and _norm_name((x.get("package") or {}).get("name", "")) in names]
        return rngs or None

    def covered(self, item):
        """Is there an advisory source for this kind of item at all? (None-query items are reported as not checked, never as clean.)"""
        v = self._version_of(item)
        return bool(v) and self._query(item, v) is not None

    def lists(self, item):
        if item.kind == "action" and inv.SHA40.match(item.version):  # EVERY version-like tag at the commit: one tag must not hide another's advisory
            tags = self._bounded([t for t in age._tags_for_commit(item.name, item.version) if re.match(r"^v?\d", t)])
            if len(tags) > 1:
                gh_all, osv_all = [], []
                for t in tags:
                    g, o = self._lists_for(item, t)
                    # a dispute is between the databases about ONE version, never across tags
                    tag_ = lambda x: dict(x, incident="%s@%s" % (x.get("incident") or x["id"], t))
                    gh_all += [tag_(x) for x in g]
                    osv_all += [tag_(x) for x in o]
                return gh_all, osv_all
        return self._lists_for(item, self._version_of(item))

    def _lists_for(self, item, version):
        q = self._query(item, version) if version else None
        if q is None or not version:
            return [], []
        osv, ghs = [], []
        rule = _go_rule(item, version)
        paths = rule.paths if rule else [q["package"]["name"]]
        for copies in self._osv_records(q, paths, strict=bool(rule)).values():
            v = dict(copies[0], aliases=sorted({a for c in copies for a in (c.get("aliases") or [])}))   # AC14: the aliases of every copy
            if rule:
                says = any([self._go_says(c, rule, version) for c in copies])   # AC14: a copy that is unsettled or affected makes the record a hit
            else:
                says = self._osv_says(v, q["package"]["name"], version, versioned="version" in q)
            osv.append({"id": v["id"], "incident": v["id"], "affected": says, "modified": v.get("modified"), "malicious": v["id"].startswith("MAL-")})
            for alias in [v["id"], *v.get("aliases", [])]:  # an OSV record can itself be the GitHub advisory (GHSA-... primary id)
                if alias.startswith("GHSA-"):
                    adv = self._gh_json(f"advisories/{alias}", strict=True)
                    names = {_norm_name(q["package"]["name"]), _norm_name(item.name)} | {_norm_name(p) for p in paths}
                    rngs = [x["vulnerable_version_range"] for x in (adv or {}).get("vulnerabilities", [])
                            if x.get("vulnerable_version_range") and _norm_name((x.get("package") or {}).get("name", "")) in names]
                    if adv and rngs:
                        ghs.append({"id": alias, "incident": v["id"], "affected": in_range(version, "|".join(rngs)), "modified": adv.get("updated_at")})
        eco = {"actions": "actions", "PyPI": "pip", "Go": "go", "npm": "npm"}.get(q["package"]["ecosystem"].replace("GitHub Actions", "actions"))
        pkg = q["package"]["name"]
        if eco:
            seen = {g["id"] for g in ghs}
            page = []
            asked = list(dict.fromkeys([pkg, *paths]))
            if q["package"]["ecosystem"] == "PyPI":
                info = age._http_json(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json") or {}
                published = (info.get("info") or {}).get("name")
                if published and published != pkg:
                    asked.append(published)            # jaraco.context vs jaraco-context: GitHub matches the exact published name
            for typ in ("", "&type=malware"):
              for nm in asked:
                for n in range(1, 11):
                    got = self._gh_json(f"advisories?ecosystem={eco}&affects={urllib.parse.quote(nm)}{typ}&per_page=100&page={n}", strict=True)
                    if not isinstance(got, list):
                        raise Fail("GitHub's advisory list was not a list: refusing to read it as 'no advisories'")
                    page += got
                    if len(got) < 100:
                        break
                else:
                    raise Fail("GitHub's advisory list has more than 10 pages")
            for adv in page:  # GitHub-only advisories (never copied to OSV) and malware reports: the ranges are read here, not trusted to a filter
                if adv.get("ghsa_id") in seen:
                    continue
                rngs = [x["vulnerable_version_range"] for x in adv.get("vulnerabilities", [])
                        if x.get("vulnerable_version_range") and _norm_name((x.get("package") or {}).get("name", "")) in {_norm_name(a) for a in asked}]
                if rngs and in_range(version, "|".join(rngs)):
                    ghs.append({"id": adv["ghsa_id"], "incident": adv["ghsa_id"], "affected": True, "modified": adv.get("updated_at"),
                        "malicious": adv.get("type") == "malware"})
                    rec = self._osv_get(adv["ghsa_id"])
                    if rec and rec.get("id"):  # OSV knows this incident too: its own verdict for this version decides whether the lists AGREE
                        osv.append({"id": rec["id"], "incident": adv["ghsa_id"], "affected": self._osv_says(rec, pkg, version, versioned=False),
                                    "modified": rec.get("modified"), "malicious": rec["id"].startswith("MAL-")})
        return ghs, osv

    def _osv_records(self, q, paths, strict=False):
        """The OSV records for the query, asked once per module path (AC14): {id: [the distinct copies returned]}. Copies of one id can differ by path."""
        records = {}
        for p in paths:
            for v in self._osv_post(dict(q, package=dict(q["package"], name=p))):
                if strict and not _readable_record(v):
                    v = {"id": "UNREADABLE-OSV-RECORD", "affected": "not a record"}   # AC14: an answer that is not a record is a hit, with this id
                copies = records.setdefault(v["id"], [])
                if v not in copies:
                    copies.append(v)
        return records

    def _go_says(self, v, rule, version):
        """AC14: does this OSV record cover a Go tool's pinned version? Where the rule cannot settle it the answer is yes (fail closed)."""
        if rule.right is None:                       # AC14: a non-empty version that is not plain MAJOR.MINOR.PATCH is a hit
            return True
        if not _well_formed_record(v):
            return True                              # AC14: one strict schema for every entry the rule reads, before any branch
        entries = v["affected"]
        path = lambda a: a["package"]["name"]
        ambiguous = rule.major <= 1 and any(path(a) in (rule.bare + "/v0", rule.bare + "/v1") for a in entries)
        if (rule.table != rule.right or ambiguous) and any(_reads_git(a) for a in entries):
            return True                              # AC14: the two branches below skip GIT ranges, so an entry that has one is a hit
        if rule.table != rule.right:                 # AC14: the table path is for another major: any entry of any path that covers the version is a hit
            return self._osv_says(_without_paths(v), "", version, versioned=True, semver=True)
        if ambiguous:
            return self._osv_says(v, rule.right, version, versioned=True, semver=True)   # AC14: a /v0 or /v1 path is ambiguous: the old verdict
        exact = [a for a in entries if path(a) == rule.right]
        if not exact or not all(_decidable(a) for a in exact):
            return True                              # AC14: no entry for the exact path, or one that is not plainly Go with readable ranges: a hit
        for a in entries:
            if a not in exact:
                self._log_ignored(v["id"], path(a), self._ignore_reason(a, rule))
        return self._osv_says(dict(v, affected=exact), rule.right, version, versioned=True, semver=True)

    @staticmethod
    def _ignore_reason(entry, rule):
        eco = entry["package"].get("ecosystem")
        return f"not the module path of major {rule.major} ({rule.right})" if eco == "Go" else f"ecosystem {eco or 'missing'} is not Go"

    def _log_ignored(self, advisory_id, path, reason):
        """AC14: an entry the rule did not use is logged, once per id, path and reason (two queries return the same record)."""
        entry = {"id": advisory_id, "path": path, "reason": reason}
        with self._lock:
            if entry not in self.ignored_entries:
                self.ignored_entries.append(entry)

    def take_ignored(self):
        """The entries logged since the last call. The net is shared by the judging pool, so a line is attached to whichever item's judge drains it first."""
        with self._lock:
            new, self._reported = self.ignored_entries[self._reported:], len(self.ignored_entries)
        return new

    @staticmethod
    def _osv_says(v, name, version, versioned, semver=False):
        """Does OSV's record cover this version? Each affected entry's ranges are judged separately and OR-ed (never one merged event list)."""
        entries = [a for a in v.get("affected", []) if (a.get("package") or {}).get("name", "").lower() == name.lower()] or v.get("affected", [])
        judged = False
        for a in entries:
            for ev in (a.get("versions") or []):
                try:
                    if _cmp(version, ev) == 0:
                        return True
                except ValueError:
                    if str(version) == str(ev):
                        return True
            for rg in a.get("ranges", []):
                if rg.get("type") in ("SEMVER", "ECOSYSTEM"):
                    judged = True
                    if covered_by_events(version, rg.get("events", []), semver):
                        return True
        if not versioned and any(rg.get("type") == "GIT" for a in entries for rg in a.get("ranges", [])):
            return True  # a commit range cannot be judged by version: unresolved is never "not affected", whatever the other ranges say
        return versioned and not judged  # a versioned query already filtered by version; with no ranges to read, trust it

    def upstream(self, item):
        if item.kind != "action" or not inv.SHA40.match(item.version):
            return None  # only a commit pin can be "not from the action's own repo"
        r = _run([*self.gh, "api", f"repos/{item.name}", "--jq", ".default_branch"], capture_output=True, text=True)
        self._api_ok(r, item)
        branch = r.stdout.strip()
        if r.returncode or not branch:
            return False
        c = _run([*self.gh, "api", f"repos/{item.name}/compare/{item.version}...{branch}", "--jq", ".status"], capture_output=True, text=True)
        self._api_ok(c, item)
        # compare/<pin>...<branch>: the branch is "ahead" of (or identical to) the pin exactly when the pin is an ancestor of the branch
        if c.stdout.strip() in ("identical", "ahead"):
            return True
        if age._tag_for_commit(item.name, item.version) is not None:
            return True
        for br in (self._gh_json(f"repos/{item.name}/branches?per_page=100") or []):  # a release branch of the same repository
            if br.get("name") != branch:
                c = _run([*self.gh, "api", f"repos/{item.name}/compare/{item.version}...{br['name']}", "--jq", ".status"], capture_output=True, text=True)
                self._api_ok(c, item)
                if c.stdout.strip() in ("identical", "ahead"):
                    return True
        return False

    @staticmethod
    def _api_ok(r, item):
        """A 404/422 means the commit or repo is not there (a finding); anything else (rate limit, outage) means we could not look, never a hit."""
        if r.returncode and not re.search(r"\b(404|422)\b", r.stderr):
            raise Fail(f"could not check {item.name}@{item.version[:12]} upstream: {r.stderr.strip()[:120]}")

    def nested(self, item):
        if item.kind != "action":
            return []
        out = []
        for name in ("action.yml", "action.yaml"):
            sub = f"{item.path}/" if getattr(item, "path", "") else ""
            c = self._gh_json(f"repos/{item.name}/contents/{sub}{name}?ref={item.version}")
            if c and c.get("content"):
                try:
                    doc = inv.yaml.load(base64.b64decode(c["content"]).decode(), Loader=inv.yaml.BaseLoader) or {}
                except inv.yaml.YAMLError:
                    return [{"ref": "(action metadata not found or unreadable)", "pinned": False}]
                runs = doc.get("runs") or {}
                refs = [st.get("uses") for st in (runs.get("steps") or []) if isinstance(st, dict) and isinstance(st.get("uses"), str)]
                if isinstance(runs.get("image"), str):
                    refs.append(runs["image"])  # docker://... or a Dockerfile in the action's repository
                for ref in refs:
                    out.append({"ref": ref, "pinned": bool(re.search(r"@[0-9a-f]{40}$|@sha256:[0-9a-f]{64}$", ref))})
                return out
        return [{"ref": "(action metadata not found or unreadable)", "pinned": False}]  # said out loud, never silently empty

    def versions(self, item):
        """Candidate versions with their publish times; None when this kind of item cannot be enumerated (then nobody searched, and it is a decision)."""
        if item.kind == "package":
            d = age._http_json(f"https://pypi.org/pypi/{urllib.parse.quote(item.name.split('/', 1)[1])}/json")
            if not d:
                return None
            out = []
            for ver, files in (d.get("releases") or {}).items():
                ups = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601") and not f.get("yanked")]
                if ups:
                    out.append({"version": ver, "sha": None, "published": min(ups), "_item": inv.Item("package", item.name, ver, ver)})
            return out
        repo = item.name if item.kind == "action" else (age.TOOL_REPOS.get(item.name) or (item.name if re.fullmatch(r"[\w.-]+/[\w.-]+", item.name) else None))
        if not repo:
            return None
        rels = []
        for pg in range(1, 11):
            chunk = self._gh_json(f"repos/{repo}/releases?per_page=100&page={pg}")
            if chunk is None:
                if pg == 1:
                    return None
                break
            rels += chunk
            if len(chunk) < 100:
                break
        out = []
        for r in rels:
            if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
                continue
            sha = None
            if item.kind == "action":
                ref = self._gh_json(f"repos/{repo}/git/ref/tags/{urllib.parse.quote(r['tag_name'])}")
                if ref and ref.get("object", {}).get("type") == "commit":
                    sha = ref["object"]["sha"]
                elif ref and ref.get("object", {}).get("type") == "tag":
                    t = self._gh_json(f"repos/{repo}/git/tags/{ref['object']['sha']}")
                    sha = (t or {}).get("object", {}).get("sha")
            cand = inv.Item(item.kind, item.name, sha, r["tag_name"]) if (item.kind == "action" and sha) else inv.Item(item.kind, item.name, r["tag_name"],
                r["tag_name"])
            out.append({"version": r["tag_name"], "sha": sha, "published": r["published_at"], "_item": cand})
        return out

    def open_pr_items(self):
        """(number, [moved items]) for every open pull request, forks included: what each PR adds over its base."""
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            return []
        out = []
        pulls = age._gh_pages(f"repos/{repo}/pulls?state=open&per_page=100")
        if pulls is None:
            raise Fail("could not list the open pull requests")
        for p in pulls:
            tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            hdr = ["-c",
                "http.https://github.com/.extraheader=AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode()] if tok else []
            f = _run(["git", "-C", self.root, *hdr, "fetch", "-q", "origin", f"pull/{p['number']}/head", p["base"]["ref"]], capture_output=True, text=True)
            if f.returncode:
                self.incomplete_prs.append(p["number"])
                print(f"information: open pull request #{p['number']} could not be fetched: not audited")
                continue
            try:
                mb = _run(["git", "-C", self.root, "merge-base", f"origin/{p['base']['ref']}", p["head"]["sha"]], capture_output=True, text=True).stdout.strip()
                if not mb:
                    self.incomplete_prs.append(p["number"])
                    print(f"information: open pull request #{p['number']} shares no history with its base: not audited")
                items = inv.moved(inv.load_at(self.root, mb), inv.load_at(self.root, p["head"]["sha"])) if mb else []
            except (RuntimeError, ValueError) as e:
                print(f"information: open pull request #{p['number']} was not audited: {clean(e)}")
                self.incomplete_prs.append(p["number"])
                continue
            out.append((p["number"], items))
        return out

    def prs(self):
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise Fail("GITHUB_REPOSITORY is not set")
        r = _run([*self.gh, "pr", "list", "--state", "open", "--json", "number,title,headRefOid,baseRefName", "--limit", "1000"], capture_output=True,
            text=True)
        if r.returncode:
            raise Fail("could not list open pull requests: " + r.stderr.strip())
        out = []
        for p in json.loads(r.stdout or "[]"):
            tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            hdr = ["-c",
                "http.https://github.com/.extraheader=AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode()] if tok else []
            f = _run(["git", "-C", self.root, *hdr, "fetch", "-q", "origin", f"pull/{p['number']}/head", f"{p['baseRefName']}"], capture_output=True, text=True)
            if f.returncode:
                continue
            try:
                head = _run(["git", "-C", self.root, "rev-parse", "FETCH_HEAD"], capture_output=True, text=True).stdout.strip()
                mb = _run(["git", "-C", self.root, "merge-base", f"origin/{p['baseRefName']}", p["headRefOid"]], capture_output=True, text=True).stdout.strip()
                moved = inv.moved(inv.load_at(self.root, mb), inv.load_at(self.root, p["headRefOid"])) if mb else []
            except (RuntimeError, ValueError):
                continue
            try:
                runs = self._gh_json(f"repos/{repo}/actions/runs?head_sha={p['headRefOid']}&event=pull_request&per_page=100") or {}
            except Fail as e:
                print(f"information: the runs of pull request #{p['number']} could not be read: {clean(e)}")
                continue
            mine = sorted((x for x in runs.get("workflow_runs", []) if str(x.get("path") or "").split("@")[0] == ".github/workflows/supply-chain.yml"),
                key=lambda x: x.get("created_at", ""), reverse=True)
            failed = mine[:1] if mine and mine[0].get("conclusion") == "failure" else []  # the NEWEST run decides: a later green run needs no re-run
            if moved and failed:
                out.append({"number": p["number"], "title": p["title"], "run_id": failed[0]["id"], "moved": [m.key for m in moved], "_items": moved,
                    "_base": mb, "_head": p["headRefOid"]})
        return out

    def proofs(self, item, base=None, head="HEAD"):
        return age.live_proofs(item, self.root, base, head)

    def observed(self):
        return age.observed()

    def tag_map(self, items):
        """{"owner/repo@tag": commit} for the latest tags of every action we use plus the tags we pin: what today's run observed."""
        out = {}
        for repo in sorted({i.name for i in items if i.kind == "action"}):
            for t in age._gh_pages(f"repos/{repo}/tags?per_page=100") or []:
                out[f"{repo}@{t['name']}"] = t["commit"]["sha"]
        for i in items:
            if i.kind == "action" and inv.SHA40.match(i.version):
                for tag in age._tags_for_commit(i.name, i.version):
                    out[f"{i.name}@{tag}"] = i.version
        return out

    def modified(self, advisory_id):
        if advisory_id.startswith("GHSA-"):
            adv = self._gh_json(f"advisories/{advisory_id}")
            if adv:
                return adv.get("updated_at")
        try:
            with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(advisory_id)}", timeout=30) as r:
                return json.load(r).get("modified")
        except (OSError, ValueError):
            return None


# ---------- exceptions (the same format as the ops repo's docs/supply-chain-exceptions.json) ----------
def load_exceptions(path, required):
    if not path or not os.path.exists(path):
        if required:
            raise Fail(f"the exceptions file {path} does not exist")
        return []
    try:
        d = json.load(open(path))
        ex = d["exceptions"]
        assert isinstance(ex, list)
        for e in ex:
            assert isinstance(e["ids"], list) and e["ids"] and all(isinstance(i, str) for i in e["ids"])
            au = e["authoritative"]
            assert isinstance(e["modified"], dict) and e["package"] and isinstance(au, dict) and str(au["source"]).lower() in ("github", "osv") and au["id"]
            assert isinstance(au["ranges"], list) and au["ranges"] and all(isinstance(r, str) for r in au["ranges"])
            assert isinstance(e["ruling"], str) and e["ruling"] and set(e["ids"]) <= set(e["modified"]) and au["id"] in e["ids"]
            assert isinstance(e.get("osv_modified", {}), dict)
            assert isinstance(e["evidence"], list) and e["evidence"] and isinstance(e["date"], str) and e["date"]
            assert isinstance(e.get("version"), str) and e["version"].strip(), "every exception names the one version it covers"
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as e:
        raise Fail(f"the exceptions file {path} is unreadable or malformed: {e}")
    return ex


class RulingLog:
    """REQ-SUP-001-AC15: what the rulings did in one run. matched: rulings for the package and ids of a real dispute; applied: those that then decided it."""

    def __init__(self):
        self.matched, self.applied = [], []


def undecided_exceptions(exceptions, log, held, net):
    """REQ-SUP-001-AC15: the rulings that decided no dispute in this run, split into (lapsed, dead, dormant). Lapsed: it matched a real dispute but failed
    the version, time or live-range check (the dispute stays reported). Dead: no dispute, and a held pin (main, its history or an open pull request)
    is named by the ruling. Dormant: nobody holds its pin. Judged from what the run matched, applied and held, never from a list."""
    lapsed, dead, dormant = [], [], []
    for e in exceptions:
        if any(e is a for a in log.applied):
            continue
        if any(e is m for m in log.matched):
            lapsed.append(e)
        elif any(package_of(it) == e["package"] and _ruling_covers(e, it, _pin_versions(it, net), every=False) for it in held):
            dead.append(e)
        else:
            dormant.append(e)
    return lapsed, dead, dormant


def dead_message(e, held, net):
    """The DEAD EXCEPTION text; when the ruling names only some of a held pin's versions (tags v3 and v3.37.8) it says how to write the series."""
    msg = f"the ruling for {_ruling_label(e)} decided no dispute while its pin is held: remove it from the exceptions file"
    for it in held:
        vers = _pin_versions(it, net)
        if package_of(it) == e["package"] and _ruling_covers(e, it, vers, every=False) and not _ruling_covers(e, it, vers):
            series = str(e["version"]).lstrip("v").split(".")[0] + ".*"
            return msg + f" (it names only some of the versions of the held pin {', '.join(vers)}; to cover the pin write the ruling as {series})"
    return msg


def _ruling_label(e):
    return f"{clean(', '.join(e['ids']))} ({clean(e['package'])} {clean(e['version'])})"


def package_of(item):
    return item.name.split("/", 1)[1] if item.kind == "package" else item.name


def version_of(item):
    """The version to hold against an advisory's ranges: a tag-like label for a commit pin, else the version itself."""
    return (item.label or None) if inv.SHA40.match(item.version) else item.version


def _norm_ranges(rs):
    return {re.sub(r"\s+", "", r) for r in rs}


def _pin_versions(item, net):
    """Every version the pin stands for: all version-like tags at an action's commit, else its one version."""
    vers = net.versions_of(item) if hasattr(net, "versions_of") else None
    if not vers:
        vers = [net.version_of(item) if hasattr(net, "version_of") else version_of(item)]
    return [v for v in vers if v]


def _ruling_covers(e, item, vers, every=True):
    """Does the ruling name this pin: its one version, or its one series ("4.*"), for EVERY version the pin stands for (to apply a ruling) or for ANY of
    them (to tell a dead ruling from a dormant one)?"""
    covered = {str(x).lstrip("v") for x in [*vers, item.label] if x} or {str(item.version).lstrip("v")}
    want = str(e.get("version", "")).lstrip("v")
    names = lambda c: c == want or (want.endswith(".*") and (c == want[:-2] or c.startswith(want[:-1])))
    return bool(want) and (all if every else any)(names(c) for c in covered)


def excepted(item, dispute_ids, current, exceptions, net=None, osv_times=None):
    """The advisor's ruling for ONE incident and package: names exactly the advisories of this dispute, each unchanged since it was written.
    Returns None (no ruling: still disputed), "pass" (the version is outside the authoritative source's affected ranges) or "hit" (inside them:
    an exception never covers a version the authoritative source lists as affected)."""
    return ruling_for(item, dispute_ids, current, exceptions, net, osv_times)[1]


def ruling_for(item, dispute_ids, current, exceptions, net=None, osv_times=None, log=None):
    """excepted() with the ruling that decided: (entry, "pass" | "hit"), or (None, None). REQ-SUP-001-AC15 reads the entry to know a ruling is alive."""
    vers = _pin_versions(item, net)
    ver = vers[0] if vers else None
    for e in exceptions:
        if e["package"] != package_of(item) or set(e["ids"]) != set(dispute_ids):
            continue
        if not _ruling_covers(e, item, vers):
            # a ruling names the one version (or one series, "4.*") it covers and must cover EVERY tag at the commit:
            # never a wildcard, never one tag speaking for another
            continue
        if log is not None:
            log.matched.append(e)   # AC15: it names this dispute and this held pin; a failure of the time or range checks below is a lapse, not a dead ruling
        if not all(e["modified"].get(i) and current.get(i) is not None and current.get(i) == e["modified"][i] for i in e["ids"]):
            continue  # an advisory changed since the ruling (or its time was never recorded): the ruling has lapsed
        # an id that BOTH databases hold has two records: this entry must also have recorded OSV's own time for it, unchanged
        if any(t is None or e.get("osv_modified", {}).get(i) != t for i, t in (osv_times or {}).items() if i in e["ids"]):
            continue  # unknown is not unchanged: a missing time refuses
        if not ver:
            return None, None  # no version to compare with the ranges: stays disputed
        # the ruling verifies itself (advisor 0182): its copied ranges must equal the authoritative advisory's LIVE ranges, or a wrong entry could hide a hit
        au = e["authoritative"]
        live = net.live_ranges(item, au["source"], au["id"]) if net is not None else None
        if not live or _norm_ranges(live) != _norm_ranges(au["ranges"]):
            return None, None
        # ANY tag of the commit inside the ranges: affected
        return e, "hit" if any(in_range(v, "|".join(e["authoritative"]["ranges"])) for v in vers) else "pass"
    return None, None


# ---------- judging ----------
class Finding:
    def __init__(self, item, kind, ids, why, disputed=False):
        self.item, self.kind, self.ids, self.why, self.disputed = item, kind, sorted(set(ids)), why, disputed
        self.via = None  # the pinned action that calls this one
        self.pr = None   # the open pull request this pin was found in (not merged yet)


def judge(item, net, exceptions, notes, current=True, log=None):
    findings = _judge(item, net, exceptions, notes, current, log)
    for e in (net.take_ignored() if hasattr(net, "take_ignored") else []):   # AC14: nothing is ignored silently
        notes.append(f"{IGNORED_NOTE} {e['id']} {e['path']}: {e['reason']}")
    if (item.kind == "action" and inv.SHA40.match(item.version) and hasattr(net, "version_of") and net.version_of(item) is None and isinstance(net, LiveNet)):
        findings.append(Finding(item, "unresolved", ["unresolved"],
            "no tag of the action's repository points at the pinned commit, so its advisories cannot be matched to a version (the # label is not evidence)"))
    return findings


def _judge(item, net, exceptions, notes, current=True, log=None):
    findings = []
    gh_l, osv_l = net.lists(item)
    by_incident = {}
    for a in gh_l + osv_l:
        by_incident.setdefault(a.get("incident") or a["id"], []).append(a)
    for inc, advs in sorted(by_incident.items()):
        yes = [a for a in advs if a.get("affected")]
        no = [a for a in advs if not a.get("affected")]
        ids = [a["id"] for a in advs]
        if yes and no:
            cur = {}
            for x in advs:  # GitHub's time for a GHSA id, OSV's otherwise: the ops file's rule; an id both databases hold must be unchanged in BOTH
                if x["id"] not in cur or (x["id"].startswith("GHSA-") and x in gh_l):
                    cur[x["id"]] = x.get("modified")
            osv_times = {a2["id"]: a2.get("modified") for a2 in osv_l if any(g["id"] == a2["id"] for g in gh_l)}
            entry, ruling = ruling_for(item, set(ids), cur, exceptions, net, osv_times, log)
            if log is not None and entry is not None:
                log.applied.append(entry)   # AC15: this ruling decided a real dispute in this run
            if ruling == "pass":
                notes.append(f"exception applied: {package_of(item)} {item.version} ({', '.join(sorted(set(ids)))}) "
                             "is outside the authoritative source's affected ranges")
                continue
            if ruling == "hit":
                findings.append(Finding(item, "advisory", ids, "the authoritative source for this incident lists this version as affected"))
                continue
            findings.append(Finding(item, "disputed", ids, "the two advisory lists disagree about this incident: "
                                    + "; ".join(f"{_safe(a['id'])} says {'affected' if a.get('affected') else 'not affected'}" for a in advs), True))
        elif yes:
            mal = any(a.get("malicious") for a in yes)
            findings.append(Finding(item, "malicious" if mal else "advisory", [a["id"] for a in yes],
                                    "a malicious-package report covers this version" if mal else "an advisory covers this version"))
    reach = net.upstream(item) if current else None  # only today's pins are checked upstream (history items: advisories only)
    if item.kind == "action" and reach is False:
        findings.append(Finding(item, "unreachable", ["not-upstream"],
            "the pinned commit is not reachable from a branch or tag of the action's own repository (a fork-only commit)"))
    return findings


def any_affected(entry_lists):
    """Disputed or not, an advisory that says affected keeps a candidate out of 'clean'."""
    return any(a.get("affected") for a in list(entry_lists.get("github") or []) + list(entry_lists.get("osv") or []))


UNKNOWN = "unknown"


def rollback(item, net, now):
    """The newest clean version public at least 7 days; never a younger one. None: drop it. UNKNOWN: this kind of item could not be searched."""
    versions = net.versions(item)
    if versions is None:
        return UNKNOWN
    eligible = []
    for v in versions:
        pub = age.parse_time(v.get("published"))
        if pub is None or (now - pub).total_seconds() < WAIT_DAYS * 86400 or v["version"] == (item.label or item.version) or v.get("sha") == item.version:
            continue
        eligible.append((pub, v))
    def vkey(x):
        try:
            nums, cls, parts = _vt(x[1]["version"])
        except ValueError:
            return None
        return (nums, cls, [(0, q) if isinstance(q, int) else (1, q) for q in parts]) if cls != 0 else None   # a pre-release is never a rollback target
    ordered = [x for x in eligible if vkey(x) is not None]
    # newest VERSION first (a late backport is not "newest"); the lists of a candidate are fetched only when it is reached
    for pub, v in sorted(ordered, key=vkey, reverse=True):
        lists = v.get("lists")
        if lists is None:
            gh_l, osv_l = net.lists(v["_item"])
            lists = {"github": gh_l, "osv": osv_l}
        if any_affected(lists):
            continue
        cand = v.get("_item")
        if cand is not None and net.proofs(cand) is not None and not age.judge_item(cand, net.proofs(cand), now)[0]:
            continue  # the candidate commit must itself be provably old enough (a tag moved under an old release is not an old version)
        if cand is not None and cand.kind == "action" and hasattr(net, "nested"):
            # the candidate's whole nested tree (depth 3) must be clean too: a replacement that calls a compromised child is no replacement
            try:
                dirty, level, seen_c = False, [cand], {cand.key}
                for _depth in range(3):
                    nxt = []
                    for outer in level:
                        for n in net.nested(outer):
                            m = re.match(r"^([\w.-]+/[\w.-]+)(?:/([^@\s]*))?@([0-9a-f]{40})$", n["ref"])
                            if not m:
                                continue
                            # the subdirectory is part of the child (o/x/sub is not o/x)
                            child = inv.Item("action", m.group(1), m.group(3), "", m.group(2) or "")
                            if child.key in seen_c:
                                continue
                            seen_c.add(child.key)
                            if any_affected(dict(zip(("github", "osv"), net.lists(child)))):
                                dirty = True
                            nxt.append(child)
                    level = nxt
            except (Fail, age.CouldNotLook):
                continue               # cannot prove it clean: not recommended
            if dirty:
                continue
        return v
    return None


def clean(text):
    """Untrusted text (a PR title, a ref read from someone's action.yml) is printed without control characters: no log-command injection."""
    return re.sub(r"[\x00-\x1f\x7f\x85\u2028\u2029]", " ", inv._hide(str(text)))  # control characters out, and an expression (a secret's name) never printed


def _safe(text, limit=64):
    """Only a plain version-like token is echoed into an issue (a hostile label from a fork's pin could carry a link or an @mention)."""
    t = str(text)
    return t if re.fullmatch(r"[A-Za-z0-9._+/@:, \-]{1,%d}" % limit, t) and "@" not in t.replace("@sha256", "") and "//" not in t else "(unparseable)"


def title_of(f):
    it = f.item
    ver = _safe(it.label or it.version[:12])
    pkg = _safe(package_of(it))
    ids = ", ".join(_safe(i) for i in f.ids)
    return f"supply-chain: {'disputed ' if f.disputed else ''}{pkg}@{ver}", f"supply-chain: {'disputed ' if f.disputed else ''}{pkg}@{ver} ({ids})"


def body_of(f, rb, owner, ran, today):
    it = f.item
    ver = _safe(it.label or it.version)
    lines = [f"# {title_of(f)[1]}", "", f"Checked {today}. Pinned: `{it.kind}:{_safe(package_of(it))}@{_safe(it.version,
        80)}`" + (f" ({ver})" if it.label else "") + ".", "",
             f"Finding: {f.why}.", f"Advisories: {', '.join(_safe(i) for i in f.ids)}.", ""]
    if f.disputed:
        lines += ["This is a DISPUTED hit, for the advisor to rule on. Nothing was rolled back and nothing was reported clean.",
                  "A ruling goes in `.github/supply-chain-exceptions.json` (advisory ids, package, version, evidence links, date, "
                  "each advisory's last-modified time); it lapses when either advisory changes."]
        return "\n".join(lines) + "\n"
    if f.via:
        lines.append(f"This action is called inside `{_safe(f.via)}`: replace or drop the outer action. Nothing here can be pinned by us.")
        lines.append("There is no rollback of ours to a clean version of a nested action: the owner decides.")
        return "\n".join(lines) + "\n"
    if rb == UNKNOWN:
        lines.append("Rollback: this kind of item cannot be searched for older versions automatically; "
                     "nobody has looked for a clean one, so the owner decides.")
    elif rb:
        lines.append(f"Rollback: pin the newest clean version public at least {WAIT_DAYS} days: {_safe(rb['version'])}"
                     + (f" (commit {_safe(rb['sha'])})" if rb.get("sha") else "") + f", published {_safe(rb['published'])}.")
    else:
        lines.append(f"No clean version public at least {WAIT_DAYS} days exists: drop it (remove its use) until one does.")
    if ran:
        lines.append(f"This version was in our workflows within the last {LOOKBACK_DAYS} days: the owner decides what follows.")
    if owner and not ran:
        lines.append("There is no clean rollback: the owner decides.")
    return "\n".join(lines) + "\n"


# ---------- history: what we ran in the last 90 days ----------
def history_items(root, start, now):
    since = (now - dt.timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    paths = [".github", "bin/install-scanner.sh", ":(glob)**/*requirements*.txt", ":(glob)**/*.sh", ":(glob)**/action.yml", ":(glob)**/action.yaml"]
    refs = ["--all"] if start == "HEAD" else [start]  # daily mode: every branch and PR ref this checkout has, not only the default branch's ancestry
    revs = [r for r in inv.git(root, "log", f"--since={since}", "--format=%H", *refs, "--", *paths).split() if r]
    before = inv.git(root, "rev-list", "-1", f"--before={since}", start).strip()
    if before:
        revs.append(before)
    items = {}
    for r in revs:
        items.update(inv.load_at(root, r))
    return items


# ---------- gh (recorded in tests) ----------
class Gh:
    def __init__(self, cmd):
        self.cmd = cmd if isinstance(cmd, list) else [cmd]

    def run(self, *args, ok_fail=False):
        r = _run([*self.cmd, *args], capture_output=True, text=True)
        if r.returncode and not ok_fail:
            raise Fail(f"gh {' '.join(args[:2])} failed: {r.stderr.strip()}")
        return r


def file_issues(gh, plan, today):
    gh.run("label", "create", HIT_LABEL, "--description", "A supply-chain hit on a pinned version", ok_fail=True)
    if any(p["owner"] for p in plan):
        gh.run("label", "create", OWNER_LABEL, "--description", "Needs the owner's decision", ok_fail=True)
    r = gh.run("issue", "list", "--label", HIT_LABEL, "--state", "all", "--json", "number,title,state", "--limit", "1000")
    try:
        open_issues = json.loads(r.stdout or "[]")
    except ValueError:
        raise Fail("gh issue list did not return JSON")
    done = set()
    consumed = set()
    for p in plan:
        prefix, title = p["title"]
        if title in done or prefix in done:
            continue
        done.add(title); done.add(prefix)
        open_issues = [i for i in open_issues if i.get("number") not in consumed]    # an issue already serving a finding in this run is out of BOTH lookups
        existing = next((i for i in open_issues if i.get("number", -1) > 0 and (str(i.get("title", "")) == title or str(i.get("title",
            "")).startswith(prefix + " ("))), None)
        pkg_of_prefix = prefix[len("supply-chain: "):].split("@")[0]
        # a dispute that became a confirmed hit is the SAME issue (one per hit), retitled
        if existing is None and not prefix.startswith("supply-chain: disputed "):
            existing = next((i for i in open_issues if i.get("number", -1) > 0 and str(i.get("title",
                "")).startswith(f"supply-chain: disputed {pkg_of_prefix} (")), None)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(p["body"])
            path = f.name
        try:
            labels = ["--label", HIT_LABEL] + (["--label", OWNER_LABEL] if p["owner"] else [])
            if existing:
                consumed.add(existing["number"])       # one issue serves one finding in a run: a second finding never overwrites it
                gh.run("issue", "edit", str(existing["number"]), "--title", title, "--body-file", path, *(["--add-label", OWNER_LABEL] if p["owner"] else []))
                if str(existing.get("state", "OPEN")).upper() == "CLOSED":
                    gh.run("issue", "reopen", str(existing["number"]))  # still a hit: the same issue, never a replacement
                print(f"audit: updated issue #{existing['number']}: {title}")
            else:
                gh.run("issue", "create", "--title", title, "--body-file", path, *labels)
                open_issues.append({"number": -1, "title": title})
                print(f"audit: opened an issue: {title}")
        finally:
            os.unlink(path)


# ---------- held pull requests ----------
def rerun_held(gh, net, now):
    n = 0
    for pr in net.prs():
        try:  # one pull request's failure (an unreachable repository, a bad response) must never stop the others from being re-run
            items = pr.get("_items") or [inv.Item(*_split_key(k)) for k in pr["moved"]]
            rows = [age.judge_item(it, net.proofs(it, pr.get("_base"), pr.get("_head", "HEAD")), now) for it in items]
        except (Fail, age.CouldNotLook, RuntimeError, ValueError) as e:
            print(f"information: pull request #{pr.get('number')} was skipped: {clean(e)}")
            continue
        if rows and all(r[0] for r in rows):
            try:
                gh.run("run", "rerun", str(pr["run_id"]))
            except Fail as e:
                print(f"information: pull request #{pr.get('number')}: the re-run failed: {clean(e)}")
                continue
            print(f"audit: pull request #{pr['number']} ({clean(pr['title'])}): every moved version is now {WAIT_DAYS} days old; re-ran its check")
            n += 1
    if not n:
        print("audit: no held pull request is ready to re-run")


def _split_key(k):
    kind, rest = k.split(":", 1)
    name, _, version = rest.rpartition("@")
    return (kind, name, version)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--base")
    ap.add_argument("--head", help="PR mode: the pull request's head commit (its blobs are read, as pin-age-check does)")
    ap.add_argument("--fixtures")
    ap.add_argument("--now")
    ap.add_argument("--gh", default="gh")
    ap.add_argument("--exceptions")
    ap.add_argument("--rerun-held", action="store_true")
    ap.add_argument("--observations-out", help="write the cumulative tag observations (state.json) FIRST, before judging anything")
    ap.add_argument("--report-only", action="store_true", help="print findings and exit 1; never touch issues (the pull request job's token cannot write them)")
    a = ap.parse_args(argv)
    try:
        fx = None
        if a.fixtures:
            try:
                fx = json.load(open(a.fixtures))
            except (OSError, ValueError) as e:
                raise Fail(f"unreadable fixtures: {e}")
        now = age.parse_time(a.now) if a.now else dt.datetime.now(dt.timezone.utc)
        if now is None:
            raise Fail("--now is not an ISO time")
        gh = Gh(a.gh)
        net = FixtureNet(fx) if fx is not None else LiveNet(gh.cmd, a.root)
        if a.rerun_held:
            rerun_held(gh, net, now)
            return 0
        default_ex = os.path.join(a.root, ".github", "supply-chain-exceptions.json")
        exceptions = load_exceptions(a.exceptions or default_ex, bool(a.exceptions))
        try:
            head = inv.load_at(a.root, a.head if (a.base and a.head) else None)
            if a.base:
                audited = inv.moved(inv.load_at(a.root, a.base), head)
                hist = history_items(a.root, a.base, now) if audited else {}
                ran_keys = set(hist)
            else:
                hist = history_items(a.root, "HEAD", now)
                audited = [hist.get(k) or head[k] for k in sorted({**hist, **head})]
                ran_keys = {i.key for i in audited}
        except RuntimeError as e:
            raise Fail(str(e))
        # placeholders (a local action, a download source) have no advisories; their CHANGE is refused by the age check
        audited = [i for i in audited if i.version not in ("(local)", "(source)")]
        today = now.strftime("%Y-%m-%d")
        if a.observations_out and not a.base:
            state = tobs.update_state(net.observed(), net.tag_map([i for i in head.values()]), now.strftime("%Y-%m-%dT%H:%M:%SZ"))
            os.makedirs(os.path.dirname(os.path.abspath(a.observations_out)), exist_ok=True)
            with open(a.observations_out, "w") as f:
                json.dump(state, f, sort_keys=True)
            print(f"audit: recorded {len(state['first_seen'])} tag observation(s)")
        try:
            seen_um = {}
            for (path, what, _line), n in inv.unmeasured({**inv.tree_files(a.root, None), **inv.tree_scripts(a.root, None)}).items():
                seen_um[(path, what)] = seen_um.get((path, what), 0) + n
            for (path, what), n in sorted(seen_um.items()):
                print(f"information: not covered by this check: {what} in {clean(path)} ({n}x)")
        except RuntimeError:
            pass
        print(f"audit: inventory of {len(head)} item(s):")
        for k in sorted(head):
            print(f"  {clean(k)}")
        notes, findings, incomplete, log = [], [], False, RulingLog()
        held = list(audited)   # AC15: the pins the run inventories (main and its 90-day history); the pins of open pull requests are added below
        for it in audited:
            if it.kind == "action" and inv.SHA40.match(it.version) and not it.label and not isinstance(net, FixtureNet):
                if not age._tag_for_commit(it.name, it.version):
                    print(f"information: {it.name}@{it.version[:12]} has no version label or tag: its advisories could not be looked up")

        for it in audited:
            if not net.covered(it):
                print(f"information: not checked against the advisory lists (no source for this kind of item): {clean(it.key)}")

        def one(it):
            n2 = []
            return judge(it, net, exceptions, n2, current=a.base is not None or it.key in head, log=log), n2

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for fs, n2 in pool.map(one, audited):
                findings += fs
                notes += n2
        pr_actions = []
        if not a.base:  # daily: the pins of every OPEN pull request too (the PR job is read-only; this is how an unmerged hit reaches an issue)
            seen_keys = {i.key for i in audited}
            try:
                open_prs = net.open_pr_items()
            except (Fail, age.CouldNotLook) as e:
                print(f"information: the open pull requests were not audited: {clean(e)}")
                open_prs, incomplete = [], True
            if getattr(net, "incomplete_prs", None):
                incomplete = True
            for number, items in open_prs:
                pr_actions.extend(items)
                if len(items) > 100:
                    print(f"information: open pull request #{number} moves {len(items)} pins: only the first 100 were audited")
                    incomplete = True
                held.extend(items[:100])
                for it in items[:100]:
                    if it.key in seen_keys:
                        continue
                    seen_keys.add(it.key)
                    try:  # one pull request's failure (a rate limit, a bad response) must never hide main's own findings or other PRs'
                        for f in judge(it, net, exceptions, notes, current=True, log=log):
                            f.pr = number
                            findings.append(f)
                    except (Fail, age.CouldNotLook) as e:
                        print(f"information: a pin of open pull request #{number} could not be checked: {clean(e)}")
                        incomplete = True
        # actions and images INSIDE the actions we pin (depth 3): listed when on a moving tag, and checked against the same advisory lists
        seen = {it.key for it in audited} | set(head)
        queue = [(it, 0) for it in (audited if a.base else head.values()) if it.kind == "action"] + [(it, 0) for it in pr_actions if it.kind == "action"]
        while queue:
            def nested_safe(q):
                try:
                    return net.nested(q[0])
                except (Fail, age.CouldNotLook) as e:
                    print(f"information: the nested references of {clean(q[0].key)} could not be read: {clean(e)}")
                    return None
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                level = list(pool.map(nested_safe, queue))
            if any(x is None for x in level):
                incomplete = True
            level = [x or [] for x in level]
            nxt = []
            for (outer, depth), refs in zip(queue, level):
                for n in refs:
                    ref = n["ref"]
                    if not n.get("pinned"):
                        print(f"information: {outer.name} uses {clean(ref)}, not pinned to a digest (a moving tag; not a hit)")
                    m = re.match(r"^([\w.-]+/[\w.-]+)(?:/[^@\s]*)?@(\S+)$", ref)
                    if ref.startswith("docker://"):
                        print(f"information: not checked against the advisory lists (a nested image has no source): {clean(ref)} inside {outer.name}")
                        continue
                    if not m:
                        print(f"information: not checked (a nested reference this check cannot resolve: a local action or a Dockerfile): "
                              f"{clean(ref)} inside {outer.name}")
                        continue
                    child = inv.Item("action", m.group(1), m.group(2), "", (ref.split("@")[0].split("/", 2) + [""])[2])
                    if not inv.SHA40.match(child.version) and hasattr(net, "resolve_ref"):
                        try:
                            sha = net.resolve_ref(child.name, child.version)
                        except (Fail, age.CouldNotLook) as e:
                            print(f"information: a nested reference of {clean(outer.name)} could not be resolved: {clean(e)}")
                            incomplete = True
                            continue
                        if sha:
                            child = inv.Item("action", child.name, sha, child.version, child.path)  # the moving tag's CURRENT commit, labelled by the tag
                        else:
                            print(f"information: the moving tag {clean(ref)} inside {outer.name} could not be resolved to a commit; "
                                  "checked by its literal name")
                    if child.key in seen:
                        continue
                    seen.add(child.key)
                    print(f"audit: nested action {clean(child.name)}@{clean(child.version[:12])} inside {clean(outer.name)}")    # listed, clean or not
                    try:
                        for f in judge(child, net, exceptions, notes, current=True, log=log):
                            f.via = outer.name
                            findings.append(f)
                    except (Fail, age.CouldNotLook) as e:
                        print(f"information: a nested action of {clean(outer.name)} could not be checked: {clean(e)}")
                        incomplete = True
                    if depth + 1 < 3:
                        nxt.append((child, depth + 1))
                    else:
                        print(f"information: not looked into (nesting depth limit of 3): what {child.name} calls")
            queue = nxt
        for n in notes:
            print(f"audit: {clean(n)}")
        # AC15: the daily run over the checked-in file only
        lapsed, dead, dormant = ([], [], []) if (a.base or a.exceptions) else undecided_exceptions(exceptions, log, held, net)
        for e in lapsed:
            print(f"audit: LAPSED EXCEPTION: the ruling for {_ruling_label(e)} no longer matches the live advisory; write a fresh ruling")
        for e in dead:
            print(f"audit: DEAD EXCEPTION: {dead_message(e, held, net)}")
        for e in dormant:
            print(f"information: dormant exception: the ruling for {_ruling_label(e)} waits for its pin; nobody holds it")
        plan, disputes, per_item, pending = [], {}, {}, []
        for f in findings:
            print(f"audit: {'DISPUTED' if f.disputed else 'HIT'}: {clean(f.item.key)} ({clean(', '.join(f.ids))}): {f.why}"
                  + (f" [inside {clean(f.via)}]" if f.via else "") + (f" [open pull request #{f.pr}]" if getattr(f, "pr", None) else ""))
            if f.disputed:  # one issue per package and incident, listing every version of it (history can hold many)
                disputes.setdefault(package_of(f.item), []).append(f)
                continue
            if (f.item.key, f.via) in per_item:  # several incidents on one pinned item: one finding, every id
                g = per_item[(f.item.key, f.via)]
                g.ids = sorted(set(g.ids) | set(f.ids))
                g.why += "; " + f.why
                continue
            per_item[(f.item.key, f.via)] = f
            rb = None if f.via else rollback(f.item, net, now)
            ran = f.item.key in ran_keys
            owner = rb is None or rb == UNKNOWN or ran or bool(f.via)
            pending.append((f, rb, ran, owner))
        by_prefix = {}
        for f, rb, ran, owner in pending:
            t = title_of(f)
            if t[0] in by_prefix:        # same identity (e.g. two commits both labelled v4): one issue carrying both
                e = by_prefix[t[0]]
                e["body"] += "\n---\nAlso, at commit `%s`:\n\n%s" % (_safe(f.item.version, 80), body_of(f, rb, owner, ran, today))
                e["owner"] = e["owner"] or owner
                e["ids"] = sorted(set(e["ids"]) | set(f.ids))
                e["title"] = (t[0], "%s (%s)" % (t[0], ", ".join(_safe(i) for i in e["ids"])))
                continue
            e = {"finding": f, "title": t, "body": body_of(f, rb, owner, ran, today), "owner": owner, "ids": list(f.ids)}
            by_prefix[t[0]] = e
            plan.append(e)
        for pkg, fs in sorted(disputes.items()):
            versions = sorted({x.item.label or x.item.version for x in fs})
            first = fs[0]
            first.ids = sorted({i for x in fs for i in x.ids})                              # EVERY incident of the package in one issue
            first.why = "; ".join(sorted({x.why for x in fs}))[:1500]
            first.item = inv.Item(first.item.kind, first.item.name, first.item.version, ", ".join(versions))
            plan.append({"finding": first, "title": (f"supply-chain: disputed {_safe(pkg)}",
                f"supply-chain: disputed {_safe(pkg)} ({', '.join(_safe(i) for i in first.ids)})"),
                         "body": body_of(first, None, False, False, today), "owner": False})
        if plan:
            if not a.report_only:
                file_issues(gh, plan, today)
            return 1
        unchecked = [i for i in audited if not net.covered(i)]
        excepted_n = len([n for n in notes if not n.startswith(IGNORED_NOTE)])   # AC14: the log lines of ignored entries are not exceptions
        if incomplete:
            print("audit: INCOMPLETE: some open pull request pins could not be checked (above): no clean claim is made today", file=sys.stderr)
            return 1
        if lapsed or dead:
            return 1
        print(f"audit: no known-compromised versions as of {today}"
              + (f" ({excepted_n} disputed hit(s) covered by a checked-in exception)" if excepted_n else "")
              + (f"; {len(dormant)} dormant exception ruling(s) wait for their pin: {', '.join(_ruling_label(e) for e in dormant)}" if dormant else "")
              + (f"; {len(unchecked)} of {len(audited)} item(s) have no advisory source and were not checked (listed above)" if unchecked else ""))
        return 0
    except (Fail, age.CouldNotLook) as e:
        print(f"audit: cannot do its job: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
