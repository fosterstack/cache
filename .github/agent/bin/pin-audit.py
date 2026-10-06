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


def _vt(v):
    """(release numbers without trailing zeros, class, suffix parts): class 0 = pre-release (before the final), 1 = final, 2 = post-release.
    1.0.0-rc.1 and 1.0.0rc1 are BEFORE 1.0.0; 1.0.post1 is AFTER 1.0; 1.2 equals 1.2.0. A suffix of any other kind raises ValueError (callers read it as affected)."""
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


def covered_by_events(version, events):
    try:
        return _covered_by_events(version, events)
    except ValueError:
        return True  # a version this check cannot order is never read as unaffected


def _covered_by_events(version, events):
    """OSV range events: introduced / fixed / last_affected, in order."""
    state = False
    for e in events:
        if "introduced" in e:
            if e["introduced"] == "0" or _cmp(version, e["introduced"]) >= 0:
                state = True
        elif "fixed" in e:
            if _cmp(version, e["fixed"]) >= 0:
                state = False
        elif "last_affected" in e:
            if _cmp(version, e["last_affected"]) > 0:
                state = False
    return state


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
            "osv": "github.com/google/osv-scanner", "gitsign": "github.com/sigstore/gitsign", "golangci-lint": "github.com/golangci/golangci-lint",
            "goreleaser": "github.com/goreleaser/goreleaser", "scout": "github.com/docker/scout-cli", "cosign": "github.com/sigstore/cosign",
            "kind": "sigs.k8s.io/kind", "helm": "helm.sh/helm/v3"}
NPM_TOOLS = {"snyk": "snyk"}


class LiveNet:
    def __init__(self, gh, root):
        self.gh, self.root = gh, root
        self._memo, self._lock = {}, threading.Lock()

    def _gh_json(self, path, strict=False):
        """JSON from gh api. A 404 is None; with strict=True nothing else may be None either (a 422 or bad JSON is not 'absent')."""
        with self._lock:
            if (path, strict) in self._memo:
                return self._memo[(path, strict)]
        r = subprocess.run([*self.gh, "api", path], capture_output=True, text=True)
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

    def versions_of(self, item):
        """Every version-like tag at an action's commit (an exception must clear them ALL), else the single version."""
        if item.kind == "action" and inv.SHA40.match(item.version):
            return [t for t in age._tags_for_commit(item.name, item.version) if re.match(r"^v?\d", t)][:40]
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
            mod = age._go_module(item.name, item.version)[0]  # the module root, resolved through the proxy; unresolved: not covered (never the raw command path)
        elif item.kind == "tool":
            mod = GO_TOOLS.get(item.name) or (f"github.com/{item.name}" if re.fullmatch(r"[\w.-]+/[\w.-]+", item.name) else None)
        return {"package": {"name": mod, "ecosystem": "Go"}, "version": version} if mod else None

    def live_ranges(self, item, source, advisory_id):
        """The authoritative advisory's affected ranges for this package, read live (GitHub only: the rulings so far name GitHub)."""
        if str(source).lower() != "github":
            return None
        adv = self._gh_json(f"advisories/{advisory_id}", strict=True)
        q = self._query(item, self._version_of(item) or "")
        names = {package_of(item).lower(), item.name.lower()} | ({q["package"]["name"].lower()} if q else set())
        rngs = [x["vulnerable_version_range"] for x in (adv or {}).get("vulnerabilities", []) if x.get("vulnerable_version_range") and (x.get("package") or {}).get("name", "").lower() in names]
        return rngs or None

    def covered(self, item):
        """Is there an advisory source for this kind of item at all? (None-query items are reported as not checked, never as clean.)"""
        v = self._version_of(item)
        return bool(v) and self._query(item, v) is not None

    def lists(self, item):
        if item.kind == "action" and inv.SHA40.match(item.version):  # EVERY version-like tag at the commit: one tag must not hide another's advisory
            tags = [t for t in age._tags_for_commit(item.name, item.version) if re.match(r"^v?\d", t)][:40]
            if len(tags) > 1:
                gh_all, osv_all = [], []
                for t in tags:
                    g, o = self._lists_for(item, t)
                    gh_all += [x for x in g if x not in gh_all]
                    osv_all += [x for x in o if x not in osv_all]
                return gh_all, osv_all
        return self._lists_for(item, self._version_of(item))

    def _lists_for(self, item, version):
        q = self._query(item, version) if version else None
        if q is None or not version:
            return [], []
        osv, ghs = [], []
        for v in self._osv_post(q):
            says = self._osv_says(v, q["package"]["name"], version, versioned="version" in q)
            osv.append({"id": v["id"], "incident": v["id"], "affected": says, "modified": v.get("modified"), "malicious": v["id"].startswith("MAL-")})
            for alias in [v["id"], *v.get("aliases", [])]:  # an OSV record can itself be the GitHub advisory (GHSA-... primary id)
                if alias.startswith("GHSA-"):
                    adv = self._gh_json(f"advisories/{alias}", strict=True)
                    names = {q["package"]["name"].lower(), item.name.lower()}
                    rngs = [x["vulnerable_version_range"] for x in (adv or {}).get("vulnerabilities", [])
                            if x.get("vulnerable_version_range") and (x.get("package") or {}).get("name", "").lower() in names]
                    if adv and rngs:
                        ghs.append({"id": alias, "incident": v["id"], "affected": in_range(version, "|".join(rngs)), "modified": adv.get("updated_at")})
        eco = {"actions": "actions", "PyPI": "pip", "Go": "go", "npm": "npm"}.get(q["package"]["ecosystem"].replace("GitHub Actions", "actions"))
        pkg = q["package"]["name"]
        if eco:
            seen = {g["id"] for g in ghs}
            page = []
            for typ in ("", "&type=malware"):
                for n in range(1, 11):
                    got = self._gh_json(f"advisories?ecosystem={eco}&affects={urllib.parse.quote(pkg)}{typ}&per_page=100&page={n}", strict=True)
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
                        if x.get("vulnerable_version_range") and (x.get("package") or {}).get("name", "").lower() == pkg.lower()]
                if rngs and in_range(version, "|".join(rngs)):
                    ghs.append({"id": adv["ghsa_id"], "incident": adv["ghsa_id"], "affected": True, "modified": adv.get("updated_at"), "malicious": adv.get("type") == "malware"})
                    rec = self._osv_get(adv["ghsa_id"])
                    if rec and rec.get("id"):  # OSV knows this incident too: its own verdict for this version decides whether the lists AGREE
                        osv.append({"id": rec["id"], "incident": adv["ghsa_id"], "affected": self._osv_says(rec, pkg, version, versioned=False),
                                    "modified": rec.get("modified"), "malicious": rec["id"].startswith("MAL-")})
        return ghs, osv

    @staticmethod
    def _osv_says(v, name, version, versioned):
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
                    if covered_by_events(version, rg.get("events", [])):
                        return True
        if not versioned and any(rg.get("type") == "GIT" for a in entries for rg in a.get("ranges", [])):
            return True  # a commit range cannot be judged by version: unresolved is never "not affected", whatever the other ranges say
        return versioned and not judged  # a versioned query already filtered by version; with no ranges to read, trust it

    def upstream(self, item):
        if item.kind != "action" or not inv.SHA40.match(item.version):
            return None  # only a commit pin can be "not from the action's own repo"
        r = subprocess.run([*self.gh, "api", f"repos/{item.name}", "--jq", ".default_branch"], capture_output=True, text=True)
        self._api_ok(r, item)
        branch = r.stdout.strip()
        if r.returncode or not branch:
            return False
        c = subprocess.run([*self.gh, "api", f"repos/{item.name}/compare/{item.version}...{branch}", "--jq", ".status"], capture_output=True, text=True)
        self._api_ok(c, item)
        # compare/<pin>...<branch>: the branch is "ahead" of (or identical to) the pin exactly when the pin is an ancestor of the branch
        if c.stdout.strip() in ("identical", "ahead"):
            return True
        if age._tag_for_commit(item.name, item.version) is not None:
            return True
        for br in (self._gh_json(f"repos/{item.name}/branches?per_page=100") or []):  # a release branch of the same repository
            if br.get("name") != branch:
                c = subprocess.run([*self.gh, "api", f"repos/{item.name}/compare/{item.version}...{br['name']}", "--jq", ".status"], capture_output=True, text=True)
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
            cand = inv.Item(item.kind, item.name, sha, r["tag_name"]) if (item.kind == "action" and sha) else inv.Item(item.kind, item.name, r["tag_name"], r["tag_name"])
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
            hdr = ["-c", "http.https://github.com/.extraheader=AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode()] if tok else []
            f = subprocess.run(["git", "-C", self.root, *hdr, "fetch", "-q", "origin", f"pull/{p['number']}/head", p["base"]["ref"]], capture_output=True, text=True)
            if f.returncode:
                continue
            try:
                mb = subprocess.run(["git", "-C", self.root, "merge-base", f"origin/{p['base']['ref']}", p["head"]["sha"]], capture_output=True, text=True).stdout.strip()
                items = inv.moved(inv.load_at(self.root, mb), inv.load_at(self.root, p["head"]["sha"])) if mb else []
            except RuntimeError as e:
                print(f"information: open pull request #{p['number']} was not audited: {clean(e)}")
                continue
            out.append((p["number"], items))
        return out

    def prs(self):
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise Fail("GITHUB_REPOSITORY is not set")
        r = subprocess.run([*self.gh, "pr", "list", "--state", "open", "--json", "number,title,headRefOid,baseRefName", "--limit", "1000"], capture_output=True, text=True)
        if r.returncode:
            raise Fail("could not list open pull requests: " + r.stderr.strip())
        out = []
        for p in json.loads(r.stdout or "[]"):
            tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            hdr = ["-c", "http.https://github.com/.extraheader=AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode()] if tok else []
            f = subprocess.run(["git", "-C", self.root, *hdr, "fetch", "-q", "origin", f"pull/{p['number']}/head", f"{p['baseRefName']}"], capture_output=True, text=True)
            if f.returncode:
                continue
            try:
                head = subprocess.run(["git", "-C", self.root, "rev-parse", "FETCH_HEAD"], capture_output=True, text=True).stdout.strip()
                mb = subprocess.run(["git", "-C", self.root, "merge-base", f"origin/{p['baseRefName']}", p["headRefOid"]], capture_output=True, text=True).stdout.strip()
                moved = inv.moved(inv.load_at(self.root, mb), inv.load_at(self.root, p["headRefOid"])) if mb else []
            except RuntimeError:
                continue
            runs = self._gh_json(f"repos/{repo}/actions/runs?head_sha={p['headRefOid']}&event=pull_request&per_page=100") or {}
            mine = sorted((x for x in runs.get("workflow_runs", []) if x.get("path") == ".github/workflows/supply-chain.yml"), key=lambda x: x.get("created_at", ""), reverse=True)
            failed = mine[:1] if mine and mine[0].get("conclusion") == "failure" else []  # the NEWEST run decides: a later green run needs no re-run
            if moved and failed:
                out.append({"number": p["number"], "title": p["title"], "run_id": failed[0]["id"], "moved": [m.key for m in moved], "_items": moved, "_base": mb, "_head": p["headRefOid"]})
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
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as e:
        raise Fail(f"the exceptions file {path} is unreadable or malformed: {e}")
    return ex


def package_of(item):
    return item.name.split("/", 1)[1] if item.kind == "package" else item.name


def version_of(item):
    """The version to hold against an advisory's ranges: a tag-like label for a commit pin, else the version itself."""
    return (item.label or None) if inv.SHA40.match(item.version) else item.version


def _norm_ranges(rs):
    return {re.sub(r"\s+", "", r) for r in rs}


def excepted(item, dispute_ids, current, exceptions, net=None, osv_times=None):
    """The advisor's ruling for ONE incident and package: names exactly the advisories of this dispute, each unchanged since it was written.
    Returns None (no ruling: still disputed), "pass" (the version is outside the authoritative source's affected ranges) or "hit" (inside them:
    an exception never covers a version the authoritative source lists as affected)."""
    vers = (net.versions_of(item) if net is not None and hasattr(net, "versions_of") else None) or [net.version_of(item) if net is not None and hasattr(net, "version_of") else version_of(item)]
    vers = [v for v in vers if v]
    ver = vers[0] if vers else None
    for e in exceptions:
        if e["package"] != package_of(item) or set(e["ids"]) != set(dispute_ids):
            continue
        if not all(e["modified"].get(i) and current.get(i) is not None and current.get(i) == e["modified"][i] for i in e["ids"]):
            continue  # an advisory changed since the ruling (or its time was never recorded): the ruling has lapsed
        # an id that BOTH databases hold has two records: this entry must also have recorded OSV's own time for it, unchanged
        if any(t is None or e.get("osv_modified", {}).get(i) != t for i, t in (osv_times or {}).items() if i in e["ids"]):
            continue  # unknown is not unchanged: a missing time refuses
        if not ver:
            return None  # no version to compare with the ranges: stays disputed
        # the ruling verifies itself (advisor 0182): its copied ranges must equal the authoritative advisory's LIVE ranges, or a wrong entry could hide a hit
        au = e["authoritative"]
        live = net.live_ranges(item, au["source"], au["id"]) if net is not None else None
        if not live or _norm_ranges(live) != _norm_ranges(au["ranges"]):
            return None
        return "hit" if any(in_range(v, "|".join(e["authoritative"]["ranges"])) for v in vers) else "pass"   # ANY tag of the commit inside the ranges: affected
    return None


# ---------- judging ----------
class Finding:
    def __init__(self, item, kind, ids, why, disputed=False):
        self.item, self.kind, self.ids, self.why, self.disputed = item, kind, sorted(set(ids)), why, disputed
        self.via = None  # the pinned action that calls this one
        self.pr = None   # the open pull request this pin was found in (not merged yet)


def judge(item, net, exceptions, notes, current=True):
    findings = _judge(item, net, exceptions, notes, current)
    if (item.kind == "action" and inv.SHA40.match(item.version) and hasattr(net, "version_of") and net.version_of(item) is None and isinstance(net, LiveNet)):
        findings.append(Finding(item, "unresolved", ["unresolved"], "no tag of the action's repository points at the pinned commit, so its advisories cannot be matched to a version (the # label is not evidence)"))
    return findings


def _judge(item, net, exceptions, notes, current=True):
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
            ruling = excepted(item, set(ids), cur, exceptions, net, osv_times)
            if ruling == "pass":
                notes.append(f"exception applied: {package_of(item)} {item.version} ({', '.join(sorted(set(ids)))}) is outside the authoritative source's affected ranges")
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
        findings.append(Finding(item, "unreachable", ["not-upstream"], "the pinned commit is not reachable from a branch or tag of the action's own repository (a fork-only commit)"))
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
    for pub, v in sorted(eligible, key=lambda x: x[0], reverse=True):  # newest first; the lists of a candidate are fetched only when it is reached
        lists = v.get("lists")
        if lists is None:
            gh_l, osv_l = net.lists(v["_item"])
            lists = {"github": gh_l, "osv": osv_l}
        if any_affected(lists):
            continue
        cand = v.get("_item")
        if cand is not None and net.proofs(cand) is not None and not age.judge_item(cand, net.proofs(cand), now)[0]:
            continue  # the candidate commit must itself be provably old enough (a tag moved under an old release is not an old version)
        return v
    return None


def clean(text):
    """Untrusted text (a PR title, a ref read from someone's action.yml) is printed without control characters: no log-command injection."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", inv._hide(str(text)))[:200]  # control characters out, and an expression (a secret's name) never printed


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
    lines = [f"# {title_of(f)[1]}", "", f"Checked {today}. Pinned: `{it.kind}:{_safe(package_of(it))}@{_safe(it.version, 80)}`" + (f" ({ver})" if it.label else "") + ".", "",
             f"Finding: {f.why}.", f"Advisories: {', '.join(_safe(i) for i in f.ids)}.", ""]
    if f.disputed:
        lines += ["This is a DISPUTED hit, for the advisor to rule on. Nothing was rolled back and nothing was reported clean.",
                  "A ruling goes in `.github/supply-chain-exceptions.json` (advisory ids, package, version, evidence links, date, each advisory's last-modified time); it lapses when either advisory changes."]
        return "\n".join(lines) + "\n"
    if f.via:
        lines.append(f"This action is called inside `{_safe(f.via)}`: replace or drop the outer action. Nothing here can be pinned by us.")
        lines.append("There is no rollback of ours to a clean version of a nested action: the owner decides.")
        return "\n".join(lines) + "\n"
    if rb == UNKNOWN:
        lines.append("Rollback: this kind of item cannot be searched for older versions automatically; nobody has looked for a clean one, so the owner decides.")
    elif rb:
        lines.append(f"Rollback: pin the newest clean version public at least {WAIT_DAYS} days: {_safe(rb['version'])}" + (f" (commit {_safe(rb['sha'])})" if rb.get("sha") else "") + f", published {_safe(rb['published'])}.")
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
    paths = [".github", "bin/install-scanner.sh", ":(glob)**/*requirements*.txt"]
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
        r = subprocess.run([*self.cmd, *args], capture_output=True, text=True)
        if r.returncode and not ok_fail:
            raise Fail(f"gh {' '.join(args[:2])} failed: {r.stderr.strip()[:200]}")
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
    for p in plan:
        prefix, title = p["title"]
        if title in done or prefix in done:
            continue
        done.add(title); done.add(prefix)
        existing = next((i for i in open_issues if i.get("number", -1) > 0 and (str(i.get("title", "")) == title or str(i.get("title", "")).startswith(prefix + " ("))), None)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(p["body"])
            path = f.name
        try:
            labels = ["--label", HIT_LABEL] + (["--label", OWNER_LABEL] if p["owner"] else [])
            if existing:
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
        items = pr.get("_items") or [inv.Item(*_split_key(k)) for k in pr["moved"]]
        rows = [age.judge_item(it, net.proofs(it, pr.get("_base"), pr.get("_head", "HEAD")), now) for it in items]
        if rows and all(r[0] for r in rows):
            gh.run("run", "rerun", str(pr["run_id"]))
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
        notes, findings = [], []
        for it in audited:
            if it.kind == "action" and inv.SHA40.match(it.version) and not it.label and not isinstance(net, FixtureNet):
                if not age._tag_for_commit(it.name, it.version):
                    print(f"information: {it.name}@{it.version[:12]} has no version label or tag: its advisories could not be looked up")

        for it in audited:
            if not net.covered(it):
                print(f"information: not checked against the advisory lists (no source for this kind of item): {clean(it.key)}")

        def one(it):
            n2 = []
            return judge(it, net, exceptions, n2, current=a.base is not None or it.key in head), n2

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for fs, n2 in pool.map(one, audited):
                findings += fs
                notes += n2
        if not a.base:  # daily: the pins of every OPEN pull request too (the PR job is read-only; this is how an unmerged hit reaches an issue)
            seen_keys = {i.key for i in audited}
            try:
                open_prs = net.open_pr_items()
            except (Fail, age.CouldNotLook) as e:
                print(f"information: the open pull requests were not audited: {clean(e)}")
                open_prs = []
            for number, items in open_prs:
                if len(items) > 100:
                    print(f"information: open pull request #{number} moves {len(items)} pins: only the first 100 were audited")
                for it in items[:100]:
                    if it.key in seen_keys:
                        continue
                    seen_keys.add(it.key)
                    try:  # one pull request's failure (a rate limit, a bad response) must never hide main's own findings or other PRs'
                        for f in judge(it, net, exceptions, notes, current=True):
                            f.pr = number
                            findings.append(f)
                    except (Fail, age.CouldNotLook) as e:
                        print(f"information: a pin of open pull request #{number} could not be checked: {clean(e)}")
        # actions and images INSIDE the actions we pin (depth 3): listed when on a moving tag, and checked against the same advisory lists
        seen = {it.key for it in audited} | set(head)
        queue = [(it, 0) for it in (audited if a.base else head.values()) if it.kind == "action"]
        while queue:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                level = list(pool.map(lambda q: net.nested(q[0]), queue))
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
                        print(f"information: not checked (a nested reference this check cannot resolve: a local action or a Dockerfile): {clean(ref)} inside {outer.name}")
                        continue
                    child = inv.Item("action", m.group(1), m.group(2), "", (ref.split("@")[0].split("/", 2) + [""])[2])
                    if not inv.SHA40.match(child.version) and hasattr(net, "resolve_ref"):
                        sha = net.resolve_ref(child.name, child.version)
                        if sha:
                            child = inv.Item("action", child.name, sha, child.version, child.path)  # the moving tag's CURRENT commit, labelled by the tag
                        else:
                            print(f"information: the moving tag {clean(ref)} inside {outer.name} could not be resolved to a commit; checked by its literal name")
                    if child.key in seen:
                        continue
                    seen.add(child.key)
                    for f in judge(child, net, exceptions, notes, current=True):
                        f.via = outer.name
                        findings.append(f)
                    if depth + 1 < 3:
                        nxt.append((child, depth + 1))
                    else:
                        print(f"information: not looked into (nesting depth limit of 3): what {child.name} calls")
            queue = nxt
        for n in notes:
            print(f"audit: {n}")
        plan, disputes, per_item, pending = [], {}, {}, []
        for f in findings:
            print(f"audit: {'DISPUTED' if f.disputed else 'HIT'}: {clean(f.item.key)} ({clean(', '.join(f.ids))}): {f.why}" + (f" [inside {clean(f.via)}]" if f.via else "") + (f" [open pull request #{f.pr}]" if getattr(f, "pr", None) else ""))
            if f.disputed:  # one issue per package and incident, listing every version of it (history can hold many)
                disputes.setdefault((package_of(f.item), tuple(f.ids)), []).append(f)
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
        for f, rb, ran, owner in pending:
            plan.append({"finding": f, "title": title_of(f), "body": body_of(f, rb, owner, ran, today), "owner": owner})
        for (pkg, ids), fs in sorted(disputes.items()):
            versions = sorted({x.item.label or x.item.version for x in fs})
            first = fs[0]
            first.item = inv.Item(first.item.kind, first.item.name, first.item.version, ", ".join(versions))
            plan.append({"finding": first, "title": (f"supply-chain: disputed {pkg}", f"supply-chain: disputed {pkg} ({', '.join(ids)})"),
                         "body": body_of(first, None, False, False, today), "owner": False})
        if plan:
            if not a.report_only:
                file_issues(gh, plan, today)
            return 1
        unchecked = [i for i in audited if not net.covered(i)]
        print(f"audit: no known-compromised versions as of {today}" + (f" ({len(notes)} disputed hit(s) covered by a checked-in exception)" if notes else "")
              + (f"; {len(unchecked)} of {len(audited)} item(s) have no advisory source and were not checked (listed above)" if unchecked else ""))
        return 0
    except (Fail, age.CouldNotLook) as e:
        print(f"audit: cannot do its job: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
