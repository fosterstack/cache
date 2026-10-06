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


class Fail(Exception):
    """The audit could not do its job (exit 2)."""


# ---------- versions and ranges (OSV events, GitHub's comma-separated comparators) ----------
def _vt(v):
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-+]", str(v).lstrip("vV")) if p != ""]


def _cmp(a, b):
    x, y = _vt(a), _vt(b)
    return (x > y) - (x < y)


def covered_by_events(version, events):
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
    """GitHub vulnerable_version_range: '>= 1.0, < 2.0' or '= 0.69.4'; several ranges may be joined by '|'."""
    for alt in str(rng).split("|"):
        ok = True
        for part in alt.split(","):
            m = re.match(r"^\s*(<=|>=|<|>|=)\s*(\S+)\s*$", part)
            if not m:
                ok = False
                break
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

    def upstream(self, item):
        return ((self.fx.get("upstream") or {}).get(f"{item.name}@{item.version}") or {}).get("reachable")

    def nested(self, item):
        return (self.fx.get("nested") or {}).get(f"{item.name}@{item.version}") or []

    def versions(self, item):
        return (self.fx.get("versions") or {}).get(item.name) or []

    def prs(self):
        return self.fx.get("prs") or []

    def proofs(self, item):
        return age.Fixture(self.fx).proofs(item)

    def modified(self, advisory_id):
        return None


GO_TOOLS = {"trivy": "github.com/aquasecurity/trivy", "grype": "github.com/anchore/grype", "syft": "github.com/anchore/syft",
            "osv": "github.com/google/osv-scanner", "gitsign": "github.com/sigstore/gitsign", "golangci-lint": "github.com/golangci/golangci-lint"}


class LiveNet:
    def __init__(self, gh, root):
        self.gh, self.root = gh, root
        self._memo, self._lock = {}, threading.Lock()

    def _gh_json(self, path):
        with self._lock:
            if path in self._memo:
                return self._memo[path]
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
        with self._lock:
            self._memo[path] = val
        return val

    def _osv_post(self, q):
        req = urllib.request.Request("https://api.osv.dev/v1/query", json.dumps(q).encode(), {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r).get("vulns", [])
        except (OSError, ValueError) as e:
            raise Fail(f"the OSV query failed: {e}")

    def _version_of(self, item):
        if item.kind == "action" and inv.SHA40.match(item.version):
            return item.label or age._tag_for_commit(item.name, item.version)
        return item.version  # a tag/branch ref, or a tool/package version

    def _query(self, item, version):
        if item.kind == "action":
            return {"package": {"name": item.name, "ecosystem": "GitHub Actions"}}
        if item.kind == "package":
            return {"package": {"name": item.name.split("/", 1)[1], "ecosystem": "PyPI"}, "version": version}
        mod = item.name if item.kind == "gotool" else GO_TOOLS.get(item.name)
        if item.kind == "gotool":
            mod = age._go_module(item.name, item.version)[0] or item.name
        return {"package": {"name": mod, "ecosystem": "Go"}, "version": version} if mod else None

    def lists(self, item):
        version = self._version_of(item)
        q = self._query(item, version) if version else None
        if q is None or not version:
            return [], []
        osv, ghs = [], []
        for v in self._osv_post(q):
            says = self._osv_says(v, q["package"]["name"], version, versioned="version" in q)
            osv.append({"id": v["id"], "incident": v["id"], "affected": says, "modified": v.get("modified"), "malicious": v["id"].startswith("MAL-")})
            for alias in [v["id"], *v.get("aliases", [])]:  # an OSV record can itself be the GitHub advisory (GHSA-... primary id)
                if alias.startswith("GHSA-"):
                    adv = self._gh_json(f"advisories/{alias}")
                    names = {q["package"]["name"].lower(), item.name.lower()}
                    rngs = [x["vulnerable_version_range"] for x in (adv or {}).get("vulnerabilities", [])
                            if x.get("vulnerable_version_range") and (x.get("package") or {}).get("name", "").lower() in names]
                    if adv and rngs:
                        ghs.append({"id": alias, "incident": v["id"], "affected": in_range(version, "|".join(rngs)), "modified": adv.get("updated_at")})
        return ghs, osv

    @staticmethod
    def _osv_says(v, name, version, versioned):
        """Does OSV's record cover this version? Each affected entry's ranges are judged separately and OR-ed (never one merged event list)."""
        entries = [a for a in v.get("affected", []) if (a.get("package") or {}).get("name", "").lower() == name.lower()] or v.get("affected", [])
        judged = False
        for a in entries:
            if version in (a.get("versions") or []):
                return True
            for rg in a.get("ranges", []):
                if rg.get("type") in ("SEMVER", "ECOSYSTEM"):
                    judged = True
                    if covered_by_events(version, rg.get("events", [])):
                        return True
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
        if c.stdout.strip() in ("identical", "behind"):
            return True
        return age._tag_for_commit(item.name, item.version) is not None

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
            c = self._gh_json(f"repos/{item.name}/contents/{name}?ref={item.version}")
            if c and c.get("content"):
                try:
                    doc = inv.yaml.load(base64.b64decode(c["content"]).decode(), Loader=inv.yaml.BaseLoader) or {}
                except inv.yaml.YAMLError:
                    break
                runs = doc.get("runs") or {}
                refs = [st.get("uses") for st in (runs.get("steps") or []) if isinstance(st, dict) and isinstance(st.get("uses"), str)]
                if isinstance(runs.get("image"), str) and runs["image"].startswith("docker://"):
                    refs.append(runs["image"])
                for ref in refs:
                    if not ref.startswith("./"):
                        out.append({"ref": ref, "pinned": bool(re.search(r"@[0-9a-f]{40}$|@sha256:[0-9a-f]{64}$", ref))})
                break
        return out

    def versions(self, item):
        repo = item.name if item.kind == "action" else age.TOOL_REPOS.get(item.name)
        if not repo:
            return []
        rels = self._gh_json(f"repos/{repo}/releases?per_page=30") or []
        out = []
        for r in rels:
            if r.get("draft") or r.get("prerelease") or not r.get("published_at"):
                continue
            cand = inv.Item(item.kind, item.name, r["tag_name"], r["tag_name"])
            sha = None
            if item.kind == "action":
                ref = self._gh_json(f"repos/{repo}/git/ref/tags/{urllib.parse.quote(r['tag_name'])}")
                if ref and ref.get("object", {}).get("type") == "commit":
                    sha = ref["object"]["sha"]
                elif ref and ref.get("object", {}).get("type") == "tag":
                    t = self._gh_json(f"repos/{repo}/git/tags/{ref['object']['sha']}")
                    sha = (t or {}).get("object", {}).get("sha")
            gh_l, osv_l = self.lists(cand) if item.kind != "action" else self.lists(cand)
            out.append({"version": r["tag_name"], "sha": sha, "published": r["published_at"], "lists": {"github": gh_l, "osv": osv_l}})
        return out

    def prs(self):
        repo = os.environ.get("GITHUB_REPOSITORY")
        if not repo:
            raise Fail("GITHUB_REPOSITORY is not set")
        r = subprocess.run([*self.gh, "pr", "list", "--state", "open", "--json", "number,title,headRefOid,baseRefName", "--limit", "100"], capture_output=True, text=True)
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
            runs = self._gh_json(f"repos/{repo}/actions/runs?head_sha={p['headRefOid']}&event=pull_request&per_page=30") or {}
            failed = [x for x in runs.get("workflow_runs", []) if x.get("name") == "supply-chain" and x.get("conclusion") == "failure"]
            if moved and failed:
                out.append({"number": p["number"], "title": p["title"], "run_id": failed[0]["id"], "moved": [m.key for m in moved], "_items": moved})
        return out

    def proofs(self, item):
        return age.live_proofs(item, self.root)

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
            assert isinstance(e["modified"], dict) and e["package"] and e["authoritative"] in ("github", "osv")
            assert isinstance(e["ranges"], list) and e["ranges"] and all(isinstance(r, str) for r in e["ranges"])
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as e:
        raise Fail(f"the exceptions file {path} is unreadable or malformed: {e}")
    return ex


def package_of(item):
    return item.name.split("/", 1)[1] if item.kind == "package" else item.name


def version_of(item):
    """The version to hold against an advisory's ranges: a tag-like label for a commit pin, else the version itself."""
    return (item.label or None) if inv.SHA40.match(item.version) else item.version


def excepted(item, dispute_ids, current, exceptions):
    """The advisor's ruling for ONE incident and package: names exactly the advisories of this dispute, each unchanged since it was written.
    Returns None (no ruling: still disputed), "pass" (the version is outside the authoritative source's affected ranges) or "hit" (inside them:
    an exception never covers a version the authoritative source lists as affected)."""
    ver = version_of(item)
    for e in exceptions:
        if e["package"] != package_of(item) or set(e["ids"]) != set(dispute_ids):
            continue
        if not all(e["modified"].get(i) and current.get(i) == e["modified"][i] for i in e["ids"]):
            continue  # an advisory changed since the ruling (or its time was never recorded): the ruling has lapsed
        if not ver:
            return None  # no version to compare with the ranges: stays disputed
        return "hit" if in_range(ver, "|".join(e["ranges"])) else "pass"
    return None


# ---------- judging ----------
class Finding:
    def __init__(self, item, kind, ids, why, disputed=False):
        self.item, self.kind, self.ids, self.why, self.disputed = item, kind, sorted(set(ids)), why, disputed
        self.via = None  # the pinned action that calls this one


def judge(item, net, exceptions, notes, current=True):
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
            for x in advs:  # GitHub's time for a GHSA id, OSV's otherwise: the ops file's rule
                if x["id"] not in cur or (x["id"].startswith("GHSA-") and x in gh_l):
                    cur[x["id"]] = x.get("modified")
            ruling = excepted(item, set(ids), cur, exceptions)
            if ruling == "pass":
                notes.append(f"exception applied: {package_of(item)} {item.version} ({', '.join(sorted(set(ids)))}) is outside the authoritative source's affected ranges")
                continue
            if ruling == "hit":
                findings.append(Finding(item, "advisory", ids, "the authoritative source for this incident lists this version as affected"))
                continue
            findings.append(Finding(item, "disputed", ids, "the two advisory lists disagree about this incident: "
                                    + "; ".join(f"{a['id']} says {'affected' if a.get('affected') else 'not affected'}" for a in advs), True))
        elif yes:
            mal = any(a.get("malicious") for a in yes)
            findings.append(Finding(item, "malicious" if mal else "advisory", [a["id"] for a in yes],
                                    "a malicious-package report covers this version" if mal else "an advisory covers this version"))
    reach = net.upstream(item) if current else None  # only today's pins are checked upstream (history items: advisories only)
    if item.kind == "action" and reach is False:
        findings.append(Finding(item, "unreachable", ["not-upstream"], "the pinned commit is not reachable from a branch or tag of the action's own repository (a fork-only commit)"))
    return findings


def undisputed_affected(entry_lists):
    advs = list(entry_lists.get("github") or []) + list(entry_lists.get("osv") or [])
    by = {}
    for a in advs:
        by.setdefault(a.get("incident") or a["id"], []).append(a)
    return any(any(a.get("affected") for a in v) and all(a.get("affected") for a in v) for v in by.values())


def rollback(item, net, now):
    """The newest clean version public at least 7 days; never a younger one. None: drop it."""
    best = None
    for v in net.versions(item):
        pub = age.parse_time(v.get("published"))
        if pub is None or (now - pub).total_seconds() < WAIT_DAYS * 86400 or v["version"] == (item.label or item.version) or v.get("sha") == item.version:
            continue
        if undisputed_affected(v.get("lists") or {}):
            continue
        if best is None or pub > best[0]:
            best = (pub, v)
    return best[1] if best else None


def clean(text):
    """Untrusted text (a PR title, a ref read from someone's action.yml) is printed without control characters: no log-command injection."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(text))[:200]


def title_of(f):
    it = f.item
    ver = it.label or it.version[:12]
    return f"supply-chain: {'disputed ' if f.disputed else ''}{package_of(it)}@{ver}", f"supply-chain: {'disputed ' if f.disputed else ''}{package_of(it)}@{ver} ({', '.join(f.ids)})"


def body_of(f, rb, owner, ran, today):
    it = f.item
    ver = it.label or it.version
    lines = [f"# {title_of(f)[1]}", "", f"Checked {today}. Pinned: `{it.kind}:{package_of(it)}@{it.version}`" + (f" ({ver})" if it.label else "") + ".", "",
             f"Finding: {f.why}.", f"Advisories: {', '.join(f.ids)}.", ""]
    if f.disputed:
        lines += ["This is a DISPUTED hit, for the advisor to rule on. Nothing was rolled back and nothing was reported clean.",
                  "A ruling goes in `.github/supply-chain-exceptions.json` (advisory ids, package, version, evidence links, date, each advisory's last-modified time); it lapses when either advisory changes."]
        return "\n".join(lines) + "\n"
    if f.via:
        lines.append(f"This action is called inside `{f.via}`: replace or drop the outer action. Nothing here can be pinned by us.")
        lines.append("There is no rollback of ours to a clean version of a nested action: the owner decides.")
        return "\n".join(lines) + "\n"
    if rb:
        lines.append(f"Rollback: pin the newest clean version public at least {WAIT_DAYS} days: {rb['version']}" + (f" (commit {rb['sha']})" if rb.get("sha") else "") + f", published {rb['published']}.")
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
    revs = [r for r in inv.git(root, "log", f"--since={since}", "--format=%H", start, "--", *paths).split() if r]
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
    r = gh.run("issue", "list", "--label", HIT_LABEL, "--state", "open", "--json", "number,title", "--limit", "200")
    try:
        open_issues = json.loads(r.stdout or "[]")
    except ValueError:
        raise Fail("gh issue list did not return JSON")
    for p in plan:
        prefix, title = p["title"]
        existing = next((i for i in open_issues if str(i.get("title", "")).startswith(prefix + " (")), None)
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
            f.write(p["body"])
            path = f.name
        try:
            labels = ["--label", HIT_LABEL] + (["--label", OWNER_LABEL] if p["owner"] else [])
            if existing:
                gh.run("issue", "edit", str(existing["number"]), "--title", title, "--body-file", path, *(["--add-label", OWNER_LABEL] if p["owner"] else []))
                print(f"audit: updated issue #{existing['number']}: {title}")
            else:
                gh.run("issue", "create", "--title", title, "--body-file", path, *labels)
                print(f"audit: opened an issue: {title}")
        finally:
            os.unlink(path)


# ---------- held pull requests ----------
def rerun_held(gh, net, now):
    n = 0
    for pr in net.prs():
        items = pr.get("_items") or [inv.Item(*_split_key(k)) for k in pr["moved"]]
        rows = [age.judge_item(it, net.proofs(it), now) for it in items]
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
    ap.add_argument("--fixtures")
    ap.add_argument("--now")
    ap.add_argument("--gh", default="gh")
    ap.add_argument("--exceptions")
    ap.add_argument("--rerun-held", action="store_true")
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
            head = inv.load_at(a.root, None)
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
        print(f"audit: inventory of {len(head)} item(s):")
        for k in sorted(head):
            print(f"  {k}")
        notes, findings = [], []
        for it in audited:
            if it.kind == "action" and inv.SHA40.match(it.version) and not it.label and not isinstance(net, FixtureNet):
                if not age._tag_for_commit(it.name, it.version):
                    print(f"information: {it.name}@{it.version[:12]} has no version label or tag: its advisories could not be looked up")

        def one(it):
            n2 = []
            return judge(it, net, exceptions, n2, current=a.base is not None or it.key in head), n2

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for fs, n2 in pool.map(one, audited):
                findings += fs
                notes += n2
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
                    if not m or ref.startswith("docker://"):
                        continue
                    child = inv.Item("action", m.group(1), m.group(2), "")
                    if child.key in seen:
                        continue
                    seen.add(child.key)
                    for f in judge(child, net, exceptions, notes, current=True):
                        f.via = outer.name
                        findings.append(f)
                    if depth + 1 < 3:
                        nxt.append((child, depth + 1))
            queue = nxt
        for n in notes:
            print(f"audit: {n}")
        plan, disputes = [], {}
        for f in findings:
            print(f"audit: {'DISPUTED' if f.disputed else 'HIT'}: {f.item.key} ({', '.join(f.ids)}): {f.why}" + (f" [inside {f.via}]" if f.via else ""))
            if f.disputed:  # one issue per package and incident, listing every version of it (history can hold many)
                disputes.setdefault((package_of(f.item), tuple(f.ids)), []).append(f)
                continue
            rb = None if f.via else rollback(f.item, net, now)
            ran = f.item.key in ran_keys
            owner = rb is None or ran or bool(f.via)
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
        print(f"audit: no known-compromised versions as of {today}" + (f" ({len(notes)} disputed hit(s) covered by a checked-in exception)" if notes else ""))
        return 0
    except Fail as e:
        print(f"audit: cannot do its job: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
