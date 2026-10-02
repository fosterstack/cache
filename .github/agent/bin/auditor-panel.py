#!/usr/bin/env python3
"""The scanner panel's audits, in the daily auditor run (scanner-panel rules 7-9, 8(c), 13, 14; owner Oct 2-3).

The daily rescan tallies the scanners mechanically and lists the findings only one scanner reported ("unique").
This step, run by auditor.yml right after the rescan, judges them:
  rule 8(a) a unique finding matching a "sees_alone" entry in that scanner's profile gets ONE audit, by the auditor
            in the primary seat (rule 14);
  rule 8(b) otherwise two audits, one per vendor seat ("A" = the auditor's existing provider, "B" = the second
            vendor); real only if both say real, each quoting evidence found verbatim in the image's evidence
            bundle; an audit that errors, or quotes nothing found in the image, cites no evidence;
  rule 8(c) round-1 disagreement opens a debate (rounds 2-4): each seat builds and delivers its case, reads the
            other's, gives a verdict; it stops at agreement; no agreement after round 4 is false by default;
  rule 9    false WITH evidence -> a not_affected VEX proposal; false by default -> logged only; a finding judged
            false that another scanner later reports is real, an "audit miss" reported to the owner, and any
            statement turns "affected";
  rule 13   every debate is recorded; it settles when the real answer arrives; +1 / -2 scoring per vendor seat;
  rule 14   the primary seat moves at a lead of 3 or more; a move is reported to the owner.
Public text names the seats ("vendor A", "vendor B", "primary", "second"); vendor and model names live only in the
environment's secrets (rule 8(b), rule 14, REQ-AUD-6 AC1).
"""
import argparse, copy, datetime, io, json, os, re, subprocess, sys, tarfile, tempfile

SEATS = ("A", "B")
DEBATE_ROUNDS = (2, 3, 4)
HISTORY_DAYS = 180          # a remembered judgment is dropped once its finding has been absent this long
MIN_QUOTE = 8               # a quote shorter than this proves nothing
LEAD = 3                    # rule 14: the primary seat moves at a lead of 3 or more
SCANNERS = ("grype", "scout", "inspector", "google")
KINDS = ("sees_alone", "blind_spot")
VENDOR_WORDS = re.compile(r"(?i)\b(anthropic|claude[\w.-]*|openai|chat\s*gpt|gpt[\w.-]*|codex|gemini|o[1-9][\w.-]*-?mini)\b")


def scoring_text():
    """What every debater is told before it argues (rule 8(c) -> rule 13)."""
    return ("Scoring (rule 13): this debate is recorded and settles only when the real answer arrives (another "
            "scanner reports the finding, an advisory names the package we ship, or a fix ships). Then the side "
            "that argued the true answer scores +1, and a side that convinced the other of a wrong answer scores "
            "-2. Argue only from evidence you can quote from the image.")


SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID",
               "ANTHROPIC_WORKSPACE_ID", "PANEL_AUDIT_A_MODEL", "PANEL_AUDIT_B_MODEL", "PANEL_AUDIT_B_IDENTITY_PROVIDER_ID",
               "PANEL_AUDIT_B_SERVICE_ACCOUNT_ID", "PANEL_AUDIT_B_PROJECT_ID")


def public(s):
    """Scrub vendor and model names, and every configured identifier, from text that may be published
    (rule 8(b), REQ-SCAN-014-AC4, REQ-AUD-6 AC4)."""
    if s is None:
        return None
    s = str(s)
    for k in SECRET_ENVS:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            s = s.replace(v, "<%s>" % k)
    return VENDOR_WORDS.sub("<auditor>", s)


def key_of(f):
    v = str(f.get("version") or "")
    if re.match(r"^v\d", v):
        v = v[1:]
    return (f.get("image"), str(f.get("id") or "").upper(), str(f.get("package") or "").lower(), v)


# ------------------------------------------------------------------------------------------------ profiles (rule 7)

def validate_profiles(doc):
    errs = []
    for i, e in enumerate((doc or {}).get("entries") or []):
        where = "entry %d" % i
        if e.get("scanner") not in SCANNERS:
            errs.append("%s: scanner %r is not one of %s" % (where, e.get("scanner"), ", ".join(SCANNERS)))
        if e.get("kind") not in KINDS:
            errs.append("%s: kind %r is not one of %s" % (where, e.get("kind"), ", ".join(KINDS)))
        for k in ("behavior", "finding", "evidence"):
            if not str(e.get(k) or "").strip():
                errs.append("%s: no %s (an entry cites the finding and the evidence from the image)" % (where, k))
        pat = (e.get("match") or {}).get("package")
        if e.get("kind") == "sees_alone" and not pat:
            errs.append("%s: a sees_alone entry needs match.package" % where)
        if pat:
            try:
                re.compile(pat)
            except re.error as x:
                errs.append("%s: match.package is not a regular expression (%s)" % (where, x))
    return errs


def profile_match(profiles, scanner, package):
    for e in (profiles or {}).get("entries") or []:
        pat = (e.get("match") or {}).get("package")
        if e.get("scanner") == scanner and e.get("kind") == "sees_alone" and pat and re.search(pat, package or ""):
            return e
    return None


# ------------------------------------------------------------------------------------------------ one vote

def _norm(s):
    return " ".join(str(s).split())


def vote(answer, bundle):
    """'real' / 'false' when the answer quotes evidence found verbatim in the image's bundle; None otherwise
    (an error, no verdict, or no quote from the image: "cites no evidence", rule 8(b))."""
    if not isinstance(answer, dict) or answer.get("error") or answer.get("verdict") not in ("real", "false"):
        return None
    ev = answer.get("evidence")
    if not isinstance(ev, list) or not ev:
        return None
    hay = _norm(bundle)
    for q in ev:
        q = _norm(q)
        if len(q) < MIN_QUOTE or q not in hay:
            return None
    return answer["verdict"]


def _ask(auditor, seat, req):
    try:
        a = auditor(req)
    except Exception as e:      # an auditor that fails is an error, never a vote
        return {"seat": seat, "error": "%s: %s" % (type(e).__name__, public(e))}
    if not isinstance(a, dict):
        return {"seat": seat, "error": "no answer"}
    if a.get("error"):
        return {"seat": seat, "error": public(a["error"])}   # an errored answer casts no vote and cites nothing
    return {"seat": seat, "verdict": a.get("verdict"), "evidence": a.get("evidence"), "why": public(a.get("why")),
            "case": public(a.get("case"))}


def _request(mode, f, bundle, **kw):
    req = {"mode": mode, "finding": {k: f.get(k) for k in ("image", "id", "package", "version", "seen_by")},
           "bundle": bundle}
    req.update(kw)
    return req


# ------------------------------------------------------------------------------------------------ rule 8 judgment

def _decide(answers, bundle):
    """real / false-evidence / false-default from final answers that all count (rule 8(b))."""
    votes = [vote(a, bundle) for a in answers]
    if votes and all(v == "real" for v in votes):
        return "report"
    if any(v == "false" for v in votes):
        return "false-evidence"
    return "false-default"


def _why(answers):
    for a in answers:
        if str(a.get("why") or "").strip():
            return a["why"]
    return None


def judge_unique(f, bundle, profiles, auditors, seat, scoring):
    scanner = f["seen_by"][0]
    if profile_match(profiles, scanner, f.get("package")):
        a = _ask(auditors[seat], seat, _request("audit", f, bundle))
        status = "report" if vote(a, bundle) == "real" else ("false-evidence" if vote(a, bundle) == "false" else "false-default")
        return {"status": status, "path": "a", "audits": [a], "debate": None, "why": _why([a]),
                "unexplained": status == "report" and not _why([a])}
    first = {s: _ask(auditors[s], s, _request("audit", f, bundle)) for s in SEATS}
    audits = [first[s] for s in SEATS]
    verdicts = {s: first[s].get("verdict") for s in SEATS}
    debate = None
    final = audits
    if all(verdicts[s] in ("real", "false") for s in SEATS) and verdicts["A"] != verdicts["B"]:
        debate = {"sides": dict(verdicts), "rounds": [], "outcome": "disagreed", "prevailing": None}
        cases = {s: first[s].get("case") for s in SEATS}
        for _rnd in DEBATE_ROUNDS:
            new_cases = {s: _ask(auditors[s], s, _request("case", f, bundle, own_case=cases[s],
                                                          opponent_case=cases[_other(s)], scoring=scoring))
                         for s in SEATS}
            cases = {s: new_cases[s].get("case") for s in SEATS}
            final = [_ask(auditors[s], s, _request("verdict", f, bundle, own_case=cases[s],
                                                   opponent_case=cases[_other(s)], scoring=scoring)) for s in SEATS]
            vs = {s: final[i].get("verdict") for i, s in enumerate(SEATS)}
            debate["rounds"].append({"cases": {s: cases[s] for s in SEATS}, "verdicts": vs})
            if vs["A"] == vs["B"] and vs["A"] in ("real", "false"):
                debate["outcome"] = "agreed-" + vs["A"]
                debate["prevailing"] = next(s for s in SEATS if verdicts[s] == vs["A"])
                break
        audits = audits + final
    if debate and debate["outcome"] == "disagreed":
        status = "false-default"        # rule 8(c): still disagreeing after round 4 -> false by default
    else:
        status = _decide(final, bundle)
    why = _why(final) if status == "report" else None
    return {"status": status, "path": "b", "audits": audits, "debate": debate, "why": why,
            "unexplained": status == "report" and not why}


def _other(s):
    return "B" if s == "A" else "A"


# ------------------------------------------------------------------------------------------------ rules 13 and 14

def score(debate, truth):
    out = {"A": 0, "B": 0}
    if truth not in ("real", "false"):
        return out
    for s in SEATS:
        if debate["sides"].get(s) == truth:
            out[s] += 1
    agreed = debate.get("outcome", "").startswith("agreed-") and debate.get("prevailing")
    if agreed and debate["outcome"] != "agreed-" + truth:
        out[debate["prevailing"]] -= 2
    return out


def _totals(debates):
    tot = {"A": 0, "B": 0}
    for d in debates:
        if d.get("settled"):
            for s, v in score(d, d["settled"]["truth"]).items():
                tot[s] += v
    return tot


def settle(state, events, today):
    """Settle recorded debates whose real answer arrived (rule 13): an event {image,id,package,version,kind} with
    kind corroborated / advisory / fix-shipped means the finding is real. A debate settles once."""
    keys = {key_of(e): e["kind"] for e in events}
    for d in state["debates"]:
        k = key_of(d)
        if not d.get("settled") and k in keys:
            d["settled"] = {"truth": "real", "by": keys[k], "on": today}
    state["scores"] = _totals(state["debates"])
    return state


def seat(scores, current):
    a, b = scores.get("A", 0), scores.get("B", 0)
    if current == "A" and b - a >= LEAD:
        return "B"
    if current == "B" and a - b >= LEAD:
        return "A"
    return current


def cve_auditor_seat(_state):
    """Rule 14: a seat change never moves the daily CVE auditor (a separate owner decision)."""
    return "A"


# ------------------------------------------------------------------------------------------------ the day

def new_state():
    return {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"}


def _expired(entry, today):
    cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=HISTORY_DAYS)).isoformat()
    return str(entry.get("last_seen") or entry.get("since") or today) < cutoff


def _ident(f):
    return {k: f.get(k) for k in ("image", "id", "package", "version")}


def apply_day(verdict, state, bundles, profiles, auditors, today, scoring):
    st = copy.deepcopy(state)
    out = {"issue": "", "vex": [], "profiles": [], "owner": [], "misses": [], "log": []}
    false_mem = {key_of(x): x for x in st["false"] if not _expired(x, today)}
    real_mem = {key_of(x): x for x in st["real"] if not _expired(x, today)}
    reported, events = [], []
    for f in verdict.get("findings") or []:
        k = key_of(f)
        seen = set(f.get("seen_by") or [])
        if k in real_mem:
            real_mem[k]["last_seen"] = today
            reported.append(f)
            continue
        if k in false_mem:
            before = false_mem[k]
            if len(seen | set(before.get("seen_by") or [])) >= 2:
                miss = dict(_ident(f), seen_by=sorted(seen | set(before.get("seen_by") or [])))
                out["misses"].append(miss)
                if before.get("vex"):
                    out["vex"].append(dict(_ident(f), status="affected",
                                           impact_statement="another scanner reported it after the audits "
                                                            "judged it not affected (audit miss)"))
                del false_mem[k]
                real_mem[k] = dict(_ident(f), seen_by=miss["seen_by"], since=today, last_seen=today)
                reported.append(f)
                events.append(dict(_ident(f), kind="corroborated"))
                continue
        if len(seen) >= 2:
            events.append(dict(_ident(f), kind="corroborated"))
            continue                                    # the rescan reports it (rule 5); nothing to judge
        r = judge_unique(f, bundles(f), profiles, auditors, st["seat"], scoring)
        entry = dict(_ident(f), seen_by=sorted(seen), status=r["status"], path=r["path"], audits=r["audits"],
                     why=r["why"])
        out["log"].append(entry)
        if r["debate"]:
            st["debates"].append(dict(_ident(f), on=today, settled=None, **r["debate"]))
        if r["status"] == "report":
            real_mem[k] = dict(_ident(f), seen_by=sorted(seen), since=today, last_seen=today)
            reported.append(f)
            prop = {"scanner": f["seen_by"][0], "kind": "sees_alone",
                    "match": {"package": "^%s$" % re.escape(f["package"])},
                    "behavior": r["why"] or "unexplained: the audits confirmed the finding but not why only this scanner saw it",
                    "finding": "%s on %s (%s %s), %s" % (f["id"], f["image"], f["package"], f["version"], today),
                    "evidence": "; ".join(q for a in r["audits"] for q in (a.get("evidence") or [])
                                          if a.get("verdict") == "real")[:500],
                    "unexplained": r["unexplained"]}
            out["profiles"].append(prop)
            if r["unexplained"]:
                out["owner"].append("Scanner panel: %s on %s is real but unexplained — the audits could not say why "
                                    "only %s found it; an unexplained profile entry is proposed." %
                                    (f["id"], f["image"], f["seen_by"][0]))
            continue
        old = false_mem.get(k) or {}
        ev = r["status"] == "false-evidence"
        false_mem[k] = dict(_ident(f), seen_by=sorted(seen | set(old.get("seen_by") or [])),
                            since=old.get("since") or today, last_seen=today, vex=bool(old.get("vex") or ev))
        if ev and not old.get("vex"):
            quotes = [q for a in r["audits"] if a.get("verdict") == "false" for q in (a.get("evidence") or [])]
            if f.get("purls"):
                out["vex"].append(dict(_ident(f), status="not_affected", purls=list(f["purls"]),
                                       impact_statement="Audited from the image: " + "; ".join(quotes)[:500]))
            else:   # no exact package identity from any scanner: a statement could not be scoped; never a blanket one
                false_mem[k]["vex"] = False
                out["owner"].append("Scanner panel: %s on %s (%s %s) was judged not affected with evidence, but no "
                                    "scanner gave its package identity, so no VEX statement was written: %s" %
                                    (f["id"], f["image"], f["package"], f["version"], "; ".join(quotes)[:300]))
    st["false"] = sorted(false_mem.values(), key=lambda x: key_of(x))
    st["real"] = sorted(real_mem.values(), key=lambda x: key_of(x))
    st = settle(st, events, today)
    new_seat = seat(st["scores"], st["seat"])
    if new_seat != st["seat"]:
        out["owner"].append("Scanner panel: the primary seat moves from vendor %s to vendor %s (scores A %d, B %d; "
                            "rule 14). The daily CVE auditor does not move." %
                            (st["seat"], new_seat, st["scores"]["A"], st["scores"]["B"]))
        st["seat"] = new_seat
    if out["misses"]:
        out["owner"].append("Scanner panel: %d audit miss(es) — a finding the audits judged false was then reported "
                            "by another scanner: %s" % (len(out["misses"]),
                                                        ", ".join("%s on %s" % (m["id"], m["image"]) for m in out["misses"])))
    if reported:
        lines = ["The daily scanner panel's audits confirm %d finding(s) on main's candidate (rule 5):" % len(reported), ""]
        missed = {key_of(m) for m in out["misses"]}
        for f in reported:
            lines.append("- `%s` in `%s %s` on %s%s" % (f["id"], f["package"], f["version"], f["image"],
                                                        " — **audit miss** (judged false earlier)" if key_of(f) in missed else ""))
        out["issue"] = public("\n".join(lines) + "\n")
    out["owner"] = [public(o) for o in out["owner"]]
    return st, out


# ------------------------------------------------------------------------------------------------ evidence bundle

GO_MARK = b"\xff Go buildinf:"


def _pick_manifest(idx, blob, arch):
    for m in idx.get("manifests") or []:
        mt = m.get("mediaType", "")
        if "index" in mt or "manifest.list" in mt:
            found = _pick_manifest(json.loads(blob(m["digest"])), blob, arch)
            if found:
                return found
            continue
        plat = m.get("platform") or {}
        if plat.get("os") == "linux" and plat.get("architecture") == arch:
            return json.loads(blob(m["digest"]))
    return None


def read_image(archive, arch):
    """The image's final filesystem facts from an OCI archive: every path, the dpkg status records, and the bytes
    of executables carrying Go build information. Layers apply in order; whiteouts remove paths."""
    paths, status, gobins = set(), {}, {}
    with tarfile.open(archive) as t:
        def blob(d):
            return t.extractfile("blobs/" + d.replace(":", "/")).read()
        man = _pick_manifest(json.loads(t.extractfile("index.json").read()), blob, arch)
        if man is None:
            raise ValueError("no linux/%s image in %s" % (arch, os.path.basename(archive)))
        for layer in man.get("layers") or []:
            with tarfile.open(fileobj=io.BytesIO(blob(layer["digest"])), mode="r:*") as lt:
                for m in lt.getmembers():
                    name = "/" + m.name.lstrip("./")
                    base = os.path.basename(name)
                    if base.startswith(".wh."):
                        gone = os.path.join(os.path.dirname(name), base[4:])
                        paths.discard(gone); status.pop(gone, None); gobins.pop(gone, None)
                        continue
                    paths.add(name)
                    if not m.isfile():
                        continue
                    if name == "/var/lib/dpkg/status" or name.startswith("/var/lib/dpkg/status.d/"):
                        status[name] = lt.extractfile(m).read().decode("utf-8", "replace")
                    elif m.mode & 0o111:
                        data = lt.extractfile(m).read()
                        if GO_MARK in data:
                            gobins[name] = data
    return {"paths": sorted(paths), "status": status, "gobins": gobins}


def go_buildinfo(gobins, run=subprocess.run):
    out = {}
    for name, data in sorted(gobins.items()):
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(data)
        try:
            r = run(["go", "version", "-m", tf.name], capture_output=True, text=True)
            out[name] = (r.stdout or "").replace(tf.name, name) if r.returncode == 0 else ""
        finally:
            os.unlink(tf.name)
    return out


def bundle_text(facts, buildinfo, f):
    """The evidence an auditor may quote for one finding: the package database records that name the package, the
    paths that mention it, and the Go build information lines that mention it; their absence is stated in words."""
    pkg = str(f.get("package") or "")
    low = pkg.lower().rsplit("/", 1)[-1]
    lines = ["image %s (%s %s, reported by %s)" % (f.get("image"), pkg, f.get("version"), ", ".join(f.get("seen_by") or []))]
    stanzas = []
    for path, text in sorted(facts["status"].items()):
        for st in text.split("\n\n"):
            hdr = {ln.split(":", 1)[0].strip().lower(): ln.split(":", 1)[1].strip()
                   for ln in st.splitlines() if ":" in ln and not ln.startswith(" ")}
            if low and (hdr.get("package", "").lower() == low or hdr.get("source", "").split(" ")[0].lower() == low):
                stanzas.append("package database %s:\n%s" % (path, st.strip()))
    lines += stanzas or ["package database: no record names %s" % pkg]
    hits = [x for x in facts["paths"] if low and low in x.lower()][:40]
    lines += ["file: %s" % x for x in hits] or ["files: no path in the image mentions %s" % pkg]
    go = ["go build info %s: %s" % (b, ln.strip()) for b, text in sorted(buildinfo.items())
          for ln in text.splitlines() if pkg and pkg.lower() in ln.lower()]
    lines += go or ["go build info: no Go binary in the image records %s" % pkg]
    return "\n".join(lines) + "\n"


class Bundles:
    """Evidence bundles for the day's findings, reading each image once from the rescan's OCI archives."""

    def __init__(self, oci_dir, read=read_image, buildinfo=go_buildinfo):
        self.oci_dir, self.read, self.buildinfo, self.cache = oci_dir, read, buildinfo, {}

    def __call__(self, f):
        img = f.get("image") or ""
        if img not in self.cache:
            variant, _, arch = img.rpartition("-")
            try:
                facts = self.read(os.path.join(self.oci_dir, variant + ".oci"), arch)
                self.cache[img] = (facts, self.buildinfo(facts["gobins"]))
            except (OSError, ValueError, KeyError, tarfile.TarError) as e:
                self.cache[img] = None
                sys.stderr.write("auditor-panel: no evidence from image %s: %s\n" % (img, e))
        got = self.cache[img]
        if got is None:     # no evidence: every quote fails, so every audit cites no evidence (false by default)
            return "image %s: the image could not be read; no evidence is available\n" % img
        return bundle_text(got[0], got[1], f)


# ------------------------------------------------------------------------------------------------ the two seats

PROMPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prompts", "panel.md")


def prompt_section(key, path=PROMPTS):
    out, grab = [], False
    for ln in open(path).read().splitlines():
        if ln.startswith("## "):
            grab = ln[3:].strip() == key
            continue
        if grab:
            out.append(ln)
    text = "\n".join(out).strip()
    if not text:
        raise RuntimeError("prompt-load: section %r missing from prompts/panel.md" % key)
    return text


def render(req):
    t = prompt_section(req["mode"])
    for k, v in (("finding", json.dumps(req["finding"], indent=1)), ("bundle", req["bundle"]),
                 ("own_case", req.get("own_case") or "(none)"), ("opponent_case", req.get("opponent_case") or "(none)"),
                 ("scoring", req.get("scoring") or "")):
        t = t.replace("{%s}" % k, str(v))
    return t


def extract_json(text):
    s, dec = str(text or ""), json.JSONDecoder()
    i = s.find("{")
    while i != -1:
        try:
            obj, _ = dec.raw_decode(s[i:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        i = s.find("{", i + 1)
    return None


def _answer(text):
    a = extract_json(text)
    return a if a is not None else {"error": "no JSON answer"}


def seat_a(env=os.environ):
    """Vendor A: the auditor's existing provider, through its existing federation (the SDK exchanges the identity
    token in ANTHROPIC_IDENTITY_TOKEN_FILE; workspace, organization and service account from the environment)."""
    import anthropic
    client, model = anthropic.Anthropic(), env["PANEL_AUDIT_A_MODEL"]

    def ask(req):
        msg = client.messages.create(model=model, max_tokens=2048, messages=[{"role": "user", "content": render(req)}])
        return _answer("".join(getattr(b, "text", "") for b in msg.content))
    return ask


def seat_b(env=os.environ):
    """Vendor B: workload identity federation (no key): the GitHub identity token in PANEL_AUDIT_B_TOKEN_FILE is
    exchanged for a short-lived token bound to the configured service account; Responses API only."""
    from openai import OpenAI
    token_file = env["PANEL_AUDIT_B_TOKEN_FILE"]

    def token():
        with open(token_file) as fh:
            return fh.read().strip()
    client = OpenAI(workload_identity={"identity_provider_id": env["PANEL_AUDIT_B_IDENTITY_PROVIDER_ID"],
                                       "service_account_id": env["PANEL_AUDIT_B_SERVICE_ACCOUNT_ID"],
                                       "provider": {"token_type": "jwt", "get_token": token}},
                    project=env["PANEL_AUDIT_B_PROJECT_ID"], timeout=300, max_retries=2)
    model = env["PANEL_AUDIT_B_MODEL"]

    def ask(req):
        return _answer(client.responses.create(model=model, input=render(req)).output_text)
    return ask


def unavailable(why):
    def ask(_req):
        return {"error": why}
    return ask


def make_seats(mode, env=os.environ, a=seat_a, b=seat_b):
    if mode != "real":
        return {s: unavailable("no auditor in this run (%s)" % mode) for s in SEATS}
    seats = {}
    for s, make in (("A", a), ("B", b)):
        try:
            seats[s] = make(env)
        except Exception as e:   # a seat that cannot start errors every audit: no evidence, reported
            seats[s] = unavailable("seat %s could not start: %s: %s" % (s, type(e).__name__, public(e)))
    return seats


# ------------------------------------------------------------------------------------------------ commands

STATE = ".auditor/panel-state.json"
PROFILES = ".github/policy/scanner-profiles.json"
VEX = ".vex/fosterstack-cache.openvex.json"
ISSUE_TITLE = "Daily scanner panel: findings on main"


def _load_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


def cmd_judge(a, seats=None, bundles=None):
    verdict = _load_json(a.verdict)
    if not isinstance(verdict, dict) or not isinstance(verdict.get("findings"), list):
        sys.stderr.write("::error::auditor-panel: the rescan run has no panel verdict (%s); nothing was judged\n" % a.verdict)
        return 2
    state = _load_json(a.state) or new_state()
    profiles = _load_json(a.profiles, {"entries": []})
    errs = validate_profiles(profiles)
    if errs:
        for e in errs:
            sys.stderr.write("::error::scanner profiles: %s\n" % e)
        return 2
    seats = seats or make_seats(a.seats)
    st, out = apply_day(verdict, state, bundles or Bundles(a.oci), profiles, seats, a.today, scoring_text())
    os.makedirs(a.out, exist_ok=True)
    for name, obj in (("state.json", st), ("day.json", out)):
        with open(os.path.join(a.out, name), "w") as fh:
            json.dump(obj, fh, indent=1)
    errors = [x for e in out["log"] for x in e["audits"] if x.get("error")]
    summary = ["## Scanner panel audits (%s)" % a.today, "",
               "%d unique finding(s) judged: %d real, %d false with evidence, %d false by default; %d debate(s); "
               "%d audit miss(es); %d audit error(s); primary seat: vendor %s; scores A %d, B %d." % (
                   len(out["log"]), sum(e["status"] == "report" for e in out["log"]),
                   sum(e["status"] == "false-evidence" for e in out["log"]),
                   sum(e["status"] == "false-default" for e in out["log"]),
                   sum(1 for d in st["debates"] if d.get("on") == a.today), len(out["misses"]), len(errors),
                   st["seat"], st["scores"]["A"], st["scores"]["B"])]
    summary += ["- audit error (vendor %s): %s" % (x["seat"], x["error"]) for x in errors]
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(public("\n".join(summary)) + "\n")
    for x in errors:
        print("::warning::scanner panel audit error (vendor %s): %s" % (x["seat"], x["error"]))
    print(public("\n".join(summary)))
    return 0


def apply_files(root, st, day, today):
    """Write the day's state, VEX proposals and profile proposals into the checkout; returns the changed paths."""
    changed = []
    path = os.path.join(root, STATE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if _load_json(path) != st:
        with open(path, "w") as fh:
            json.dump(st, fh, indent=1, sort_keys=True)
            fh.write("\n")
        changed.append(STATE)
    if day["vex"]:
        vpath = os.path.join(root, VEX)
        doc = _load_json(vpath)
        ts = "%sT00:00:00Z" % today
        for v in day["vex"]:
            subs = [{"@id": p} for p in v.get("purls") or []]
            if v["status"] == "not_affected":
                doc["statements"].append({
                    "@id": "%s#panel-%s-%s" % (doc.get("@id", ""), v["id"].lower(), re.sub(r"[^a-z0-9]+", "-", v["package"].lower())),
                    "vulnerability": {"name": v["id"]}, "timestamp": ts, "status": "not_affected",
                    "products": [{"@id": "pkg:oci/cache?repository_url=ghcr.io/fosterstack/cache", "subcomponents": subs}],
                    "justification": "component_not_present", "impact_statement": v["impact_statement"]})
            else:
                for stmt in doc["statements"]:
                    if (stmt.get("vulnerability") or {}).get("name") == v["id"] and str(stmt.get("@id", "")).find("#panel-") != -1:
                        stmt.update(status="affected", last_updated=ts,
                                    action_statement="Under investigation: " + v["impact_statement"])
                        stmt.pop("justification", None)
                        stmt.pop("impact_statement", None)
        doc["timestamp"], doc["version"] = ts, int(doc.get("version", 1)) + 1
        with open(vpath, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        changed.append(VEX)
    if day["profiles"]:
        ppath = os.path.join(root, PROFILES)
        prof = _load_json(ppath)
        prof["entries"].extend(day["profiles"])
        with open(ppath, "w") as fh:
            json.dump(prof, fh, indent=2)
            fh.write("\n")
        changed.append(PROFILES)
    return changed


def _sh(cmd, plan, real, run=subprocess.run, **kw):
    plan.append(cmd)
    if real:
        r = run(cmd, capture_output=True, text=True, **kw)
        if r.returncode != 0:
            raise RuntimeError("%s failed: %s" % (cmd[0:3], public(r.stderr)[-400:]))
        return r.stdout
    return ""


def cmd_deliver(a, run=subprocess.run):
    """Rule 0: the day's changes reach main only through a pull request from the auditor lane's branch; the tracking
    issue (rule 5) and the owner report (rules 8, 9, 14) are issues. Real git/gh only with AUDITOR_ALLOW_REAL_GH=1
    and not dry; otherwise the plan is written."""
    st = _load_json(os.path.join(a.out, "state.json"))
    day = _load_json(os.path.join(a.out, "day.json"))
    if st is None or day is None:
        sys.stderr.write("::error::auditor-panel: nothing to deliver (no judgment in %s)\n" % a.out)
        return 2
    real = (not a.dry_run) and os.environ.get("AUDITOR_ALLOW_REAL_GH") == "1"
    plan, branch = [], "auditor/panel"
    # the base: the open panel PR's branch (yesterday's unmerged proposals stay), else the main commit this run is on
    existing = _sh(["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "number", "--jq", ".[0].number"],
                   plan, real, run).strip()
    if existing:
        _sh(["git", "-C", a.repo, "fetch", "origin", branch], plan, real, run)
        base = "FETCH_HEAD"
    else:
        base = os.environ.get("GITHUB_SHA") or "HEAD"
    _sh(["git", "-C", a.repo, "checkout", "--force", "-B", branch, base], plan, real, run)
    changed = apply_files(a.repo, st, day, a.today)
    if changed:
        _sh(["git", "-C", a.repo, "add", "--"] + changed, plan, real, run)
        _sh(["git", "-C", a.repo, "commit", "-m", "Scanner panel audits, %s (rules 7-9, 13, 14)" % a.today], plan, real, run)
        _sh(["git", "-C", a.repo, "push", "--force", "origin", "HEAD:refs/heads/" + branch], plan, real, run)
        body = public("The daily scanner panel's audits of the rescan's unique findings (%s).\n\n%s" % (
            a.today, "\n".join("- " + c for c in changed)))
        if existing:
            _sh(["gh", "pr", "edit", existing, "--body", body], plan, real, run)
        else:
            _sh(["gh", "pr", "create", "--draft", "--head", branch, "--base", "main",
                 "--title", "Scanner panel audits (rules 7-9, 13, 14)", "--body", body], plan, real, run)
    ienv = dict(os.environ, GH_TOKEN=os.environ.get("AUDITOR_ISSUES_TOKEN", os.environ.get("GH_TOKEN", "")))
    if day["issue"]:
        n = _sh(["gh", "issue", "list", "--state", "open", "--label", "daily-rescan", "--search", ISSUE_TITLE,
                 "--json", "number", "--jq", ".[0].number"], plan, real, run, env=ienv).strip()
        if n:
            _sh(["gh", "issue", "comment", n, "--body", day["issue"]], plan, real, run, env=ienv)
        else:
            _sh(["gh", "issue", "create", "--title", ISSUE_TITLE, "--label", "daily-rescan", "--label", "security",
                 "--body", day["issue"]], plan, real, run, env=ienv)
    if day["owner"]:
        _sh(["gh", "issue", "create", "--title", "Scanner panel: for the owner (%s)" % a.today, "--label", "owner-decision",
             "--body", public("\n\n".join(day["owner"]))], plan, real, run, env=ienv)
    with open(os.path.join(a.out, "plan.json"), "w") as fh:
        json.dump({"real": real, "changed": changed, "commands": plan}, fh, indent=1)
    print("auditor-panel: delivered (%s): %d path(s), %d command(s)" % ("real" if real else "plan only", len(changed), len(plan)))
    return 0


def main(argv=None, judge=cmd_judge, deliver=cmd_deliver):
    ap = argparse.ArgumentParser(prog="auditor-panel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--verdict", required=True)
    j.add_argument("--state", required=True)
    j.add_argument("--profiles", required=True)
    j.add_argument("--oci", required=True)
    j.add_argument("--out", required=True)
    j.add_argument("--seats", choices=("real", "none"), default="none")
    j.add_argument("--today", default=datetime.date.today().isoformat())
    d = sub.add_parser("deliver")
    d.add_argument("--out", required=True)
    d.add_argument("--repo", default=".")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--today", default=datetime.date.today().isoformat())
    a = ap.parse_args(argv)
    return judge(a) if a.cmd == "judge" else deliver(a)


if __name__ == "__main__":
    sys.exit(main())
