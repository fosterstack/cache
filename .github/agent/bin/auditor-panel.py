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
import argparse, copy, datetime, io, json, os, re, subprocess, sys, tarfile, tempfile, time, urllib.parse, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auditorlib import policy  # noqa: E402

SEATS = ("A", "B")
DEBATE_ROUNDS = (2, 3, 4)
HISTORY_DAYS = 180          # a remembered judgment is dropped once its finding has been absent this long
MIN_QUOTE = 8               # a quote shorter than this proves nothing
LEAD = 3                    # rule 14: the primary seat moves at a lead of 3 or more
SCANNERS = ("grype", "scout", "inspector", "google")
KINDS = ("sees_alone", "blind_spot")
# a leading boundary only, so a vendor name inside an identifier (OpenAIError, AnthropicAPIError) is caught too
VENDOR_WORDS = re.compile(r"(?i)(?<![a-z])(anthropic|claude|openai|chat\s*gpt|gpt|codex|gemini)[\w.-]*|"
                          r"\bo[1-9][\w.-]*-?mini\b")


def scoring_text():
    """What every debater is told before it argues (rule 8(c) -> rule 13)."""
    return ("Scoring (rule 13): this debate is recorded and settles only when the real answer arrives (another "
            "scanner reports the finding, an advisory names the package we ship, or a fix ships). Then the side "
            "that argued the true answer scores +1, and a side that convinced the other of a wrong answer scores "
            "-2. Argue only from evidence you can quote from the image.")


KEYLIKE = re.compile(r"(sk-[A-Za-z0-9_-]{6,}|gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}|"
                     r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|(?i:bearer)\s+[A-Za-z0-9._-]{6,})")
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
        elif v:                 # a short value (a model alias like o3) only as a whole word
            s = re.sub(r"(?<![A-Za-z0-9_.-])%s(?![A-Za-z0-9_.-])" % re.escape(v), "<%s>" % k, s)
    return KEYLIKE.sub("<redacted>", VENDOR_WORDS.sub("<auditor>", s))


def scrub(obj):
    """public() applied to every string in a JSON-able object: what is written out (day, state, plan) is public."""
    if isinstance(obj, dict):
        return {(public(k) if isinstance(k, str) else k): scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return public(obj) if isinstance(obj, str) else obj


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


def _same_entry(e, scanner, package):
    return (e.get("scanner") == scanner and e.get("kind") == "sees_alone"
            and (e.get("match") or {}).get("package") == "^%s$" % re.escape(package))


def profile_match(profiles, scanner, package):
    for e in (profiles or {}).get("entries") or []:
        pat = (e.get("match") or {}).get("package")
        if e.get("scanner") == scanner and e.get("kind") == "sees_alone" and pat and re.search(pat, package or ""):
            return e
    return None


# ------------------------------------------------------------------------------------------------ one vote

def _norm(s):
    return " ".join(str(s).split())


EVIDENCE_MARK = "--- evidence from the image ---"
ABSENT = ("no record names", "no path in the image mentions", "no Go binary in the image records")


def _ver(v):
    v = str(v or "")
    return v[2:] if re.match(r"^go\d", v) else (v[1:] if re.match(r"^v\d", v) else v)


def installed_versions(bundle, f):
    """The versions of the finding's package the image's evidence section actually records: a package-database record's
    own Version field (within its stanza: no other package's field, never a Breaks/Depends constraint), or a Go build
    info module line. Returns None when the image could not be read."""
    if EVIDENCE_MARK not in str(bundle):
        return None
    pkg = str(f.get("package") or "").lower()
    short = pkg.rsplit("/", 1)[-1]
    found = set()
    for stanza in re.split(r"\npackage database [^\n]*:\n|\n\n", str(bundle).split(EVIDENCE_MARK, 1)[1]):
        m = re.search(r"(?m)^Package:\s*(\S+)\s*$", stanza)
        v = re.search(r"(?m)^Version:\s*(\S+)\s*$", stanza)
        src = re.search(r"(?m)^Source:\s*(\S+)", stanza)
        if v and ((m and m.group(1).lower() in (pkg, short)) or (src and src.group(1).lower() in (pkg, short))):
            found.add(_ver(v.group(1)).lower())
    ev = str(bundle).split(EVIDENCE_MARK, 1)[1]
    for m in re.finditer(r"(?m)\b(?:dep|mod)\s+(\S+)\s+(v?\S+)", ev):
        if m.group(1).lower() == pkg:
            found.add(_ver(m.group(2)).lower())
    if pkg in ("stdlib", "go"):         # the Go standard library: each Go binary's toolchain version
        found |= {m.group(1).lower() for m in re.finditer(r"(?m)^go build info \S+: \S+: go(\d[\w.+-]*)\s*$", ev)}
    return found


def absence_is_complete(bundle, f):
    """Absence is proof only where the evidence covers that kind of package: a distribution package (deb/rpm/apk)
    with no record AND no file path mentioning it, or a Go module (not the standard library) in an image whose Go
    binaries carry build information. Anything else (a static non-Go binary such as busybox, an unknown type) can
    never be shown absent by this evidence (Codex r3 B1)."""
    ev = str(bundle).split(EVIDENCE_MARK, 1)[1] if EVIDENCE_MARK in str(bundle) else ""
    pkg = str(f.get("package") or "").lower()
    short = pkg.rsplit("/", 1)[-1]
    kinds = {p[4:].split("/", 1)[0] for p in f.get("purls") or [] if str(p).startswith("pkg:")}
    if kinds & {"deb", "rpm", "apk"} and len(kinds) == 1:
        return not any(ln.startswith("file: ") and short in ln.lower() for ln in ev.splitlines())
    if kinds == {"golang"} and pkg not in ("stdlib", "go"):
        return bool(re.search(r"(?m)^go build info \S+: \S+: go\d", ev))
    return False


def vote(answer, bundle, f):
    return validated(answer, bundle, f)[0]


def validated(answer, bundle, f):
    """(verdict, the quotes that prove it): 'real' / 'false' only when the answer quotes the EVIDENCE section of the
    image's bundle verbatim (never its header, never a diagnostic) and the quotes support the verdict: "real" needs a
    quote naming the package AND its reported version; "false" needs a quote stating the package is absent, or naming
    it at a different version. Anything else cites no evidence (rule 8(b)) -> (None, []). Only the returned quotes are
    ever published (a VEX justification, a profile entry)."""
    none = (None, [])
    if not isinstance(answer, dict) or answer.get("error") or answer.get("verdict") not in ("real", "false"):
        return none
    ev = answer.get("evidence")
    if not isinstance(ev, list) or not ev or EVIDENCE_MARK not in str(bundle):
        return none
    hay = _norm(str(bundle).split(EVIDENCE_MARK, 1)[1])
    quotes = []
    for q in ev:
        q = _norm(q)
        if len(q) < MIN_QUOTE or q not in hay or EVIDENCE_MARK in q:
            return none
        quotes.append(q)
    pkg = str(f.get("package") or "").lower()
    short, ver = pkg.rsplit("/", 1)[-1], _ver(f.get("version")).lower()
    have = installed_versions(bundle, f)
    pkg_re = r"(?i)(Package:\s*%s\s|(?:dep|mod)\s+%s\s)" % (re.escape(short), re.escape(pkg))
    if pkg in ("stdlib", "go"):         # the standard library's record is a Go binary's toolchain line
        pkg_re = r"(?i)^go build info \S+: \S+: go\d"

    def record(q):          # a quote of one record of THIS package: its own Package/Version, or its Go module line
        return re.search(pkg_re, q + " ") and q.lower().count("package:") <= 1
    if answer["verdict"] == "real":
        # real: the image records the package at exactly the reported version, and the quote shows that record
        proof = [q for q in quotes if record(q) and re.search(r"(?i)(Version:\s*|\s|go)v?%s(\s|$)" % re.escape(ver), q)]
        return ("real", proof) if proof and ver in (have or ()) else none
    # false: the image records NO installed copy at the reported version, and the quote shows absence or another version
    if have is None or ver in have:
        return none
    absent = [q for q in quotes if any(a.lower() in q.lower() for a in ABSENT) and (pkg in q.lower() or short in q.lower())]
    other = [q for q in quotes if record(q) and re.search(r"(?i)(Version:\s*\S|(?:dep|mod)\s+\S+\s+v?\d)", q)]
    proof = (absent if not have and absence_is_complete(bundle, f) else []) + other
    return ("false", proof) if proof else none


def _ask(auditor, seat, req):
    tag = {"seat": seat, "mode": req["mode"], "round": req.get("round", 1)}
    try:
        a = auditor(req)
    except Exception as e:      # an auditor that fails is an error, never a vote; its SDK's class name is never kept
        return dict(tag, error="seat error: %s" % e)
    if not isinstance(a, dict):
        return dict(tag, error="no answer")
    if a.get("error"):
        return dict(tag, error=str(a["error"]))   # an errored answer casts no vote and cites nothing
    def text(x):            # an answer's fields are plain text; anything else is flattened before it is kept
        return None if x is None else (x if isinstance(x, str) else json.dumps(x, sort_keys=True))
    ev = a.get("evidence")
    return dict(tag, verdict=a.get("verdict") if a.get("verdict") in ("real", "false") else text(a.get("verdict")),
                evidence=[text(q) for q in ev] if isinstance(ev, list) else text(ev), why=text(a.get("why")),
                case=text(a.get("case")))


def _request(mode, f, bundle, **kw):
    req = {"mode": mode, "finding": {k: f.get(k) for k in ("image", "id", "package", "version", "seen_by")},
           "bundle": bundle}
    req.update(kw)
    return req


# ------------------------------------------------------------------------------------------------ rule 8 judgment

def _decide(answers, bundle, f):
    """real / false-evidence / false-default from final answers that all count (rule 8(b))."""
    votes = [vote(a, bundle, f) for a in answers]
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
        v, proof = validated(a, bundle, f)
        status = "report" if v == "real" else ("false-evidence" if v == "false" else "false-default")
        return {"status": status, "path": "a", "audits": [a], "debate": None, "why": _why([a]),
                "unexplained": status == "report" and not _why([a]), "proof": proof}
    first = {s: _ask(auditors[s], s, _request("audit", f, bundle)) for s in SEATS}
    audits = [first[s] for s in SEATS]
    verdicts = {s: first[s].get("verdict") for s in SEATS}
    debate = None
    final = audits
    if all(verdicts[s] in ("real", "false") for s in SEATS) and verdicts["A"] != verdicts["B"]:
        debate = {"sides": dict(verdicts), "rounds": [], "outcome": "disagreed", "prevailing": None}
        cases = {s: first[s].get("case") for s in SEATS}
        for rnd in DEBATE_ROUNDS:
            new_cases = {s: _ask(auditors[s], s, _request("case", f, bundle, own_case=cases[s], round=rnd,
                                                          opponent_case=cases[_other(s)], scoring=scoring))
                         for s in SEATS}
            cases = {s: new_cases[s].get("case") for s in SEATS}
            final = [_ask(auditors[s], s, _request("verdict", f, bundle, own_case=cases[s], round=rnd,
                                                   opponent_case=cases[_other(s)], scoring=scoring)) for s in SEATS]
            audits = audits + [new_cases[s] for s in SEATS] + final     # every answer, error and citation is kept
            vs = {s: final[i].get("verdict") for i, s in enumerate(SEATS)}
            debate["rounds"].append({"cases": {s: cases[s] for s in SEATS}, "verdicts": vs})
            if vs["A"] == vs["B"] and vs["A"] in ("real", "false"):
                debate["outcome"] = "agreed-" + vs["A"]
                debate["prevailing"] = next(s for s in SEATS if verdicts[s] == vs["A"])
                break
    if debate and debate["outcome"] == "disagreed":
        status = "false-default"        # rule 8(c): still disagreeing after round 4 -> false by default
    else:
        status = _decide(final, bundle, f)
    want = {"report": "real", "false-evidence": "false"}.get(status)
    proof = [q for a in final for v, qs in [validated(a, bundle, f)] if v == want for q in qs]
    why = _why(final) if status == "report" else None
    return {"status": status, "path": "b", "audits": audits, "debate": debate, "why": why,
            "unexplained": status == "report" and not why, "proof": proof}


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


# ------------------------------------------------------------------------------------------------ the day

def new_state():
    return {"version": 1, "false": [], "real": [], "debates": [], "scores": {"A": 0, "B": 0}, "seat": "A"}


def _expired(entry, today):
    cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=HISTORY_DAYS)).isoformat()
    return str(entry.get("last_seen") or entry.get("since") or today) < cutoff


def _ident(f):
    return {k: f.get(k) for k in ("image", "id", "package", "version")}


def purls_for(f):
    """The finding's purls whose decoded version is the version the audits validated: a statement never names a
    package identity other than the one judged (Codex r4 R6)."""
    ver = _ver(f.get("version")).lower()
    out = []
    for p in f.get("purls") or []:
        _, at, rest = str(p).partition("@")
        if at and _ver(urllib.parse.unquote(rest.split("?", 1)[0].split("#", 1)[0])).lower() == ver:
            out.append(p)
    return out


def _not_in_image(bundles, f, image):
    """The image's evidence shows the finding's package is not installed at the reported version there."""
    g = dict(f, image=image)
    b = bundles(g)
    have = installed_versions(b, g)
    ver = _ver(f.get("version")).lower()
    return have is not None and ver not in have and (bool(have) or absence_is_complete(b, g))


def osv_advisory(f, opener=urllib.request.urlopen):
    """Does a published advisory (OSV) name this exact package version for this CVE? True / False, or None when it
    cannot be asked or answered (no purl of the judged version, a network error): None is never a "yes"."""
    purls = purls_for(f)
    if not purls:
        return None
    want = str(f.get("id") or "").upper()
    try:
        for p in purls:
            req = urllib.request.Request("https://api.osv.dev/v1/query", method="POST",
                                         data=json.dumps({"package": {"purl": urllib.parse.unquote(p.split("?", 1)[0])}}).encode(),
                                         headers={"Content-Type": "application/json"})
            with opener(req, timeout=30) as r:
                for v in (json.load(r).get("vulns") or []):
                    if want in [str(x).upper() for x in [v.get("id")] + list(v.get("aliases") or [])]:
                        return True
        return False
    except (OSError, ValueError):
        return None


def _present_in(bundles, f, images):
    ver = _ver(f.get("version")).lower()
    return [img for img in images if ver in (installed_versions(bundles(dict(f, image=img)), dict(f, image=img)) or ())]


def apply_day(verdict, state, bundles, profiles, auditors, today, scoring, advisory=None):
    st = copy.deepcopy(state)
    images = sorted((verdict.get("images") or {}).keys())      # every image the rescan built today
    out = {"issue": "", "vex": [], "profiles": [], "owner": [], "misses": [], "log": []}
    false_mem = {key_of(x): x for x in st["false"] if not _expired(x, today)}
    real_mem = {key_of(x): x for x in st["real"] if not _expired(x, today)}
    reported, events = [], []
    for f in verdict.get("findings") or []:
        k = key_of(f)
        seen = set(f.get("seen_by") or [])
        if len(seen) >= 2:
            events.append(dict(_ident(f), kind="corroborated"))     # settles any debate on it (rule 13)
        if k in real_mem:
            ever = seen | set(real_mem[k].get("seen_by") or [])
            if len(ever) >= 2 and len(seen) < 2:
                events.append(dict(_ident(f), kind="corroborated"))    # corroborated across days
            real_mem[k]["seen_by"] = sorted(ever)
            real_mem[k]["last_seen"] = today
            reported.append(f)
            continue
        if k in false_mem:
            before = false_mem[k]
            if len(seen | set(before.get("seen_by") or [])) >= 2:
                miss = dict(_ident(f), seen_by=sorted(seen | set(before.get("seen_by") or [])))
                out["misses"].append(miss)
                if before.get("vex"):
                    out["vex"].append(dict(_ident(f), status="affected", purls=list(before.get("purls") or []),
                                           impact_statement="another scanner reported it after the audits "
                                                            "judged it not affected (audit miss)"))
                del false_mem[k]
                real_mem[k] = dict(_ident(f), seen_by=miss["seen_by"], since=today, last_seen=today)
                if len(seen) < 2:
                    events.append(dict(_ident(f), kind="corroborated"))   # corroborated across days
                reported.append(f)
                continue
        if len(seen) >= 2:
            continue                                    # the rescan reports it (rule 5); nothing to judge
        r = judge_unique(f, bundles(f), profiles, auditors, st["seat"], scoring)
        entry = dict(_ident(f), seen_by=sorted(seen), status=r["status"], path=r["path"], audits=r["audits"],
                     why=r["why"])
        out["log"].append(entry)
        if r["debate"]:
            then = installed_versions(bundles(f), f)
            st["debates"].append(dict(_ident(f), on=today, settled=None,
                                      installed_then=(_ver(f.get("version")).lower() in then) if then is not None else None,
                                      **r["debate"]))
        if r["status"] == "report":
            if k in false_mem:      # a later audit reversed a remembered false judgment: that is an audit miss too
                before = false_mem.pop(k)
                out["misses"].append(dict(_ident(f), seen_by=sorted(seen), by="a later audit"))
                if before.get("vex"):       # rule 9: a published statement turns "affected" (Sonnet r4 blocker)
                    out["vex"].append(dict(_ident(f), status="affected", purls=list(before.get("purls") or []),
                                           impact_statement="a later audit found it present after the audits judged "
                                                            "it not affected (audit miss)"))
            real_mem[k] = dict(_ident(f), seen_by=sorted(seen), since=today, last_seen=today)
            reported.append(f)
            if r["path"] == "a" or any(_same_entry(x, f["seen_by"][0], f["package"]) for x in out["profiles"]):
                continue        # a recorded behavior took this finding (rule 8(a)), or today already proposes it
            prop = {"scanner": f["seen_by"][0], "kind": "sees_alone",
                    "match": {"package": "^%s$" % re.escape(f["package"])},
                    "behavior": r["why"] or "unexplained: the audits confirmed the finding but not why only this scanner saw it",
                    "finding": "%s on %s (%s %s), %s" % (f["id"], f["image"], f["package"], f["version"], today),
                    "evidence": "; ".join(r["proof"])[:500],
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
                            since=old.get("since") or today, last_seen=today, vex=bool(old.get("vex") or ev),
                            purls=list(old.get("purls") or purls_for(f)))
        if ev and not old.get("vex"):
            quotes = r["proof"]       # only quotes vote() validated against the image, never an answer's raw text
            elsewhere = [img for img in images if not _not_in_image(bundles, f, img)]
            purls = purls_for(f)
            if purls and images and not elsewhere:
                out["vex"].append(dict(_ident(f), status="not_affected", purls=purls,
                                       impact_statement="Audited from the images: " + "; ".join(quotes)[:500]))
            elif purls:
                # the statement would cover every image; one that has the package at that version (or could not be
                # read) means no statement — never broader than the evidence (Codex r3 B2)
                false_mem[k]["vex"] = False
                out["owner"].append("Scanner panel: %s on %s (%s %s) was judged not affected with evidence there, but "
                                    "the package at that version is present in, or could not be checked on: %s — so no "
                                    "VEX statement was written." % (f["id"], f["image"], f["package"], f["version"],
                                                                    ", ".join(elsewhere)))
            else:   # no exact package identity from any scanner: a statement could not be scoped; never a blanket one
                false_mem[k]["vex"] = False
                out["owner"].append("Scanner panel: %s on %s (%s %s) was judged not affected with evidence, but no "
                                    "scanner gave its package identity, so no VEX statement was written: %s" %
                                    (f["id"], f["image"], f["package"], f["version"], "; ".join(quotes)[:300]))
    seen_today = {key_of(f) for f in verdict.get("findings") or []}

    def reverse(k, entry, by, kind):
        out["misses"].append(dict(_ident(entry), seen_by=entry.get("seen_by") or [], by=by))
        if entry.get("vex"):
            out["vex"].append(dict(_ident(entry), status="affected", purls=list(entry.get("purls") or []),
                                   impact_statement="%s after the audits judged it not affected (audit miss)" % by))
        false_mem.pop(k, None)
        real_mem[k] = dict(_ident(entry), seen_by=entry.get("seen_by") or [], since=today, last_seen=today)
        reported.append(entry)
        events.append(dict(_ident(entry), kind=kind))
    # (1) a finding our own statement hides: the scanners whose results the tally filters record what they covered
    covered = {}
    for c in verdict.get("vex_covered") or []:
        covered.setdefault((str(c.get("id")).upper(), str(c.get("package")).lower(), _ver(c.get("version")).lower()),
                           set()).add(c.get("scanner"))
    for k, e in sorted(false_mem.items()):
        others = covered.get((str(e["id"]).upper(), str(e["package"]).lower(), _ver(e["version"]).lower()), set())
        if e.get("vex") and others - set(e.get("seen_by") or []):
            e["seen_by"] = sorted(set(e.get("seen_by") or []) | others)
            reverse(k, e, "another scanner reported it (hidden by our statement)", "corroborated")
    # (2) every remembered false judgment is re-checked against today's images
    for k, e in sorted(false_mem.items()):
        if not images:
            continue                # (re-judged false today or not reported today: both are re-checked)
        present = _present_in(bundles, e, images)
        if not present:
            continue
        if advisory and advisory(e):
            reverse(k, e, "an advisory names the package we ship", "advisory")
        elif e.get("vex"):          # the statement says absent; an image now has it: it cannot stand
            out["vex"].append(dict(_ident(e), status="affected", purls=list(e.get("purls") or []),
                                   impact_statement="an image now contains this package version; under investigation"))
            e["vex"] = False
            out["owner"].append("Scanner panel: %s (%s %s) was stated not affected, but %s now contain(s) that version; "
                                "the statement is turned affected." % (e["id"], e["package"], e["version"], ", ".join(present)))
    # (3) a fix shipped: the debated image HAD the debated version when debated, and today that same image is readable,
    # carries another version of the package, and no longer has the debated one (Codex final verification, item 1)
    for d in st["debates"]:
        if d.get("settled") or d.get("installed_then") is not True or key_of(d) in seen_today or d["image"] not in images:
            continue
        now = installed_versions(bundles(dict(d)), dict(d))
        if now and _ver(d["version"]).lower() not in now:
            events.append(dict(_ident(d), kind="fix-shipped"))
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
                members = lt.getmembers()

                def drop(prefix, exact=None):
                    for coll in (paths, status, gobins):
                        for gone in [x for x in coll if x == exact or x.startswith(prefix)]:
                            coll.remove(gone) if isinstance(coll, set) else coll.pop(gone)
                # whiteouts apply to the LOWER layers, before this layer's own entries are added
                for m in members:
                    name = "/" + m.name.lstrip("./")
                    base = os.path.basename(name)
                    if base == ".wh..wh..opq":          # opaque directory: nothing from lower layers survives in it
                        drop(os.path.dirname(name).rstrip("/") + "/")
                    elif base.startswith(".wh."):       # a removed file or directory, with everything below it
                        gone = os.path.join(os.path.dirname(name), base[4:])
                        drop(gone + "/", exact=gone)
                for m in members:
                    name = "/" + m.name.lstrip("./")
                    base = os.path.basename(name)
                    if base.startswith(".wh."):
                        continue
                    paths.add(name)
                    status.pop(name, None); gobins.pop(name, None)      # a later layer replaces the file
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
    lines = ["image %s (%s %s, reported by %s)" % (f.get("image"), pkg, f.get("version"), ", ".join(f.get("seen_by") or [])),
             EVIDENCE_MARK]
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
    toolchains = ["go build info %s: %s" % (b, text.splitlines()[0].strip()) for b, text in sorted(buildinfo.items())
                  if text.strip()]
    go = ["go build info %s: %s" % (b, ln.strip()) for b, text in sorted(buildinfo.items())
          for ln in text.splitlines()[1:] if pkg and pkg.lower() in ln.lower()]
    lines += toolchains + (go or ["go build info: no Go binary in the image records %s" % pkg])
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


def mint_oidc(audience, env=os.environ, opener=urllib.request.urlopen):
    """A fresh GitHub OIDC identity token for one audience, from the job's own endpoint (id-token: write), masked in
    the log at once. Minted inside this process, so a long debate never outlives its tokens."""
    url, tok = env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not url or not tok:
        raise RuntimeError("no GitHub OIDC endpoint in this job (needs id-token: write)")
    req = urllib.request.Request("%s&audience=%s" % (url, urllib.parse.quote(audience, safe="")),
                                 headers={"Authorization": "bearer " + tok})
    with opener(req, timeout=30) as r:
        value = json.load(r)["value"]
    print("::add-mask::" + value)
    return value


class TokenFile:
    """Keeps an identity-token file fresh for an SDK that reads its token from a file (re-mints after max_age)."""

    def __init__(self, path, audience, mint=mint_oidc, clock=time.time, max_age=240):
        self.path, self.audience, self.mint, self.clock, self.max_age, self.at = path, audience, mint, clock, max_age, None

    def fresh(self):
        if self.at is None or self.clock() - self.at > self.max_age:
            token = self.mint(self.audience)
            with open(self.path, "w") as fh:
                fh.write(token)
            self.at = self.clock()


class Budget:
    """The panel's per-run token budget (REQ-AUD-6 AC2): once spent, no seat is asked again this run; the unasked
    audits error (no evidence -> false by default, judged again tomorrow) and the run reports the stop."""

    def __init__(self, cap):
        self.cap, self.used, self.stopped = cap, 0, False

    def wrap(self, ask):
        def budgeted(req):
            if self.used >= self.cap:
                self.stopped = True
                return {"error": "the run's token budget is spent (%d of %d); not asked" % (self.used, self.cap)}
            a = ask(req)
            if isinstance(a, dict):
                self.used += int(a.pop("_tokens", 0) or 0)
            return a
        return budgeted


MODEL_PATHS = ("/v1/messages", "/v1/responses")


class SeatCapError(Exception):
    pass


class SeatCap:
    """The probe's request cap (retries disabled; Codex #155 phase-2 r2). Both pinned SDKs re-send once after a 401
    OUTSIDE max_retries (a federated token refresh), so max_retries=0 alone still allowed a second model request and
    hid the first failure. These HTTP hooks allow ONE model-endpoint request per seat, and turn a 401 from it into a
    named failure before the SDK can re-send. Token exchanges are not model requests and are not counted."""

    def __init__(self):
        self.sent, self.failure = 0, None

    def _fail(self, why):
        self.failure = self.failure or why
        raise SeatCapError(self.failure)

    def on_request(self, request):
        if request.url.path in MODEL_PATHS:
            self.sent += 1
            if self.sent > 1:
                self._fail("a second model request (an SDK retry) was refused: the probe sends one per seat")

    def on_response(self, response):
        if response.request.url.path in MODEL_PATHS and response.status_code == 401:
            self._fail("the model endpoint refused the federated token (HTTP 401)")


def capped_client(cap, transport=None):
    import httpx2
    kw = {"transport": transport} if transport is not None else {}
    return httpx2.Client(event_hooks={"request": [cap.on_request], "response": [cap.on_response]}, timeout=300, **kw)


def _capped(call, cap):
    """Run a seat's SDK call; a cap failure is reported as itself, never as the SDK's generic wrapper of it."""
    try:
        return call()
    except Exception:
        if cap is not None and cap.failure:
            raise SeatCapError(cap.failure) from None
        raise


def seat_a(env=os.environ, mint=mint_oidc, retries=None, transport=None):
    """Vendor A: the auditor's existing provider, through its existing federation (the SDK exchanges the identity
    token in ANTHROPIC_IDENTITY_TOKEN_FILE; workspace, organization and service account from the environment)."""
    import anthropic
    token = TokenFile(env["ANTHROPIC_IDENTITY_TOKEN_FILE"], "https://api.anthropic.com", mint=mint)
    token.fresh()
    cap = SeatCap() if retries == 0 else None
    client = anthropic.Anthropic(**({} if retries is None else {"max_retries": retries}),
                                 **({"http_client": capped_client(cap, transport)} if cap is not None else {}))
    model = env["PANEL_AUDIT_A_MODEL"]

    def ask(req):
        token.fresh()
        msg = _capped(lambda: client.messages.create(model=model, max_tokens=2048,
                                                     messages=[{"role": "user", "content": render(req)}]), cap)
        a = _answer("".join(getattr(b, "text", "") for b in msg.content))
        u = getattr(msg, "usage", None)
        a["_tokens"] = (getattr(u, "input_tokens", 0) or 0) + (getattr(u, "output_tokens", 0) or 0)
        return a
    return ask


def seat_b(env=os.environ, mint=mint_oidc, retries=2, transport=None):
    """Vendor B: workload identity federation (no key): a fresh GitHub identity token, minted on every exchange, is
    traded for a short-lived token bound to the configured service account; Responses API only."""
    from openai import OpenAI

    def token():
        return mint("https://api.openai.com/v1")
    cap = SeatCap() if retries == 0 else None
    client = OpenAI(workload_identity={"identity_provider_id": env["PANEL_AUDIT_B_IDENTITY_PROVIDER_ID"],
                                       "service_account_id": env["PANEL_AUDIT_B_SERVICE_ACCOUNT_ID"],
                                       "provider": {"token_type": "jwt", "get_token": token}},
                    project=env["PANEL_AUDIT_B_PROJECT_ID"], timeout=300, max_retries=retries,
                    **({"http_client": capped_client(cap, transport)} if cap is not None else {}))
    model = env["PANEL_AUDIT_B_MODEL"]

    def ask(req):
        r = _capped(lambda: client.responses.create(model=model, input=render(req), max_output_tokens=4096), cap)
        a = _answer(r.output_text)
        a["_tokens"] = getattr(getattr(r, "usage", None), "total_tokens", 0) or 0
        return a
    return ask


def unavailable(why):
    def ask(_req):
        return {"error": why}
    return ask


def make_seats(mode, env=os.environ, a=seat_a, b=seat_b, retries=None):
    if mode != "real":
        return {s: unavailable("no auditor in this run (%s)" % mode) for s in SEATS}
    seats = {}
    for s, make in (("A", a), ("B", b)):
        try:
            seats[s] = make(env) if retries is None else make(env, retries=retries)
        except Exception as e:   # a seat that cannot start errors every audit: no evidence, reported
            seats[s] = unavailable("seat %s could not start: %s: %s" % (s, type(e).__name__, public(e)))
    return seats


# ------------------------------------------------------------------------------------------------ commands

STATE = ".auditor/panel-state.json"
PROFILES = ".github/policy/scanner-profiles.json"
VEX = ".vex/fosterstack-cache.openvex.json"
ISSUE_TITLE = "Daily scanner panel: findings on main"           # shared with the rescan's two-or-more issue
OWNER_TITLE = policy.subject("owner-decision: scanner panel")   # one standing owner issue, updated, never duplicated


def automerge_allowed(changed, env=os.environ):
    """REQ-AUD-17 AC3/AC4, as the auditor applies it: only when the owner turned auto-merge on, and never for a day
    that proposes a scanner-profile entry (rule 7: profile entries are reviewed like any other change)."""
    on = (env.get("AUDITOR_AUTOMERGE") or "").strip().lower() in ("on", "true", "1", "yes")
    # only the panel's own records may auto-merge: its state and its VEX statements. A profile entry, a prompt, a workflow or any other path waits for the owner.
    return on and all(c in (STATE, VEX) for c in changed)


def _load_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default


SHA1 = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def rescan_binding(path, oci_dir):
    """(binding, None) or (None, why). The judgment is bound to the rescan it judges (owner RATIFIED Oct 3, item a;
    advisor 0113/0136): its run, the head it scanned, main's head now, its conclusion (any: a red rescan is judged), and
    the image digests of the evidence it left — every archive must name one, else the evidence is not that run's."""
    try:
        b = _load_json(path)
    except ValueError:
        b = None
    keys = ("run_id", "head", "main_head", "conclusion")
    if not isinstance(b, dict) or not all(isinstance(b.get(k), str) and b[k].strip() for k in keys) \
            or not SHA1.match(b["head"]) or not SHA1.match(b["main_head"]):
        return None, "no rescan binding (run, scanned head, main's head, conclusion) in %s" % path
    digests = {}
    for name in sorted(os.listdir(oci_dir)) if os.path.isdir(oci_dir) else []:
        if not name.endswith(".oci"):
            continue
        try:
            with tarfile.open(os.path.join(oci_dir, name)) as t:
                idx = json.loads(t.extractfile("index.json").read())
                ds = [m["digest"] for m in idx.get("manifests") or [] if DIGEST.match(str(m.get("digest", "")))]
                # every manifest the index names must itself be readable — a syntactically valid digest over a blob
                # that is missing or truncated is not usable evidence (Codex #177 r1, B2)
                for d in ds:
                    t.getmember("blobs/" + d.replace(":", "/"))
        except (OSError, ValueError, KeyError, AttributeError, tarfile.TarError):
            ds = []
        if not ds:
            return None, "the rescan's evidence %s has no image digest" % name
        digests[name[:-4]] = ", ".join(ds)
    if not digests:
        return None, "the rescan's evidence has no image digest (%s)" % oci_dir
    return dict({k: b[k] for k in keys}, digests=digests), None


def cmd_judge(a, seats=None, bundles=None, advisory=None):
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
    rescan, why = rescan_binding(a.rescan, a.oci)
    if why:
        sys.stderr.write("::error::auditor-panel: %s; nothing was judged\n" % why)
        return 2
    # every image the verdict judges must have its own READABLE evidence (Codex #177 r1/r2, B2) — a missing archive,
    # or one whose manifest/layers do not actually read, must never fall through to "no evidence, false by default"
    # as if that image had simply cleared. A present-but-unreadable blob (getmember alone proves nothing: truncated
    # JSON, a missing nested manifest or layer, the wrong architecture) is read the same way Bundles() will read it.
    images = sorted({f.get("image", "") for f in verdict.get("findings") or [] if f.get("image")})
    unreadable = []
    for img in images:
        variant, _, arch = img.rpartition("-")
        if variant not in rescan["digests"]:
            unreadable.append(img)
            continue
        try:
            read_image(os.path.join(a.oci, variant + ".oci"), arch)
        except (OSError, ValueError, KeyError, tarfile.TarError):
            unreadable.append(img)
    if unreadable:
        sys.stderr.write("::error::auditor-panel: the rescan's evidence is missing or unreadable for %s; nothing was "
                         "judged\n" % ", ".join(unreadable))
        return 2
    budget = Budget(a.token_budget)
    seats = {s: budget.wrap(ask) for s, ask in (seats or make_seats(a.seats)).items()}
    st, out = apply_day(verdict, state, bundles or Bundles(a.oci), profiles, seats, a.today, scoring_text(),
                        advisory=advisory if advisory is not None else (osv_advisory if a.seats == "real" else None))
    moved = rescan["main_head"] != rescan["head"]
    if moved:
        out["owner"].append("Scanner panel: main has moved past the scanned head %s (main is at %s); this judgment "
                            "names the scanned bytes only." % (rescan["head"], rescan["main_head"]))
    if rescan["conclusion"] != "success":
        out["owner"].append("Scanner panel: the rescan run %s finished %s; the panel judged its evidence (quorum, rule 3, "
                            "decides per image)." % (rescan["run_id"], rescan["conclusion"]))
    out["rescan"] = rescan
    st, out = scrub(st), scrub(out)      # everything written below is public (artifact, state file, PR)
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
                   st["seat"], st["scores"]["A"], st["scores"]["B"]),
               "Tokens used: %d of the run's budget of %d%s." % (budget.used, budget.cap,
                                                              " — STOPPED at the budget; the unasked audits are judged "
                                                              "again tomorrow" if budget.stopped else "")]
    summary += ["Judged rescan run %s of main at %s (conclusion %s); images: %s." % (
        rescan["run_id"], rescan["head"], rescan["conclusion"],
        "; ".join("%s %s" % kv for kv in sorted(rescan["digests"].items())))]
    summary += ["- audit error (vendor %s): %s" % (x["seat"], x["error"]) for x in errors]
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(public("\n".join(summary)) + "\n")
    for x in errors:
        print("::warning::scanner panel audit error (vendor %s): %s" % (x["seat"], x["error"]))
    if moved:
        print("::warning::scanner panel: main has moved past the scanned head %s (main is at %s)"
              % (rescan["head"], rescan["main_head"]))
    if budget.stopped:
        print("::warning::scanner panel: the run's token budget (%d) is spent; remaining audits were not asked" % budget.cap)
    print(public("\n".join(summary)))
    return 0


def statement_id(v):
    """The statement's scope: the repository's product (every image — written only when every image's evidence shows
    the package absent at that version) narrowed to the exact package purls (REQ-AUD-13 scope ids)."""
    return policy.scope_id(v["id"], policy.VEX_PRODUCT, v.get("purls") or [])


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
            sid = statement_id(v)
            if v["status"] == "not_affected":
                if any(stmt.get("@id") == sid for stmt in doc["statements"]):
                    continue                        # the same scope is stated once
                doc["statements"].append({
                    "@id": sid,
                    "vulnerability": {"name": v["id"]}, "timestamp": ts, "status": "not_affected",
                    "products": [{"@id": policy.VEX_PRODUCT, "subcomponents": subs}],
                    "justification": "component_not_present", "impact_statement": v["impact_statement"]})
            else:
                for stmt in doc["statements"]:
                    if stmt.get("@id") == sid:     # exactly the panel's statement for this CVE, image and package
                        stmt.update(status="affected", last_updated=ts,
                                    action_statement="Under investigation: " + v["impact_statement"])
                        stmt.pop("justification", None)
                        stmt.pop("impact_statement", None)
        doc["timestamp"], doc["version"] = ts, int(doc.get("version", 1)) + 1
        with open(vpath, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        changed.append(VEX)
    ppath = os.path.join(root, PROFILES)
    prof = _load_json(ppath) if day["profiles"] else None
    key = lambda e: (e.get("scanner"), e.get("kind"), (e.get("match") or {}).get("package"))
    # never twice: an entry the file (or its open PR) already holds is skipped
    new = [e for e in day["profiles"] if prof is not None and key(e) not in {key(x) for x in prof["entries"]}]
    if new:
        prof["entries"].extend(new)
        with open(ppath, "w") as fh:
            json.dump(prof, fh, indent=2)
            fh.write("\n")
        changed.append(PROFILES)
    return changed


def _sh(cmd, plan, real, run=subprocess.run, check=True, **kw):
    plan.append(cmd)
    if real:
        r = run(cmd, capture_output=True, text=True, **kw)
        if r.returncode != 0 and check:
            raise RuntimeError("%s failed: %s" % (cmd[0:3], public(r.stderr)[-400:]))
        return r.stdout
    return ""


def _conflict(path, why):
    return RuntimeError("auditor-panel: %s: the open PR and main both changed %s since the PR's base (conflict); refusing to pick a winner" % (path, why))


def carry_forward(repo, ref, base_ref, pr_files, plan, real, run):
    """Carry the open PR's OWN additions onto the freshly checked-out main: a three-way merge by content, not a copy of the PR's files (a copy would
    silently revert whatever main merged since). The state file is not carried: it is rewritten from the day's judgment. Returns the paths changed."""
    def show(r, path):
        return _sh(["git", "-C", repo, "show", "%s:%s" % (r, path)], plan, real, run, check=False)

    def read(path):
        full = os.path.join(repo, path)
        return open(full).read() if os.path.exists(full) else ""

    def write(path, text):
        full = os.path.join(repo, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)

    carried = []
    for path in sorted(set(pr_files)):
        if path == STATE:
            continue
        pr_txt, base_txt = show(ref, path), show(base_ref, path)
        if not pr_txt or pr_txt == base_txt:
            continue                                   # removed by the PR, or untouched by it
        cur_txt = read(path)
        if cur_txt == pr_txt:
            continue                                   # main already has exactly this
        if path == VEX:
            pr_doc, base_doc, cur_doc = json.loads(pr_txt), json.loads(base_txt or '{"statements": []}'), json.loads(cur_txt)
            base_by = {x.get("@id"): x for x in base_doc.get("statements", [])}
            cur_by = {x.get("@id"): x for x in cur_doc.get("statements", [])}
            touched = False
            for stmt in pr_doc.get("statements", []):
                sid = stmt.get("@id")
                if sid not in base_by:                 # a statement the PR ADDED
                    if sid not in cur_by:
                        cur_doc["statements"].append(stmt)
                        touched = True
                    elif cur_by[sid] != stmt:
                        raise _conflict(path, sid)
                elif stmt != base_by[sid]:             # a statement the PR CHANGED (e.g. turned to affected)
                    if cur_by.get(sid) == base_by[sid]:
                        cur_doc["statements"][[x.get("@id") for x in cur_doc["statements"]].index(sid)] = stmt
                        touched = True
                    elif cur_by.get(sid) != stmt:
                        raise _conflict(path, sid)
            if touched:
                cur_doc["timestamp"] = pr_doc.get("timestamp", cur_doc.get("timestamp"))
                cur_doc["version"] = int(cur_doc.get("version", 1)) + 1
                write(path, json.dumps(cur_doc, indent=2) + "\n")
                carried.append(path)
        elif path == PROFILES:
            pr_doc, base_doc, cur_doc = json.loads(pr_txt), json.loads(base_txt or '{"entries": []}'), json.loads(cur_txt)
            key = lambda e: (e.get("scanner"), e.get("kind"), (e.get("match") or {}).get("package"))
            have, base_keys = {key(e) for e in cur_doc["entries"]}, {key(e) for e in base_doc["entries"]}
            new = [e for e in pr_doc["entries"] if key(e) not in base_keys and key(e) not in have]
            if new:
                cur_doc["entries"].extend(new)
                write(path, json.dumps(cur_doc, indent=2) + "\n")
                carried.append(path)
        else:                                          # the panel writes ONLY its state, its VEX and its profile file: anything else on this branch is not ours
            raise RuntimeError("auditor-panel: the open PR's branch holds %s, which the panel never writes; refusing to carry it (a human pushed to the App's branch?)" % path)
    return carried


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
    # the base is ALWAYS the main commit this run is on (advisor 0186): a branch that builds on the open PR's old tip stays on the day it was first
    # opened, falls further behind, and can never merge under strict up-to-date checks. The open PR's branch is only READ: its files carry forward.
    base = os.environ.get("GITHUB_SHA") or "HEAD"
    existing = _sh(["gh", "pr", "list", "--head", branch, "--state", "open", "--json", "number,isCrossRepository", "--jq",
                    ".[] | select(.isCrossRepository == false) | .number"], plan, real, run).strip().split("\n")[0].strip()   # a fork's PR from a branch of this name is not ours
    pr_files, merge_base = [], ""
    if existing:
        _sh(["git", "-C", a.repo, "fetch", "--no-tags", "--depth=1000", "origin", "main"], plan, real, run, check=False)
        _sh(["git", "-C", a.repo, "fetch", "--no-tags", "--depth=1000", "origin", branch], plan, real, run)
        # no shared history within the fetched depth fails the command (and so the run): never a rebuild without knowing what the PR itself added
        merge_base = _sh(["git", "-C", a.repo, "merge-base", "FETCH_HEAD", base], plan, real, run).strip()
        if merge_base:  # the PR's own files come from git itself, not from what a listing says
            pr_files = [x for x in _sh(["git", "-C", a.repo, "diff", "--name-only", "-z", merge_base, "FETCH_HEAD"], plan, real, run).split("\0") if x]
    if existing and merge_base and pr_files and real:
        # only what the App itself pushed may be carried: the reserved-branch guard (a check on every push to auditor/*) must have passed on the PR branch's tip.
        # A human push to the App's branch fails that guard; carrying it into a fresh App commit would launder it past the guard and into auto-merge.
        tip = _sh(["git", "-C", a.repo, "rev-parse", "FETCH_HEAD"], plan, real, run).strip()
        verdict = _sh(["gh", "api", "repos/{owner}/{repo}/commits/%s/check-runs?check_name=only-the-app-pushes-auditor-lane" % tip, "--jq",
                       '.check_runs | map(.conclusion) | join(",")'], plan, real, run).strip()
        if verdict != "success":
            raise RuntimeError("auditor-panel: the open PR's branch tip %s has no passing reserved-branch guard (%r): it may hold a push that was not the App's; refusing to carry it forward"
                               % (tip[:12], verdict))
    _sh(["git", "-C", a.repo, "checkout", "--force", "-B", branch, base], plan, real, run)
    carried = carry_forward(a.repo, "FETCH_HEAD", merge_base, pr_files, plan, real, run) if existing and merge_base else []
    changed = list(carried)
    for path in apply_files(a.repo, st, day, a.today):
        if path not in changed:
            changed.append(path)
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
                 "--title", policy.subject("scanner panel audits (rules 7-9, 13, 14)"), "--body", body], plan, real, run)
    if changed or existing:     # the switch is re-checked every day, so it regains control of an armed PR (Sonnet r4)
        pr_paths = set(changed)
        if existing:            # the whole PR, not just today's change: yesterday's profile proposal still needs review
            pr_paths |= set(_sh(["gh", "pr", "diff", existing, "--name-only"], plan, real, run).split())
        if automerge_allowed(sorted(pr_paths)):
            _sh(["gh", "pr", "ready", branch], plan, real, run)
            _sh(["gh", "pr", "merge", "--auto", "--squash", branch], plan, real, run)
        elif existing:          # no longer allowed (a profile entry arrived, or the switch is off): disarm it if armed
            armed = _sh(["gh", "pr", "view", existing, "--json", "autoMergeRequest", "--jq", ".autoMergeRequest != null"],
                        plan, real, run).strip()
            if armed == "true" or not real:
                _sh(["gh", "pr", "merge", "--disable-auto", existing], plan, real, run)    # a failure stops delivery
    ienv = dict(os.environ, GH_TOKEN=os.environ.get("AUDITOR_ISSUES_TOKEN", os.environ.get("GH_TOKEN", "")))
    if day["issue"]:
        n = _sh(["gh", "issue", "list", "--state", "open", "--label", "daily-rescan", "--search", ISSUE_TITLE,
                 "--json", "number", "--jq", ".[0].number"], plan, real, run, env=ienv).strip()
        if n:                   # the rescan's tracking issue, when it is open
            _sh(["gh", "issue", "comment", n, "--body", day["issue"]], plan, real, run, env=ienv)
        else:                   # one the auditor opens carries the auditor's subject prefix (REQ-AUD-17 AC1)
            for lab in ("daily-rescan", "security"):    # a missing label would lose the issue: create it first (not forced)
                _sh(policy.label_create_cmd(lab), plan, real, run, check=False, env=ienv)
            _sh(["gh", "issue", "create", "--title", policy.subject(ISSUE_TITLE), "--label", "daily-rescan",
                 "--label", "security", "--body", day["issue"]], plan, real, run, env=ienv)
    if day["owner"]:
        body = public("Scanner panel, %s:\n\n%s" % (a.today, "\n\n".join(day["owner"])))
        n = _sh(["gh", "issue", "list", "--state", "open", "--label", policy.OWNER_LABEL, "--search", OWNER_TITLE,
                 "--json", "number", "--jq", ".[0].number"], plan, real, run, env=ienv).strip()
        if n:
            _sh(["gh", "issue", "comment", n, "--body", body], plan, real, run, env=ienv)
        else:
            _sh(policy.label_create_cmd(policy.OWNER_LABEL), plan, real, run, check=False, env=ienv)
            _sh(["gh", "issue", "create", "--title", OWNER_TITLE, "--label", policy.OWNER_LABEL,
                 "--assignee", policy.OWNER_LOGIN, "--body", body], plan, real, run, env=ienv)
    with open(os.path.join(a.out, "plan.json"), "w") as fh:
        json.dump(scrub({"real": real, "changed": changed, "commands": plan}), fh, indent=1)
    print("auditor-panel: delivered (%s): %d path(s), %d command(s)" % ("real" if real else "plan only", len(changed), len(plan)))
    return 0


PROBE_BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures", "panel", "probe-bundle.txt")
PROBE_FINDING = {"image": "probe-amd64", "id": "PROBE-0001", "package": "probe-pkg", "version": "1.0.0",
                 "seen_by": ["probe"]}


def cmd_probe(a, seats=None):
    """Prove both seats live (REQ-SCAN-008-AC3): one fixed audit per seat over a committed synthetic bundle, inside the
    run's token budget. Publishes nothing (no state, no PR, no issue); the summary names only the seats. Exit 0 only
    when both seats answered; a failing seat is reported with its masked error, never retried."""
    bundle = open(PROBE_BUNDLE).read()
    budget = Budget(a.token_budget)
    # retries disabled: each seat is asked exactly once (at most two model requests), and a failure is never retried
    seats = {s: budget.wrap(ask) for s, ask in (seats or make_seats(a.seats, retries=0)).items()}
    lines, ok = ["## Scanner panel seat probe", ""], True
    for s in SEATS:
        ans = _ask(seats[s], s, _request("audit", PROBE_FINDING, bundle))
        v = vote(ans, bundle, PROBE_FINDING)
        if ans.get("error"):
            ok = False
            lines.append("- vendor %s: error: %s" % (s, ans["error"]))
        elif v:
            lines.append("- vendor %s: answered with a valid vote (%s)" % (s, v))
        else:
            lines.append("- vendor %s: answered without a valid vote (the seat is reachable; its answer cited no "
                         "evidence from the bundle)" % s)
    lines += ["", "Tokens used: %d of the run's budget of %d." % (budget.used, budget.cap)]
    os.makedirs(a.out, exist_ok=True)
    text = public("\n".join(lines)) + "\n"
    with open(os.path.join(a.out, "summary.md"), "w") as fh:
        fh.write(text)
    print(text)
    return 0 if ok else 1


def main(argv=None, judge=cmd_judge, deliver=cmd_deliver, probe=cmd_probe):
    ap = argparse.ArgumentParser(prog="auditor-panel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("judge")
    j.add_argument("--verdict", required=True)
    j.add_argument("--state", required=True)
    j.add_argument("--profiles", required=True)
    j.add_argument("--oci", required=True)
    j.add_argument("--rescan", required=True, help="the rescan binding: run_id, head, main_head, conclusion (JSON)")
    j.add_argument("--out", required=True)
    j.add_argument("--seats", choices=("real", "none"), default="none")
    j.add_argument("--today", default=datetime.date.today().isoformat())
    j.add_argument("--token-budget", type=int, default=policy.TOKEN_BUDGET)
    d = sub.add_parser("deliver")
    d.add_argument("--out", required=True)
    d.add_argument("--repo", default=".")
    d.add_argument("--dry-run", action="store_true")
    d.add_argument("--today", default=datetime.date.today().isoformat())
    pr = sub.add_parser("probe")
    pr.add_argument("--out", required=True)
    pr.add_argument("--seats", choices=("real", "none"), default="none")
    pr.add_argument("--token-budget", type=int, default=policy.TOKEN_BUDGET)
    a = ap.parse_args(argv)
    return {"judge": judge, "deliver": deliver, "probe": probe}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
