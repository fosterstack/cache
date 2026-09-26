#!/usr/bin/env python3
"""Real model adjudicator client (production default). Reads the federated identity
token from $ANTHROPIC_IDENTITY_TOKEN_FILE and the workspace/model identifiers from the
environment, and asks the model to PROPOSE a disposition for one finding. The code that
calls this always re-verifies the proposal against evidence before writing any VEX, so a
compromised or wrong answer cannot itself produce a suppression. Reads one request as
JSON on stdin, prints one answer on stdout (same contract as the stub). Never used by the
suite (which passes --adjudicator <stub>); it is the workflow's default."""
import json, os, re, sys

# The identifiers/tokens that must never reach the uploaded report. We surface the REAL error
# (class, HTTP status, message) so a failure is diagnosable, but with these values redacted.
_SECRET_ENVS = ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
                "AUDITOR_MODEL_PRIMARY", "AUDITOR_MODEL_FALLBACK", "SNYK_TOKEN",
                "AUDITOR_APP_PRIVATE_KEY", "ANTHROPIC_API_KEY")


def _mask(s):
    s = str(s or "")
    for k in _SECRET_ENVS:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            s = s.replace(v, "<%s>" % k)
    s = re.sub(r"claude-[A-Za-z0-9._-]+", "<model-id>", s)
    s = re.sub(r"sk-[A-Za-z0-9._-]{6,}", "<redacted-key>", s)
    s = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]{6,}", "Bearer <redacted>", s)
    return s


def _err_detail(step, e):
    """(step, masked detail) for an SDK error. A 401/403 status is an identity/federation failure
    (the scoped-token exchange), not the model call; secrets and model ids are masked."""
    status = getattr(e, "status_code", None) or getattr(e, "status", None)
    if status in (401, 403):
        step = "identity/federation"
    return step, "%s%s: %s" % (type(e).__name__, (" status=%s" % status) if status else "", _mask(str(e)))


def _fail(step, e):
    """One-shot fatal: write the masked step failure to stderr and exit (the driver surfaces it)."""
    step, detail = _err_detail(step, e)
    sys.stderr.write("adjudicator-client: %s step failed: %s\n" % (step, detail))
    sys.exit(5)


def _build_client():
    """Construct the SDK client ONCE. The federated identity token is exchanged on the first API
    call and its access token is cached in this process, so a whole run's findings reuse one
    exchange (a fresh exchange per subprocess reused the identity token's jti -> jti_reused)."""
    token_file = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
    if not token_file or not os.path.exists(token_file):
        sys.stderr.write("adjudicator-client: no identity token file; cannot reach the model\n")
        sys.exit(3)
    try:
        import anthropic  # the SDK exchanges the identity token for a scoped access token
    except Exception as e:
        sys.stderr.write("adjudicator-client: sdk-import step failed: %s: %s\n"
                         % (type(e).__name__, _mask(str(e))))
        sys.exit(4)
    try:
        return anthropic.Anthropic()  # SDK reads ANTHROPIC_IDENTITY_TOKEN_FILE + workspace env
    except Exception as e:
        _fail("identity/federation", e)


_PROMPT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "prompts", "adjudicator.md")


def _load_prompt(key):
    """Load a named prompt section from the versioned prompt file (REQ-AUD-16 AC2): the model's
    standing instructions live in the repo and change only through reviewed PRs — never inline
    here. A section is a '## <key>' heading; its body runs to the next '## ' or EOF."""
    try:
        text = open(_PROMPT_FILE).read()
    except Exception:
        return None
    out = []; grab = False
    for ln in text.splitlines():
        if ln.startswith("## "):
            grab = (ln[3:].strip() == key)
            continue
        if grab:
            out.append(ln)
    return "\n".join(out).strip() or None


def _fill(tmpl, **kw):
    for k, v in kw.items():
        tmpl = tmpl.replace("{%s}" % k, v)
    return tmpl


def _handle(req, client):
    """One adjudication (or narrative) against the shared client. Raises the SDK error on a
    model-call/federation failure; the caller decides whether to exit (one-shot) or return an
    {"error": ...} answer (serve)."""
    model = os.environ.get("AUDITOR_MODEL_PRIMARY")
    if req.get("attempt") == "fallback":
        model = os.environ.get("AUDITOR_MODEL_FALLBACK", model)
    if req.get("mode") == "narrative":
        # R12 item 3: write the top-of-report Conclusion from the STRUCTURED results only.
        prompt = _fill(_load_prompt("narrative"), context=json.dumps(req.get("structured"), indent=1))
        msg = client.messages.create(model=model, max_tokens=512,
                                     messages=[{"role": "user", "content": prompt}])
        text = "".join(getattr(b, "text", "") for b in msg.content)
        return {"refused": False, "narrative": text, "token_usage": _usage(msg)}
    if req.get("kind") == "pullability" or req.get("attempt") == "pullability":
        # REQ-AUD-14: a scanner names a FIXED version, but the fix may not be PULLABLE — the
        # vulnerable component is carried inside another artifact (static/vendored/embedded) or held
        # by our pinned base under the reproducibility policy. Ask the model to do the carrier
        # analysis from the SBOM evidence and base metadata and answer as ONE JSON object; our code
        # re-verifies (requires a hold + lift trigger) before writing any affected VEX.
        ctxp = json.dumps({k: req.get(k) for k in
                           ("finding_id", "package", "purl", "installed_version", "component",
                            "component_fixed", "carrier", "base", "candidate_digest")
                           if req.get(k) is not None}, indent=1)
        prompt = _fill(_load_prompt("pullability"), context=ctxp)
        msg = client.messages.create(model=model, max_tokens=1024,
                                     messages=[{"role": "user", "content": prompt}])
        text = "".join(getattr(b, "text", "") for b in msg.content)
        ans = _extract_json(text) or {}
        ans["refused"] = bool("cannot" in text.lower() and "pullable" not in ans)
        ans.setdefault("proposed", True)
        ans["token_usage"] = _usage(msg)
        return ans
    # Full finding context, not a bare id (R11 rank 6): the model reasons about THIS package,
    # version, scanner set, and reachability summary. Its answer is still only a proposal our
    # code re-verifies against evidence before any VEX is written.
    ctx = "\n".join("- %s: %s" % (k, req.get(k)) for k in
                    ("finding_id", "aliases", "package", "purl", "installed_version",
                     "fixed_version", "scanners", "severity", "reachability", "candidate_digest")
                    if req.get(k) is not None)
    ask = ("rephrase the question plainly and answer" if req.get("attempt") == "rephrase"
           else "answer")
    # {knowledge} is the doc generated from our structured records (REQ-AUD-16 AC3), passed in by
    # the driver; the model reads it for pattern judgment but never free-writes it.
    knowledge = req.get("knowledge") or "(no prior scanner-defect or package patterns recorded yet)"
    prompt = _fill(_load_prompt("disposition"), ask=ask, knowledge=knowledge, context=ctx)
    msg = client.messages.create(model=model, max_tokens=512,
                                 messages=[{"role": "user", "content": prompt}])
    text = "".join(getattr(b, "text", "") for b in msg.content)
    cat = next((c for c in ("false_positive", "not_affected_unreachable", "real_fixable",
                            "risk_acceptance") if c in text), "under_investigation")
    ans = {"refused": "cannot" in text.lower() and cat == "under_investigation",
           "category": cat, "proposed": True, "token_usage": _usage(msg)}
    # REQ-AUD-16 AC4: the model MAY propose a new defect-log/knowledge entry (with evidence). Pass
    # it through under "propose"; the driver delivers it in the draft PR and it takes effect only
    # after merge. The model never edits its own instructions or the live records here.
    p = _extract_json(text)
    if isinstance(p, dict) and isinstance(p.get("propose"), dict):
        ans["propose"] = p["propose"]
    return ans


def main():
    client = _build_client()   # ONE client / ONE exchange for the whole run
    if "--serve" in sys.argv:
        # The driver keeps this process for the run and sends one request per line. A per-request
        # model-call failure is returned as {"error": ...} (masked) WITHOUT exiting, so the one
        # exchange is preserved and every finding is answered from the same process.
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                ans = _handle(json.loads(line), client)
            except Exception as e:
                step, detail = _err_detail("model-call", e)
                ans = {"error": "adjudicator-client: %s step failed: %s" % (step, detail)}
            sys.stdout.write(json.dumps(ans) + "\n")
            sys.stdout.flush()
        return
    # one-shot back-compat
    try:
        ans = _handle(json.load(sys.stdin), client)
    except Exception as e:
        _fail("model-call", e)
    json.dump(ans, sys.stdout)


def _extract_json(text):
    """The first top-level JSON OBJECT in a model response (the model may wrap it in prose or a
    code fence). Uses json.raw_decode from each '{', which respects strings — so a value that
    itself contains a '}' does not break extraction (Codex round-2 P2). Returns the dict or None."""
    s = str(text or "")
    dec = json.JSONDecoder()
    i = s.find("{")
    while i != -1:
        try:
            obj, _end = dec.raw_decode(s[i:])
            if isinstance(obj, dict):
                return obj
        except ValueError:
            pass
        i = s.find("{", i + 1)
    return None


def _usage(msg):
    """Real token cost from the SDK response so the driver's budget actually advances
    (R1 outer round-1 #8)."""
    u = getattr(msg, "usage", None)
    if not u:
        return 0
    return int(getattr(u, "input_tokens", 0) or 0) + int(getattr(u, "output_tokens", 0) or 0)


if __name__ == "__main__":
    main()
