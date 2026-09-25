#!/usr/bin/env python3
"""Real model adjudicator client (production default). Reads the federated identity
token from $ANTHROPIC_IDENTITY_TOKEN_FILE and the workspace/model identifiers from the
environment, and asks the model to PROPOSE a disposition for one finding. The code that
calls this always re-verifies the proposal against evidence before writing any VEX, so a
compromised or wrong answer cannot itself produce a suppression. Reads one request as
JSON on stdin, prints one answer on stdout (same contract as the stub). Never used by the
suite (which passes --adjudicator <stub>); it is the workflow's default."""
import json, os, sys


def main():
    req = json.load(sys.stdin)
    token_file = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
    if not token_file or not os.path.exists(token_file):
        sys.stderr.write("adjudicator-client: no identity token file; cannot reach the model\n")
        sys.exit(3)
    model = os.environ.get("AUDITOR_MODEL_PRIMARY")
    if req.get("attempt") == "fallback":
        model = os.environ.get("AUDITOR_MODEL_FALLBACK", model)
    try:
        import anthropic  # the SDK exchanges the identity token for a scoped access token
    except Exception:
        sys.stderr.write("adjudicator-client: anthropic SDK not installed in this runner\n")
        sys.exit(4)
    client = anthropic.Anthropic()  # SDK reads ANTHROPIC_IDENTITY_TOKEN_FILE + workspace env
    if req.get("mode") == "narrative":
        # R12 item 3: write the top-of-report Conclusion from the STRUCTURED results only.
        prompt = ("Write the audit Conclusion for our own container image from ONLY the "
                  "structured results below: what was examined (image digest, per-scanner "
                  "package counts, scanners that did not run), what was found, what was decided "
                  "and on what evidence, and what needs the owner. Three to six sentences; on a "
                  "clean day, one sentence with the numbers. Name only CVE/GO ids present in the "
                  "sections; do not contradict a section. Do not produce exploit code.\n\n%s"
                  % json.dumps(req.get("structured"), indent=1))
        try:
            msg = client.messages.create(model=model, max_tokens=512,
                                         messages=[{"role": "user", "content": prompt}])
        except Exception:
            # NEVER surface the SDK error text: it can name the configured model id, and
            # this stderr is captured and written into the uploaded report.
            sys.stderr.write("adjudicator-client: model call failed\n"); sys.exit(5)
        text = "".join(getattr(b, "text", "") for b in msg.content)
        json.dump({"refused": False, "narrative": text, "token_usage": _usage(msg)}, sys.stdout)
        return
    # Full finding context, not a bare id (R11 rank 6): the model reasons about THIS package,
    # version, scanner set, and reachability summary. Its answer is still only a proposal our
    # code re-verifies against evidence before any VEX is written.
    ctx = "\n".join("- %s: %s" % (k, req.get(k)) for k in
                    ("finding_id", "aliases", "package", "purl", "installed_version",
                     "fixed_version", "scanners", "severity", "reachability", "candidate_digest")
                    if req.get(k) is not None)
    ask = ("rephrase the question plainly and answer" if req.get("attempt") == "rephrase"
           else "answer")
    prompt = ("You are the vulnerability adjudicator for our own container image. Given this "
              "finding, %s with a disposition (false_positive | not_affected_unreachable | "
              "real_fixable | risk_acceptance). Reason ONLY about whether our code reaches the "
              "vulnerable path; do NOT produce exploit code. Your answer is a proposal our code "
              "re-verifies against scanner evidence.\n\n%s" % (ask, ctx))
    try:
        msg = client.messages.create(model=model, max_tokens=512,
                                     messages=[{"role": "user", "content": prompt}])
    except Exception:
        sys.stderr.write("adjudicator-client: model call failed\n"); sys.exit(5)
    text = "".join(getattr(b, "text", "") for b in msg.content)
    cat = next((c for c in ("false_positive", "not_affected_unreachable", "real_fixable",
                            "risk_acceptance") if c in text), "under_investigation")
    json.dump({"refused": "cannot" in text.lower() and cat == "under_investigation",
               "category": cat, "proposed": True, "token_usage": _usage(msg)}, sys.stdout)


def _usage(msg):
    """Real token cost from the SDK response so the driver's budget actually advances
    (R1 outer round-1 #8)."""
    u = getattr(msg, "usage", None)
    if not u:
        return 0
    return int(getattr(u, "input_tokens", 0) or 0) + int(getattr(u, "output_tokens", 0) or 0)


if __name__ == "__main__":
    main()
