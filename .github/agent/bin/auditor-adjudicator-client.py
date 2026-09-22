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
    prompt = ("Propose a disposition (false_positive | not_affected_unreachable | "
              "real_fixable | risk_acceptance) for %s in our own image. Reason only about "
              "whether our code reaches the vulnerable path; do not produce exploit code. "
              "Your answer is a proposal our code re-verifies against scanner evidence."
              % req.get("finding_id"))
    msg = client.messages.create(model=model, max_tokens=512,
                                 messages=[{"role": "user", "content": prompt}])
    text = "".join(getattr(b, "text", "") for b in msg.content)
    cat = next((c for c in ("false_positive", "not_affected_unreachable", "real_fixable",
                            "risk_acceptance") if c in text), "under_investigation")
    json.dump({"refused": "cannot" in text.lower() and cat == "under_investigation",
               "category": cat, "proposed": True}, sys.stdout)


if __name__ == "__main__":
    main()
