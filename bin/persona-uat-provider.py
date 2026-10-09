#!/usr/bin/env python3
"""The persona UAT's model provider: one model call per process (REQ-UAT-001-AC5).

stdin : {"model": str, "system": str, "messages": [{"role", "content"}]}
stdout: {"usage": {"tokens": N}, "action": {"type": "shell", "command": str} | {"type": "finish", "findings": [...]}}

The model is whatever the request names (the owner's variable, set by the driver); no model is chosen or remembered here.
The provider is the only process that holds the model identity. It speaks one protocol and fails closed: a reply that is
not exactly a shell action or a finish exits non-zero with nothing on stdout, so the agent (and then the driver) counts
the persona as did-not-run, never as a pass. Authentication is whatever the SDK reads from the environment the agent
passes down (the federated identity variables or a key); nothing is read or logged here.
"""
import json
import sys

MAX_TOKENS = 4096        # one reply is one short action; the owner's token budget is the real bound, enforced by the agent


def fail(msg):
    sys.stderr.write("persona-uat-provider: %s\n" % msg)
    sys.exit(1)


def finding(f):
    if (not isinstance(f, dict) or sorted(f) != ["kind", "text"] or f["kind"] not in ("blocking", "friction")
            or not isinstance(f["text"], str) or not f["text"].strip()):
        fail("a finding is not exactly {kind: blocking|friction, text: non-empty string}")
    return {"kind": f["kind"], "text": f["text"]}


def parse_action(text):
    """the first JSON object in the reply that carries an `action` (a reply may wrap it in prose)"""
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _ = dec.raw_decode(text[i:])
        except ValueError:
            continue
        if isinstance(obj, dict) and "action" in obj:
            break
    else:
        fail("the reply holds no JSON action")
    kind = obj.get("action")
    if kind == "shell":
        tool = obj.get("tool")
        if "tool" in obj and not isinstance(tool, str):
            fail("tool is not a string")
        if "tool" not in obj or tool == "shell":
            cmd = obj.get("command")
            if not isinstance(cmd, str) or not cmd.strip() or "args" in obj:
                fail("a shell action needs a non-empty command and no args")
            out = {"type": "shell", "command": cmd}
            if "tool" in obj:
                out = {"type": "shell", "tool": tool, "command": cmd}
            return out
        args = obj.get("args")
        if "command" in obj or not isinstance(args, list) or not args or not all(isinstance(x, str) for x in args):
            fail("a tool action needs args (a list of strings) and no command")
        return {"type": "shell", "tool": tool, "args": args}
    if kind == "finish":
        fs = obj.get("findings")
        if not isinstance(fs, list):
            fail("a finish needs a findings list")
        return {"type": "finish", "findings": [finding(f) for f in fs]}
    fail("unknown action")


def main():
    try:
        req = json.loads(sys.stdin.read())
    except ValueError:
        fail("the request is not JSON")
    if (not isinstance(req, dict) or not isinstance(req.get("model"), str) or not req["model"].strip()
            or not isinstance(req.get("system"), str) or not isinstance(req.get("messages"), list) or not req["messages"]):
        fail("the request needs a model, a system prompt and messages")
    import anthropic    # imported only here: the SDK is installed (hash-pinned) by the persona jobs and nowhere else
    client = anthropic.Anthropic()
    resp = client.messages.create(model=req["model"], max_tokens=MAX_TOKENS, system=req["system"], messages=req["messages"])
    text = "".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    u = resp.usage
    tokens = getattr(u, "input_tokens", None), getattr(u, "output_tokens", None)
    if any(isinstance(t, bool) or not isinstance(t, int) or t < 0 for t in tokens):
        fail("the reply carries no usable token count")
    action = parse_action(text)
    print(json.dumps({"usage": {"tokens": tokens[0] + tokens[1]}, "action": action}))


try:
    main()
except SystemExit:
    raise
except Exception as e:      # an SDK error, an auth error, a network error: the persona did not run
    fail("%s: %s" % (type(e).__name__, str(e)[:300]))
