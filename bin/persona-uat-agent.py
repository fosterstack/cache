#!/usr/bin/env python3
"""One persona's agent loop (REQ-UAT-001-AC1, AC4, AC5).

stdin : the driver's request JSON {persona, instructions, docs_dir, endpoint, image, model, token_budget, tools}
stdout: {"findings": [{"kind": "blocking|friction", "text": str}], "tokens": N, "transcript": str, "commands": [str], "exits": [int]}
        (`exits` holds the exit status of each executed command, in the order of `commands`)
exit  : non-zero with NOTHING on stdout when the persona could not run (a provider that fails or leaves the protocol, a
        docker that cannot start): the driver then counts that persona as blocking, never as a pass.

The loop asks the provider (one process per call) for an action: run a shell command, or finish with findings. Every
shell command runs in the digest-pinned shell image through the driver's docker, with a FIXED argument vector: the model
supplies only the text after `sh -c`, never a docker option, so nothing it types can add a mount, a privilege or a
credential. The only mount is the persona's sandbox (the public docs). The token budget is a hard, cumulative stop:
15% of it is reserved for ONE forced final `finish` call. The loop works until 85% of the budget is spent, then asks once
for the findings so far; a model that cannot finish then (another action, a failing provider) is BLOCKING ("did not finish
within its budget"), never a pass. Tokens are the provider's own per-call numbers, summed. A step limit is the second stop,
for a model that spends nothing and never finishes. With --transcript-file every executed action is appended to that file
(scrubbed, flushed and fsynced) before the next model call, so a kill keeps what was completed.
"""
import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
from urllib.parse import urlparse

# environment handed to a child: a shell's own settings plus the docker client's; a job credential is never inherited
# SHELL_ENV and DOCKER_ENV are duplicated verbatim in persona-uat.py (a test asserts they are equal), so this process and the driver
# address the same docker daemon
SHELL_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR")
DOCKER_ENV = ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION")
BASE_ENV = SHELL_ENV + DOCKER_ENV
MODEL_ENV_PREFIX = "ANTHROPIC_"      # the model identity (key or federated-identity variables); the provider alone receives it
OUT_LIMIT = 8000                     # characters of each stream returned to the model
ACTION_TOOLS = ("shell", "cosign", "kubectl", "gradle", "maven")
DIGEST_REF = re.compile(r"^[a-z0-9][^\s@]*@sha256:[0-9a-f]{64}$")
DOCKER_OWN_FAILURE = 125             # docker's exit status for ITS failure (daemon, image); 126/127 are indistinguishable from the command's own


class Fail(Exception):
    pass


def child_env(with_model):
    env = {k: os.environ[k] for k in BASE_ENV if k in os.environ}
    if with_model:
        env.update({k: v for k, v in os.environ.items() if k.startswith(MODEL_ENV_PREFIX)})
    return env


def run_bounded(argv, stdin_text, timeout, env, cwd=None):
    """run argv with a hard timeout; on timeout the client gets SIGTERM (docker proxies it to the container), then SIGKILL"""
    p = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, cwd=cwd, text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(stdin_text, timeout=timeout)
        return p.returncode, out, err, False
    except subprocess.TimeoutExpired:
        for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 30)):
            try:
                os.killpg(p.pid, sig)
            except ProcessLookupError:
                pass
            try:
                out, err = p.communicate(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                continue
        else:
            out, err = "", ""
        return None, out or "", err or "", True


def clip(s):
    return s if len(s) <= OUT_LIMIT else s[:OUT_LIMIT] + "\n[truncated: %d more characters]" % (len(s) - OUT_LIMIT)


def valid_findings(fs):
    return (isinstance(fs, list) and all(isinstance(f, dict) and sorted(f) == ["kind", "text"] and f["kind"] in ("blocking", "friction")
                                         and isinstance(f["text"], str) for f in fs))


def call_provider(cmd, model, system, messages, timeout):
    rc, out, err, timed_out = run_bounded(cmd, json.dumps({"model": model, "system": system, "messages": messages}), timeout, child_env(True))
    if timed_out or rc != 0:
        raise Fail("the provider failed (exit %s)" % ("timeout" if timed_out else rc))
    try:
        a = json.loads(out)
    except ValueError:
        raise Fail("the provider's answer is not JSON")
    tokens = a.get("usage", {}).get("tokens") if isinstance(a, dict) and isinstance(a.get("usage"), dict) else None
    act = a.get("action") if isinstance(a, dict) else None
    if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0 or not isinstance(act, dict):
        raise Fail("the provider's answer is outside the protocol")
    if act.get("type") == "shell":
        t = act.get("tool", "shell")
        if not isinstance(t, str):
            raise Fail("the provider's action is outside the protocol")
        if t == "shell" or "tool" not in act:
            if isinstance(act.get("command"), str) and act["command"].strip() and "args" not in act:
                return tokens, act
        else:
            if "command" not in act and isinstance(act.get("args"), list) and act["args"] and all(isinstance(x, str) for x in act["args"]):
                return tokens, act
    if act.get("type") == "finish" and valid_findings(act.get("findings")):
        return tokens, act
    raise Fail("the provider's action is outside the protocol")


RESERVE = 0.15                       # of the token budget: kept for the forced final finish call
FORCED_FINISH = ("You have reached your token budget and cannot run any more commands. Reply now with a finish action: "
                 "{\"action\": \"finish\", \"findings\": [...]} reporting your findings so far (what you observed, quoting the failing step), and nothing else.")
LABEL_RE = re.compile(r"^persona-uat=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
SCRUB = [re.compile(x) for x in (r"gh[pousr]_[A-Za-z0-9]{8,}", r"github_pat_[A-Za-z0-9_]{8,}", r"\bsk-[A-Za-z0-9_-]{12,}", r"\b(AKIA|ASIA)[0-9A-Z]{12,}", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}", r"-----BEGIN", r"(?i)bearer[\s-]+\S+", r"(?i)password\s*[=:]\s*\S+")]


def scrub(text, model):
    if model:
        text = text.replace(model, "[scrubbed]")
    for r in SCRUB:
        text = r.sub("[scrubbed]", text)
    return text


def run_shell(docker, image, sandbox, act, timeout, label=None):
    # FIXED argument vector (pinned by the tests): the model's text is only ever after the image
    tail = ["sh", "-c", act["command"]] if "command" in act else list(act["args"])
    argv = docker + ["run", "--rm", "--network", "host", "--label", label, "-v", "%s:/work" % sandbox, "-w", "/work", image] + tail
    rc, out, err, timed_out = run_bounded(argv, None, timeout, child_env(False))
    if timed_out:
        ids = run_bounded(docker + ["ps", "-aq", "--filter", "label=" + label], None, 30, child_env(False))[1].split()
        if ids:
            run_bounded(docker + ["rm", "-f"] + ids, None, 60, child_env(False))
        return "timed out after %ss (the command was cut off)" % timeout, None, False
    if rc == DOCKER_OWN_FAILURE:
        raise Fail("docker could not run the shell action: %s" % err.strip()[:200])
    return "exit status: %d\nstdout:\n%s\nstderr:\n%s" % (rc, clip(out), clip(err)), (rc, out), True


def open_stream(path):
    """the transcript file (the driver's private file, outside the sandbox); a file that cannot be written means no run at all"""
    if not path:
        return None
    try:
        return open(path, "w", encoding="utf-8", errors="replace")
    except OSError as e:
        raise Fail("the transcript file cannot be written: %s" % e)


def system_prompt(req):
    return "\n".join([
        "You are a simulated customer doing an acceptance test of a software product, in the role described below.",
        "You may use only the public documentation in your working directory (README.md and the docs) and the product's running endpoint. "
        "Do not clone the repository, do not read its source, do not look for internal documents: a real customer cannot.",
        "Follow the documentation as written, step by step, with shell commands. Each command runs in a fresh minimal container whose "
        "working directory is /work (your documentation) on the host network, so the endpoint and tool endpoints below are reachable on 127.0.0.1.",
        "Reply with exactly one JSON object and nothing else. To run a command: {\"action\": \"shell\", \"tool\": \"shell\", \"command\": \"<sh command>\"}. "
        "To run another tool (cosign, kubectl, gradle, maven) give its args as a list: {\"action\": \"shell\", \"tool\": \"cosign\", \"args\": [\"version\"]}. "
        "For gradle and maven the FIRST element of args is the program (\"gradle\", \"mvn\"); for cosign and kubectl it is the subcommand. ",
        "When you are done: {\"action\": \"finish\", \"findings\": [{\"kind\": \"blocking\" or \"friction\", \"text\": \"<what happened>\"}]}.",
        "Each command's result comes back with its exit status, stdout and stderr. Report only what you observed, quoting the failing step.",
        "",
        "Your role and task:",
        req["instructions"],
    ])


def first_message(req):
    return "\n".join([
        "Endpoint: %s" % req["endpoint"],
        "Image under test: %s" % req["image"],
        "Tools available for this task (container id, endpoint and any kubeconfig file in your working directory): %s" % json.dumps(req["tools"], sort_keys=True),
        "Begin.",
    ])


def main():
    holder = []
    ap = argparse.ArgumentParser()
    ap.add_argument("--docker", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--provider-cmd")
    ap.add_argument("--shell-timeout", type=int, default=300)
    ap.add_argument("--provider-timeout", type=int, default=600)
    ap.add_argument("--max-steps", type=int, default=400)
    ap.add_argument("--transcript-file")
    a = ap.parse_args()
    try:
        req = json.loads(sys.stdin.read())
        keys = ("persona", "instructions", "docs_dir", "endpoint", "image", "model", "token_budget", "tools")
        if (not isinstance(req, dict) or [k for k in keys if k not in req] or not isinstance(req["token_budget"], int)
                or isinstance(req["token_budget"], bool) or req["token_budget"] <= 0 or not isinstance(req["tools"], dict)
                or not all(isinstance(req[k], str) and req[k] for k in ("instructions", "docs_dir", "endpoint", "model"))):
            raise Fail("the request is not the driver's contract")
        try:
            tools = json.load(open(a.tools))
        except (OSError, ValueError):
            raise Fail("the tools file is unreadable")
        if not isinstance(tools, dict) or "shell" not in tools or not all(isinstance(v, str) and DIGEST_REF.match(v) for v in tools.values()):
            raise Fail("the tools file is not a map of digest-pinned images with a shell")
        if not LABEL_RE.match(a.label):
            raise Fail("--label is not persona-uat=<uuid>")
        docker = shlex.split(a.docker)
        # the provider is started with `python3` from PATH (never sys.executable: the SDK lives with the PATH's interpreter)
        provider = shlex.split(a.provider_cmd) if a.provider_cmd else ["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "persona-uat-provider.py")]
        system = system_prompt(req)
        messages = [{"role": "user", "content": first_message(req)}]
        transcript, findings, ended = [], None, "finish"
        holder.append(transcript); holder.append(req["model"])
        used = steps = shells = 0
        commands, exits = [], []
        stream = open_stream(a.transcript_file)

        def note(entry):
            """one transcript entry: kept in memory and, when asked, appended to the transcript file and made durable before anything else happens"""
            transcript.append(entry)
            if stream is not None:
                stream.write(scrub(entry, req["model"]) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        while True:
            if used >= req["token_budget"] * (1 - RESERVE):
                # the reserve: ONE forced call asks for the findings so far; whatever else comes back, the persona did not finish within its budget
                note("[token budget reached: one forced finish call, then no more]")
                messages[-1] = {"role": "user", "content": messages[-1]["content"] + "\n\n" + FORCED_FINISH}      # the last message is always the user's (the task or a tool result)
                try:
                    tokens, act = call_provider(provider, req["model"], system, messages, a.provider_timeout)
                    used += tokens
                except Fail:
                    act = None
                if act is not None and act["type"] == "finish":
                    findings = act["findings"]
                    note("[finish] %s" % json.dumps(findings))
                else:
                    ended = "budget"
                    findings = [{"kind": "blocking", "text": "the persona did not finish within its budget (%d tokens): its findings so far were lost" % req["token_budget"]}]
                    note("[no finish within the budget]")
                break
            if steps >= a.max_steps:
                note("[step limit reached]")
                ended = "steplimit"
                findings = [{"kind": "blocking", "text": "the persona did not finish: the step limit (%d model calls) was reached" % a.max_steps}]
                break
            tokens, act = call_provider(provider, req["model"], system, messages, a.provider_timeout)
            steps += 1
            used += tokens
            if act["type"] == "finish":
                findings = act["findings"]
                note("[finish] %s" % json.dumps(findings))
                break
            tool = act.get("tool", "shell")
            label = act["command"] if "command" in act else "%s %s" % (tool, " ".join(act["args"]))
            if tool not in ACTION_TOOLS or tool not in tools:
                text = "refused: unknown tool %r; the tools are %s" % (tool, ", ".join(ACTION_TOOLS))
                note("$ %s\n%s" % (label, text))
                messages.append({"role": "assistant", "content": json.dumps(act)})
                messages.append({"role": "user", "content": text})
                continue
            shells += 1
            commands.append(label)
            text, res, ran = run_shell(docker, tools[tool], req["docs_dir"], act, a.shell_timeout, a.label)
            exits.append(res[0] if res else 124)        # a timed-out action has no status of its own: 124, like timeout(1)
            note("$ %s\n%s" % (label, text))
            messages.append({"role": "assistant", "content": json.dumps(act)})
            messages.append({"role": "user", "content": text})
        findings = list(findings or [])
        # a pass must be earned: the persona ran something, and a clean finish needs an answer from the endpoint
        if ended == "finish" and shells == 0:
            findings.append({"kind": "blocking", "text": "the persona finished without running a single shell action: nothing was exercised"})
        out = {"findings": findings, "tokens": used, "transcript": scrub("\n".join(transcript) + "\n", req["model"]), "commands": [scrub(c, req["model"]) for c in commands], "exits": exits}
    except Fail as e:
        if holder:
            sys.stderr.write(scrub("\n".join(holder[0]), holder[1]) + "\n")
        sys.stderr.write("persona-uat-agent: %s\n" % e)
        return 1
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
