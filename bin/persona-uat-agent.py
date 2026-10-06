#!/usr/bin/env python3
"""One persona's agent loop (REQ-UAT-001-AC1, AC4, AC5).

stdin : the driver's request JSON {persona, instructions, docs_dir, endpoint, image, model, token_budget, tools}
stdout: {"findings": [{"kind": "blocking|friction", "text": str}], "tokens": N, "transcript": str}
exit  : non-zero with NOTHING on stdout when the persona could not run (a provider that fails or leaves the protocol, a
        docker that cannot start): the driver then counts that persona as blocking, never as a pass.

The loop asks the provider (one process per call) for an action: run a shell command, or finish with findings. Every
shell command runs in the digest-pinned shell image through the driver's docker, with a FIXED argument vector: the model
supplies only the text after `sh -c`, never a docker option, so nothing it types can add a mount, a privilege or a
credential. The only mount is the persona's sandbox (the public docs). The token budget is a hard, cumulative stop:
once the owner's budget is reached the model is not called again (the cap is flagged by the driver, it adds no finding
here). A step limit is the second stop, for a model that spends nothing and never finishes.
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
BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT")
MODEL_ENV_PREFIX = "ANTHROPIC_"      # the model identity (key or federated-identity variables); the provider alone receives it
OUT_LIMIT = 8000                     # characters of each stream returned to the model
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
    if act.get("type") == "shell" and isinstance(act.get("command"), str) and act["command"].strip():
        return tokens, act
    if act.get("type") == "finish" and valid_findings(act.get("findings")):
        return tokens, act
    raise Fail("the provider's action is outside the protocol")


def run_shell(docker, shell_image, sandbox, command, timeout):
    # FIXED argument vector (pinned by the tests): the model's text is only ever the last argument
    argv = docker + ["run", "--rm", "--network", "host", "-v", "%s:/work" % sandbox, "-w", "/work", shell_image, "sh", "-c", command]
    rc, out, err, timed_out = run_bounded(argv, None, timeout, child_env(False))
    if timed_out:
        return "timed out after %ss (the command was cut off)" % timeout, None, False
    if rc == DOCKER_OWN_FAILURE:
        raise Fail("docker could not run the shell action: %s" % err.strip()[:200])
    return "exit status: %d\nstdout:\n%s\nstderr:\n%s" % (rc, clip(out), clip(err)), (rc, out), True


def reached(endpoint, command, res):
    """the command named the cache endpoint AND got an answer from it: exit 0 and output (a refused connection hidden by `|| true` leaves no output)"""
    if res is None or res[0] != 0 or not res[1].strip():
        return False
    u = urlparse(endpoint)
    hp = "%s:%s" % (u.hostname, u.port)
    return hp in command or ("localhost:%s" % u.port) in command


def system_prompt(req):
    return "\n".join([
        "You are a simulated customer doing an acceptance test of a software product, in the role described below.",
        "You may use only the public documentation in your working directory (README.md and the docs) and the product's running endpoint. "
        "Do not clone the repository, do not read its source, do not look for internal documents: a real customer cannot.",
        "Follow the documentation as written, step by step, with shell commands. Each command runs in a fresh minimal container whose "
        "working directory is /work (your documentation) on the host network, so the endpoint and tool endpoints below are reachable on 127.0.0.1.",
        "Reply with exactly one JSON object and nothing else. To run a command: {\"action\": \"shell\", \"command\": \"<sh command>\"}. "
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--docker", required=True)
    ap.add_argument("--shell-image", required=True)
    ap.add_argument("--provider-cmd")
    ap.add_argument("--shell-timeout", type=int, default=300)
    ap.add_argument("--provider-timeout", type=int, default=600)
    ap.add_argument("--max-steps", type=int, default=400)
    a = ap.parse_args()
    try:
        req = json.loads(sys.stdin.read())
        keys = ("persona", "instructions", "docs_dir", "endpoint", "image", "model", "token_budget", "tools")
        if (not isinstance(req, dict) or [k for k in keys if k not in req] or not isinstance(req["token_budget"], int)
                or isinstance(req["token_budget"], bool) or req["token_budget"] <= 0 or not isinstance(req["tools"], dict)
                or not all(isinstance(req[k], str) and req[k] for k in ("instructions", "docs_dir", "endpoint", "model"))):
            raise Fail("the request is not the driver's contract")
        docker = shlex.split(a.docker)
        # the provider is started with `python3` from PATH (never sys.executable: the SDK lives with the PATH's interpreter)
        provider = shlex.split(a.provider_cmd) if a.provider_cmd else ["python3", os.path.join(os.path.dirname(os.path.abspath(__file__)), "persona-uat-provider.py")]
        system = system_prompt(req)
        messages = [{"role": "user", "content": first_message(req)}]
        transcript, findings, ended = [], None, "finish"
        used = steps = shells = 0
        contacted = False
        while True:
            if used >= req["token_budget"]:
                transcript.append("[token budget reached: the model is not called again]")
                ended = "budget"
                break
            if steps >= a.max_steps:
                transcript.append("[step limit reached]")
                ended = "steplimit"
                findings = [{"kind": "blocking", "text": "the persona did not finish: the step limit (%d model calls) was reached" % a.max_steps}]
                break
            tokens, act = call_provider(provider, req["model"], system, messages, a.provider_timeout)
            steps += 1
            used += tokens
            if act["type"] == "finish":
                findings = act["findings"]
                transcript.append("[finish] %s" % json.dumps(findings))
                break
            shells += 1
            text, res, ran = run_shell(docker, a.shell_image, req["docs_dir"], act["command"], a.shell_timeout)
            contacted = contacted or reached(req["endpoint"], act["command"], res)
            transcript.append("$ %s\n%s" % (act["command"], text))
            messages.append({"role": "assistant", "content": json.dumps(act)})
            messages.append({"role": "user", "content": text})
        findings = list(findings or [])
        # a pass must be earned: the persona ran something, and a clean finish needs an answer from the endpoint
        if ended == "finish" and shells == 0:
            findings.append({"kind": "blocking", "text": "the persona finished without running a single shell action: nothing was exercised"})
        elif ended == "finish" and not findings and not contacted:
            findings.append({"kind": "blocking", "text": "the persona never got an answer from the cache endpoint (no command named it and exited 0 with output): a clean pass is not credible"})
        out = {"findings": findings, "tokens": used, "transcript": "\n".join(transcript) + "\n"}
    except Fail as e:
        sys.stderr.write("persona-uat-agent: %s\n" % e)
        return 1
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
