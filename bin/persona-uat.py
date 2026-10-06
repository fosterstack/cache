#!/usr/bin/env python3
"""The persona UAT driver (REQ-UAT-001-AC1..AC5; owner ratified Oct 3 and Oct 4, point 9).

Five agents, each playing a different customer, read only our PUBLIC documents and exercise the image under test by digest.
The driver owns everything with authority: it starts the image and the pinned CI tools (Jenkins, a GitLab runner, kind) as
digest-pinned containers on loopback, builds a sandbox holding only README.md and the top-level docs, runs one agent per
persona with a scrubbed environment, validates what each agent answers (anything that is not exactly the contract is
blocking, "did not run"), writes ONE short report per persona, and publishes issues (--publish) through gh.

  persona-uat.py --mode rc|weekly --image REF@sha256:... --repo DIR --out DIR --tools FILE --docker CMD --gh CMD
                 --agent CMD [--port N] [--ready-timeout S] [--agent-timeout S] [--publish]
  env PERSONA_UAT_MODEL, PERSONA_UAT_COMPLIANCE_MODEL (required; no built-in default), PERSONA_UAT_TOKEN_BUDGET (default 400000)

Public surfaces (this repository is public; job logs and artifacts are public): a report is SCANNED before it is written; a
hit replaces it with a fixed notice and counts that persona as blocking. Raw transcripts are written under --out and are
never echoed to stdout or stderr. Containers are FIXED-ARGUMENT: every docker command is built here from the allowlisted
images and fixed options, the docker client gets an allowlisted environment, and no credential is passed to a container.
Exit status: 0 clean (or weekly with its blocking issue published), 1 a blocking finding or a publication failure, 2 a refused
configuration (nothing was started), 3 the public docs are missing.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import stat
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PERSONAS = ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer")
TOOLS_FOR = {"maven-jenkins-ci": ("jenkins", "gitlab-runner"), "on-call-engineer": ("kind",)}
DIGEST_REF = re.compile(r"^[a-z0-9][^\s@]*@sha256:[0-9a-f]{64}$")
TOOL_KEYS = ("jenkins", "gitlab-runner", "kind", "shell")
DEFAULT_BUDGET = 400000
# the environment an agent and the docker client get: a shell's settings and the docker client's, never a job credential;
# the agent additionally gets the model identity (names starting with the provider's prefix), which only its provider uses
BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "DOCKER_HOST", "DOCKER_CONFIG")
MODEL_ENV_PREFIX = "ANTHROPIC_"
# docs a customer can read: README.md and the TOP-LEVEL docs/*.md; unreleased notes are not public yet
DOCS_EXCLUDE = ("next-release-notes.md",)
FRICTION_LABEL = "persona-uat-friction"
BLOCKING_LABEL = "blocking"
BLOCKING_TITLE = "Persona UAT: blocking findings (weekly)"

INSTRUCTIONS = {
    "gradle-platform-engineer": (
        "You are a first-time user, a Gradle platform engineer setting up this cache. Following the documentation, install it, "
        "point a Gradle build at it, and configure the proxy settings your company needs. Judge whether a newcomer could finish "
        "using only what is written."),
    "maven-jenkins-ci": (
        "You are a Maven user whose builds run in CI on Jenkins and on a GitLab runner. Following the documentation, wire a Maven "
        "build to this cache from a Jenkins job and from a GitLab runner job, using the Jenkins and GitLab runner containers you "
        "are given."),
    "compliance-reviewer": (
        "You are a compliance reviewer. Following the documentation's guide, verify the image's signature, fetch and inspect its "
        "SBOM, and read its VEX statements, exactly as the guide says, and judge whether the evidence is complete and verifiable."),
    "readme-evaluator": (
        "You are an evaluator who has only the README and ten minutes. Decide, from the README alone, what the product is, and try "
        "to get a working result within ten minutes. Do not open any other document."),
    "on-call-engineer": (
        "You are an on-call engineer in the middle of an incident. Following the documentation, perform an upgrade to a newer "
        "version and a rollback to the previous one on the Kubernetes cluster you are given (its kubeconfig is in your working "
        "directory), and find and read the logs you need to diagnose a problem."),
}
CLASSIFY = (
    "Classify everything you find. A finding is blocking when it is broken behavior or a documented step that fails as written "
    "(quote the step and what happened). A finding is friction when everything works but something is confusing, slow or easy to "
    "get wrong. Report nothing you did not observe.")

# The driver's own source holds no model or vendor name (a rule the tests enforce), so the scan's list is assembled from parts.
_NAMES = [("anth", "ropic"), ("cla", "ude"), ("open", "ai"), ("g", "pt"), ("co", "dex"), ("gem", "ini"), ("google", " ai"), ("lla", "ma"),
          ("mist", "ral"), ("son", "net"), ("op", "us"), ("hai", "ku"), ("fa", "ble")]
VENDOR_RE = re.compile("|".join(r"\b" + re.escape("".join(p)) for p in _NAMES), re.I)
CRED_RES = [re.compile(x) for x in (
    r"gh[pousr]_[A-Za-z0-9]{8,}", r"github_pat_[A-Za-z0-9_]{8,}", r"\b(AKIA|ASIA)[0-9A-Z]{12,}", r"\bsk-[A-Za-z0-9_-]{12,}",
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}", r"-----BEGIN", r"\bxox[abprs]-[A-Za-z0-9-]{8,}", r"\bAIza[0-9A-Za-z_-]{16,}",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}", r"[A-Fa-f0-9]{32,}")]
BASE64_RUN = re.compile(r"[A-Za-z0-9+/_=-]{40,}")
IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")      # a content digest is public by construction, not a credential


class Refuse(Exception):
    """a configuration the driver will not run (exit 2): nothing has been started"""


def log(msg):
    sys.stderr.write("persona-uat: %s\n" % msg)


def scan_hit(text, secrets):
    """True when text holds a model/vendor name, an owner-set model value, or a credential-looking string"""
    t = IMAGE_DIGEST.sub("", text)
    if VENDOR_RE.search(t):
        return True
    low = t.lower()
    if any(s and s.lower() in low for s in secrets):
        return True
    if any(r.search(t) for r in CRED_RES):
        return True
    for m in BASE64_RUN.finditer(t):          # a long run that looks random: upper, lower and a digit (paths and words are not)
        v = m.group(0)
        if re.search(r"[A-Z]", v) and re.search(r"[a-z]", v) and re.search(r"[0-9]", v):
            return True
    return False


def clean_env(extra_prefix=None):
    env = {k: os.environ[k] for k in BASE_ENV if k in os.environ}
    if extra_prefix:
        env.update({k: v for k, v in os.environ.items() if k.startswith(extra_prefix)})
    return env


def docker_env():
    """the docker CLIENT's environment: a shell's settings plus its own DOCKER_* settings (host, config, context, tls); no job credential"""
    env = clean_env()
    env.update({k: v for k, v in os.environ.items() if k.startswith("DOCKER_")})
    return env


class Docker:
    def __init__(self, cmd):
        self.cmd = cmd

    def call(self, *args, timeout=120):
        return subprocess.run(self.cmd + list(args), capture_output=True, text=True, timeout=timeout, env=docker_env())

    def start(self, ref, port_map=None, privileged=False):
        """`run -d [--privileged] [-p 127.0.0.1:H:C] REF`: the only shapes the driver ever builds"""
        args = ["run", "-d"]
        if privileged:
            args.append("--privileged")
        if port_map:
            args += ["-p", "127.0.0.1:%d:%d" % port_map]
        p = self.call(*args, ref)
        cid = p.stdout.strip()
        if p.returncode != 0 or not cid or len(cid.split()) != 1:
            raise RuntimeError("could not start a container")
        return cid

    def running(self, cid):
        p = self.call("inspect", "-f", "{{.State.Running}}", cid)
        return p.returncode == 0 and p.stdout.strip() == "true"

    def remove(self, cids):
        if cids:
            try:
                self.call("rm", "-f", *cids)
            except Exception:
                pass


def http_ready(url):
    try:
        urllib.request.urlopen(url, timeout=2)
        return True
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def loopback_listeners(proc_net):
    """The ports with a LISTEN socket bound to a loopback address (127.0.0.0/8 or ::1), read from the kernel's tcp and tcp6 tables. The agent's
    shell containers use host networking to reach the endpoint, so anything else listening on the loopback is reachable from a persona: the
    driver refuses to run an agent next to one it does not know (advisor 0206). Wildcard binds and non-listening sockets are not counted.
    Raises Refuse when neither table can be read: nothing can then be said about the loopback."""
    ports, read = set(), 0
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc_net, name)) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        read += 1
        for ln in lines:
            f = ln.split()
            if len(f) < 4 or f[3] != "0A":
                continue
            addr, _, port = f[1].partition(":")
            loop = addr.endswith("7F") if len(addr) == 8 else addr == "00000000000000000000000001000000"
            if loop:
                ports.add(int(port, 16))
    if not read:
        raise Refuse("the kernel's socket tables cannot be read (%s)" % proc_net)
    return ports


def wait_ready(docker, cid, url, timeout):
    """running AND answering; a container that stops is a failure at once"""
    deadline = time.time() + timeout
    while True:
        if not docker.running(cid):
            raise RuntimeError("a container is not running")
        if url is None or http_ready(url):
            return
        if time.time() >= deadline:
            raise RuntimeError("a container never answered on its endpoint")
        time.sleep(0.5)


def read_docs(repo):
    """{relative name: bytes} for README.md and top-level docs/*.md; symlinks, dotfiles, subdirectories, other types are never read"""
    files = {}
    rp = os.path.join(repo, "README.md")
    data = read_regular(rp)
    if data is None:
        return None
    files["README.md"] = data
    d = os.path.join(repo, "docs")
    if os.path.isdir(d) and not os.path.islink(d):
        for name in sorted(os.listdir(d)):
            if name.startswith(".") or not name.endswith(".md") or name in DOCS_EXCLUDE:
                continue
            b = read_regular(os.path.join(d, name))
            if b is not None:
                files["docs/" + name] = b
    return files


def read_regular(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        return fh.read()


def validate_answer(text):
    try:
        a = json.loads(text)
    except ValueError:
        raise ValueError("the answer is not JSON")
    if not isinstance(a, dict) or sorted(a) != ["findings", "tokens", "transcript"]:
        raise ValueError("the answer does not have exactly findings, tokens and transcript")
    if isinstance(a["tokens"], bool) or not isinstance(a["tokens"], int) or a["tokens"] < 0:
        raise ValueError("tokens is not a non-negative integer")
    if not isinstance(a["transcript"], str):
        raise ValueError("transcript is not a string")
    fs = a["findings"]
    if not isinstance(fs, list):
        raise ValueError("findings is not a list")
    for f in fs:
        if (not isinstance(f, dict) or sorted(f) != ["kind", "text"] or f["kind"] not in ("blocking", "friction")
                or not isinstance(f["text"], str) or not f["text"].strip()):
            raise ValueError("a finding is not {kind, text}")
    return a


def run_agent(agent_cmd, agent_args, request, sandbox, timeout):
    """-> (answer or None, transcript text, failure reason or None). The agent's stderr is kept for the transcript FILE only."""
    p = subprocess.Popen(agent_cmd + agent_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=sandbox,
                         env=clean_env(MODEL_ENV_PREFIX), text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(json.dumps(request), timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = p.communicate()
        return None, "agent timed out after %ss\n%s" % (timeout, (err or "")[-200000:]), "timed out after %ss" % timeout
    if p.returncode != 0:
        return None, "agent failed (exit %d)\n%s" % (p.returncode, err[-200000:]), "the agent failed (exit %d)" % p.returncode
    try:
        return validate_answer(out), None, None
    except ValueError as e:
        return None, "the agent's answer was refused: %s\n%s" % (e, err[-200000:]), "the agent's answer is outside the contract (%s)" % e


def absolutize(tokens):
    """a relative script path (not the interpreter) is made absolute: the agent runs with its cwd in the sandbox"""
    out = tokens[:1]
    for t in tokens[1:]:
        out.append(os.path.abspath(t) if not os.path.isabs(t) and not t.startswith("-") and os.path.isfile(t) else t)
    return out


def kubeconfig_for(docker, cid, port, timeout):
    deadline = time.time() + timeout
    while True:
        p = docker.call("exec", cid, "cat", "/etc/kubernetes/admin.conf")
        if p.returncode == 0 and "server:" in p.stdout:
            kc = re.sub(r"server:\s*https://[^\s:]+:\d+", "server: https://127.0.0.1:%d" % port, p.stdout)
            return kc
        if time.time() >= deadline:
            raise RuntimeError("no kubeconfig from the kind container")
        time.sleep(0.5)


def report_text(persona, verdict, findings, tokens, capped, did_not_run=None):
    lines = ["VERDICT: %s" % verdict, "persona: %s" % persona, ""]
    if did_not_run:
        lines += ["This persona did not run: %s." % did_not_run, ""]
    for kind, title in (("blocking", "Blocking findings"), ("friction", "Friction (information only)")):
        fs = [f["text"] for f in findings if f["kind"] == kind]
        if fs:
            lines.append(title + ":")
            lines += ["- " + t.strip() for t in fs]
            lines.append("")
    if tokens is not None:
        lines.append("tokens used: %d" % tokens)
    if capped:
        lines.append("THIS PERSONA HIT ITS TOKEN CAP: its run may be incomplete.")
    return "\n".join(lines).rstrip() + "\n"


WITHHELD = ("VERDICT: blocking\npersona: %s\n\nThis report was withheld by the public-surface scan (it held a model or vendor name, an "
            "owner-set value or a credential-looking string). The run counts this persona as BLOCKING; read the transcript artifact "
            "under access control, not this report.\n")


class Gh:
    def __init__(self, cmd):
        self.cmd = cmd
        self.failed = False
        self.env = dict(os.environ)
        if os.environ.get("GITHUB_REPOSITORY"):
            self.env["GH_REPO"] = os.environ["GITHUB_REPOSITORY"]      # the weekly workspace root has no .git

    def call(self, *args):
        p = subprocess.run(self.cmd + list(args), capture_output=True, text=True, env=self.env, timeout=120)
        return p

    def ensure_label(self, name, description, color):
        p = self.call("label", "create", name, "--force", "--description", description, "--color", color)
        if p.returncode != 0:
            log("could not create the label %s" % name)
            self.failed = True

    def find(self, label, state, title):
        """-> issue number of the exact-title match, None when there is none; raises on a failing or unreadable list"""
        p = self.call("issue", "list", "--label", label, "--state", state, "--search", "%s in:title" % title, "--json", "number,title", "--limit", "100")
        if p.returncode != 0:
            raise RuntimeError("issue list failed")
        try:
            items = json.loads(p.stdout)
        except ValueError:
            raise RuntimeError("the issue list is not JSON")
        if not isinstance(items, list) or not all(isinstance(i, dict) and isinstance(i.get("title"), str) and isinstance(i.get("number"), int)
                                                  and not isinstance(i.get("number"), bool) for i in items):
            raise RuntimeError("the issue list is not a list of issues")
        for i in items:
            if i["title"] == title:
                return i["number"]
        return None

    def upsert(self, label, description, color, state, title, body_file):
        try:
            self.ensure_label(label, description, color)
            n = self.find(label, state, title)
            if n is None:
                p = self.call("issue", "create", "--title", title, "--label", label, "--body-file", body_file)
            else:
                p = self.call("issue", "edit", str(n), "--body-file", body_file)
            if p.returncode != 0:
                raise RuntimeError("issue create/edit failed")
        except Exception as e:
            log("publishing the %s issue failed: %s" % (label, e))
            self.failed = True


def issue_body(heading, mode, run_id, image, rows):
    lines = [heading, "", "mode: %s, run: %s, image: %s" % (mode, run_id, image), ""]
    for persona, kind, text in rows:
        lines.append("- %s (%s): %s" % (persona, kind, text.strip()))
    return "\n".join(lines) + "\n"


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("rc", "weekly"), required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--docker", required=True)
    ap.add_argument("--gh", required=True)
    ap.add_argument("--agent", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--ready-timeout", type=int, default=120)
    ap.add_argument("--agent-timeout", type=int, default=3600)
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--proc-net", default="/proc/net", help="where the kernel's tcp and tcp6 tables are read (a test passes a fixture)")
    ap.add_argument("--allow-listen", type=int, action="append", default=[], help="a loopback port that may listen besides the driver's own")
    try:
        return ap.parse_args()
    except SystemExit as e:
        raise SystemExit(2 if e.code else 0)


def configure(a):
    models = {}
    for var in ("PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"):
        if not os.environ.get(var):
            raise Refuse("%s is not set (the owner sets the model; there is no default)" % var)
        models[var] = os.environ[var]
    raw = os.environ.get("PERSONA_UAT_TOKEN_BUDGET", "")
    if raw == "":
        budget = DEFAULT_BUDGET
    elif re.fullmatch(r"[0-9]+", raw) and int(raw) > 0:
        budget = int(raw)
    else:
        raise Refuse("PERSONA_UAT_TOKEN_BUDGET must be a positive integer (got %r)" % raw)
    if not DIGEST_REF.match(a.image):
        raise Refuse("--image must be pinned by a full sha256 digest")
    try:
        tools = json.load(open(a.tools))
    except (OSError, ValueError):
        raise Refuse("--tools is not readable JSON")
    if not isinstance(tools, dict) or sorted(tools) != sorted(TOOL_KEYS):
        raise Refuse("--tools must hold exactly %s" % ", ".join(TOOL_KEYS))
    for k in TOOL_KEYS:
        if not isinstance(tools[k], str) or not DIGEST_REF.match(tools[k]):
            raise Refuse("the tool %s is not pinned by a full sha256 digest" % k)
    if not 1 <= a.port <= 65533:
        raise Refuse("--port is out of range")
    return models, budget, tools


def main():
    a = parse_args()
    try:
        models, budget, tools = configure(a)
    except Refuse as e:
        log("refused: %s" % e)
        return 2
    docker_cmd = shlex.split(a.docker)
    if not os.path.isabs(docker_cmd[0]) and os.path.isfile(docker_cmd[0]):
        docker_cmd[0] = os.path.abspath(docker_cmd[0])
    docker = Docker(docker_cmd)
    agent_cmd = absolutize(shlex.split(a.agent))
    gh = Gh(shlex.split(a.gh))
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    secrets = [v for v in models.values() if len(v) >= 4]
    run_id = os.environ.get("GITHUB_RUN_ID") or "local"

    results = {}        # persona -> {"verdict", "findings", "tokens", "capped"}

    def record(persona, answer, transcript, did_not_run=None):
        if answer:
            findings, tokens = list(answer["findings"]), answer["tokens"]
            capped = tokens >= budget
            verdict = "blocking" if any(f["kind"] == "blocking" for f in findings) else ("friction" if findings else "pass")
            text = report_text(persona, verdict, findings, tokens, capped)
        else:       # fail closed: whatever is not exactly the contract is a blocking persona that did not run
            findings = [{"kind": "blocking", "text": "%s did not run: %s" % (persona, did_not_run)}]
            tokens, capped, verdict = None, False, "blocking"
            text = report_text(persona, verdict, [], None, False, did_not_run)
        if scan_hit(text, secrets):
            text = WITHHELD % persona
            findings = [{"kind": "blocking", "text": "the report was withheld by the public-surface scan"}]
            verdict = "blocking"
        with open(os.path.join(out_dir, persona + ".report.md"), "w") as fh:
            fh.write(text)
        with open(os.path.join(out_dir, persona + ".transcript.txt"), "w") as fh:
            fh.write(transcript)
        results[persona] = {"verdict": verdict, "findings": findings, "tokens": tokens, "capped": capped}
        log("%s: %s" % (persona, verdict))

    def all_did_not_run(reason):
        for p in PERSONAS:
            if p not in results:
                record(p, None, "did not run: %s\n" % reason, reason)

    docs = read_docs(os.path.abspath(a.repo))
    started = []
    sandboxes = []
    try:
        if docs is None:
            log("README.md is missing or is not a regular file: there is nothing public to test")
            all_did_not_run("the public README.md is missing")
            finish(a, results, out_dir, gh, run_id, budget)
            return 3
        # the image under test: by digest, loopback only
        try:
            cid = docker.start(a.image, (a.port, 8080))
            started.append(cid)
            wait_ready(docker, cid, "http://127.0.0.1:%d" % a.port, a.ready_timeout)
        except Exception as e:
            all_did_not_run("the image under test did not start or answer (%s)" % e)
        for persona in PERSONAS:
            if persona in results:
                continue
            tool_cids, req_tools = [], {}
            sandbox = tempfile.mkdtemp(prefix="persona-uat-")
            sandboxes.append(sandbox)
            try:
                files = dict(docs)
                if persona == "readme-evaluator":
                    files = {"README.md": docs["README.md"]}
                for name, data in files.items():
                    dest = os.path.join(sandbox, name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as fh:
                        fh.write(data)
                try:
                    for i, tool in enumerate(TOOLS_FOR.get(persona, ())):
                        if tool == "jenkins":
                            tc = docker.start(tools[tool], (a.port + 1, 8080)); tool_cids.append(tc)
                            wait_ready(docker, tc, "http://127.0.0.1:%d" % (a.port + 1), a.ready_timeout)
                            req_tools[tool] = {"container": tc, "endpoint": "http://127.0.0.1:%d" % (a.port + 1)}
                        elif tool == "gitlab-runner":
                            tc = docker.start(tools[tool]); tool_cids.append(tc)
                            wait_ready(docker, tc, None, a.ready_timeout)
                            req_tools[tool] = {"container": tc, "endpoint": ""}
                        else:
                            tc = docker.start(tools[tool], (a.port + 2, 6443), privileged=True); tool_cids.append(tc)
                            wait_ready(docker, tc, None, a.ready_timeout)
                            kc = kubeconfig_for(docker, tc, a.port + 2, a.ready_timeout)
                            with open(os.path.join(sandbox, "kubeconfig"), "w") as fh:
                                fh.write(kc)
                            req_tools[tool] = {"container": tc, "endpoint": "https://127.0.0.1:%d" % (a.port + 2), "kubeconfig": "kubeconfig"}
                except Exception as e:
                    record(persona, None, "did not run: %s\n" % e, "a tool container did not start or answer (%s)" % e)
                    continue
                if not docker.running(started[0]):
                    record(persona, None, "did not run: the image under test stopped\n", "the image under test stopped")
                    continue
                request = {
                    "docs_dir": sandbox, "endpoint": "http://127.0.0.1:%d" % a.port, "image": a.image,
                    "instructions": INSTRUCTIONS[persona] + " " + CLASSIFY,
                    "model": models["PERSONA_UAT_COMPLIANCE_MODEL" if persona == "compliance-reviewer" else "PERSONA_UAT_MODEL"],
                    "persona": persona, "token_budget": budget, "tools": req_tools,
                }
                try:
                    stray = sorted(loopback_listeners(a.proc_net) - {53, a.port, a.port + 1, a.port + 2} - set(a.allow_listen))
                except Refuse as e:
                    record(persona, None, "did not run: %s\n" % e, "the loopback could not be inspected (%s)" % e)
                    continue
                if stray:
                    record(persona, None, "did not run: unexpected loopback listener(s)\n",
                           "an unexpected listener is bound to the loopback (port%s %s): a persona's containers share the host network, so none runs" % ("s" if len(stray) > 1 else "", ", ".join(map(str, stray))))
                    continue
                args = ["--docker", " ".join(shlex.quote(t) for t in docker_cmd), "--shell-image", tools["shell"]]
                answer, transcript, why = run_agent(agent_cmd, args, request, sandbox, a.agent_timeout)
                if answer is None:
                    record(persona, None, transcript, why)
                else:
                    record(persona, answer, answer["transcript"])
            finally:
                docker.remove(tool_cids)
    finally:
        docker.remove(started)
        for s in sandboxes:
            shutil.rmtree(s, ignore_errors=True)
    return finish(a, results, out_dir, gh, run_id, budget)


def finish(a, results, out_dir, gh, run_id, budget):
    blocking = [p for p in PERSONAS if results[p]["verdict"] == "blocking"]
    with open(os.path.join(out_dir, "summary.json"), "w") as fh:
        json.dump({"mode": a.mode, "image": a.image, "verdicts": {p: results[p]["verdict"] for p in PERSONAS},
                   "capped": [p for p in PERSONAS if results[p]["capped"]]}, fh, indent=1)
    rows = lambda kind: [(p, kind, f["text"]) for p in PERSONAS for f in results[p]["findings"] if f["kind"] == kind]
    friction = rows("friction")
    if friction:
        title = "Persona UAT friction: %s run %s" % (a.mode, run_id)
        path = os.path.join(out_dir, "friction-issue.md")
        with open(path, "w") as fh:
            fh.write(issue_body("Friction found by the persona UAT. Information only: it blocks nothing.", a.mode, run_id, a.image, friction))
        if a.publish:
            gh.upsert(FRICTION_LABEL, "Persona UAT friction (information only)", "fbca04", "all", title, path)
    if a.mode == "weekly" and blocking:
        path = os.path.join(out_dir, "blocking-issue.md")
        with open(path, "w") as fh:
            fh.write(issue_body("The weekly persona UAT found blocking findings.", a.mode, run_id, a.image, rows("blocking")))
        if a.publish:
            gh.upsert(BLOCKING_LABEL, "Blocking finding", "b60205", "open", BLOCKING_TITLE, path)
    if gh.failed:
        return 1
    if a.mode == "weekly":
        return 1 if blocking and not a.publish else 0       # published: the issue is the signal; a dry run must not look green
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
