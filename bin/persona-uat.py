#!/usr/bin/env python3
"""The persona UAT driver (REQ-UAT-001-AC1..AC5; owner ratified Oct 3 and Oct 4, point 9; results stay private, amendment 0215).

Five agents, each playing a different customer, read only our PUBLIC documents and exercise the image under test by digest.
The driver owns everything with authority: it starts the image and the pinned CI tools (Jenkins, a GitLab runner) as
digest-pinned containers on loopback, creates the on-call persona's kind cluster with the job's kind binary, builds a sandbox
holding only README.md and the top-level docs, runs one agent per persona with a scrubbed environment, validates what each
agent answers (anything that is not exactly the contract is blocking, "did not run"), proves each persona reached the
endpoint (the image's request counter), and writes ONE encrypted artifact per persona.

  persona-uat.py --mode rc|weekly --image REF@sha256:... --repo DIR --out DIR --tools FILE [--docker CMD] [--recipient CERT]
                 --agent CMD [--port N] [--ready-timeout S] [--agent-timeout S]
  env PERSONA_UAT_MODEL, PERSONA_UAT_COMPLIANCE_MODEL (required; no built-in default), PERSONA_UAT_TOKEN_BUDGET (default 400000)

Results are private (this repository is public; job logs and artifacts are public): the only output is one
`persona-uat: <persona|overall>: pass|fail` line per persona and overall, on stdout and in GITHUB_STEP_SUMMARY. Each persona's
report and transcript are encrypted (openssl cms, AES-256, to the committed recipient certificate) into <out>/<persona>.cms;
if any encryption fails, no file is left in --out. The driver opens no issue and calls no gh. Containers are FIXED-ARGUMENT: every
docker command is built here from the allowlisted images and fixed options, the docker client gets an allowlisted environment,
and no credential is passed to a container.
Exit status: 0 clean (friction is information, never a failure), 1 a blocking persona (in rc and weekly mode alike) or a failed
encryption, 2 a refused configuration (nothing was started), 3 the public docs are missing.
"""
import argparse
import warnings
import itertools
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
import urllib.parse
import urllib.request
import base64
import uuid
import shlex as _shlex

warnings.simplefilter("ignore")        # nothing but the fixed lines is ever printed: no interpreter warning either
PERSONAS = ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer")
TOOLS_FOR = {"maven-jenkins-ci": ("jenkins", "gitlab-runner"), "on-call-engineer": ("kind",)}
DIGEST_REF = re.compile(r"^[a-z0-9][^\s@]*@sha256:[0-9a-f]{64}$")
TOOL_KEYS = ("cosign", "gitlab-runner", "gradle", "jenkins", "kind", "kubectl", "maven", "shell")
KIND_NAME = "persona-uat"
PERSONA_NS = "persona"
JENKINS_ENV = "JAVA_OPTS=-Djenkins.install.runSetupWizard=false"
URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,15}://[^\s'\"<>)\]|;&`]+")      # a URL of ANY scheme (http, ftp, sftp, socks5h, ssh, ws, ...)
METRIC_RE = re.compile(r"^fscache_http_requests_total(\{[^}]*\})?\s+([0-9.eE+-]+)(\s+\d+)?\s*$")
DEFAULT_BUDGET = 400000
JOB_BUDGET = 6600           # seconds: the 120-minute job minus setup and the cleanup steps; the agent timeouts are cut from what is left of it
MIN_PERSONA_SECONDS = 300   # a persona that cannot be given this long is blocking (cannot prove), never run
TRANSCRIPT_CAP = 16 * 1024 * 1024    # the agent's own cap; the encrypted transcript holds the persisted history whole up to it
SETTLE_QUIET = 3.0          # seconds of an unchanged request counter before a persona's window is closed
SETTLE_MAX = 20.0           # the ceiling: a counter that never settles makes the persona blocking
DEFAULT_PORT = 38080        # the image's host port; never 8080: the docs' `kubectl port-forward svc/fscache 8080:80` must work next to the driver (Jenkins and the runner take the next two)
TOKEN_MARGIN = 900          # seconds the persona's kubeconfig token outlives --agent-timeout
# the environment an agent and the docker client get: a shell's settings and the docker client's, never a job credential;
# the agent additionally gets the model identity (names starting with the provider's prefix), which only its provider uses
# SHELL_ENV and DOCKER_ENV are duplicated verbatim in persona-uat-agent.py (a test asserts they are equal), so the agent and the
# driver always address the same docker daemon
SHELL_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR")
DOCKER_ENV = ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION")
BASE_ENV = SHELL_ENV + DOCKER_ENV
MODEL_ENV_PREFIX = "ANTHROPIC_"
# docs a customer can read: README.md, RELEASING.md (public customer-facing guidance: how a release is verified) and the TOP-LEVEL docs/*.md; unreleased notes are not public yet
DOCS_EXCLUDE = ("next-release-notes.md",)
ROOT_DOCS = ("README.md", "RELEASING.md")

INSTRUCTIONS = {
    "gradle-platform-engineer": (
        "You are a first-time user, a Gradle platform engineer setting up this cache. Following the documentation, install it, "
        "point a Gradle build at it, and configure the proxy settings your company needs. Judge whether a newcomer could finish "
        "using only what is written."),
    "maven-jenkins-ci": (
        "You are a Maven user whose builds run in CI on Jenkins and on a GitLab runner. Following the documentation, wire a Maven "
        "build to this cache from a Jenkins job, using the Jenkins container you are given; a GitLab runner container is given too (see the environment "
        "limits: do not try to run a GitLab job, report what a customer could not do here as friction)."),
    "compliance-reviewer": (
        "You are a compliance reviewer. Following the documentation's guide, verify the image's signature (with the cosign tool, naming the image under test by the "
        "digest reference you are given), fetch and inspect its SBOM, and read its VEX statements, exactly as the guide says, and judge whether the evidence is "
        "complete and verifiable."),
    "readme-evaluator": (
        "You are an evaluator who has only the README and ten minutes. Decide, from the README alone, what the product is, and try "
        "to get a working result within ten minutes. Do not open any other document."),
    "on-call-engineer": (
        "You are an on-call engineer in the middle of an incident. Following the documentation, perform an upgrade to a newer "
        "version and a rollback to the previous one on the Kubernetes cluster you are given (its kubeconfig is in your working "
        "directory), and find and read the logs you need to diagnose a problem."),
}
LIMITS = (
    "each command runs in its own disposable container, so a foreground `kubectl port-forward` followed by commands 'in another terminal' cannot be held across actions",
    "there is no pre-seeded Jenkins job or credentials and no GitLab server or runner registration (the GitLab runner container exposes its metrics endpoint only)",
    "these tools are not in the sandbox: gh, docker, jq (and kubectl exec is not permitted)",
    "the provenance step that needs GitHub's attestation store (`gh attestation verify`) cannot run in the sandbox",
)
ENV_LIMITS = ("Environment limits (report each as friction, not as blocking; they are limits of this test environment, not defects of the documentation): "
              + "; ".join("(%s) %s" % (k, t) for k, t in zip("abcd", LIMITS))
              + ". A step that can run in the sandbox is judged as written: if it fails, that is blocking. ")
CLASSIFY = ENV_LIMITS + (
    "Classify everything you find. A finding is blocking when it is broken behavior or a documented step that fails as written "
    "(quote the step and what happened). A finding is friction when everything works but something is confusing, slow or easy to "
    "get wrong. Report nothing you did not observe.")

# The driver's own source holds no model or vendor name (a rule the tests enforce), so the scan's list is assembled from parts.
CRED_RES = [re.compile(x) for x in (
    r"gh[pousr]_[A-Za-z0-9]{8,}", r"github_pat_[A-Za-z0-9_]{8,}", r"\b(AKIA|ASIA)[0-9A-Z]{12,}", r"\bsk-[A-Za-z0-9_-]{12,}",
    r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}", r"-----BEGIN", r"\bxox[abprs]-[A-Za-z0-9-]{8,}", r"\bAIza[0-9A-Za-z_-]{16,}",
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}", r"[A-Fa-f0-9]{32,}",
    # plain credentials: an Authorization header with a value; NAME=value / NAME: value for a secret-looking NAME (8+ characters);
    # password/secret/token followed by = or : and a value of 4+ characters
    r"(?i)authorization[\"']?\s*[:=]\s*[\"']?(basic|bearer|token)\s+[\"']?\S+",
    r"(?i)[A-Za-z0-9_.-]{0,64}(secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_.-]{0,64}[\"']?\s*[=:]\s*[\"']?[^\s\"']{8,}",     # bounded: a megabyte of letters must not make the scan quadratic
    r"(?i)\b(password|passwd|pwd|secret|token)[\"']?\s*[=:]\s*[\"']?[^\s\"']{4,}")]


class Refuse(Exception):
    """a configuration the driver will not run (exit 2): nothing has been started"""


def log(msg):
    sys.stderr.write("persona-uat: %s\n" % msg)


def clean_env(extra_prefix=None):
    env = {k: os.environ[k] for k in BASE_ENV if k in os.environ}
    if extra_prefix:
        env.update({k: v for k, v in os.environ.items() if k.startswith(extra_prefix)})
    return env


def docker_env():
    """the docker CLIENT's environment: a shell's settings plus its own allowlisted DOCKER_* settings (host, config, context, tls); no job credential"""
    return clean_env()


class TranscriptFile:
    """a transcript kept in the agent's streamed file: `prefix` text first, then the file (read bounded, never whole into memory)"""
    def __init__(self, prefix, path):
        self.prefix, self.path = prefix, path


class Docker:
    def __init__(self, cmd):
        self.cmd = cmd

    def call(self, *args, timeout=120):
        return subprocess.run(self.cmd + list(args), capture_output=True, text=True, timeout=timeout, env=docker_env())

    def start(self, ref, port_map=None, env=None, tail=()):
        """`run -d [-e FIXED] [-p 127.0.0.1:H:C] REF`: the only shapes the driver ever builds"""
        args = ["run", "-d"]
        if env:
            args += ["-e", env]
        if port_map:
            args += ["-p", "127.0.0.1:%d:%d" % port_map]
        p = self.call(*args, ref, *tail)
        cid = p.stdout.strip()
        if p.returncode != 0 or not cid or len(cid.split()) != 1:
            raise RuntimeError("could not start a container")
        return cid

    def running(self, cid):
        p = self.call("inspect", "-f", "{{.State.Running}}", cid)
        return p.returncode == 0 and p.stdout.strip() == "true"

    def remove(self, cids):
        """True when every container is gone (nothing to remove counts); a failing `docker rm` is a failed teardown, never ignored"""
        if not cids:
            return True
        try:
            return self.call("rm", "-f", *cids).returncode == 0
        except Exception:
            return False


def http_ready(url, strict=False):
    try:
        urllib.request.urlopen(url, timeout=2)
        return True
    except urllib.error.HTTPError as e:
        return False if strict else e.code < 500
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


def wait_ready(docker, cid, url, timeout, strict=False):
    """running AND answering; a container that stops is a failure at once"""
    deadline = time.time() + timeout
    while True:
        if not docker.running(cid):
            raise RuntimeError("a container is not running")
        if url is None or http_ready(url, strict):
            return
        if time.time() >= deadline:
            raise RuntimeError("a container never answered on its endpoint")
        time.sleep(0.5)


def open_modes(sandbox):
    """the container runs as another uid: the sandbox and everything in it is readable and traversable by all, writable by the owner only"""
    for d, dirs, fs in os.walk(sandbox):
        os.chmod(d, 0o777)
        for f in fs:
            os.chmod(os.path.join(d, f), 0o644)


def read_docs(repo):
    """{relative name: bytes} for README.md, RELEASING.md and top-level docs/*.md; symlinks, dotfiles, subdirectories, other types are never read"""
    files = {}
    data = read_regular(os.path.join(repo, "README.md"))
    if data is None:
        return None
    files["README.md"] = data
    for name in ROOT_DOCS[1:]:
        extra = read_regular(os.path.join(repo, name))
        if extra is not None:
            files[name] = extra
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
    if not isinstance(a, dict) or sorted(k for k in a if k not in ("commands", "actions")) != ["findings", "tokens", "transcript"]:
        raise ValueError("the answer does not have exactly findings, tokens and transcript")
    if "commands" in a and not (isinstance(a["commands"], list) and all(isinstance(c, str) for c in a["commands"])):
        raise ValueError("commands is not a list of strings")
    if "actions" in a:
        acts = a["actions"]
        if not (isinstance(acts, list) and len(acts) == len(a.get("commands", [])) and all(
                isinstance(x, dict) and sorted(x) == ["argv", "exit", "tool"] and isinstance(x["tool"], str) and isinstance(x["argv"], list)
                and all(isinstance(t, str) for t in x["argv"]) and isinstance(x["exit"], int) and not isinstance(x["exit"], bool) for x in acts)):
            raise ValueError("actions is not a list of {tool, argv, exit} matching commands")
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


UNSETTLED = object()        # the window could not be closed: a connection stayed open or the counter kept changing for the whole ceiling


def established_to(proc_net, port):
    """how many ESTABLISHED sockets (state 01) have `port` as their local or remote port, from the kernel's tcp and tcp6 tables; None when neither can be read.
    A request still being served holds its connection open until the response is written, which is before the server counts it."""
    n, read = 0, 0
    for name in ("tcp", "tcp6"):
        try:
            with open(os.path.join(proc_net, name)) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        read += 1
        for ln in lines:
            f = ln.split()
            if len(f) >= 4 and f[3] == "01" and (f[1].rpartition(":")[2] == "%04X" % port or f[2].rpartition(":")[2] == "%04X" % port):
                n += 1
    return n if read else None


def free_port():
    """a host port nothing listens on right now (the persona's own container is published there)"""
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def settled(ep, quiet_for=SETTLE_QUIET, ceiling=SETTLE_MAX, idle=lambda: True):
    """close a persona's window: the real server counts AFTER its handler returns, so the total must have been UNCHANGED for `quiet_for` seconds (a change restarts the interval)
    with no connection to the endpoint left (`idle()`), within `ceiling`. -> the total, None when /metrics cannot be read, UNSETTLED when the ceiling was hit."""
    v = scrape(ep)
    if v is None:
        return None
    t0 = quiet = time.time()
    while True:
        if time.time() - quiet >= quiet_for and idle():
            return v
        if time.time() - t0 >= ceiling:
            return UNSETTLED
        time.sleep(0.2)
        w = scrape(ep)
        if w is None:
            return None
        if w != v or not idle():
            v, quiet = w, time.time()


def cleanup(docker, label, sandbox, image):
    """files a tool image created as another uid cannot be removed by the runner: empty the mount from inside, as root. -> False when that failed"""
    try:
        return docker.call("run", "--rm", "--network", "none", "--user", "0:0", "--label", label, "-v", "%s:/work" % sandbox, "-w", "/work", image,
                           "sh", "-c", "rm -rf /work/* /work/.[!.]* /work/..?*", timeout=300).returncode == 0
    except Exception:
        return False


def sweep(docker, label):
    """remove every container that carries the persona's label. -> False when the daemon could not list or remove them: a survivor may still be sending traffic"""
    try:
        p = docker.call("ps", "-aq", "--filter", "label=" + label)
        if p.returncode != 0:
            return False
        ids = p.stdout.split()
        return docker.remove(ids)
    except Exception:
        return False


REPO_SRC = "\0repo"
GH_API_SRC = re.compile(r"^https?://api\.github\.com/repos/[^/\s]+/[^/\s]+/(?:tarball|zipball)(?:[/?]|$)", re.I)
GH_SRC = re.compile(r"^https?://github\.com/[^/\s]+/[^/\s]+/(?:archive|raw|blob|tree)/", re.I)


def scrub(text, secrets):
    for v in secrets:
        if v:
            text = text.replace(v, "[scrubbed]")
    for r in CRED_RES:
        text = r.sub("[scrubbed]", text)
    return text


def descendants(root):
    q = subprocess.run(["ps", "-A", "-o", "pid=,ppid="], capture_output=True, text=True).stdout.split()
    kids = {}
    for pid, ppid in zip(q[::2], q[1::2]):
        kids.setdefault(int(ppid), []).append(int(pid))
    out, todo = [], [root]
    while todo:
        for c in kids.get(todo.pop(), []):
            out.append(c); todo.append(c)
    return out


TRANSCRIPT_KEEP_HEAD = 200000        # characters kept from the start of a persisted transcript longer than head + tail
TRANSCRIPT_KEEP_TAIL = 800000


TRANSCRIPT_KEEP_HEAD = 200000        # above the cap only: the first 200000 and the last 800000 characters, with a marker
TRANSCRIPT_KEEP_TAIL = 800000


def file_chunks(path, secrets):
    """the persisted transcript as scrubbed text pieces: WHOLE up to TRANSCRIPT_CAP (streamed in pieces cut at line ends), else the first and last parts with an explicit
    marker of how many characters were omitted"""
    try:
        size = os.path.getsize(path)
        fh = open(path, "rb")
    except (OSError, TypeError):
        return
    with fh:
        if size > TRANSCRIPT_CAP:
            head = fh.read(TRANSCRIPT_KEEP_HEAD)
            fh.seek(size - TRANSCRIPT_KEEP_TAIL)
            tail = fh.read(TRANSCRIPT_KEEP_TAIL)
            yield scrub(head.decode("utf-8", "replace"), secrets)
            yield "\n[... %d characters omitted ...]\n" % (size - TRANSCRIPT_KEEP_HEAD - TRANSCRIPT_KEEP_TAIL)
            yield scrub(tail.decode("utf-8", "replace"), secrets)
            return
        carry = b""
        while True:
            blob = fh.read(262144)
            if not blob:
                break
            blob = carry + blob
            cut = blob.rfind(b"\n") + 1
            if cut == 0 and len(blob) < 1048576:        # no line end yet: keep reading (a single enormous line is cut after a megabyte)
                carry = blob
                continue
            cut = cut or len(blob)
            carry = blob[cut:]
            yield scrub(blob[:cut].decode("utf-8", "replace"), secrets)
        if carry:
            yield scrub(carry.decode("utf-8", "replace"), secrets)


def transcript_chunks(transcript, secrets):
    if isinstance(transcript, TranscriptFile):
        yield scrub(transcript.prefix, secrets)
        yield from file_chunks(transcript.path, secrets)
    else:
        for i in range(0, len(transcript), 262144):
            yield scrub(transcript[i:i + 262144], secrets)


def transcript_commands(transcript):
    """the `$ command` lines of a transcript (a string, or an agent's streamed file read up to the cap), for the hosts of a persona that did not run"""
    if isinstance(transcript, TranscriptFile):
        lines = transcript.prefix.splitlines()
        try:
            with open(transcript.path, errors="replace") as fh:
                for ln in fh:
                    lines.append(ln.rstrip("\n")[:20000])
                    if len(lines) > 400000:
                        break
        except (OSError, TypeError):
            pass
    else:
        lines = transcript.splitlines()
    return [ln[2:] for ln in lines if ln.startswith("$ ")]


def kill_group(p):
    """everything the agent left in its own session goes with it (work started in other sessions is found from its descendants first)"""
    for pid in descendants(p.pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_agent(agent_cmd, agent_args, request, sandbox, timeout, tfile=None):
    """-> (answer or None, transcript (text or a TranscriptFile), failure reason or None). The agent's stderr is kept for the encrypted transcript only; the actions it completed
    before a timeout or a failure come from its streamed transcript file. Whatever the agent left running is killed on EVERY exit: its window must end with nothing of it alive."""
    p = subprocess.Popen(agent_cmd + agent_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=sandbox,
                         env=clean_env(MODEL_ENV_PREFIX), text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(json.dumps(request), timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_group(p)
        out, err = p.communicate()
        return None, TranscriptFile("agent timed out after %ss\n%s\n" % (timeout, (err or "")[-200000:]), tfile), "timed out after %ss" % timeout
    kill_group(p)
    if p.returncode != 0:
        return None, TranscriptFile("agent failed (exit %d)\n%s\n" % (p.returncode, err[-200000:]), tfile), "the agent failed (exit %d)" % p.returncode
    try:
        return validate_answer(out), None, None
    except ValueError as e:
        return None, TranscriptFile("the agent's answer was refused: %s\n%s\n" % (e, err[-200000:]), tfile), "the agent's answer is outside the contract (%s)" % e


def absolutize(tokens):
    """a relative script path (not the interpreter) is made absolute: the agent runs with its cwd in the sandbox"""
    out = tokens[:1]
    for t in tokens[1:]:
        out.append(os.path.abspath(t) if not os.path.isabs(t) and not t.startswith("-") and os.path.isfile(t) else t)
    return out


def host_run(argv, stdin=None, timeout=300):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout, env=clean_env())


class Cluster:
    """kind via the job's binary; the admin kubeconfig stays in a private directory of the driver"""
    leaked = False        # a cluster that could not be deleted exists somewhere: the run's windows are no longer attributable

    def __init__(self, image, timeout=300):
        self.deleted = False
        self.dir = tempfile.mkdtemp(prefix="persona-uat-kube-")
        self.kc = os.path.join(self.dir, "admin.kubeconfig")
        self.created = True
        try:
            self._create(image, timeout)
        except BaseException:
            self.delete()
            raise

    def _create(self, image, timeout):
        try:
            p = host_run(["kind", "create", "cluster", "--image", image, "--name", KIND_NAME, "--kubeconfig", self.kc], timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RuntimeError("kind create cluster timed out")
        if p.returncode != 0:
            raise RuntimeError("kind create cluster failed")
        admin = open(self.kc).read()
        m = re.search(r"server:\s*(https://127\.0\.0\.1:(\d+))", admin)
        c = re.search(r"certificate-authority-data:\s*(\S+)", admin)
        if not m or not c:
            raise RuntimeError("the admin kubeconfig is not readable")
        self.server, self.port, self.ca = m.group(1), int(m.group(2)), c.group(1)
        self.kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=120s")       # `kind create cluster --wait 0s` returns before the node is Ready

    def kubectl(self, *args, stdin=None):
        p = host_run(["kubectl", "--kubeconfig", self.kc] + list(args), stdin)
        if p.returncode != 0:
            raise RuntimeError("kubectl %s failed" % args[0])
        return p.stdout

    def provision(self, duration):
        ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": PERSONA_NS, "labels": {"pod-security.kubernetes.io/" + k: "restricted" for k in ("enforce", "warn", "audit")}}}
        sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "persona", "namespace": PERSONA_NS}}
        role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "persona", "namespace": PERSONA_NS}, "rules": [
            {"apiGroups": [""], "resources": ["pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "events"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
            {"apiGroups": ["apps"], "resources": ["deployments", "replicasets"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/portforward"], "verbs": ["create"]},
            {"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get", "update", "patch"]}]}
        rb = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "persona", "namespace": PERSONA_NS},
              "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "persona"}, "subjects": [{"kind": "ServiceAccount", "name": "persona", "namespace": PERSONA_NS}]}
        self.kubectl("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "List", "items": [ns, sa, role, rb]}))
        token = self.kubectl("create", "token", "persona", "-n", PERSONA_NS, "--duration", "%ds" % duration).strip()
        if not token:
            raise RuntimeError("no token")
        try:
            pl = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
            life = pl["exp"] - pl["iat"]
        except Exception:
            life = 0
        remaining = pl.get("exp", 0) - time.time() if life else 0
        if life < duration or remaining < duration - 60 or life > 86400:
            raise RuntimeError("the issued token is shorter-lived than a persona window")
        name = "kind-" + KIND_NAME
        return json.dumps({"apiVersion": "v1", "kind": "Config", "clusters": [{"name": name, "cluster": {"server": self.server, "certificate-authority-data": self.ca}}],
                           "users": [{"name": "persona", "user": {"token": token}}], "contexts": [{"name": name, "context": {"cluster": name, "user": "persona", "namespace": PERSONA_NS}}],
                           "current-context": name}, indent=1)

    def delete(self):
        """-> True when the cluster is gone (or never existed); a failing `kind delete cluster` is a failed teardown"""
        if self.deleted:
            return True
        self.deleted = True
        ok = True
        if self.created:
            try:
                ok = host_run(["kind", "delete", "cluster", "--name", KIND_NAME]).returncode == 0
            except Exception:
                ok = False
        shutil.rmtree(self.dir, ignore_errors=True)
        if not ok:
            Cluster.leaked = True
        return ok


def scrape(endpoint):
    """sum of every fscache_http_requests_total sample (0 when the exposition holds none), or None when /metrics cannot be read"""
    try:
        with urllib.request.urlopen(endpoint + "/metrics", timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
    except Exception:
        return None
    total, valid = 0.0, False
    for ln in body.splitlines():
        if ln.startswith("# TYPE") or ln.startswith("# HELP"):
            valid = True
        m = METRIC_RE.match(ln)
        if m:
            valid = True
            total += float(m.group(2))
    return total if valid else None


HOST_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::[0-9]+)?(?:/.*)?$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?(?:/.*)?$")
# options that take a value, per program: short letters (a value may be attached in a cluster: -sSLxHOST) and long names (--opt VALUE or --opt=VALUE)
SHORT_VALUE = {"curl": set("oUuHdXAeTFmxKEbcCDwyYzrtQ"), "wget": set("OoPtTeiBUaQwlARDIX")}
LONG_VALUE = {"curl": {"output", "user", "header", "data", "request", "user-agent", "referer", "upload-file", "form", "cacert", "max-time", "retry", "proxy", "connect-to",
                       "resolve", "config", "url", "proxy-user", "cookie", "cookie-jar", "cert", "key", "write-out", "output-dir", "limit-rate", "range", "data-raw",
                       "data-binary", "data-urlencode", "json", "connect-timeout", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname", "proxy1.0", "doh-url",
                       "proxy-header", "proxy-cacert", "proxy-cert", "proxy-key", "proxy-pass", "proxy-service-name", "proxy-tlsuser", "proxy-tlspassword", "proxy-ciphers"},
              "wget": {"output-document", "output-file", "directory-prefix", "user", "password", "header", "tries", "timeout", "execute", "input-file", "base", "user-agent",
                       "post-data", "post-file", "body-data", "body-file"}}
FILE_VALUE = {"curl": ({"K"}, {"config"}), "wget": ({"i"}, {"input-file"})}      # the value is a FILE whose content is not observed (its name is never a host)


def _clean_host(h):
    """a hostname as the URL parser gave it, cut at the first character a name cannot hold (an open quote can drag text behind a host); an IPv6 literal stays whole"""
    if not h:
        return None
    if re.fullmatch(r"[0-9A-Fa-f:.]+", h) and ":" in h:
        return h.lower()
    m = re.match(r"[A-Za-z0-9._-]+", h)
    return m.group(0).lower() if m else None


def _strip_host(v):
    """HOST from [user@]HOST[:port][/path] or scheme://HOST..., or None. A value the URL parser refuses raises ValueError: the caller marks that command unparsed."""
    if "://" in v:
        return _clean_host(urllib.parse.urlsplit(v).hostname)
    return _clean_host(_host_of(v, strict=True)) if HOST_RE.match(v) else None


def _option_hosts(prog, name, value):
    """hosts a value-taking option NAMES: a URL, a proxy, --connect-to HOST1:P1:HOST2:P2, --resolve HOST:PORT:ADDR, wget -e http_proxy=HOST, wget -B HOST"""
    out = []
    if prog == "curl" and name in ("url", "proxy", "x", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname", "proxy1.0", "doh-url"):
        out.append(_strip_host(value))
    elif prog == "curl" and name == "connect-to":
        f = value.split(":")
        out += [_strip_host(f[0]) if f[0] else None, _strip_host(f[2]) if len(f) > 2 and f[2] else None]
    elif prog == "curl" and name == "resolve":
        f = value.lstrip("+").split(":")
        out += [_strip_host(f[0]), f[2] if len(f) > 2 else None]
    elif prog == "wget" and name in ("e", "execute"):
        m = re.match(r"^(?:https?_proxy|ftp_proxy)\s*=\s*(.+)$", value, re.I)
        out.append(_strip_host(m.group(1)) if m else None)
    elif prog == "wget" and name in ("B", "base"):
        out.append(_strip_host(value))
    return [h.lower() for h in out if h]


def _fetch_tokens(prog, toks):
    """-> (hosts named by options, positional words) for a curl/wget command line"""
    hosts, positional, i = [], [], 0
    short_files, long_files = FILE_VALUE[prog]
    while i < len(toks):
        t = toks[i]
        i += 1
        if t.startswith("--") and len(t) > 2:
            name, eq, val = t[2:].partition("=")
            if name in LONG_VALUE[prog]:
                if not eq:
                    val = toks[i] if i < len(toks) else ""
                    i += 1
                if name not in long_files:
                    hosts += _option_hosts(prog, name, val)
        elif t.startswith("-") and len(t) > 1 and t != "--":
            for k, ch in enumerate(t[1:], 1):               # a cluster: the first value-taking letter takes the rest of the cluster, or the next word
                if ch in SHORT_VALUE[prog]:
                    val = t[k + 1:]
                    if not val:
                        val = toks[i] if i < len(toks) else ""
                        i += 1
                    if ch not in short_files:
                        hosts += _option_hosts(prog, ch, val)
                    break
        else:
            positional.append(t)
    return hosts, positional


def _host_of(tok, strict=False):
    try:
        return urllib.parse.urlsplit("//" + tok).hostname
    except ValueError:
        if strict:
            raise
        return None


PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy_unused")
WRAPPERS = {"env", "sudo", "time", "command", "nohup", "nice", "exec", "stdbuf", "timeout", "setsid", "ionice", "builtin", "doas", "export", "xargs"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "fi", "done", "esac", "in", "case", "select", "coproc"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
WRAPPER_VALUE_OPTS = {"xargs": set("IndaLsE"), "sudo": set("ugCDhpRTt"), "env": {"u", "C", "S"}, "nice": {"n"}, "timeout": {"k", "s"}, "stdbuf": set("ioe"), "ionice": set("cnp"), "doas": {"u", "C"}}
NET_NAME = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9-]*[A-Za-z]$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^localhost$")


def _name(v):
    """a hostname/IP from [user@]HOST[:port][/path] or [v6], or None (not a name)"""
    v = v.rsplit("@", 1)[-1]
    if v.startswith("["):
        v = v.split("]", 1)[0] + "]" if "]" in v else v
        return v.lower() if re.fullmatch(r"\[[0-9A-Fa-f:.]+\]", v) else None
    v = re.split(r"[:/]", v, maxsplit=1)[0]
    return v.lower() if NET_NAME.match(v) else None


def _positionals(toks, value_opts):
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        i += 1
        if t == "--":
            out += toks[i:]
            break
        if t.startswith("--"):
            if "=" not in t and t[2:] in value_opts:
                i += 1
        elif t.startswith("-") and len(t) > 1:
            if t[1:] in value_opts or (len(t) == 2 and t[1] in value_opts):
                i += 1
        else:
            out.append(t)
    return out


def _segment_hosts(toks, depth=0, info=None):
    """hosts named by ONE simple command (the words between ; && || | & and parentheses): leading NAME=value words (proxy variables name hosts), wrappers (env, sudo, time,
    command, nohup, timeout N ...), the program by BASENAME, then its own rules (curl/wget/kubectl/cosign, nc, ssh/scp, ping, dig, telnet, openssl s_client, git clone)"""
    out, i = set(), 0
    while toks and (toks[0] in KEYWORDS):
        toks = toks[1:]
    def assign(tok):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", tok)
        if not m:
            return False
        if m.group(1).lower() in PROXY_VARS and m.group(2):
            h = _strip_host(m.group(2))
            if h:
                out.add(h.lower())
        return True
    while i < len(toks):
        t = toks[i]
        base = t.rsplit("/", 1)[-1]
        if assign(t):
            i += 1
        elif base in WRAPPERS:
            i += 1
            vals = WRAPPER_VALUE_OPTS.get(base, set())
            while i < len(toks) and (toks[i].startswith("-") or assign(toks[i]) or (base == "timeout" and re.match(r"^[0-9.]+[smhd]?$", toks[i]))):
                if toks[i].startswith("-") and toks[i].lstrip("-")[:1] in vals and len(toks[i].lstrip("-")) == 1:
                    i += 1
                i += 1
        else:
            break
    if i >= len(toks):
        return out
    prog, rest = toks[i].rsplit("/", 1)[-1], toks[i + 1:]
    if prog in SHELLS and depth < 4:
        for k, t in enumerate(rest):
            if t.startswith("-") and not t.startswith("--") and "c" in t[1:] and k + 1 < len(rest):
                out.update(url_hosts(rest[k + 1], info, depth + 1))      # `sh -c '...'` / `bash -lc "..."`: the string is a command line of its own
                break
        return out
    if prog == "eval" and depth < 4:
        out.update(url_hosts(" ".join(rest), info, depth + 1))
        return out
    if prog in ("curl", "wget"):
        opt_hosts, positional = _fetch_tokens(prog, rest)
        out.update(opt_hosts)
        for t in positional:        # a schemeless DESTINATION operand of a network program is a host whatever its suffix (evil.zip, x.sh, run.py): output names are option values, never here
            if "://" not in t and HOST_RE.match(t):
                out.add(_host_of(t, strict=True).lower())
    elif prog == "kubectl":
        for k, t in enumerate(rest):
            v = t.split("=", 1)[1] if t.startswith("--server=") else (rest[k + 1] if t == "--server" and k + 1 < len(rest) else None)
            if v and "://" not in v and HOST_RE.match(v):
                out.add(_host_of(v, strict=True).lower())
    elif prog == "cosign":
        for t in rest:
            if "://" not in t and re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::[0-9]+)?/\S+$", t):
                out.add(t.split("/")[0].lower())
    elif prog in ("nc", "ncat", "netcat"):
        for k, t in enumerate(rest):
            if t in ("-x", "-X") and k + 1 < len(rest):
                n = _name(rest[k + 1])
                if n:
                    out.add(n)
        for t in _positionals(rest, {"w", "p", "s", "i", "q", "T", "X", "x", "I", "O", "P", "m"}):
            n = _name(t)
            if n:
                out.add(n); break
    elif prog in ("ssh", "sftp", "rsync"):
        opts = {"p", "i", "l", "o", "F", "L", "R", "D", "b", "c", "e", "m", "O", "S", "W", "w", "B", "E", "Q", "J", "I"}
        for k, t in enumerate(rest):
            if t == "-J" and k + 1 < len(rest):
                for hop in rest[k + 1].split(","):
                    n = _name(hop)
                    if n:
                        out.add(n)
        for t in _positionals(rest, opts):
            n = _name(t.split(":", 1)[0] if prog == "rsync" else t)
            if n:
                out.add(n); break
    elif prog == "scp":
        for t in _positionals(rest, {"P", "i", "l", "o", "F", "S", "c", "J", "D"}):
            if ":" in t and not t.startswith("/") and "://" not in t:
                n = _name(t.rsplit(":", 1)[0])
                if n:
                    out.add(n)
    elif prog in ("ping", "ping6", "traceroute", "telnet", "nslookup", "host", "whois", "mtr", "tracepath"):
        n = None
        for t in _positionals(rest, {"c", "i", "W", "w", "s", "t", "I", "M", "p", "Q", "S", "T", "m", "q", "l"}):
            n = _name(t)
            if n:
                out.add(n); break
    elif prog == "dig":
        for t in rest:
            if t.startswith("@"):
                n = _name(t[1:])
                if n:
                    out.add(n)
        for t in _positionals(rest, {"b", "c", "f", "k", "m", "p", "q", "t", "x", "y"}):
            if not t.startswith("@"):
                n = _name(t)
                if n:
                    out.add(n); break
    elif prog == "openssl" and rest[:1] == ["s_client"]:
        for k, t in enumerate(rest):
            if t in ("-connect", "-servername", "-proxy") and k + 1 < len(rest):
                n = _name(rest[k + 1])
                if n:
                    out.add(n)
    elif prog == "git" and "clone" in rest:
        for t in rest[rest.index("clone") + 1:]:
            if t.startswith("-"):
                continue
            if "://" in t:
                h = urllib.parse.urlsplit(t).hostname
                if h:
                    out.add(h.lower())
            elif re.match(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+:", t):
                out.add(t.split("@", 1)[1].split(":", 1)[0].lower())
            break
    return out


def _tokens(text):
    """the command text as shell words, with the control syntax (; & | ( ) { } ` and an UNQUOTED newline) as words of their own, quoting removed, an unquoted `#` comment dropped,
    a backslash-newline joined. A quoted string stays ONE word whatever it holds (a multi-line `sh -c '...'` too). -> (words, ok); ok is False when a quote is left open: the
    words are then a best effort (the quote is dropped and the rest read as it stands) and the caller counts the command as unparsed."""
    out, cur, started, quote, i, ok = [], [], False, None, 0, True
    n = len(text)
    def flush():
        nonlocal cur, started
        if started:
            out.append("".join(cur))
        cur, started = [], False
    while i < n:
        c = text[i]
        if quote == "'":
            if c == "'": quote = None
            else: cur.append(c)
        elif quote == '"':
            if c == '"': quote = None
            elif c == "\\" and i + 1 < n and text[i + 1] in '"\\$`':
                i += 1; cur.append(text[i])
            else: cur.append(c)
        elif c == "\\":
            if text[i + 1:i + 2] == "\n":
                i += 1
            elif i + 1 < n:
                i += 1; cur.append(text[i]); started = True
        elif c in "'\"":
            quote, started = c, True
        elif c == "#" and not started:
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c in " \t\r":
            flush()
        elif c in ";&|(){}`\n":
            flush()
            out.append(";" if c == "\n" else c)
        else:
            cur.append(c); started = True
        i += 1
    if quote:
        ok = False
    flush()
    return out, ok


def _uncomment(text):
    """the text without its unquoted `# comment`s (a comment is not a contact), quoting respected"""
    out, quote, i, n, word_start = [], None, 0, len(text), True
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == quote and not (quote == '"' and text[i - 1] == "\\"):
                quote = None
            word_start = False
        elif c in "'\"":
            quote = c; out.append(c); word_start = False
        elif c == "#" and word_start:
            while i < n and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(c)
            word_start = c in " \t\n;&|(){}`"
        i += 1
    return "".join(out)


def url_hosts(text, info=None, depth=0):
    """every host the command text NAMES: URLs of ANY scheme anywhere in it (raw text, control syntax ignored), and what the programs on each simple command take as hosts
    (wrappers, assignments, conditionals, pipelines, subshells and nested `sh -c` strings included). `info` (a dict) gets info['unparsed'] += 1 when a quote was left open (the
    best-effort words are still read, and the raw URL scan covers the rest). Raises ValueError for a value the URL parser refuses: the caller marks the command unparsed."""
    out = set()
    text = _uncomment(text.replace("\\\n", " "))
    clone_urls = {u for ln in text.splitlines() if re.search(r"\bgit\s+clone\b", ln) for u in URL_RE.findall(ln)}
    for u in URL_RE.findall(text):
        try:
            h = _clean_host(urllib.parse.urlsplit(u).hostname)
        except ValueError:
            continue
        if h:
            h = h.lower()
            out.add(h + REPO_SRC if (h in ("raw.githubusercontent.com", "codeload.github.com") or GH_SRC.match(u) or GH_API_SRC.match(u) or (u in clone_urls and h == "github.com")) else h)
    words, ok = _tokens(text)
    if not ok and info is not None:
        info["unparsed"] = info.get("unparsed", 0) + 1
    seg = []
    for t in words + [";"]:
        if t in (";", "&", "|", "(", ")", "{", "}", "`"):
            if seg:
                try:
                    out.update(_segment_hosts(seg, depth, info))
                except ValueError:          # a value the URL parser refuses: this simple command is unparsed, the others and the raw URL scan stand
                    if info is not None and not info.get("segment_bad"):
                        info["segment_bad"] = True
                        info["unparsed"] = info.get("unparsed", 0) + 1
            seg = []
        else:
            seg.append(t)
    return out


def registry_of(ref):
    first = ref.split("/")[0]
    return first.lower() if "/" in ref and ("." in first or ":" in first or first == "localhost") else "docker.io"


HOSTS_LABEL = "Hosts named in its commands (redirects and tool-internal contacts such as dependency downloads are not observed):"
ENV_LIMITS_LINE = "Environment limits of this run (reported as friction, never blocking): " + "; ".join("(%s) %s" % (k, t) for k, t in zip("abcd", LIMITS))
COUNTER_GUARANTEE = ("Counter guarantee: this persona ran against its OWN fresh container of the image under test, published on a host port of its own, and its request counter "
                     "was read from that container only, at its start and again at its end (after its processes and containers were removed, no established connection to the "
                     "container remained and the counter was unchanged for 3 seconds); the container was removed afterwards, so a request of an earlier persona can only land "
                     "in an earlier, removed container. If a scrape failed or the window could not be closed within 20 seconds the persona is blocking (cannot prove). Not "
                     "covered: this persona's own request still being served more than 3 seconds after its connection closed (the server exposes no in-flight gauge), which "
                     "can only cost this persona its own credit.")


# cosign flags that take a VALUE (a digest given as one is never the verification target) and the booleans; any other flag is treated as taking a value (fail closed)
COSIGN_VALUE_FLAGS = {"--certificate-identity", "--certificate-identity-regexp", "--certificate-oidc-issuer", "--certificate-oidc-issuer-regexp", "--certificate",
                      "--certificate-chain", "--certificate-github-workflow-name", "--certificate-github-workflow-ref", "--certificate-github-workflow-repository",
                      "--certificate-github-workflow-sha", "--certificate-github-workflow-trigger", "--key", "--type", "--policy", "--rekor-url", "--output", "-o", "--annotations",
                      "-a", "--attachment", "--signature", "--platform", "--sk", "--slot", "--bundle", "--registry-username", "--registry-password", "--payload", "--cert-email",
                      "--max-workers", "--timestamp-certificate-chain", "--trusted-root", "--new-bundle-format", "--ca-roots", "--ca-intermediates"}
COSIGN_BOOL_FLAGS = {"--offline", "--insecure-ignore-tlog", "--insecure-ignore-sct", "--verbose", "-d", "--check-claims", "--local-image", "--private-infrastructure",
                     "--use-signed-timestamps", "--allow-insecure-registry", "--allow-http-registry", "--output-file-is-stdout"}


def asks_for_help(t):
    """a word that asks cosign for help or the version, however spelled: -h, -help, --help, --help=true (any value, a boolean-valued form included), --version, -version, and an
    abbreviation of the long names (--h, --he, --hel, --ver, --versi ...): the option NAME is normalised before anything is decided"""
    if not t.startswith("-") or t == "-":
        return False
    name = t.lstrip("-").split("=", 1)[0].lower()
    if not name:
        return False
    if t.startswith("--"):
        return "help".startswith(name) or "version".startswith(name)
    return name in ("h", "help", "version") or (len(name) <= 4 and name.isalpha() and "h" in name)      # -h, -help, -version, and a short cluster holding -h (-dh)


def cosign_operation(argv):
    """-> (subcommand, positional words, flags) of a cosign command line, or None when it asks for help/version or cannot be read. A flag's value is never positional."""
    if any(asks_for_help(t) for t in argv):
        return None
    sub, pos, flags, i = None, [], [], 0
    while i < len(argv):
        t = argv[i]
        i += 1
        if t.startswith("-") and t != "-":
            name = t.split("=", 1)[0]
            flags.append(name)
            if "=" in t or name in COSIGN_BOOL_FLAGS:
                continue
            i += 1                  # a value flag (or one we do not know: its next word is its value, never a target)
            continue
        if sub is None:
            sub = t
        else:
            pos.append(t)
    return (sub, pos, flags) if sub else None


def verified_digest(answer, image):
    """the compliance reviewer's proof of exercising the RC image: a recorded ACTION whose tool is cosign and whose operation PARSES as `cosign verify` (or `cosign
    verify-attestation` with a --type) of exactly ONE image argument that ends @sha256:<the RC digest> (never a flag's value, never help/version), exit 0. Words in
    echo, comments or shell actions are never proof."""
    digest = image.split("@")[-1]
    if not digest.startswith("sha256:"):
        return False
    for act in answer.get("actions", []):
        if act.get("tool") != "cosign" or act.get("exit") != 0 or not isinstance(act.get("argv"), list):
            continue
        op = cosign_operation(act["argv"])
        if not op:
            continue
        sub, pos, flags = op
        if sub not in ("verify", "verify-attestation") or (sub == "verify-attestation" and "--type" not in flags):
            continue
        if len(pos) == 1 and pos[0].endswith("@" + digest):
            return True
    return False


def report_text(persona, verdict, findings, tokens, capped, did_not_run=None, hosts=None, unparsed=0):
    lines = ["VERDICT: %s" % verdict, "persona: %s" % persona, ""]
    lines += [ENV_LIMITS_LINE, COUNTER_GUARANTEE, ""]
    if hosts is not None:
        lines += ["%s %s" % (HOSTS_LABEL, ", ".join(hosts) if hosts else "none")]
        if unparsed:
            lines += ["Unparsed commands (hosts not extracted): %d" % unparsed]
        lines += [""]
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


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("rc", "weekly"), required=True)
    ap.add_argument("--image", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--docker", default="docker")
    ap.add_argument("--recipient", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "persona-uat-recipient.pem"))
    ap.add_argument("--agent", required=True)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--ready-timeout", type=int, default=120)
    ap.add_argument("--agent-timeout", type=int, default=3600)
    ap.add_argument("--job-budget", type=float, default=JOB_BUDGET, help="seconds of the job's time the personas may use in all; each agent timeout is cut from what is left")
    ap.add_argument("--min-persona-seconds", type=float, default=MIN_PERSONA_SECONDS, help="a persona that cannot be given this long is blocking (cannot prove) and not run")
    ap.add_argument("--settle-quiet", type=float, default=SETTLE_QUIET, help="seconds of an unchanged counter before a window closes")
    ap.add_argument("--settle-max", type=float, default=SETTLE_MAX, help="ceiling for that wait: a counter that never settles blocks the persona")
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
    try:
        cert = open(a.recipient).read()
    except OSError:
        raise Refuse("--recipient is not readable")
    if "PRIVATE KEY" in cert or "BEGIN CERTIFICATE" not in cert:
        raise Refuse("--recipient is not a certificate (a private key is never accepted)")
    return models, budget, tools


STATE = {}        # what the last-resort handler needs to write the encrypted reports of what is known: filled by _main as soon as it is known


def main():
    """the driver. Nothing but the fixed pass/fail lines (and, if something nobody expected goes wrong, the fixed line `driver error`) is ever printed: whatever raises is
    caught here, the encrypted reports of what is known are still written, and the run fails"""
    try:
        return _main()
    except SystemExit:
        raise
    except BaseException:
        sys.stderr.write("persona-uat: driver error\n")
        try:
            return last_resort()
        except BaseException:
            return 1


def last_resort():
    """every persona without a result gets an encrypted blocking report saying the driver failed; then the usual pass/fail lines"""
    results, out_dir, recipient = STATE.get("results"), STATE.get("out_dir"), STATE.get("recipient")
    if results is None or not out_dir or not recipient:
        return 1
    for persona in PERSONAS:
        if persona in results:
            continue
        text = report_text(persona, "blocking", [{"kind": "blocking", "text": "the driver failed before this persona could be recorded (driver error)"}], None, False,
                           "the driver failed (driver error)")
        ok = encrypt(recipient, persona, out_dir, [text.encode(), b"\n=== TRANSCRIPT ===\ndriver error\n"])
        results[persona] = {"verdict": "blocking", "findings": [], "tokens": None, "capped": False, "encfail": not ok}
    return finish(results, out_dir) or 1


def _main():
    a = parse_args()
    try:
        models, budget, tools = configure(a)
    except Refuse as e:
        log("refused: %s" % e)
        return 2
    job_t0 = time.time()
    docker_cmd = shlex.split(a.docker)
    if not os.path.isabs(docker_cmd[0]) and os.path.isfile(docker_cmd[0]):
        docker_cmd[0] = os.path.abspath(docker_cmd[0])
    docker = Docker(docker_cmd)
    agent_cmd = absolutize(shlex.split(a.agent))
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    STATE.update(out_dir=out_dir, recipient=a.recipient)
    secrets = [v for v in models.values() if len(v) >= 4]
    run_id = os.environ.get("GITHUB_RUN_ID") or "local"

    results = {}        # persona -> {"verdict", "findings", "tokens", "capped"}
    STATE["results"] = results

    def known_hosts():
        doc_hosts = set()
        for data in (docs or {}).values():
            try:
                doc_hosts |= url_hosts(data.decode("utf-8", "replace"))
            except Exception:
                pass
        return doc_hosts | {"127.0.0.1", "localhost", registry_of(a.image)} | {registry_of(v) for v in tools.values()}      # the image under test's own registry is not "outside"

    def labelled(hosts):
        src = {h for h in hosts if h.endswith(REPO_SRC)}
        plain = {h for h in hosts if not h.endswith(REPO_SRC)}
        out = set()
        for h in (plain - known_hosts()):
            out.add(h if len(h) <= 253 else h[:60] + "... (over-long name)")
        for h in src:
            out.add(h[:-len(REPO_SRC)] + " (repository source)")
        return sorted(out)

    def hosts_of(commands):
        """-> (hosts, number of commands whose hosts could not be extracted): one command that cannot be parsed never costs the others or the report"""
        hosts, bad = set(), 0
        for c in commands:
            info = {}
            try:
                hosts |= url_hosts(c, info)
            except Exception:
                bad += 1
                continue
            bad += 1 if info.get("unparsed") else 0
        return hosts, bad

    def record(persona, answer, transcript, did_not_run=None, proven=True, extra_blocking=None):
        """the persona's encrypted report and the one pass/fail line. Every step is exception-safe INSIDE this path: whatever fails here costs this persona a 'driver error'
        report, never a traceback and never an unwritten report"""
        try:
            _record(persona, answer, transcript, did_not_run, proven, extra_blocking)
        except Exception:
            text = report_text(persona, "blocking", [{"kind": "blocking", "text": "the driver failed while recording this persona (driver error)"}], None, False,
                               "the driver failed while recording (driver error)")
            ok = encrypt(a.recipient, persona, out_dir, [text.encode(), b"\n=== TRANSCRIPT ===\ndriver error\n"])
            results[persona] = {"verdict": "blocking", "findings": [], "tokens": None, "capped": False, "encfail": not ok}
            sys.stderr.write("persona-uat: %s: fail\n" % persona)

    def _record(persona, answer, transcript, did_not_run, proven, extra_blocking):
        if answer:
            findings, tokens = list(answer["findings"]), answer["tokens"]
            if persona == "compliance-reviewer":
                proven = verified_digest(answer, a.image)         # the reviewer never calls the endpoint: its proof is a successful verification of the RC's digest
            if extra_blocking:
                findings.append({"kind": "blocking", "text": extra_blocking})
            elif not proven:
                # no proof of exercising the RC image blocks the persona whatever else it reported (friction stays information, and stays in the report)
                findings.append({"kind": "blocking", "text": (
                    "the persona did not exercise the image under test: no cosign verify (or verify-attestation with a --type) of the release candidate's digest exited 0"
                    if persona == "compliance-reviewer" else
                    "the persona did not exercise the image under test: the endpoint was never exercised (its request counter did not move during this persona's run)")})
            capped = tokens >= budget
            verdict = "blocking" if any(f["kind"] == "blocking" for f in findings) else ("friction" if findings else "pass")
            hosts, bad = hosts_of(answer.get("commands", []))
            text = report_text(persona, verdict, findings, tokens, capped, hosts=labelled(hosts), unparsed=bad)
        else:       # fail closed: whatever is not exactly the contract is a blocking persona that did not run
            findings = [{"kind": "blocking", "text": "%s did not run: %s" % (persona, did_not_run)}]
            tokens, capped, verdict = None, False, "blocking"
            hosts, bad = hosts_of(transcript_commands(transcript))
            text = report_text(persona, verdict, [], None, False, did_not_run, hosts=labelled(hosts), unparsed=bad)
        ok = encrypt(a.recipient, persona, out_dir, itertools.chain([text.encode("utf-8", "replace"), b"\n=== TRANSCRIPT ===\n"],
                                                                    (c.encode("utf-8", "replace") for c in transcript_chunks(transcript, secrets))))
        if not ok:          # no readable fallback: the persona fails closed and nothing plaintext exists
            findings = [{"kind": "blocking", "text": "the report could not be encrypted"}]
            verdict = "blocking"
        results[persona] = {"verdict": verdict, "findings": findings, "tokens": tokens, "capped": capped, "encfail": not ok}
        sys.stderr.write("persona-uat: %s: %s\n" % (persona, "fail" if verdict == "blocking" else "pass"))

    def all_did_not_run(reason):
        for p in PERSONAS:
            if p not in results:
                record(p, None, "did not run: %s\n" % reason, reason)

    docs = read_docs(os.path.abspath(a.repo))
    started = []
    sandboxes = []
    teardown_failed = False
    TD = "teardown failed: window not attributable"
    try:
        if docs is None:
            all_did_not_run("the public README.md is missing")
            finish(results, out_dir)
            return 3
        for persona in PERSONAS:
            if persona in results:
                continue
            if teardown_failed:         # a survivor may still be sending traffic: no window after it is attributable, and nothing new is started
                record(persona, None, "did not run: %s\n" % TD, "%s (an earlier teardown failed)" % TD)
                continue
            # the job's time budget: this persona's agent timeout is what is left of the budget over the personas still to run (itself included), never above --agent-timeout
            left = len([q for q in PERSONAS if q not in results])
            persona_timeout = int(min(a.agent_timeout, (a.job_budget - (time.time() - job_t0)) / left))
            if persona_timeout < min(a.min_persona_seconds, a.agent_timeout):      # an explicitly short --agent-timeout is the caller's choice, not a lack of budget
                why_ = "cannot prove: the job's time budget left no time for this persona (%d seconds each, %d needed)" % (max(persona_timeout, 0), a.min_persona_seconds)
                record(persona, None, "did not run: %s\n" % why_, why_)
                continue
            token_seconds = min(86400, max(3600, persona_timeout + TOKEN_MARGIN))      # the persona's kubeconfig token outlives its window
            tool_cids, req_tools = [], {}
            cluster = None
            sandbox = tempfile.mkdtemp(prefix="persona-uat-")
            sandboxes.append(sandbox)
            tdir = tempfile.mkdtemp(prefix="persona-uat-tr-")          # the agent's streamed transcript: private, outside the sandbox the shell containers mount

            image_cids = []

            def teardown_tools(image=False):
                """the persona's tool containers and its cluster are gone (and, with image=True, its OWN container of the image under test: that one is removed only AFTER the
                closing scrape reads its counter). -> False when one could not be removed"""
                ok = cluster.delete() if cluster else True
                ok = docker.remove(tool_cids) and ok
                del tool_cids[:]
                if image:
                    ok = docker.remove(image_cids) and ok
                    del image_cids[:]
                return ok and not Cluster.leaked
            img_port = free_port()          # this persona's endpoint: a container of its own, a host port of its own, a request counter of its own
            try:
                files = dict(docs)
                if persona == "readme-evaluator":
                    files = {"README.md": docs["README.md"]}
                for name, data in files.items():
                    dest = os.path.join(sandbox, name)
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    with open(dest, "wb") as fh:
                        fh.write(data)
                open_modes(sandbox)
                try:
                    cid = docker.start(a.image, (img_port, 8080))
                    image_cids.append(cid)
                    started.append(cid)
                    wait_ready(docker, cid, "http://127.0.0.1:%d" % img_port, a.ready_timeout)
                except Exception as e:
                    reason = "the image under test did not start or answer (%s)" % e
                    if not teardown_tools(image=True):
                        teardown_failed = True
                        reason += "; " + TD
                    record(persona, None, "did not run: %s\n" % reason, reason)
                    continue
                try:
                    for i, tool in enumerate(TOOLS_FOR.get(persona, ())):
                        if tool == "jenkins":
                            tc = docker.start(tools[tool], (a.port + 1, 8080), env=JENKINS_ENV); tool_cids.append(tc)
                            wait_ready(docker, tc, "http://127.0.0.1:%d" % (a.port + 1), a.ready_timeout, strict=True)
                            req_tools[tool] = {"container": tc, "endpoint": "http://127.0.0.1:%d" % (a.port + 1)}
                        elif tool == "gitlab-runner":
                            tc = docker.start(tools[tool], (a.port + 2, 9252), tail=("run", "--listen-address=0.0.0.0:9252")); tool_cids.append(tc)
                            wait_ready(docker, tc, "http://127.0.0.1:%d/metrics" % (a.port + 2), a.ready_timeout)
                            req_tools[tool] = {"container": tc, "endpoint": "http://127.0.0.1:%d" % (a.port + 2)}
                        else:
                            cluster = Cluster(tools[tool], timeout=max(a.ready_timeout * 2, 3))
                            kc = cluster.provision(token_seconds)
                            with open(os.path.join(sandbox, "kubeconfig"), "w") as fh:
                                fh.write(kc)
                            open_modes(sandbox)
                            req_tools[tool] = {"endpoint": cluster.server, "kubeconfig": "kubeconfig", "namespace": PERSONA_NS}
                except Exception as e:
                    reason = "a tool container did not start or answer (%s)" % e
                    if not teardown_tools(image=True):
                        teardown_failed = True
                        reason += "; " + TD
                    record(persona, None, "did not run: %s\n" % reason, reason)
                    continue
                if not docker.running(cid):
                    record(persona, None, "did not run: the image under test stopped\n", "the image under test stopped")
                    continue
                request = {
                    "docs_dir": sandbox, "endpoint": "http://127.0.0.1:%d" % img_port, "image": a.image,
                    "instructions": INSTRUCTIONS[persona] + " " + CLASSIFY,
                    "model": models["PERSONA_UAT_COMPLIANCE_MODEL" if persona == "compliance-reviewer" else "PERSONA_UAT_MODEL"],
                    "persona": persona, "token_budget": budget, "tools": req_tools,
                }
                try:
                    stray = sorted(loopback_listeners(a.proc_net) - {53, a.port, a.port + 1, a.port + 2, img_port} - set(a.allow_listen) - ({cluster.port} if cluster else set()))
                except Refuse as e:
                    record(persona, None, "did not run: %s\n" % e, "the loopback could not be inspected (%s)" % e)
                    continue
                if stray:
                    record(persona, None, "did not run: unexpected loopback listener(s)\n",
                           "an unexpected listener is bound to the loopback (port%s %s): a persona's containers share the host network, so none runs" % ("s" if len(stray) > 1 else "", ", ".join(map(str, stray))))
                    continue
                label = "persona-uat=%s" % uuid.uuid4()
                tfile = os.path.join(tdir, "transcript")
                args = ["--docker", " ".join(shlex.quote(t) for t in docker_cmd), "--tools", os.path.abspath(a.tools), "--label", label, "--transcript-file", tfile]
                ep = "http://127.0.0.1:%d" % img_port
                before = scrape(ep)
                answer, transcript, why = run_agent(agent_cmd, args, request, sandbox, persona_timeout, tfile)
                # the window is closed BEHIND everything of this persona: its containers (swept by label), its tool containers and cluster are removed, THEN the counter is
                # read once no connection to the endpoint is left and it has been unchanged for the quiet interval
                swept = sweep(docker, label)
                tools_gone = teardown_tools()
                after = settled(ep, a.settle_quiet, a.settle_max, lambda: established_to(a.proc_net, img_port) == 0)
                cleaned = cleanup(docker, label, sandbox, tools["shell"])
                image_gone = docker.remove(image_cids)          # the persona's container goes only now, after its counter was read; whatever completes in it later counts for nobody
                del image_cids[:]
                tools_gone = tools_gone and image_gone
                if after is UNSETTLED:
                    after = None
                    cannot = ("cannot prove: this persona's window could not be closed (a connection to its container stayed open or its request counter kept changing for %d seconds)"
                              % a.settle_max)
                elif persona != "compliance-reviewer" and (before is None or after is None):
                    cannot = "cannot prove: the request counter of this persona's container could not be read (the opening or the closing scrape failed)"
                else:
                    cannot = None
                ok = before is not None and after is not None and after - before > 0
                if not (swept and tools_gone and cleaned):
                    teardown_failed = True          # this persona and every later one: a survivor may have sent traffic into a window we cannot attribute
                    record(persona, None, (transcript if answer is None else answer["transcript"]) or "", "%s%s" % (TD, "" if answer is not None else "; " + why))
                elif cannot:
                    record(persona, answer, answer["transcript"] if answer is not None else transcript, None if answer is not None else cannot, proven=False,
                           extra_blocking=cannot if answer is not None else None)
                elif answer is None:
                    record(persona, None, transcript, why)
                else:
                    record(persona, answer, answer["transcript"], proven=ok)
            finally:
                teardown_tools(image=True)
                shutil.rmtree(tdir, ignore_errors=True)
    finally:
        docker.remove(started)          # whatever is left of the personas' containers (they were removed with each persona's teardown)
        for s_ in sandboxes:
            for d, dirs, fs in os.walk(s_):
                try:
                    os.chmod(d, 0o777)
                except OSError:
                    pass
            shutil.rmtree(s_, ignore_errors=True)
        tf = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")       # the job re-mints it every few minutes; nothing of it outlives this run
        if tf:
            try:
                os.remove(tf)
            except OSError:
                pass
    return finish(results, out_dir)


def finish(results, out_dir=None):
    blocking = [p for p in PERSONAS if results[p]["verdict"] == "blocking"]
    enc_failed = [p for p in PERSONAS if results[p].get("encfail")]
    if out_dir is not None:
        publish_artifacts(out_dir, not enc_failed)
    line = "persona-uat: overall: %s\n" % ("fail" if blocking else "pass")
    sys.stderr.write(line)
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        with open(summ, "a") as fh:
            for p in PERSONAS:
                fh.write("persona-uat: %s: %s\n" % (p, "fail" if results[p]["verdict"] == "blocking" else "pass"))
            fh.write(line)
    return 1 if blocking else 0


STAGE = []        # destination paths written so far: one failure and every one of them (and the failed one) is removed


def encrypt(recipient, persona, out_dir, chunks):
    """openssl cms -encrypt reading the payload from STDIN, chunk by chunk (a transcript of many megabytes is never held twice, and no plaintext file is written); the
    ciphertext goes to <out>/<persona>.cms. -> False on any failure (the caller removes every artifact)"""
    dest = os.path.join(out_dir, persona + ".cms")
    STAGE.append(dest)
    try:
        p = subprocess.Popen(["openssl", "cms", "-encrypt", "-aes-256-cbc", "-binary", "-outform", "DER", "-recip", recipient, "-out", dest],
                             stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=clean_env())
        try:
            for c in chunks:
                p.stdin.write(c)
            p.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        p.wait(timeout=600)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
        return False
    return p.returncode == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0


def publish_artifacts(out_dir, ok):
    if not ok:
        for d in STAGE:
            try:
                os.remove(d)
            except OSError:
                pass
    STAGE.clear()


if __name__ == "__main__":
    sys.exit(main())
