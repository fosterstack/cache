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

PERSONAS = ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer")
TOOLS_FOR = {"maven-jenkins-ci": ("jenkins", "gitlab-runner"), "on-call-engineer": ("kind",)}
DIGEST_REF = re.compile(r"^[a-z0-9][^\s@]*@sha256:[0-9a-f]{64}$")
TOOL_KEYS = ("cosign", "gitlab-runner", "gradle", "jenkins", "kind", "kubectl", "maven", "shell")
KIND_NAME = "persona-uat"
PERSONA_NS = "persona"
JENKINS_ENV = "JAVA_OPTS=-Djenkins.install.runSetupWizard=false"
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")
METRIC_RE = re.compile(r"^fscache_http_requests_total(\{[^}]*\})?\s+([0-9.eE+-]+)(\s+\d+)?\s*$")
DEFAULT_BUDGET = 400000
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


def settled(ep, quiet_for=SETTLE_QUIET, ceiling=SETTLE_MAX):
    """the real server counts AFTER its response: wait until the total has been UNCHANGED across readings spanning `quiet_for` seconds (a change restarts the interval),
    giving up after `ceiling`. A request that finishes server-side later than that is not attributed to the window: the limit is stated in every report header."""
    v = scrape(ep)
    if v is None:
        return None
    t0 = quiet = time.time()
    while time.time() - quiet < quiet_for:
        if time.time() - t0 >= ceiling:
            return None                 # never settles: not attributable
        time.sleep(0.2)
        w = scrape(ep)
        if w is None:
            return None
        if w != v:
            v, quiet = w, time.time()
    return v


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


def streamed(tfile):
    """what the agent had written to its transcript file (every completed action) before it ended, killed or not: whole up to one million characters, else the first
    200000 and the last 800000 with an explicit marker of how many were omitted (the file is read bounded, never whole, whatever its size)"""
    try:
        size = os.path.getsize(tfile)
        with open(tfile, "rb") as fh:
            if size <= TRANSCRIPT_KEEP_HEAD + TRANSCRIPT_KEEP_TAIL:
                return fh.read().decode("utf-8", "replace")
            head = fh.read(TRANSCRIPT_KEEP_HEAD)
            fh.seek(size - TRANSCRIPT_KEEP_TAIL)
            tail = fh.read(TRANSCRIPT_KEEP_TAIL)
        return "%s\n[... %d characters omitted ...]\n%s" % (head.decode("utf-8", "replace"), size - TRANSCRIPT_KEEP_HEAD - TRANSCRIPT_KEEP_TAIL, tail.decode("utf-8", "replace"))
    except (OSError, TypeError):
        return ""


def run_agent(agent_cmd, agent_args, request, sandbox, timeout, tfile=None):
    """-> (answer or None, transcript text, failure reason or None). The agent's stderr is kept for the transcript FILE only; the actions it completed before a
    timeout or a failure come from its streamed transcript file."""
    p = subprocess.Popen(agent_cmd + agent_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=sandbox,
                         env=clean_env(MODEL_ENV_PREFIX), text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(json.dumps(request), timeout=timeout)
    except subprocess.TimeoutExpired:
        for pid in descendants(p.pid):          # work the agent started in other sessions survives a killpg: find it first
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = p.communicate()
        return None, "agent timed out after %ss\n%s\n%s" % (timeout, streamed(tfile), (err or "")[-200000:]), "timed out after %ss" % timeout
    if p.returncode != 0:
        return None, "agent failed (exit %d)\n%s\n%s" % (p.returncode, streamed(tfile), err[-200000:]), "the agent failed (exit %d)" % p.returncode
    try:
        return validate_answer(out), None, None
    except ValueError as e:
        return None, "the agent's answer was refused: %s\n%s\n%s" % (e, streamed(tfile), err[-200000:]), "the agent's answer is outside the contract (%s)" % e


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
                       "data-binary", "data-urlencode", "json", "connect-timeout"},
              "wget": {"output-document", "output-file", "directory-prefix", "user", "password", "header", "tries", "timeout", "execute", "input-file", "base", "user-agent",
                       "post-data", "post-file", "body-data", "body-file"}}
FILE_VALUE = {"curl": ({"K"}, {"config"}), "wget": ({"i"}, {"input-file"})}      # the value is a FILE whose content is not observed (its name is never a host)


def _strip_host(v):
    """HOST from HOST[:port][/path] or scheme://HOST..., or None"""
    if "://" in v:
        return urllib.parse.urlsplit(v).hostname
    return _host_of(v) if HOST_RE.match(v) else None


def _option_hosts(prog, name, value):
    """hosts a value-taking option NAMES: a URL, a proxy, --connect-to HOST1:P1:HOST2:P2, --resolve HOST:PORT:ADDR, wget -e http_proxy=HOST, wget -B HOST"""
    out = []
    if prog == "curl" and name in ("url", "proxy", "x"):
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


def _host_of(tok):
    try:
        return urllib.parse.urlsplit("//" + tok).hostname
    except ValueError:
        return None


def url_hosts(text):
    out = set()
    lines_ = []
    for l in text.splitlines():
        if l.lstrip().startswith("#"):
            continue
        try:
            l = " ".join(_shlex.quote(t) for t in _shlex.split(l, comments=True))        # an inline `# comment` is not a contact either (quoting kept: a quoted header is one word)
        except ValueError:
            pass
        lines_.append(l)
    text = "\n".join(lines_)
    clone_urls = {u for ln in text.splitlines() if re.search(r"\bgit\s+clone\b", ln) for u in URL_RE.findall(ln)}
    for u in URL_RE.findall(text):
        try:
            h = urllib.parse.urlsplit(u).hostname
        except ValueError:
            continue
        if h:
            h = h.lower()
            out.add(h + REPO_SRC if (h in ("raw.githubusercontent.com", "codeload.github.com") or GH_SRC.match(u) or GH_API_SRC.match(u) or (u in clone_urls and h == "github.com")) else h)
    for line in text.splitlines():
        try:
            toks = _shlex.split(line, comments=True)
        except ValueError:
            continue
        prog = next((t for t in toks if t in ("curl", "wget", "kubectl", "cosign")), None)
        if prog is None:
            continue
        if prog == "cosign":
            for t in toks:
                if "://" not in t and re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::[0-9]+)?/\S+$", t):
                    out.add(t.split("/")[0].lower())
            continue
        if prog == "kubectl":
            for i, t in enumerate(toks):
                v = t.split("=", 1)[1] if t.startswith("--server=") else (toks[i + 1] if t == "--server" and i + 1 < len(toks) else None)
                if v and "://" not in v and HOST_RE.match(v):
                    out.add(_host_of(v).lower())
            continue
        opt_hosts, positional = _fetch_tokens(prog, toks[toks.index(prog) + 1:])
        out.update(opt_hosts)
        for t in positional:
            if "://" not in t and HOST_RE.match(t) and not re.search(r"\.(txt|json|zip|tgz|gz|xml|yaml|yml|pom|jar)(?::|$)", t.split("/")[0]):
                out.add(_host_of(t).lower())
    return out


def registry_of(ref):
    first = ref.split("/")[0]
    return first.lower() if "/" in ref and ("." in first or ":" in first or first == "localhost") else "docker.io"


HOSTS_LABEL = "Hosts named in its commands (redirects and tool-internal contacts such as dependency downloads are not observed):"
ENV_LIMITS_LINE = "Environment limits of this run (reported as friction, never blocking): " + "; ".join("(%s) %s" % (k, t) for k, t in zip("abcd", LIMITS))
COUNTER_LIMIT = ("Counter limit: a request that finishes server-side more than 3 seconds after its response is not attributed to the persona's window "
                 "(no in-flight gauge exists to prove otherwise).")


def verified_digest(answer, image):
    """the compliance reviewer's proof of exercising the RC image: a recorded ACTION whose tool is cosign, whose subcommand is `verify` (the one cosign verification
    docs/verify-images.md documents for an image), that names the RC image by its DIGEST as an argument (an argument ending @sha256:<digest>, not a flag's value and not
    text in a shell command), and that exited 0. Words in echo, comments or shell actions are never proof."""
    digest = image.split("@")[-1]
    if not digest.startswith("sha256:"):
        return False
    for act in answer.get("actions", []):
        argv = act.get("argv", [])
        if (act.get("tool") == "cosign" and act.get("exit") == 0 and argv and argv[0] == "verify"
                and any(not t.startswith("-") and t.endswith("@" + digest) for t in argv[1:])):
            return True
    return False


def report_text(persona, verdict, findings, tokens, capped, did_not_run=None, hosts=None):
    lines = ["VERDICT: %s" % verdict, "persona: %s" % persona, ""]
    lines += [ENV_LIMITS_LINE, COUNTER_LIMIT, ""]
    if hosts is not None:
        lines += ["%s %s" % (HOSTS_LABEL, ", ".join(hosts) if hosts else "none"), ""]
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
    out_dir = os.path.abspath(a.out)
    os.makedirs(out_dir, exist_ok=True)
    secrets = [v for v in models.values() if len(v) >= 4]
    run_id = os.environ.get("GITHUB_RUN_ID") or "local"

    prev = [0.0]
    results = {}        # persona -> {"verdict", "findings", "tokens", "capped"}

    def known_hosts():
        doc_hosts = set()
        for data in (docs or {}).values():
            doc_hosts |= url_hosts(data.decode("utf-8", "replace"))
        return doc_hosts | {"127.0.0.1", "localhost", registry_of(a.image)} | {registry_of(v) for v in tools.values()}      # the image under test's own registry is not "outside"

    def labelled(hosts):
        src = {h for h in hosts if h.endswith(REPO_SRC)}
        plain = {h for h in hosts if not h.endswith(REPO_SRC)}
        out = set()
        for h in (plain - known_hosts()):
            out.add(h)
        for h in src:
            out.add(h[:-len(REPO_SRC)] + " (repository source)")
        return sorted(out)

    def record(persona, answer, transcript, did_not_run=None, proven=True):
        if answer:
            findings, tokens = list(answer["findings"]), answer["tokens"]
            if persona == "compliance-reviewer":
                proven = verified_digest(answer, a.image)         # the reviewer never calls the endpoint: its proof is a successful verification of the RC's digest
            if not proven:
                # no proof of exercising the RC image blocks the persona whatever else it reported (friction stays information, and stays in the report)
                findings.append({"kind": "blocking", "text": (
                    "the persona did not exercise the image under test: no verification action (cosign verify, attestation, SBOM or VEX) naming the release candidate's digest exited 0"
                    if persona == "compliance-reviewer" else
                    "the persona did not exercise the image under test: the endpoint was never exercised (its request counter did not move during this persona's run)")})
            capped = tokens >= budget
            verdict = "blocking" if any(f["kind"] == "blocking" for f in findings) else ("friction" if findings else "pass")
            hosts = set()
            for c in answer.get("commands", []):
                hosts |= url_hosts(c)
            text = report_text(persona, verdict, findings, tokens, capped, hosts=labelled(hosts))
        else:       # fail closed: whatever is not exactly the contract is a blocking persona that did not run
            findings = [{"kind": "blocking", "text": "%s did not run: %s" % (persona, did_not_run)}]
            tokens, capped, verdict = None, False, "blocking"
            hosts = set()
            for ln in transcript.splitlines():
                if ln.startswith("$ "):
                    hosts |= url_hosts(ln[2:])
            text = report_text(persona, verdict, [], None, False, did_not_run, hosts=labelled(hosts))
        transcript = scrub(transcript, secrets)
        ok = encrypt(a.recipient, persona, out_dir, text + "\n=== TRANSCRIPT ===\n" + transcript)
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
    token_seconds = min(86400, max(3600, a.agent_timeout + TOKEN_MARGIN))      # the persona's kubeconfig token outlives its window
    try:
        if docs is None:
            all_did_not_run("the public README.md is missing")
            finish(results, out_dir)
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
            if teardown_failed:         # a survivor may still be sending traffic: no window after it is attributable, and nothing new is started
                record(persona, None, "did not run: %s\n" % TD, "%s (an earlier teardown failed)" % TD)
                continue
            tool_cids, req_tools = [], {}
            cluster = None
            sandbox = tempfile.mkdtemp(prefix="persona-uat-")
            sandboxes.append(sandbox)
            tdir = tempfile.mkdtemp(prefix="persona-uat-tr-")          # the agent's streamed transcript: private, outside the sandbox the shell containers mount

            def teardown_tools():
                """every tool container and the cluster of THIS persona are gone. -> False when one could not be removed"""
                ok = cluster.delete() if cluster else True
                ok = docker.remove(tool_cids) and ok
                del tool_cids[:]
                return ok and not Cluster.leaked
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
                    if not teardown_tools():
                        teardown_failed = True
                        reason += "; " + TD
                    record(persona, None, "did not run: %s\n" % reason, reason)
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
                    stray = sorted(loopback_listeners(a.proc_net) - {53, a.port, a.port + 1, a.port + 2} - set(a.allow_listen) - ({cluster.port} if cluster else set()))
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
                ep = "http://127.0.0.1:%d" % a.port
                before = scrape(ep)
                answer, transcript, why = run_agent(agent_cmd, args, request, sandbox, a.agent_timeout, tfile)
                swept = sweep(docker, label)        # containers are the daemon's: whatever this persona's agent left is removed before the window closes
                after = settled(ep, a.settle_quiet, a.settle_max)
                cleaned = cleanup(docker, label, sandbox, tools["shell"])
                tools_gone = teardown_tools()       # the tool containers and the cluster go after the window is read, before the next persona's
                if not [q for q in PERSONAS if q not in results and q != persona]:
                    # the last persona: the image under test goes with the rest, and a container that cannot be removed fails the run like any other teardown
                    if docker.remove(started):
                        del started[:]
                    else:
                        tools_gone = False
                ok = before is not None and after is not None and after - before > 0 and not (before == 0 and prev[0] > 0)
                if after is not None:
                    prev[0] = after
                if not (swept and tools_gone and cleaned):
                    teardown_failed = True          # this persona and every later one: a survivor may have sent traffic into a window we cannot attribute
                    record(persona, None, (transcript if answer is None else answer["transcript"]) or "", "%s%s" % (TD, "" if answer is not None else "; " + why))
                elif answer is None:
                    record(persona, None, transcript, why)
                else:
                    record(persona, answer, answer["transcript"], proven=ok)
            finally:
                teardown_tools()
                shutil.rmtree(tdir, ignore_errors=True)
    finally:
        docker.remove(started)
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


def encrypt(recipient, persona, out_dir, payload):
    dest = os.path.join(out_dir, persona + ".cms")
    STAGE.append(dest)
    try:
        r = subprocess.run(["openssl", "cms", "-encrypt", "-aes-256-cbc", "-binary", "-outform", "DER", "-recip", recipient, "-out", dest], input=payload.encode("utf-8", "replace"),
                           capture_output=True, env=clean_env(), timeout=120)
    except Exception:
        return False
    return r.returncode == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 0


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
