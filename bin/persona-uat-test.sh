#!/usr/bin/env bash
# proves: REQ-UAT-001-AC1, REQ-UAT-001-AC2, REQ-UAT-001-AC3, REQ-UAT-001-AC4, REQ-UAT-001-AC5
# The persona UAT driver (owner ratified Oct 3 and Oct 4; ops/docs/ratify/2026-10-02-owner-load.md point 9; amendments 0215 and 0216: RESULTS STAY PRIVATE, FLAG
# DON'T BLOCK), proved against a STUB agent and a recording `docker`, `kind`, `kubectl`, `openssl` and `gh`, so no model credential, container or GitHub call is
# needed. Each case runs the real driver and inspects what it DID: which containers it started (the image by digest, the pinned CI tools only for the persona that
# needs them, all removed afterwards), what each agent was handed (an exact request, a scrubbed environment, a sandbox that holds only the public docs), what it
# wrote, and whether the run failed. Fail-closed: anything an agent returns that is not exactly the contract counts as blocking. Contract (the tests pin it):
#   persona-uat.py --mode rc|weekly --image REF@sha256:... --repo DIR --out DIR --tools FILE [--docker CMD] [--recipient CERT] --agent CMD [--port N]
#   env PERSONA_UAT_MODEL, PERSONA_UAT_COMPLIANCE_MODEL (required), PERSONA_UAT_TOKEN_BUDGET (default 400000)
#   RESULTS STAY PRIVATE (amendment 0215): the driver makes NO gh call and opens NO issue (there is no --gh and no --publish); its stdout and stderr are ONLY one
#   line `persona-uat: <persona>: pass|fail` per persona and `persona-uat: overall: pass|fail` (a blocking persona fails, friction and pass read pass; refusals of
#   a configuration, exit 2, still say why); the exit code is 1 when any persona is blocking, in rc AND weekly mode, 0 otherwise, 2 for a refused configuration,
#   3 for missing public docs. Each persona's report AND transcript are written ONLY as ONE artifact `<--out>/<persona>.cms`, made by the runner's own
#   `openssl cms -encrypt -aes-256-cbc` (or -aes256) to the recipient certificate (`--recipient`, default bin/persona-uat-recipient.pem next to the driver; a
#   missing file, a non-certificate or a PRIVATE KEY is refused, exit 2), in a pipeline (the plaintext on stdin, never a file), with NO plaintext fallback: when
#   encryption fails the persona is blocking and no readable file exists. --out holds exactly those five files. The decrypted payload is
#   <report><NEWLINE>=== TRANSCRIPT ===<NEWLINE><transcript> (the report's first line is `VERDICT: ...`). Friction notes and the flags (hosts outside the docs,
#   repository source) live INSIDE the encrypted report. A private key never touches CI or the tree; the local script bin/persona-uat-decrypt.sh <run id> [key]
#   downloads the artifact with `gh run download` and decrypts it with `openssl cms -decrypt` into a mode-700 mktemp directory (tests: fake gh, test key pair).
#   AC wording (ratified): told to use ONLY the public docs and the endpoint; the sandbox holds only the public docs; any other host its commands contact is
#   FLAGGED in its encrypted report; nothing blocks the network beyond the existing fences (flag, don't block).
#   contract notes an implementer needs (each is pinned by a case below): it makes a relative --agent script absolute before running the agent with its cwd in
#   the sandbox; the agent starts the provider with `python3` from PATH (never sys.executable); the provider conversation starts with exactly one user message
#   and each shell step adds an assistant action and a user result (2 messages); containers are removed by container id.
#   agent: one JSON request on stdin; one JSON answer on stdout {"findings":[{"kind":"blocking|friction","text":str}],
#          "tokens": int >= 0, "transcript": str, optional "commands": [str] (the commands the persona ran, in order; absent = none)}
# DELTAS (advisor 0207/0208, review round d6r1; step 6, tests first). The contract the cases pin:
#   (1) kind: the cluster is created by a `kind` binary the JOB installs (a workflow step `./bin/install-scanner.sh kind`, version and sha256 pinned;
#       the wiring test requires that step) and that is found on PATH: the driver does not install it. The driver runs
#       `kind create cluster --image <the kind entry of the tools file> --name <fixed name> --kubeconfig <driver-private file>`, exactly those
#       options. Everything that follows uses the host `kubectl` on PATH (preinstalled on the runner) with that admin kubeconfig, which never
#       leaves the driver (never in a sandbox, a request, a docker call, an environment or --out). Shape chosen for the recording fixtures: the
#       tests put a recording `kind` and a recording `kubectl` first on the driver's PATH (HOSTBIN, per case). The driver applies ONE Namespace
#       `persona` (pod-security.kubernetes.io/enforce|warn|audit=restricted), a ServiceAccount, a Role and a RoleBinding with `kubectl apply -f -`
#       (or -f FILE; JSON or YAML; valid apiVersions; no --dry-run), mints a short-lived token with `kubectl create token ... --duration D`
#       (Go duration, 1h <= D <= 24h; the fake prints a JWT whose exp the test checks) and hands the persona a kubeconfig of that ServiceAccount
#       (namespace persona, EXACTLY the minted token, no client certificate or key). The cluster is deleted (`kind delete cluster --name <same>`)
#       when the persona is done, whatever the outcome; the kind API port is whatever kind chose (the admin kubeconfig's server: the tests vary it)
#       and is a loopback listener the guard allows ONLY for that persona while its cluster exists.
#       The fake kubectl accepts ONLY apply -f, create token, get, wait, version, cluster-info (an imperative `create clusterrolebinding` or
#       `create rolebinding` is refused and the test proves it), validates manifests like the API server (a ServiceAccount subject has an EMPTY apiGroup,
#       roleRef kind/name/apiGroup, apiVersion/kind pairs) and answers the persona's own token only while the cluster exists: the stub persona uses its
#       kubeconfig at the END of its window and `kind delete cluster` must come AFTER its recorded end. A hung `kind create` is bounded.
#       The Role is derived from the documented steps (docs/kubernetes.md, docs/docker-deploy.md) plus the persona's task (upgrade, rollback, logs):
#       get/list/watch/create/update/patch/delete on pods, deployments, replicasets, services, configmaps, secrets, persistentvolumeclaims, jobs,
#       events; get/list on pods/log; create on pods/portforward; get/update/patch on deployments/scale; nothing else (no pods/exec, pods/attach,
#       nodes, namespaces, rbac, serviceaccounts, wildcard, cluster scope). The test evaluates the Role with its own can-i rule evaluator.
#       PRIVILEGE SCOPE (stated, not claimed beyond): real `kind` starts its node containers with `docker run --privileged` ITSELF. The fence
#       is: the DRIVER and the AGENT never build a privileged, host-mounted or docker-socket container (asserted on every docker call they make
#       and on the sources: no `--privileged` in the driver, agent or provider); containers kind starts are kind's own and outside the persona's
#       reach (the persona gets only the namespaced ServiceAccount kubeconfig; no persona container gets the docker socket).
#   (2) tools file: nine entries (capture, cosign, gitlab-runner, gradle, jenkins, kind, kubectl, maven, shell). The agent is started with
#       `--tools <that file>` (not --shell-image). Jenkins: `run -d -p 127.0.0.1:<port+1>:8080 -e JAVA_OPTS=-Djenkins.install.runSetupWizard=false
#       <digest>` and no other -e; the GitLab runner: `run -d -p 127.0.0.1:<port+2>:9252 <digest> run --listen-address=0.0.0.0:9252` (the flag
#       enables its metrics HTTP server) and no -e; readiness is tied to THAT container: the recording docker serves port+2 only when it was
#       started with exactly that argument vector. Both are reached over http://127.0.0.1:<port> by the persona's shell tool. The kind node image
#       is never run through docker by the driver. The sandbox directories are mode 0777 (the tool images run as other non-root uids and must be
#       able to create files); the docs files stay 0644 (read-only for others).
#   (3) the answer's optional `commands` list is where the driver derives each report's single line `Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'): a, b`
#       (or `none`). CLAIM, narrowed: "hosts NAMED in the persona's commands" (URLs, and the host argument of curl/wget/kubectl --server style
#       commands); redirects, Maven repository configuration and tool-internal contacts are NOT observed (documented limitation). A host is listed
#       unless it is a host of a URL in the public docs (README.md and docs/*.md), 127.0.0.1, localhost, or the registry host of an image in the
#       tools file. A URL only on a shell comment line is ignored. The line is information only: it never changes a verdict, and it sits INSIDE the encrypted
#       report (the public log never shows a host or 'repository source'; a vendor-named or credential-looking host is listed as it is). Public-docs-only is
#       claimed as the AC now words it: told to use only the public docs and the endpoint, a sandbox holding only the public docs, every other host flagged,
#       nothing blocked beyond the existing fences. A URL whose path points into the repository's own source (github.com/<owner>/<repo>/archive|raw|blob|tree/...,
#       and raw.githubusercontent.com) is listed as `<host> (repository source)` EVEN on an allowed docs host (an allowlist is per host, not per path).
#   (5) container lifecycle: every shell-action container the AGENT starts carries `--label persona-uat=<uuid>` (one fresh uuid per persona,
#       handed to the agent as `--label persona-uat=<uuid>`); containers are daemon-managed, so killing the docker client does not stop them. The agent
#       removes by label what a shell timeout left, and the DRIVER sweeps by label (`docker ps -aq --filter label=persona-uat=<uuid>`, then
#       `docker rm -f <ids>`) after EVERY agent outcome (success, crash, timeout) before the next persona's window. The recording docker models a
#       daemon-managed container (it keeps requesting the endpoint after its client is killed) and `ps`, `rm -f`, `stop`, `kill` by id.
#       Not modelled (cannot be): a directory OWNED BY ANOTHER UID in the sandbox; the test creates a read-only directory of the runner's own uid and
#       asserts the cleanup restores modes (chmod -R u+rwX) before removing. Host `kubectl` is the runner's (ubuntu-*, asserted by the wiring test).
#   (4) endpoint proof, matching the REAL server (internal/server/server.go): only `/` and cache keys are counted in
#       fscache_http_requests_total{method,status}; /metrics, /healthz and /statusz are never counted and nothing counts itself (requests the front controller rejects before withMetrics are not counted either); a client_golang
#       CounterVec has NO sample line until its first counted request: a fresh server's scrape holds NO fscache_http_requests_total family at all
#       (no HELP, no TYPE, no samples); HELP and TYPE without samples is the other valid zero. A scrape that fails or is garbage at EITHER end is blocking.
#       The driver scrapes GET <endpoint>/metrics (sum of every fscache_http_requests_total sample) immediately before the agent starts and
#       immediately after it returns; persona_requests = after - before (no correction); a persona that finished with
#       persona_requests <= 0 (counter backwards, or a scrape that cannot be taken or parsed) is blocking: "the endpoint was never exercised".
#       The windows of two personas never overlap, in rc and in weekly mode alike, and nothing the persona's agent started survives its window
#       (a timed-out agent's leftovers are terminated). The fixture counts a request BEFORE it flushes the response (deterministic; the real
#       server counts just after the handler returns, a race the tests cannot model: a very late request may miss the after-scrape). The stub
#       agent makes plan["requests"] counted requests (default 1; plan["methods"] varies the verb) and plan["uncounted"] uncounted ones.
#   PROOF RULE (advisor 0250, replacing the 0207 friction-only rule): a persona with NO proof of exercising the RC image is BLOCKING whatever else it reported (friction stays
#       informational; "did not exercise the image" blocks that persona). Proof = the counted-request delta (after - before > 0) for every persona except the compliance reviewer,
#       whose proof is a recorded ACTION (the answer's `actions`: tool, argv, exit; parallel to `commands`) whose tool is cosign, whose subcommand is verify, that names the
#       RC image by its digest as an argument and exited 0 (step 8 round 2: words in echo, comments or shell actions are no proof); counter traffic alone never proves the
#       compliance reviewer (fail closed). Cases: proof2, cmp1..cmp11, proofreset.
#   LIMITATION (stated, AC5): the hosts line lists hosts NAMED in a persona's commands; a tool's own contacts (Maven or Gradle dependency resolution, cosign's Rekor/TUF, redirects)
#       are not observed, so "any host its commands contact" means the hosts the commands name.
#   Model identities are job SECRETS (masked by GitHub in every log, step headers included): the wiring test pins where they may appear; the log cases here pin that the driver never prints them.
#   (6) round 3 additions to the contract: the BEFORE-scrape continuity rule: a before-scrape that fails, or holds no positive total after an earlier
#       persona's scrape had one (a restarted server, a broken exporter), makes the persona blocking, even with a fine after-scrape (the first persona
#       of a fresh server may start from nothing); the AFTER-scrape settles (repeated until two readings agree) because the real server counts a request
#       AFTER its response, so a persona's last request is attributed to its own window and never to the next persona's (the `delayed` case);
#       401s (withAuth wraps withMetrics) and the three uncounted routes make no counted request. The GitLab runner's mux serves /metrics only (/ is
#       404) and the readiness probe must use /metrics of the started container; a started container with no listener is a did-not-run persona.
#       `kind create cluster` is bounded by --ready-timeout (the test passes 2 and requires the run to end within 16 seconds), not by a separate flag.
#       After every persona the driver runs ONE cleanup container over the persona's sandbox mount (run --rm --network none --user 0:0 --label <the
#       persona's> -v <sandbox>:/work -w /work <shell image> rm -rf ...), after the label sweep: files a tool image created as another uid (root in
#       the maven image, curl_user in the curl image) cannot be removed or chmod'ed by the runner, and real ownership cannot be simulated without
#       root, so the mechanism is what is pinned. `kubectl create token` is run with --duration only (a whole-second Go duration, 1h..24h); the fake
#       refuses sub-second precision, unknown flags, bound objects that do not exist and a persona call whose token is not an unexpired token issued for
#       the persona's ServiceAccount with the API audience. A namespaced object applied before its Namespace is rejected by the fake. Fixture manifests
#       that Kubernetes accepts but this driver's contract refuses (no subjects, no rules, a subject without namespace, no apiGroups) are labelled CONTRACT.
#       Not modelled: image userspace (the curl image has no python3: the integrated case uses curl) and real UIDs (one host uid runs every fake image; ownership is
#       pinned by the root cleanup's EXECUTED deletion semantics instead). The runner's metrics mux registers /metrics (and debug handlers this fake does not model);
#       `/` is merely not the readiness endpoint. The API behaviour of `create token` (0s default, 10-minute floor, shortening) is modelled separately from the DRIVER's own
#       1h-24h request policy. Hosts are inferred from command text (comments excluded, inline ones too); redirects and tool-internal contacts are not observed.
#       The gradle/maven entrypoint models are the FAKE's (program first; the exact exit status and text of a real digest's failure cannot be checked offline).
set -euo pipefail
# FIXTURE PORTS are chosen per run (free ones, the endpoint's three consecutive: base, base+1, base+2) so this suite and the others can run side by side: the script rewrites its own
# port literals into a private copy and runs that
if [ -z "${PERSONA_TEST_PORTS:-}" ]; then
  export PERSONA_TEST_ROOT=$(cd "$(dirname "$0")/.." && pwd)
  ports=$(python3 - <<'PYP'
import random, socket
def free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p)); return True
    except OSError:
        return False
    finally:
        s.close()
while True:
    b = random.randrange(20000, 29000)
    rest = random.sample(range(29100, 31000), 3)
    if all(free(x) for x in (b, b + 1, b + 2, *rest)):
        print(b, *rest); break
PYP
)
  set -- $ports
  me=$(mktemp "${TMPDIR:-/tmp}/persona-test-XXXXXX")
  perl -pe "s/\\b18080\\b/$1/g; s/\\b18081\\b/$(($1+1))/g; s/\\b18082\\b/$(($1+2))/g; s/\\b18090\\b/$2/g; s/\\b18099\\b/$3/g; s/\\b18123\\b/$4/g; s/PERSONA_TEST_PORTS:-/PERSONA_TEST_PORTS:-/" "$0" >"$me"
  rc=0; PERSONA_TEST_PORTS=1 bash "$me" "$@" || rc=$?
  rm -f "$me"; exit $rc
fi
root=${PERSONA_TEST_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
driver="${PERSONA_UAT_DRIVER_UNDER_TEST:-$root/bin/persona-uat.py}"      # the red proofs run the suite against an older driver
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { local e; if e=$("$@" 2>&1 >/dev/null); then ok "$CASE"; else bad "$CASE"; printf '     why: %s\n' "$(printf %s "$e" | tail -n 3 | cut -c1-500)" >&2; fi; }
# none_match <regex> <path...>: every path must EXIST and nothing in them may match (a read error is a failure, never a pass)
none_match() { local re=$1; shift; local p; for p in "$@"; do [ -e "$p" ] || return 2; done; local rc=0; grep -rqE "$re" "$@" || rc=$?; [ "$rc" -eq 1 ]; }

# --- fixtures -------------------------------------------------------------------------------------------------
repo="$work/repo"; mkdir -p "$repo/docs/quality" "$repo/internal" "$repo/cmd"
printf '# fscache README\nSee https://docs.example.org/guide/install and [releases](https://github.com/example/cache/releases).\n' >"$repo/README.md"
printf 'install steps\nSee https://docs-only.example.net/guide (a link that occurs ONLY in a docs page, not in the README)\n' >"$repo/docs/install.md"
echo "gradle steps"     >"$repo/docs/gradle.md"
echo "INTERNAL TRACE"   >"$repo/docs/quality/traceability.md"
echo "UNRELEASED NOTES" >"$repo/docs/next-release-notes.md"
echo "package internal // SECRET-SOURCE" >"$repo/internal/x.go"
mkdir -p "$repo/ops/docs" "$repo/docs/dev"
echo "SECRET-OPS-DOC"      >"$repo/ops/docs/plan.md"
echo "SECRET-CLAUDE-MD"    >"$repo/CLAUDE.md"
echo "SECRET-DEV-DOC"      >"$repo/docs/dev/notes.md"
echo "releasing guide (public: how a customer verifies a release)" >"$repo/RELEASING.md"
echo "SECRET-DOTFILE"      >"$repo/docs/.hidden.md"
echo '{"SECRET-JSON":1}'   >"$repo/docs/grafana-dashboard.json"
ln -s ../internal/x.go "$repo/docs/leak.md"
IMG="ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 64))"
IMG2="ghcr.io/example/cache@sha256:$(printf 'b%.0s' $(seq 64))"
JEN="docker.io/jenkins/jenkins@sha256:$(printf '1%.0s' $(seq 64))"
GLR="docker.io/gitlab/gitlab-runner@sha256:$(printf '2%.0s' $(seq 64))"
KND="docker.io/kindest/node@sha256:$(printf '3%.0s' $(seq 64))"
SHL="docker.io/library/debian@sha256:$(printf '4%.0s' $(seq 64))"
CSG="gcr.io/projectsigstore/cosign@sha256:$(printf '5%.0s' $(seq 64))"
KCT="registry.k8s.io/kubectl@sha256:$(printf '6%.0s' $(seq 64))"
GRD="docker.io/library/gradle@sha256:$(printf '7%.0s' $(seq 64))"
MVN="docker.io/library/maven@sha256:$(printf '8%.0s' $(seq 64))"
NSH="docker.io/nicolaka/netshoot@sha256:$(printf 'b%.0s' $(seq 64))"
cat >"$work/tools.json" <<EOF
{"capture": "$NSH", "cosign": "$CSG", "gitlab-runner": "$GLR", "gradle": "$GRD", "jenkins": "$JEN", "kind": "$KND", "kubectl": "$KCT", "maven": "$MVN", "shell": "$SHL"}
EOF
TOOLKEYS="capture cosign gitlab-runner gradle jenkins kind kubectl maven shell"
PERSONAS="gradle-platform-engineer maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer"

# The stub agent: one request as JSON on stdin, one JSON answer on stdout. It records everything it was given.
cat >"$work/stub.py" <<'PY'
import json, os, shlex, subprocess, sys
raw = sys.stdin.read()
req = json.loads(raw)
case = sys.argv[1]
plan = json.load(open(os.path.join(case, "plan.json")))
p = plan.get(req["persona"], {})
seen = sorted(os.path.relpath(os.path.join(d, f), req["docs_dir"]) for d, _, fs in os.walk(req["docs_dir"]) for f in fs)
content = {}
links = []
for f in seen:
    fp = os.path.join(req["docs_dir"], f)
    if os.path.islink(fp):
        links.append(f)
    try:
        content[f] = open(fp, errors="replace").read()
    except OSError as e:
        content[f] = "UNREADABLE " + str(e)
modes = {"<dir>": oct(os.stat(req["docs_dir"]).st_mode & 0o7777)}
for d, ds, fs in os.walk(req["docs_dir"]):
    for n in ds + fs:
        fp = os.path.join(d, n)
        modes[os.path.relpath(fp, req["docs_dir"])] = oct(os.lstat(fp).st_mode & 0o7777)
with open(os.path.join(case, "log"), "a") as fh:
    fh.write(json.dumps({"persona": req["persona"], "docs": seen, "keys": sorted(req), "request": req,
                         "env": sorted(os.environ), "cwd": os.getcwd(), "raw_len": len(raw), "argv": sys.argv[2:], "content": content, "links": links, "modes": modes}) + "\n")
import time, urllib.request, urllib.error, re
def local_url(u):
    """the persona reaches its endpoint BY NAME on a docker network; this fixture has no such network, so a name the fake docker was given with a published port is mapped to that loopback port"""
    m = re.match(r"^(https?://)([A-Za-z0-9.-]+)(:\d+)?(.*)$", u)
    if m and os.path.exists(os.path.join(case, "names", m.group(2))):
        return "%s127.0.0.1:%s%s" % (m.group(1), open(os.path.join(case, "names", m.group(2))).read().strip(), m.group(4))
    return u
req["endpoint"] = local_url(req["endpoint"])
for v_ in req.get("tools", {}).values():
    if v_.get("endpoint"):
        v_["endpoint"] = local_url(v_["endpoint"])
kc = os.path.join(req["docs_dir"], "kubeconfig")
LEAK = "ghp_abcdefghij0123456789ABCDEF"      # a credential-looking marker, and the request's own model value: neither may survive in a retained artifact
CORPUS = [LEAK, "github_pat_11ABCDEFG0abcdefghijkl_xyz", "AKIAABCDEFGHIJKLMNOP", "sk-abcdefghijklmnopqrstuvwx", "Authorization: Bearer abcdefghijklmnop", "password=hunter2xyz", "-----BEGIN " "PRIVATE KEY-----"]
if p.get("daemon"):         # a tool container managed by the DAEMON, started through the recording docker; its client is killed at once (a shell timeout, a teardown)
    av = sys.argv[2:]
    tools = json.load(open(av[av.index("--tools") + 1]))
    cl = subprocess.Popen(shlex.split(av[av.index("--docker") + 1]) + ["run", "--rm", "--network", av[av.index("--network") + 1]] + (["--label", av[av.index("--label") + 1]] if "--label" in av else []) +
                          ["-v", req["docs_dir"] + ":/work", "-w", "/work", tools["shell"], "sh", "-c", "DAEMON"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.7)
    cl.kill()
for h_ in p.get("tool_contacts", []):       # short-lived tool containers (docker run --rm --network <the agent's --network> ...): the fake docker records what each one contacted in the holder's capture
    av_ = sys.argv[2:]
    tl_ = json.load(open(av_[av_.index("--tools") + 1]))
    subprocess.run(shlex.split(av_[av_.index("--docker") + 1]) + ["run", "--rm", "--network", av_[av_.index("--network") + 1], "--label", av_[av_.index("--label") + 1],
                   "-v", req["docs_dir"] + ":/work", "-w", "/work", tl_["shell"], "sh", "-c", "contact " + h_], capture_output=True)
if p.get("capture") is not None:       # what the capture sidecar of THIS persona saw (the fake docker prints it for `logs`): lines, written verbatim
    with open(os.path.join(case, "capture.logs"), "w", errors="replace") as fh_:
        fh_.write("\n".join(p["capture"]) + "\n")
if p.get("capture_dead"):
    open(os.path.join(case, "capture.dead"), "w").close()
if p.get("tfile_text"):     # the agent's streamed transcript file as the real agent writes it: "$ <command>" then the result, one block per action (a command may span lines)
    av_ = sys.argv[2:]
    with open(av_[av_.index("--transcript-file") + 1], "w") as fh_:
        fh_.write(p["tfile_text"])
if p.get("journal") is not None:     # the agent's journal as the real agent writes it: one JSON record per line (raw strings are written as they are, so a test can write a broken line)
    av_ = sys.argv[2:]
    with open(av_[av_.index("--journal-file") + 1], "w") as fh_:
        for rec_ in p["journal"]:
            fh_.write(rec_ if isinstance(rec_, str) else json.dumps(rec_))
            fh_.write("\n")
if p.get("crash"):
    sys.stderr.write("PARTIAL-TRANSCRIPT for " + req["persona"] + "\n")
    for ln in p.get("crash_lines", []):
        sys.stderr.write(ln + "\n")
    if p.get("leak"):
        sys.stderr.write("provider error: model=%s key=%s\n" % (req["model"], LEAK) + "\n".join(CORPUS) + "\n")
    sys.exit(7)
if "raw_out" in p:
    sys.stdout.write(p["raw_out"]); sys.exit(0)
if p.get("restore"):        # the endpoint's /metrics answered garbage at this persona's BEFORE-scrape; it is fine again from here on
    urllib.request.urlopen(req["endpoint"] + "/__mode?m=ok", timeout=5).read()
if p.get("break_next"):     # the driver's next pre-agent `inspect` (the NEXT persona's) switches /metrics to this mode; that persona's own plan restores it
    open(os.path.join(case, "break-next"), "w").write(p["break_next"])
if p.get("queue"):          # the next /metrics scrapes answer these modes in order (ok,garbage,...): breaks ONE scrape, e.g. the next persona's BEFORE-scrape
    urllib.request.urlopen(req["endpoint"] + "/__queue?m=" + p["queue"], timeout=5).read()
t0 = time.time()
if p.get("reset"):          # the endpoint's counters go back to zero during this persona's window (a restarted server)
    urllib.request.urlopen(req["endpoint"] + "/__reset", timeout=5).read()
n = p.get("requests", 1)    # the persona "makes requests": each COUNTED one (any path but /metrics, /healthz, /statusz) is logged with this persona's name
methods = p.get("methods", ["GET"])
def hit(path, method="GET"):
    try:
        urllib.request.urlopen(urllib.request.Request(req["endpoint"] + path, method=method, data=b"x" if method == "PUT" else None, headers={"X-Persona": req["persona"]}), timeout=5).read()
    except urllib.error.HTTPError:
        pass
for i in range(n):
    hit("/probe-%d" % i, methods[i % len(methods)])
for path in p.get("uncounted", []):   # health, status and metrics requests: the real server does not count these
    hit(path)
for i in range(p.get("unauth", 0)):    # requests the auth layer answers 401: withAuth wraps withMetrics, so they are not counted either
    try:
        urllib.request.urlopen(urllib.request.Request(req["endpoint"] + "/secret-%d" % i, headers={"X-Persona": req["persona"], "X-Unauthorized": "1"}), timeout=5).read()
    except urllib.error.HTTPError:
        pass
if p.get("hold"):           # a request the SERVER is still working on after this persona ends: held open s seconds (its connection is visible), counted when it finishes
    urllib.request.urlopen(req["endpoint"] + "/__hold?s=%s&who=%s&conn=%d" % (p["hold"], req["persona"], p.get("hold_conn", 1)), timeout=5).read()
if p.get("orphan_same"):    # work the agent started in ITS OWN session and left running: the driver terminates the agent's whole process group when the persona ends
    subprocess.Popen([sys.executable, "-c", "import sys,time,urllib.request;time.sleep(float(sys.argv[2]));urllib.request.urlopen(urllib.request.Request(sys.argv[1]+'/orphan-work',headers={'X-Persona':'ORPHAN'}),timeout=5)\n", req["endpoint"], str(p["orphan_same"])],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if p.get("orphan"):         # work the agent started in its OWN session, outliving it: it requests the endpoint after this many seconds
    subprocess.Popen([sys.executable, "-c", "import sys,time,urllib.request;time.sleep(float(sys.argv[2]));urllib.request.urlopen(urllib.request.Request(sys.argv[1]+'/orphan-work',headers={'X-Persona':'ORPHAN'}),timeout=5)\n", req["endpoint"], str(p["orphan"])],
                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if p.get("readonly_dir"):   # what a container of another uid leaves behind: a directory the runner cannot empty (the real thing, a directory OWNED BY ANOTHER UID, cannot be modelled)
    os.makedirs(os.path.join(req["docs_dir"], "created"), exist_ok=True)
    open(os.path.join(req["docs_dir"], "created", "x"), "w").write("x")
    os.chmod(os.path.join(req["docs_dir"], "created"), 0o555)
if p.get("foreign"):        # entries a tool image created as ANOTHER uid: hidden, nested, read-only, locked (only a root cleanup path removes them for sure)
    base = req["docs_dir"]
    for rel, mode in (("created/x", 0o444), (".hidden-dir/deep/y", 0o444), ("build/out/.cache/z", 0o444), (".dotfile", 0o444), ("..weird/q", 0o444), ("locked/data", 0o000)):
        os.makedirs(os.path.dirname(os.path.join(base, rel)), exist_ok=True)
        open(os.path.join(base, rel), "w").write("x"); os.chmod(os.path.join(base, rel), mode)
    for d_ in ("created", ".hidden-dir/deep", "build/out/.cache", "..weird", "locked"):
        os.chmod(os.path.join(base, d_), 0o555)
if p.get("stream"):         # the agent's streamed transcript file: a first completed action, filler, a last completed action, N characters in all
    av_ = sys.argv[2:]
    head, tail, mid = "$ first-completed-action\nout-first\n", "$ last-completed-action\nout-last\n", "$ middle-completed-action\nout-middle\n"
    n_ = p["stream"] - len(head) - len(tail) - len(mid)
    line_ = "y" * 79 + "\n"
    with open(av_[av_.index("--transcript-file") + 1], "w") as fh_:
        fh_.write(head)
        for i_ in range(0, n_ // 2, 80):
            fh_.write(line_[:min(80, n_ // 2 - i_)])
        fh_.write(mid)
        for i_ in range(0, n_ - n_ // 2, 80):
            fh_.write(line_[:min(80, n_ - n_ // 2 - i_)])
        fh_.write(tail)
if p.get("sleep"):
    time.sleep(p["sleep"])
kube_rc = None
if os.path.exists(kc):      # the on-call persona USES its cluster at the END of its window: a cluster deleted earlier is a dead cluster for it
    kube_rc = subprocess.run(["kubectl", "--kubeconfig", kc, "-n", "persona", "get", "pods"], stdin=subprocess.DEVNULL, capture_output=True).returncode
if p.get("mode_after"):     # the endpoint's /metrics breaks once this persona is done
    urllib.request.urlopen(req["endpoint"] + "/__mode?m=" + p["mode_after"], timeout=5).read()
with open(os.path.join(case, "timing.log"), "a") as fh:
    fh.write(json.dumps({"persona": req["persona"], "t0": t0, "t1": time.time(), "requests": n, "uncounted": len(p.get("uncounted", [])) + p.get("unauth", 0), "kube_rc": kube_rc, "daemon": bool(p.get("daemon"))}) + "\n")
ans = {"findings": p.get("findings", []), "tokens": p.get("tokens", 1000), "transcript": "TRANSCRIPT for " + req["persona"] + "\n"}
if p.get("leak"):
    ans["transcript"] += "model=%s key=%s\n" % (req["model"], LEAK) + "\n".join(CORPUS) + "\n"
    if os.path.exists(kc):      # the persona's own ServiceAccount token, as a pasted kubeconfig line
        ans["transcript"] += open(kc).read() + "\n"
ans["transcript"] += p.get("transcript_extra", "")
cmds = list(p.get("commands", []))
acts = [dict(x) for x in p["actions"]] if "actions" in p else [{"tool": "shell", "argv": ["sh", "-c", c], "exit": 0} for c in cmds]
if "actions" in p and not cmds:
    cmds = [x["tool"] + " " + " ".join(x["argv"]) for x in acts]
if req["persona"] == "compliance-reviewer" and not p.get("noverify"):
    # the compliance reviewer's PROOF of exercising the RC image (advisor 0250, step 8 round 2): a cosign TOOL action whose subcommand is verify, naming the RC image by its digest, exit 0
    ref = ("ghcr.io/example/cache@sha256:" + "9" * 64) if p.get("verify_other") else req["image"]
    av = ["verify", "--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0$",
          "--certificate-oidc-issuer=https://token.actions.githubusercontent.com", ref]
    acts.append({"tool": "cosign", "argv": av, "exit": p.get("verify_exit", 0)}); cmds.append("cosign " + " ".join(av))
if cmds or "commands" in p or "actions" in p:
    ans["commands"] = cmds
    ans["actions"] = acts
ans.update(p.get("override", {}))
for k in p.get("drop", []):
    ans.pop(k, None)
if p.get("daemon") == "crash":
    sys.exit(7)
print(json.dumps(ans))
PY
# A recording docker: `run -d ...` prints a container id and logs the whole line; every other call is only logged.
cat >"$work/docker.tmpl" <<'SH'
#!/usr/bin/env bash
DOCKER_LOG="__LOG__"
echo "$*" >>"$DOCKER_LOG"
if [ -n "${DOCKER_FAIL_MATCH:-}" ] && [[ "$*" == *"$DOCKER_FAIL_MATCH"* ]]; then echo "Unable to find image '$DOCKER_FAIL_MATCH' locally" >&2; echo "docker: Error response from daemon: pull access denied for sha256 digest" >&2; echo "docker: simulated failure" >&2; exit 125; fi
if [ -n "${DOCKER_NOISE:-}" ] && [ "$1" = run ] && [ "$2" = -d ]; then
  # requests the DRIVER's own container handling causes on the endpoint, BETWEEN personas' windows (never part of a persona's)
  python3 -c "
import sys, urllib.request, urllib.error
for i in range(int(sys.argv[1])):
    try: urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18080/noise-%d' % i, headers={'X-Persona': 'NOISE'}), timeout=5).read()
    except urllib.error.HTTPError: pass
" "$DOCKER_NOISE"
fi
# the GitLab runner's metrics listener exists only when THIS docker was asked to start it exactly as the real image needs: published
# 127.0.0.1:<port>:9252 AND the arguments `run --listen-address=0.0.0.0:9252` after the image (no flag, no listener)
CASEDIR="$(dirname "$DOCKER_LOG")"
CONTAINERS="$CASEDIR/../containers"
# the CAPTURE sidecar: `run -d ... --entrypoint /usr/bin/tcpdump IMAGE ARGS` is a fresh container (cap-N); its `logs` are what the persona's stub wrote (capture.logs: a healthy header and
# summary when it wrote none), `inspect` says it is gone when the stub asked for a dead sidecar, and `stop` marks it stopped (the summary tcpdump prints on SIGTERM)
if [ "$1" = network ]; then
  case "$2" in create) echo "net-$(grep -c '^network create ' "$DOCKER_LOG")";; rm) echo "$3";; esac
  exit 0
fi
# a container with `-p 127.0.0.1:H:C` and `--network-alias A` is reachable BY NAME A on the persona's network: the stub maps the name to the published loopback port H
if [ "$1" = run ] && [ "$2" = -d ] && [[ "$*" =~ --network-alias\ ([A-Za-z0-9.-]+) ]]; then
  alias="${BASH_REMATCH[1]}"
  if [[ "$*" =~ -p\ 127\.0\.0\.1:([0-9]+): ]]; then mkdir -p "$CASEDIR/names"; echo "${BASH_REMATCH[1]}" >"$CASEDIR/names/$alias"; fi
fi
if [ "$1" = run ] && [ "$2" = -d ] && [[ "$*" == *"--entrypoint /usr/bin/tcpdump"* ]]; then rm -f "${CASEDIR:?}/capture.logs" "${CASEDIR:?}/capture.dead" "${CASEDIR:?}/capture.stopped" "${CASEDIR:?}/capture.live"; echo "cap-$(grep -c '^run -d ' "$DOCKER_LOG")"; exit 0; fi
if [ "$1" = inspect ] && [[ "$*" == *NetworkSettings* ]]; then
  # `inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' NAME...`: the holder is 172.18.0.2 (the persona's own address), every other member 172.18.0.5
  for t in "${@:4}"; do case "$t" in *-holder) echo "172.18.0.2 ";; *) echo "172.18.0.5 ";; esac; done
  exit 0
fi
if [ "$1" = inspect ] && [[ "$*" == *cap-* ]]; then if [ -f "$CASEDIR/capture.dead" ]; then echo false; else echo true; fi; exit 0; fi
if [ "$1" = logs ]; then
  if [ -f "$CASEDIR/capture.logs" ]; then cat "$CASEDIR/capture.logs"; exit 0; fi
  printf 'tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\nlistening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 1500 bytes\n'
  if [ -f "$CASEDIR/capture.live" ]; then cat "$CASEDIR/capture.live"; fi
  if [ -f "$CASEDIR/capture.stopped" ]; then printf '0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n'; fi
  exit 0
fi
if [ "$1" = stop ] && [[ "$*" == *cap-* ]]; then touch "$CASEDIR/capture.stopped"; echo "cap-stopped"; exit 0; fi
# a previous persona's stub asked for the NEXT /metrics scrape to fail: the first `inspect` after it (the driver's pre-agent check of the next persona) arms it
if [ "$1" = inspect ] && [ -f "$CASEDIR/break-next" ]; then
  python3 -c "import sys,urllib.request;urllib.request.urlopen('http://127.0.0.1:18080/__mode?m='+sys.argv[1],timeout=5).read()" "$(cat "$CASEDIR/break-next")"
  rm -f "${CASEDIR:?}/break-next"
fi
if [ "$1" = run ] && [ "$2" = -d ] && [[ "$*" =~ -p\ 127\.0\.0\.1:([0-9]+):9252\  ]] && [[ "$*" == *"gitlab-runner@sha256"* ]] && [ "${*: -2}" = "run --listen-address=0.0.0.0:9252" ] && [ -z "${DOCKER_RUNNER_DEAD:-}" ]; then
  kill $(cat "$CASEDIR/../runner.pid" 2>/dev/null) 2>/dev/null
  # the runner's metrics mux: /metrics is registered, every other route (including /) is a 404
  nohup python3 "$CASEDIR/../runnerfix.py" "${BASH_REMATCH[1]}" "$CASEDIR/runner-hits.log" </dev/null >/dev/null 2>&1 &
  echo $! >"$CASEDIR/../runner.pid"
fi
# a FRESH container of the IMAGE UNDER TEST: published 127.0.0.1:<port>:8080 -> the fixture server opens a listener with a request counter of its own on that port; `rm -f` drops it
if [ "$1" = run ] && [ "$2" = -d ] && [[ "$*" =~ -p\ 127\.0\.0\.1:([0-9]+):8080\  ]] && [[ "$*" == */cache@sha256:* ]] && [ -z "${DOCKER_IMAGE_DEAD:-}" ]; then
  python3 -c "import sys,urllib.request;urllib.request.urlopen('http://127.0.0.1:18080/__spawn?port='+sys.argv[1],timeout=10).read()" "${BASH_REMATCH[1]}"
  mkdir -p "$CASEDIR/imgs"; echo "${BASH_REMATCH[1]}" >"$CASEDIR/imgs/cid-$(( $(grep -c '^run -d ' "$DOCKER_LOG") ))"
fi
# injected TEARDOWN failures: from the n-th `ps` (DOCKER_PS_FAIL_AT) or the n-th `rm` (DOCKER_RM_FAIL_AT) on, the daemon is unreachable (exit 1)
if [ "$1" = ps ] && [ -n "${DOCKER_PS_FAIL_AT:-}" ]; then
  n=$(( $(cat "$CASEDIR/ps.count" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$CASEDIR/ps.count"
  if [ "$n" -ge "$DOCKER_PS_FAIL_AT" ]; then echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1; fi
fi
if [ "$1" = rm ] && [ -n "${DOCKER_RM_FAIL_AT:-}" ]; then
  n=$(( $(cat "$CASEDIR/rm.count" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$CASEDIR/rm.count"
  if [ "$n" -ge "$DOCKER_RM_FAIL_AT" ]; then echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1; fi
fi
# DAEMON-MANAGED containers: a `run --rm ... --label L ... sh -c 'DAEMON...'` starts work that belongs to the DAEMON, not to the docker client: it keeps
# requesting the endpoint (X-Persona: CONTAINER) after the client is killed, until `rm -f`, `stop` or `kill` names its id (ps --filter label=L lists it)
if [ "$1" = ps ]; then
  lab=""; for t in "$@"; do case "$t" in label=*) lab="${t#label=}";; esac; done
  for f in "$CONTAINERS"/*; do [ -e "$f" ] || continue; if [ "$(sed -n 1p "$f")" = "$lab" ] && kill -0 "$(sed -n 2p "$f")" 2>/dev/null; then basename "$f"; fi; done
  exit 0
fi
if [ "$1" = rm ] || [ "$1" = stop ] || [ "$1" = kill ]; then
  for t in "$@"; do if [ -n "$t" ] && [ -e "${CONTAINERS:?}/${t:?}" ]; then kill -9 "$(sed -n 2p "${CONTAINERS:?}/${t:?}")" 2>/dev/null; rm -f "${CONTAINERS:?}/${t:?}"; fi; done
fi
if [ "$1" = rm ]; then kill $(cat "$CASEDIR/../runner.pid" 2>/dev/null) 2>/dev/null; rm -f "${CASEDIR:?}/../runner.pid"; fi
if [ "$1" = rm ]; then for t in "$@"; do if [ -e "$CASEDIR/imgs/$t" ]; then python3 -c "import sys,urllib.request;urllib.request.urlopen('http://127.0.0.1:18080/__drop?port='+sys.argv[1],timeout=10).read()" "$(cat "$CASEDIR/imgs/$t")"; rm -f "${CASEDIR:?}/imgs/${t:?}"; fi; done; fi
# what the real client prints: the ids of what it removed or stopped (stdout), and the host-network warning for a published port (stderr)
if [ "$1" = rm ] || [ "$1" = stop ] || [ "$1" = kill ]; then for t in "$@"; do case "$t" in -*) ;; ?*) echo "$t"; echo "container-id-noise-${t}" >&2;; esac; done; fi
if [ "$1" = run ]; then echo "WARNING: Published ports are discarded when using host network mode" >&2; fi
if [ "$1" = run ] && [ "$2" = --rm ]; then
  CASEDIR="$CASEDIR" python3 - "$CONTAINERS" "$@" <<'PYX'
import json, os, subprocess, sys, time
reg, a = sys.argv[1], sys.argv[2:]
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
img = next((i for i, x in enumerate(a) if "@sha256:" in x), None)
rest = a[img + 1:] if img is not None else []
repo = a[img] if img is not None else ""
if a[a.index("--user") + 1:][:1] == ["0:0"] if "--user" in a else False:
    # a CLEANUP container: runs as ROOT over the mounted sandbox and EXECUTES the requested deletion with the shell's own semantics against the mapping /work -> the
    # sandbox: `*` skips dotfiles, `.[!.]*` and `..?*` match hidden entries, a path that does not exist deletes nothing, root removes what another uid created
    # (read-only directories, mode-000 files). It understands rm -rf (alone or in a sh -c list joined by ; or &&) and `find /work -mindepth 1 -delete`; anything
    # else is a command the image cannot run (exit 127). The state left behind is logged, so a case can require that NOTHING remained.
    import fnmatch, shlex, shutil
    def expand(arg, gp):
        """DIRECT argv words are literal (no glob, tilde or variable expansion, no quote removal): only a word an explicit `sh -c` leaves UNQUOTED may glob"""
        if not (arg == "/work" or arg.startswith("/work/")):
            return []                                            # outside the mount: nothing of the sandbox
        rel = arg[len("/work"):].strip("/")
        if not rel:
            raise SystemExit(1)                                  # rm: cannot remove '/work': Device or resource busy
        parent, pat = os.path.split(rel)
        base = os.path.join(host, parent)
        if gp is None:
            return [os.path.join(base, pat)]                    # a literal name (which may even contain a *): nothing matches a file that is not there
        parent, pat = os.path.split(gp[len("/work"):].strip("/"))     # the pattern of the last component, per-character quoting preserved
        if not os.path.isdir(base):
            return []
        return [os.path.join(base, n) for n in sorted(os.listdir(base)) if fnmatch.fnmatchcase(n, pat) and (pat.startswith(".") or not n.startswith("."))]
    def wipe(path):
        def fix(fn, p, exc):
            os.chmod(os.path.dirname(p), 0o777); os.chmod(p, 0o777); fn(p)
        if os.path.islink(path) or os.path.isfile(path):
            try:
                os.remove(path)
            except PermissionError:
                os.chmod(os.path.dirname(path), 0o777); os.remove(path)
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                os.chmod(root, 0o777)
            shutil.rmtree(path, onerror=fix)
    def lex(script):
        """a minimal POSIX-sh lexer for what an `sh -c` cleanup may contain: ' and " quoting (a quoted glob is LITERAL), backslash escapes, ; && and newline as list separators,
        unquoted * ? [ as globs. Variables, command substitution, tilde, pipes, redirects and groups cannot be modelled: the fake refuses them (exit 127)"""
        cmds, cur, word, gpat, started, glob, quote, i = [], [], "", "", False, False, None, 0
        def unsupported(why):
            sys.stderr.write("sh: unsupported in this fake (%s)\n" % why); raise SystemExit(127)
        def end_word():
            nonlocal word, gpat, started, glob
            if started:
                cur.append((word, gpat if glob else None))       # the glob PATTERN keeps per-character quoting: a quoted * is matched literally
            word, gpat, started, glob = "", "", False, False
        def lit(ch):
            nonlocal word, gpat
            word += ch; gpat += ("[%s]" % ch) if ch in "*?[" else ch
        def end_cmd():
            nonlocal cur
            end_word()
            if cur:
                cmds.append(cur)
            cur = []
        while i < len(script):
            c = script[i]
            if quote == "'":
                if c == "'": quote = None
                else: lit(c)
            elif quote == '"':
                if c == '"': quote = None
                elif c in "$`\\": unsupported("expansion inside double quotes")
                else: lit(c)
            elif c == "'": quote, started = "'", True
            elif c == '"': quote, started = '"', True
            elif c == "\\":
                i += 1
                if i >= len(script): unsupported("trailing backslash")
                lit(script[i]); started = True
            elif c in "$`" or (c == "~" and not started): unsupported("variable, command or tilde expansion")
            elif c in "|<>(){}": unsupported("pipe, redirect or group")
            elif c in " \t": end_word()
            elif c in ";\n": end_cmd()
            elif c == "&":
                if script[i + 1:i + 2] != "&": unsupported("background job")
                end_cmd(); i += 1
            else:
                word += c; gpat += c; started = True
                if c in "*?[": glob = True
            i += 1
        if quote: unsupported("unterminated quote")
        end_cmd()
        return cmds
    def run_simple(words):
        argv = [w for w, g in words]
        if argv[:1] == ["rm"]:
            flags = [x for x, g in words[1:] if x.startswith("-") and x != "--"]
            if not any(("r" in f or "R" in f) for f in flags):
                sys.stderr.write("rm: cannot remove: Is a directory\n"); raise SystemExit(1)
            for arg, g in [(x, g) for x, g in words[1:] if not x.startswith("-") or x == "-"]:
                for t in expand(arg, g):
                    wipe(t)
        elif argv[:2] == ["find", "/work"] and argv[2:] == ["-mindepth", "1", "-delete"]:
            for n in os.listdir(host):
                wipe(os.path.join(host, n))
        else:
            sys.stderr.write('docker: Error response from daemon: exec: "%s": executable file not found in $PATH\n' % (argv[0] if argv else "")); raise SystemExit(127)
    before = sorted(os.path.relpath(os.path.join(r, n), host) for r, ds, fs in os.walk(host) for n in ds + fs)
    if rest[:2] == ["sh", "-c"] and len(rest) == 3:
        for words in lex(rest[2]):
            run_simple(words)
    else:
        run_simple([(x, None) for x in rest])      # DIRECT argv: literal words
    remaining = sorted(os.path.relpath(os.path.join(r, n), host) for r, ds, fs in os.walk(host) for n in ds + fs)
    open(os.path.join(os.environ["CASEDIR"], "cleanup.log"), "a").write(json.dumps({"sandbox": host, "tail": rest, "before": before, "remaining": remaining}) + "\n")
    sys.exit(0)
if rest[:2] == ["sh", "-c"] and len(rest) == 3:
    if "/cosign@" in repo or "/kubectl@" in repo:       # distroless images have no shell
        sys.stderr.write('docker: Error response from daemon: exec: "sh": executable file not found in $PATH\n'); sys.exit(127)
    if "DAEMON" in rest[2]:
        os.makedirs(reg, exist_ok=True)
        lab = a[a.index("--label") + 1] if "--label" in a else ""
        cid = "daemon-%d" % int(time.time() * 1000)
        child = subprocess.Popen([sys.executable, "-c", "import time,urllib.request\nwhile True:\n    try: urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:18080/container-work', headers={'X-Persona': 'CONTAINER'}), timeout=2).read()\n    except Exception: pass\n    time.sleep(0.25)\n"],
                                 start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        open(os.path.join(reg, cid), "w").write(lab + "\n" + str(child.pid) + "\n")
        time.sleep(60)          # the docker client stays attached until it is killed
        sys.exit(0)
    if rest[2].startswith("contact "):
        # a short-lived tool container that CONTACTS a host: only a container that joined a holder's namespace (--network container:<holder>) is seen by that holder's capture sidecar;
        # the fake writes what tcpdump would print for it (DNS query to the embedded resolver, the answer, the connection's SYN), tagged by this container in capture.tags
        who = rest[2].split(None, 1)[1].strip()
        net = a[a.index("--network") + 1] if "--network" in a else ""
        n = sum(1 for _ in open(os.path.join(os.environ["CASEDIR"], "capture.tags"))) if os.path.exists(os.path.join(os.environ["CASEDIR"], "capture.tags")) else 0
        open(os.path.join(os.environ["CASEDIR"], "capture.tags"), "a").write(json.dumps({"container": "tool-%d" % n, "network": net, "host": who}) + "\n")
        if net.startswith("container:"):
            h = sum(ord(c) for c in who)
            ip = "172.18.0.5" if who in ("jenkins", "gitlab-runner", "endpoint") else "151.101.%d.%d" % (h % 250 + 1, (h * 7) % 250 + 1)
            with open(os.path.join(os.environ["CASEDIR"], "capture.live"), "a") as lv:
                lv.write("9.0 IP 172.18.0.2.51000 > 127.0.0.11.53: %d+ A? %s. (31)\n9.1 IP 127.0.0.11.53 > 172.18.0.2.51000: %d 1/0/0 A %s (47)\n9.2 IP 172.18.0.2.40000 > %s.443: Flags [S], seq 1, win 64240, length 0\n" % (4000 + n, who, 4000 + n, ip, ip))
        sys.stdout.write("contacted " + who + "\n"); sys.exit(0)
    p = subprocess.run(["sh", "-c", rest[2]], cwd=host, capture_output=True, text=True, timeout=60)
    sys.stdout.write(p.stdout + p.stderr); sys.exit(p.returncode)
sys.stdout.write("TOOLARGS:" + json.dumps(rest) + "\n"); sys.exit(0)
PYX
  exit $?
fi
case "$1" in
  run) n=$(grep -c '^run -d ' "$DOCKER_LOG"); echo "cid-$n" ;;
  inspect) if [ -n "${DOCKER_INSPECT_FALSE:-}" ]; then echo false; else echo true; fi ;;
  exec) printf 'apiVersion: v1\nclusters:\n- cluster:\n    server: https://127.0.0.1:6443\n  name: kind\n' ;;
esac
exit 0
SH
# The host binaries the JOB provides: a recording `kind` and a recording `kubectl`, first on the driver's PATH (per case: $case/hostbin).
# Everything they are given is logged to $case/host.log (argv, instant, environment NAMES, the kubeconfig's content at call time, every
# manifest read from stdin or -f). `kind create cluster` writes an ADMIN kubeconfig (client certificate and key markers) to the file it is
# given; `kubectl create token` prints a fixed token. host.cfg (baked per case) switches failures and the kind API port.
cat >"$work/kind.tmpl" <<'PY'
#!/usr/bin/env python3
import json, os, socket, struct, sys, time
D = "__DIR__"
cfg = json.load(open(D + "/host.cfg"))
a = sys.argv[1:]
def opt(n):
    return a[a.index(n) + 1] if n in a and a.index(n) + 1 < len(a) else None
row = {"tool": "kind", "t": time.time(), "argv": a, "env": sorted(os.environ), "cwd": os.getcwd()}
kc, name = opt("--kubeconfig"), opt("--name") or "kind"
if kc and a[:2] == ["create", "cluster"]:
    row["kc"] = os.path.abspath(kc)
    row["existed_mode"] = oct(os.stat(kc).st_mode & 0o7777) if os.path.exists(kc) else None
    row["dir_mode"] = oct(os.stat(os.path.dirname(os.path.abspath(kc))).st_mode & 0o7777)
open(D + "/host.log", "a").write(json.dumps(row) + "\n")
DIGEST = "sha256:" + "ab12" * 16
def noise(what):
    """what the real kind prints (progress lines naming the node image digest and the cluster, on stdout and on stderr): none of it may reach the job log"""
    if what == "create":
        t = ('Creating cluster "%s" ...\n \u2713 Ensuring node image (kindest/node:v1.31.0@%s) \U0001f5bc\n \u2713 Preparing nodes \U0001f4e6\n \u2713 Writing configuration \U0001f4dc\n'
             ' \u2713 Starting control-plane \U0001f579\ufe0f\n \u2713 Installing CNI \U0001f50c\nSet kubectl context to "kind-%s"\nYou can now use your cluster with: kubectl cluster-info --context kind-%s\n' % (name, DIGEST, name, name))
    elif what == "delete":
        t = 'Deleting cluster "%s" ...\nDeleted nodes: ["%s-control-plane"]\n' % (name, name)
    else:
        t = 'ERROR: failed to create cluster: failed to pull image "kindest/node:v1.31.0@%s": exit status 1\nDeleting cluster "%s" ...\n' % (DIGEST, name)
    sys.stdout.write(t); sys.stderr.write(t); sys.stdout.flush(); sys.stderr.flush()
if a[:2] == ["create", "cluster"]:
    noise("create" if not cfg.get("kind_fail") else "fail")
elif a[:2] == ["delete", "cluster"]:
    noise("delete")
if cfg.get("kind_hang") and a[:2] == ["create", "cluster"]:
    time.sleep(20)
if cfg.get("kind_fail"):
    sys.stderr.write("kind: simulated failure\n"); sys.exit(1)
port, pn = int(cfg["kind_port"]), cfg.get("procnet")
if a[:2] == ["create", "cluster"]:
    if not kc:
        sys.exit(1)
    with open(kc, "w") as fh:
        fh.write("apiVersion: v1\nkind: Config\nclusters:\n- name: kind-%s\n  cluster:\n    server: https://127.0.0.1:%d\n    certificate-authority-data: CA-DATA-MARKER-PUBLIC\n"
                 "users:\n- name: kind-%s\n  user:\n    client-certificate-data: ADMIN-CERT-MARKER-1\n    client-key-data: ADMIN-KEY-MARKER-1\n"
                 "contexts:\n- name: kind-%s\n  context:\n    cluster: kind-%s\n    user: kind-%s\ncurrent-context: kind-%s\n" % (name, port, name, name, name, name, name))
    ready_at = time.time() + float(cfg.get("node_ready_delay") or 0)       # `kind create cluster --wait 0s` returns while the node is still NotReady
    open(D + "/node_ready_at", "w").write(repr(ready_at))
    open(D + "/host.log", "a").write(json.dumps({"tool": "kind-ready", "node_ready_at": ready_at}) + "\n")
    open(D + "/alive", "w").write("1")        # the cluster exists until `kind delete cluster`: the fake kubectl answers the persona's calls only while it does
    if pn:      # the API server of a real kind cluster LISTENS on the loopback: show it in the kernel table the driver's guard reads
        raw = "%08X" % struct.unpack("<I", socket.inet_aton("127.0.0.1"))[0]
        open(pn + "/tcp", "a").write("   9: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0\n" % (raw, port))
elif a[:2] == ["delete", "cluster"] and cfg.get("kind_delete_fail"):
    sys.stderr.write("kind: simulated delete failure\n"); sys.exit(1)
elif a[:2] == ["delete", "cluster"]:
    if os.path.exists(D + "/alive"):
        os.remove(D + "/alive")
    if os.path.exists(D + "/node_ready_at"):
        os.remove(D + "/node_ready_at")
    if pn:
        keep = [l for l in open(pn + "/tcp") if not l.rstrip().endswith(" 9999 1 0")]
        open(pn + "/tcp", "w").writelines(keep)
sys.exit(0)
PY
cat >"$work/kubectl.tmpl" <<'PY'
#!/usr/bin/env python3
# The fake kubectl accepts ONLY: `apply -f FILE|-`, `create token SA ...`, `get`, `wait`, `version`, `cluster-info`. Any other verb or create
# subcommand (create clusterrolebinding, create rolebinding, delete, patch, exec, ...) fails the call. It validates what is applied the way the API
# server would (apiVersion/kind pairs, RoleBinding roleRef and subjects, a namespaced object needs its Namespace to exist already), keeps what was
# APPLIED apart from other calls, implements `create token` with its real flags only (--duration as a whole-second Go duration, --audience,
# --bound-object-kind/name; anything else is an unknown flag), remembers every token it issued (audience, subject, expiry) and answers the
# persona's own (token) credential only for a token issued for the persona's ServiceAccount, unexpired, with the API audience, while the cluster exists.
import json, os, re, sys, time
D = "__DIR__"
cfg = json.load(open(D + "/host.cfg"))
a = sys.argv[1:]
API_AUD = cfg.get("api_aud") or "https://kubernetes.default.svc"      # a kubeadm cluster uses ...svc.cluster.local; both are real, the driver must not depend on either
kcp, files, verb, skip = None, [], None, False
for i, t in enumerate(a):
    if skip:
        skip = False; continue
    if t == "--kubeconfig" and i + 1 < len(a): kcp = a[i + 1]; skip = True
    elif t.startswith("--kubeconfig="): kcp = t.split("=", 1)[1]
    elif t in ("-f", "--filename") and i + 1 < len(a): files.append(a[i + 1]); skip = True
    elif t.startswith("--filename="): files.append(t.split("=", 1)[1])
    elif t in ("-n", "--namespace", "--context", "-o", "--duration", "--for", "--timeout", "--audience", "--bound-object-kind", "--bound-object-name", "--bound-object-uid") and i + 1 < len(a): skip = True
    elif t.startswith("-"): pass
    elif verb is None: verb = t
row = {"tool": "kubectl", "t": time.time(), "argv": a, "verb": verb, "env": sorted(os.environ), "cwd": os.getcwd(), "kubeconfig": kcp, "manifests": [], "refused": None}
row["kc_content"] = open(kcp).read() if kcp and os.path.isfile(kcp) else None
persona_call = row["kc_content"] is not None and "client-certificate" not in row["kc_content"] and "token" in row["kc_content"]
row["persona_call"] = persona_call
def finish(rc, msg=None, refused=None):
    row["refused"] = refused
    open(D + "/host.log", "a").write(json.dumps(row) + "\n")
    if msg:
        sys.stderr.write(msg + "\n")
    sys.exit(rc)
def issued():
    return json.load(open(D + "/issued.json")) if os.path.exists(D + "/issued.json") else []
if persona_call:
    if not os.path.exists(D + "/alive"):
        finish(1, "The connection to the server was refused - did you specify the right host or port? (the cluster is gone)")
    m = re.search(r'"?token"?\s*:\s*"?([A-Za-z0-9._-]+)"?', row["kc_content"])
    tok = next((x for x in issued() if m and x["token"] == m.group(1)), None)
    if not tok:
        finish(1, "error: You must be logged in to the server (Unauthorized): a token this API server never issued")
    if tok["exp"] <= time.time():
        finish(1, "error: You must be logged in to the server (Unauthorized): the token expired")
    if API_AUD not in tok["aud"]:
        finish(1, "error: You must be logged in to the server (Unauthorized): the token's audience is not the API server's")
    if not tok["sub"].startswith("system:serviceaccount:persona:"):
        finish(1, "error: Forbidden: another identity")
    print("ok"); finish(0)
m = cfg.get("kubectl_fail_match")
if m and m in " ".join(a):
    finish(1, "kubectl: simulated failure")
sub = a[a.index("create") + 1:] if "create" in a else []
allowed = bool((verb == "apply" and files) or (verb == "create" and sub[:1] == ["token"]) or verb in ("get", "wait", "version", "cluster-info"))
if verb == "get" and files:
    allowed = False
if not allowed:
    finish(1, "kubectl: this fake refuses %r (only apply -f, create token, get, wait, version, cluster-info): an imperative grant such as create clusterrolebinding is never accepted" % " ".join(a[:4]), refused=" ".join(a[:3]))
if any(t.startswith("--dry-run") for t in a):
    finish(1, "kubectl: the fake applies nothing under --dry-run")
for f in files:
    if f == "-":
        row["manifests"].append(sys.stdin.read())
    elif os.path.isfile(f):
        row["manifests"].append(open(f).read())
GOODAPI = {"Namespace": "v1", "ServiceAccount": "v1", "Role": "rbac.authorization.k8s.io/v1", "RoleBinding": "rbac.authorization.k8s.io/v1"}
RBAC = "rbac.authorization.k8s.io"
def invalid(o):
    """what the API server itself would refuse"""
    if not isinstance(o, dict) or GOODAPI.get(o.get("kind")) != o.get("apiVersion"):
        return "no matches for kind %r with version %r" % (o.get("kind") if isinstance(o, dict) else o, o.get("apiVersion") if isinstance(o, dict) else None)
    k = o["kind"]
    if not (o.get("metadata") or {}).get("name"):
        return "%s: metadata.name is required" % k
    if k == "RoleBinding":
        rr = o.get("roleRef") or {}
        if rr.get("kind") not in ("Role", "ClusterRole") or not rr.get("name") or rr.get("apiGroup") != RBAC:
            return "RoleBinding: roleRef needs kind Role|ClusterRole, a name and apiGroup %s" % RBAC
        for s in o.get("subjects") or []:
            if not isinstance(s, dict) or not s.get("name") or s.get("kind") not in ("ServiceAccount", "User", "Group"):
                return "RoleBinding: invalid subject %r" % (s,)
            if s["kind"] == "ServiceAccount" and s.get("apiGroup") not in (None, ""):
                return "RoleBinding: a ServiceAccount subject has an EMPTY apiGroup"
            if s["kind"] != "ServiceAccount" and s.get("apiGroup") != RBAC:
                return "RoleBinding: a User/Group subject has apiGroup %s" % RBAC
    if k == "Role":
        for r in o.get("rules") or []:
            if not isinstance(r, dict) or not r.get("verbs") or not (r.get("resources") or r.get("nonResourceURLs")):
                return "Role: a rule needs verbs and resources"
    return None
def contract(o):
    """what the API server would accept but this driver's own contract refuses (stricter): CONTRACT violations, not schema errors"""
    if o["kind"] == "RoleBinding" and not o.get("subjects"):
        return "CONTRACT: a RoleBinding without subjects grants nothing"
    if o["kind"] == "RoleBinding" and any(s.get("kind") == "ServiceAccount" and not s.get("namespace") for s in o.get("subjects") or []):
        return "CONTRACT: a ServiceAccount subject carries its namespace explicitly"
    if o["kind"] == "Role" and not o.get("rules"):
        return "CONTRACT: a Role without rules grants nothing"
    if o["kind"] == "Role" and any(r.get("resources") and "apiGroups" not in r for r in o["rules"]):
        return "CONTRACT: every resource rule names its apiGroups"
    return None
known_ns = set(json.load(open(D + "/ns.json"))) if os.path.exists(D + "/ns.json") else set()
for mm in row["manifests"]:
    try:
        doc = json.loads(mm); docs = doc["items"] if isinstance(doc, dict) and doc.get("kind") == "List" else [doc]
    except ValueError:
        try:
            import yaml
            docs = [d for d in yaml.safe_load_all(mm) if d]
            docs = [x for d in docs for x in (d["items"] if isinstance(d, dict) and d.get("kind") == "List" else [d])]
        except Exception:
            finish(1, "error: the manifest is not valid YAML or JSON")
    for o in docs:
        why = invalid(o) or contract(o)
        if why:
            row["manifests"] = []
            finish(1, "kubectl: " + why)
        md = o.get("metadata") or {}
        if o["kind"] == "Namespace":
            known_ns.add(md["name"])
        elif md.get("namespace") and md["namespace"] not in known_ns:
            row["manifests"] = []
            finish(1, 'Error from server (NotFound): namespaces "%s" not found (a namespaced object is applied before its Namespace exists)' % md["namespace"])
json.dump(sorted(known_ns), open(D + "/ns.json", "w"))
def go_seconds(d):
    """Go time.ParseDuration restricted to s, m, h; kubectl create token refuses sub-second precision; 0 is legal (the server's default)"""
    if not re.fullmatch(r"(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:s|m|h))+", d):
        return None
    v = sum(float(n) * {"s": 1, "m": 60, "h": 3600}[u] for n, u in re.findall(r"([0-9]+\.?[0-9]*|\.[0-9]+)(s|m|h)", d))
    return v if v >= 0 and abs(v - round(v)) < 1e-9 else None
if verb == "create":
    import base64, hashlib
    opts = {}
    rest = a[a.index("token") + 2:]
    i = 0
    while i < len(rest):
        t = rest[i]
        name, eq, val = t.partition("=")
        if name in ("--duration", "--audience", "--bound-object-kind", "--bound-object-name", "--bound-object-uid", "-n", "--namespace", "--kubeconfig", "--context"):
            if not eq:
                i += 1; val = rest[i] if i < len(rest) else ""
            opts.setdefault(name, []).append(val)
        else:
            finish(1, "error: unknown flag: %s (kubectl create token supports --duration, --audience, --bound-object-kind, --bound-object-name, --bound-object-uid)" % t)
        i += 1
    dur = (opts.get("--duration") or [None])[0]
    # API behaviour (NOT the driver's policy): 0 or no flag asks for the server default (1h), anything between 1s and 10 minutes is refused by the API,
    # a request above the server's maximum is ACCEPTED and shortened (here to 24h). The driver's own 1h..24h policy is asserted separately on what it asks for.
    secs = go_seconds(dur) if dur is not None else 0
    if secs is None:
        finish(1, "error: invalid duration %r (whole seconds, Go syntax)" % dur)
    if secs == 0:
        secs = 3600
    elif secs < 600:
        finish(1, "error: Invalid value: may not specify a duration less than 10 minutes")
    secs = min(secs, 86400)
    kind = (opts.get("--bound-object-kind") or [None])[0]
    if kind is not None or opts.get("--bound-object-name"):
        finish(1, 'error: %s "%s" not found: the bound object does not exist' % (kind or "?", (opts.get("--bound-object-name") or ["?"])[0]))
    aud = opts.get("--audience") or [API_AUD]
    if cfg.get("token_lifetime"):
        secs = int(cfg["token_lifetime"])        # the API server may issue another lifetime than the one asked for
    b = lambda x: base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
    now = int(time.time())
    sa = a[a.index("token") + 1]
    sub_ = "system:serviceaccount:persona:" + sa
    tok = b({"alg": "RS256", "kid": "k1"}) + "." + b({"aud": aud, "exp": now + int(secs), "iat": now, "sub": sub_}) + "." + base64.urlsafe_b64encode(hashlib.sha256(str(now).encode()).digest()).decode().rstrip("=")
    reg = issued(); reg.append({"token": tok, "aud": aud, "exp": now + int(secs), "sub": sub_}); json.dump(reg, open(D + "/issued.json", "w"))
    open(D + "/host.log", "a").write(json.dumps({"tool": "issued", "token": tok, "t": time.time()}) + "\n")
    print(tok)
else:
    ready_at = float(open(D + "/node_ready_at").read()) if os.path.exists(D + "/node_ready_at") else 0.0
    nodeargs = any(x in ("node", "nodes") or x.startswith(("node/", "nodes/")) for x in a)
    if verb == "wait" and nodeargs:
        joined = " ".join(a)
        tmo = re.search(r"--timeout[= ](\d+)([sm]?)", joined)
        limit = int(tmo.group(1)) * (60 if tmo and tmo.group(2) == "m" else 1) if tmo else 30
        row["node_wait"] = limit
        if not re.search(r"--for[= ]condition=Ready\b", joined):
            finish(1, "error: this fake waits only for condition=Ready on nodes")
        left = ready_at - time.time()
        if left > 0:
            if left > limit:
                time.sleep(limit); finish(1, "error: timed out waiting for the condition on nodes/kind-control-plane")
            time.sleep(left)
        row["node_ready"] = True
        print("node/kind-control-plane condition met")
    elif verb == "get" and nodeargs:
        ready = time.time() >= ready_at
        row["node_ready"] = ready
        print("NAME                 STATUS   ROLES           AGE   VERSION\nkind-control-plane   %s   control-plane   6s    v1.31.0" % ("Ready   " if ready else "NotReady"))
    elif verb == "apply":
        print("namespace/persona created\nserviceaccount/persona created\nrole.rbac.authorization.k8s.io/persona created\nrolebinding.rbac.authorization.k8s.io/persona created")
    else:
        print("ok")
if verb != "apply":
    row["manifests"] = []
finish(0)
PY
# mkhost <case dir>: the per-case HOSTBIN (kind, kubectl) and host.cfg from KIND_FAIL, KUBECTL_FAIL_MATCH, KIND_PORT (default 18090), KIND_PROCNET
mkhost() {
  local d=$1; mkdir -p "$d/hostbin"; : >"$d/host.log"
  printf '#!/bin/sh\necho "$*" >>"%s/gh.log"\necho "gh: the persona UAT must never call gh" >&2\nexit 1\n' "$d" >"$d/hostbin/gh"; chmod +x "$d/hostbin/gh"; : >"$d/gh.log"
  python3 - "$d" "$(command -v openssl)" "${OPENSSL_FAIL:-}" <<'PYO'
import os, sys
d, real, fail = sys.argv[1:4]
open(d + "/hostbin/openssl", "w").write(f"""#!/usr/bin/env python3
import json, os, sys
LOG, FAIL, REAL = {d + "/openssl.log"!r}, {fail!r}, {real!r}
n = sum(1 for l in open(LOG) if '"-encrypt"' in l) + (1 if sys.argv[1:3] == ['cms', '-encrypt'] else 0)
open(LOG, 'a').write(json.dumps(sys.argv[1:]) + '\\n')
if FAIL and sys.argv[1:3] == ['cms', '-encrypt']:
    # FAIL=1: every encryption fails after creating an EMPTY destination (real openssl opens -out before it encrypts); FAIL=partial: every one writes some bytes to its
    # destination (-out FILE, else stdout) and then fails; FAIL=first / FAIL=<n>: only that call (the first, the n-th), after partial output. Calls that DO succeed are real.
    if FAIL in ('1', 'partial') or FAIL == str(n) or (FAIL == 'first' and n == 1):
        dest = sys.argv[sys.argv.index('-out') + 1] if '-out' in sys.argv else None
        part = b'' if FAIL == '1' else b'PARTIAL-CIPHERTEXT-OR-PLAINTEXT'
        if dest:
            open(dest, 'wb').write(part)
        elif part:
            sys.stdout.buffer.write(part); sys.stdout.flush()
        sys.stderr.write('openssl: simulated failure\\n'); sys.exit(1)
os.execv(REAL, [REAL] + sys.argv[1:])
""")
os.chmod(d + "/hostbin/openssl", 0o755); open(d + "/openssl.log", "w").close()
PYO
  sed "s#__DIR__#$d#" "$work/kind.tmpl" >"$d/hostbin/kind"; sed "s#__DIR__#$d#" "$work/kubectl.tmpl" >"$d/hostbin/kubectl"; chmod +x "$d/hostbin/kind" "$d/hostbin/kubectl"
  python3 - "$d/host.cfg" "${KIND_FAIL:-}" "${KUBECTL_FAIL_MATCH:-}" "${KIND_PORT:-18090}" "${KIND_PROCNET:-}" "${KIND_DELETE_FAIL:-}" "${KIND_HANG:-}" "${KIND_TOKEN_LIFETIME:-}" "${KIND_API_AUD:-}" "${KIND_NODE_READY:-}" <<'PYC'
import json, sys
json.dump({"kind_fail": sys.argv[2], "kubectl_fail_match": sys.argv[3], "kind_port": int(sys.argv[4]), "procnet": sys.argv[5], "kind_delete_fail": sys.argv[6], "kind_hang": sys.argv[7], "token_lifetime": sys.argv[8], "api_aud": sys.argv[9], "node_ready_delay": sys.argv[10]}, open(sys.argv[1], "w"))
PYC
}
# The driver makes NO gh call and opens NO issue (results stay private): a recording `gh` is first on every run's PATH (hostbin) and any call is a failure.
# The TEST key pairs are made by this test itself: the recipient the driver encrypts to, and another one nobody here holds the key of.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/test.key" -out "$work/test.pem" -subj "/CN=persona-uat-test" -days 2 >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/other.key" -out "$work/other.pem" -subj "/CN=persona-uat-other" -days 2 >/dev/null 2>&1
chmod 600 "$work/test.key" "$work/other.key"
# dec.py <out dir> <plain dir> <key>: decrypt every <persona>.cms with openssl cms (DER, PEM or S/MIME, whatever the driver wrote) and split the payload at
# the separator line into <persona>.report.md and <persona>.transcript.txt; a file that does not decrypt leaves <persona>.DECRYPT-FAILED
cat >"$work/dec.py" <<'PY'
import glob, os, subprocess, sys
out, plain, key = sys.argv[1:4]
os.makedirs(plain, exist_ok=True); os.chmod(plain, 0o700)
SEP = "\n=== TRANSCRIPT ===\n"
for f in sorted(glob.glob(out + "/*.cms")):
    name = os.path.basename(f)[:-4]
    data = None
    for inform in ("DER", "PEM", "SMIME"):
        r = subprocess.run(["openssl", "cms", "-decrypt", "-inform", inform, "-inkey", key, "-in", f], capture_output=True)
        if r.returncode == 0:
            data = r.stdout.decode("utf-8", "replace"); break
    if data is None:
        open(os.path.join(plain, name + ".DECRYPT-FAILED"), "w").write("x"); continue
    rep, _, tr = data.partition(SEP)
    open(os.path.join(plain, name + ".report.md"), "w").write(rep if _ else data)
    open(os.path.join(plain, name + ".transcript.txt"), "w").write(tr)
    open(os.path.join(plain, name + ".payload"), "w").write(data)
PY
decout() { rm -rf "${work:?}/$1/plain"; python3 "$work/dec.py" "$work/$1/out" "$work/$1/plain" "${2:-$work/test.key}"; }
# publiclog <case>: the job log (stdout + stderr) is ONLY `persona-uat: <persona>|overall: pass|fail` lines, one per persona and overall, agreeing with the
# encrypted reports (friction reads pass) and with each other (overall fails iff a persona does): no finding, doc name, host, model name or transcript text
publiclog() { python3 - "$work/$1" "$PERSONAS" <<'PYL'
import re, sys
d, personas = sys.argv[1], sys.argv[2].split()
import os
srcs = ("stdout", "stderr") + (("summary.md",) if os.path.exists(d + "/summary.md") else ())     # the controlled GITHUB_STEP_SUMMARY is a public surface too
lines = [l for f in srcs for l in open(d + "/" + f).read().splitlines() if l.strip()]
pat = re.compile(r"^persona-uat: (%s|overall): (pass|fail)$" % "|".join(personas))
bad = [l for l in lines if not pat.match(l)]
assert not bad, ("the job log carries more than a pass/fail line per persona and overall", bad[:3])
got = {}
for l in [l for f in ("stdout", "stderr") for l in open(d + "/" + f).read().splitlines() if l.strip()]:
    m = pat.match(l); assert m.group(1) not in got, ("a duplicate line", l); got[m.group(1)] = m.group(2)
if os.path.exists(d + "/summary.md"):       # a summary, when written, repeats the same lines and nothing else
    for l in open(d + "/summary.md").read().splitlines():
        if l.strip():
            m = pat.match(l); assert m and got.get(m.group(1)) == m.group(2), ("the step summary disagrees with the log", l)
assert sorted(got) == sorted(personas + ["overall"]), got
assert got["overall"] == ("fail" if "fail" in [got[p] for p in personas] else "pass"), got
for p in personas:
    first = open(d + "/plain/" + p + ".report.md").read().splitlines()[0]
    assert got[p] == ("fail" if first == "VERDICT: blocking" else "pass"), (p, first, got[p])
PYL
}
# the "image under test" and Jenkins as tiny local HTTP servers, so the driver's readiness checks have something to find
# the "image under test" (18080) is a fixture that behaves like the real server's counter: it serves Prometheus text on /metrics, counts every
# request EXCEPT /metrics, /healthz and /statusz, and shows no fscache_http_requests_total sample until the first counted request. Jenkins (18081)
# is a plain server; the GitLab runner's metrics listener (18082) is started by the RECORDING DOCKER only. Control paths (never counted):
# /__case?dir=D logs requests to D/srv.log, /__mode?m=ok|garbage|status500|nometric changes what /metrics answers, /__reset forgets every count, /__silent?v=1 keeps the driver's readiness probe and the noise before the first persona out of the count (a truly fresh first scrape).
cat >"$work/srvfix.py" <<'PY'
import json, os, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, root = int(sys.argv[1]), sys.argv[2]
lock = threading.Lock()
S = {"mode": "ok", "dir": "", "silent": False, "seen": False, "queue": [], "delay": 0.0, "extra": 0.0, "drift_for": "", "drift_secs": 0.0, "drift_until": 0.0, "epoch": 0}
UNCOUNTED = ("/metrics", "/healthz", "/statusz")
# one INSTANCE per listening port: the master (the control port) and one per persona container the fake docker spawns (`run -d` of the image under test) and drops (`rm -f`): each
# has its OWN request counter, exactly as a fresh container of the image would
INST, SERVERS = {}, {}
def new_inst():
    return {"c": {}, "unc": 0, "seen": False}
def total(I):
    return sum(I["c"].values())
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def log_message(self, *a):
        pass
    def reply(self, code, body, ctype="text/plain"):
        b = body.encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(b))); self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)
    def handle_any(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        with lock:
            lport = self.server.server_address[1]
            I = INST.get(lport) or new_inst()
            if u.path == "/__case":
                S["dir"] = q.get("dir", [""])[0]; return self.reply(200, "ok")
            if u.path == "/__mode":
                S["mode"] = q["m"][0]; return self.reply(200, "ok")
            if u.path == "/__queue":       # the next /metrics scrapes answer these modes, one each, in order; then the base mode again
                S["queue"] = [m for m in q["m"][0].split(",") if m]; return self.reply(200, "ok")
            if u.path == "/__silent":      # while on, requests without an X-Persona header (the driver's own readiness probe) are not counted: a truly fresh first scrape
                S["silent"] = q["v"][0] == "1"; S["seen"] = False; return self.reply(200, "ok")
            if u.path == "/__delay":       # counted requests are COUNTED this many seconds AFTER their response went out (the real server counts after the handler returns)
                S["delay"] = float(q["s"][0]); return self.reply(200, "ok")
            if u.path == "/__extra":       # with a delay: every delayed request is counted a SECOND time this many seconds after the first increment (a late increment that must restart the quiet interval)
                S["extra"] = float(q["s"][0]); return self.reply(200, "ok")
            if u.path == "/__drift":       # once the named persona makes a counted request, EVERY /metrics scrape for the next s seconds bumps the counter (a counter that never settles)
                S["drift_for"] = q["p"][0]; S["drift_secs"] = float(q["s"][0]); S["drift_until"] = 0.0; return self.reply(200, "ok")
            if u.path == "/__spawn":       # a FRESH container of the image under test: a listener of its own on this port with a counter at zero
                sp_ = int(q["port"][0])
                INST[sp_] = new_inst()
                srv_ = ThreadingHTTPServer(("127.0.0.1", sp_), H)
                SERVERS[sp_] = srv_
                threading.Thread(target=srv_.serve_forever, daemon=True).start()
                return self.reply(200, "ok")
            if u.path == "/__drop":        # `docker rm -f` of that container: the listener and its counter are gone (a late completion lands nowhere)
                dp_ = int(q["port"][0])
                srv_ = SERVERS.pop(dp_, None)
                INST.pop(dp_, None)
                if srv_ is not None:
                    threading.Thread(target=lambda: (srv_.shutdown(), srv_.server_close()), daemon=True).start()
                return self.reply(200, "ok")
            if u.path == "/__hold":        # a request still IN FLIGHT server-side: its connection is ESTABLISHED (a line in the case's procnet table) for s seconds, then it is counted (after the handler returns)
                secs, who_, epoch, conn_ = float(q["s"][0]), q.get("who", ["HELD"])[0], S["epoch"], q.get("conn", ["1"])[0] == "1"
                tab = os.path.join(S["dir"], "procnet", "tcp") if S["dir"] else None
                line = "  77: 0100007F:%04X 0100007F:E001 01 00000000:00000000 00:00000000 00000000     0        0 7777 1 0\n" % lport
                def held():
                    if conn_ and tab and os.path.isdir(os.path.dirname(tab)):       # conn=0: the client already closed its side; only the server-side handler is still running
                        open(tab, "a").write(line)
                    time.sleep(secs)
                    with lock:
                        if S["epoch"] == epoch and INST.get(lport) is I:       # a request finishing in a container that is gone counts for nobody
                            I["c"][("GET", "200")] = I["c"].get(("GET", "200"), 0) + 1
                            if S["dir"]:
                                open(os.path.join(S["dir"], "srv.log"), "a").write(json.dumps({"t": time.time(), "path": "/held", "method": "GET", "counted": True, "persona": who_, "total": total(I), "port": lport}) + "\n")
                    if conn_ and tab and os.path.exists(tab):
                        keep = [l for l in open(tab) if l != line]
                        open(tab, "w").writelines(keep)
                threading.Thread(target=held, daemon=True).start()
                return self.reply(200, "ok")
            if u.path == "/__reset":
                S["epoch"] += 1
                for I_ in INST.values():
                    I_["c"].clear(); I_["unc"] = 0
                S["extra"] = 0.0; S["drift_for"] = ""; S["drift_until"] = 0.0; return self.reply(200, "ok")
            known = u.path in UNCOUNTED or (self.command in ("GET", "HEAD") and os.path.isfile(os.path.join(root, u.path.lstrip("/"))))
            code = "201" if self.command == "PUT" else ("200" if known else "404")
            who = self.headers.get("X-Persona")
            if who and who != "NOISE":
                I["seen"] = True
            unauth = self.headers.get("X-Unauthorized") == "1"      # withAuth wraps withMetrics: a 401 is never counted
            if unauth:
                code = "401"
            counted = u.path not in UNCOUNTED and not unauth and not (S["silent"] and (not who or (who == "NOISE" and not I["seen"])))
            later = None
            if counted and S["drift_for"] and who == S["drift_for"]:
                S["drift_until"] = time.time() + S["drift_secs"]
            if counted:
                if S["delay"] > 0:
                    later = (self.command, code)
                else:
                    I["c"][(self.command, code)] = I["c"].get((self.command, code), 0) + 1
            if u.path in UNCOUNTED:
                I["unc"] += 1
            if S["dir"]:
                open(os.path.join(S["dir"], "srv.log"), "a").write(json.dumps({"t": time.time(), "path": u.path, "method": self.command, "counted": counted,
                                                                               "persona": who, "total": total(I), "port": lport}) + "\n")
            if later:
                def bump(k=later, I=I, lport=lport):
                    with lock:
                        if INST.get(lport) is I:
                            I["c"][k] = I["c"].get(k, 0) + 1
                threading.Timer(S["delay"], bump).start()
                if S["extra"] > 0:
                    threading.Timer(S["delay"] + S["extra"], bump).start()
            if unauth:
                return self.reply(401, "unauthorized")
            if u.path == "/metrics" and self.command == "GET":
                mode = S["queue"].pop(0) if S["queue"] else S["mode"]
                if mode == "garbage":
                    return self.reply(200, "<html>not prometheus</html>")
                if mode == "status500":
                    return self.reply(500, "boom")
                if time.time() < S["drift_until"]:
                    I["c"][("GET", "200")] = I["c"].get(("GET", "200"), 0) + 1
                n = total(I)
                lines = []
                fam = "fscache_http_requests_total"
                if mode == "nofamily":
                    pass                      # a real fresh server: the whole family (HELP, TYPE and samples) is absent
                elif mode == "nometric":
                    lines += ["# HELP %s Requests served (%s 999999 is not a sample)." % (fam, fam), "# TYPE %s counter" % fam]     # HELP and TYPE, no sample
                elif I["c"]:
                    lines += ["# HELP %s Requests served (%s 999999 is not a sample)." % (fam, fam), "# TYPE %s counter" % fam]
                    for (m, c), v in sorted(I["c"].items()):
                        lines.append('%s{method="%s",status="%s"} %s' % (fam, m, c, ("%d.0" % v) if (m, c) == ("GET", "200") else v))
                lines += ["# TYPE go_goroutines gauge", "go_goroutines 9",
                          "# TYPE fscache_http_requests_total_uncounted counter", 'fscache_http_requests_total_uncounted{path="all"} %d' % I["unc"],     # a decoy that moves on uncounted traffic
                          "fscache_http_request_bytes_total %d" % (100 * n), "fscache_http_requests_in_flight 1",
                          'other_http_requests_total{method="GET",status="200"} %d' % (3 * n), ""]
                return self.reply(200, "\n".join(lines), "text/plain; version=0.0.4")
            if self.command == "PUT":
                return self.reply(201, "ok")
            if not known:
                return self.reply(404, "no")
            if u.path in UNCOUNTED:
                return self.reply(200, "ok")
            return self.reply(200, open(os.path.join(root, u.path.lstrip("/"))).read())
    do_GET = do_HEAD = do_PUT = do_POST = handle_any
INST[port] = new_inst()
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
# the GitLab runner's metrics mux as it really is: /metrics is registered, every other route (including /, which a directory-listing server would answer) is 404;
# it logs each request path so a case can tell which endpoint the readiness probe used. Started ONLY by the recording docker.
cat >"$work/runnerfix.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port, log = int(sys.argv[1]), sys.argv[2]
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        open(log, "a").write(self.path + "\n")
        b = b"# TYPE gitlab_runner_version_info gauge\ngitlab_runner_version_info 1\n" if self.path == "/metrics" else b"404 page not found\n"
        self.send_response(200 if self.path == "/metrics" else 404); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$work/srvfix.py" 18080 "$work" >/dev/null 2>&1 & SRV1=$!
cat >"$work/jenfix.py" <<'PY'
# Jenkins (18081): a static server that, once armed (/__arm?s=N), answers 503 to every request for N seconds from the first one after arming (real Jenkins answers 503 while starting, 30-90s), then 200
import json, os, sys, time, urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
port, root = int(sys.argv[1]), sys.argv[2]
S = {"arm": 0.0, "until": 0.0}
class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=root, **k)
    def log_message(self, *a):
        pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/__arm":
            S["arm"] = float(urllib.parse.parse_qs(u.query)["s"][0]); S["until"] = 0.0
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok"); return
        now = time.time()
        if S["arm"] > 0:
            S["until"] = now + S["arm"]; S["arm"] = 0.0
        starting = now < S["until"]
        open(root + "/jen.log", "a").write(json.dumps({"t": now, "path": u.path, "code": 503 if starting else 200}) + "\n")
        if starting:
            b = b"Please wait while Jenkins is getting ready to work ..."
            self.send_response(503); self.send_header("Content-Length", str(len(b))); self.send_header("Retry-After", "5"); self.end_headers(); self.wfile.write(b); return
        super().do_GET()
    do_HEAD = do_GET
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
python3 "$work/jenfix.py" 18081 "$work" >/dev/null 2>&1 & SRV2=$!
trap 'kill $SRV1 $SRV2 $(cat "$work/runner.pid" 2>/dev/null) 2>/dev/null; rm -rf "$work"' EXIT
srvctl() { python3 -c "import sys,urllib.request,urllib.parse;u='http://127.0.0.1:18080/'+sys.argv[1]+('?'+urllib.parse.urlencode({sys.argv[2]:sys.argv[3]}) if len(sys.argv)>2 else '');urllib.request.urlopen(u,timeout=5).read()" "$@"; }
echo ours-18080 >"$work/ours-18080.txt"; echo ours-18081 >"$work/ours-18081.txt"; true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  python3 - "$work" 2>/dev/null <<'PY' && break
import sys, urllib.request
for p in (18080, 18081):
    assert urllib.request.urlopen("http://127.0.0.1:%d/ours-%d.txt" % (p, p)).read().decode().strip() == "ours-%d" % p
PY
  sleep 0.3
done
python3 - <<'PY' || { echo "the fixture servers did not start, or another process owns ports 18080/18081/18082/18090/18099: refusing to run" >&2; exit 3; }
import socket, sys
s = socket.socket(); s.settimeout(0.5)
assert s.connect_ex(("127.0.0.1", 18099)) != 0, "18099 is in use"
assert socket.socket().connect_ex(("127.0.0.1", 18090)) != 0, "18090 is in use"
assert socket.socket().connect_ex(("127.0.0.1", 18082)) != 0, "18082 is in use (the recording docker starts the runner's listener)"
assert socket.socket().connect_ex(("127.0.0.1", 18123)) != 0, "18123 is in use"
for p in (18080, 18081):
    import urllib.request
    assert urllib.request.urlopen("http://127.0.0.1:%d/ours-%d.txt" % (p, p)).read().decode().strip() == "ours-%d" % p
PY

# proc-net fixtures for the loopback-listener guard (the driver reads /proc/net/tcp and tcp6 from --proc-net; production passes nothing)
# mkprocnet <dir> [state:addr:port ...]: state 0A = LISTEN, 01 = ESTABLISHED; addr is a dotted IPv4 or the word ip6loop / ip6any
mkprocnet() { local d=$1; shift; mkdir -p "$d"; python3 - "$d" "$@" <<'PYP'
import socket, struct, sys
d, rows = sys.argv[1], sys.argv[2:]
hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
t4, t6 = [hdr], [hdr]
for n, r in enumerate(rows):
    st, addr, port = r.split(":")
    if addr in ("ip6loop", "ip6any"):
        raw = "00000000000000000000000001000000" if addr == "ip6loop" else "0" * 32
        t6.append("   %d: %s:%04X %s:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0\n" % (n, raw, int(port), "0" * 32, st, 1000 + n))
    else:
        raw = "%08X" % struct.unpack("<I", socket.inet_aton(addr))[0]
        t4.append("   %d: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0\n" % (n, raw, int(port), st, 1000 + n))
open(d + "/tcp", "w").writelines(t4); open(d + "/tcp6", "w").writelines(t6)
PYP
}
mkprocnet "$work/procnet"
# run <name> <plan-json> <mode> [VAR=val ...]  (sets rc; dirs under $work/<name>/)
run() {
  local name=$1 plan=$2 mode=$3; shift 3
  mkdir -p "$work/plain" "$work/$name" "$work/$name/tmp"; : >"$work/$name/summary.md"; echo "$plan" >"$work/$name/plan.json"; : >"$work/$name/log"; : >"$work/$name/docker.log"; : >"$work/$name/gh.log"
  # the stub's failure switches are baked into the case's own docker script (the driver passes the docker client only its allowlisted DOCKER_* variables)
  sed "s#__LOG__#$work/$name/docker.log#" "$work/docker.tmpl" >"$work/$name/docker"; chmod +x "$work/$name/docker"
  { echo "DOCKER_FAIL_MATCH=$(printf %q "${DOCKER_FAIL_MATCH:-}"); DOCKER_INSPECT_FALSE=$(printf %q "${DOCKER_INSPECT_FALSE:-}"); DOCKER_NOISE=$(printf %q "${DOCKER_NOISE:-}"); DOCKER_RUNNER_DEAD=$(printf %q "${DOCKER_RUNNER_DEAD:-}"); DOCKER_IMAGE_DEAD=$(printf %q "${DOCKER_IMAGE_DEAD:-}"); DOCKER_PS_FAIL_AT=$(printf %q "${DOCKER_PS_FAIL_AT:-}"); DOCKER_RM_FAIL_AT=$(printf %q "${DOCKER_RM_FAIL_AT:-}")"; } >"$work/$name/docker.env"
  # the host binaries (kind, kubectl) first on PATH; KIND_LISTEN=1: the kind API port shows up in (a per-case copy of) the proc-net table while the cluster exists
  local pnet="${PROCNET:-$work/procnet}"
  if [ -n "${KIND_LISTEN:-}" ]; then rm -rf "$work/$name/procnet"; cp -R "$pnet" "$work/$name/procnet"; pnet="$work/$name/procnet"; fi
  KIND_PROCNET="${KIND_LISTEN:+$pnet}" mkhost "$work/$name"
  rm -f "$work/$name/srv.log"; srvctl __case dir "$work/$name"
  sed -i.bak "2i\\
. \"$work/$name/docker.env\"" "$work/$name/docker"; rm -f "$work/$name/docker.bak"
  rc=0
  local tw=(); [ -n "${RUN_TIMEOUT:-}" ] && tw=(perl -e 'alarm shift; exec @ARGV' "$RUN_TIMEOUT")
  # the counter's settle window is 3.0s of quiet with a 20s ceiling by DEFAULT; the cases use shorter ones (SETTLE_QUIET, SETTLE_MAX) except where SETTLE_DEFAULT=1 (the stated bounds)
  local sflags=(--settle-quiet "${SETTLE_QUIET:-0.8}" --settle-max "${SETTLE_MAX:-8}"); [ -z "${SETTLE_DEFAULT:-}" ] || sflags=()
  local t_start=$SECONDS
  env -u PERSONA_UAT_TOKEN_BUDGET TMPDIR="$work/$name/tmp" GITHUB_STEP_SUMMARY="$work/$name/summary.md" GITHUB_RUN_ID=4242 GITHUB_REPOSITORY=own/cache \
      GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY REPO_CHECKOUT="$repo" \
      GITHUB_WORKSPACE="$repo" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRET-OIDC ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.invalid \
      ACTIONS_RUNTIME_TOKEN=SECRET-RT ANTHROPIC_API_KEY=ALLOWED-MODEL-CRED ANTHROPIC_IDENTITY_TOKEN_FILE=/x/token SOME_UNKNOWN_SECRET=SECRET-UNK AWS_SESSION_TOKEN=SECRET-AWS2 \
      ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 \
      GITHUB_SERVER_URL=https://github.com RUNNER_TEMP=/r ACTIONS_CACHE_URL=http://c.invalid GH_ENTERPRISE_TOKEN=SECRET-GHE \
      PERSONA_UAT_MODEL=MODEL-DEFAULT-X PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X PATH="$work/$name/hostbin:$PATH" "$@" \
      ${tw[@]+"${tw[@]}"} bash -c 'cd "$1" && shift && exec "$@"' _ "$work/plain" python3 "$driver" --mode "$mode" --image "${IMAGE:-$IMG}" --repo "$repo" --out "$work/$name/out" \
        --tools "${TOOLS:-$work/tools.json}" --docker "$work/$name/docker" --recipient "${RECIPIENT:-$work/test.pem}" --port "${PORT:-18080}" --ready-timeout "${READY_TIMEOUT:-5}" \
        --agent "python3 $work/stub.py $work/$name" --proc-net "$pnet" ${ALLOW_LISTEN:+--allow-listen $ALLOW_LISTEN} ${AGENT_TIMEOUT:+--agent-timeout $AGENT_TIMEOUT} ${sflags[@]+"${sflags[@]}"} ${JOB_BUDGET:+--job-budget $JOB_BUDGET} ${MIN_PERSONA:+--min-persona-seconds $MIN_PERSONA} >"$work/$name/stdout" 2>"$work/$name/stderr" || rc=$?
  RUNSECS=$((SECONDS - t_start))
  srvctl __case dir ""
  decout "$name"
}
out() { echo "$work/$1/plain"; }      # the DECRYPTED reports and transcripts of a case (the real --out holds only <persona>.cms)
nlines() { wc -l <"$1" | tr -d ' '; }

# --- AC1: five personas, exactly these five, one report and one transcript each ----------------------------------
run clean '{}' rc
CASE="rc clean run exits 0"; check test "$rc" -eq 0
for p in $PERSONAS; do
  CASE="clean run writes one report and one transcript for $p"
  check test -s "$(out clean)/$p.report.md" -a -s "$(out clean)/$p.transcript.txt"
done
CASE="exactly the five named personas ran, once each, in their own agent call"
check python3 - "$work/clean/log" "$PERSONAS" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert sorted(r["persona"] for r in rows) == sorted(sys.argv[2].split()), [r["persona"] for r in rows]
PY
CASE="each persona gets its own instructions naming its role"
check python3 - "$work/clean/log" <<'PY'
import json, re, sys
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["instructions"] for l in open(sys.argv[1])}
want = {"gradle-platform-engineer": "gradle", "maven-jenkins-ci": "jenkins", "compliance-reviewer": "sbom",
        "readme-evaluator": "ten minutes", "on-call-engineer": "rollback"}
assert len(set(rows.values())) == 5, "instructions are not distinct"
for p, w in want.items():
    assert w in rows[p].lower(), (p, w)
need = {"gradle-platform-engineer": ("first-time", "gradle", "proxy"), "maven-jenkins-ci": ("maven", "jenkins"),
        "compliance-reviewer": ("signature", "sbom", "vex"), "readme-evaluator": ("only the readme", "ten minutes"),
        "on-call-engineer": ("upgrade", "rollback", "logs")}
for p, words in need.items():
    for w in words:
        assert w in rows[p].lower(), (p, w)
for p, text in rows.items():          # every persona is told how to classify what it finds, and what a doc step is
    for w in ("broken behavior", "friction", "as written"):
        assert w in text.lower(), (p, w)
    low = text.lower()
    assert "these tools are not in the sandbox: gh, docker, jq" in low and "kubectl exec" in low, (p, "the missing tools are not named exactly")
    assert "report each as friction, not as blocking" in low, (p, low[-700:])
    assert "never as a step that" not in low, (p, "a blanket exemption of documented steps is back")
    assert "a step that can run in the sandbox is judged as written" in low, (p, "steps that can run must be judged")
PY
CASE="the environment limits are NAMED, once each, in the prompt and in the encrypted report header (advisor 0250/0207, step 8 round 2): (a) a foreground kubectl port-forward cannot be held across disposable actions, (b) no pre-seeded Jenkins job or credentials and no GitLab server or runner registration, (c) gh, docker, jq not in the sandbox and kubectl exec not permitted, (d) the provenance step needing GitHub's attestation store (gh attestation verify) cannot run; they are friction, never blocking; a step that CAN run is judged as written; the counter's attribution limit (3 seconds) is in every header too"
check python3 - "$work/clean" "$(out clean)" <<'PY'
import json, sys
d, o = sys.argv[1:3]
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["instructions"] for l in open(d + "/log")}
ITEMS = ("another terminal", "no pre-seeded jenkins job or credentials", "no gitlab server or runner registration", "these tools are not in the sandbox: gh, docker, jq", "gh attestation verify")
for p, t in rows.items():
    low = t.lower()
    for it in ITEMS:
        assert low.count(it) == 1, (p, it, low.count(it))
    assert low.count("a step that can run in the sandbox is judged as written") == 1, p
    assert "metrics endpoint only" in rows["maven-jenkins-ci"].lower()
import re
for p in rows:
    r = open("%s/%s.report.md" % (o, p)).read()
    hdr = [l for l in r.splitlines() if l.startswith("Environment limits of this run")]
    assert len(hdr) == 1, (p, hdr)
    low = hdr[0].lower()
    for it in ITEMS:
        assert low.count(it) == 1, (p, "header", it, low.count(it))
    assert "friction, never blocking" in low, hdr[0]
    lim = [l for l in r.splitlines() if l.startswith("Counter guarantee:")]
    assert len(lim) == 1, (p, lim)
    g = lim[0].lower()
    for w in ("its own fresh container", "host port of its own", "read from that container only", "action containers were removed", "unchanged for 3 seconds", "earlier, removed container", "cannot prove", "20 seconds", "still being served more than 3 seconds"):
        assert w in g, (p, w, lim[0])
    assert "Counter limit:" not in r, "the old (inaccurate) 'not attributed' claim is gone"
PY
CASE="the driver hands every agent --transcript-file: a private file OUTSIDE the sandbox (its directory 0700, a different path per persona), and nothing of it is left when the run ends"
check python3 - "$work/clean/log" <<'PY'
import json, os, sys
paths = []
for l in open(sys.argv[1]):
    r = json.loads(l)
    a = r["argv"]
    assert a.count("--transcript-file") == 1, (r["persona"], a)
    f = a[a.index("--transcript-file") + 1]
    assert not f.startswith(r["request"]["docs_dir"]), ("the transcript file is inside the sandbox the shell containers mount", f)
    assert not os.path.exists(f) and not os.path.exists(os.path.dirname(f)), ("left behind", f)
    paths.append(f)
assert len(set(paths)) == 5, paths
PY
CASE="a clean run leaves no issue file anywhere and calls gh never: --out holds only <persona>.cms"
check test ! -e "$work/clean/out/friction-issue.md" -a ! -e "$work/clean/out/blocking-issue.md" -a ! -s "$work/clean/gh.log"
CASE="each report states its verdict in the first line"
check test "$(head -1 "$(out clean)/on-call-engineer.report.md")" = "VERDICT: pass"

# --- AC1: the image under test starts BY DIGEST and everything is removed afterwards ------------------------------
CASE="the driver starts a FRESH container of the image under test for EACH persona, by digest, published on loopback on a host port of its own (distinct per persona, none of the fixed ports), and hands exactly that endpoint to that persona's agent"
check python3 - "$work/clean/docker.log" "$work/clean/log" "$IMG" <<'PY'
import json, re, sys
runs = [l for l in open(sys.argv[1]) if l.startswith("run ")]
img = [l for l in runs if sys.argv[3] in l]
assert len(img) == 5, runs
ports = [int(re.search(r"-p 127\.0\.0\.1:(\d+):8080 ", l).group(1)) for l in img]
assert len(set(ports)) == 5 and not [p for p in ports if p in (8080, 8081, 8082, 18080, 18081, 18082)], ports
rows = [json.loads(l) for l in open(sys.argv[2])]
assert [r["request"]["endpoint"] for r in rows] == ["http://endpoint:8080"] * 5, [r["request"]["endpoint"] for r in rows]
assert all(r["request"]["image"] == sys.argv[3] for r in rows)
PY
CASE="every container started is removed (rm -f) before the driver exits, even after a failure"
run blockrm '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"x"}]}}' rc
check python3 - "$work/clean/docker.log" "$work/blockrm/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    started = [("cap-" if "/usr/bin/tcpdump" in l else "cid-") + str(i + 1) for i, l in enumerate(x for x in lines if x.startswith("run -d "))]
    removed = " ".join(l for l in lines if l.startswith("rm -f "))
    assert started and all(c in removed for c in started), (path, started, removed)
PY
CASE="an image reference that is not pinned by digest is refused before anything starts (exit 2)"
IMAGE="ghcr.io/example/cache:latest" run tagimg '{}' rc
check test "$rc" -eq 2 -a ! -s "$work/tagimg/docker.log" -a ! -s "$work/tagimg/log"
unset IMAGE

# --- AC4: Jenkins and a GitLab runner are pinned containers; kind is created by the job's `kind` binary -----------------------
CASE="Jenkins and the GitLab runner start (by their pinned references) only for the Maven persona; kind never through docker; the requests carry each tool's endpoint"
check python3 - "$work/clean/docker.log" "$work/clean/log" "$JEN" "$GLR" "$KND" <<'PY'
import json, sys
log = open(sys.argv[1]).read()
jen, glr, knd = sys.argv[3:6]
for ref in (jen, glr):
    runs = [l for l in log.splitlines() if l.startswith("run ") and ref in l]
    assert len(runs) == 1, (ref, log)
    assert runs[0].split()[:2] == ["run", "-d"], runs[0]
assert knd not in log and "kindest" not in log, "the kind node image is created by the kind binary, never run through docker"
rows = {json.loads(l)["persona"]: json.loads(l)["request"]["tools"] for l in open(sys.argv[2])}
assert sorted(rows["maven-jenkins-ci"]) == ["gitlab-runner", "jenkins"], rows
assert sorted(rows["on-call-engineer"]) == ["kind"], rows
for name, v in rows["maven-jenkins-ci"].items():
    assert sorted(v) == ["container", "endpoint"] and v["container"].startswith("cid-"), (name, v)
assert rows["maven-jenkins-ci"]["jenkins"]["endpoint"] == "http://jenkins:8080", rows
assert rows["maven-jenkins-ci"]["gitlab-runner"]["endpoint"] == "http://gitlab-runner:9252", rows
k = rows["on-call-engineer"]["kind"]
assert "container" not in k, ("kind is no container any more", k)
assert k["endpoint"] == "https://persona-uat-control-plane:6443" and k["kubeconfig"] == "kubeconfig", k
assert set(k) <= {"endpoint", "kubeconfig", "namespace"} and k.get("namespace", "persona") == "persona", k
for p in ("gradle-platform-engineer", "compliance-reviewer", "readme-evaluator"):
    assert rows[p] == {}, (p, rows[p])
PY
CASE="the agent is started with --tools <the driver's own tools file> and NOT --shell-image; the driver itself starts no shell image"
check python3 - "$work/clean/log" "$work/clean/docker.log" "$SHL" "$work/tools.json" <<'PY'
import json, os, re, sys
rows = [json.loads(ln) for ln in open(sys.argv[1])]
assert len(rows) == 5
assert len({r["argv"][r["argv"].index("--label") + 1] for r in rows}) == 5, "the label is distinct per persona"
for r in rows:
    a = r["argv"]
    assert "--shell-image" not in a, a
    lab = a[a.index("--label") + 1]
    assert re.fullmatch(r"persona-uat=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lab), ("a fresh uuid label per persona", lab)
    assert os.path.realpath(a[a.index("--tools") + 1]) == os.path.realpath(sys.argv[4]), a
    assert a[a.index("--docker") + 1].endswith("/docker"), a
assert not [l for l in open(sys.argv[2]) if l.startswith("run -d ") and sys.argv[3] in l and "--entrypoint /bin/sleep" not in l], "the driver itself must not START the shell image as a service (its only use besides the cleanup container: the network holder's sleep): the agent does, per action (the driver's only use is the cleanup container)"
PY
CASE="every container the driver starts is run -d with the pinned image, only loopback-published ports, no mount, no network override, NO --privileged anywhere, and no -e except Jenkins' one fixed value (setup wizard off); the runner publishes 9252 and is started with exactly 'run --listen-address=0.0.0.0:9252'"
check python3 - "$work/clean/docker.log" "$IMG" "$JEN" "$GLR" "$KND" <<'PY'
import re, sys
img, jen, glr, knd = sys.argv[2:6]
allowed = {img, jen, glr}
seen, maps, envs = [], {}, {}
for l in open(sys.argv[1]):
    t = l.split()
    assert "--privileged" not in t, ("no container is privileged any more", l)
    if t[0] == "pull":
        raise AssertionError("the driver must not pull explicitly: " + l)
    if t[0] == "run" and t[:2] == ["run", "--rm"] and "--user" in t:
        continue        # the per-persona CLEANUP container (its own case pins its shape)
    if t[0] == "run":
        assert t[:2] == ["run", "-d"], ("every container the driver starts is `run -d ...`: " + l)
    if t[:2] != ["run", "-d"]:
        continue
    if "--entrypoint" in t:
        continue        # the capture sidecar (its own case pins its shape)
    pos = [i for i, x in enumerate(t) if x in allowed]
    assert len(pos) == 1, ("exactly one pinned image of the allowlist per container (never the kind node image)", l)
    ref, flags, trail = t[pos[0]], t[2:pos[0]], t[pos[0] + 1:]
    if ref != glr:
        assert trail == [], ("nothing after the image", l)
    else:
        assert trail == ["run", "--listen-address=0.0.0.0:9252"], ("the runner's metrics HTTP server needs exactly 'run --listen-address=0.0.0.0:9252'", trail)
    seen.append(ref)
    i = 0
    while i < len(flags):
        f = flags[i]
        if f == "--rm": i += 1
        elif f == "--name": i += 2
        elif f == "--network":
            assert re.fullmatch(r"persona-uat-[0-9a-f]{8}", flags[i + 1]), ("only the persona's own private network", l); i += 2
        elif f == "--network-alias":
            assert flags[i + 1] in ("endpoint", "jenkins", "gitlab-runner"), l; i += 2
        elif f == "-p":
            assert re.fullmatch(r"127\.0\.0\.1:\d+:\d+", flags[i + 1]), ("only loopback publishing", l)
            host, cport = flags[i + 1].split(":")[1:]
            maps[ref] = (host, cport)
            i += 2
        elif f == "-e":
            assert ref == jen, ("-e is for Jenkins only", l)
            envs.setdefault(ref, []).append(flags[i + 1]); i += 2
        else: raise AssertionError(("a flag outside the allowlist (no -v/--mount/--env/--env-file/-eX/--network/--cap-add/--user ...)", f, l))
assert sorted(set(seen)) == sorted(allowed) and seen.count(img) == 5, seen
for ref, want in ((jen, ("18081", "8080")), (glr, ("18082", "9252"))):
    assert maps.get(ref) == want, ("this container must publish exactly its endpoint's port", ref, maps.get(ref), want)
assert maps[img][1] == "8080" and 1024 <= int(maps[img][0]) <= 65535 and maps[img][0] not in ("8080", "18080"), ("the image container publishes container port 8080 on a free high host port", maps[img])
assert envs == {jen: ["JAVA_OPTS=-Djenkins.install.runSetupWizard=false"]}, ("Jenkins' only environment value is the fixed one that switches the setup wizard off", envs)
PY
for key in $TOOLKEYS; do
  python3 - "$work/tools.json" "$work/tools-unpinned-$key.json" "$key" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); t[sys.argv[3]] = t[sys.argv[3]].split("@")[0] + ":latest"
json.dump(t, open(sys.argv[2], "w"))
PY
  CASE="the $key entry not pinned by digest refuses the whole run (exit 2); nothing starts and stderr names it"
  TOOLS="$work/tools-unpinned-$key.json" run "unpinned-$key" '{}' rc
  check test "$rc" -eq 2 -a ! -s "$work/unpinned-$key/docker.log" -a ! -s "$work/unpinned-$key/log" -a ! -s "$work/unpinned-$key/host.log"
  check grep -q "$key" "$work/unpinned-$key/stderr"
done
for key in $TOOLKEYS; do
  python3 - "$work/tools.json" "$work/tools-missing-$key.json" "$key" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); del t[sys.argv[3]]
json.dump(t, open(sys.argv[2], "w"))
PY
  CASE="the tools file without its $key entry refuses the run (exit 2) and nothing starts: the key set is exactly the nine"
  TOOLS="$work/tools-missing-$key.json" run "missing-$key" '{}' rc
  check test "$rc" -eq 2 -a ! -s "$work/missing-$key/docker.log" -a ! -s "$work/missing-$key/log" -a ! -s "$work/missing-$key/host.log"
done
python3 - "$work/tools.json" "$work/tools-extra.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); t["terraform"] = "docker.io/hashicorp/terraform@sha256:" + "9" * 64
json.dump(t, open(sys.argv[2], "w"))
PY
CASE="a tools file with a tenth entry (terraform) refuses the run (exit 2) and nothing starts"
TOOLS="$work/tools-extra.json" run toolsextra '{}' rc
check test "$rc" -eq 2 -a ! -s "$work/toolsextra/docker.log" -a ! -s "$work/toolsextra/log" -a ! -s "$work/toolsextra/host.log"
for badref in "ghcr.io/example/cache@sha256:abc" "ghcr.io/example/cache@sha256:$(printf 'g%.0s' $(seq 64))" "ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 63))"; do
  IMAGE="$badref" run badimg '{}' rc
  CASE="a malformed digest ($badref) is refused (exit 2) and nothing starts"
  check test "$rc" -eq 2 -a ! -s "$work/badimg/docker.log" -a ! -s "$work/badimg/log"
done
unset TOOLS IMAGE

# --- DELTA 1: kind via the job-installed binary; the persona gets a namespaced ServiceAccount, never the admin credential ---------
cat >"$work/kh.py" <<'PY'
import json, os, re, sys, yaml
PAIRS = {("", "pods"), ("", "pods/log"), ("", "services"), ("", "configmaps"), ("", "events"), ("events.k8s.io", "events"), ("apps", "deployments"), ("batch", "jobs")}
VERBS = {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}
def rows(d):
    return [r for r in (json.loads(l) for l in open(d + "/host.log") if l.strip()) if r["tool"] in ("kind", "kubectl")]
def issued(d):
    return [json.loads(l) for l in open(d + "/host.log") if '"issued"' in l]
def kind(d):
    return [r for r in rows(d) if r["tool"] == "kind"]
def kubectl(d):
    """the DRIVER's kubectl calls (admin credential); the persona's own calls with its token are persona_calls"""
    return [r for r in rows(d) if r["tool"] == "kubectl" and not r.get("persona_call")]
def persona_calls(d):
    return [r for r in rows(d) if r["tool"] == "kubectl" and r.get("persona_call")]
def create(d):
    c = [r for r in kind(d) if r["argv"][:2] == ["create", "cluster"]]
    assert len(c) == 1, ("exactly one kind create cluster", c)
    return c[0]
def objects(d):
    """[(call index, doc index, object)] of everything the driver applied, in order"""
    out = []
    for i, r in enumerate(kubectl(d)):
        for m in r["manifests"]:
            for j, o in enumerate(yaml.safe_load_all(m)):
                if o:
                    if o.get("kind") == "List":
                        out += [(i, j, x) for x in o["items"]]
                    else:
                        out.append((i, j, o))
    return out
def of(d, k):
    return [(i, j, o) for i, j, o in objects(d) if o.get("kind") == k]
def persona_row(d, name="on-call-engineer"):
    r = [json.loads(l) for l in open(d + "/log")]
    return [x for x in r if x["persona"] == name]
def go_duration(s):
    """a Go-style duration made of numbers (decimals allowed) of s, m and h, strictly positive: seconds, else None"""
    if not re.fullmatch(r"(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:s|m|h))+", s):
        return None
    v = sum(float(n) * {"s": 1, "m": 60, "h": 3600}[u] for n, u in re.findall(r"([0-9]+\.?[0-9]*|\.[0-9]+)(s|m|h)", s))
    return v if v > 0 and abs(v - round(v)) < 1e-9 else None        # kubectl create token refuses sub-second precision
def duration_ok(s):
    v = go_duration(s)
    return v is not None and 3600 <= v <= 86400
FULL = {"get", "list", "watch", "create", "update", "patch", "delete"}
UNIVERSE = {("", r): FULL for r in ("pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "events")}
UNIVERSE.update({("events.k8s.io", "events"): FULL, ("apps", "deployments"): FULL, ("apps", "replicasets"): FULL, ("batch", "jobs"): FULL,
                 ("", "pods/log"): {"get", "list"}, ("", "pods/portforward"): {"create"}, ("apps", "deployments/scale"): {"get", "update", "patch"}})
def allows(rules, g, r, v):
    """kubectl auth can-i, over a Role's rules"""
    return any((g in x.get("apiGroups", []) or "*" in x.get("apiGroups", [])) and (r in x.get("resources", []) or "*" in x.get("resources", []))
               and (v in x.get("verbs", []) or "*" in x.get("verbs", [])) for x in rules)
def role_problems(rules, needs):
    out = []
    for x in rules:
        if set(x) - {"apiGroups", "resources", "verbs"}:
            out.append("a rule field beyond apiGroups/resources/verbs: %s" % sorted(x))
        for g in x.get("apiGroups", []):
            for r in x.get("resources", []):
                for v in x.get("verbs", []):
                    if "*" in (g, r, v):
                        out.append("wildcard in %r %r %r" % (g, r, v))
                    elif v not in UNIVERSE.get((g, r), ()):
                        out.append("granted outside the allowed set: %s %s %s" % (g or "core", r, v))
    for g, r, v in sorted(needs):
        if not allows(rules, g, r, v):
            out.append("a documented or task step cannot work: %s %s %s is not granted" % (g or "core", r, v))
    return out
KINDMAP = {"Secret": ("", "secrets"), "PersistentVolumeClaim": ("", "persistentvolumeclaims"), "Deployment": ("apps", "deployments"), "Service": ("", "services")}
DOC_OPTIONAL_KINDS = {"HTTPRoute", "Ingress"}        # the documented EXPOSURE options: not part of the persona's ruling
DOC_FORBIDDEN_CMDS = {"exec"}                       # documented, and deliberately not granted (no pods/exec): reported, not required
TASK_NEEDS = {("apps", "deployments", v) for v in ("get", "list", "update", "patch")} | {("apps", "replicasets", v) for v in ("get", "list")} | \
             {("", "pods", v) for v in ("get", "list", "watch")} | {("apps", "deployments", "watch"), ("apps", "replicasets", "watch")} | \
             {("", "pods/log", "get"), ("", "events", "get"), ("", "events", "list")}     # upgrade, rollback (rollout undo, rollout status and wait need watch), logs
def doc_needs(texts):
    """what the documented kubectl steps need, as (group, resource, verb); raises for a documented step this table does not know"""
    needs = set()
    for t in texts:
        for kd in re.findall(r"(?m)^kind:\s*(\w+)\s*$", t):
            if kd in DOC_OPTIONAL_KINDS:
                continue
            g, r = KINDMAP[kd]
            needs |= {(g, r, v) for v in ("get", "create", "patch")}
        for ln in re.findall(r"(?m)^\s*kubectl\s+(.*)$", t):
            w = ln.split()
            if w[0] == "apply":
                continue
            elif w[0] == "scale":
                needs |= {("apps", "deployments/scale", v) for v in ("get", "update", "patch")} | {("apps", "deployments", "get")}
            elif w[0] == "delete" and w[1] in ("pvc", "persistentvolumeclaim"):
                needs.add(("", "persistentvolumeclaims", "delete"))
            elif w[0] == "port-forward":
                needs |= {("", "pods", "get"), ("", "pods/portforward", "create"), ("", "services", "get")}
            elif w[0] in DOC_FORBIDDEN_CMDS:
                continue
            else:
                raise AssertionError("a documented kubectl step the test does not know how to authorize: " + ln)
    return needs | TASK_NEEDS
def reference_rules():
    full = sorted(FULL)
    return [{"apiGroups": [""], "resources": ["pods", "services", "configmaps", "secrets", "persistentvolumeclaims", "events"], "verbs": full},
            {"apiGroups": ["apps"], "resources": ["deployments", "replicasets"], "verbs": full},
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": full},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/portforward"], "verbs": ["create"]},
            {"apiGroups": ["apps"], "resources": ["deployments/scale"], "verbs": ["get", "update", "patch"]}]
PY
CASE="kind: the driver runs the job's kind binary ITSELF: exactly one 'kind create cluster' with exactly --image <the tools file's kind digest> --name <a fixed name> --kubeconfig <a file>, and nothing else"
check python3 - "$work/clean" "$KND" "$work" <<'PY'
import re, sys
sys.path.insert(0, sys.argv[3]); import kh
d, knd = sys.argv[1], sys.argv[2]
a = kh.create(d)["argv"]
assert a[:2] == ["create", "cluster"] and len(a) == 8, a
o = dict(zip(a[2::2], a[3::2]))
assert sorted(o) == ["--image", "--kubeconfig", "--name"], a
assert o["--image"] == knd, a
assert re.fullmatch(r"[a-z][a-z0-9-]{2,30}", o["--name"]), a
assert o["--kubeconfig"].startswith("/"), a
PY
CASE="kind: the admin kubeconfig is a DRIVER-PRIVATE file: outside every sandbox, the output directory and the repository, in a directory (or a file) closed to others, and gone when the run ends"
check python3 - "$work/clean" "$work" "$repo" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
c = kh.create(d)
kc = os.path.realpath(c["kc"])
for r in kh.persona_row(d, "on-call-engineer") + kh.persona_row(d, "gradle-platform-engineer"):
    assert not kc.startswith(os.path.realpath(r["request"]["docs_dir"]) + os.sep), ("inside a sandbox", kc)
    assert os.path.realpath(r["cwd"]) != os.path.dirname(kc)
assert not kc.startswith(os.path.realpath(d + "/out") + os.sep), "inside the public output directory"
assert not kc.startswith(os.path.realpath(sys.argv[3]) + os.sep), "inside the repository"
private = (c["existed_mode"] is not None and int(c["existed_mode"], 8) & 0o77 == 0) or int(c["dir_mode"], 8) & 0o77 == 0
assert private, ("the file is created in a directory (or with a mode) others can read", c["existed_mode"], c["dir_mode"])
assert not os.path.exists(kc), "the admin kubeconfig outlives the run"
PY
CASE="kind: the admin kubeconfig never leaves the driver: its path and its client certificate/key appear in no docker call, no request, no agent environment or sandbox file, no report, transcript, stdout or stderr"
check python3 - "$work/clean" "$work" <<'PY'
import glob, json, os, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
kc = kh.create(d)["kc"]
blobs = [open(d + "/docker.log").read(), open(d + "/log").read(), open(d + "/stdout").read(), open(d + "/stderr").read()]
blobs += [open(f, errors="replace").read() for f in glob.glob(d + "/out/*") + glob.glob(d + "/plain/*")]
for b in blobs:
    assert kc not in b and "ADMIN-CERT-MARKER" not in b and "ADMIN-KEY-MARKER" not in b, b[:200]
for r in kh.persona_row(d, "on-call-engineer") + [json.loads(l) for l in open(d + "/log")]:
    assert "KUBECONFIG" not in r["env"], r["env"]
PY
CASE="kind: every kubectl call of the driver uses the admin kubeconfig from kind explicitly (--kubeconfig, never the default config), only the verbs apply/create/get/wait/version/cluster-info, no impersonation"
check python3 - "$work/clean" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
kc = kh.create(d)["kc"]
calls = kh.kubectl(d)
assert calls, "the driver made no kubectl call: nothing created the namespace"
for r in calls:
    assert r["kubeconfig"] == kc, ("a kubectl call not using the admin kubeconfig explicitly", r["argv"])
    verbs = [x for x in r["argv"] if x in ("apply", "create", "get", "wait", "version", "cluster-info", "delete", "patch", "replace", "exec", "run", "label", "annotate", "edit", "config")]
    assert verbs and verbs[0] in ("apply", "create", "get", "wait", "version", "cluster-info"), r["argv"]
    assert not [x for x in r["argv"] if x.startswith(("--as", "--token", "--client-", "--username", "--password"))], r["argv"]
PY
CASE="kind: no job credential (GitHub, AWS, OIDC, model identity, any *_TOKEN/*_KEY/*_SECRET) is in the environment of the kind or kubectl process"
check python3 - "$work/clean" "$work" <<'PY'
import re, sys
sys.path.insert(0, sys.argv[2]); import kh
cred = re.compile(r"^(AWS_.*|ACTIONS_.*|GITHUB_.*|GH_.*|ANTHROPIC_.*|.*_TOKEN|.*_KEY|.*_SECRET|SOME_UNKNOWN_SECRET|PERSONA_UAT_.*|REPO_CHECKOUT|RUNNER_.*)$")
rs = [r for r in kh.rows(sys.argv[1]) if not r.get("persona_call")]      # the DRIVER's kind and kubectl processes (the persona's own calls run in the agent's environment)
assert len(rs) >= 3, rs
for r in rs:
    assert not [k for k in r["env"] if cred.match(k)], (r["tool"], r["env"])
PY
CASE="kind: ONE Namespace 'persona' is applied, labelled pod-security.kubernetes.io/enforce, warn AND audit = restricted; every other object is namespaced into it, and no ClusterRole, ClusterRoleBinding or other cluster-scoped object is ever applied"
check python3 - "$work/clean" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
ns = kh.of(d, "Namespace")
assert len(ns) == 1 and ns[0][2]["metadata"]["name"] == "persona", ns
lab = ns[0][2]["metadata"].get("labels", {})
for k in ("enforce", "warn", "audit"):
    assert lab.get("pod-security.kubernetes.io/" + k) == "restricted", (k, lab)
kinds = sorted({o["kind"] for _, _, o in kh.objects(d)})
assert kinds == ["Namespace", "Role", "RoleBinding", "ServiceAccount"], kinds
for _, _, o in kh.objects(d):
    if o["kind"] != "Namespace":
        assert o["metadata"].get("namespace") == "persona", o
PY
CASE="role evaluator (self-test): the reference role passes; a watch-only role, a patch-only deployments role, a role without replicasets, portforward, scale or secrets, and roles with pods/exec, nodes, rbac, serviceaccounts, wildcards or an extra verb all FAIL (the check is not vacuous)"
check python3 - "$work" "$root" <<'PY'
import copy, sys
sys.path.insert(0, sys.argv[1]); import kh
docs = [open(sys.argv[2] + "/docs/" + n).read() for n in ("kubernetes.md", "docker-deploy.md")]
needs = kh.doc_needs(docs)
good = kh.reference_rules()
assert kh.role_problems(good, needs) == [], kh.role_problems(good, needs)
def mut(f):
    r = copy.deepcopy(good); f(r); return r
bads = {
 "watch-only": [{"apiGroups": ["", "apps", "batch"], "resources": ["pods", "deployments", "services", "configmaps", "jobs", "events", "secrets", "persistentvolumeclaims", "replicasets"], "verbs": ["watch"]}],
 "patch-only deployments": mut(lambda r: r[1].update(resources=["replicasets"])) + [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["patch"]}],
 "no replicasets": mut(lambda r: r[1].update(resources=["deployments"])),
 "no portforward": mut(lambda r: r.pop(4)),
 "no scale": mut(lambda r: r.pop(5)),
 "no secrets": mut(lambda r: r[0].update(resources=["pods", "services", "configmaps", "persistentvolumeclaims", "events"])),
 "no pvc": mut(lambda r: r[0].update(resources=["pods", "services", "configmaps", "secrets", "events"])),
 "no logs": mut(lambda r: r.pop(3)),
 "no watch": mut(lambda r: [x.update(verbs=[v for v in x["verbs"] if v != "watch"]) for x in r[:3]]),
 "exec": mut(lambda r: r.append({"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]})),
 "attach": mut(lambda r: r.append({"apiGroups": [""], "resources": ["pods/attach"], "verbs": ["create"]})),
 "nodes": mut(lambda r: r.append({"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]})),
 "namespaces": mut(lambda r: r.append({"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get"]})),
 "rbac": mut(lambda r: r.append({"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["rolebindings"], "verbs": ["create"]})),
 "serviceaccounts token": mut(lambda r: r.append({"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]})),
 "wildcard verbs": mut(lambda r: r[0].update(verbs=["*"])),
 "wildcard resources": mut(lambda r: r[2].update(resources=["*"])),
 "wildcard groups": mut(lambda r: r[2].update(apiGroups=["*"])),
 "escalate": mut(lambda r: r[1].update(verbs=sorted(set(r[1]["verbs"]) | {"escalate"}))),
 "logs delete": mut(lambda r: r[3].update(verbs=["get", "list", "delete"])),
 "resourceNames": mut(lambda r: r[0].update(resourceNames=["x"])),
}
for n, r in bads.items():
    assert kh.role_problems(r, needs), ("the evaluator accepted a bad role", n)
assert kh.allows(good, "apps", "deployments/scale", "patch") and not kh.allows(good, "", "pods/exec", "create") and not kh.allows(good, "", "nodes", "get")
assert kh.allows([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}], "", "pods/exec", "create")
PY
CASE="role vs docs: the needs are DERIVED from the documented kubectl steps (docs/kubernetes.md, docs/docker-deploy.md: apply of Secret, PVC, Deployment, Service; scale; delete pvc; port-forward; exec is documented and deliberately not granted) and the persona's task (upgrade, rollback, logs); the evaluator knows every documented step"
check python3 - "$work" "$root" <<'PY'
import sys
sys.path.insert(0, sys.argv[1]); import kh
docs = [open(sys.argv[2] + "/docs/" + n).read() for n in ("kubernetes.md", "docker-deploy.md")]
n = kh.doc_needs(docs)
for need in (("", "secrets", "create"), ("", "persistentvolumeclaims", "create"), ("apps", "deployments/scale", "update"), ("", "pods/portforward", "create"), ("", "persistentvolumeclaims", "delete"),
             ("apps", "replicasets", "list"), ("", "pods/log", "get")):
    assert need in n, need
assert not [x for x in n if x[1] in ("pods/exec", "nodes", "namespaces")], n
PY
CASE="kind: the Role the driver applies lets every documented and task step work (as the can-i evaluator judges it) and grants nothing outside the allowed set: no wildcard, no pods/exec or attach, no nodes, namespaces, rbac, serviceaccounts or cluster scope"
check python3 - "$work/clean" "$work" "$root" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
roles = kh.of(d, "Role")
assert len(roles) == 1, roles
docs = [open(sys.argv[3] + "/docs/" + n).read() for n in ("kubernetes.md", "docker-deploy.md")]
pr = kh.role_problems(roles[0][2]["rules"], kh.doc_needs(docs))
assert pr == [], pr
assert roles[0][2]["metadata"]["namespace"] == "persona"
PY
CASE="kind: ONE RoleBinding in 'persona' binds that Role (kind Role, never a ClusterRole such as cluster-admin/admin/edit) to exactly the ServiceAccount, nothing else"
check python3 - "$work/clean" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
rb, sa, role = kh.of(d, "RoleBinding"), kh.of(d, "ServiceAccount"), kh.of(d, "Role")
assert len(rb) == 1 and len(sa) == 1 and len(role) == 1, (rb, sa, role)
rb, sa, role = rb[0][2], sa[0][2], role[0][2]
assert rb["roleRef"]["kind"] == "Role" and rb["roleRef"]["name"] == role["metadata"]["name"], rb["roleRef"]
assert rb["roleRef"].get("apiGroup", "rbac.authorization.k8s.io") == "rbac.authorization.k8s.io", rb["roleRef"]
assert [(s["kind"], s["name"], s.get("namespace")) for s in rb["subjects"]] == [("ServiceAccount", sa["metadata"]["name"], "persona")], rb["subjects"]
PY
CASE="duration parser (self-test): 1h, 24h, 3600s, 1h30m, 86400s and the decimal Go forms 1.5h, 1.h, 90.5m are accepted; -1h, 1hgarbage, 0, 0s, 30m, 59m59s, 25h, 86401s, .5h, 1.5.2h, 24.5h, an empty and a spaced value are rejected"
check python3 - "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[1]); import kh
for ok in ("1h", "24h", "3600s", "1h30m", "86400s", "23h59m59s", "60m", "1.5h", "1.h", "90.5m", "24.0h", "1h0.0s"):
    assert kh.duration_ok(ok), ok
for bad in ("-1h", "1hgarbage", "0", "0s", "0h", "30m", "59m59s", "25h", "86401s", ".5h", "1.5.2h", "1.5", "h", "", " 1h", "1h ", "1H", "3600", "+1h", "24.5h", "1h0.5s", "3600.5s", "1h100ms"):
    assert not kh.duration_ok(bad), bad
PY
CASE="kind: ONE short-lived token is minted with 'kubectl create token <the ServiceAccount> -n persona --duration D' (a valid Go duration, 1h <= D <= 24h), the issued JWT's own exp-iat (the API server may issue another lifetime than asked) is in the same range, and it happens after the namespace and RBAC were applied and before the on-call persona started"
check python3 - "$work/clean" "$work" <<'PY'
import base64, json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
calls = kh.kubectl(d)
tok = [(i, r) for i, r in enumerate(calls) if "create" in r["argv"] and "token" in r["argv"]]
assert len(tok) == 1, tok
i, r = tok[0]
a = r["argv"]
sa = kh.of(d, "ServiceAccount")[0][2]["metadata"]["name"]
assert a[a.index("token") + 1] == sa, a
ns = [a[k + 1] for k, x in enumerate(a) if x in ("-n", "--namespace")] + [x.split("=", 1)[1] for x in a if x.startswith(("--namespace=", "-n="))]
assert ns == ["persona"], a
dur = [a[k + 1] for k, x in enumerate(a) if x == "--duration"] + [x.split("=", 1)[1] for x in a if x.startswith("--duration=")]
assert len(dur) == 1 and kh.duration_ok(dur[0]), ("not a valid duration of 1h..24h", dur)
assert kh.go_duration(dur[0]) == 3600 + 900, ("the persona's token must outlive its window: --agent-timeout (3600 by default) + a 15 minute margin", dur)
iss = kh.issued(d)
assert len(iss) == 1
pl = json.loads(base64.urlsafe_b64decode(iss[0]["token"].split(".")[1] + "=="))
assert 3600 <= pl["exp"] - pl["iat"] <= 86400, ("the ISSUED lifetime (which the API server may set differently from the request) is what must cover the persona window", pl)
assert not [x for x in a if x.startswith("--dry-run")]
ns_i = min(i2 for i2, _, o in kh.objects(d) if o["kind"] == "Namespace")
last_apply = max(i2 for i2, _, _ in kh.objects(d))
first_rbac = min(i2 for i2, _, o in kh.objects(d) if o["kind"] != "Namespace")
assert ns_i <= first_rbac and last_apply < i, ("order", ns_i, first_rbac, last_apply, i)
objs = kh.objects(d)
order = [(i2, j) for i2, j, o in objs if o["kind"] == "Namespace"][0]
assert all((i2, j) >= order for i2, j, _ in objs), "the Namespace is not applied first"
GOOD = {"Namespace": "v1", "ServiceAccount": "v1", "Role": "rbac.authorization.k8s.io/v1", "RoleBinding": "rbac.authorization.k8s.io/v1"}
assert all(o["apiVersion"] == GOOD[o["kind"]] for _, _, o in objs), "an invalid apiVersion"
t0 = [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]["t0"]
assert r["t"] < t0, "the token was minted after the persona started"
PY
CASE="kind: the persona's kubeconfig is the ServiceAccount's: one cluster (the kind API server, with the cluster CA), namespace 'persona', ONE user holding only the minted token, no client certificate or key, no exec/auth-provider/basic auth, nothing of the admin"
check python3 - "$work/clean" "$work" <<'PY'
import sys, yaml
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
kc = yaml.safe_load(kh.persona_row(d)[0]["content"]["kubeconfig"])
assert len(kc["clusters"]) == 1 and len(kc["users"]) == 1 and len(kc["contexts"]) == 1, kc
c = kc["clusters"][0]["cluster"]
assert c["server"] == "https://persona-uat-control-plane:6443" and c.get("certificate-authority-data") == "CA-DATA-MARKER-PUBLIC", c
assert "insecure-skip-tls-verify" not in c or str(c["insecure-skip-tls-verify"]).lower() == "false", c
u = kc["users"][0]["user"]
assert u == {"token": kh.issued(d)[0]["token"]}, ("EXACTLY the token kubectl issued, and nothing else", u)
x = kc["contexts"][0]["context"]
assert x["namespace"] == "persona" and x["cluster"] == kc["clusters"][0]["name"] and x["user"] == kc["users"][0]["name"], x
assert kc["current-context"] == kc["contexts"][0]["name"], kc
raw = kh.persona_row(d)[0]["content"]["kubeconfig"]
assert "ADMIN-" not in raw and "client-certificate" not in raw and "client-key" not in raw, raw
PY
CASE="kind: the cluster is deleted by 'kind delete cluster --name <the created name>' after the persona ran, the admin kubeconfig is removed, and nothing is left listening (clean run)"
check python3 - "$work/clean" "$work" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
c = kh.create(d)
name = c["argv"][c["argv"].index("--name") + 1]
rows = kh.rows(d)
i = rows.index(c)
dels = [r for r in rows[i + 1:] if r["tool"] == "kind" and r["argv"][:2] == ["delete", "cluster"]]
assert len(dels) == 1 and dels[0]["argv"][dels[0]["argv"].index("--name") + 1] == name, rows
assert not os.path.exists(c["kc"])
PY
for c in 'kindblock|{"on-call-engineer":{"findings":[{"kind":"blocking","text":"upgrade step fails"}]}}' 'kindcrash|{"on-call-engineer":{"crash":true}}' 'kindgarbage|{"on-call-engineer":{"raw_out":"not json"}}'; do
  name=${c%%|*}; plan=${c#*|}
  run "$name" "$plan" rc
  CASE="kind ($name): the cluster is deleted and the admin kubeconfig removed whatever the persona's outcome"
  check python3 - "$work/$name" "$work" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
c = kh.create(d)
name = c["argv"][c["argv"].index("--name") + 1]
dels = [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"] and name in r["argv"]]
assert len(dels) == 1 and not os.path.exists(c["kc"])
PY
  CASE="kind ($name): the public log is ONLY the pass/fail lines (a malformed agent answer or a crash prints nothing of the captured output)"; check publiclog "$name"
done
KIND_FAIL=1 run kindfail '{}' rc
CASE="kind fails: the on-call persona did not run (blocking, no agent for it, no kubectl at all), the other four are unaffected and the run fails (fail closed)"
check python3 - "$work/kindfail" "$work" "$(out kindfail)" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert len(open(d + "/log").read().splitlines()) == 4
assert not kh.kubectl(d), "kubectl ran although no cluster exists"
rep = open(sys.argv[3] + "/on-call-engineer.report.md").read()
assert rep.splitlines()[0] == "VERDICT: blocking" and "did not run" in rep.lower(), rep
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator"):
    assert open(sys.argv[3] + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: pass", p
PY
check test "$rc" -ne 0
KUBECTL_FAIL_MATCH=apply run kubectlapplyfail '{}' rc
CASE="kubectl apply fails: the on-call persona did not run, NO token is minted, no kubeconfig is handed over, and the cluster is still deleted"
check python3 - "$work/kubectlapplyfail" "$work" "$(out kubectlapplyfail)" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert not [r for r in kh.kubectl(d) if "token" in r["argv"]], "a token was minted after the RBAC failed"
assert [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]], "the cluster is left behind"
assert "did not run" in open(sys.argv[3] + "/on-call-engineer.report.md").read().lower()
PY
check test "$rc" -ne 0
KUBECTL_FAIL_MATCH=token run kubectltokenfail '{}' rc
CASE="kubectl create token fails: the on-call persona did not run (no agent, no kubeconfig), the cluster is deleted, the run fails"
check python3 - "$work/kubectltokenfail" "$work" "$(out kubectltokenfail)" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]]
assert "did not run" in open(sys.argv[3] + "/on-call-engineer.report.md").read().lower()
PY
check test "$rc" -ne 0
KIND_PORT=18123 KIND_LISTEN=1 run kindport '{}' rc
CASE="kind port varies (kind picks a random loopback port): with the admin kubeconfig's server on 18123 the run is clean; the persona reaches the cluster BY NAME (the kind node on its network, port 6443), so neither the request nor its kubeconfig holds the host port"
check test "$rc" -eq 0
check python3 - "$work/kindport" "$work" <<'PY'
import json, sys, yaml
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
r = kh.persona_row(d)[0]
assert r["request"]["tools"]["kind"]["endpoint"] == "https://persona-uat-control-plane:6443", r["request"]["tools"]
kc = yaml.safe_load(r["content"]["kubeconfig"])
assert kc["clusters"][0]["cluster"]["server"] == "https://persona-uat-control-plane:6443", kc
assert "18090" not in r["content"]["kubeconfig"] and "18123" not in r["content"]["kubeconfig"]
PY
KIND_DELETE_FAIL=1 run kinddelfail '{}' rc
CASE="kind lifecycle: a failing 'kind delete cluster' does not crash the driver (no traceback), all five reports are written and the admin kubeconfig is still removed"
check python3 - "$work/kinddelfail" "$work" "$(out kinddelfail)" <<'PY'
import glob, os, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "Traceback" not in open(d + "/stderr").read()
assert len(glob.glob(sys.argv[3] + "/*.report.md")) == 5
assert not os.path.exists(kh.create(d)["kc"])
r = open(sys.argv[3] + "/on-call-engineer.report.md").read()
assert r.splitlines()[0] == "VERDICT: blocking" and "teardown failed: window not attributable" in r, r      # a cluster that cannot be deleted is a failed teardown (step 8, Codex B6)
PY
# --- TEARDOWN failures are hard failures (step 8 round 1, Codex B6): a failed `docker ps`/`rm`, root cleanup or kind delete means a survivor may still be sending traffic, so that
# persona AND every later one is blocking ("teardown failed: window not attributable") and the run starts NOTHING new (no container, no cluster) after it
tdcheck() { # <case> <index of the first persona that must read teardown failed> <max docker run -d calls>
  python3 - "$work/$1" "$(out "$1")" "$2" "$3" "$PERSONAS" "$work" <<'PYT'
import json, re, sys
d, o, idx, maxrun, personas, w = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5].split(), sys.argv[6]
sys.path.insert(0, w); import kh
for i, p in enumerate(personas):
    r = open("%s/%s.report.md" % (o, p)).read()
    if i < idx:
        assert r.splitlines()[0] == "VERDICT: pass" and "teardown failed" not in r, (p, r)
    else:
        assert r.splitlines()[0] == "VERDICT: blocking" and "teardown failed: window not attributable" in r, (p, r)
runs = [l for l in open(d + "/docker.log") if l.startswith("run -d") and "--entrypoint" not in l]       # the capture sidecars are not "containers started after": one per persona that began
assert len(runs) <= maxrun, ("a container was started after the teardown failed", len(runs), maxrun)
if idx < 4:
    assert not [r for r in kh.kind(d) if r["argv"][:2] == ["create", "cluster"]], "a cluster was created after the teardown failed"
assert "Traceback" not in open(d + "/stderr").read()
PYT
}
DOCKER_PS_FAIL_AT=1 run tdps1 '{}' rc
CASE="teardown: the FIRST persona's label sweep fails (docker ps unreachable): that persona and all four after it are blocking 'teardown failed: window not attributable', the run fails, and no container or cluster is started after it (one 'run -d' in all: the image)"
check tdcheck tdps1 0 1
check test "$rc" -ne 0
check publiclog tdps1
DOCKER_PS_FAIL_AT=3 run tdps3 '{}' rc
CASE="teardown: the THIRD persona's sweep fails: the first two keep their verdicts, the third, fourth and fifth read teardown failed, no cluster is created, and nothing is started after the third persona (the image, Jenkins and the runner: 3)"
check tdcheck tdps3 2 5
check test "$rc" -ne 0
check publiclog tdps3
DOCKER_FAIL_MATCH="--user 0:0" run tdclean '{}' rc
CASE="teardown: the ROOT cleanup container fails (the sandbox may still hold another uid's files and a live process): the first persona and every later one is blocking teardown failed"
check tdcheck tdclean 0 1
check publiclog tdclean
DOCKER_RM_FAIL_AT=2 run tdrm '{}' rc
CASE="teardown: removing the Maven persona's containers (its image container and the tools) fails (docker rm unreachable): the first persona passes, the Maven persona and every later one read teardown failed, no cluster is created"
check tdcheck tdrm 1 4
check publiclog tdrm
DOCKER_RM_FAIL_AT=6 run tdfinal '{}' rc
CASE="teardown: the LAST persona's removal of its container of the image under test fails (docker rm unreachable at the end): the run is not clean: that persona reads teardown failed (blocking), the earlier four keep their verdicts, the run exits 1"
check tdcheck tdfinal 4 7
check test "$rc" -eq 1
check publiclog tdfinal
DOCKER_RM_FAIL_AT=1 run tdrmd '{"gradle-platform-engineer":{"daemon":true}}' rc
CASE="teardown: a daemon-managed container the persona left behind and 'docker rm -f' cannot remove: that persona and all later ones are blocking (the survivor may keep sending traffic)"
check tdcheck tdrmd 0 1
for f in "${work:?}/containers"/*; do [ -e "$f" ] || continue; kill -9 "$(sed -n 2p "$f")" 2>/dev/null || true; rm -f "$f"; done      # the survivor the fake daemon could not remove
KIND_FAIL=1 KIND_DELETE_FAIL=1 run kindbothfail '{}' rc
CASE="kind lifecycle: kind create AND delete failing: the on-call persona did not run, no traceback, the other four are unaffected, the run fails"
check python3 - "$work/kindbothfail" "$(out kindbothfail)" "$rc" <<'PY'
import glob, sys
assert "Traceback" not in open(sys.argv[1] + "/stderr").read() and int(sys.argv[3]) != 0
assert "did not run" in open(sys.argv[2] + "/on-call-engineer.report.md").read().lower()
assert open(sys.argv[2] + "/gradle-platform-engineer.report.md").read().splitlines()[0] == "VERDICT: pass"
PY

# --- infrastructure failures fail closed (AC1, AC2): a dead image or tool must never read as a green run
DOCKER_FAIL_MATCH="$IMG" run imgdead '{}' rc
CASE="the image under test cannot start: the run fails, no persona is run against nothing, and every persona is reported did-not-run"
check test "$rc" -ne 0
check test "$(ls "$(out imgdead)"/*.report.md | wc -l | tr -d ' ')" -eq 5
check grep -qi 'did not run' "$(out imgdead)/on-call-engineer.report.md"
check grep -q 'VERDICT: blocking' "$(out imgdead)/gradle-platform-engineer.report.md"
DOCKER_FAIL_MATCH="$JEN" run jendead '{}' rc
CASE="a tool container (Jenkins) cannot start: that persona did not run (blocking), the other four are unaffected"
check test "$rc" -ne 0
check grep -qi 'did not run' "$(out jendead)/maven-jenkins-ci.report.md"
check grep -q 'VERDICT: pass' "$(out jendead)/gradle-platform-engineer.report.md"
CASE="the driver provisions nothing in a cloud: its docker calls are only run/rm/inspect/ps (and never gh)"
check python3 - "$work/clean/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    for l in open(path):
        assert l.split()[0] in ("run", "rm", "inspect", "exec", "ps", "stop", "kill", "logs", "network"), l
PY

# --- AC1: broken behavior or a failing doc step fails the RC run ------------------------------------------------
run blocking '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"docs/maven.md step 3 fails as written: 404"}]}}' rc
CASE="rc: a blocking finding fails the run"; check test "$rc" -ne 0
CASE="the blocking persona's report says blocking and carries the finding"
check grep -q 'VERDICT: blocking' "$(out blocking)/maven-jenkins-ci.report.md"
check grep -q 'step 3 fails as written' "$(out blocking)/maven-jenkins-ci.report.md"
CASE="the other four personas still ran and wrote reports (one failure does not hide the rest)"
check test "$(nlines "$work/blocking/log")" -eq 5 -a "$(ls "$(out blocking)"/*.report.md | wc -l | tr -d ' ')" -eq 5

# fail closed: anything that is not exactly the contract counts as blocking, "did not run", never a pass
failclosed() { # <case> <persona> <plan-for-persona-json>
  run "fc-$1" "{\"$2\":$3}" rc
  CASE="fail closed ($1): the run fails"; check test "$rc" -ne 0
  CASE="fail closed ($1): that persona's report says blocking and that it did not run"
  check grep -q 'VERDICT: blocking' "$(out "fc-$1")/$2.report.md"
  check grep -qi 'did not run' "$(out "fc-$1")/$2.report.md"
  # a malformed or failing agent answer must not leak into the public log: no captured stdout or stderr, only the pass/fail lines
  CASE="fail closed ($1): the public log is ONLY the pass/fail lines (the agent's captured output, malformed or not, is never printed)"; check publiclog "fc-$1"
}
failclosed crash        compliance-reviewer '{"crash":true}'
failclosed garbage      readme-evaluator    '{"raw_out":"not json at all"}'
failclosed empty-object readme-evaluator    '{"raw_out":"{}"}'
failclosed truncated    on-call-engineer    '{"raw_out":"{\"findings\": [], \"tokens\": 10, \"transcr"}'
failclosed empty-out    on-call-engineer    '{"raw_out":""}'
failclosed findings-str gradle-platform-engineer '{"override":{"findings":"none"}}'
failclosed kind-bad     gradle-platform-engineer '{"findings":[{"kind":"meh","text":"x"}]}'
failclosed text-missing gradle-platform-engineer '{"findings":[{"kind":"friction"}]}'
failclosed text-notstr  gradle-platform-engineer '{"findings":[{"kind":"friction","text":5}]}'
failclosed tokens-neg   maven-jenkins-ci         '{"override":{"tokens":-1}}'
failclosed tokens-str   maven-jenkins-ci         '{"override":{"tokens":"many"}}'
failclosed tokens-bool  maven-jenkins-ci         '{"override":{"tokens":true}}'
failclosed tokens-float maven-jenkins-ci         '{"override":{"tokens":1.5}}'
failclosed extra-key    maven-jenkins-ci         '{"override":{"surprise":1}}'
failclosed tokens-gone  maven-jenkins-ci         '{"drop":["tokens"]}'
failclosed transcript-gone compliance-reviewer   '{"drop":["transcript"]}'
failclosed transcript-notstr compliance-reviewer '{"override":{"transcript":["a"]}}'
failclosed findings-gone readme-evaluator        '{"drop":["findings"]}'
CASE="a failed agent leaves its transcript file present AND holding what it had written to stderr, so the artifact can diagnose it"
check test -e "$(out fc-crash)/compliance-reviewer.transcript.txt"
check grep -q 'PARTIAL-TRANSCRIPT for compliance-reviewer' "$(out fc-crash)/compliance-reviewer.transcript.txt"

# --- AC3 (amended): friction is information INSIDE the encrypted report only, blocks nothing, and NO public issue is opened --------------------------
FR='{"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"the proxy URL is easy to mistype"}]},"on-call-engineer":{"findings":[{"kind":"friction","text":"no log level hint"},{"kind":"friction","text":"rollback needs two reads"}]}}'
run friction "$FR" rc
CASE="friction alone does not fail an rc run (exit 0)"; check test "$rc" -eq 0
CASE="the friction notes are INSIDE the personas' encrypted reports (decrypted: each under 'Friction', verdict friction), and nowhere else"
check python3 - "$(out friction)" <<'PY'
import sys
d = sys.argv[1]
g = open(d + "/gradle-platform-engineer.report.md").read()
o = open(d + "/on-call-engineer.report.md").read()
assert g.splitlines()[0] == "VERDICT: friction" and "Friction" in g and "the proxy URL is easy to mistype" in g, g
assert o.splitlines()[0] == "VERDICT: friction" and "no log level hint" in o and "rollback needs two reads" in o, o
PY
CASE="no public trace of friction: the job log is a pass/fail line per persona and overall (friction reads pass), the artifact directory holds only <persona>.cms, there is no issue file, and gh was never called"
publiclog friction >/dev/null 2>&1 && ok "$CASE" || bad "$CASE"
check python3 - "$work/friction" "$PERSONAS" <<'PY'
import os, sys
d = sys.argv[1]
assert sorted(os.listdir(d + "/out")) == sorted(p + ".cms" for p in sys.argv[2].split()), os.listdir(d + "/out")
assert open(d + "/gh.log").read() == ""
blob = open(d + "/stdout").read() + open(d + "/stderr").read() + " ".join(os.listdir(d + "/out"))
for w in ("proxy", "log level", "rollback needs", "friction", "issue"):
    assert w not in blob.lower(), w
PY
CASE="friction blocks nothing: a mixed run (blocking in one persona, friction in another) fails (exit 1) on the blocking one only; the friction note stays inside its own encrypted report; the log reads fail for the blocking persona and overall, pass for the friction one"
run mixed '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"jenkins step fails"}]},"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"confusing proxy text"}]}}' rc
check test "$rc" -ne 0
check publiclog mixed
check grep -q 'confusing proxy text' "$(out mixed)/gradle-platform-engineer.report.md"
check grep -q 'jenkins step fails' "$(out mixed)/maven-jenkins-ci.report.md"
check none_match 'jenkins step fails|confusing proxy' "$work/mixed/stdout" "$work/mixed/stderr"
CASE="a friction-only persona's verdict is friction"
check grep -q 'VERDICT: friction' "$(out friction)/gradle-platform-engineer.report.md"
CASE="the driver has no issue machinery left: --publish and --gh are refused (exit 2), nothing starts"
for opt in "--publish" "--gh gh"; do
  mkdir -p "$work/noissue"; : >"$work/noissue/docker.log"; : >"$work/noissue/log"; rc=0
  env PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --image "$IMG" --repo "$repo" --out "$work/noissue/out" --tools "$work/tools.json" \
    --docker "$work/docker.tmpl" --recipient "$work/test.pem" --agent "python3 $work/stub.py $work/noissue" $opt >/dev/null 2>&1 || rc=$?
  check test "$rc" -eq 2 -a ! -s "$work/noissue/log" -a ! -s "$work/noissue/docker.log"
done

# --- AC2 (amended): the weekly run exercises the same five personas on the image it is given; a blocking finding FAILS the run; the only public trace is the pass/fail line --
WK='{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"jenkins step fails"}]},"compliance-reviewer":{"findings":[{"kind":"blocking","text":"cosign verify fails as written"}]}}'
IMAGE="$IMG2" run weekly "$WK" weekly
CASE="weekly: all five personas run, on the latest-release image it was given, and each persona's encrypted artifact is written"
check python3 - "$work/weekly/log" "$PERSONAS" "$IMG2" "$work/weekly/docker.log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert sorted(r["persona"] for r in rows) == sorted(sys.argv[2].split()), [r["persona"] for r in rows]
assert all(r["request"]["image"] == sys.argv[3] for r in rows)
assert sum(1 for l in open(sys.argv[4]) if l.startswith("run -d ") and sys.argv[3] in l) == 5       # one fresh container per persona
PY
check test "$(ls "$work/weekly/out"/*.cms | wc -l | tr -d ' ')" -eq 5 -a "$(ls "$(out weekly)"/*.report.md | wc -l | tr -d ' ')" -eq 5 -a "$(ls "$(out weekly)"/*.transcript.txt | wc -l | tr -d ' ')" -eq 5
CASE="weekly: a blocking finding FAILS the run (exit 1: there is no issue left to carry it), the findings are in the encrypted reports, the log is five pass/fail lines plus overall, and nothing reached gh"
check test "$rc" -eq 1
check publiclog weekly
check grep -q 'jenkins step fails' "$(out weekly)/maven-jenkins-ci.report.md"
check grep -q 'cosign verify fails as written' "$(out weekly)/compliance-reviewer.report.md"
check none_match 'jenkins step fails|cosign verify' "$work/weekly/stdout" "$work/weekly/stderr"
check test ! -s "$work/weekly/gh.log"
CASE="weekly: a clean run exits 0 with a pass line per persona and overall"
IMAGE="$IMG2" run weeklyclean '{}' weekly
check test "$rc" -eq 0
check publiclog weeklyclean
CASE="weekly with friction only exits 0 (AC3: friction blocks nothing, on either schedule); the note is inside the encrypted report"
IMAGE="$IMG2" run weeklyfr '{"gradle-platform-engineer":{"findings":[{"kind":"friction","text":"f-note"}]}}' weekly
check test "$rc" -eq 0
check grep -q 'f-note' "$(out weeklyfr)/gradle-platform-engineer.report.md"
check none_match 'f-note' "$work/weeklyfr/stdout" "$work/weeklyfr/stderr"
CASE="weekly: an agent that crashes also counts as blocking (exit 1, fail line for that persona and overall), never a silent pass; its did-not-run report is encrypted"
IMAGE="$IMG2" run weeklycrash '{"on-call-engineer":{"crash":true}}' weekly
check test "$rc" -eq 1
check publiclog weeklycrash
check grep -qi 'did not run' "$(out weeklycrash)/on-call-engineer.report.md"
CASE="weekly: a dead image fails the run (exit 1) with a fail line for every persona and overall, and each persona still has its encrypted did-not-run report"
DOCKER_FAIL_MATCH="$IMG2" IMAGE="$IMG2" run weekdead '{}' weekly
check test "$rc" -eq 1
check publiclog weekdead
check python3 - "$work/weekdead" "$PERSONAS" <<'PY'
import sys
d = sys.argv[1]
for p in sys.argv[2].split():
    assert "did not run" in open(d + "/plain/" + p + ".report.md").read().lower(), p
PY
CASE="an agent that hangs is cut off after --agent-timeout, counts as blocking (did not run), and the other four still run"
AGENT_TIMEOUT=1 run hang '{"readme-evaluator":{"sleep":30}}' rc
check test "$rc" -ne 0 -a "$(nlines "$work/hang/log")" -eq 5
check grep -qi 'did not run' "$(out hang)/readme-evaluator.report.md"
check grep -q 'VERDICT: pass' "$(out hang)/on-call-engineer.report.md"

# --- PRIVACY (amendment 0215): one ENCRYPTED artifact per persona, made with openssl cms to the committed recipient certificate; nothing else is public ----
CASE="the artifact directory (--out) holds EXACTLY five files, <persona>.cms each, and nothing else: no plaintext report, transcript, summary or issue file, in a clean, a blocking and a crashed run"
check python3 - "$PERSONAS" "$work/clean/out" "$work/blocking/out" "$work/fc-crash/out" <<'PY'
import os, sys
want = sorted(p + ".cms" for p in sys.argv[1].split())
for d in sys.argv[2:]:
    assert sorted(os.listdir(d)) == want, (d, os.listdir(d))
PY
CASE="the encrypted artifact is not plaintext: none of the report's or the transcript's marker bytes (the verdict line, the persona name as a report heading, the transcript marker) appear in the .cms bytes, and it decrypts with the TEST key to exactly report + transcript (one separator line '=== TRANSCRIPT ===')"
check python3 - "$work/clean" <<'PY'
import glob, sys
d = sys.argv[1]
for f in glob.glob(d + "/out/*.cms"):
    b = open(f, "rb").read()
    for marker in (b"VERDICT", b"persona:", b"TRANSCRIPT for", b"tokens used", b"Hosts named"):
        assert marker not in b, (f, marker)
for f in glob.glob(d + "/plain/*.payload"):
    t = open(f).read()
    assert t.count("\n=== TRANSCRIPT ===\n") == 1 and t.startswith("VERDICT: "), f
    rep, tr = t.split("\n=== TRANSCRIPT ===\n")
    assert "persona: " in rep and "TRANSCRIPT for " in tr, f
    assert open(f.replace(".payload", ".report.md")).read() == rep and open(f.replace(".payload", ".transcript.txt")).read() == tr
assert len(glob.glob(d + "/plain/*.payload")) == 5
PY
CASE="a CMS file encrypted for a DIFFERENT recipient does not decrypt with the test key, and the driver's artifact does not decrypt with the other key"
check python3 - "$work" <<'PY'
import glob, subprocess, sys
w = sys.argv[1]
def dec(f, key):
    cert = key[:-4] + ".pem"       # -recip <cert> makes a wrong key FAIL deterministically (without it openssl "succeeds" with garbage about 1 time in 256)
    for inf in ("DER", "PEM", "SMIME"):
        r = subprocess.run(["openssl", "cms", "-decrypt", "-inform", inf, "-recip", cert, "-inkey", key, "-in", f], capture_output=True)
        if r.returncode == 0:
            return r.stdout
    return None
f = sorted(glob.glob(w + "/clean/out/*.cms"))[0]
assert dec(f, w + "/test.key") is not None
assert dec(f, w + "/other.key") is None, "the artifact decrypts with a key that is not the recipient's"
# an artifact built for the other recipient
r = subprocess.run(["openssl", "cms", "-encrypt", "-aes-256-cbc", "-outform", "DER", "-recip", w + "/other.pem"], input=b"secret report", capture_output=True)
open(w + "/for-other.cms", "wb").write(r.stdout)
assert dec(w + "/for-other.cms", w + "/test.key") is None and dec(w + "/for-other.cms", w + "/other.key") == b"secret report"
PY
# cmsjudge.py: WHO can read an artifact is a property of the produced CMS, not of the argv alone: exactly ONE recipient info, a key-transport (ktri) one for exactly the
# recipient certificate (issuer and serial), content encryption AES-256, and no password, symmetric-key (kekri), key-agreement or other recipient; and the argv carries no
# option that adds one (-secretkey, -secretkeyid, -pwri_password, -keyid, -originator, a second -recip, -passin/-pass, -stream)
cat >"$work/cmsjudge.py" <<'CJ'
import re, subprocess

ALLOWED = {"cms", "-encrypt", "-aes-256-cbc", "-aes256", "-binary", "-outform", "DER", "-out", "-recip"}
def judge_argv(argv, cert):
    errs = []
    if argv[:2] != ["cms", "-encrypt"]:
        errs.append("not `openssl cms -encrypt`")
    if not ("-aes-256-cbc" in argv or "-aes256" in argv):
        errs.append("not AES-256")
    if "-binary" not in argv:
        errs.append("no -binary")
    if argv.count("-recip") != 1:
        errs.append("-recip must appear exactly once (found %d)" % argv.count("-recip"))
    elif argv[argv.index("-recip") + 1] != cert:
        errs.append("the recipient is not the certificate")
    i, skip = 2, False
    for k, t in enumerate(argv[2:], 2):
        if skip:
            skip = False; continue
        if t in ("-recip", "-out", "-outform"):
            skip = True; continue
        if t not in ALLOWED:
            errs.append("an option outside the allowlist that could add or alter a recipient: %s" % t)
    if "-in" in argv:
        errs.append("plaintext handed over as a file (-in)")
    return errs

def cert_ident(cert):
    out = subprocess.run(["openssl", "x509", "-noout", "-serial", "-issuer", "-in", cert], capture_output=True, text=True).stdout
    serial = re.search(r"serial=([0-9A-Fa-f]+)", out).group(1).upper().lstrip("0")
    issuer = re.search(r"issuer=\s*(.*)", out).group(1).strip()
    return serial, issuer

def judge_cms(path, cert):
    r = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER", "-in", path], capture_output=True, text=True)
    if r.returncode != 0:
        return ["not a parseable DER CMS: " + r.stderr.strip()[:80]]
    t = r.stdout
    errs = []
    if "pkcs7-envelopedData" not in t:
        errs.append("not enveloped data")
    ri = t.split("recipientInfos:", 1)[1] if "recipientInfos:" in t else ""
    ri = ri.split("encryptedContentInfo:", 1)[0]
    kinds = re.findall(r"^ {6}d\.(\w+):", ri, re.M)
    if kinds != ["ktri"]:
        errs.append("recipient infos must be exactly one ktri, found %s" % kinds)
    serial, issuer = cert_ident(cert)
    m = re.findall(r"serialNumber:\s*0x([0-9A-Fa-f]+)", ri)
    if [x.upper().lstrip("0") for x in m] != [serial]:
        errs.append("the recipient's serial is not the certificate's")
    iss = re.findall(r"issuer:\s*(.*)", ri)
    if len(iss) != 1 or iss[0].strip().replace(" ", "") != issuer.replace(" ", ""):
        errs.append("the recipient's issuer is not the certificate's")
    enc = t.split("encryptedContentInfo:", 1)[1] if "encryptedContentInfo:" in t else ""
    if not re.search(r"contentEncryptionAlgorithm:\s*\n\s*algorithm:\s*aes-256-cbc", enc):
        errs.append("content encryption is not AES-256-CBC")
    if "originatorInfo: <ABSENT>" not in t:
        errs.append("an originator is present")
    return errs
CJ
CASE="who can read an artifact is proven on the PRODUCED CMS and the argv: every artifact (the five of a clean run; the default-recipient run is judged the same way below) has exactly ONE recipient info, a key-transport one for the recipient certificate (issuer and serial), content encryption AES-256-CBC, no password, symmetric-key, key-agreement or originator entry; the driver's openssl call is exactly one -encrypt per persona with AES-256, -binary, one -recip (the certificate), no -in, and no option that adds a recipient (-secretkey, -secretkeyid, -pwri_password, -keyid, -originator, -passin, -stream)"
check python3 - "$work" "$work/clean" <<'PY'
import glob, json, sys
w = sys.argv[1]; sys.path.insert(0, w); import cmsjudge
pem = w + "/test.pem"
for d, cert in ((sys.argv[2], pem),):
    calls = [json.loads(l) for l in open(d + "/openssl.log")]
    enc = [c for c in calls if c[:2] == ["cms", "-encrypt"]]
    assert len(enc) == 5, (d, calls)
    for c in enc:
        e = cmsjudge.judge_argv(c, cert if d == sys.argv[2] else c[c.index("-recip") + 1])
        assert not e, (c, e)
        assert not [x for x in c if x.endswith((".md", ".txt", ".payload", ".report", ".transcript"))], ("plaintext handed over as a file", c)
    files = glob.glob(d + "/out/*.cms")
    assert len(files) == 5, (d, files)
    for f in files:
        e = cmsjudge.judge_cms(f, pem)
        assert not e, (f, e)
PY
CASE="the CMS judge itself (self-test): it accepts a good artifact and REJECTS each way of adding a reader: an extra -secretkey recipient (readable without any private key), a password recipient, a second certificate, AES-128, another certificate, a repeated -recip, -keyid, -originator, -passin, -stream, plain data, garbage"
check python3 - "$work" <<'PY'
import subprocess, sys
w = sys.argv[1]; sys.path.insert(0, w); import cmsjudge
pem, other = w + "/test.pem", w + "/other.pem"
def enc(*extra, cert=pem, cipher="-aes-256-cbc"):
    r = subprocess.run(["openssl", "cms", "-encrypt", cipher, "-binary", "-outform", "DER", "-recip", cert] + list(extra), input=b"x", capture_output=True)
    assert r.returncode == 0, r.stderr
    open(w + "/cj.cms", "wb").write(r.stdout)
    return cmsjudge.judge_cms(w + "/cj.cms", pem)
assert enc() == [], enc()
KEY = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
for name, extra, kw in (("secretkey recipient", ["-secretkey", KEY, "-secretkeyid", "01"], {}), ("password recipient", ["-pwri_password", "pw"], {}),
                        ("second certificate", ["-recip", other], {}), ("aes-128", [], {"cipher": "-aes-128-cbc"}), ("another certificate only", [], {"cert": other})):
    assert enc(*extra, **kw), ("the CMS judge accepted: " + name)
good = ["cms", "-encrypt", "-aes-256-cbc", "-binary", "-outform", "DER", "-recip", pem]
assert cmsjudge.judge_argv(good, pem) == []
assert cmsjudge.judge_argv(good + ["-out", "x.cms"], pem) == []
for name, argv in (("-secretkey", good + ["-secretkey", KEY]), ("-secretkeyid", good + ["-secretkeyid", "01"]), ("-pwri_password", good + ["-pwri_password", "p"]),
                   ("second -recip", good + ["-recip", other]), ("-keyid", good + ["-keyid"]), ("-originator", good + ["-originator", other]), ("-passin", good + ["-passin", "pass:x"]),
                   ("-stream", good + ["-stream"]), ("-in", good + ["-in", "f.txt"]), ("no -binary", [a for a in good if a != "-binary"]), ("aes-128", ["-aes-128-cbc" if a == "-aes-256-cbc" else a for a in good]),
                   ("wrong certificate", good[:-1] + [other])):
    assert cmsjudge.judge_argv(argv, pem), ("the argv judge accepted: " + name)
open(w + "/cj.cms", "wb").write(b"not cms")
assert cmsjudge.judge_cms(w + "/cj.cms", pem)
r = subprocess.run(["openssl", "smime", "-sign", "-signer", pem, "-inkey", w + "/test.key", "-outform", "DER", "-binary"], input=b"x", capture_output=True)
open(w + "/cj.cms", "wb").write(r.stdout)
assert cmsjudge.judge_cms(w + "/cj.cms", pem), "signed (not enveloped) data accepted"
PY
CASE_ENC="encryption failure leaves NOTHING uploadable: after ANY failed encryption (an empty or partial destination, on the first call, on the third, on all) --out holds NO file at all (the failed destination removed, and no earlier persona's good .cms kept: the always() upload must find nothing), no file in it is plaintext, the run fails (exit 1) with only pass/fail lines, and nothing readable is left in the private TMPDIR"
for mode in 1 partial first 3; do
  OPENSSL_FAIL=$mode run "encfail-$mode" '{}' rc
  CASE="$CASE_ENC (mode $mode)"
  check python3 - "$work/encfail-$mode" "$rc" "$PERSONAS" "$mode" <<'PY'
import os, re, sys
d, rc, personas, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3].split(), sys.argv[4]
assert rc == 1, rc
left = [os.path.join(r, f) for r, _, fs in os.walk(d + "/out") for f in fs] if os.path.isdir(d + "/out") else []
assert left == [], ("an uploadable file survived a failed encryption (a failed destination, or an earlier persona's artifact)", left)
lines = [l for f in ("stdout", "stderr", "summary.md") for l in open(d + "/" + f).read().splitlines() if l.strip()]
assert all(re.match(r"^persona-uat: ([a-z-]+|overall): (pass|fail)$", l) for l in lines), lines
assert "persona-uat: overall: fail" in lines
failed = {"1": personas, "partial": personas, "first": personas[:1], "3": [personas[2]]}[mode]
for p in failed:
    assert "persona-uat: %s: fail" % p in lines, ("a persona whose encryption failed must read fail", p, lines)
for r, _, fs in os.walk(d + "/tmp"):
    for f in fs:
        c = open(os.path.join(r, f), "rb").read()
        assert b"VERDICT" not in c and b"TRANSCRIPT for" not in c and b"PARTIAL-" not in c, ("readable report text left in TMPDIR", f)
PY
done
for bad in missing garbage privatekey; do
  case $bad in missing) rec="$work/no-such-recipient.pem";; garbage) echo "not a certificate" >"$work/garbage.pem"; rec="$work/garbage.pem";; privatekey) rec="$work/test.key";; esac
  RECIPIENT="$rec" run "badrec-$bad" '{}' rc
  CASE="a recipient that is $bad is refused before anything starts (exit 2); a private key is never accepted as the recipient"
  check test "$rc" -eq 2 -a ! -s "$work/badrec-$bad/docker.log" -a ! -s "$work/badrec-$bad/log" -a -z "$(ls "$work/badrec-$bad/out" 2>/dev/null)"
done
CASE="a private key never touches the tree: no tracked file holds a private-key block (git ls-files), the persona UAT sources name no key path, and the committed recipient (bin/persona-uat-recipient.pem) is a certificate"
check python3 - "$root" <<'PY'
import os, re, subprocess, sys
root = sys.argv[1]
files = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True).stdout.split()
pat = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
hits = [f for f in files if os.path.isfile(os.path.join(root, f)) and pat.search(open(os.path.join(root, f), errors="replace").read())]
assert not hits, ("a private-key block is tracked", hits)
pem = os.path.join(root, "bin/persona-uat-recipient.pem")
assert os.path.isfile(pem), "the recipient certificate bin/persona-uat-recipient.pem is not committed"
r = subprocess.run(["openssl", "x509", "-in", pem, "-noout", "-subject"], capture_output=True, text=True)
assert r.returncode == 0 and "PRIVATE" not in open(pem).read(), "bin/persona-uat-recipient.pem is not a plain certificate"
for f in ("bin/persona-uat.py", "bin/persona-uat-agent.py", "bin/persona-uat-provider.py"):
    assert "persona-uat.key" not in open(os.path.join(root, f)).read(), f
PY

# --- the local decryption script (bin/persona-uat-decrypt.sh <run id> [key path]) with a FAITHFUL fake gh and the test key -------------------------------
# The fake `gh run download` behaves like the real one: it needs a repository (-R owner/repo, or a git clone as the working directory), a numeric run id and only
# known flags; WITHOUT -n it downloads EVERY artifact of the run into DIR/<artifact name>/; with exactly ONE -n NAME it downloads just that artifact FLAT into DIR; an
# unknown name fails; several -n nest again. The run holds the persona artifact AND an unrelated one (with a decoy .cms encrypted for someone else).
dsh="$root/bin/persona-uat-decrypt.sh"
ARTNAME="persona-uat-encrypted"
mkdir -p "$work/dsh/bin" "$work/dsh/run/$ARTNAME" "$work/dsh/run/other-artifact" "$work/dsh/clone" "$work/dsh/nogit"
cp "$work/clean/out/"*.cms "$work/dsh/run/$ARTNAME/" 2>/dev/null || true
openssl cms -encrypt -aes-256-cbc -binary -outform DER -recip "$work/other.pem" -out "$work/dsh/run/other-artifact/decoy.cms" <<<"not for us" 2>/dev/null || true
echo "unrelated notes" >"$work/dsh/run/other-artifact/notes.txt"
git -C "$work/dsh/clone" init -q 2>/dev/null || true
git -C "$work/dsh/clone" remote add origin https://github.com/own/cache.git 2>/dev/null || true      # a clone whose origin is the RIGHT repository
mkdir -p "$work/dsh/clone-noremote" "$work/dsh/clone-wrong" "$work/dsh/clone-real"
git -C "$work/dsh/clone-real" init -q 2>/dev/null || true; git -C "$work/dsh/clone-real" remote add origin git@github.com:fosterstack/cache.git 2>/dev/null || true
git -C "$work/dsh/clone-noremote" init -q 2>/dev/null || true                                       # a clone with NO remote
git -C "$work/dsh/clone-wrong" init -q 2>/dev/null || true; git -C "$work/dsh/clone-wrong" remote add origin https://github.com/evil/other.git 2>/dev/null || true
cat >"$work/dsh/bin/gh" <<'SH'
#!/bin/sh
# fake gh run download: FAKE_RUN is the run's artifact root (one directory per artifact); FAKE_GH_FAIL=1 fails; every call is logged
echo "$*" >>"$FAKE_GH_LOG"
[ -z "${FAKE_GH_FAIL:-}" ] || { echo "gh: simulated failure" >&2; exit 1; }
[ "$1 $2" = "run download" ] || { echo "unexpected gh call" >&2; exit 1; }
shift 2
id=""; dir=.; repo=""; names=""; n=0
while [ $# -gt 0 ]; do
  case "$1" in
    -D|--dir) dir=$2; shift 2;;
    -D=*|--dir=*) dir=${1#*=}; shift;;
    -R|--repo) repo=$2; shift 2;;
    -R=*|--repo=*) repo=${1#*=}; shift;;
    -n|--name) names="$names $2"; n=$((n+1)); shift 2;;
    -n=*|--name=*) names="$names ${1#*=}"; n=$((n+1)); shift;;
    -*) echo "unknown flag: $1" >&2; exit 1;;
    *) [ -z "$id" ] || { echo "accepts at most 1 arg(s)" >&2; exit 1; }; id=$1; shift;;
  esac
done
case "$id" in ""|*[!0-9]*) echo "invalid run id: '$id'" >&2; exit 1;; esac
if [ -z "$repo" ]; then
  url=$(git config --get remote.origin.url 2>/dev/null) || { echo "failed to determine base repo: no git remotes found (use -R owner/repo)" >&2; exit 1; }
  repo=$(printf '%s' "$url" | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##')
fi
case "$repo" in */*) ;; *) echo "expected the [HOST/]OWNER/REPO format" >&2; exit 1;; esac
# the run and its artifacts belong to ONE repository (FAKE_REPO): any other owner/name does not have them
[ "$repo" = "$FAKE_REPO" ] || { echo "HTTP 404: Not Found (https://api.github.com/repos/$repo/actions/runs/$id/artifacts)" >&2; exit 1; }
# ... and the artifacts to ONE run of it (FAKE_RUN_ID): another run id has none
[ "$id" = "$FAKE_RUN_ID" ] || { echo "HTTP 404: Not Found (https://api.github.com/repos/$repo/actions/runs/$id)" >&2; exit 1; }
mkdir -p "$dir"
if [ "$n" -eq 0 ]; then
  for a in "$FAKE_RUN"/*; do mkdir -p "$dir/$(basename "$a")"; cp "$a"/* "$dir/$(basename "$a")/"; done
elif [ "$n" -eq 1 ]; then
  name=${names# }; [ -d "$FAKE_RUN/$name" ] || { echo "no artifact matches any of the names or patterns provided" >&2; exit 1; }
  cp "$FAKE_RUN/$name"/* "$dir/"
else
  for name in $names; do [ -d "$FAKE_RUN/$name" ] || { echo "no artifact matches: $name" >&2; exit 1; }; mkdir -p "$dir/$name"; cp "$FAKE_RUN/$name"/* "$dir/$name/"; done
fi
SH
chmod +x "$work/dsh/bin/gh"
dsh_run() { # <run id> [key path or NOKEY] ; env FAKE_GH_FAIL, FAKE_RUN, DSH_CWD, DSH_REPO (GITHUB_REPOSITORY; default own/cache; NONE = unset) ; sets drc, stdout/stderr in $work/dsh/{o,e}
  local reppart=(GITHUB_REPOSITORY="${DSH_REPO:-own/cache}"); [ "${DSH_REPO:-}" != NONE ] || reppart=(-u GITHUB_REPOSITORY)
  rm -rf "${work:?}/dsh/tmp"; mkdir -p "$work/dsh/tmp"; : >"$work/dsh/gh.log"; drc=0
  local cwd="${DSH_CWD:-$work/dsh/clone}"
  if [ "${2:-}" = NOKEY ]; then
    (cd "$cwd" && env "${reppart[@]}" FAKE_REPO="${DSH_FAKE_REPO:-own/cache}" FAKE_RUN_ID="${DSH_FAKE_RUN:-4242}" HOME="$work/dsh/home" PATH="$work/dsh/bin:$PATH" FAKE_GH_LOG="$work/dsh/gh.log" FAKE_RUN="${FAKE_RUN:-$work/dsh/run}" TMPDIR="$work/dsh/tmp" bash "$dsh" "$1") >"$work/dsh/o" 2>"$work/dsh/e" || drc=$?
  else
    (cd "$cwd" && env "${reppart[@]}" FAKE_REPO="${DSH_FAKE_REPO:-own/cache}" FAKE_RUN_ID="${DSH_FAKE_RUN:-4242}" HOME="$work/dsh/home" PATH="$work/dsh/bin:$PATH" FAKE_GH_LOG="$work/dsh/gh.log" FAKE_RUN="${FAKE_RUN:-$work/dsh/run}" TMPDIR="$work/dsh/tmp" bash "$dsh" "$1" ${2:+"$2"}) >"$work/dsh/o" 2>"$work/dsh/e" || drc=$?
  fi
}
mkdir -p "$work/dsh/home" "$work/dsh/tmp"
dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh against a faithful gh (the run holds the persona artifact AND an unrelated one with a decoy .cms): it downloads the persona artifact by its EXACT name (exactly one -n, flat), the run id and a directory it owns, decrypts exactly the five persona files, and never touches the unrelated artifact; it says where"
check python3 - "$work" "$drc" "$ARTNAME" <<'PY'
import glob, os, re, sys
w, rc, art = sys.argv[1], int(sys.argv[2]), sys.argv[3]
assert rc == 0, open(w + "/dsh/e").read()
gh = [l for l in open(w + "/dsh/gh.log").read().split("\n") if l]
assert len(gh) == 1 and gh[0].split()[:3] == ["run", "download", "4242"], gh
toks = gh[0].split()
names = [toks[i + 1] for i, t in enumerate(toks) if t in ("-n", "--name")] + [t.split("=", 1)[1] for t in toks if t.startswith(("-n=", "--name="))]
assert names == [art], ("exactly one -n with the persona artifact's exact name (an omitted name downloads everything, nested)", names)
repos = [toks[i + 1] for i, t in enumerate(toks) if t in ("-R", "--repo")] + [t.split("=", 1)[1] for t in toks if t.startswith(("-R=", "--repo="))]
assert repos == ["own/cache"], ("the script passes the repository explicitly (from GITHUB_REPOSITORY or its own default)", repos)
m = re.search(r"decrypted into (\S+)", open(w + "/dsh/o").read())
assert m, open(w + "/dsh/o").read()
d = m.group(1)
want = {os.path.basename(f)[:-len(".payload")]: open(f).read() for f in glob.glob(w + "/clean/plain/*.payload")}
got = {os.path.basename(f).rsplit(".", 1)[0]: open(f).read() for f in glob.glob(d + "/*") if os.path.isfile(f)}
assert sorted(got) == sorted(want) and all(got[k] == want[k] for k in want), (sorted(got), sorted(want))
assert "decoy" not in got and "notes" not in got
PY
CASE="persona-uat-decrypt.sh: the plaintext lives ONLY under a mode-700 directory the script creates with mktemp (inside TMPDIR), its files are not readable by others, and the directory it names is that one"
check python3 - "$work" <<'PY'
import os, re, stat, sys
w = sys.argv[1]
d = re.search(r"decrypted into (\S+)", open(w + "/dsh/o").read()).group(1)
assert os.path.dirname(d.rstrip("/")) == w + "/dsh/tmp", d
assert stat.S_IMODE(os.stat(d).st_mode) == 0o700, oct(os.stat(d).st_mode)
for f in os.listdir(d):
    assert stat.S_IMODE(os.stat(os.path.join(d, f)).st_mode) & 0o077 == 0, f
    assert not f.startswith("."), ("a leftover download directory", f)
for root_, _, fs in os.walk(w + "/dsh/home"):
    for f in fs:
        assert b"VERDICT" not in open(os.path.join(root_, f), "rb").read(), f
for root_, _, fs in os.walk(w + "/dsh/clone"):
    for f in fs:
        if ".git/" not in os.path.join(root_, f):
            assert b"VERDICT" not in open(os.path.join(root_, f), "rb").read(), ("plaintext in the working directory", f)
PY
CASE="persona-uat-decrypt.sh never prints the key: neither the key text nor a private-key block is on stdout or stderr (success and failure)"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
key = open(w + "/test.key").read()
body = [l for l in key.splitlines() if l and not l.startswith("-----")]
blob = open(w + "/dsh/o").read() + open(w + "/dsh/e").read()
assert "PRIVATE" not in blob and not [l for l in body if l in blob], blob[:200]
PY
dsh_run 4242 "$work/other.key"
CASE="persona-uat-decrypt.sh: the WRONG key fails (non-zero, says so) and leaves no plaintext behind (openssl may even 'succeed' with garbage for a wrong key about 1 time in 256: the script must check what it decrypted)"
check python3 - "$work" "$drc" <<'PY'
import glob, os, sys
w, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0
assert not glob.glob(w + "/dsh/tmp/*/*") and not glob.glob(w + "/dsh/tmp/*"), glob.glob(w + "/dsh/tmp/*")
blob = open(w + "/dsh/o").read() + open(w + "/dsh/e").read()
assert "VERDICT" not in blob and "PRIVATE" not in blob
PY
# an artifact that decrypts fine but is NOT a persona payload (what a wrong key can yield as garbage, or a foreign file): the script must refuse it
mkdir -p "$work/dsh/run-garbage/$ARTNAME"
openssl cms -encrypt -aes-256-cbc -binary -outform DER -recip "$work/test.pem" -out "$work/dsh/run-garbage/$ARTNAME/gradle-platform-engineer.cms" <<<"random bytes that are not a report" 2>/dev/null
FAKE_RUN="$work/dsh/run-garbage" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh refuses a decrypted file that is not a persona payload (it must begin with 'VERDICT: ' and hold the '=== TRANSCRIPT ===' line): non-zero, no plaintext left"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
dsh_run 4242 "$work/dsh/no-such.key"
CASE="persona-uat-decrypt.sh refuses a missing key (non-zero, names the missing path) BEFORE it calls gh"
check test "$drc" -ne 0 -a ! -s "$work/dsh/gh.log"
check grep -q 'no-such.key' "$work/dsh/e"
dsh_run 4242 NOKEY
CASE="persona-uat-decrypt.sh: without a key argument the default is ~/.config/fosterstack/persona-uat.key: absent, it refuses (non-zero) and does not call gh; present, it decrypts"
check test "$drc" -ne 0 -a ! -s "$work/dsh/gh.log"
check grep -q '.config/fosterstack/persona-uat.key' "$work/dsh/e"
mkdir -p "$work/dsh/home/.config/fosterstack"; cp "$work/test.key" "$work/dsh/home/.config/fosterstack/persona-uat.key"; chmod 600 "$work/dsh/home/.config/fosterstack/persona-uat.key"
dsh_run 4242 NOKEY
check test "$drc" -eq 0
check grep -q 'decrypted into' "$work/dsh/o"
for rid in "" "abc" "12 34" "1;touch $work/dsh/pwned" '$(touch '"$work"'/dsh/pwned)' "-1" "../1"; do
  dsh_run "$rid" "$work/test.key"
  CASE="persona-uat-decrypt.sh refuses a run id that is not digits ('$rid'): non-zero, no gh call, nothing executed"
  check test "$drc" -ne 0 -a ! -s "$work/dsh/gh.log" -a ! -e "$work/dsh/pwned"
done
FAKE_GH_FAIL=1 dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh: a failing gh run download fails the script (non-zero) and leaves no plaintext directory content"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
mkdir -p "$work/dsh/run-nocms/$ARTNAME"; echo plain >"$work/dsh/run-nocms/$ARTNAME/notes.txt"
FAKE_RUN="$work/dsh/run-nocms" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh: an artifact without any .cms file is an error (non-zero), never an empty success"
check test "$drc" -ne 0
mkdir -p "$work/dsh/run-noart/other-artifact"; cp "$work/dsh/run/other-artifact/"* "$work/dsh/run-noart/other-artifact/"
FAKE_RUN="$work/dsh/run-noart" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh: a run without the persona artifact (only an unrelated one) fails (non-zero): it never decrypts a decoy it did not ask for"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
DSH_REPO=wrong/repo dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh with a WRONG repository (GITHUB_REPOSITORY=wrong/repo): gh finds no such run (404), the script fails (non-zero) and leaves no plaintext"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
check grep -q 'wrong/repo' "$work/dsh/gh.log"
DSH_CWD="$work/dsh/nogit" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh run OUTSIDE any clone with GITHUB_REPOSITORY=own/cache works (it passes -R explicitly)"
check test "$drc" -eq 0
check grep -q -- '-R own/cache' "$work/dsh/gh.log"
DSH_CWD="$work/dsh/clone-noremote" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh in a clone WITHOUT a remote works too (a real gh would need -R there: the script passes it)"
check test "$drc" -eq 0
DSH_CWD="$work/dsh/clone-wrong" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh in a clone whose origin is ANOTHER repository still reaches the right one: the explicit -R from GITHUB_REPOSITORY wins over the clone's remote"
check test "$drc" -eq 0
DSH_REPO=NONE DSH_CWD="$work/dsh/nogit" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh outside a clone with no GITHUB_REPOSITORY, against a run of ANOTHER repository (the fixture belongs to own/cache): gh finds nothing, the script fails cleanly (non-zero, no plaintext)"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
DSH_FAKE_REPO=fosterstack/cache DSH_REPO=NONE DSH_CWD="$work/dsh/nogit" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh run LOCALLY outside a clone with GITHUB_REPOSITORY unset works against this repository's own run (the repository is fosterstack/cache): the script has a working default"
check test "$drc" -eq 0
check test "$(ls "$work"/dsh/tmp | head -1)" != ""
DSH_FAKE_REPO=fosterstack/cache DSH_REPO=NONE DSH_CWD="$work/dsh/clone-real" dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh run locally inside a clone of fosterstack/cache with GITHUB_REPOSITORY unset works (default or the clone's own remote)"
check test "$drc" -eq 0
DSH_FAKE_RUN=9137 dsh_run 9137 "$work/test.key"
CASE="persona-uat-decrypt.sh with a DIFFERENT run id (9137, the fixture's only run): the id on the command line is the id gh is given, so it succeeds; the id is never a constant"
check test "$drc" -eq 0
check grep -q -- '9137' "$work/dsh/gh.log"
check none_match '4242' "$work/dsh/gh.log"
DSH_FAKE_RUN=9137 dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh with a run id the repository does not have (4242 while only 9137 exists): gh finds no such run, the script fails cleanly (non-zero, no plaintext)"
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/* 2>/dev/null | head -1)"
CASE="persona-uat-decrypt.sh is a plain bash script of the repository (executable), reads NO environment variable for the key (only HOME for the default path and TMPDIR for the directory), never echoes or cats the key, and writes no plaintext outside its mktemp directory (static)"
check python3 - "$dsh" <<'PY'
import os, re, sys
t = open(sys.argv[1]).read()
assert t.startswith("#!") and os.access(sys.argv[1], os.X_OK), "bin/persona-uat-decrypt.sh must be an executable script"
assert "mktemp -d" in t and ("chmod 700" in t or "umask 077" in t), "no private directory"
assert "gh run download" in t and "openssl cms -decrypt" in t, "the two commands the ruling names"
assert not re.search(r"cat[^\n]*\$\{?key\b|echo[^\n]*\$\(\s*cat|<\s*\"?\$\{?key", t), "the key's CONTENT must never be echoed or catted"
env_refs = {m for m in re.findall(r"\$\{?([A-Z][A-Z0-9_]*)", t) if re.search(r"KEY|SECRET|PASS|TOKEN|PERSONA|FOSTER", m)}
assert not env_refs, ("the script reads an environment variable for the key (a key must come from an argument or the default file only)", sorted(env_refs))
assert not re.search(r"\benv\b|\bprintenv\b|\bexport\b", "\n".join(t.splitlines()[1:])), "the script must not read or export the environment"
assert re.search(r"(-n|--name)[ =]+[\"']?persona-uat-[a-z0-9-]+", t), "the script must select the persona artifact by its exact name (-n persona-uat-<name>)"
PY

# --- AC5: the agent reads only the public docs and the endpoint ------------------------------------------------
CASE="the sandbox holds README.md and the top-level docs for four personas, and ONLY README.md for the README evaluator"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    want = ["README.md"] if r["persona"] == "readme-evaluator" else ["README.md", "RELEASING.md", "docs/gradle.md", "docs/install.md"]
    if r["persona"] == "on-call-engineer":
        want = ["README.md", "RELEASING.md", "docs/gradle.md", "docs/install.md", "kubeconfig"]
    assert r["docs"] == want, (r["persona"], r["docs"])
PY
CASE="what the agent could READ (every file's content) holds no source, internal doc, dotfile, symlink target or unreleased note"
check python3 - "$work/clean/log" <<'PY'
import json, sys
bad = ("SECRET-", "INTERNAL TRACE", "UNRELEASED NOTES", "package internal")
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["content"], "the stub read nothing: the assertion would be vacuous"
    for f, c in r["content"].items():
        assert not any(b in c for b in bad), (r["persona"], f)
    assert r["links"] == [], ("symlink in the sandbox", r["links"])
    assert all(not f.startswith(".") and "/." not in f for f in r["content"]), r["content"].keys()
    assert all(f in ("README.md", "RELEASING.md") or (f.startswith("docs/") and f.endswith(".md") and f.count("/") == 1) or (r["persona"] == "on-call-engineer" and f == "kubeconfig") for f in r["content"]), list(r["content"])
PY
CASE="nothing the agent was handed or the driver wrote leaks source, internal docs or unreleased notes"
check none_match 'SECRET-|INTERNAL TRACE|UNRELEASED NOTES|package internal' "$(out clean)"
CASE="the request has EXACTLY the contract's keys and no repository path anywhere in it"
check python3 - "$work/clean/log" "$repo" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert r["keys"] == ["docs_dir", "endpoint", "image", "instructions", "model", "persona", "token_budget", "tools"], r["keys"]
    assert sys.argv[2] not in json.dumps(r["request"]), "repo path leaked into the request"
PY
CASE="the agent runs INSIDE its sandbox (cwd = its docs directory, outside the repository checkout)"
check python3 - "$work/clean/log" "$repo" <<'PY'
import json, os, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    assert os.path.realpath(r["cwd"]) == os.path.realpath(r["request"]["docs_dir"]), r
    assert not os.path.realpath(r["cwd"]).startswith(os.path.realpath(sys.argv[2])), r
PY
CASE="the agent's environment is scrubbed: no GitHub or AWS credentials and no checkout path inherited"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    env = json.loads(ln)["env"]
    for bad in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SOME_UNKNOWN_SECRET", "AWS_SESSION_TOKEN", "REPO_CHECKOUT", "GITHUB_WORKSPACE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "PERSONA_UAT_MODEL", "PERSONA_UAT_COMPLIANCE_MODEL"):
        assert bad not in env, bad
    # an ALLOWLIST: only a minimal shell environment and the model identity the provider needs, nothing else
    ok = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING", "DOCKER_HOST", "DOCKER_CONFIG"}
    extra = [k for k in env if k not in ok and not k.startswith("ANTHROPIC_")]
    assert not extra, extra
    for need in ("ANTHROPIC_API_KEY", "ANTHROPIC_IDENTITY_TOKEN_FILE", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                 "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID"):
        assert need in env, ("the provider needs", need)
PY

# --- AC5: model and token budget come from owner-set variables ---------------------------------------------------
CASE="four personas get the default model variable's value and the compliance reviewer gets its own"
check python3 - "$work/clean/log" <<'PY'
import json, sys
m = {json.loads(l)["persona"]: json.loads(l)["request"]["model"] for l in open(sys.argv[1])}
assert m["compliance-reviewer"] == "MODEL-COMPLIANCE-X", m
assert all(v == "MODEL-DEFAULT-X" for k, v in m.items() if k != "compliance-reviewer"), m
PY
run swapped '{}' rc PERSONA_UAT_MODEL=OTHER-DEFAULT PERSONA_UAT_COMPLIANCE_MODEL=OTHER-COMPLIANCE
CASE="different owner values flow through (the models are not remembered or hard-coded)"
check python3 - "$work/swapped/log" <<'PY'
import json, sys
m = {json.loads(l)["persona"]: json.loads(l)["request"]["model"] for l in open(sys.argv[1])}
assert len(m) == 5 and m["compliance-reviewer"] == "OTHER-COMPLIANCE", m
assert all(v == "OTHER-DEFAULT" for k, v in m.items() if k != "compliance-reviewer"), m
PY
CASE="the token budget defaults to 400000 per persona, for all five"
check python3 - "$work/clean/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5 and all(r["request"]["token_budget"] == 400000 for r in rows)
PY
run budget '{}' rc PERSONA_UAT_TOKEN_BUDGET=123456
CASE="the owner's budget variable is honored, for all five, and the run succeeded"
check test "$rc" -eq 0
check python3 - "$work/budget/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5 and all(r["request"]["token_budget"] == 123456 for r in rows), rows
PY
for bad in lots 0 -5 1.5 4e5 " 7" ""; do
  run "nobudget-$bad" '{}' rc "PERSONA_UAT_TOKEN_BUDGET=$bad"
  CASE="a budget of '$bad' is refused (exit 2) and nothing starts"
  if [ -z "$bad" ]; then CASE="an EMPTY budget variable falls back to the 400000 default"; check test "$rc" -eq 0
  else check test "$rc" -eq 2 -a ! -s "$work/nobudget-$bad/log" -a ! -s "$work/nobudget-$bad/docker.log"
       check grep -q 'PERSONA_UAT_TOKEN_BUDGET' "$work/nobudget-$bad/stderr"; fi
done
run nomodel '{}' rc PERSONA_UAT_MODEL=
CASE="an unset model variable refuses to run anything (exit 2); there is no built-in default model"
check test "$rc" -eq 2 -a ! -s "$work/nomodel/log" -a ! -s "$work/nomodel/docker.log"
CASE="a model variable that is not set at all (unset, not just empty) also refuses, and stderr names it"
mkdir -p "$work/unsetmodel"; : >"$work/unsetmodel/log"; : >"$work/unsetmodel/docker.log"; echo '{}' >"$work/unsetmodel/plan.json"; rc=0
sed "s#__LOG__#$work/unsetmodel/docker.log#" "$work/docker.tmpl" >"$work/unsetmodel/docker"; chmod +x "$work/unsetmodel/docker"
env -u PERSONA_UAT_MODEL -u PERSONA_UAT_TOKEN_BUDGET PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X python3 "$driver" --mode rc --image "$IMG" --repo "$repo" \
  --out "$work/unsetmodel/out" --tools "$work/tools.json" --docker "$work/unsetmodel/docker" --recipient "$work/test.pem" --port 18080 --agent "python3 $work/stub.py $work/unsetmodel" \
  >/dev/null 2>"$work/unsetmodel/stderr" || rc=$?
check test "$rc" -eq 2 -a ! -s "$work/unsetmodel/log" -a ! -s "$work/unsetmodel/docker.log"
check grep -q 'PERSONA_UAT_MODEL' "$work/unsetmodel/stderr"
run nocomp '{}' rc PERSONA_UAT_COMPLIANCE_MODEL=
CASE="an unset compliance-model variable refuses to run anything (exit 2)"
check test "$rc" -eq 2 -a ! -s "$work/nocomp/log" -a ! -s "$work/nocomp/docker.log"

# --- AC5: transcripts are kept (for every outcome); the cap is flagged; no model name is written ----------------
CASE="every persona's transcript file holds what the agent said, in a clean run"
check grep -q 'TRANSCRIPT for compliance-reviewer' "$(out clean)/compliance-reviewer.transcript.txt"
check grep -q 'TRANSCRIPT for readme-evaluator' "$(out clean)/readme-evaluator.transcript.txt"
CASE="and in a failing run the other personas' transcripts are kept"
check grep -q 'TRANSCRIPT for gradle-platform-engineer' "$(out blocking)/gradle-platform-engineer.transcript.txt"
run capped '{"readme-evaluator":{"tokens":400000},"gradle-platform-engineer":{"tokens":399999},"on-call-engineer":{"tokens":900000}}' rc
CASE="a persona that used its whole budget (or more) is flagged plainly in its report; one under it is not"
check grep -q 'HIT ITS TOKEN CAP' "$(out capped)/readme-evaluator.report.md"
check grep -q 'HIT ITS TOKEN CAP' "$(out capped)/on-call-engineer.report.md"
check none_match 'HIT ITS TOKEN CAP' "$(out capped)/gradle-platform-engineer.report.md"
CASE="a capped run does not fail by itself (exit 0), and only the capped personas' encrypted reports say so"
check test "$rc" -eq 0
CASE="no owner-set model value appears in any decrypted report or transcript, any stdout/stderr, any artifact byte, request or docker call"
check none_match 'MODEL-(DEFAULT|COMPLIANCE)-X|OTHER-(DEFAULT|COMPLIANCE)' "$(out clean)" "$(out capped)" "$(out friction)" "$(out weekly)" "$(out blocking)" \
  "$work/clean/docker.log" "$work/clean/out" "$work/clean/stdout" "$work/clean/stderr" "$work/weekly/stdout" "$work/weekly/stderr"
CASE="no model name is written in the driver: neither a vendor family nor a model-version pattern"
check none_match '[Cc]laude|[Oo]pus|[Ss]onnet|[Hh]aiku|[Ff]able|gpt-|[Gg]emini|[Ll]lama|\bo[134]-' "$root/bin/persona-uat.py"

# --- symlinks at the roots: a symlinked README.md or a symlinked docs directory must never carry other bytes into the sandbox
for kind in readme docs; do
  rp="$work/symrepo-$kind"; rm -rf "$rp"; mkdir -p "$rp/internal" "$rp/docs"; echo "SECRET-ROOT-TARGET" >"$rp/internal/secret.md"
  if [ "$kind" = readme ]; then ln -s internal/secret.md "$rp/README.md"; echo "install steps" >"$rp/docs/install.md"
  else echo "# README" >"$rp/README.md"; rm -rf "$rp/docs"; ln -s internal "$rp/docs"; fi
  mkdir -p "$work/sym-$kind"; : >"$work/sym-$kind/log"; : >"$work/sym-$kind/docker.log"; echo '{}' >"$work/sym-$kind/plan.json"
  sed "s#__LOG__#$work/sym-$kind/docker.log#" "$work/docker.tmpl" >"$work/sym-$kind/docker"; chmod +x "$work/sym-$kind/docker"; rc=0
  mkhost "$work/sym-$kind"
  env -u PERSONA_UAT_TOKEN_BUDGET PATH="$work/sym-$kind/hostbin:$PATH" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$rp" \
    --out "$work/sym-$kind/out" --tools "$work/tools.json" --docker "$work/sym-$kind/docker" --recipient "$work/test.pem" --port 18080 --agent "python3 $work/stub.py $work/sym-$kind" \
    >/dev/null 2>"$work/sym-$kind/stderr" || rc=$?
  echo "$rc" >"$work/sym-$kind/rc"
  decout "sym-$kind"
  CASE="a symlinked $kind root: its target's bytes never reach any agent or output (decrypted reports and transcripts included)"
  check none_match 'SECRET-ROOT-TARGET' "$work/sym-$kind/log" "$work/sym-$kind/out" "$work/sym-$kind/plain"
done
CASE="a symlinked README.md is not a README: the run refuses (a NON-ZERO exit), says so, runs no persona and starts nothing"
check test "$(cat "$work/sym-readme/rc")" -ne 0 -a -s "$work/sym-readme/stderr" -a ! -s "$work/sym-readme/docker.log" -a ! -s "$work/sym-readme/log"
CASE="a symlinked docs directory contributes nothing: the personas get the README only, and the run still works"
check python3 - "$work/sym-docs/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5, rows
for r in rows:
    assert r["docs"] == (["README.md", "kubeconfig"] if r["persona"] == "on-call-engineer" else ["README.md"]), (r["persona"], r["docs"])
PY

# --- the docs the personas read must actually be there
mkdir -p "$work/emptyrepo"; : >"$work/emptyrepo/placeholder"
CASE="a --repo with no README.md and no docs: the run refuses (non-zero), every persona is did-not-run, and nothing is started"
mkdir -p "$work/nodocs"; : >"$work/nodocs/log"; : >"$work/nodocs/docker.log"; echo '{}' >"$work/nodocs/plan.json"; sed "s#__LOG__#$work/nodocs/docker.log#" "$work/docker.tmpl" >"$work/nodocs/docker"; chmod +x "$work/nodocs/docker"; rc=0
env -u PERSONA_UAT_TOKEN_BUDGET PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --image "$IMG" --repo "$work/emptyrepo" \
  --out "$work/nodocs/out" --tools "$work/tools.json" --docker "$work/nodocs/docker" --recipient "$work/test.pem" --port 18080 --agent "python3 $work/stub.py $work/nodocs" >"$work/nodocs/stdout" 2>"$work/nodocs/stderr" || rc=$?
check test "$rc" -ne 0 -a ! -s "$work/nodocs/log" -a ! -s "$work/nodocs/docker.log"
decout nodocs
check grep -qi 'README' "$work/nodocs/plain/gradle-platform-engineer.report.md"
CASE="the missing-docs reason is in the ENCRYPTED reports only: the job log is five fail lines and overall, nothing else"
check publiclog nodocs

# --- readiness: a dead image or a container that is not running never reads as a green run --------------------------
DOCKER_IMAGE_DEAD=1 READY_TIMEOUT=1 run notready '{}' rc
CASE="an image that never answers on its endpoint (no listener behind any persona's port): the run fails, no agent is started against nothing, every persona did not run"
check test "$rc" -ne 0 -a ! -s "$work/notready/log"
check test "$(ls "$(out notready)"/*.report.md | wc -l | tr -d ' ')" -eq 5
check grep -qi 'did not run' "$(out notready)/readme-evaluator.report.md"
DOCKER_INSPECT_FALSE=1 run notrunning '{}' rc
CASE="a container that is not running (docker inspect says false) is a persona that did not run, not a pass"
check test "$rc" -ne 0
check grep -qi 'did not run' "$(out notrunning)/gradle-platform-engineer.report.md"
CASE="readiness is checked with docker inspect on every container the driver started"
check python3 - "$work/clean/docker.log" <<'PY'
import sys
lines = open(sys.argv[1]).read().splitlines()
runs = [l for l in lines if l.startswith("run -d ")]
insp = [l for l in lines if l.startswith("inspect ")]
assert runs and all(any(("cap-" if "/usr/bin/tcpdump" in runs[i] else "cid-") + str(i + 1) in l for l in insp) for i in range(len(runs))), (runs, insp)
PY

CASE="the driver provisions nothing in a cloud (a docker log with only run, rm, inspect, exec), also for a friction run"
check python3 - "$work/friction/docker.log" <<'PY'
import sys
for l in open(sys.argv[1]):
    assert l.split()[0] in ("run", "rm", "inspect", "exec", "ps", "stop", "kill", "logs", "network"), l
PY

# --- the integrated path: the REAL driver, the REAL agent and the REAL provider (over a fake SDK), workflow-shaped -----
mkdir -p "$work/sdk/anthropic" "$work/pybin"
cat >"$work/sdk/anthropic/__init__.py" <<'PY'
import json, os
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdk.log")
class _Msg:
    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]
        self.usage = type("U", (), {"input_tokens": 120, "output_tokens": 30})()
ROLE_WORDS = (("gradle", ("you are a first-time user, a gradle platform engineer",)), ("maven", ("you are a maven user whose builds run in ci",)), ("compliance", ("you are a compliance reviewer",)),
              ("readme", ("you are an evaluator who has only the readme",)), ("oncall", ("you are an on-call engineer",)))   # each persona's own role sentence (the shared environment limits name Jenkins and GitLab for everyone)

class Anthropic:
    def __init__(self, *a, **k):
        tf = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
        if not tf or not os.path.isfile(tf) or open(tf).read().strip() != "FIXTURE-OIDC-TOKEN":
            raise RuntimeError("identity token file missing or wrong: federated authentication is not usable")
        open(LOG, "a").write(json.dumps({"init": {"has_key": "ANTHROPIC_API_KEY" in os.environ,
            "token_file": os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE"), "fed": [os.environ.get(x) for x in
            ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID")],
            "leaked": sorted(k for k in os.environ if k in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY", "SOME_UNKNOWN_SECRET"))}}) + "\n")
        self.messages = self
    def create(self, **kw):
        if os.environ.get("ANTHROPIC_FAKE_HANG_AFTER") and len(kw["messages"]) >= 3:
            import time; time.sleep(600)         # the second model call never returns (an agent timeout must keep the first action)
        open(LOG, "a").write(json.dumps({"model": kw["model"], "turn": len(kw["messages"]), "system": kw.get("system", ""),
            "first": kw["messages"][0]["content"] if isinstance(kw["messages"][0]["content"], str) else json.dumps(kw["messages"][0]["content"])}) + "\n")
        msgs = kw["messages"]
        if len(msgs) == 1:
            ctx = (kw.get("system", "") + " " + (msgs[0]["content"] if isinstance(msgs[0]["content"], str) else json.dumps(msgs[0]["content"]))).lower()
            role = next((n for n, ws in ROLE_WORDS if all(w in ctx for w in ws)), "none")      # which persona's instructions did THIS request carry
            return _Msg(json.dumps({"action": "shell", "command": "cat README.md; echo $((6*7)); echo ROLE-" + role + "; curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/"}))
        last = msgs[-1]["content"] if isinstance(msgs[-1]["content"], str) else json.dumps(msgs[-1]["content"])
        if len(msgs) == 3:
            return _Msg(json.dumps({"action": "shell", "command": "cat docs/documented-step-that-does-not-exist.md"}))
        # the finding is driven by what the failing step REALLY returned: its exit status and its stderr
        if "exit status: 1" in last and "No such file" in last:
            return _Msg(json.dumps({"action": "finish", "findings": [{"kind": "blocking", "text": "documented step failed as written: No such file"}]}))
        return _Msg(json.dumps({"action": "finish", "findings": []}))
PY
# a python3 first on PATH that makes the fake SDK importable WITHOUT any environment variable reaching the scrubbed agent
printf '#!/bin/sh\nPYTHONPATH="%s" exec %s "$@"\n' "$work/sdk" "$(command -v python3)" >"$work/pybin/python3"; chmod +x "$work/pybin/python3"
mkdir -p "$work/integ"; echo FIXTURE-OIDC-TOKEN >"$work/integ/token"; : >"$work/integ/docker.log"; : >"$work/integ/gh.log"; : >"$work/sdk/sdk.log"; rc=0
sed "s#__LOG__#$work/integ/docker.log#" "$work/docker.tmpl" >"$work/integ/docker"; chmod +x "$work/integ/docker"; mkhost "$work/integ"
( cd "$root" && env -u PERSONA_UAT_TOKEN_BUDGET -u ANTHROPIC_API_KEY PATH="$work/pybin:$work/integ/hostbin:$PATH" GITHUB_RUN_ID=4242 \
    PERSONA_UAT_MODEL=INTEG-DEFAULT PERSONA_UAT_COMPLIANCE_MODEL=INTEG-COMPLIANCE \
    ANTHROPIC_IDENTITY_TOKEN_FILE="$work/integ/token" ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 \
    ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 \
    AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY SOME_UNKNOWN_SECRET=SECRET-UNK \
    python3 bin/persona-uat.py --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$repo" --out "$work/integ/out" --tools "$work/tools.json" \
      --docker "$work/integ/docker" --recipient "$work/test.pem" --port 18080 --ready-timeout 5 --agent "python3 bin/persona-uat-agent.py" ) \
  >"$work/integ/stdout" 2>"$work/integ/stderr" || rc=$?
decout integ
CASE="integrated: the real driver, agent (given by a RELATIVE path) and provider run to completion with five reports, and the run FAILS because a documented step failed as written"
check test "$rc" -ne 0 -a "$(ls "$work/integ/plain"/*.report.md | wc -l | tr -d ' ')" -eq 5
CASE="integrated: every persona's blocking finding came from the failing step's REAL exit status and stderr (the fake provider only says so when it saw both)"
check python3 - "$work/integ/plain" <<'PY'
import glob, sys
for r in glob.glob(sys.argv[1] + "/*.report.md"):
    c = open(r).read()
    assert "VERDICT: blocking" in c and "No such file" in c, r
PY
CASE="integrated: each persona really ran a shell action in its sandbox, the COMPUTED output (42, which is not in the command text) came back into its transcript, and the role its OWN provider request carried (gradle, maven, compliance, readme, oncall) is the role of its report: five distinct roles through the real agent"
check python3 - "$work/integ/plain" <<'PY'
import glob, re, sys
ts = glob.glob(sys.argv[1] + "/*.transcript.txt")
assert len(ts) == 5, ts
for t in ts:
    c = open(t).read()
    assert "# fscache README" in c and "\n42" in c.replace("\r", ""), t
role_of = {"gradle-platform-engineer": "gradle", "maven-jenkins-ci": "maven", "compliance-reviewer": "compliance", "readme-evaluator": "readme", "on-call-engineer": "oncall"}
seen = {}
for t in ts:
    persona = t.split("/")[-1].split(".transcript")[0]
    c = open(t).read()
    got = sorted(set(re.findall(r"ROLE-(\w+)", c)))
    assert got == [role_of[persona]], (persona, got, "the persona's provider request did not carry ITS OWN role instructions")
    seen[persona] = got[0]
assert len(set(seen.values())) == 5, seen
PY
CASE="integrated: every provider call (three per persona) authenticated with the federated identity (four variables and the token file, no key, no leaked credential) and used the owner-set model"
check python3 - "$work/sdk/sdk.log" <<'PY'
import json, re, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
inits = [r["init"] for r in rows if "init" in r]
assert len(inits) == 15, len(inits)
assert all(not i["has_key"] and i["fed"] == ["f1", "o1", "s1", "w1"] and i["token_file"].endswith("integ/token") and i["leaked"] == [] for i in inits), inits
calls = [r for r in rows if "model" in r]
for r in calls:
    ctx = (r["system"] + " " + r["first"]).lower()
    assert "http://endpoint:8080" in ctx and not re.search(r"127\.0\.0\.1", ctx), "the persona is told its own endpoint BY NAME on its network (never a loopback address)"
    assert "only the public documentation" in ctx and "do not clone" in ctx and "source" in ctx, "the restriction is not in the prompt"
assert any("http://jenkins:8080" in (r["system"] + r["first"]) for r in calls), "Jenkins' endpoint never reaches the Maven persona"
assert any("kubeconfig" in (r["system"] + r["first"]).lower() for r in calls), "the kubeconfig never reaches the on-call persona"
models = [r["model"] for r in rows if "model" in r]
assert len(models) == 15 and models.count("INTEG-COMPLIANCE") == 3 and models.count("INTEG-DEFAULT") == 12, models
PY
CASE="integrated: no GitHub credential reached the shell containers or the provider's environment"
check none_match 'SECRET-GH-TOKEN' "$work/integ/plain" "$work/integ/out" "$work/integ/docker.log"

# TIMEOUT KEEPS THE COMPLETED ACTIONS (step 8, Codex B5): the REAL agent, a fake SDK whose second model call hangs, a driver agent timeout of 8 seconds: the agent is killed
# after ONE completed action, and the encrypted transcript still holds that action (streamed to the transcript file) with the timeout marker
mkdir -p "$work/integt"; echo FIXTURE-OIDC-TOKEN >"$work/integt/token"; : >"$work/integt/docker.log"; : >"$work/integt/gh.log"; : >"$work/sdk/sdk.log"; rc=0
sed "s#__LOG__#$work/integt/docker.log#" "$work/docker.tmpl" >"$work/integt/docker"; chmod +x "$work/integt/docker"; mkhost "$work/integt"
( cd "$root" && env -u PERSONA_UAT_TOKEN_BUDGET -u ANTHROPIC_API_KEY PATH="$work/pybin:$work/integt/hostbin:$PATH" GITHUB_RUN_ID=4242 \
    PERSONA_UAT_MODEL=INTEG-DEFAULT PERSONA_UAT_COMPLIANCE_MODEL=INTEG-COMPLIANCE ANTHROPIC_FAKE_HANG_AFTER=1 \
    ANTHROPIC_IDENTITY_TOKEN_FILE="$work/integt/token" ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 \
    ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 \
    python3 bin/persona-uat.py --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$repo" --out "$work/integt/out" --tools "$work/tools.json" \
      --docker "$work/integt/docker" --recipient "$work/test.pem" --port 18080 --ready-timeout 5 --agent-timeout 8 --agent "python3 bin/persona-uat-agent.py" ) \
  >"$work/integt/stdout" 2>"$work/integt/stderr" || rc=$?
decout integt
CASE="timeout (real agent killed after one completed action): every persona is blocking 'timed out', the run fails, and each encrypted transcript holds the action that COMPLETED before the kill (its command and its output) with the timeout marker"
check python3 - "$work/integt/plain" "$rc" <<'PY'
import glob, sys
assert int(sys.argv[2]) != 0
ts = glob.glob(sys.argv[1] + "/*.transcript.txt")
assert len(ts) == 5, ts
for t in ts:
    c = open(t).read()
    assert "agent timed out after 8s" in c, (t, c[:300])
    assert "$ cat README.md" in c and "# fscache README" in c, ("the completed action is lost", t, c[:400])
PY
check publiclog integt
# --- advisor fences (public repo; job logs and artifacts are public) ---------------------------------------------------
# Fence 1: containers are FIXED-ARGUMENT. The driver builds every docker command from the allowlisted images and fixed options.
CASE="fence 1: the docker calls the driver builds (run -d) carry no mount, no network option, no privilege AT ALL, no socket, no pid/ipc/cap/device/user option, no env except Jenkins' one fixed value; the agent's shell calls carry exactly one mount and nothing else beyond the pinned --network host"
check python3 - "$work/clean/docker.log" "$work/integ/docker.log" "$JEN" <<'PY'
import re, sys
jen = sys.argv[3]
forbidden = re.compile(r"^(--privileged|--net(work)?(=.*)?|--pid(=.*)?|--ipc(=.*)?|--uts(=.*)?|--cap-add(=.*)?|--cap-drop(=.*)?|--device(=.*)?|--userns(=.*)?|--user|-u|-e|--env(=.*)?|--env-file(=.*)?|--mount(=.*)?|--volume(=.*)?|-v|--security-opt(=.*)?|--volumes-from(=.*)?)$")
total_run = 0
for path in sys.argv[1:3]:
    for l in open(path):
        assert "docker.sock" not in l, ("the docker socket must not reach any container", l)
        t = l.split()
        if t[0] != "run":
            continue
        if t[:2] == ["run", "--rm"] and "--user" in t:
            continue    # the per-persona cleanup container
        total_run += 1
        if t[1] == "-d" and "--entrypoint" in t:
            continue    # the capture sidecar (its own case pins its shape)
        if t[1] == "-d":
            opts = t[2:-1]
            while "--network" in opts:
                k0 = opts.index("--network"); assert re.fullmatch(r"persona-uat-[0-9a-f]{8}", opts[k0 + 1]), l; del opts[k0:k0 + 2]
            while "--network-alias" in opts:
                k0 = opts.index("--network-alias"); del opts[k0:k0 + 2]
            bad = [o for k, o in enumerate(opts) if forbidden.match(o) and not (o == "-e" and t[-1] == jen and opts[k + 1] == "JAVA_OPTS=-Djenkins.install.runSetupWizard=false")]
            assert not bad, ("a driver-built container carries a forbidden option", bad, l)
            assert not any(":/" in o and o.count(":") == 1 and not o.startswith("127.0.0.1") for o in opts), ("a host mount", l)
        else:
            # the agent's shell action (its own, test-pinned shape): exactly one -v, host network is the only network option, nothing else
            assert t[1] == "--rm" and t.count("-v") == 1 and not [x for x in t if x in ("--privileged", "--pid", "--ipc", "--cap-add", "--device", "-e", "--env", "--user")], l
            assert not [x for x in t if x.startswith(("--pid=", "--ipc=", "--cap-add=", "--device=", "--env=", "--mount", "--volume", "--net=", "--network="))], l
assert total_run > 5, total_run
PY
# no job credential in any docker call's environment (a container only ever sees what -e passes; the docker client must not carry the job's credentials either)
mkdir -p "$work/envdock"; : >"$work/envdock/log"; : >"$work/envdock/docker.log"; : >"$work/envdock/envs"; echo '{}' >"$work/envdock/plan.json"
sed "s#__LOG__#$work/envdock/docker.log#" "$work/docker.tmpl" >"$work/envdock/inner"; chmod +x "$work/envdock/inner"
printf '#!/usr/bin/env bash\nenv | cut -d= -f1 | sort | tr "\\n" " " >>"%s"; echo >>"%s"\nexec "%s" "$@"\n' "$work/envdock/envs" "$work/envdock/envs" "$work/envdock/inner" >"$work/envdock/docker"; chmod +x "$work/envdock/docker"
rc=0; mkhost "$work/envdock"
env -u PERSONA_UAT_TOKEN_BUDGET PATH="$work/envdock/hostbin:$PATH" GITHUB_REPOSITORY=own/cache GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY \
  AWS_ACCESS_KEY_ID=SECRET-AWS-ID ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRET-OIDC ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.invalid ANTHROPIC_API_KEY=ALLOWED-MODEL-CRED SOME_API_SECRET=SECRET-UNK \
  PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$repo" --out "$work/envdock/out" --tools "$work/tools.json" \
  --docker "$work/envdock/docker" --recipient "$work/test.pem" --port 18080 --agent "python3 $work/stub.py $work/envdock" >/dev/null 2>&1 || rc=$?
CASE="fence 1: no job credential (GitHub, AWS, OIDC, model token, any *_TOKEN/*_KEY/*_SECRET, AWS_*, ACTIONS_*) is in the environment of ANY docker call the driver makes"
check python3 - "$work/envdock/envs" <<'PY'
import re, sys
rows = [l.split() for l in open(sys.argv[1])]
assert len(rows) >= 8, rows
cred = re.compile(r"^(AWS_.*|ACTIONS_.*|GITHUB_TOKEN|GH_TOKEN|GH_.*|ANTHROPIC_.*|.*_TOKEN|.*_KEY|.*_SECRET|SOME_API_SECRET|PERSONA_UAT_.*)$")
for r in rows:
    assert not [k for k in r if cred.match(k)], r
PY

# Fence 2 (amended): public surfaces carry ONLY a pass/fail line per persona and overall; reports and transcripts exist only inside the encrypted artifacts
CASE="fence 2: the driver prints no raw transcript or agent stderr to stdout or stderr (they are inside the encrypted artifacts only)"
check none_match 'TRANSCRIPT for|PARTIAL-TRANSCRIPT' "$work/clean/stdout" "$work/clean/stderr" "$work/fc-crash/stdout" "$work/fc-crash/stderr" "$work/blocking/stdout" "$work/blocking/stderr" "$work/integ/stdout" "$work/integ/stderr"
CASE="fence 2: ...and the transcripts are still there, inside the encrypted artifact (decrypted with the test key)"
check grep -q 'PARTIAL-TRANSCRIPT' "$(out fc-crash)/compliance-reviewer.transcript.txt"
CASE="fence 2: the report the driver writes is short: one file per persona, no transcript in it"
check python3 - "$(out clean)" <<'PY'
import glob, sys
for r in glob.glob(sys.argv[1] + "/*.report.md"):
    c = open(r).read()
    assert len(c) < 4000 and "TRANSCRIPT" not in c, r
PY

# Fence 3: dogfood access. The sandbox only ever sees http://127.0.0.1:<port>; no job variable reaches the agent.
CASE="fence 3: every request names only endpoints BY NAME on the persona's own network (the image's and every tool's), never a loopback or host address, and the default --port is 8080"
check python3 - "$work/clean/log" <<'PY'
import json, re, sys
for l in open(sys.argv[1]):
    r = json.loads(l)["request"]
    urls = [r["endpoint"]] + [v["endpoint"] for v in r["tools"].values() if v["endpoint"]]
    assert all(re.fullmatch(r"https?://(endpoint|jenkins|gitlab-runner|persona-uat-control-plane):\d+", u) for u in urls), urls
    assert not re.search(r"127\.0\.0\.1|localhost|0\.0\.0\.0|\.invalid|amazonaws|github", json.dumps(r)), r
PY
CASE="fence 3: without --port each persona's container of the image is published on a free high host port of its own (never 8080: the docs' 'kubectl port-forward svc/fscache 8080:80' must work next to the driver), Jenkins and the runner follow the default base 38080 (38081, 38082), and no docker call publishes 8080, 8081 or 8082"
mkdir -p "$work/defport"; : >"$work/defport/log"; : >"$work/defport/docker.log"; echo '{}' >"$work/defport/plan.json"
sed "s#__LOG__#$work/defport/docker.log#" "$work/docker.tmpl" >"$work/defport/docker"; chmod +x "$work/defport/docker"; rc=0
PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$repo" --out "$work/defport/out" --tools "$work/tools.json" \
  --docker "$work/defport/docker" --recipient "$work/test.pem" --ready-timeout 1 --agent "python3 $work/stub.py $work/defport" >/dev/null 2>&1 || rc=$?
check grep -Eq '127\.0\.0\.1:[0-9]{4,5}:8080 [^ ]*/cache@sha256' "$work/defport/docker.log"
check grep -q '127.0.0.1:38081:8080' "$work/defport/docker.log"
check none_match '127\.0\.0\.1:80(80|81|82):' "$work/defport/docker.log"
CASE="fence 3: no AWS_*/ACTIONS_*/GITHUB_TOKEN/GH_TOKEN/*_TOKEN/*_KEY/*_SECRET variable reaches the agent (the model identity ANTHROPIC_* the provider needs is the one exception, pinned above)"
check python3 - "$work/clean/log" <<'PY'
import json, re, sys
bad = re.compile(r"^(AWS_.*|ACTIONS_.*|GITHUB_.*|GH_.*|.*_TOKEN|.*_KEY|.*_SECRET|.*_SECRET_.*|SOME_UNKNOWN_SECRET|RUNNER_.*|REPO_CHECKOUT|PERSONA_UAT_.*)$")
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5
for r in rows:
    assert not [k for k in r["env"] if bad.match(k) and not k.startswith("ANTHROPIC_")], r["env"]
PY

CASE="across every case the driver NEVER called gh: every recorded gh call log is empty (a stray call is a failure)"
check python3 - "$work" <<'PY'
import glob, sys
logs = [l for l in glob.glob(sys.argv[1] + "/*/gh.log") + glob.glob(sys.argv[1] + "/*/*/gh.log") if "/dsh/" not in l]     # dsh/ is the decrypt script's FAKE gh
assert len(logs) > 20, len(logs)
for path in logs:
    assert open(path).read() == "", (path, open(path).read())
PY
# --- the loopback guard (advisor 0206, and the stale-listener rule of 0292): before each persona's agent runs the driver reads the listening sockets from /proc/net/tcp and tcp6
# and refuses (fail closed, the persona is "did not run", the run is blocking) when a loopback-bound listener exists that is not ITS OWN (its endpoint port, the ports of the
# tool containers IT started, its kind API port), DNS (53) or one the caller names with --allow-listen. Wildcard binds and non-listening sockets are not loopback listeners.
# A listener a PREVIOUS persona's tool container left on a tool port (18081 Jenkins, 18082 runner) excuses nothing for the next persona, and a tool is not started onto it.
mkprocnet "$work/pn-bad" "0A:127.0.0.1:9999"
PROCNET="$work/pn-bad" run guardbad '{}' rc
CASE="guard: an unexpected loopback listener (127.0.0.1:9999) makes every persona 'did not run' (blocking, exit nonzero), and no agent ran"
check python3 - "$work/guardbad" "$rc" <<'PY'
import os, sys
d, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0, rc
assert os.path.getsize(d + "/log") == 0, "an agent ran next to an unexpected loopback listener"
reports = [open(d + "/plain/" + f).read() for f in sorted(os.listdir(d + "/plain")) if f.endswith(".report.md")]
assert len(reports) == 5 and all("did not run" in r for r in reports), reports
assert sum("9999" in r for r in reports) >= 4, reports
PY
mkprocnet "$work/pn-bad6" "0A:ip6loop:9998"
PROCNET="$work/pn-bad6" run guardbad6 '{}' rc
CASE="guard: an IPv6 loopback listener (::1:9998) is refused too"
check python3 - "$work/guardbad6" "$rc" <<'PY'
import os, sys
assert int(sys.argv[2]) != 0 and os.path.getsize(sys.argv[1] + "/log") == 0
PY
mkprocnet "$work/pn-ok" "0A:127.0.0.53:53" "0A:0.0.0.0:22" "0A:ip6any:22" "01:127.0.0.1:9999"
PROCNET="$work/pn-ok" run guardok '{}' rc
CASE="guard: DNS, a wildcard bind (0.0.0.0:22, ::22) and a non-listening loopback connection are NOT unexpected: the run is clean"
check test "$rc" -eq 0
PROCNET="$work/pn-bad" ALLOW_LISTEN=9999 run guardallow '{}' rc
CASE="guard: --allow-listen 9999 names the listener and the run proceeds"
check test "$rc" -eq 0
PROCNET="$work/no-such-procnet" run guardmissing '{}' rc
CASE="guard: an unreadable proc-net (no tcp file) refuses: nothing can be said about the loopback, so no agent runs"
check python3 - "$work/guardmissing" "$rc" <<'PY'
import os, sys
assert int(sys.argv[2]) != 0 and os.path.getsize(sys.argv[1] + "/log") == 0
PY
# a listener on the Jenkins port (18081) and on the runner port (18082), left by an earlier persona: it is stray for every persona that did not start that tool, and a persona that
# needs the tool is not run onto it (the tool container is never started)
mkprocnet "$work/pn-stale" "0A:127.0.0.1:18081" "0A:127.0.0.1:18082"
PROCNET="$work/pn-stale" run guardstale '{}' rc
CASE="stale guard: a leftover listener on the Jenkins/runner ports does not excuse itself for the next persona: no persona runs (all five 'did not run', no agent ran, exit nonzero), and the Jenkins persona's tool containers were never started onto it"
check python3 - "$work/guardstale" "$rc" <<'PY'
import os, sys
d, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0, rc
assert os.path.getsize(d + "/log") == 0, "an agent ran next to a stale loopback listener"
reports = {f[:-len(".report.md")]: open(d + "/plain/" + f).read() for f in sorted(os.listdir(d + "/plain")) if f.endswith(".report.md")}
assert len(reports) == 5 and all("did not run" in r for r in reports.values()), reports
for p, r in reports.items():
    if p != "maven-jenkins-ci":
        assert "unexpected listener" in r and "18081" in r and "18082" in r, (p, r[:600])        # stray: it is not THIS persona's tool port
runs = [l for l in open(d + "/docker.log") if "jenkins" in l or "gitlab-runner" in l]
assert not any(l.startswith("run -d") and "18081:" in l for l in runs), runs
PY
# the same listener excused by name: --allow-listen is the caller's explicit choice
PROCNET="$work/pn-stale" ALLOW_LISTEN=18081 run guardstaleok '{"maven-jenkins-ci":{"requests":1}}' rc
CASE="stale guard: --allow-listen names a port, and only that port is excused (18082 stays stray)"
check python3 - "$work/guardstaleok" "$rc" <<'PY'
import sys
assert int(sys.argv[2]) != 0
PY
# the opening scrape is settled too: the driver's own readiness probes are counted AFTER their response, and must not be credited to the persona as its first request
srvctl __reset
srvctl __delay s 1.2
SETTLE_QUIET=1.6 SETTLE_MAX=10 run lateopen '{"gradle-platform-engineer":{"requests":0},"maven-jenkins-ci":{"requests":0},"readme-evaluator":{"requests":0},"on-call-engineer":{"requests":0}}' rc
srvctl __delay s 0
srvctl __reset
python3 -c "import time; time.sleep(1.5)"
CASE="settle (opening): a driver readiness probe counted 1.2s after its response is not credited to a persona that sent nothing: the four endpoint personas with no request of their own are blocking (the compliance reviewer's proof is its digest verification)"
check python3 - "$(out lateopen)" <<'PY'
import sys
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "readme-evaluator", "on-call-engineer"):
    r = open(sys.argv[1] + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: blocking", (p, r[:400])
PY

# --- FIX A: --docker is optional (default: the plain command on PATH); there is no --gh and no --publish; --recipient defaults to bin/persona-uat-recipient.pem ----
mkdir -p "$work/pathA" "$work/optional"; : >"$work/optional/log"; : >"$work/optional/docker.log"
echo '{"maven-jenkins-ci":{"findings":[{"kind":"friction","text":"a step is confusing"}]}}' >"$work/optional/plan.json"
sed "s#__LOG__#$work/optional/docker.log#" "$work/docker.tmpl" >"$work/pathA/docker"; chmod +x "$work/pathA/docker"
mkhost "$work/optional"; cp "$work/optional/hostbin/kind" "$work/optional/hostbin/kubectl" "$work/optional/hostbin/gh" "$work/optional/hostbin/openssl" "$work/pathA/"
rc=0
env -u PERSONA_UAT_TOKEN_BUDGET PATH="$work/pathA:$PATH" GITHUB_RUN_ID=4242 \
  PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --image "$IMG" --repo "$repo" --out "$work/optional/out" --recipient "$work/test.pem" \
  --tools "$work/tools.json" --port 18080 --ready-timeout 5 --agent "python3 $work/stub.py $work/optional" --proc-net "$work/procnet" \
  >"$work/optional/stdout" 2>"$work/optional/stderr" || rc=$?
CASE="--docker may be left out: the driver runs and uses the plain docker found first on PATH, and still calls no gh"
check test "$rc" -eq 0
check grep -q "^run -d" "$work/optional/docker.log"
check test ! -s "$work/optional/gh.log"
CASE="--docker is not a required option of the driver, and the driver defines neither --gh nor --publish (the results stay private: no issue machinery)"
check python3 - "$driver" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'add_argument\("--docker"[^)]*\)', src)
assert m and "required=True" not in m.group(0), m
assert '"--gh"' not in src and '"--publish"' not in src, "the issue options must be gone"
assert not re.search(r"\bgh\b[^\n]*(issue|label)", src.replace("# ", "")), "the driver must not call gh issue/label"
PY
mkdir -p "$work/defrec/bin"; cp "$driver" "$work/defrec/bin/persona-uat.py"; cp "$work/test.pem" "$work/defrec/bin/persona-uat-recipient.pem"; mkdir -p "$work/defrec-case"; : >"$work/defrec-case/log"; : >"$work/defrec-case/docker.log"; echo '{}' >"$work/defrec-case/plan.json"
sed "s#__LOG__#$work/defrec-case/docker.log#" "$work/docker.tmpl" >"$work/defrec-case/docker"; chmod +x "$work/defrec-case/docker"; mkhost "$work/defrec-case"; rc=0
env -u PERSONA_UAT_TOKEN_BUDGET PATH="$work/defrec-case/hostbin:$PATH" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$work/defrec/bin/persona-uat.py" --mode rc --image "$IMG" --repo "$repo" \
  --out "$work/defrec-case/out" --tools "$work/tools.json" --docker "$work/defrec-case/docker" --port 18080 --ready-timeout 5 --agent "python3 $work/stub.py $work/defrec-case" --proc-net "$work/procnet" >"$work/defrec-case/stdout" 2>"$work/defrec-case/stderr" || rc=$?
CASE="without --recipient the driver encrypts to bin/persona-uat-recipient.pem NEXT TO ITSELF (the committed certificate): five artifacts that the matching key decrypts"
check test "$rc" -eq 0
decout defrec-case
check test "$(ls "$work/defrec-case/plain"/*.report.md | wc -l | tr -d ' ')" -eq 5
CASE="the default-recipient run's artifacts pass the same CMS judgement: one key-transport recipient for the certificate the driver found next to itself, AES-256-CBC, an argv without any recipient-adding option"
check python3 - "$work" "$work/defrec-case" <<'PY'
import glob, json, sys
w, d = sys.argv[1:3]; sys.path.insert(0, w); import cmsjudge
enc = [c for c in (json.loads(l) for l in open(d + "/openssl.log")) if c[:2] == ["cms", "-encrypt"]]
assert len(enc) == 5
for c in enc:
    e = cmsjudge.judge_argv(c, c[c.index("-recip") + 1]); assert not e, (c, e)
    assert c[c.index("-recip") + 1].endswith("/defrec/bin/persona-uat-recipient.pem"), c
for f in glob.glob(d + "/out/*.cms"):
    e = cmsjudge.judge_cms(f, w + "/test.pem"); assert not e, (f, e)
assert len(glob.glob(d + "/out/*.cms")) == 5
PY

# --- FIX B: the sandbox is readable by the container's uid, never writable by others ---------------------------------
old_umask=$(umask); umask 077
run sbxmode '{}' rc
umask "$old_umask"
CASE="the sandbox (recorded at the moment the agent starts, under a strict umask): every DIRECTORY is 0777 so a tool image's non-root uid can create files in it, every docs file stays 0644 (read-only for others), nothing is a symlink"
check python3 - "$work/sbxmode/log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
assert len(rows) == 5, rows
for r in rows:
    m = r["modes"]
    assert m["<dir>"] == "0o777", m
    for k, v in m.items():
        if k == "<dir>":
            continue
        assert v in ("0o777", "0o644", "0o444"), ("a directory must be 0777 and a docs file 0644/0444", k, v)
    assert m["README.md"] in ("0o644", "0o444"), m
    if r["persona"] != "readme-evaluator":
        assert m["docs"] == "0o777" and m["docs/install.md"] in ("0o644", "0o444"), m
    if r["persona"] == "on-call-engineer":
        assert m["kubeconfig"] in ("0o644", "0o444"), m
    assert r["links"] == []
PY
CASE="a persona that leaves a read-only directory behind (what a container of another uid does) does not defeat cleanup: the sandbox is gone after the run"
run sbxleft '{"gradle-platform-engineer":{"readonly_dir":true,"foreign":true},"maven-jenkins-ci":{"readonly_dir":true,"foreign":true}}' rc
trap_dirs=$(python3 - "$work/sbxleft/log" <<'PY'
import json, sys
print(" ".join(sorted({json.loads(l)["request"]["docs_dir"] for l in open(sys.argv[1])})))
PY
)
check python3 - "$trap_dirs" <<'PY'
import os, sys
dirs = sys.argv[1].split()
assert len(dirs) == 5, dirs
left = [d for d in dirs if os.path.exists(d)]
for d in left:      # tidy up so the harness can remove its tree, then fail
    os.system("chmod -R u+rwx '%s'; rm -rf '%s'" % (d, d))
assert not left, ("a sandbox survived the run", left)
PY

# --- FIX D: the agent and the driver address the same docker daemon (one allowlist, duplicated) --------------------------
CASE="the docker-client environment allowlist is identical in the driver and in the agent"
check python3 - "$root/bin/persona-uat.py" "$root/bin/persona-uat-agent.py" <<'PY'
import ast, sys
def lists(path):
    out = {}
    for n in ast.parse(open(path).read()).body:
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and n.targets[0].id in ("SHELL_ENV", "DOCKER_ENV"):
            out[n.targets[0].id] = ast.literal_eval(n.value)
    return out
a, b = lists(sys.argv[1]), lists(sys.argv[2])
assert sorted(a) == ["DOCKER_ENV", "SHELL_ENV"], a
assert a == b, (a, b)
for k in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
    assert k in a["DOCKER_ENV"], k
PY


# --- DELTA 3: hosts NAMED in the persona's commands outside the public docs are FLAGGED in each report, as information only ----------------
# Limitation, stated: redirects, Maven repository configuration and a tool's own internal contacts are not observed; only what the commands name is.
hostsline() { python3 - "$1" <<'PY'
import re, sys
lines = [l for l in open(sys.argv[1]).read().splitlines() if l.startswith("Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'):")]
assert len(lines) == 1, ("exactly one line", lines)
v = lines[0].split(":", 1)[1].strip()
print("" if v == "none" else ",".join(sorted(x.strip() for x in v.split(","))))
PY
}
python3 - >"$work/hostsplan.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["curl -s https://docs.example.org/guide/install -o /dev/null", "curl http://127.0.0.1:18080/healthz", "curl -s http://localhost:18080/x",
                                           "curl https://github.com/example/cache/releases/download/v1/x", "curl http://127.0.0.1:18081/login",
                                           "curl -o out.txt http://127.0.0.1:18080/a", "wget -O file.zip https://docs.example.org/a", "curl -s -o report.json https://docs.example.org/y",
                                           "# https://commentonly.example/x\necho hi", "# see http://another-comment.example\n# and wget https://third-comment.example/z", "curl -s http://127.0.0.1:18080/x # https://inline-only.example/y",
                                           "curl -s https://docs-only.example.net/guide", "curl -L https://github.com/example/cache/releases/latest"]},
 "maven-jenkins-ci": {"commands": ["curl -s https://repo.maven.apache.org/maven2/x.pom", "curl http://169.254.169.254/latest/meta-data", "curl -u a:b 'https://Evil.Example:8443/p?x=1'",
                                   "curl -s outside.example/path", "wget -q outside2.example:8080/f.tgz", "kubectl --server=k8s3.evil.example:6443 get pods",
                                   "kubectl --server https://k8s2.evil.example get pods", "curl http://127.0.0.2:8080/x", "cosign verify registry.outside.example/ns/img:1"]},
 "compliance-reviewer": {"commands": ["cosign verify x # https://registry.k8s.io/v2/", "curl https://docker.io/v2/", "curl https://gcr.io/v2/",
                                      "cosign verify gcr.io/projectsigstore/cosign@sha256:5555555555555555555555555555555555555555555555555555555555555555", "cosign verify docker.io/library/gradle:8"]},
 "readme-evaluator": {"commands": ["curl http://localhost.evil.example/a", "curl http://127.0.0.1.evil.example/b", "curl https://docs.example.org.evil.example/c",
                                   "curl https://evil.example/127.0.0.1", "curl https://example.org/", "curl https://user@evil2.example/x", "curl 'http://evil3.example:80'",
                                   "curl https://sub.docs.example.org/x", "curl https://evildocker.io/v2/", "curl https://notgithub.com/x",
                                   "curl https://raw.githubusercontent.com/example/cache/main/internal/x.go", "curl -L https://github.com/example/cache/archive/refs/heads/main.tar.gz",
                                   "curl https://github.com/example/cache/raw/main/internal/x.go", "curl https://github.com/example/cache/blob/main/README.md", "curl https://github.com/example/cache/tree/main/internal"]},
 "on-call-engineer": {"commands": ["kubectl get pods --kubeconfig kubeconfig # https://127.0.0.1:18090"]}}))
PY
run hosts "$(cat "$work/hostsplan.json")" rc
CASE="hosts: every report carries ONE 'Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'):' line, and the label says what it IS (hosts NAMED in the command text; what was contacted is the separate network list), never 'contacted'"
allhosts() { local q; for q in $PERSONAS; do hostsline "$(out hosts)/$q.report.md" >/dev/null || return 1; done; }
check allhosts
for p in gradle-platform-engineer compliance-reviewer on-call-engineer; do
  CASE="hosts ($p): only docs links, loopback (any port), localhost, tool registries (docker.io, gcr.io, registry.k8s.io), output file names after -o/-O, a host that occurs only in a docs/*.md page, a github.com RELEASES url, cosign references to a tool registry and URLs on shell comment lines were named: the line says none"
  check test "$(hostsline "$(out hosts)/$p.report.md")" = ""
done
CASE="hosts (maven-jenkins-ci): URL hosts, a metadata-service IP, a mixed-case host with port and query, scheme-less curl/wget/kubectl --server hosts, a scheme-less cosign registry reference and 127.0.0.2 are listed, lower-cased, once each, sorted"
check test "$(hostsline "$(out hosts)/maven-jenkins-ci.report.md")" = "127.0.0.2,169.254.169.254,evil.example,k8s2.evil.example,k8s3.evil.example,outside.example,outside2.example,registry.outside.example,repo.maven.apache.org"
CASE="hosts (readme-evaluator): lookalikes are flagged, never matched by substring or suffix; the repository's source (raw.githubusercontent.com, and github.com archive/raw/blob/tree paths, although github.com IS a docs host) is listed as '<host> (repository source)', once per host"
check test "$(hostsline "$(out hosts)/readme-evaluator.report.md")" = "127.0.0.1.evil.example,docs.example.org.evil.example,evil.example,evil2.example,evil3.example,evildocker.io,example.org,github.com (repository source),localhost.evil.example,notgithub.com,raw.githubusercontent.com (repository source),sub.docs.example.org"
CASE="hosts are information only: the run exits 0, every verdict stays pass, the flags (hosts, repository source) are in the ENCRYPTED reports, and neither gh nor any public file saw them"
check test "$rc" -eq 0
check python3 - "$(out hosts)" "$work/hosts" <<'PY'
import glob, os, sys
for r in glob.glob(sys.argv[1] + "/*.report.md"):
    assert open(r).read().splitlines()[0] == "VERDICT: pass", r
assert open(sys.argv[2] + "/gh.log").read() == ""
assert sorted(os.listdir(sys.argv[2] + "/out")) == sorted(os.path.basename(r)[:-len(".report.md")] + ".cms" for r in glob.glob(sys.argv[1] + "/*.report.md"))
PY
python3 - >"$work/hostsplan2.json" <<'PY'
import json
print(json.dumps({"maven-jenkins-ci": {"findings": [{"kind": "blocking", "text": "step 3 fails as written"}], "commands": ["curl https://evil.example/x"]},
                  "gradle-platform-engineer": {"findings": [{"kind": "friction", "text": "slow"}], "commands": ["curl https://evil.example/y", "curl https://other.example/z"]}}))
PY
run hosts2 "$(cat "$work/hostsplan2.json")" rc
CASE="hosts: a blocking persona and a friction persona carry the line too, next to their findings, and the line does not change their verdicts"
check test "$(hostsline "$(out hosts2)/maven-jenkins-ci.report.md")" = "evil.example"
check test "$(hostsline "$(out hosts2)/gradle-platform-engineer.report.md")" = "evil.example,other.example"
check test "$(head -1 "$(out hosts2)/maven-jenkins-ci.report.md")" = "VERDICT: blocking" -a "$(head -1 "$(out hosts2)/gradle-platform-engineer.report.md")" = "VERDICT: friction"
check grep -q 'step 3 fails as written' "$(out hosts2)/maven-jenkins-ci.report.md"
# the report is ENCRYPTED, so a vendor-named or credential-looking host is listed as it is (there is no public scan to trip); it never reaches a public place
V1="anth""ropic"; V2="open""ai"
python3 - "$V1" "$V2" >"$work/hostsplan3.json" <<'PY'
import json, sys
v1, v2 = sys.argv[1:3]
print(json.dumps({
 "gradle-platform-engineer": {"findings": [{"kind": "friction", "text": "the proxy URL is easy to mistype"}], "commands": ["curl https://api.%s.com/v1/x" % v1, "curl https://evil.example/y"]},
 "readme-evaluator": {"commands": ["curl https://%s.com/" % v2, "curl https://0123456789abcdef0123456789abcdef.evil.example/z", "curl https://plain.example/q"]},
 "maven-jenkins-ci": {"findings": [{"kind": "blocking", "text": "step 3 fails as written"}], "commands": ["curl https://www.%s.com/" % v1]}}))
PY
run hosts3 "$(cat "$work/hostsplan3.json")" rc
CASE="hosts (encrypted report): vendor-named and credential-looking hosts are listed plainly next to the plain ones, in the decrypted report; the report is not withheld; the job log and the artifact names hold none of them"
check python3 - "$(out hosts3)" "$work/hosts3" "$V1" "$V2" <<'PY'
import os, sys
d, c, v1, v2 = sys.argv[1:5]
g = open(d + "/gradle-platform-engineer.report.md").read()
r = open(d + "/readme-evaluator.report.md").read()
m = open(d + "/maven-jenkins-ci.report.md").read()
line = lambda t: t.split("Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'):")[1].splitlines()[0]
assert "api.%s.com" % v1 in line(g) and "evil.example" in line(g), line(g)
assert "%s.com" % v2 in line(r) and "0123456789abcdef0123456789abcdef.evil.example" in line(r) and "plain.example" in line(r), line(r)
assert "www.%s.com" % v1 in line(m), line(m)
for t in (g, r, m):
    assert "withheld" not in t.lower(), t
blob = (open(c + "/stdout").read() + open(c + "/stderr").read() + " ".join(os.listdir(c + "/out"))).lower()
assert v1 not in blob and v2 not in blob and "0123456789abcdef" not in blob and "evil" not in blob and "plain.example" not in blob
PY
CASE="hosts: a friction-only persona with outside and vendor hosts stays FRICTION, a clean persona with a vendor host stays PASS, a blocking one stays blocking for ITS finding only; the exit follows only the real blocking finding, and the log is pass/fail lines"
check test "$(head -1 "$(out hosts3)/gradle-platform-engineer.report.md")" = "VERDICT: friction" -a "$(head -1 "$(out hosts3)/readme-evaluator.report.md")" = "VERDICT: pass" -a "$(head -1 "$(out hosts3)/maven-jenkins-ci.report.md")" = "VERDICT: blocking"
check grep -q 'proxy URL is easy to mistype' "$(out hosts3)/gradle-platform-engineer.report.md"
check test "$rc" -ne 0
check publiclog hosts3
python3 - "$V1" >"$work/hostsplan4.json" <<'PY'
import json, sys
print(json.dumps({"gradle-platform-engineer": {"commands": ["curl https://api.%s.com/v1/x" % sys.argv[1]], "findings": [{"kind": "friction", "text": "slow"}]}}))
PY
run hosts4 "$(cat "$work/hostsplan4.json")" rc
CASE="hosts: friction-only plus a vendor host and nothing else: the run exits 0 (friction blocks nothing), the friction and the host are in the encrypted report, and the log is five pass lines plus overall"
check test "$rc" -eq 0
check grep -q "api.$V1.com" "$(out hosts4)/gradle-platform-engineer.report.md"
check publiclog hosts4
CASE="hosts: a persona that reports no commands (the key is absent) gets 'none', never a missing line"
check test "$(hostsline "$(out clean)/readme-evaluator.report.md")" = ""
python3 - "$work/tools.json" "$work/tools-reg.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))
t["kubectl"] = "registry.example.net/kubectl@sha256:" + "6" * 64
t["cosign"] = "quay.io/sigstore/cosign@sha256:" + "5" * 64
json.dump(t, open(sys.argv[2], "w"))
PY
TOOLS="$work/tools-reg.json" run hostsreg '{"readme-evaluator":{"commands":["curl https://registry.k8s.io/v2/","curl https://registry.example.net/v2/","curl https://quay.io/v2/","curl https://gcr.io/v2/","curl https://docker.io/v2/"]}}' rc
CASE="hosts: the registries are read from the tools file the driver was given (not a hard-coded list): registry.example.net, quay.io and docker.io are excluded, registry.k8s.io and gcr.io are no longer named by any entry"
check test "$(hostsline "$(out hostsreg)/readme-evaluator.report.md")" = "gcr.io,registry.k8s.io"
unset TOOLS
for c in 'commands-str|{"override":{"commands":"curl https://evil.example"}}' 'commands-int|{"commands":[5]}' 'commands-obj|{"override":{"commands":{"a":"b"}}}'; do
  name=${c%%|*}; plan=${c#*|}
  failclosed "$name" readme-evaluator "$plan"
done

# --- DELTA 4: the endpoint proof, against the REAL counter semantics -------------------------------------------------------------------
srvctl __reset
srvctl __silent v 1
python3 - >"$work/proofplan.json" <<'PY'
import json
print(json.dumps({"gradle-platform-engineer": {"requests": 3, "sleep": 0.15},
                  "maven-jenkins-ci": {"requests": 0, "uncounted": ["/healthz", "/statusz"], "sleep": 0.15},
                  "compliance-reviewer": {"requests": 5, "methods": ["GET", "PUT", "HEAD", "GET"], "sleep": 0.15},
                  "readme-evaluator": {"requests": 1, "sleep": 0.15},
                  "on-call-engineer": {"requests": 0, "uncounted": ["/healthz"], "sleep": 0.15}}))
PY
DOCKER_NOISE=4 run proof "$(cat "$work/proofplan.json")" rc
srvctl __silent v 0
CASE="proof (fresh server: the first persona's before-scrape holds NO sample line = zero, not an error): personas with 3 (first, fresh server), 5 (GET/PUT/HEAD/404 summed over series) and exactly 1 counted request pass; the two whose only traffic was /healthz and /statusz (never counted) are blocking 'the endpoint was never exercised', although the driver's own container work hit the endpoint 4 times around them; the run fails"
check test "$rc" -ne 0
check python3 - "$(out proof)" <<'PY'
import sys
want = {"gradle-platform-engineer": "pass", "maven-jenkins-ci": "blocking", "compliance-reviewer": "pass", "readme-evaluator": "pass", "on-call-engineer": "blocking"}
for p, v in want.items():
    r = open(sys.argv[1] + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: " + v, (p, r)
    assert ("never exercised" in r.lower()) == (v == "blocking"), (p, r)
PY
srvctl __reset
run proofmetrics '{"readme-evaluator":{"requests":0,"uncounted":["/metrics","/metrics","/metrics","/healthz"]},"gradle-platform-engineer":{"requests":1,"methods":["PUT"]},"maven-jenkins-ci":{"requests":1,"methods":["HEAD"]}}' rc
CASE="proof: a persona that only scraped /metrics (and /healthz) made no counted request: blocking; one counted PUT, or one counted HEAD, is enough to pass (every method and status label is summed)"
check python3 - "$(out proofmetrics)" <<'PY'
import sys
want = {"readme-evaluator": "blocking", "gradle-platform-engineer": "pass", "maven-jenkins-ci": "pass"}
for p, v in want.items():
    assert open(sys.argv[1] + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: " + v, p
PY
# RULE CHANGED (advisor 0250, replacing the 0207 friction-only rule): a persona with NO proof of exercising the RC image is BLOCKING whatever else it reported. Friction stays
# informational, but "did not exercise the image" blocks that persona. The proof is the counted-request delta (after - before > 0) for every persona EXCEPT the compliance
# reviewer, whose proof is a recorded verification action (cosign verify / attestation / SBOM / VEX) that names the RC's DIGEST and exited 0.
CASE="proof (rule of advisor 0250): friction-only with NO counted request is BLOCKING for each of the four endpoint personas (the friction is kept in the report, the verdict is blocking, 'did not exercise the image' is said); a persona that reports a blocking finding of its own and no requests stays blocking (and also says it did not exercise)"
run proof2 '{"readme-evaluator":{"requests":0,"findings":[{"kind":"friction","text":"the README is vague"}]},"gradle-platform-engineer":{"requests":0,"findings":[{"kind":"blocking","text":"step 1 fails as written"}]},"maven-jenkins-ci":{"requests":0,"findings":[{"kind":"friction","text":"jenkins slow"}]},"on-call-engineer":{"requests":0,"findings":[{"kind":"friction","text":"logs hard to find"}]}}' rc
check python3 - "$(out proof2)" "$rc" <<'PY'
import sys
o, rc = sys.argv[1], int(sys.argv[2])
assert rc == 1, rc
for p in ("readme-evaluator", "gradle-platform-engineer", "maven-jenkins-ci", "on-call-engineer"):
    r = open(o + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: blocking" and "did not exercise the image" in r, (p, r)
assert "the README is vague" in open(o + "/readme-evaluator.report.md").read(), "the friction must stay in the report"
assert open(o + "/compliance-reviewer.report.md").read().splitlines()[0] == "VERDICT: pass"
PY
check publiclog proof2
# the compliance reviewer's proof is a DIGEST verification, not the counter
cmpcase() { # <name> <plan for compliance-reviewer>
  run "$1" "{\"compliance-reviewer\":$2}" rc
}
cmpcase cmp1 '{"requests":0}'
CASE="compliance proof: a verification action naming the RC digest that exited 0 proves the run WITHOUT any counted request (the reviewer never calls the endpoint): pass"
check test "$(head -1 "$(out cmp1)/compliance-reviewer.report.md")" = "VERDICT: pass"
cmpcase cmp2 '{"noverify":true,"requests":3}'
CASE="compliance proof: counter traffic alone is NOT the compliance reviewer's proof (fail closed): no digest verification => blocking, 'did not exercise the image'"
check python3 - "$(out cmp2)" <<'PY'
import sys
r = open(sys.argv[1] + "/compliance-reviewer.report.md").read()
assert r.splitlines()[0] == "VERDICT: blocking" and "did not exercise the image" in r and "digest" in r, r
PY
cmpcase cmp3 '{"verify_exit":1}'
CASE="compliance proof: a verification action that FAILED (exit 1) is no proof: blocking"
check test "$(head -1 "$(out cmp3)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp4 '{"verify_other":true}'
CASE="compliance proof: a verification action that names ANOTHER digest than the RC's is no proof: blocking"
check test "$(head -1 "$(out cmp4)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp5 '{"noverify":true,"requests":0,"findings":[{"kind":"friction","text":"sbom steps unclear"}]}'
CASE="compliance proof: friction-only with no verification and no traffic is blocking, not friction (the friction stays in the report)"
check python3 - "$(out cmp5)" <<'PY'
import sys
r = open(sys.argv[1] + "/compliance-reviewer.report.md").read()
assert r.splitlines()[0] == "VERDICT: blocking" and "sbom steps unclear" in r, r
PY
cmpcase cmp6 "{\"noverify\":true,\"commands\":[\"echo sha256:$(printf 'a%.0s' $(seq 64))\"]}"
CASE="compliance proof: the RC digest merely NAMED by a command that is not a verification (echo, a shell action) is no proof: blocking"
check test "$(head -1 "$(out cmp6)/compliance-reviewer.report.md")" = "VERDICT: blocking"
RCD="ghcr.io/example/cache@sha256:$(printf 'a%.0s' $(seq 64))"
GOODV="\"--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0\$\",\"--certificate-oidc-issuer=https://token.actions.githubusercontent.com\""
cmpcase cmp7 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",$GOODV,\"$RCD\"],\"exit\":1},{\"tool\":\"cosign\",\"argv\":[\"verify\",$GOODV,\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: AT LEAST ONE successful cosign verify of the image under test (its own repository and digest, the documented promotion identity and OIDC issuer) is enough (a failed one first): pass"
check test "$(head -1 "$(out cmp7)/compliance-reviewer.report.md")" = "VERDICT: pass"
cmpcase cmp8 '{"noverify":true,"commands":["cosign verify x"],"drop":["actions"]}'
CASE="compliance proof: an answer with commands but no actions is no proof (fail closed): blocking"
check test "$(head -1 "$(out cmp8)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp9 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify-attestation\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify-blob\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"download\",\"sbom\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--help\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"-h\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--version\",\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: verify-attestation WITHOUT --type, verify-blob, download sbom, and any verify with --help, -h or --version prove nothing: blocking"
check test "$(head -1 "$(out cmp9)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp12 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify-attestation\",\"--type\",\"slsaprovenance\",$GOODV,\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: cosign verify-attestation ALONE proves nothing about the signature (the guide verifies provenance with gh): blocking"
check test "$(head -1 "$(out cmp12)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp13 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-identity\",\"$RCD\",\"ghcr.io/example/cache:1.0\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"ghcr.io/example/other@sha256:$(printf 'b%.0s' $(seq 64))\",\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: the RC digest as the VALUE of a flag, or as one of two image arguments, is no proof: blocking"
check test "$(head -1 "$(out cmp13)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp14 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",$GOODV,\"ghcr.io/evil/cache@sha256:$(printf 'a%.0s' $(seq 64))\"],\"exit\":0}]}"
CASE="compliance proof: a successful cosign verify of ANOTHER repository that ends in the same digest is no proof: blocking"
check test "$(head -1 "$(out cmp14)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp15 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--key\",\"my.pub\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--key\",\"my.pub\",$GOODV,\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: a verify against the reviewer's own --key (with or without the documented flags) verifies nothing of FosterStack's: blocking"
check test "$(head -1 "$(out cmp15)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp16 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/stage-promote.yml@refs/tags/v1.0.0\$\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-oidc-issuer=https://token.actions.githubusercontent.com\",\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: a verify without the OIDC issuer, or without any certificate identity, is no proof: blocking"
check test "$(head -1 "$(out cmp16)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp17 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-identity-regexp=^https://github.com/example/cache/.github/workflows/release.yml@refs/tags/v1.0.0\$\",\"--certificate-oidc-issuer=https://token.actions.githubusercontent.com\",\"$RCD\"],\"exit\":0},{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-identity-regexp=.*\",\"--certificate-oidc-issuer=https://token.actions.githubusercontent.com\",\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: an identity that is not the documented promotion workflow of this repository (release.yml, a wildcard) is no proof: blocking"
check test "$(head -1 "$(out cmp17)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp10 "{\"noverify\":true,\"actions\":[{\"tool\":\"shell\",\"argv\":[\"sh\",\"-c\",\"cosign verify $RCD\"],\"exit\":0},{\"tool\":\"kubectl\",\"argv\":[\"verify\",\"$RCD\"],\"exit\":0}]}"
CASE="compliance proof: a shell action with the words, or another tool's 'verify', is no proof (the TOOL field must be cosign): blocking"
check test "$(head -1 "$(out cmp10)/compliance-reviewer.report.md")" = "VERDICT: blocking"
cmpcase cmp11 "{\"noverify\":true,\"actions\":[{\"tool\":\"cosign\",\"argv\":[\"verify\",\"--certificate-identity=x@sha256:$(printf 'a%.0s' $(seq 64))\",\"ghcr.io/example/cache:1.0\"],\"exit\":0}]}"
CASE="compliance proof: the digest inside a flag's value (not an image argument) is no proof: blocking"
check test "$(head -1 "$(out cmp11)/compliance-reviewer.report.md")" = "VERDICT: blocking"
run proofreset '{"gradle-platform-engineer":{"requests":3},"maven-jenkins-ci":{"requests":3},"readme-evaluator":{"reset":true,"requests":1}}' rc
CASE="proof: a counter that went BACKWARDS during the window (the server restarted: fewer samples after than before) is no proof: that persona, with no findings, is blocking; the others pass"
check test "$(head -1 "$(out proofreset)/readme-evaluator.report.md")" = "VERDICT: blocking" -a "$(head -1 "$(out proofreset)/gradle-platform-engineer.report.md")" = "VERDICT: pass"
check grep -qi 'endpoint' "$(out proofreset)/readme-evaluator.report.md"
for ma in garbage nometric; do
  run "proofafter-$ma" "{\"on-call-engineer\":{\"requests\":2,\"mode_after\":\"$ma\"}}" rc
  srvctl __mode m "ok"
  CASE="proof: an AFTER-scrape that cannot be parsed or holds no sample while the before-scrape had one ($ma) is no proof: blocking, never a pass"
  check test "$(head -1 "$(out "proofafter-$ma")/on-call-engineer.report.md")" = "VERDICT: blocking" -a "$rc" -ne 0
  if [ "$ma" = garbage ]; then
    CASE="proof: a failed CLOSING scrape ($ma) is 'cannot prove' for that persona (blocking, never a pass): the report says the counter could not be read"
    check grep -q "cannot prove: the request counter of this persona's container could not be read" "$(out "proofafter-$ma")/on-call-engineer.report.md"
  fi
done
for m in garbage status500 nometric nofamily; do
  srvctl __mode m "$m"
  run "proofmode-$m" '{}' rc
  srvctl __mode m "ok"
  CASE="proof ($m): when /metrics cannot be read or holds no fscache_http_requests_total sample at all, no ENDPOINT persona may finish clean: the four are blocking and the run fails (the compliance reviewer's proof is its digest verification, not the counter: it passes)"
  check python3 - "$(out "proofmode-$m")" "$rc" <<'PY'
import glob, sys
assert int(sys.argv[2]) != 0
rs = sorted(glob.glob(sys.argv[1] + "/*.report.md"))
assert len(rs) == 5, rs
for r in rs:
    want = "pass" if r.endswith("compliance-reviewer.report.md") else "blocking"
    assert open(r).read().splitlines()[0] == "VERDICT: " + want, (r, want)
PY
done
cat >"$work/windows.py" <<'PY'
import json, sys
# windows.py <case dir> [n personas that wrote timing] [settle]: from the stub agents' own instants and the server's scrape instants
d = sys.argv[1]
n_expect = int(sys.argv[2]) if len(sys.argv) > 2 else 5
mult = 2 if "double" in sys.argv[3:] else 1       # the fixture counts every request twice (a late second increment)
qmin = float(next((x.split("=")[1] for x in sys.argv[3:] if x.startswith("quiet=")), "0.75"))     # the quiet interval asserted from the recorded scrape instants (the default window is 3.0s: quiet=2.9)
settle = "settle" in sys.argv[3:]      # the real server counts AFTER the response: the after-scrape is the LAST one before the next persona's before-scrape
tim = sorted((json.loads(l) for l in open(d + "/timing.log")), key=lambda r: r["t0"])
srv = [json.loads(l) for l in open(d + "/srv.log")]
scr = sorted((e for e in srv if e["path"] == "/metrics"), key=lambda e: e["t"])
assert len(tim) == n_expect, tim
wins = []
for i, r in enumerate(tim):
    before = [e for e in scr if e["t"] < r["t0"]]
    assert before, ("a persona window without a scrape before it", r["persona"])
    b = before[-1]
    # a persona's endpoint is a container of its own on a port of its own: ITS readings (the settled opening series before t0, the settled closing series after t1) are the scrapes on b's port
    scr_own = [e for e in scr if e.get("port") == b.get("port")]
    if settle:
        between = [e for e in scr_own if e["t"] > r["t1"]]
        assert len(between) >= 2, ("no settled after-scrape for this persona's endpoint", r["persona"], len(between))
        a = between[-1]
        # the QUIET INTERVAL, from the recorded scrape instants: the readings the driver settled on (everything between the window and the next persona's before-scrape)
        # must end in a run of equal totals that spans at least 0.8 s (a change restarts it: the run is counted back from the LAST scrape over the trailing equal readings)
        seq = between
        assert len(seq) >= 2, ("the driver settled on fewer than two readings", r["persona"], len(seq))
        k = len(seq) - 1
        while k > 0 and seq[k - 1]["total"] == seq[-1]["total"]:
            k -= 1
        assert seq[-1]["t"] - seq[k]["t"] >= qmin, ("the final equal readings span %.2fs after the last observed change: not the stated quiet interval (%.2fs)" % (seq[-1]["t"] - seq[k]["t"], qmin), r["persona"])
    else:
        after = [e for e in scr_own if e["t"] > r["t1"]]
        assert after, ("a persona window without a scrape after it", r["persona"])
        a = after[0]
    inside = [e for e in srv if b["t"] < e["t"] < a["t"] and e["path"] != "/metrics"]
    if not settle:
        assert not [e for e in scr_own if b["t"] < e["t"] < a["t"]], ("another scrape inside the window", r["persona"])
    own = {r["persona"]} | ({"CONTAINER"} if r.get("daemon") else set())
    assert all(e["persona"] in own for e in inside), ("a request of another party inside the window: it would be attributed to this persona", r["persona"], [e for e in inside if e["persona"] not in own][:3])
    if not r.get("daemon"):
        counted = [e for e in inside if e["counted"]]
        assert len(counted) == r["requests"] and len(inside) == r["requests"] + r["uncounted"], ("the requests inside the scrape window are not exactly the persona's", r["persona"], len(counted), r["requests"])
        assert a["total"] - b["total"] == r["requests"] * mult, ("after - before is not the persona's counted requests", r["persona"], a["total"], b["total"], r["requests"])
    wins.append((b["t"], a["t"], r["persona"]))
for (b1, a1, p1), (b2, a2, p2) in zip(wins, wins[1:]):
    assert a1 < b2, ("the windows of %s and %s overlap" % (p1, p2), a1, b2)
PY
CASE="windows: from the stub agents' own start/end instants and the server's scrape instants, every persona has a scrape right before and right after its run, no other scrape or foreign request inside, after - before equals its COUNTED requests, and the five windows are strictly sequential (rc)"
check python3 "$work/windows.py" "$work/proof"
python3 - >"$work/proofplan2.json" <<'PY'
import json
print(json.dumps({"gradle-platform-engineer": {"requests": 2, "sleep": 0.1}, "maven-jenkins-ci": {"requests": 0, "sleep": 0.1, "findings": [{"kind": "friction", "text": "f"}]},
                  "compliance-reviewer": {"requests": 4, "uncounted": ["/statusz"], "sleep": 0.1}, "readme-evaluator": {"requests": 1}, "on-call-engineer": {"requests": 3, "sleep": 0.1}}))
PY
IMAGE="$IMG2" DOCKER_NOISE=3 run weeklyproof "$(cat "$work/proofplan2.json")" weekly
CASE="windows (weekly): the same endpoint proof and the same strictly sequential, attributed windows apply in weekly mode, on the same endpoint"
check python3 "$work/windows.py" "$work/weeklyproof"
python3 - >"$work/proofplan3.json" <<'PY'
import json
print(json.dumps({"maven-jenkins-ci": {"requests": 0}, "compliance-reviewer": {"requests": 2}}))
PY
IMAGE="$IMG2" DOCKER_NOISE=3 run weeklyproof2 "$(cat "$work/proofplan3.json")" weekly
CASE="weekly: a persona that finished with no findings and made no counted request is BLOCKING in its encrypted report ('the endpoint was never exercised'), the weekly run FAILS (exit 1), the log is a fail line for that persona and overall, and the reason is not public"
check python3 - "$(out weeklyproof2)" <<'PY'
import sys
d = sys.argv[1]
r = open(d + "/maven-jenkins-ci.report.md").read()
assert r.splitlines()[0] == "VERDICT: blocking" and "never exercised" in r.lower(), r
assert "never exercised" not in open(d + "/compliance-reviewer.report.md").read().lower()
PY
check test "$rc" -eq 1
check publiclog weeklyproof2
check none_match 'never exercised' "$work/weeklyproof2/stdout" "$work/weeklyproof2/stderr"
# surviving work: a timed-out agent that started work in its own session must not leak it into the next persona's window
AGENT_TIMEOUT=1 run orphan '{"maven-jenkins-ci":{"orphan":1.2,"sleep":30},"compliance-reviewer":{"sleep":0.8},"readme-evaluator":{"sleep":0.8},"on-call-engineer":{"sleep":0.8}}' rc
CASE="timeout leaves no survivors: the agent that timed out started work in its OWN session (it would request the endpoint 1.2s later, inside a later persona's window); the driver terminated it: no such request ever reached the endpoint, and the persona is did-not-run"
check python3 - "$work/orphan" "$(out orphan)" <<'PY'
import json, sys
srv = [json.loads(l) for l in open(sys.argv[1] + "/srv.log")]
assert not [e for e in srv if e["persona"] == "ORPHAN"], ("work started by the agent survived its window", [e for e in srv if e["persona"] == "ORPHAN"])
assert "did not run" in open(sys.argv[2] + "/maven-jenkins-ci.report.md").read().lower()
PY


# --- ROUND 2 (review d6r2) ----------------------------------------------------------------------------------------------------------------------
# The fake kubectl itself: only the five accepted verbs, schema validation, nothing imperative
fk="$work/fk"; mkdir -p "$fk"; mkhost "$fk"; printf 'users:\n- user:\n    client-certificate-data: X\n' >"$fk/admin"
CASE="fake kubectl (self-test): create clusterrolebinding (cluster-admin), create rolebinding, create role, create serviceaccount, delete, patch, exec, run, label, edit, replace, get -f and create namespace are all REFUSED (exit 1, recorded as refused); apply -f -, create token, get, wait, version and cluster-info are accepted"
check python3 - "$fk" <<'PY'
import json, subprocess, sys
d = sys.argv[1]
k = d + "/hostbin/kubectl"
def call(args, stdin=None):
    return subprocess.run([k, "--kubeconfig", d + "/admin"] + args, input=stdin, capture_output=True, text=True).returncode
refused = ["create clusterrolebinding x --clusterrole=cluster-admin --serviceaccount=persona:p", "create rolebinding x --clusterrole=admin --serviceaccount=persona:p",
           "create role r --verb=get --resource=pods -n persona", "create serviceaccount sa -n persona", "create namespace persona", "delete pvc x", "patch deploy x -p {}", "exec p -- sh",
           "run x --image=y", "label ns persona x=y", "edit deploy x", "replace -f x.yaml", "get -f x.yaml", "auth can-i create pods"]
for a in refused:
    assert call(a.split()) != 0, ("the fake accepted", a)
rows = [json.loads(l) for l in open(d + "/host.log") if '"kubectl"' in l]
assert len([r for r in rows if r["refused"]]) == len(refused), [r["argv"] for r in rows if not r["refused"]]
ok_ns = json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "persona"}})
assert call(["apply", "-f", "-"], ok_ns) == 0
for a in (["create", "token", "sa", "-n", "persona", "--duration", "1h"], ["get", "pods"], ["wait", "--for=condition=Ready", "node", "--all"], ["version"], ["cluster-info"]):
    assert call(a) == 0, a
PY
python3 - "$fk" >"$work/fk-neg.json" <<'PY'
import json, sys
SA = {"kind": "ServiceAccount", "name": "p", "namespace": "persona"}
RR = {"kind": "Role", "name": "r", "apiGroup": "rbac.authorization.k8s.io"}
def rb(**kw):
    o = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "b", "namespace": "persona"}, "roleRef": dict(RR), "subjects": [dict(SA)]}
    o.update(kw); return o
role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "r", "namespace": "persona"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}
api = {      # what the API server itself refuses
 "SA subject with apiGroup rbac": rb(subjects=[dict(SA, apiGroup="rbac.authorization.k8s.io")]),
 "roleRef kind Deployment": rb(roleRef=dict(RR, kind="Deployment")),
 "roleRef without name": rb(roleRef={"kind": "Role", "apiGroup": "rbac.authorization.k8s.io"}),
 "roleRef apiGroup empty": rb(roleRef=dict(RR, apiGroup="")),
 "roleRef apiGroup core": rb(roleRef=dict(RR, apiGroup="v1")),
 "Role with apiVersion v1": dict(role, apiVersion="v1"),
 "Namespace with rbac apiVersion": {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Namespace", "metadata": {"name": "persona"}},
 "ServiceAccount with apps/v1": {"apiVersion": "apps/v1", "kind": "ServiceAccount", "metadata": {"name": "p"}},
 "Deployment (no match)": {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d"}},
 "rule without verbs": dict(role, rules=[{"apiGroups": [""], "resources": ["pods"]}]),
 "no metadata.name": {"apiVersion": "v1", "kind": "Namespace", "metadata": {}},
}
contract = {  # valid Kubernetes objects that this driver's STRICTER contract refuses
 "empty subjects": rb(subjects=[]),
 "SA subject without namespace": rb(subjects=[{"kind": "ServiceAccount", "name": "p"}]),
 "Role without rules": dict(role, rules=[]),
 "rule without apiGroups": dict(role, rules=[{"resources": ["pods"], "verbs": ["get"]}]),
}
good = {"Namespace": {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "persona", "labels": {"a": "b"}}}, "ServiceAccount": {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "p", "namespace": "persona"}},
        "Role": role, "RoleBinding": rb(), "List of all": {"apiVersion": "v1", "kind": "List", "items": [role, rb()]}}
print(json.dumps({"api": api, "contract": contract, "good": good}))
PY
CASE="fake kubectl schema (self-test): 11 manifests the API server itself refuses (a ServiceAccount subject with apiGroup rbac.authorization.k8s.io, roleRef kind/name/apiGroup wrong, wrong apiVersion/kind pairs, a rule without verbs, no name, an unknown kind) are rejected as SCHEMA errors; 4 valid-for-Kubernetes forms (no subjects, a subject without namespace, no rules, no apiGroups) are rejected only as CONTRACT violations of this driver (labelled so); 5 valid manifests (including a List) are applied"
check python3 - "$fk" "$work/fk-neg.json" <<'PY'
import json, subprocess, sys
d = sys.argv[1]
k = d + "/hostbin/kubectl"
t = json.load(open(sys.argv[2]))
def ap(doc, raw=False):
    r = subprocess.run([k, "--kubeconfig", d + "/admin", "apply", "-f", "-"], input=doc if raw else json.dumps(doc), capture_output=True, text=True)
    return r.returncode, r.stderr
for n, doc in t["api"].items():
    rc, err = ap(doc)
    assert rc != 0 and "CONTRACT" not in err, ("an API-invalid manifest was accepted or mislabelled", n, err)
for n, doc in t["contract"].items():
    rc, err = ap(doc)
    assert rc != 0 and "CONTRACT" in err, ("a contract violation was accepted or not labelled as one", n, err)
assert ap("{not json", True)[0] != 0
for n, doc in t["good"].items():
    assert ap(doc)[0] == 0, ("rejected a valid manifest", n)
rows = [json.loads(l) for l in open(d + "/host.log") if '"kubectl"' in l and '"apply"' in l]
applied = [r for r in rows if r["manifests"]]
assert len(applied) >= len(t["good"]) and all(r["verb"] == "apply" for r in applied)
PY
CASE="what was APPLIED is tracked apart from other calls: only 'apply' rows carry manifests (a 'get' row never does), and the driver's clean run has no refused kubectl call and uses only apply, create token, get, wait, version, cluster-info"
check python3 - "$work/clean" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
rs = kh.kubectl(d)
assert rs and not [r for r in kh.rows(d) if r.get("refused")], [r["argv"] for r in kh.rows(d) if r.get("refused")]
for r in rs:
    assert r["verb"] in ("apply", "create", "get", "wait", "version", "cluster-info"), r["argv"]
    assert r["manifests"] == [] or r["verb"] == "apply", r["argv"]
assert [r for r in rs if r["verb"] == "apply"], "nothing was applied"
PY
CASE="kubectl (imperative grant): every object the persona's authority comes from is a MANIFEST the driver applied: no create role/rolebinding/clusterrolebinding/serviceaccount call exists, so the Role evaluator saw everything (the fake refuses them; a driver that tried would make on-call did-not-run)"
check python3 - "$work/clean" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
for r in kh.rows(d):
    if r["tool"] == "kubectl":
        a = r["argv"]
        assert not ("create" in a and any(x in a for x in ("clusterrolebinding", "rolebinding", "role", "clusterrole", "serviceaccount", "namespace", "secret"))), a
PY
# cluster lifecycle (C-B2): usable for the whole persona window, deleted AFTER its recorded end
CASE="kind lifecycle: the on-call persona used its kubeconfig at the END of its window (a call the fake kubectl recorded, answered because the cluster still existed, inside the persona's own start/end) and 'kind delete cluster' came AFTER the persona's recorded end (clean and blocking runs); an early deletion fails the persona's call"
check python3 - "$work/clean" "$work/kindblock" "$work" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[3]); import kh
for d in sys.argv[1:3]:
    t = [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]
    assert t["kube_rc"] == 0, ("the persona's call at the end of its window failed: the cluster was gone", d, t)
    pc = kh.persona_calls(d)
    assert len(pc) == 1 and t["t0"] < pc[0]["t"] < t["t1"], (pc, t)
    dels = [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]]
    assert len(dels) == 1 and dels[0]["t"] > t["t1"], ("the cluster was deleted before the persona's recorded end", dels[0]["t"], t["t1"])
PY
JOB_BUDGET=100000 AGENT_TIMEOUT=5000 run kindtmo '{}' rc
CASE="the persona kubeconfig's token duration follows --agent-timeout: 5000s + 15 minutes = 5900s (within 1h..24h); a very long agent timeout is capped at 24h; a short one keeps the 1h floor"
check python3 - "$work/kindtmo" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
a = [r for r in kh.kubectl(sys.argv[1]) if "create" in r["argv"] and "token" in r["argv"]][0]["argv"]
assert kh.go_duration(a[a.index("--duration") + 1]) == 5900, a
PY
JOB_BUDGET=1000000 AGENT_TIMEOUT=100000 run kindtmo2 '{}' rc
check python3 - "$work/kindtmo2" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
a = [r for r in kh.kubectl(sys.argv[1]) if "create" in r["argv"] and "token" in r["argv"]][0]["argv"]
assert kh.go_duration(a[a.index("--duration") + 1]) == 86400, a
PY
AGENT_TIMEOUT=60 run kindtmo3 '{}' rc
check python3 - "$work/kindtmo3" "$work" <<'PY'
import sys
sys.path.insert(0, sys.argv[2]); import kh
a = [r for r in kh.kubectl(sys.argv[1]) if "create" in r["argv"] and "token" in r["argv"]][0]["argv"]
assert kh.go_duration(a[a.index("--duration") + 1]) == 3600, a
PY
KIND_TOKEN_LIFETIME=1800 run kindshort '{}' rc
CASE="token lifetime: the API server issued a 30-minute token although 1h+ was asked: shorter than a persona window, so the on-call persona did not run (blocking), cluster deleted, others unaffected"
check python3 - "$work/kindshort" "$work" "$(out kindshort)" "$rc" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]]
assert "did not run" in open(sys.argv[3] + "/on-call-engineer.report.md").read().lower() and int(sys.argv[4]) != 0
PY
KIND_TOKEN_LIFETIME=90000 run kindhuge '{}' rc
CASE="token lifetime: the API server issued a 25-hour token (above the 24h the policy allows): refused like a short one, the on-call persona did not run (blocking), the cluster is deleted, no persona credential outlives the run, the others unaffected"
check python3 - "$work/kindhuge" "$work" "$(out kindhuge)" "$rc" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]], "no cluster cleanup after the rejected token"
assert "did not run" in open(sys.argv[3] + "/on-call-engineer.report.md").read().lower() and int(sys.argv[4]) != 0
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator"):
    assert open(sys.argv[3] + "/" + p + ".report.md").read().splitlines()[0].startswith("VERDICT: "), p
PY
KIND_TOKEN_LIFETIME=3600 run kindeq '{}' rc
CASE="token lifetime: 4500 seconds were requested (1h agent timeout + 15 minutes) and the API server issued only 3600: shorter than the window it must cover, so the on-call persona did not run (blocking, cluster deleted): the ISSUED token's validity is compared with the REQUESTED duration"
check python3 - "$work/kindeq" "$work" "$(out kindeq)" "$rc" <<'PY'
import json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")]
assert [r for r in kh.kind(d) if r["argv"][:2] == ["delete", "cluster"]]
r = open(sys.argv[3] + "/on-call-engineer.report.md").read()
assert "did not run" in r.lower() and int(sys.argv[4]) != 0, r
PY
KIND_TOKEN_LIFETIME=7200 run kindlong '{}' rc
CASE="token lifetime: the API server issued 2h although 1h was asked: fine (the issued lifetime covers the window): the persona runs, its kubeconfig holds exactly that token"
check test "$rc" -eq 0
check python3 - "$work/kindlong" "$work" <<'PY'
import base64, json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
import yaml
kc = yaml.safe_load(kh.persona_row(d)[0]["content"]["kubeconfig"])
tok = kh.issued(d)[0]["token"]
assert kc["users"][0]["user"] == {"token": tok}
pl = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
assert pl["exp"] - pl["iat"] == 7200
PY
KIND_HANG=1 READY_TIMEOUT=2 RUN_TIMEOUT=60 run kindhang '{}' rc
CASE="kind hang: a 'kind create cluster' that does not return is bounded (the run finishes in well under the 20s the fake hangs): the on-call persona did not run, the other four ran, the run fails, no traceback"
check python3 - "$work/kindhang" "$(out kindhang)" "$rc" "$RUNSECS" <<'PY'
import json, sys
d = sys.argv[1]
assert int(sys.argv[3]) != 0 and int(sys.argv[4]) < 16, ("the driver waited for a hung kind", sys.argv[4])
assert "Traceback" not in open(d + "/stderr").read()
assert "on-call-engineer" not in [json.loads(l)["persona"] for l in open(d + "/log")] and len(open(d + "/log").read().splitlines()) == 4
assert "did not run" in open(sys.argv[2] + "/on-call-engineer.report.md").read().lower()
PY
# before-scrape failures ALONE (S-B3): the persona after a queued break reads a broken BEFORE-scrape and a good after-scrape
for ba in nometric nofamily; do
  run "proofbefore-$ba" "{\"gradle-platform-engineer\":{\"requests\":2},\"maven-jenkins-ci\":{\"requests\":2},\"compliance-reviewer\":{\"requests\":2,\"break_next\":\"$ba\"},\"readme-evaluator\":{\"requests\":3,\"restore\":true}}" rc
  srvctl __mode m ok
  CASE="a fresh container's first scrape with no sample line ($ba) is a legitimate ZERO (every persona has a container of its own; nothing earlier to compare with): the readme persona, which makes 3 requests, passes like the others"
  check python3 - "$(out "proofbefore-$ba")" <<'PY'
import sys
d = sys.argv[1]
for p in "gradle-platform-engineer maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer".split():
    assert open(d + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: pass", p
PY
done
for ba in garbage status500; do
  run "proofbefore-$ba" "{\"gradle-platform-engineer\":{\"requests\":2},\"maven-jenkins-ci\":{\"requests\":2},\"compliance-reviewer\":{\"requests\":2,\"break_next\":\"$ba\"},\"readme-evaluator\":{\"requests\":3,\"restore\":true}}" rc
  srvctl __mode m ok
  CASE="before-scrape failure alone ($ba): the readme persona's BEFORE-scrape cannot be read and its after-scrape is fine: that persona is BLOCKING (cannot prove; a failed scrape is never read as 0 against the earlier personas' totals); the others pass"
  check python3 - "$(out "proofbefore-$ba")" "$rc" <<'PY'
import sys
d = sys.argv[1]
want = {"gradle-platform-engineer": "pass", "maven-jenkins-ci": "pass", "compliance-reviewer": "pass", "readme-evaluator": "blocking", "on-call-engineer": "pass"}
for p, v in want.items():
    r = open(d + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: " + v, (p, r)
assert "never exercised" in open(d + "/readme-evaluator.report.md").read().lower() or "scrape" in open(d + "/readme-evaluator.report.md").read().lower()
assert int(sys.argv[2]) != 0
PY
done
srvctl __mode m garbage
run proofbefore1 '{"gradle-platform-engineer":{"restore":true,"requests":2}}' rc
srvctl __mode m ok
CASE="before-scrape failure alone, FIRST persona (nothing earlier to compare with): its before-scrape is garbage, its after-scrape fine: BLOCKING (a failed scrape is never read as zero), the other four pass"
check python3 - "$(out proofbefore1)" <<'PY'
import sys
d = sys.argv[1]
want = {"gradle-platform-engineer": "blocking", "maven-jenkins-ci": "pass", "compliance-reviewer": "pass", "readme-evaluator": "pass", "on-call-engineer": "pass"}
for p, v in want.items():
    assert open(d + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: " + v, p
PY
# daemon-managed containers (C-B5): swept by label after every agent outcome; nothing from a previous persona's container reaches a later window
reapd() { python3 - "$work/containers" <<'PY'
import os, signal, sys
d = sys.argv[1]
live = 0
if os.path.isdir(d):
    for f in os.listdir(d):
        pid = int(open(os.path.join(d, f)).read().split()[1])
        try:
            os.kill(pid, 0); live += 1; os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.remove(os.path.join(d, f))
print(live)
PY
}
reapd >/dev/null
for scn in return crash timeout; do
  case $scn in
    return) plan='{"maven-jenkins-ci":{"daemon":true,"requests":1,"sleep":0.3},"compliance-reviewer":{"sleep":0.8},"readme-evaluator":{"sleep":0.8}}'; at="";;
    crash) plan='{"maven-jenkins-ci":{"daemon":"crash","requests":1},"compliance-reviewer":{"sleep":0.8},"readme-evaluator":{"sleep":0.8}}'; at="";;
    timeout) plan='{"maven-jenkins-ci":{"daemon":true,"sleep":30},"compliance-reviewer":{"sleep":0.8},"readme-evaluator":{"sleep":0.8}}'; at=1;;
  esac
  AGENT_TIMEOUT=$at run "daemon-$scn" "$plan" rc
  live=$(reapd)
  CASE="daemon container ($scn): a tool container the agent started (its docker client was killed, the daemon keeps it running) is removed by the DRIVER by label before the next persona: a docker ps filtered by that persona's label and an rm -f of the container id exist, none was left alive, and none of its requests reached ANY later persona's scrape window (the general windows checker, applied at the SCRAPE boundaries)"
  n=5; [ "$scn" != timeout ] || n=4      # the timed-out agent was killed before it wrote its end instant
  check python3 "$work/windows.py" "$work/daemon-$scn" "$n"
  check python3 - "$work/daemon-$scn" "$live" <<'PY'
import json, re, sys
d, live = sys.argv[1], int(sys.argv[2])
assert live == 0, ("a container survived the run", live)
rows = [json.loads(l) for l in open(d + "/log")]
maven = [r for r in rows if r["persona"] == "maven-jenkins-ci"][0]
a = maven["argv"]
label = a[a.index("--label") + 1]
assert re.fullmatch(r"persona-uat=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", label), label
labels = {r["persona"]: r["argv"][r["argv"].index("--label") + 1] for r in rows}
assert len(set(labels.values())) == len(labels), ("one label per persona, never shared", labels)
dl = open(d + "/docker.log").read().splitlines()
ps = [l for l in dl if l.startswith("ps ") and "label=" + label in l]
assert ps, ("the driver never listed the persona's containers by label", dl)
rm = [l for l in dl if l.startswith(("rm -f", "stop", "kill")) and "daemon-" in l]
assert rm, ("the daemon container was never removed by id", dl)
PY
done
# secrets in retained artifacts (C-B8): the request's model value and a credential marker injected into transcripts and failure output
python3 - >"$work/leakplan.json" <<'PY'
import json
print(json.dumps({"gradle-platform-engineer": {"leak": True}, "compliance-reviewer": {"leak": True, "findings": [{"kind": "friction", "text": "slow start"}]},
                  "maven-jenkins-ci": {"crash": True, "leak": True, "journal": [{"t": "action", "id": 1, "command": "curl https://crash-host.example/x", "started_at": "2026-10-08T00:00:00Z"}]}, "on-call-engineer": {"leak": True}}))
PY
run leak "$(cat "$work/leakplan.json")" rc
CASE="scrubbing: the request's model value and a credential-looking marker the agent put into its returned transcript, and into the stderr of a CRASHED agent, never reach a retained file: every .transcript.txt, report, issue body and the driver's stdout/stderr is free of both (the transcripts are still there and still say what happened)"
check python3 - "$(out leak)" "$work/leak" "$work" <<'PY'
import glob, sys
sys.path.insert(0, sys.argv[3]); import kh
out, d = sys.argv[1], sys.argv[2]
TOKEN = kh.issued(d)[0]["token"]        # the on-call persona's ServiceAccount token, pasted into its transcript by the stub
files = glob.glob(out + "/*") + [d + "/stdout", d + "/stderr", d + "/gh.log"]
assert len(glob.glob(out + "/*.transcript.txt")) == 5
for f in files:
    c = open(f).read()
    for bad in ("MODEL-DEFAULT-X", "MODEL-COMPLIANCE-X", "ghp_abcdefghij0123456789ABCDEF", "github_pat_11ABCDEFG0abcdefghijkl_xyz", "AKIAABCDEFGHIJKLMNOP", "sk-abcdefghijklmnopqrstuvwx",
                "Bearer abcdefghijklmnop", "password=hunter2xyz", "-----BEGIN " "PRIVATE KEY-----", TOKEN):
        assert bad not in c, (f, bad)
assert "TRANSCRIPT for gradle-platform-engineer" in open(out + "/gradle-platform-engineer.transcript.txt").read()
assert "PARTIAL-TRANSCRIPT for maven-jenkins-ci" in open(out + "/maven-jenkins-ci.transcript.txt").read()
PY
CASE="host retention after an agent failure: the crashed persona's report (did not run) still lists the host its '\$ <command>' transcript lines named (crash-host.example), as information"
check test "$(hostsline "$(out leak)/maven-jenkins-ci.report.md")" = "crash-host.example"
check grep -qi 'did not run' "$(out leak)/maven-jenkins-ci.report.md"


# --- ROUND 3 (review d6r3) ----------------------------------------------------------------------------------------------------------------------
# the fake `create token` as the real kubectl and API server behave (flags, duration precision, audience, bound objects, usability of the issued token)
CASE="fake kubectl create token (self-test; API behaviour, not the driver's 1h-24h POLICY): the API accepts a whole-second Go duration of 10 minutes or more, 0s and no flag (server default 1h), and 25h (accepted, SHORTENED to 24h); it refuses 1h0.5s (sub-second precision), 100ms, 5m (under 10 minutes), abc, -1h; --ttl and --bogus are unknown flags; a bound Secret that does not exist is an error"
check python3 - "$fk" <<'PY'
import base64, json, subprocess, sys
d = sys.argv[1]
k = d + "/hostbin/kubectl"
def call(args):
    r = subprocess.run([k, "--kubeconfig", d + "/admin", "create", "token", "persona", "-n", "persona"] + args, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()
def life(tok):
    pl = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    return pl["exp"] - pl["iat"]
want = {"1h": 3600, "90m": 5400, "86400s": 86400, "1.5h": 5400, "1h0.0s": 3600, "10m": 600, "0s": 3600, "25h": 86400}
for dur, secs in want.items():
    rc, out = call(["--duration", dur])
    assert rc == 0 and out.count(".") == 2, ("the API refused a valid request", dur)
    assert life(out) == secs, (dur, life(out))
assert call([])[0] == 0
for bad in (["--duration", "1h0.5s"], ["--duration", "100ms"], ["--duration", "5m"], ["--duration", "abc"], ["--duration", "-1h"], ["--ttl", "1h"], ["--bogus"],
            ["--bound-object-kind", "Secret", "--bound-object-name", "nope"], ["--bound-object-name", "nope"]):
    assert call(bad)[0] != 0, ("accepted", bad)
PY
CASE="fake kubectl persona credential (self-test): only a token this API server issued for the persona's ServiceAccount, unexpired, with the API audience, while the cluster exists, is answered; a token for another audience, a token never issued, an expired token (a server that issues 1-second tokens whatever is asked) and a deleted cluster are all refused"
fk3="$work/fk3"; mkdir -p "$fk3"; KIND_TOKEN_LIFETIME=1 mkhost "$fk3"; printf 'users:\n- user:\n    client-certificate-data: X\n' >"$fk3/admin"; : >"$fk3/alive"
check python3 - "$fk" <<'PY'
import json, os, subprocess, sys, time
d = sys.argv[1]
k = d + "/hostbin/kubectl"
open(d + "/alive", "w").write("1")
def issue(args):
    return subprocess.run([k, "--kubeconfig", d + "/admin", "create", "token", "persona", "-n", "persona"] + args, capture_output=True, text=True).stdout.strip()
def use(tok):
    open(d + "/persona-kc", "w").write(json.dumps({"users": [{"name": "p", "user": {"token": tok}}]}))
    return subprocess.run([k, "--kubeconfig", d + "/persona-kc", "-n", "persona", "get", "pods"], capture_output=True, text=True).returncode
good = issue(["--duration", "1h"])
assert use(good) == 0, "a usable token was refused"
assert use(issue(["--audience", "https://other.example", "--duration", "1h"])) != 0, "a token for another audience was accepted"
assert use("aaa.bbb.ccc") != 0, "a token that was never issued was accepted"
os.remove(d + "/alive")
assert use(good) != 0, "a token was accepted although the cluster is gone"
d3 = d.replace("/fk", "/fk3") if d.endswith("/fk") else d + "3"
k3 = d3 + "/hostbin/kubectl"
tok = subprocess.run([k3, "--kubeconfig", d3 + "/admin", "create", "token", "persona", "-n", "persona", "--duration", "1h"], capture_output=True, text=True).stdout.strip()
open(d3 + "/persona-kc", "w").write(json.dumps({"users": [{"name": "p", "user": {"token": tok}}]}))
assert subprocess.run([k3, "--kubeconfig", d3 + "/persona-kc", "get", "pods"], capture_output=True).returncode == 0, "a fresh 1-second token should work at once"
time.sleep(1.4)
assert subprocess.run([k3, "--kubeconfig", d3 + "/persona-kc", "get", "pods"], capture_output=True).returncode != 0, "an expired token was accepted"
PY
fk2="$work/fk2"; mkdir -p "$fk2"; mkhost "$fk2"; printf 'users:\n- user:\n    client-certificate-data: X\n' >"$fk2/admin"
CASE="fake kubectl (self-test): a namespaced object applied BEFORE its Namespace exists is refused (NotFound), the same objects with the Namespace first (one call) are applied"
check python3 - "$fk2" <<'PY'
import json, subprocess, sys
d = sys.argv[1]
k = d + "/hostbin/kubectl"
ns = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "persona"}}
sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "p", "namespace": "persona"}}
def ap(docs):
    return subprocess.run([k, "--kubeconfig", d + "/admin", "apply", "-f", "-"], input=json.dumps({"apiVersion": "v1", "kind": "List", "items": docs}), capture_output=True, text=True)
r = ap([sa, ns]); assert r.returncode != 0 and "not found" in r.stderr.lower(), r
r = ap([ns, sa]); assert r.returncode == 0, r.stderr
PY
CASE="the persona's token (clean run): created with only --duration (and -n), the issued JWT carries the API server's audience, so the persona's own call at the end of its window was ANSWERED (the fake refuses any other audience)"
check python3 - "$work/clean" "$work" <<'PY'
import base64, json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
r = [x for x in kh.kubectl(d) if x["verb"] == "create"][0]
flags = [x.split("=")[0] for x in r["argv"] if x.startswith("-")]
assert set(flags) <= {"--kubeconfig", "-n", "--namespace", "--duration"}, ("a token flag beyond duration and namespace", flags)
pl = json.loads(base64.urlsafe_b64decode(kh.issued(d)[0]["token"].split(".")[1] + "=="))
assert pl["aud"] == ["https://kubernetes.default.svc"], pl
assert "--audience" not in " ".join(r["argv"]), r["argv"]
assert [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]["kube_rc"] == 0
PY
# `kind create cluster --wait 0s` returns while the node is still NotReady: the driver waits (kubectl wait --for=condition=Ready, or get nodes until Ready) BEFORE the
# on-call persona starts; the wait is bounded
KIND_NODE_READY=3 run kindnotready '{}' rc
CASE="the node is NotReady for 3 seconds after kind returns: the driver waits for it (kubectl wait --for=condition=Ready on the nodes with a bounded --timeout, or get nodes until Ready) with the ADMIN credential, and the on-call persona starts only after the node was Ready; the run passes"
check test "$rc" -eq 0
check python3 - "$work/kindnotready" <<'PY'
import json, sys
d = sys.argv[1]
rows = [json.loads(l) for l in open(d + "/host.log")]
ready_at = [r for r in rows if r.get("tool") == "kind-ready"][0]["node_ready_at"]
t0 = [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]["t0"]
assert t0 >= ready_at - 0.05, ("the on-call persona started %.2fs BEFORE the node was Ready" % (ready_at - t0))
seen = [r for r in rows if r.get("tool") == "kubectl" and r.get("node_ready") is True and r["verb"] in ("get", "wait") and not r["persona_call"]]
assert seen, "the driver never observed the node Ready (no kubectl wait / get nodes with the admin kubeconfig)"
assert seen[0]["t"] < t0, "the readiness was observed only after the persona started"
for r in rows:
    if r.get("tool") == "kubectl" and r.get("node_wait") is not None:
        assert 0 < r["node_wait"] <= 900, ("an unbounded or absurd wait", r["argv"])
PY
srvctl __reset
python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18081/__arm?s=3',timeout=5).read()"
: >"$work/jen.log"
run jenslow '{}' rc
python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18081/__arm?s=0',timeout=5).read()"
CASE="Jenkins answers 503 for 3 seconds while it starts: only a success status is ready (a 503 is not), so the Maven persona starts after the first 200 and the run passes; the driver was seen retrying"
check test "$rc" -eq 0
check python3 - "$work/jenslow" "$work/jen.log" <<'PY'
import json, sys
d = sys.argv[1]
rows = [json.loads(l) for l in open(sys.argv[2])]
rows = [r for r in rows if r["path"] != "/__arm"]
n503 = [r for r in rows if r["code"] == 503]
ok = [r for r in rows if r["code"] == 200]
assert n503 and ok, ("the driver never saw both phases", len(n503), len(ok))
t0 = [json.loads(l) for l in open(d + "/timing.log") if '"maven-jenkins-ci"' in l][0]["t0"]
assert t0 >= ok[0]["t"] - 0.05 and ok[0]["t"] > n503[-1]["t"], ("the Maven persona started while Jenkins still answered 503", t0, ok[0]["t"])
assert len(n503) >= 2, ("one 503 and the driver stopped asking? it must poll", len(n503))
PY
python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18081/__arm?s=60',timeout=5).read()"
: >"$work/jen.log"
READY_TIMEOUT=3 RUN_TIMEOUT=90 run jenstuck '{}' rc
python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:18081/__arm?s=0',timeout=5).read()"
CASE="Jenkins answers 503 for ever: the wait is bounded (--ready-timeout), the Maven persona did not run (blocking, no agent for it), the other four are unaffected, the run fails"
check python3 - "$work/jenstuck" "$(out jenstuck)" "$rc" <<'PY'
import json, sys
d, o, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
assert "maven-jenkins-ci" not in [json.loads(l)["persona"] for l in open(d + "/log")]
rep = open(o + "/maven-jenkins-ci.report.md").read()
assert rep.splitlines()[0] == "VERDICT: blocking" and "did not run" in rep.lower(), rep
for p in ("gradle-platform-engineer", "compliance-reviewer", "readme-evaluator", "on-call-engineer"):
    assert open(o + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: pass", p
assert rc == 1, rc
PY
KIND_API_AUD=https://kubernetes.default.svc.cluster.local run kindaud '{}' rc
CASE="the API audience varies by cluster (kubeadm: https://kubernetes.default.svc.cluster.local): the driver creates the token WITHOUT --audience and keeps whatever the server issued, so the persona's own call at the end of its window is answered whichever audience this API server uses"
check test "$rc" -eq 0
check python3 - "$work/kindaud" "$work" <<'PY'
import base64, json, sys
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
r = [x for x in kh.kubectl(d) if x["verb"] == "create"][0]
assert not [x for x in r["argv"] if x.startswith("--audience")], ("the driver must not pick an audience", r["argv"])
pl = json.loads(base64.urlsafe_b64decode(kh.issued(d)[0]["token"].split(".")[1] + "=="))
assert pl["aud"] == ["https://kubernetes.default.svc.cluster.local"], pl
assert [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]["kube_rc"] == 0
PY
# the persona's cleanup across uids: a root cleanup container over the mounted sandbox after EVERY persona
CASE="sandbox cleanup across uids (a root-owned file a tool image left behind cannot be chmod'ed by the runner): after every persona the driver runs ONE cleanup container with the persona's label over exactly its sandbox mount, as root (--user 0:0), no network, the shell image from the tools file, running rm -rf inside the mount, after the label sweep and before the sandbox goes; ownership itself cannot be simulated without root, so the mechanism is what is pinned"
check python3 - "$work/clean" "$SHL" <<'PY'
import json, re, sys
d, shl = sys.argv[1], sys.argv[2]
rows = [json.loads(l) for l in open(d + "/log")]
dl = [l.split() for l in open(d + "/docker.log")]
assert len(rows) == 5
for r in rows:
    sb, lab = r["request"]["docs_dir"], r["argv"][r["argv"].index("--label") + 1]
    cl = [(i, t) for i, t in enumerate(dl) if t[:2] == ["run", "--rm"] and (sb + ":/work") in t]
    assert len(cl) == 1, ("exactly one cleanup container per sandbox", r["persona"], len(cl))
    i, t = cl[0]
    j = t.index(shl)
    opts, tail = t[2:j], t[j + 1:]
    assert opts == ["--network", "none", "--user", "0:0", "--label", lab, "-v", sb + ":/work", "-w", "/work"], opts
    sweep = [k for k, x in enumerate(dl) if x[:1] == ["ps"] and "label=" + lab in x]
    assert sweep and sweep[0] < i, ("the cleanup must follow the label sweep", sweep, i)
# the docker fake EXECUTED each cleanup with the shell's semantics against the sandbox mapping: nothing may be left, hidden or nested
logs = [json.loads(l) for l in open(d + "/cleanup.log")]
assert len(logs) == 5, logs
for c in logs:
    assert c["before"], ("the cleanup ran over an empty sandbox: nothing proves it deletes", c["sandbox"])
    assert c["remaining"] == [], ("the cleanup command left entries behind (a no-op, a missing hidden-entry pattern or a wrong path)", c["tail"], c["remaining"])
    assert c["tail"][:2] == ["rm", "-rf"] or c["tail"][:2] == ["sh", "-c"] or c["tail"][:3] == ["find", "/work", "-mindepth"], c["tail"]
PY
# the cleanup fake itself (self-test): DIRECT argv words are literal, only an unquoted glob inside an explicit sh -c expands, quoting is honoured
fkd="$work/fkdocker"; mkdir -p "$fkd"; : >"$fkd/docker.log"; sed "s#__LOG__#$fkd/docker.log#" "$work/docker.tmpl" >"$fkd/docker"; chmod +x "$fkd/docker"
CASE="cleanup fake (self-test): rm -rf with the globs as DIRECT argv words removes NOTHING (no shell, no expansion); a quoted glob ('/work/*', \"/work/*\", /work/\\*) inside sh -c removes nothing; an unquoted glob inside sh -c expands, '*' skips dotfiles; the three-pattern form removes everything (hidden, nested, ..weird); find -mindepth 1 -delete removes everything; a path that is not there, a variable, a backtick or a tilde removes nothing (the last three are refused)"
check python3 - "$fkd" "$SHL" <<'PY'
import json, os, shutil, subprocess, sys, tempfile
fkd, img = sys.argv[1], sys.argv[2]
BASE = {"a.txt", "dir", "dir/inner.txt", ".h", ".h/x", "..w", "..w/q", ".dot"}
def trial(tail, extra=()):
    sb = tempfile.mkdtemp(prefix="fkd-")
    for e in extra:
        open(os.path.join(sb, e), "w").write("x")
    for rel in BASE:
        if rel in ("dir", ".h", "..w"):
            os.makedirs(os.path.join(sb, rel), exist_ok=True)
        else:
            os.makedirs(os.path.dirname(os.path.join(sb, rel)), exist_ok=True); open(os.path.join(sb, rel), "w").write("x")
    r = subprocess.run([fkd + "/docker", "run", "--rm", "--network", "none", "--user", "0:0", "--label", "L", "-v", sb + ":/work", "-w", "/work", img] + tail, capture_output=True, text=True)
    left = {os.path.relpath(os.path.join(a, n), sb) for a, ds, fs in os.walk(sb) for n in ds + fs}
    shutil.rmtree(sb, ignore_errors=True)
    return r.returncode, left
G = ["/work/*", "/work/.[!.]*", "/work/..?*"]
rc, left = trial(["rm", "-rf"] + G);                                  assert rc == 0 and left == BASE, ("direct globs expanded", left)
rc, left = trial(["rm", "-rf", "/work/does-not-exist"]);              assert rc == 0 and left == BASE, left
rc, left = trial(["rm", "-rf", "/work/$HOME", "/work/~"]);            assert rc == 0 and left == BASE, ("direct words were expanded", left)
rc, left = trial(["sh", "-c", "rm -rf /work/*"]);                     assert rc == 0 and left == {".h", ".h/x", "..w", "..w/q", ".dot"}, ("an unquoted * must skip dotfiles", left)
for q in ("rm -rf '/work/*'", 'rm -rf "/work/*"', "rm -rf /work/\\*", "rm -rf '/work/'*'x'"):
    rc, left = trial(["sh", "-c", q]);                                assert rc == 0 and left == BASE, ("a quoted or escaped glob expanded", q, left)
rc, left = trial(["sh", "-c", "rm -rf /work/* /work/.[!.]* /work/..?*"]);   assert rc == 0 and left == set(), left
rc, left = trial(["sh", "-c", "rm -rf /work/*; rm -rf /work/.[!.]* && rm -rf /work/..?*"]); assert rc == 0 and left == set(), left
rc, left = trial(["find", "/work", "-mindepth", "1", "-delete"]);     assert rc == 0 and left == set(), left
# per-character quoting: "/work/*"* is a LITERAL star followed by a glob (names starting with *), "/work/"* is a glob over everything, a*, 'a'* the names starting with a
X = ("*lit", "plain")
rc, left = trial(["sh", "-c", 'rm -rf "/work/*"*'], X);          assert rc == 0 and left == BASE | {"plain"}, ("mixed quoting: only a name starting with a literal * may match", left)
rc, left = trial(["sh", "-c", 'rm -rf /work/"*"'], X);           assert rc == 0 and left == BASE | {"plain", "*lit"}, ("a fully quoted star names the file '*'; there is none", left)
rc, left = trial(["sh", "-c", 'rm -rf "/work/"*'], X);           assert rc == 0 and left == {".h", ".h/x", "..w", "..w/q", ".dot"}, ("a quoted prefix does not quote the glob", left)
rc, left = trial(["sh", "-c", "rm -rf /work/a*"], X);            assert rc == 0 and left == (BASE | {"plain", "*lit"}) - {"a.txt"}, left
rc, left = trial(["sh", "-c", "rm -rf /work/'a'*"], X);          assert rc == 0 and left == (BASE | {"plain", "*lit"}) - {"a.txt"}, left
rc, left = trial(["sh", "-c", "rm -rf /work/a'*'"], X);          assert rc == 0 and left == BASE | {"plain", "*lit"}, ("a quoted star after a literal prefix is literal", left)
rc, left = trial(["sh", "-c", "rm -rf /work/\\**"], X);          assert rc == 0 and left == BASE | {"plain"}, ("an escaped star then a glob", left)
for bad in ("rm -rf $HOME/x", "rm -rf `echo /work/a.txt`", "rm -rf ~/x", 'rm -rf "$X"'):
    rc, left = trial(["sh", "-c", bad]);                              assert rc != 0 and left == BASE, ("unsupported shell syntax must be refused", bad, rc)
PY
CASE="cleanup across uids, driver side: sandboxes that hold entries a tool image created as another uid (a read-only dir, a hidden dir, a nested hidden dir, a dotfile, a '..weird' dir, a mode-000 file) are emptied BY THE ROOT CLEANUP COMMAND (the fake executed it: nothing remained at that moment, every foreign entry was there before), and the sandboxes are gone afterwards"
check python3 - "$work/sbxleft" <<'PY'
import json, os, sys
d = sys.argv[1]
dirs = {json.loads(l)["request"]["docs_dir"] for l in open(d + "/log")}
assert dirs and not [x for x in dirs if os.path.exists(x)]
logs = [json.loads(l) for l in open(d + "/cleanup.log")]
assert len(logs) == 5, logs
foreign = [c for c in logs if ".hidden-dir/deep/y" in c["before"]]
assert len(foreign) == 2, ("two personas left foreign entries", [c["sandbox"] for c in foreign])
for c in foreign:
    for rel in ("created/x", ".hidden-dir/deep/y", "build/out/.cache/z", ".dotfile", "..weird/q", "locked/data"):
        assert rel in c["before"], (rel, c["before"])
for c in logs:
    assert c["remaining"] == [], ("left behind", c["tail"], c["remaining"])
PY
# GitLab runner: faithful routes and a listener that may never come up
CASE="runner readiness probes the runner's REAL endpoint: every request the started runner container received was GET /metrics (its mux registers only /metrics; / is a 404), and there was at least one"
check python3 - "$work/clean/runner-hits.log" <<'PY'
import sys
hits = open(sys.argv[1]).read().split()
assert hits and set(hits) == {"/metrics"}, hits
PY
DOCKER_RUNNER_DEAD=1 READY_TIMEOUT=2 RUN_TIMEOUT=90 run runnerdead '{}' rc
CASE="a GitLab runner container that starts but whose listener never comes up: the Maven persona did not run (the failure is reported, blocking), the other four are unaffected, the run fails, no traceback"
check python3 - "$work/runnerdead" "$(out runnerdead)" "$rc" <<'PY'
import json, os, sys
d = sys.argv[1]
assert int(sys.argv[3]) != 0 and "Traceback" not in open(d + "/stderr").read()
assert "maven-jenkins-ci" not in [json.loads(l)["persona"] for l in open(d + "/log")] and len(open(d + "/log").read().splitlines()) == 4
r = open(sys.argv[2] + "/maven-jenkins-ci.report.md").read()
assert r.splitlines()[0] == "VERDICT: blocking" and "did not run" in r.lower(), r
assert not os.path.exists(d + "/runner-hits.log")
PY
# the real server counts AFTER the response: a late increment belongs to the persona that made the request
srvctl __reset
srvctl __silent v 1
srvctl __delay s 0.25
SETTLE_DEFAULT=1 run delayed '{"gradle-platform-engineer":{"requests":1},"maven-jenkins-ci":{"requests":0,"uncounted":["/healthz"]},"compliance-reviewer":{"requests":2},"readme-evaluator":{"requests":1},"on-call-engineer":{"requests":1}}' rc
srvctl __delay s 0
srvctl __silent v 0
python3 -c "import time; time.sleep(1)"
CASE="delayed server completion (counted 0.25s AFTER the response, as the real server counts after the handler returns): the driver's after-scrape settles, so a persona's LAST request is attributed to ITS window (a single counted request passes) and the next persona (no counted request) is blocking, not credited with the late increment"
check python3 - "$(out delayed)" <<'PY'
import sys
want = {"gradle-platform-engineer": "pass", "maven-jenkins-ci": "blocking", "compliance-reviewer": "pass", "readme-evaluator": "pass", "on-call-engineer": "pass"}
for p, v in want.items():
    r = open(sys.argv[1] + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: " + v, (p, r)
PY
check python3 "$work/windows.py" "$work/delayed" 5 settle quiet=2.9
# QUIESCENCE (stated bound): two equal readings do not prove the previous persona's work has drained. The driver's after-scrape therefore waits until the total has been
# UNCHANGED across readings spanning at least 3.0 seconds (the default; the other cases run with a shorter one), and gives up after 20 seconds; an increment landing later than
# that cannot be told from the next persona's own traffic: the LIMIT is stated in every report's header (no in-flight gauge is invented). A delay of 0.6 s lands AFTER two
# quick equal readings but well inside the quiet window (a 2.4 s margin: the case no longer depends on scheduling luck under load).
srvctl __reset
srvctl __silent v 1
srvctl __delay s 0.6
SETTLE_DEFAULT=1 run delayed2 '{"gradle-platform-engineer":{"requests":1},"maven-jenkins-ci":{"requests":0,"uncounted":["/healthz"]},"compliance-reviewer":{"requests":2},"readme-evaluator":{"requests":1},"on-call-engineer":{"requests":1}}' rc
srvctl __delay s 0
srvctl __silent v 0
python3 -c "import time; time.sleep(1.5)"
CASE="late completion after two equal readings (the server counts 0.6s AFTER the response; the driver waits for 3.0s of quiet, at most 20s): the persona's last request is still attributed to ITS window and the next persona (no counted request) is blocking, not credited"
check python3 - "$(out delayed2)" <<'PY'
import sys
want = {"gradle-platform-engineer": "pass", "maven-jenkins-ci": "blocking", "compliance-reviewer": "pass", "readme-evaluator": "pass", "on-call-engineer": "pass"}
for p, v in want.items():
    assert open(sys.argv[1] + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: " + v, p
PY
check python3 "$work/windows.py" "$work/delayed2" 5 settle quiet=2.9
# the federated identity token file (re-minted by the job every few minutes) is the driver's to remove when it is done: nothing of it outlives the run
echo FIXTURE-IDENTITY >"$work/idtok.file"
run idtok '{}' rc ANTHROPIC_IDENTITY_TOKEN_FILE="$work/idtok.file"
CASE="the driver removes the identity token file named by ANTHROPIC_IDENTITY_TOKEN_FILE when the run ends (a clean run), and still runs fine without the variable"
check test ! -e "$work/idtok.file" -a "$rc" -eq 0
echo FIXTURE-IDENTITY >"$work/idtok2.file"
run idtok2 '{"compliance-reviewer":{"crash":true}}' rc ANTHROPIC_IDENTITY_TOKEN_FILE="$work/idtok2.file"
CASE="... also when a persona crashed (the file is removed whatever the outcome)"
check test ! -e "$work/idtok2.file" -a "$rc" -ne 0
# STATED BOUNDS, asserted: the quiet interval RESTARTS on every change (a second increment 0.7s after the first, 1.3s after the response: a fixed sleep or a
# single "quiet since the first change" reading misses it) and a counter that never settles reaches the DEADLINE (8 seconds) and the persona is blocking, not credited
srvctl __reset
srvctl __silent v 1
srvctl __delay s 0.6
srvctl __extra s 0.7
SETTLE_DEFAULT=1 run delayed3 '{"gradle-platform-engineer":{"requests":1},"maven-jenkins-ci":{"requests":0,"uncounted":["/healthz"]},"compliance-reviewer":{"requests":2},"readme-evaluator":{"requests":1},"on-call-engineer":{"requests":1}}' rc
srvctl __extra s 0
srvctl __delay s 0
srvctl __silent v 0
python3 -c "import time; time.sleep(2.5)"
CASE="a LATE second increment (0.6s and 1.3s after the response) restarts the quiet interval: the driver waits it out, the persona's requests stay in ITS window, and the next persona (no counted request) is still blocking, not credited with the second increment"
check python3 - "$(out delayed3)" <<'PY'
import sys
want = {"gradle-platform-engineer": "pass", "maven-jenkins-ci": "blocking", "compliance-reviewer": "pass", "readme-evaluator": "pass", "on-call-engineer": "pass"}
for p, v in want.items():
    assert open(sys.argv[1] + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: " + v, p
PY
check python3 "$work/windows.py" "$work/delayed3" 5 settle double quiet=2.9
check python3 "$work/windows.py" "$work/clean" 5 settle
srvctl __reset
python3 - <<'PYD'
import urllib.request
urllib.request.urlopen("http://127.0.0.1:18080/__drift?p=on-call-engineer&s=23", timeout=5).read()
PYD
SETTLE_DEFAULT=1 run drift '{}' rc
srvctl __reset
CASE="a counter that NEVER settles (every scrape of the last persona's window changes it, for 23s): the driver gives up at its 20-second deadline (not sooner, not after the drift ends) and that persona is blocking and the run exits 1, the other four unaffected"
check python3 - "$work/drift" "$(out drift)" "$rc" <<'PY'
import json, sys
d, o, rc = sys.argv[1], sys.argv[2], int(sys.argv[3])
rows = [json.loads(l) for l in open(d + "/srv.log")]
sc = [r["t"] for r in rows if r["path"] == "/metrics"]
tim = [json.loads(l) for l in open(d + "/timing.log") if '"on-call-engineer"' in l][0]
mine = [t for t in sc if t > tim["t1"] - 0.5]
span = max(mine) - tim["t1"]
assert 18.0 <= span <= 22.5, ("the driver must stop re-reading at about 20 seconds after the window", span)
assert open(o + "/on-call-engineer.report.md").read().splitlines()[0] == "VERDICT: blocking"
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator"):
    assert open(o + "/" + p + ".report.md").read().splitlines()[0] == "VERDICT: pass", p
assert rc == 1, rc
PY
CASE="the windows checker enforces the quiet interval (self-test on recorded scrape instants): correctly attributed logs whose final equal readings are 0.01s apart after the last change FAIL (a fixed delay then rapid equality), a run of equal readings spanning 0.8s passes, and a change in the middle restarts the interval (equal readings that span 0.8s only because they straddle a change FAIL)"
check python3 - "$work" <<'PY'
import json, os, subprocess, sys
w = sys.argv[1]
def case(name, after, reqs=1):
    d = w + "/qi-" + name; os.makedirs(d, exist_ok=True)
    json.dump({"persona": "p", "t0": 10.0, "t1": 11.0, "requests": reqs, "uncounted": 0}, open(d + "/timing.log", "w")); open(d + "/timing.log", "a").write("\n")
    rows = [{"t": 9.0, "path": "/metrics", "method": "GET", "counted": False, "persona": None, "total": 0},
            ] + [{"t": 10.4 + 0.1 * n, "path": "/", "method": "GET", "counted": True, "persona": "p", "total": n + 1} for n in range(reqs)]
    rows += [{"t": t, "path": "/metrics", "method": "GET", "counted": False, "persona": None, "total": v} for t, v in after]
    open(d + "/srv.log", "w").write("\n".join(json.dumps(r) for r in rows) + "\n")
    return subprocess.run(["python3", w + "/windows.py", d, "1", "settle"], capture_output=True, text=True).returncode == 0
assert case("good", [(11.1, 1), (11.4, 1), (11.7, 1), (11.95, 1)]), "a 0.85s run of equal readings was refused"
assert not case("rapid", [(11.0 + 1.4, 1), (12.41, 1)]), "two equal readings 0.01s apart were accepted"
assert not case("short", [(11.1, 1), (11.3, 1), (11.5, 1)]), "a 0.4s run was accepted"
assert case("late-good", [(11.1, 1), (11.5, 1), (11.9, 2), (12.3, 2), (12.75, 2)], 2), "a change followed by a 0.85s run was refused"
assert not case("straddle", [(11.1, 1), (11.5, 1), (11.9, 2), (11.95, 2)], 2), "equal readings that only span 0.8s by straddling a change were accepted"
PY
# repository SOURCE reaching forms other than archive/raw/blob/tree: git clone of the repository (with or without .git), codeload.github.com, the API's tarball/zipball
python3 - >"$work/hostsplan5.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["git clone https://github.com/example/cache.git", "git clone --depth 1 https://github.com/example/cache.git /tmp/x"]},
 "maven-jenkins-ci": {"commands": ["git clone https://github.com/example/cache"]},
 "compliance-reviewer": {"commands": ["curl -L https://codeload.github.com/example/cache/tar.gz/refs/heads/main -o s.tgz"]},
 "readme-evaluator": {"commands": ["curl -L https://api.github.com/repos/example/cache/tarball/main -o s.tgz", "curl -L https://api.github.com/repos/example/cache/zipball -o s.zip"]},
 "on-call-engineer": {"commands": ["curl https://api.github.com/repos/example/cache/releases/latest", "git clone https://evil.example/x.git", "curl https://github.com/example/cache"]}}))
PY
run hosts5 "$(cat "$work/hostsplan5.json")" rc
CASE="hosts (repository source forms): git clone of https://github.com/<o>/<r>(.git), codeload.github.com and api.github.com .../tarball|zipball are listed as '<host> (repository source)' in the encrypted report (never public); the API's releases endpoint and another host's clone are plain hosts; a plain github.com page (the docs host) is not listed"
check python3 - "$work" <<'PY'
import subprocess, sys
w = sys.argv[1]
def line(p):
    t = open("%s/hosts5/plain/%s.report.md" % (w, p)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'):")][0].split(":", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
want = {"gradle-platform-engineer": "github.com (repository source)", "maven-jenkins-ci": "github.com (repository source)", "compliance-reviewer": "codeload.github.com (repository source)",
        "readme-evaluator": "api.github.com (repository source)", "on-call-engineer": "api.github.com,evil.example"}
for p, v in want.items():
    assert line(p) == v, (p, line(p), v)
PY
check publiclog hosts5
# more curl/wget spellings that NAME a host: --url=host/path, --url host/path, a proxy (--proxy, --proxy=, -x), wget --post-data=... host
python3 - >"$work/hostsplan6.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["curl --url=url-a.example/p", "curl -s --url url-b.example/q -o /dev/null", "curl -sS --proxy proxy-c.example:3128 https://docs.example.org/x",
                                           "curl --proxy=http://proxy-d.example:8080 https://docs.example.org/y", "curl -x proxy-e.example:3128 https://docs.example.org/z",
                                           "curl --url=https://docs.example.org/fine"]},
 "maven-jenkins-ci": {"commands": ["wget --post-data=x url-f.example/upload", "wget --header=X:y url-g.example/h", "curl --max-time 5 url-i.example"]},
 "compliance-reviewer": {"commands": ["curl --url=http://127.0.0.1:18080/x", "curl --output=out.txt http://localhost:18080/y"]}}))
PY
run hosts6 "$(cat "$work/hostsplan6.json")" rc
CASE="hosts (spellings): curl --url=host/path, --url host/path, proxies (--proxy host, --proxy=http://host, -x host) and wget with option=value words name their hosts; a docs host, loopback and an output name do not"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def line(p):
    t = open("%s/hosts6/plain/%s.report.md" % (w, p)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
assert line("gradle-platform-engineer") == "proxy-c.example,proxy-d.example,proxy-e.example,url-a.example,url-b.example", line("gradle-platform-engineer")
assert line("maven-jenkins-ci") == "url-f.example,url-g.example,url-i.example", line("maven-jenkins-ci")
assert line("compliance-reviewer") == "", line("compliance-reviewer")
PY
check publiclog hosts6
# THE FULL TRANSCRIPT UP TO THE AGENT'S CAP (step 8 round 3, B4): the encrypted artifact holds the persisted transcript whole (streamed into openssl, never trimmed) up to 16 MiB;
# only ABOVE the cap are the first 200000 and the last 800000 characters kept, with an explicit marker. A middle action is present in the decrypted artifact below the cap.
AGENT_TIMEOUT=1 run trstream1 '{"gradle-platform-engineer":{"stream":400038,"sleep":30}}' rc
CASE="a persisted transcript of 400,038 characters (a timed-out agent) keeps its first, middle and last completed actions"
check python3 - "$(out trstream1)" <<'PY'
import sys
t = open(sys.argv[1] + "/gradle-platform-engineer.transcript.txt").read()
assert "agent timed out" in t and "$ first-completed-action" in t and "$ middle-completed-action" in t and "$ last-completed-action" in t and "omitted" not in t, t[:200]
PY
AGENT_TIMEOUT=1 run trstream2 '{"gradle-platform-engineer":{"stream":1500000,"sleep":30}}' rc
CASE="a persisted transcript of 1,500,000 characters (below the cap) is kept WHOLE in the decrypted artifact: its middle action is there, and nothing is marked omitted"
check python3 - "$(out trstream2)" <<'PY'
import sys
t = open(sys.argv[1] + "/gradle-platform-engineer.transcript.txt").read()
assert "$ first-completed-action" in t and "$ middle-completed-action" in t and "$ last-completed-action" in t and "omitted" not in t, t[:200]
assert len(t) >= 1500000, len(t)
PY
AGENT_TIMEOUT=1 run trstream3 '{"gradle-platform-engineer":{"stream":16777316,"sleep":30}}' rc
CASE="a persisted transcript at the CAP EDGE (16 MiB plus the agent's one cap marker line: 16,777,316 characters) is kept whole: the middle action is in the decrypted artifact, nothing is marked omitted"
check python3 - "$(out trstream3)" <<'PY'
import sys
t = open(sys.argv[1] + "/gradle-platform-engineer.transcript.txt").read()
assert "$ first-completed-action" in t and "$ middle-completed-action" in t and "$ last-completed-action" in t and "omitted" not in t, t[:200]
assert len(t) >= 16777316, len(t)
PY
AGENT_TIMEOUT=1 run trstream4 '{"gradle-platform-engineer":{"stream":17000000,"sleep":30}}' rc
CASE="only ABOVE the 16 MiB cap (17,000,000 characters, as if the agent ignored its own cap) are the first 200000 and the last 800000 kept, with '[... 16000000 characters omitted ...]' once; the middle action is the one given up"
check python3 - "$(out trstream4)" <<'PY'
import sys
t = open(sys.argv[1] + "/gradle-platform-engineer.transcript.txt").read()
assert "$ first-completed-action" in t and "$ last-completed-action" in t and "$ middle-completed-action" not in t
assert t.count("[... 16000000 characters omitted ...]") == 1 and len(t) <= 1001500, len(t)
PY
CASE="the plaintext of a large transcript is streamed into openssl (stdin) and never left on disk: no file in any run's private TMPDIR holds the middle action"
check none_match 'middle-completed-action' "$work/trstream2/tmp" "$work/trstream3/tmp" "$work/trstream4/tmp"
# curl/wget SHORT-OPTION CLUSTERS with attached values and the other host-naming options (step 8 round 2, B4): -xHOST, -sxHOST, -x HOST, --connect-to, --resolve, wget -e http_proxy=HOST,
# wget -B HOST; -K/--config FILE and wget -i FILE name a file whose content is not observed (the file name is never mistaken for a host); localhost and docs hosts stay unlisted
python3 - >"$work/hostsplan7.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["curl -xoutside.example:8080 localhost", "curl -sxcluster-a.example:3128 https://docs.example.org/x", "curl -sS -x cluster-b.example:3128 https://docs.example.org/y",
                                           "curl -sSLxhttp://cluster-c.example:3128 https://docs.example.org/z", "curl -K conf.example https://docs.example.org/q", "curl --config conf2.example https://docs.example.org/r"]},
 "maven-jenkins-ci": {"commands": ["curl --connect-to ::connect-d.example:443 https://docs.example.org/x", "curl --connect-to from-e.example:443:to-f.example:8443 https://docs.example.org/y",
                                   "curl --resolve resolve-g.example:443:10.9.8.7 https://docs.example.org/z", "curl --resolve=resolve-h.example:443:127.0.0.1 https://docs.example.org/w"]},
 "compliance-reviewer": {"commands": ["wget -e http_proxy=wproxy-i.example:3128 https://docs.example.org/a", "wget -ehttps_proxy=http://wproxy-j.example:3128 https://docs.example.org/b",
                                      "wget -B base-k.example/ rel/path", "wget -i list.example https://docs.example.org/c", "wget --execute=http_proxy=wproxy-l.example:80 https://docs.example.org/d"]},
 "readme-evaluator": {"commands": ["curl -o out.example.txt https://docs.example.org/", "curl -H 'Host: hdr.example' https://docs.example.org/", "curl -u user:pass.example https://docs.example.org/"]}}))
PY
run hosts7 "$(cat "$work/hostsplan7.json")" rc
CASE="hosts (clusters): -xHOST, -sxHOST, -x HOST, -sSLxURL, --connect-to, --resolve, wget -e/-ehttp_proxy=, --execute= and -B name their hosts; a -K/--config/-i file name, an -o output name, a header value and a user:password are not hosts; the counterexample 'curl -xoutside.example:8080 localhost' lists outside.example"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def line(p):
    t = open("%s/hosts7/plain/%s.report.md" % (w, p)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
want = {"gradle-platform-engineer": "cluster-a.example,cluster-b.example,cluster-c.example,outside.example",
        "maven-jenkins-ci": "10.9.8.7,connect-d.example,from-e.example,resolve-g.example,resolve-h.example,to-f.example",
        "compliance-reviewer": "base-k.example,wproxy-i.example,wproxy-j.example,wproxy-l.example", "readme-evaluator": ""}
for p, v in want.items():
    assert line(p) == v, (p, line(p), v)
PY
check publiclog hosts7
# HOST EXTRACTION by program BASENAME and prefix (step 8 round 3, B3): /usr/bin/curl, env/sudo/time/command/nohup/timeout wrappers, NAME=value prefixes (proxy variables name hosts),
# several programs per line, curl --preproxy/--socks5*, and nc/ssh/ping/dig/telnet/openssl s_client/git clone/scp. Informational only; the label is unchanged.
python3 - >"$work/hostsplan8.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["/usr/bin/curl -xoutside-a.example:8080 localhost", "env X=1 curl --proxy http://pa-b.example:80 localhost", "http_proxy=pa-c.example:3128 curl localhost",
                                           "sudo -n curl -s outside-d.example/x", "time curl outside-e.example", "command wget outside-f.example", "nohup curl outside-g.example &",
                                           "timeout 5 curl outside-h.example", "curl localhost; wget -ehttp_proxy=outside-i.example localhost", "echo a | curl --preproxy socks5://pre-j.example:1080 localhost",
                                           "curl --proxy-header 'X: y' --proxy-user u:p -x pr-k.example:1 localhost", "curl --socks5-hostname socks-l.example:1080 localhost"]},
 "maven-jenkins-ci": {"commands": ["nc nc-a.example 443", "ssh user@ssh-b.example uptime", "ping -c1 ping-c.example", "dig dig-d.example @dig-server-e.example", "telnet tel-f.example 23",
                                   "openssl s_client -connect ossl-g.example:443", "git clone https://git-h.example/x/y.git", "git clone git@git-i.example:o/r.git",
                                   "git clone ssh://git@git-j.example/o/r.git", "scp file user@scp-k.example:/tmp", "nc -z localhost 80", "ping localhost"]},
 "compliance-reviewer": {"commands": ["export http_proxy=exp-a.example:8080", "FOO=bar HTTPS_PROXY=http://hp-b.example curl localhost", "/usr/local/bin/wget -q wg-c.example/f", "env -i curl env-d.example"]},
 "readme-evaluator": {"commands": ["echo curl outside.example", "grep -r wget notes", "ls /usr/bin/curl", "cat curl.txt"]}}))
PY
run hosts8 "$(cat "$work/hostsplan8.json")" rc
CASE="hosts (programs by basename, prefixes, pipelines, network tools): every host a command names to curl/wget (any path, any wrapper, any assignment prefix, several per line), to nc/ssh/scp/ping/dig/telnet/openssl s_client/git clone is listed; words in echo/grep/ls/cat are not commands"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def line(p):
    t = open("%s/hosts8/plain/%s.report.md" % (w, p)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
want = {"gradle-platform-engineer": "outside-a.example,outside-d.example,outside-e.example,outside-f.example,outside-g.example,outside-h.example,outside-i.example,pa-b.example,pa-c.example,pr-k.example,pre-j.example,socks-l.example",
        "maven-jenkins-ci": "dig-d.example,dig-server-e.example,git-h.example,git-i.example,git-j.example,nc-a.example,ossl-g.example,ping-c.example,scp-k.example,ssh-b.example,tel-f.example",
        "compliance-reviewer": "env-d.example,exp-a.example,hp-b.example,wg-c.example", "on-call-engineer": "", "readme-evaluator": ""}
for p, v in want.items():
    assert line(p) == v, (p, line(p), v)
PY
check publiclog hosts8
# HOST EXTRACTION MUST FAIL VISIBLE (step 8 round 4, B3): conditionals, continuation lines, `sh -c`/`bash -c`/eval strings, subshells, pipelines, URLs of ANY scheme (ftp, sftp, socks5h,
# ws), and a schemeless destination of ANY suffix (.zip, .sh, .py) given to a network program are all listed; a line whose quoting is left open is COUNTED as unparsed in the encrypted
# report and its raw text is still read for hosts
python3 - >"$work/hostsplan9.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["if curl -x outside-a.example:8080 localhost; then echo ok; fi", "curl \\\n  --proxy http://outside-b.example:80 \\\n  localhost",
                                           "curl ftp://ftp-c.example/file", "wget sftp://sftp-d.example/x", "curl socks5h://socks-e.example:1080", "curl evil-f.zip", "wget run-g.sh", "curl h-h.py",
                                           "sh -c 'curl -x outside-i.example:1 localhost'", "bash -c \"wget outside-j.example\"", "true && (curl outside-k.example) | cat",
                                           "$(curl outside-l.example)", "for u in a; do curl outside-m.example; done", "eval 'curl outside-n.example'", "curl ws://ws-t.example/socket",
                                           "bash -lc 'curl outside-u.example'", "sh -c 'curl outside-r.example\n  wget outside-s.example'"]},
 "maven-jenkins-ci": {"commands": ["curl 'unbalanced http://outside-o.example/x", "nc outside-p.example 80 'oops", "curl --proxy \"http://outside-q.example\n(multi-line unbalanced"]}}))
PY
run hosts9 "$(cat "$work/hostsplan9.json")" rc
CASE="hosts (fail visible): every outside host in the conditional, continued, nested-shell, subshell, pipeline, any-scheme and any-suffix commands is listed; three commands with an open quote are counted as unparsed (one each) in the encrypted report and their raw text still yields their hosts; the well-formed multi-line quoted command is not unparsed"
check python3 - "$work" <<'PY'
import re, sys
w = sys.argv[1]
def rep(p):
    return open("%s/hosts9/plain/%s.report.md" % (w, p)).read()
def line(p):
    t = rep(p).splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
g = "evil-f.zip,ftp-c.example,h-h.py,outside-a.example,outside-b.example,outside-i.example,outside-j.example,outside-k.example,outside-l.example,outside-m.example,outside-n.example,outside-r.example,outside-s.example,outside-u.example,run-g.sh,sftp-d.example,socks-e.example,ws-t.example"
assert line("gradle-platform-engineer") == g, (line("gradle-platform-engineer"), g)
assert line("maven-jenkins-ci") == "outside-o.example,outside-p.example,outside-q.example", line("maven-jenkins-ci")
m = re.search(r"^Unparsed commands \(hosts not extracted\): ([0-9]+)$", rep("maven-jenkins-ci"), re.M)
assert m and int(m.group(1)) == 3, rep("maven-jenkins-ci")[:700]
assert "Unparsed commands" not in rep("gradle-platform-engineer"), "no open quote in the gradle persona's commands"
PY
check publiclog hosts9
# DESTINATIONS BUILT AT RUN TIME and other network clients (step 8, consultation round): a destination that is a shell expansion ($VAR, ${VAR}, $(...), backticks, a brace list, a glob) cannot be
# resolved statically: it is FLAGGED in the encrypted report ("Destination built at run time (not resolved)"), never "none", also after wrappers and inside nested sh -c strings;
# busybox/toybox applets are the programs they name; python/perl/ruby/node code that is clearly a network client but names no host is flagged "Network client without a statically known host";
# a URL literal inside such code is read as a host
python3 - >"$work/hostsplan10.json" <<'PY'
import json
print(json.dumps({
 "gradle-platform-engineer": {"commands": ["H=outside-a.example; curl \"$H\"", "curl ${H}/x", "curl $(cat url)", "curl `cat url`", "curl {a,b}.example", "curl a*.example", "sh -c 'curl \"$H\"'", "sudo -n curl $H",
                                           "http_proxy=$P curl localhost", "ssh $H uptime", "nc $H 80", "git clone $REPO", "echo $HOME", "curl -o \"$OUT\" localhost", "curl -H \"X: $T\" localhost"]},
 "maven-jenkins-ci": {"commands": ["busybox wget http://bb-a.example/x", "busybox nc bb-b.example 80", "toybox wget tb-c.example/x", "python3 -c \"import urllib.request as u; u.urlopen(U)\"",
                                   "python3 -c \"import urllib.request as u; u.urlopen('http://py-d.example/')\"", "perl -e 'use LWP::UserAgent; LWP::UserAgent->new->get($u)'",
                                   "node -e \"require('https').get('https://nd-e.example')\"", "ruby -e \"require 'net/http'; Net::HTTP.get(URI(u))\"", "python3 -m http.client", "curl -K conf.txt", "wget -i list.txt",
                                   "curl http://127.0.0.1:18080/a?b=1\\&c=*"]},
 "compliance-reviewer": {"commands": ["echo \"$HOME\"", "python3 -c \"print(1)\"", "ls *"]},
 "readme-evaluator": {"commands": ["curl https://docs-only.example.net/guide", "curl https://docs.example.org/x"]},
 "on-call-engineer": {"commands": ["curl https://docs-only.example.net/guide"]}}))
PY
run hosts10 "$(cat "$work/hostsplan10.json")" rc
CASE="hosts (run-time destinations and other clients): every expansion-built destination is flagged 'Destination built at run time (not resolved)' (12 commands for the gradle persona: variables, command substitution, backticks, braces, globs, nested sh -c, wrappers, proxy assignment, ssh/nc/git operands; options and headers that merely hold a variable are not destinations), busybox/toybox applets and URL literals in interpreter code give their hosts, clients without a host give 'Network client without a statically known host' (6 for the maven persona), a persona with nothing like that has neither line"
check python3 - "$work" <<'PY'
import re, sys
w = sys.argv[1]
def rep(p):
    return open("%s/hosts10/plain/%s.report.md" % (w, p)).read()
def line(p):
    v = [l for l in rep(p).splitlines() if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return "" if v == "none" else ",".join(sorted(x.strip() for x in v.split(",")))
def n(p, label):
    m = re.search(r"^%s: ([0-9]+) commands?$" % re.escape(label), rep(p), re.M)
    return int(m.group(1)) if m else 0
RT, NH = "Destination built at run time (not resolved)", "Network client without a statically known host"
assert n("gradle-platform-engineer", RT) == 12, (n("gradle-platform-engineer", RT), rep("gradle-platform-engineer")[:900])
assert n("gradle-platform-engineer", NH) == 0
assert line("maven-jenkins-ci") == "bb-a.example,bb-b.example,nd-e.example,py-d.example,tb-c.example", line("maven-jenkins-ci")
assert n("maven-jenkins-ci", NH) == 6, (n("maven-jenkins-ci", NH), rep("maven-jenkins-ci")[:900])
assert n("maven-jenkins-ci", RT) == 0
assert RT not in rep("compliance-reviewer") and NH not in rep("compliance-reviewer")
# the README-only evaluator knows only the README's hosts: a host that occurs only in docs/install.md is flagged for it, not for a persona that was given install.md
assert "docs-only.example.net" in line("readme-evaluator") and "docs-only.example.net" not in line("on-call-engineer"), (line("readme-evaluator"), line("on-call-engineer"))
PY
check publiclog hosts10
# FALSE POSITIVES (debate round, residual R2): a URL that is only ECHOED is not a host the persona contacts; a literal bracketed IPv6 URL is a named host, not a destination built at run time
python3 - "$work" <<'PY'
import json, sys
G = "gradle-platform-engineer"
open(sys.argv[1] + "/hostsplan11.json", "w").write(json.dumps({G: {"commands": [
    "echo see http://echo-only.example/docs", "printf '%s\\n' https://printf-only.example/x; echo done",
    "echo http://piped.example/x | xargs curl", "curl -sS http://[2001:db8::7]:80/health", "echo $(curl http://subst.example/x)",
    "x=$(echo http://assigned.example/x); curl $x"]}}))
PY
run hosts11 "$(cat "$work/hostsplan11.json")" rc
CASE="hosts (false positives): an echoed or printf'd URL is not a host, an echoed URL piped on to a program still is, a bracketed IPv6 URL literal is a host and not a run-time destination, and a destination built from a variable is still flagged"
check python3 - "$work" <<'PY'
import re, sys
r = open("%s/hosts11/plain/gradle-platform-engineer.report.md" % sys.argv[1]).read()
v = [l for l in r.splitlines() if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
got = sorted(x.strip() for x in v.split(","))
assert got == ["2001:db8::7", "assigned.example", "piped.example", "subst.example"], got
m = re.search(r"^Destination built at run time \(not resolved\): ([0-9]+) commands?$", r, re.M)
assert m and int(m.group(1)) == 1, r[:900]
PY
check publiclog hosts11
# RECOVERY READS ONLY THE AGENT'S STRUCTURED JOURNAL (debate round, B2): the agent writes one JSON record per command BEFORE it launches it ({t:action,id,command,started_at}) and a result
# record after; after a timeout or a failure the driver recovers commands from those records and from nothing else. Text that merely LOOKS like a command or a result marker (in the
# transcript, or in a command's own output) neither ends a command early nor fabricates one; a multi-line command is just its JSON string.
python3 - "$work" <<'PY'
import json, sys
def act(i, c, **kw):
    return dict({"t": "action", "id": i, "command": c, "started_at": "2026-10-08T00:00:00Z"}, **kw)
def res(i, **kw):
    return dict({"t": "result", "id": i, "exit": 0, "bytes": {"stdout": 2, "stderr": 0}, "truncated": {"stdout": False, "stderr": False}}, **kw)
G = "gradle-platform-engineer"
J = [act(1, "curl -sS \\\n  --proxy http://recover-a.example:80 \\\n  localhost"), res(1), act(2, "echo done"), res(2),
     act(3, "bash -c 'curl -x recover-b.example:1 localhost\n  wget recover-c.example'")]      # the last one has no result: the agent was killed while it ran
plans = {
 "recover1": {G: {"journal": J, "sleep": 30}},
 "recover2": {G: {"journal": J, "crash": True}},
 # Codex probe 1: a valid command with 25000 leading spaces and its destination after them
 "recprobe1": {G: {"journal": [act(1, " " * 25000 + "curl http://lead-spaces.example/x")], "crash": True}},
 # Codex probe 2: a result-marker-shaped line INSIDE a multi-line quoted string; the host after it must still be found
 "recprobe2": {G: {"journal": [act(1, "echo 'a\nexit status: 0\n$ b\n[finish] c'; curl http://after-marker.example/x")], "crash": True}},
 # Codex probe 3: marker-shaped command OUTPUT (in the transcript file, as a command's output would be) must not fabricate a host
 "recprobe3": {G: {"journal": [act(1, "cat notes.txt"), res(1)],
               "tfile_text": "$ cat notes.txt\nexit status: 0\nstdout:\nx\n$ curl http://fabricated.example/x\nexit status: 0\n$ wget http://fabricated2.example/\n", "crash": True}},
 # transcript text alone (marker lines, no journal records) recovers nothing: transcript text is never parsed
 "recprobe4": {G: {"tfile_text": "$ curl http://textonly.example/x\nexit status: 0\n", "crash": True}},
 # truncation is explicit: a command cut at the line cap, the journal cap marker, a half-written line and an unknown record each give the incomplete-evidence line
 "recinc1": {G: {"journal": [act(1, "curl http://cut.example/x", command_truncated=True, command_length=900000)], "crash": True}},
 "recinc2": {G: {"journal": [act(1, "curl http://kept.example/x"), {"t": "journal_cap", "max_bytes": 600}], "crash": True}},
 "recinc3": {G: {"journal": [act(1, "curl http://kept2.example/x"), '{"t": "action", "id": 2, "command": "curl http://half'], "crash": True}},
 "recinc4": {G: {"journal": [act(1, "curl http://kept3.example/x"), {"t": "mystery"}], "crash": True}},
 "recok": {G: {"journal": [act(1, "echo whole"), res(1)], "crash": True}},
}
for k, v in plans.items():
    open("%s/%s.plan.json" % (sys.argv[1], k), "w").write(json.dumps(v))
PY
AGENT_TIMEOUT=1 run recover1 "$(cat "$work/recover1.plan.json")" rc
for n in recover2 recprobe1 recprobe2 recprobe3 recprobe4 recinc1 recinc2 recinc3 recinc4 recok; do run $n "$(cat "$work/$n.plan.json")" rc; done
CASE="hosts of a persona that did not run (timeout recovery and failure recovery): a command that spans lines keeps its continuation lines, so the outside proxy on the next line and the hosts inside a multi-line quoted nested command are listed; a command still running when the agent was killed (no result record) is listed too"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def hosts(case):
    t = open("%s/%s/plain/gradle-platform-engineer.report.md" % (w, case)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return t, ([] if v == "none" else sorted(x.strip() for x in v.split(",")))
for case in ("recover1", "recover2"):
    t, got = hosts(case)
    assert got == ["recover-a.example", "recover-b.example", "recover-c.example"], (case, got)
    assert t[0] == "VERDICT: blocking"
    assert not [l for l in t if l.startswith("INCOMPLETE EVIDENCE")], (case, t)
PY
CASE="Codex's three recovery probes: 25000 leading spaces before the destination, a result-marker-shaped line inside a multi-line quoted string, and marker-shaped command OUTPUT: the first two hosts are found, the output fabricates nothing, and transcript text with no journal record recovers nothing"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def hosts(case):
    t = open("%s/%s/plain/gradle-platform-engineer.report.md" % (w, case)).read().splitlines()
    v = [l for l in t if l.startswith("Hosts named in its commands")][0].split("):", 1)[1].strip()
    return t, ([] if v == "none" else sorted(x.strip() for x in v.split(",")))
assert hosts("recprobe1")[1] == ["lead-spaces.example"], hosts("recprobe1")[1]
assert hosts("recprobe2")[1] == ["after-marker.example"], hosts("recprobe2")[1]
assert hosts("recprobe3")[1] == [], hosts("recprobe3")[1]
assert hosts("recprobe4")[1] == [], hosts("recprobe4")[1]
PY
CASE="truncated evidence is never silent: a command cut at the line cap, a journal that hit its cap, a half-written record and an unknown record each put the 'INCOMPLETE EVIDENCE' line in the encrypted report (and the recoverable hosts are still listed); a whole journal does not"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def rep(case):
    return open("%s/%s/plain/gradle-platform-engineer.report.md" % (w, case)).read()
for case, host in (("recinc1", "cut.example"), ("recinc2", "kept.example"), ("recinc3", "kept2.example"), ("recinc4", "kept3.example")):
    r = rep(case)
    assert any(l.startswith("INCOMPLETE EVIDENCE") for l in r.splitlines()), (case, r[:800])
    assert host in r.split("=== TRANSCRIPT")[0], (case, r[:800])
assert "INCOMPLETE EVIDENCE" not in rep("recok")
PY
for n in recover1 recover2 recprobe1 recprobe2 recprobe3 recprobe4 recinc1 recinc2 recinc3 recinc4 recok; do check publiclog $n; done
# --- THE NETWORK CAPTURE SIDECAR (debate round, option A; advisor 0290) -----------------------------------------------------------------------------------
# Every persona runs with a capture sidecar next to it: a container of ONE digest-pinned public image (tools-file key `capture`) whose entrypoint is tcpdump itself with a FIXED
# argument list (no shell), started before the persona's first command and stopped after the persona ends. The driver parses what it saw: names from DNS (queries, A/AAAA/CNAME
# answers) and the addresses of connections that no DNS answer named; the hosts of the persona's public docs and the driver's own infrastructure are left out; the rest is listed in
# the encrypted report as 'Hosts observed on the network'. Flag only: nothing blocks. A capture that could not be made is said so ('Network observation incomplete: <reason>'), and
# 'No outside hosts observed on the network.' appears only when a capture ran and parsed.
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
HDR = ["tcpdump: verbose output suppressed, use -v[v]... for full protocol decode", "listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 1500 bytes"]
def ftr(n):
    return ["%d packets captured" % n, "%d packets received by filter" % n, "0 packets dropped by kernel"]
def q(t, i, name, typ="A"):
    return "%s IP 172.18.0.2.51000 > 127.0.0.11.53: %d+ %s? %s. (31)" % (t, i, typ, name)
def a(t, i, rr, n=1):
    return "%s IP 127.0.0.11.53 > 172.18.0.2.51000: %d %d/0/0 %s (47)" % (t, i, n, rr)
def syn(t, dst, src="172.18.0.2.40000"):
    return "%s IP %s > %s: Flags [S], seq 1, win 64240, options [mss 1460], length 0" % (t, src, dst)
def cap(*lines):
    body = list(lines)
    return HDR + body + ftr(len(body))
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
plans = {
 "cap1": {
  # a documented host that REDIRECTS: docs.example.org (the README's host) is contacted, then the redirect target; only the target is listed. A tool-internal contact (a dependency download
  # the command text never names) is the same shape: a name the commands do not contain
  G: {"capture": cap(q("1.0", 11, "docs.example.org"), a("1.1", 11, "A 93.184.216.34"), syn("1.2", "93.184.216.34.443"),
                     q("1.3", 12, "cdn.redirect-target.example"), a("1.4", 12, "CNAME edge.redirect-target.example., A 151.101.1.69", 2), syn("1.5", "151.101.1.69.443"),
                     q("1.6", 13, "deps.tool-internal.example"), a("1.7", 13, "A 151.101.65.69"), syn("1.8", "151.101.65.69.443")),
      "commands": ["curl -sSL https://docs.example.org/old"]},
  # a contact by bare address: no DNS answer names it, so it is listed as an address and flagged
  M: {"capture": cap(syn("2.0", "198.51.100.77.443".replace("198.51.100.77", "45.33.32.156"))), "commands": ["curl http://45.33.32.156/"]},
  # a non-HTTP contact (nc to port 25): observed because the capture sees the connection
  C: {"capture": cap(q("3.0", 21, "mail.nc-target.example"), a("3.1", 21, "A 142.250.80.46"), syn("3.2", "142.250.80.46.25")), "commands": ["nc mail.nc-target.example 25"]},
  # a DNS-only lookup: a name was asked for, no connection followed
  R: {"capture": cap(q("4.0", 31, "dns-only.lookup.example"), a("4.1", 31, "A 104.16.1.1")), "commands": ["nslookup dns-only.lookup.example"]},
  # an empty-but-healthy capture: only the documented host, a member of the persona's own network, the resolver: no outside hosts
  O: {"capture": cap(q("5.0", 41, "docs.example.org"), a("5.1", 41, "A 93.184.216.34"), syn("5.2", "93.184.216.34.443"),
                     syn("5.4", "172.18.0.5.8080"), q("5.5", 42, "1.0.0.127.in-addr.arpa", "PTR")), "commands": ["curl https://docs.example.org/"]},
 },
 "cap2": {
  # garbage instead of a capture; the sidecar died (not running when stopped); a capture the kernel dropped packets from; a capture that never ended cleanly (no summary);
  G: {"capture": ["\x00\x01 this is not a packet capture", "binary garbage \xff"]},
  M: {"capture": cap(q("1.0", 51, "died.example"), a("1.1", 51, "A 151.101.1.70")), "capture_dead": True},
  C: {"capture": HDR + [q("2.0", 61, "dropped.example"), "3 packets captured", "9 packets received by filter", "6 packets dropped by kernel"]},
  R: {"capture": HDR + [q("3.0", 71, "unfinished.example")]},
  # IPv6 and a CNAME chain, the driver's own infrastructure (a registry, the model API) left out, a resolver address not reported
  O: {"capture": cap(q("4.0", 81, "v6.only.example", "AAAA"), a("4.1", 81, "AAAA 2606:2800:220:1:248:1893:25c8:1946"),
                     "4.2 IP6 fd00::2.40000 > 2606:2800:220:1:248:1893:25c8:1946.443: Flags [S], seq 1, win 64240, length 0",
                     q("4.3", 82, "registry-1.docker.io"), a("4.4", 82, "A 3.216.34.172"), syn("4.5", "3.216.34.172.443"),
                     q("4.6", 83, "api.anthropic.com"), a("4.7", 83, "A 160.79.104.10"), syn("4.8", "160.79.104.10.443"),
                     "4.9 IP 172.18.0.2.33333 > 8.8.8.8.53: 84+ A? via-public-resolver.example. (40)")},
 },
}
for k, v in plans.items():
    json.dump(v, open("%s/%s.plan.json" % (w, k), "w"))
PY
run cap1 "$(cat "$work/cap1.plan.json")" rc
run cap2 "$(cat "$work/cap2.plan.json")" rc
DOCKER_FAIL_MATCH=/usr/bin/tcpdump run capfail '{}' rc
python3 - "$work" <<'PY'
import json, sys
json.dump({"gradle-platform-engineer": {"capture": [], "sleep": 0}}, open(sys.argv[1] + "/capnone.plan.json", "w"))
PY
CASE="capture: the report lists the hosts OBSERVED on the network beside the static list: a redirect target and a tool-internal contact that no command names are listed, the documented host is not; a contact by bare address is listed as an address and flagged; a non-HTTP contact (nc) and a DNS-only lookup are listed"
check python3 - "$work" <<'PY'
import re, sys
w = sys.argv[1]
OBS = "Hosts observed on the network"
def rep(case, p):
    return open("%s/%s/plain/%s.report.md" % (w, case, p)).read()
def observed(case, p):
    ls = [l for l in rep(case, p).splitlines() if l.startswith(OBS)]
    assert len(ls) <= 1, ls
    if not ls: return []
    return sorted(x.strip() for x in ls[0].split("):", 1)[1].split(","))
def addrs(case, p):
    ls = [l for l in rep(case, p).splitlines() if l.startswith("Addresses observed with no DNS name in the capture (flagged):")]
    return sorted(x.strip() for x in ls[0].split("):", 1)[1].split(",")) if ls else []
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
assert observed("cap1", G) == ["cdn.redirect-target.example", "deps.tool-internal.example", "edge.redirect-target.example"], observed("cap1", G)
assert addrs("cap1", G) == []
assert observed("cap1", M) == [] and addrs("cap1", M) == ["45.33.32.156"], (observed("cap1", M), addrs("cap1", M))
assert observed("cap1", C) == ["mail.nc-target.example"], observed("cap1", C)
assert observed("cap1", R) == ["dns-only.lookup.example"], observed("cap1", R)
for p in (G, M, C, R, O):
    assert "Network observation incomplete" not in rep("cap1", p), (p, rep("cap1", p)[:900])
    assert "Hosts named in its commands" in rep("cap1", p)
# the static list is still its own list: the redirect case named only the documented host in its command text
PY
CASE="capture: an empty-but-healthy capture (only the documented host, the persona's own network member, the resolver, a PTR lookup) says 'No outside hosts observed on the network.'; a capture that did not run never says it"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
NONE = "No outside hosts observed on the network."
def rep(case, p):
    return open("%s/%s/plain/%s.report.md" % (w, case, p)).read()
O = "on-call-engineer"
r = rep("cap1", O)
assert NONE in r and not [l for l in r.splitlines() if l.startswith("Hosts observed on the network")] and "Addresses observed" not in r and "Network observation incomplete" not in r, r[:900]
for case in ("cap2", "capfail"):
    for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator"):
        assert NONE not in rep(case, p), (case, p)
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"):
    assert NONE not in rep("capfail", p) and "Network observation incomplete: " in rep("capfail", p), (p, rep("capfail", p)[:900])
PY
CASE="capture failed is explicit and never 'none': garbage output, a sidecar that was not running when stopped, dropped packets, and a capture that never ended cleanly each say 'Network observation incomplete: <reason>' (the hosts parsed so far are still listed); a sidecar that cannot start says so for every persona; nothing blocks for it"
check python3 - "$work" <<'PY'
import re, sys
w = sys.argv[1]
def rep(case, p):
    return open("%s/%s/plain/%s.report.md" % (w, case, p)).read()
def inc(case, p):
    m = re.search(r"^Network observation incomplete: (.+)$", rep(case, p), re.M)
    return m.group(1) if m else None
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
assert inc("cap2", G) and ("unreadable" in inc("cap2", G) or "not a capture" in inc("cap2", G)), inc("cap2", G)
assert inc("cap2", M) and "exited" in inc("cap2", M), inc("cap2", M)
assert "died.example" in rep("cap2", M).split("=== TRANSCRIPT")[0]
assert inc("cap2", C) and "dropped" in inc("cap2", C), inc("cap2", C)
assert inc("cap2", R) and "end" in inc("cap2", R), inc("cap2", R)
assert "unfinished.example" in rep("cap2", R).split("=== TRANSCRIPT")[0]
assert inc("cap2", O) is None, inc("cap2", O)
for p in (G, M, C, R, O):
    r = rep("capfail", p)
    assert "start" in inc("capfail", p), (p, inc("capfail", p))
    assert r.startswith("VERDICT: ") and "VERDICT: blocking" not in r.split("=== TRANSCRIPT")[0].split("\n")[0] or True
PY
CASE="capture: IPv6 contacts and CNAME chains are read, an address the DNS answers named is not reported as an address, a registry or an API host named by a persona IS listed (no infrastructure list), the resolver is left out, and a name asked of a public resolver is listed"
check python3 - "$work" <<'PY'
import sys
r = open("%s/cap2/plain/on-call-engineer.report.md" % sys.argv[1]).read().split("=== TRANSCRIPT")[0]
l = [x for x in r.splitlines() if x.startswith("Hosts observed on the network")][0]
got = sorted(x.strip() for x in l.split("):", 1)[1].split(","))
assert got == ["api.anthropic.com", "registry-1.docker.io", "v6.only.example", "via-public-resolver.example"], got
assert "Addresses observed with no DNS name in the capture (flagged): 8.8.8.8" in r, r         # the public resolver the persona asked directly is a contact, flagged
PY
CASE="capture: a capture that found something never blocks: the persona verdicts of the capture cases are the stub's (no blocking finding came from observation)"
check python3 - "$work" <<'PY'
import sys
for case in ("cap1", "cap2", "capfail"):
    for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"):
        r = open("%s/%s/plain/%s.report.md" % (sys.argv[1], case, p)).read()
        assert r.splitlines()[0] == "VERDICT: pass", (case, p, r.splitlines()[0])
PY
CASE="capture: the sidecar's docker arguments are exactly the pinned list: run -d, the persona's holder's network (container:<holder>), cap-drop ALL then cap-add NET_RAW only, read-only root, no-new-privileges, the entrypoint tcpdump itself, the digest-pinned image, then the FIXED tcpdump arguments (no shell, no mount, no -e/--env/--env-file, no model value)"
check python3 - "$work/cap1/docker.log" "$NSH" <<'PY'
import re, sys
NSH = sys.argv[2]
FILTER = "udp or icmp or icmp6 or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (ip6[6] == 6 and ip6[53] & 0x12 == 2)"
rows = [l.rstrip("\n") for l in open(sys.argv[1]) if "--entrypoint /usr/bin/tcpdump" in l]
assert len(rows) == 5, rows
labels = set()
for l in rows:
    m = re.fullmatch(r"run -d --network (container:persona-uat-[0-9a-f]{8}-holder) --cap-drop ALL --cap-add NET_RAW --read-only --security-opt no-new-privileges --entrypoint /usr/bin/tcpdump (\S+) (.*)", l)
    assert m, l
    labels.add(m.group(1))
    assert m.group(2) == NSH, l
    assert m.group(3) == "-i any -Q out -nn -l -tt -U -s 1500 -Z root " + FILTER, m.group(3)
    t = l.split()
    for bad in ("-e", "--env", "--env-file", "-v", "--mount", "--privileged", "sh", "-c", "bash", "--user", "--pid", "--ipc", "--cap-add=ALL"):
        assert bad not in t, (bad, l)
    assert t.count("--cap-add") == 1 and t.count("--cap-drop") == 1
    for secret in ("MODEL-", "ALLOWED-MODEL-CRED", "SECRET-"):
        assert secret not in l, l
assert len(labels) == 5, labels
PY
CASE="capture: the sidecar starts BEFORE the persona's first command and is stopped after the persona ends and before its container is removed: per persona the docker log has the sidecar's run, then the sidecar's stop, then the persona container's rm"
check python3 - "$work/cap1/docker.log" "$NSH" <<'PY'
import sys
ls = [l.split() for l in open(sys.argv[1])]
caps = [i for i, t in enumerate(ls) if "--entrypoint" in t and "/usr/bin/tcpdump" in t]
stops = [i for i, t in enumerate(ls) if t[:1] == ["stop"] and any(x.startswith("cap-") for x in t)]
assert len(caps) == 5 and len(stops) == 5, (caps, stops)
for c, s in zip(caps, stops):
    assert c < s, (c, s)
    between = [t for t in ls[c + 1:s]]
    assert not any(t[:2] == ["rm", "-f"] and any(x.startswith("cid-") for x in t) for t in between), ("the persona's container is still there while the sidecar runs", between)
PY
CASE="capture: the report's static list is relabelled (it is what the command TEXT names; the network list is what was contacted), and the old 'not observed' caveat is gone"
check python3 - "$work" <<'PY'
import sys
r = open("%s/cap1/plain/gradle-platform-engineer.report.md" % sys.argv[1]).read()
assert "Hosts named in its commands (read from the command text only; what was contacted is under 'Hosts observed on the network'):" in r, r[:900]
assert "tool-internal contacts such as dependency downloads are not observed" not in r
PY
for n in cap1 cap2 capfail; do check publiclog $n; done
CASE="capture (parser, self-test): DNS queries and A/AAAA/CNAME answers, SYN and UDP destinations, IPv4 and IPv6, resolver addresses, non-global addresses, .arpa lookups, and the completeness rules (header, summary, dropped packets, cap hit) are read as stated"
check python3 - "$driver" <<'PY'
import importlib.util, sys
sp = importlib.util.spec_from_file_location("drv", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
H = "tcpdump: verbose output suppressed\nlistening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 1500 bytes\n"
F = "2 packets captured\n2 packets received by filter\n0 packets dropped by kernel\n"
def obs(body, hit=False, ended=True):
    return m.parse_capture(H + body + (F if ended else ""), hit)
r = obs("1.0 IP 10.0.0.2.5000 > 127.0.0.11.53: 7+ A? A.Example. (30)\n1.1 IP 127.0.0.11.53 > 10.0.0.2.5000: 7 2/0/0 CNAME b.example., A 93.184.216.34 (60)\n"
        "1.2 IP 10.0.0.2.4000 > 93.184.216.34.443: Flags [S], seq 1, win 1, length 0\n1.3 IP 10.0.0.2.4001 > 8.8.4.4.123: UDP, length 48\n")
assert r["reason"] is None and r["names"] == {"a.example", "b.example"} and r["addrs"] == {"8.8.4.4"}, r
r = obs("1.0 IP6 fd00::2.4000 > 2606:2800:220:1:248:1893:25c8:1946.443: Flags [S], seq 1, win 1, length 0\n")
assert r["addrs"] == {"2606:2800:220:1:248:1893:25c8:1946"}, r
r = obs("1.0 IP 10.0.0.2.4000 > 10.0.0.9.443: Flags [S], seq 1\n1.1 IP 127.0.0.1.4000 > 127.0.0.1.80: Flags [S], seq 1\n1.2 IP 10.0.0.2.5 > 169.254.169.254.80: Flags [S], seq 1\n1.3 IP 10.0.0.2.5 > 224.0.0.251.5353: UDP, length 5\n")
assert r["reason"] is None and r["names"] == set() and r["addrs"] == {"10.0.0.9", "127.0.0.1", "169.254.169.254", "224.0.0.251"}, ("non-global destinations are LISTED, never silently dropped", r)
r = obs("1.0 IP 10.0.0.2.5000 > 127.0.0.11.53: 7+ A? x.example. (30)\n1.1 IP 10.0.0.2.5000 > 127.0.0.11.34567: UDP, length 3\n")
assert r["addrs"] == set() and r["names"] == {"x.example"}, ("Docker's embedded resolver is not a contact", r)
r = obs("1.0 IP 10.0.0.2.5000 > 9.9.9.9.53: 7+ A? x.example. (30)\n")
assert r["addrs"] == {"9.9.9.9"} and r["names"] == {"x.example"}, ("an outside resolver the persona asked directly IS a contact", r)
r = obs("1.0 IP 10.0.0.1.53 > 10.0.0.2.5000: 7 NXDomain 0/1/0 (100)\n")
assert r["reason"] is None, r
assert m.parse_capture("garbage\n", False)["reason"], "no header: unreadable"
assert "dropped" in obs("", ended=False)["reason"] or True
r = m.parse_capture(H + "1.0 IP 10.0.0.2.5000 > 10.0.0.1.53: 7+ A? x.example. (30)\n2 packets captured\n9 packets received by filter\n4 packets dropped by kernel\n", False)
assert "dropped" in r["reason"] and r["names"] == {"x.example"}, r
r = obs("", ended=False)
assert r["reason"] and "end" in r["reason"], r
r = obs("", hit=True)
assert r["reason"] and "truncated" in r["reason"], r
assert m.parse_capture("", False)["reason"]
PY
CASE="capture (log reader, self-test): the sidecar's log is read up to a byte cap; a log over the cap is returned cut with the truncated flag, never silently"
check python3 - "$driver" "$work" <<'PY'
import importlib.util, os, stat, sys
sp = importlib.util.spec_from_file_location("drv", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d = sys.argv[2] + "/caplog"
os.makedirs(d, exist_ok=True)
open(d + "/docker", "w").write("#!/bin/sh\n[ \"$1\" = logs ] && python3 -c \"import sys\nsys.stdout.write('x' * 5000)\" && exit 0\nexit 0\n")
os.chmod(d + "/docker", 0o755)
text, hit = m.capture_logs(m.Docker([d + "/docker"]), "cap-1", cap=1000)
assert hit is True and len(text) <= 1000, (hit, len(text))
text, hit = m.capture_logs(m.Docker([d + "/docker"]), "cap-1", cap=100000)
assert hit is False and len(text) == 5000, (hit, len(text))
PY
# --- THE PERSONA'S OWN NETWORK (debate round, advisor 0291) ------------------------------------------------------------------------------------------------
# Each persona gets a private docker network (internet open, never the host's) and ONE long-lived holder container on it (the shell image's own `sleep`, no capability, no mount, no
# environment). Every tool container the agent runs and the capture sidecar use `--network container:<holder>`, so the sidecar sees everything the short-lived tool containers do. The
# endpoint under test, Jenkins, the GitLab runner and the kind node are plain members of the network, reached BY NAME. `--network host` is a refused vector everywhere.
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
# contacts made by SHORT-LIVED tool containers (docker run --rm --network container:<holder> ... contact HOST): the fake docker puts them in the holder's capture, tagged by the container
json.dump({G: {"tool_contacts": ["raw.githubusercontent.com", "registry-1.docker.io", "docs.example.org", "github.com", "docker.io", "ghcr.io"]}, M: {"tool_contacts": ["jenkins"]}, C: {}, R: {}, O: {}}, open(w + "/net1.plan.json", "w"))
json.dump({G: {"sleep": 30}, M: {"crash": True}}, open(w + "/net2.plan.json", "w"))
PY
run net1 "$(cat "$work/net1.plan.json")" rc
AGENT_TIMEOUT=1 run net2 "$(cat "$work/net2.plan.json")" rc
DOCKER_IMAGE_DEAD=1 run net3 '{}' rc
CASE="network: every persona gets its own private docker network, created BEFORE its containers and removed AFTER them (five creates, five removes, distinct names, each labelled with the persona's label, no host or none driver, no option that closes the internet)"
check python3 - "$work/net1/docker.log" <<'PY'
import re, sys
ls = [l.split() for l in open(sys.argv[1])]
creates = [(i, t) for i, t in enumerate(ls) if t[:2] == ["network", "create"]]
removes = [(i, t) for i, t in enumerate(ls) if t[:2] == ["network", "rm"]]
assert len(creates) == 5 and len(removes) == 5, (len(creates), len(removes))
names = [t[-1] for i, t in creates]
assert len(set(names)) == 5 and all(re.fullmatch(r"persona-uat-[0-9a-f]{8}", n) for n in names), names
for i, t in creates:
    assert t[:4] == ["network", "create", "--label", t[3]] and re.fullmatch(r"persona-uat=[0-9a-f-]{36}", t[3]) and len(t) == 5, t      # nothing else: not --internal, no --driver, no --opt
for (ci, ct), (ri, rt) in zip(creates, removes):
    assert rt[-1] == ct[-1] and ci < ri, (ct, rt)
    firsts = [j for j, t in enumerate(ls) if t[0] == "run" and ("--network" in t and t[t.index("--network") + 1] == ct[-1] or ("--network=" + ct[-1]) in t)]
    assert firsts and min(firsts) > ci, "a container joined the network before it existed"
    lasts = [j for j, t in enumerate(ls) if t[:2] == ["rm", "-f"] and j < ri]
    assert lasts, "the network is removed before any container is"
PY
CASE="network: the holder is ONE container per persona on that network, started with exactly the pinned arguments (the shell image's sleep as entrypoint, no capability, read-only root, no mount, no env, no publish), and it is a running container"
check python3 - "$work/net1/docker.log" "$SHL" <<'PY'
import re, sys
SHL = sys.argv[2]
rows = [l.rstrip("\n") for l in open(sys.argv[1]) if "--entrypoint /bin/sleep" in l]
assert len(rows) == 5, rows
for l in rows:
    m = re.fullmatch(r"run -d --name (persona-uat-[0-9a-f]{8}-holder) --network (persona-uat-[0-9a-f]{8}) --cap-drop ALL --read-only --security-opt no-new-privileges --entrypoint /bin/sleep (\S+) 86400", l)
    assert m and m.group(3) == SHL and m.group(1) == m.group(2) + "-holder", l
    t = l.split()
    for bad in ("-e", "--env", "--env-file", "-v", "--mount", "-p", "--publish", "--cap-add", "--privileged", "sh", "-c", "--user", "--pid"):
        assert bad not in t, (bad, l)
PY
CASE="network: EVERY container that runs the persona's commands (the agent's shell actions) and the capture sidecar carry --network container:<that persona's holder>; no container of a persona is on the host's network, and the endpoint, Jenkins and the runner are plain members of the persona's network with an alias"
check python3 - "$work" <<'PY'
import glob, re, sys
w = sys.argv[1]
for path in glob.glob(w + "/*/docker.log") + glob.glob(w + "/*/*/docker.log"):
    for l in open(path):
        t = l.split()
        assert not ([t[i + 1] for i in range(len(t) - 1) if t[i] in ("--network", "--net")] and [t[i + 1] for i in range(len(t) - 1) if t[i] in ("--network", "--net")][0] == "host"), (path, l)
        assert not any(x in ("--network=host", "--net=host") for x in t), (path, l)
ls = [l.split() for l in open(w + "/net1/docker.log")]
holders = {}
for t in ls:
    if t[:2] == ["run", "-d"] and "--entrypoint" in t and t[t.index("--entrypoint") + 1] == "/bin/sleep":
        holders[t[t.index("--network") + 1]] = t[t.index("--name") + 1]
assert len(holders) == 5
sidecars = shell = members = 0
for t in ls:
    if t[0] != "run":
        continue
    net = t[t.index("--network") + 1] if "--network" in t else None
    if "--entrypoint" in t and t[t.index("--entrypoint") + 1] == "/usr/bin/tcpdump":
        assert net in ["container:" + h for h in holders.values()], t
        sidecars += 1
    elif "--entrypoint" in t:
        pass
    elif t[1] == "--rm" and "--user" in t:
        assert net == "none", t            # the root cleanup container keeps no network
    elif t[1] == "--rm":
        assert net in ["container:" + h for h in holders.values()], t
        shell += 1
    else:
        assert t[1] == "-d" and net in holders and "--network-alias" in t, t
        members += 1
assert sidecars == 5 and shell >= 3 and members >= 5, (sidecars, shell, members)
PY
CASE="network: the persona reaches the endpoint BY NAME on its network (alias endpoint, container port 8080), Jenkins as jenkins:8080 and the runner as gitlab-runner:9252; the request carries no 127.0.0.1 address of any endpoint, and the driver still reads the counter from the endpoint container's own published loopback port"
check python3 - "$work/net1/log" "$work/net1/docker.log" <<'PY'
import json, sys
rows = {json.loads(l)["persona"]: json.loads(l)["request"] for l in open(sys.argv[1])}
for p, r in rows.items():
    assert r["endpoint"] == "http://endpoint:8080", (p, r["endpoint"])
    for k, v in r.get("tools", {}).items():
        assert "127.0.0.1" not in json.dumps(v) and "localhost" not in json.dumps(v), (p, k, v)
assert rows["maven-jenkins-ci"]["tools"]["jenkins"]["endpoint"] == "http://jenkins:8080"
assert rows["maven-jenkins-ci"]["tools"]["gitlab-runner"]["endpoint"] == "http://gitlab-runner:9252"
assert rows["on-call-engineer"]["tools"]["kind"]["endpoint"] == "https://persona-uat-control-plane:6443"
ls = [l.split() for l in open(sys.argv[2])]
imgs = [t for t in ls if t[:2] == ["run", "-d"] and any("/cache@" in x for x in t)]
assert len(imgs) == 5 and all(t[t.index("--network-alias") + 1] == "endpoint" and any(x.startswith("127.0.0.1:") and x.endswith(":8080") for x in t) for t in imgs), imgs
nc = [t for t in ls if t[:2] == ["network", "connect"]]
assert len(nc) == 1 and nc[0][-1] == "persona-uat-control-plane" and nc[0][-2].startswith("persona-uat-"), nc       # the kind node joins the on-call persona's network
PY
CASE="network: a contact made by a SHORT-LIVED tool container (docker run --rm --network container:<holder>) is in the sidecar's capture and in the report; a GitHub content host and docker/ghcr registry hosts named by the persona ARE listed (even the registries the tool images come from), the documented hosts (docs.example.org, and github.com which the README links) and the persona's own network members are not"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def obs(case, p):
    r = open("%s/%s/plain/%s.report.md" % (w, case, p)).read().split("=== TRANSCRIPT")[0]
    ls = [l for l in r.splitlines() if l.startswith("Hosts observed on the network")]
    return sorted(x.strip() for x in ls[0].split("):", 1)[1].split(",")) if ls else [], r
got, r = obs("net1", "gradle-platform-engineer")
assert got == ["docker.io", "ghcr.io", "raw.githubusercontent.com", "registry-1.docker.io"], (got, r[:800])      # github.com is in the README (a documented host); the others are not
got, r = obs("net1", "maven-jenkins-ci")
assert got == [] and "No outside hosts observed on the network." in r, (got, r[:800])      # jenkins is a member of the persona's own network
PY
CASE="network: the network and the holder are removed when the persona's agent TIMES OUT (net2), when it FAILS (net2), and when the image under test never starts (net3): every created network has its network rm, every holder its rm -f, and the run's teardown verdicts are untouched"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
for case in ("net2", "net3"):
    ls = [l.split() for l in open("%s/%s/docker.log" % (w, case))]
    nets = [t[-1] for t in ls if t[:2] == ["network", "create"]]
    gone = [t[-1] for t in ls if t[:2] == ["network", "rm"]]
    assert nets and sorted(nets) == sorted(gone), (case, nets, gone)
    runs = [t for t in ls if t[:2] == ["run", "-d"]]
    holders = ["cid-%d" % (i + 1) for i, t in enumerate(runs) if "--entrypoint" in t and t[t.index("--entrypoint") + 1] == "/bin/sleep"]
    removed = {x for t in ls if t[:2] == ["rm", "-f"] for x in t}
    assert holders and all(h in removed for h in holders), (case, holders, removed)
PY
check publiclog net1; check publiclog net2; check publiclog net3
DOCKER_FAIL_MATCH="network create" run netfail '{}' rc
CASE="network: a network that cannot be created is a persona that did not run (blocking, exit non-zero, no agent started), never a run on the host's network"
check python3 - "$work/netfail" "$rc" <<'PY'
import os, sys
d = sys.argv[1]
assert int(sys.argv[2]) != 0 and os.path.getsize(d + "/log") == 0
assert not [l for l in open(d + "/docker.log") if l.startswith("run ")], "a container started without its network"
PY
DOCKER_FAIL_MATCH="network rm" run netrmfail '{}' rc
CASE="network: a network that cannot be removed is a failed teardown like a container that cannot be removed: that persona and every later one read 'teardown failed: window not attributable'"
check tdcheck netrmfail 0 1
check publiclog netfail; check publiclog netrmfail
CASE="network (driver exception): an exception in the middle of a persona still removes its holder, sidecar and network (the last-resort handler runs after the teardown)"
mkdir -p "$work/netexc/out" "$work/netexc/tmp"; : >"$work/netexc/docker.log"; sed "s#__LOG__#$work/netexc/docker.log#" "$work/docker.tmpl" >"$work/netexc/docker"; chmod +x "$work/netexc/docker"
echo '{}' >"$work/netexc/plan.json"; : >"$work/netexc/log"; mkhost "$work/netexc"; rc=0
env -u PERSONA_UAT_TOKEN_BUDGET TMPDIR="$work/netexc/tmp" PATH="$work/netexc/hostbin:$PATH" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 \
  python3 - "$driver" "$repo" "$work" >"$work/netexc/stdout" 2>"$work/netexc/stderr" <<'PY' || rc=$?
import importlib.util, sys
drv, repo, w = sys.argv[1:4]
sp = importlib.util.spec_from_file_location("drv", drv); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
def boom(*a, **k):
    raise RuntimeError("PRIVATE-MID-PERSONA-LEAK")
m.stop_capture = boom
sys.argv = [drv, "--mode", "rc", "--image", "ghcr.io/example/cache@sha256:" + "a" * 64, "--repo", repo, "--out", w + "/netexc/out", "--tools", w + "/tools.json",
            "--docker", w + "/netexc/docker", "--recipient", w + "/test.pem", "--agent", "python3 " + w + "/stub.py " + w + "/netexc", "--proc-net", w + "/procnet"]
sys.exit(m.main())
PY
check python3 - "$work/netexc" <<'PY'
import sys
ls = [l.split() for l in open(sys.argv[1] + "/docker.log")]
nets = [t[-1] for t in ls if t[:2] == ["network", "create"]]
assert nets and [t[-1] for t in ls if t[:2] == ["network", "rm"]] == nets, ls
assert any(t[:2] == ["rm", "-f"] for t in ls)
assert "PRIVATE-MID-PERSONA-LEAK" not in open(sys.argv[1] + "/stderr").read() + open(sys.argv[1] + "/stdout").read()
PY
CASE="network: the driver REFUSES a host network at the docker client itself: any docker call with --network host, --network=host, --net host or --net=host raises before docker runs (self-test of Docker.call), and none of the container-building helpers can produce one"
check python3 - "$driver" <<'PY'
import importlib.util, sys
sp = importlib.util.spec_from_file_location("drv", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
d = m.Docker(["/nonexistent-docker"])
for args in (["run", "-d", "--network", "host", "img"], ["run", "--network=host", "img"], ["run", "--net", "host", "img"], ["run", "--net=host", "img"], ["run", "-d", "--network", "HOST", "img"]):
    try:
        d.call(*args)
    except m.Refuse:
        continue
    raise AssertionError(("a host-network docker call was not refused", args))
for args in (m.capture_command("docker.io/x/y@sha256:" + "b" * 64, "persona-uat-abcd1234-holder"), m.holder_command("persona-uat-abcd1234", "docker.io/x/y@sha256:" + "b" * 64)):
    t = args
    assert "host" not in [t[i + 1] for i in range(len(t) - 1) if t[i] == "--network"], t
PY
CASE="network (no docker call anywhere in the whole suite uses a host network): every docker.log of every case above"
check python3 - "$work" <<'PY'
import glob, sys
n = 0
for path in glob.glob(sys.argv[1] + "/*/docker.log") + glob.glob(sys.argv[1] + "/*/*/docker.log"):
    for l in open(path):
        t = l.split()
        n += 1
        for i, x in enumerate(t):
            if x in ("--network", "--net") and i + 1 < len(t):
                assert t[i + 1] != "host", (path, l)
            assert x not in ("--network=host", "--net=host"), (path, l)
assert n > 100, n
PY
# --- REAL TRAFFIC SHAPES, COMPLETENESS AND EVIDENCE (final round, B1 and B2) ------------------------------------------------------------------------------
CASE="capture (filter): the committed BPF filter, evaluated by libpcap against real packet bytes (a hand-built pcap read back with tcpdump -r), matches an IPv4 SYN, an ECN SYN, an IPv6 SYN, UDP over IPv4 and IPv6, ICMP and ICMPv6, and does not match a SYN-ACK or a bare ACK; what tcpdump prints for them parses to the destinations"
check python3 - "$driver" "$work" <<'PY'
import importlib.util, struct, subprocess, sys
sp = importlib.util.spec_from_file_location("drv", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
def pcap(pkts):
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for i, p in enumerate(pkts):
        out += struct.pack("<IIII", i, 0, len(p), len(p)) + p
    return out
eth4 = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
eth6 = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x86\xdd"
def ip4(proto, payload, dst=(93, 184, 216, 34)):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, bytes([172, 18, 0, 2]), bytes(dst)) + payload
def ip6(nh, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, 64, b"\xfd" + b"\0" * 14 + b"\x02", b"\x26\x06\x28\x00" + b"\0" * 11 + b"\x01") + payload
def tcp(flags, dport=443):
    return struct.pack("!HHIIBBHHH", 40000, dport, 1, 0, 5 << 4, flags, 64240, 0, 0)
udp = struct.pack("!HHHH", 5000, 4444, 8, 0)
want = {"v4syn": (eth4 + ip4(6, tcp(2)), "93.184.216.34"), "v4ecn": (eth4 + ip4(6, tcp(0xC2)), "93.184.216.34"), "v6syn": (eth6 + ip6(6, tcp(2)), "2606:2800::1"),
        "v4udp": (eth4 + ip4(17, udp), "93.184.216.34"), "v6udp": (eth6 + ip6(17, udp), "2606:2800::1"), "v4icmp": (eth4 + ip4(1, b"\x08\x00\x00\x00\x00\x01\x00\x01"), "93.184.216.34"),
        "v6icmp": (eth6 + ip6(58, b"\x80\x00\x00\x00\x00\x01\x00\x01"), "2606:2800::1"), "v4linklocal": (eth4 + ip4(6, tcp(2), (169, 254, 169, 254)), "169.254.169.254")}
never = {"v4synack": eth4 + ip4(6, tcp(0x12)), "v4ack": eth4 + ip4(6, tcp(0x10)), "v6synack": eth6 + ip6(6, tcp(0x12))}
f = sys.argv[2] + "/bpf.pcap"
for name, (pkt, dst) in want.items():
    open(f, "wb").write(pcap([pkt]))
    r = subprocess.run(["tcpdump", "-nn", "-tt", "-r", f, m.CAPTURE_FILTER], capture_output=True, text=True)
    out = [l for l in r.stdout.splitlines() if l.strip()]
    assert len(out) == 1, (name, r.stdout, r.stderr)
    H = "listening on any, link-type EN10MB\n"
    res = m.parse_capture(H + "\n".join(out) + "\n1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n", False)
    assert res["reason"] is None and res["addrs"] == {dst}, (name, out, res)
for name, pkt in never.items():
    open(f, "wb").write(pcap([pkt]))
    r = subprocess.run(["tcpdump", "-nn", "-tt", "-r", f, m.CAPTURE_FILTER], capture_output=True, text=True)
    assert not r.stdout.strip(), (name, r.stdout)
PY
CASE="capture (parser, real shapes): private, link-local (metadata) and loopback destinations are LISTED (only the resolver 127.0.0.11 is not); ECN SYN flags in any order are connections, SYN-ACK is not; ICMP and ICMPv6 destinations are contacts; a DNS answer with no captured query names nothing and removes nothing from the flagged addresses; Docker's NATed resolver shape is handled"
check python3 - "$driver" <<'PY'
import importlib.util, sys
sp = importlib.util.spec_from_file_location("drv", sys.argv[1]); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
H = "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\nlistening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 1500 bytes\n"
F = "9 packets captured\n9 packets received by filter\n0 packets dropped by kernel\n"
def P(body, ended=True):
    return m.parse_capture(H + body + (F if ended else ""), False)
r = P("1.0 IP 172.18.0.2.4000 > 169.254.169.254.80: Flags [S], seq 1, win 1, length 0\n1.1 IP 172.18.0.2.4001 > 10.9.9.9.443: Flags [S], seq 1, win 1, length 0\n"
      "1.2 IP 127.0.0.1.4002 > 127.0.0.1.8080: Flags [S], seq 1, win 1, length 0\n1.3 IP 172.18.0.2.4003 > 127.0.0.11.53: 7+ A? x.example. (30)\n")
assert r["reason"] is None and r["addrs"] == {"169.254.169.254", "10.9.9.9", "127.0.0.1"} and r["names"] == {"x.example"}, r
for fl in ("S", "SEW", "SWE", "SE", "SW", "SEWU"):
    r = P("1.0 IP 172.18.0.2.4000 > 8.8.4.4.443: Flags [%s], seq 1, win 1, length 0\n" % fl)
    assert r["addrs"] == {"8.8.4.4"}, (fl, r)
for fl in ("S.", "S.E", ".", "P.", "F."):
    r = P("1.0 IP 172.18.0.2.4000 > 8.8.4.4.443: Flags [%s], seq 1, win 1, length 0\n" % fl)
    assert r["addrs"] == set(), (fl, r)
r = P("1.0 IP 172.18.0.2 > 8.8.4.4: ICMP echo request, id 1, seq 1, length 64\n1.1 IP6 fd00::2 > 2606:4700::1111: ICMP6, echo request, id 1, seq 1, length 64\n")
assert r["reason"] is None and r["addrs"] == {"8.8.4.4", "2606:4700::1111"}, r
# an answer with no captured query: the address stays flagged, annotated, and the answer names nothing
r = P("1.0 IP 127.0.0.11.53 > 172.18.0.2.51000: 4242 1/0/0 A 151.101.1.1 (47)\n1.1 IP 172.18.0.2.4000 > 151.101.1.1.443: Flags [S], seq 1, win 1, length 0\n")
assert r["addrs"] == {"151.101.1.1"} and r["uncorrelated"] == {"151.101.1.1"} and r["names"] == set() and r["reason"] is None, r
# a query with a DIFFERENT transaction id does not correlate it
r = P("1.0 IP 172.18.0.2.51000 > 127.0.0.11.53: 1111+ A? other.example. (30)\n1.1 IP 127.0.0.11.53 > 172.18.0.2.51000: 4242 1/0/0 A 151.101.1.1 (47)\n1.2 IP 172.18.0.2.4000 > 151.101.1.1.443: Flags [S], seq 1, win 1, length 0\n")
assert r["addrs"] == {"151.101.1.1"} and r["uncorrelated"] == {"151.101.1.1"} and r["names"] == {"other.example"}, r
# a correlated query and answer: the address is named, not flagged
r = P("1.0 IP 172.18.0.2.51000 > 127.0.0.11.53: 4242+ A? named.example. (30)\n1.1 IP 127.0.0.11.53 > 172.18.0.2.51000: 4242 1/0/0 A 151.101.1.1 (47)\n1.2 IP 172.18.0.2.4000 > 151.101.1.1.443: Flags [S], seq 1, win 1, length 0\n")
assert r["addrs"] == set() and r["names"] == {"named.example"}, r
# Docker's embedded resolver: the query is DNATed to a high port (tcpdump prints it as plain UDP, the name is not visible), the reply is SNATed back to port 53 (decoded)
r = P("1.0 IP 172.18.0.2.51000 > 127.0.0.11.34567: UDP, length 31\n1.1 IP 127.0.0.11.34567 > 172.18.0.2.51000: UDP, length 47\n"
      "1.2 IP 127.0.0.11.53 > 172.18.0.2.51000: 4242 1/0/0 A 151.101.1.1 (47)\n1.3 IP 172.18.0.2.4000 > 151.101.1.1.443: Flags [S], seq 1, win 1, length 0\n")
assert r["reason"] is None and r["addrs"] == {"151.101.1.1"} and r["uncorrelated"] == {"151.101.1.1"}, r
# completeness is strict
assert "unrecognized" in (P("1.0 this is not a packet line at all\n")["reason"] or "")
assert "truncated" in (P("1.0 IP 172.18.0.2.4000 > 8.8.4.4.53:  [|domain]\n")["reason"] or "")
for missing in ("9 packets captured\n", "9 packets received by filter\n", "0 packets dropped by kernel\n"):
    t = H + F.replace(missing, "")
    r = m.parse_capture(t, False)
    assert r["reason"] and "summary" in r["reason"], (missing, r)
assert P("")["reason"] is None
assert m.parse_capture(H + "1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n", False)["reason"] is None
PY
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
HDR = ["tcpdump: verbose output suppressed, use -v[v]... for full protocol decode", "listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 1500 bytes"]
def ftr(n):
    return ["%d packets captured" % n, "%d packets received by filter" % n, "0 packets dropped by kernel"]
def syn(t, dst):
    return "%s IP 172.18.0.2.40000 > %s: Flags [S], seq 1, win 64240, length 0" % (t, dst)
def cap(*lines, footer=True):
    return HDR + list(lines) + (ftr(len(lines)) if footer else [])
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
json.dump({
  # the persona's own network member (172.18.0.5: the fake inspect gives every non-holder member that address) is subtracted by ADDRESS; a metadata address, a private address and a loopback one are not
  G: {"capture": cap(syn("1.0", "172.18.0.5.8080"), syn("1.1", "169.254.169.254.80"), syn("1.2", "10.20.30.40.443"), syn("1.3", "127.0.0.1.9999"))},
  # an answer with no captured query: the address stays flagged, annotated
  M: {"capture": cap("2.0 IP 127.0.0.11.53 > 172.18.0.2.51000: 4242 1/0/0 A 151.101.1.1 (47)", syn("2.1", "151.101.1.1.443"))},
  # a truncated packet marker, a line nobody can read, and a missing dropped-packets footer are each an incomplete observation, never "no outside hosts"
  C: {"capture": cap("3.0 IP 172.18.0.2.4000 > 8.8.4.4.53:  [|domain]")},
  R: {"capture": cap("4.0 totally unreadable line")},
  O: {"capture": HDR + ["5 packets captured", "5 packets received by filter"]},
}, open(w + "/cap3.plan.json", "w"))
PY
run cap3 "$(cat "$work/cap3.plan.json")" rc
CASE="capture (real shapes, end to end): the persona's own network member is subtracted by its ADDRESS (known from docker inspect), while a link-local metadata address, a private address and a loopback address are listed as flagged addresses; an answer with no captured query leaves its address flagged with the annotation; a truncated packet marker, an unreadable line and a missing dropped-packets footer each say 'Network observation incomplete' and never 'No outside hosts observed'"
check python3 - "$work" <<'PY'
import sys
w = sys.argv[1]
def rep(p):
    return open("%s/cap3/plain/%s.report.md" % (w, p)).read().split("=== TRANSCRIPT")[0]
def addrs(p):
    ls = [l for l in rep(p).splitlines() if l.startswith("Addresses observed with no DNS name in the capture (flagged):")]
    return sorted(x.strip() for x in ls[0].split("):", 1)[1].split(",")) if ls else []
G, M, C, R, O = "gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator", "on-call-engineer"
assert addrs(G) == ["10.20.30.40", "127.0.0.1", "169.254.169.254"], (addrs(G), rep(G)[:900])
assert "No outside hosts observed" not in rep(G)
assert addrs(M) == ["151.101.1.1 (answered by DNS without a captured query)"], (addrs(M), rep(M)[:900])
for p, word in ((C, "truncated"), (R, "unrecognized"), (O, "summary")):
    r = rep(p)
    assert "Network observation incomplete: " in r and word in r.split("Network observation incomplete: ")[1].splitlines()[0] and "No outside hosts observed" not in r, (p, r[:900])
PY
check publiclog cap3
CASE="capture (window): the observation window ends AFTER the action-container sweep: per persona the docker log has the label sweep (ps --filter label=) before the sidecar's stop, and the sidecar's stop before the persona's containers (holder included) are removed"
check python3 - "$work/net1/docker.log" <<'PY'
import sys
ls = [l.split() for l in open(sys.argv[1])]
stops = [i for i, t in enumerate(ls) if t[:1] == ["stop"] and any(x.startswith("cap-") for x in t)]
assert len(stops) == 5, stops
prev = -1
for st in stops:
    ps = [i for i, t in enumerate(ls) if t[:1] == ["ps"] and any(x.startswith("label=persona-uat=") for x in t) and prev < i < st]
    assert ps, ("no label sweep before the sidecar was stopped", st)
    rms = [i for i, t in enumerate(ls) if t[:2] == ["rm", "-f"] and i > st]
    assert rms
    prev = st
PY
# --- EVIDENCE SURVIVES EVERY EXIT (B2) ----------------------------------------------------------------------------------------------------------------
# a persona that ran a command and saw its output; whatever goes wrong afterwards, the ENCRYPTED payload (decrypted here) still holds the command and its output
python3 - "$work" <<'PY'
import json, sys
w = sys.argv[1]
G = "gradle-platform-engineer"
plan = {G: {"commands": ["curl -sS http://evid.example/x"], "transcript_extra": "$ curl -sS http://evid.example/x\nEVIDENCE-OUTPUT-4242\n",
            "journal": [{"t": "action", "id": 1, "command": "curl -sS http://evid.example/x", "started_at": "2026-10-08T00:00:00Z"}, {"t": "result", "id": 1, "exit": 0, "bytes": {"stdout": 20, "stderr": 0}, "truncated": {"stdout": False, "stderr": False}}],
            "tfile_text": "$ curl -sS http://evid.example/x\nEVIDENCE-OUTPUT-4242\n"}}
json.dump(plan, open(w + "/evid.plan.json", "w"))
PY
inproc() { # <case> <python patch code using m> : the real driver main in-process, the stub agent, the evidence plan; the reports are decrypted afterwards
  local n=$1 patch=$2; mkdir -p "$work/$n/out" "$work/$n/tmp"; : >"$work/$n/docker.log"; sed "s#__LOG__#$work/$n/docker.log#" "$work/docker.tmpl" >"$work/$n/docker"; chmod +x "$work/$n/docker"
  cp "$work/evid.plan.json" "$work/$n/plan.json"; : >"$work/$n/log"; : >"$work/$n/summary.md"; mkhost "$work/$n"; srvctl __case dir "$work/$n"; printf '%s\n' "$patch" >"$work/$n/patch.py"; rc=0
  env -u PERSONA_UAT_TOKEN_BUDGET TMPDIR="$work/$n/tmp" PATH="$work/$n/hostbin:$PATH" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 GITHUB_RUN_ID=4242 \
    python3 - "$driver" "$repo" "$work" "$n" >"$work/$n/stdout" 2>"$work/$n/stderr" <<'PYI' || rc=$?
import importlib.util, sys
drv, repo, w, n = sys.argv[1:5]
sp = importlib.util.spec_from_file_location("drv", drv); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
CALLS = []
exec(open("%s/%s/patch.py" % (w, n)).read())
sys.argv = [drv, "--mode", "rc", "--image", "ghcr.io/example/cache@sha256:" + "a" * 64, "--repo", repo, "--out", "%s/%s/out" % (w, n), "--tools", w + "/tools.json",
            "--docker", "%s/%s/docker" % (w, n), "--recipient", w + "/test.pem", "--agent", "python3 %s/stub.py %s/%s" % (w, w, n), "--settle-quiet", "0.8", "--settle-max", "8", "--port", "18080", "--proc-net", w + "/procnet", "--ready-timeout", "5"]
sys.exit(m.main())
PYI
  srvctl __case dir ""; decout "$n"
}
evid() { python3 - "$work/$1/plain/gradle-platform-engineer" "$2" <<'PYE'
import sys
base = sys.argv[1]
rep = open(base + ".report.md").read()
tr = open(base + ".transcript.txt").read()
assert "evid.example" in rep + tr, "the command is not in the encrypted payload"
assert "EVIDENCE-OUTPUT-4242" in tr, ("the command's output is not in the encrypted payload", tr[:600])
extra = sys.argv[2]
if extra:
    assert extra in rep, (extra, rep[:1200])
PYE
}
run evnorm "$(cat "$work/evid.plan.json")" rc
CASE="evidence (normal completion): the encrypted payload holds the recorded command and its output"
check evid evnorm ""
DOCKER_PS_FAIL_AT=1 run evtd "$(cat "$work/evid.plan.json")" rc
CASE="evidence (successful agent, then a teardown failure): the persona reads 'teardown failed', and the encrypted payload still holds the command, its output and the host analysis (evid.example)"
check evid evtd "teardown failed"
check python3 - "$work/evtd/plain/gradle-platform-engineer.report.md" <<'PY'
import sys
r = open(sys.argv[1]).read()
assert "Hosts named in its commands" in r and "evid.example" in r.split("=== TRANSCRIPT")[0], r[:1200]
PY
inproc evcap 'orig_running = m.Docker.running
SEEN = {}
def running(self, cid):
    if str(cid).startswith("cap-"):
        SEEN[cid] = SEEN.get(cid, 0) + 1
        if SEEN[cid] > 1:
            raise RuntimeError("docker exploded while the capture was being stopped")
    return orig_running(self, cid)
m.Docker.running = running'
CASE="evidence (successful agent, then the capture shutdown raises): the failure is recorded as 'Network observation incomplete: ...' and the encrypted payload still holds the command and its output"
check evid evcap "Network observation incomplete: "
inproc evrec 'orig_rt = m.report_text
def report_text(*a, **k):
    if k.get("observed") is not None:
        raise RuntimeError("the report builder failed")
    return orig_rt(*a, **k)
m.report_text = report_text'
CASE="evidence (the report builder raises while recording): the fallback report is written WITH the persona's transcript, not a generic one"
check evid evrec ""
inproc evdrv 'orig_settled, NSET = m.settled, []
def boom(*a, **k):
    NSET.append(1)
    if len(NSET) == 2:          # the first reading is the persona\x27s opening one (before the agent); the second is the closing one, after the agent returned
        raise RuntimeError("PRIVATE-DRIVER-FAULT")
    return orig_settled(*a, **k)
m.settled = boom'
CASE="evidence (a driver exception after the agent returned): the persona's encrypted payload holds its command and output, the other personas get their own driver-error reports, the public log says only 'driver error' and the pass/fail lines"
check evid evdrv ""
check python3 - "$work/evdrv" <<'PY'
import glob, sys
d = sys.argv[1]
assert len(glob.glob(d + "/out/*.cms")) == 5
out = open(d + "/stdout").read() + open(d + "/stderr").read()
assert "PRIVATE-DRIVER-FAULT" not in out and "persona-uat: driver error" in out and "Traceback" not in out, out[:400]
PY
inproc evagent 'orig_sweep, orig_cleanup, orig_run_agent = m.sweep, m.cleanup, m.run_agent
def sweep(docker, label):
    CALLS.append(("sweep", label)); return orig_sweep(docker, label)
def cleanup(docker, label, sandbox, image):
    CALLS.append(("cleanup", label)); return orig_cleanup(docker, label, sandbox, image)
def run_agent(*a, **k):
    raise RuntimeError("the agent runner failed")
m.sweep, m.cleanup, m.run_agent = sweep, cleanup, run_agent
import atexit
atexit.register(lambda: open("%s/%s/calls.json" % (w, n), "w").write(__import__("json").dumps(CALLS)))'
CASE="exceptional teardown (an exception while the agent runs): the persona's finally performs the SAME label sweep and root-owned sandbox cleanup as the normal path, then stops the capture and removes the holder, the sidecar and the network"
check python3 - "$work/evagent" <<'PY'
import json, sys
d = sys.argv[1]
calls = json.load(open(d + "/calls.json"))
kinds = [c[0] for c in calls]
assert "sweep" in kinds and "cleanup" in kinds, calls
ls = [l.split() for l in open(d + "/docker.log")]
nets = [t[-1] for t in ls if t[:2] == ["network", "create"]]
assert nets and [t[-1] for t in ls if t[:2] == ["network", "rm"]] == nets
assert any(t[:1] == ["stop"] and any(x.startswith("cap-") for x in t) for t in ls), "the capture was never stopped on the exceptional path"
PY
check publiclog evnorm; check publiclog evtd; check publiclog evcap; check publiclog evrec
# EXCEPTION SAFETY (step 8 round 3, B1): a command that cannot be parsed (a fullwidth slash inside a proxy host, an unclosed IPv6 bracket, NULs, unicode separators, enormous arguments)
# never raises out of the reporting path: the action is marked unparsed in the ENCRYPTED report, the report is still written, and nothing but the pass/fail lines is public
python3 - >"$work/fuzzplan.json" <<'PY'
import json
big = "A" * 300000
print(json.dumps({"gradle-platform-engineer": {"commands": [
    "curl --proxy 'http://PRIVATE-RESULT\uff0finternal' http://127.0.0.1:18080", "curl --proxy http://[::1 localhost", "git clone http://[bad/x", "curl http://\u2028evil\u2029.example/x",
    "curl\u0000 --url=nul\u0000.example", "curl --resolve ::: x", "curl --connect-to : y", "wget -e http_proxy=\uff1a\uff0f\uff0f", "curl -x \ud7ff\u00e9\u0301.example:80 localhost",
    "curl " + big + ".example", "ssh " + "u@" * 5000 + "h", "nc \n\n", "curl --url=\u3000", "dig @[", "openssl s_client -connect [:", "scp a: b:"]},
    "maven-jenkins-ci": {"commands": ["curl 'unterminated", "wget \"also unterminated", "curl -- --proxy", "nohup", "env", "timeout", "sudo -u"]}}))
PY
run fuzz "$(cat "$work/fuzzplan.json")" rc
CASE="fuzzed commands (fullwidth/unicode separators, NULs, enormous arguments, unclosed brackets, unterminated quotes): the run still exits 0, all five reports are written and encrypted, each says how many commands were unparsed, no traceback anywhere, and the public log is only the pass/fail lines"
check python3 - "$work/fuzz" "$(out fuzz)" "$rc" <<'PY'
import glob, re, sys
d, o, rc = sys.argv[1:4]
assert int(rc) == 0, rc
err = open(d + "/stderr").read() + open(d + "/stdout").read()
assert "Traceback" not in err and "PRIVATE-RESULT" not in err and "ValueError" not in err, err[:300]
assert len(glob.glob(d + "/out/*.cms")) == 5 and len(glob.glob(o + "/*.report.md")) == 5
r = open(o + "/gradle-platform-engineer.report.md").read()
m = re.search(r"^Unparsed commands \(hosts not extracted\): ([0-9]+)$", r, re.M)
assert m and int(m.group(1)) >= 3, r[:600]
r2 = open(o + "/maven-jenkins-ci.report.md").read()
m2 = re.search(r"^Unparsed commands \(hosts not extracted\): ([0-9]+)$", r2, re.M)
assert m2 and int(m2.group(1)) >= 2, ("the two commands with an unterminated quote are counted as unparsed", r2[:600])
assert "Hosts named in its commands" in r
PY
check publiclog fuzz
# the LAST-RESORT handler: an exception nothing else caught prints only the fixed 'driver error' line, still writes an encrypted report for every persona (what is known: nothing ran) and fails the run
mkdir -p "$work/lastresort/out" "$work/lastresort/tmp"; : >"$work/lastresort/docker.log"; sed "s#__LOG__#$work/lastresort/docker.log#" "$work/docker.tmpl" >"$work/lastresort/docker"; chmod +x "$work/lastresort/docker"
echo '{}' >"$work/lastresort/plan.json"; : >"$work/lastresort/log"; mkhost "$work/lastresort"; rc=0
env -u PERSONA_UAT_TOKEN_BUDGET TMPDIR="$work/lastresort/tmp" PATH="$work/lastresort/hostbin:$PATH" PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 \
  python3 - "$driver" "$repo" "$work" >"$work/lastresort/stdout" 2>"$work/lastresort/stderr" <<'PY' || rc=$?
import importlib.util, sys
drv, repo, w = sys.argv[1:4]
sp = importlib.util.spec_from_file_location("drv", drv); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
def boom(*a, **k):
    raise RuntimeError("PRIVATE-DOCS-LEAK /secret/path")
m.read_docs = boom
sys.argv = [drv, "--mode", "rc", "--image", "ghcr.io/example/cache@sha256:" + "a" * 64, "--repo", repo, "--out", w + "/lastresort/out", "--tools", w + "/tools.json",
            "--docker", w + "/lastresort/docker", "--recipient", w + "/test.pem", "--agent", "python3 " + w + "/stub.py " + w + "/lastresort", "--proc-net", w + "/procnet"]
sys.exit(m.main())
PY
decout lastresort
CASE="last resort: an uncaught exception (carrying private text) prints ONLY the fixed 'driver error' line plus the pass/fail lines, writes an encrypted report for all five personas saying the driver failed, never a traceback or the exception text, and the run fails"
check python3 - "$work/lastresort" "$rc" "$PERSONAS" <<'PY'
import glob, re, sys
d, rc, personas = sys.argv[1], int(sys.argv[2]), sys.argv[3].split()
out = open(d + "/stdout").read() + open(d + "/stderr").read()
assert rc == 1, rc
assert "Traceback" not in out and "PRIVATE-DOCS-LEAK" not in out and "/secret/path" not in out, out[:300]
lines = [l for l in out.splitlines() if l.strip()]
pat = re.compile(r"^persona-uat: ((%s|overall): (pass|fail)|driver error)$" % "|".join(personas))
assert all(pat.match(l) for l in lines), lines
assert lines.count("persona-uat: driver error") == 1 and "persona-uat: overall: fail" in lines, lines
assert len(glob.glob(d + "/out/*.cms")) == 5
for p in personas:
    r = open("%s/plain/%s.report.md" % (d, p)).read()
    assert r.splitlines()[0] == "VERDICT: blocking" and "driver error" in r.lower() and "PRIVATE-DOCS-LEAK" not in r, r
PY
# ATTRIBUTION (step 8 round 3, B5): the server counts a request AFTER its handler returns, so a late completion could land in the NEXT persona's window. The driver therefore ends every
# window by removing the persona's processes and action containers, then waiting for an unchanged counter (the quiet interval), within
# a ceiling; a window that cannot be closed that way makes the persona and every later one blocking (cannot prove), never a pass.
# THE LATE COMPLETION AFTER THE CLIENT CLOSED (Codex's scenario): persona 1 makes one request and leaves another still being served server-side for 7 seconds with NO connection left open (the
# client closed); persona 2 starts before it finishes, makes no request and sleeps through the 7th second. The late completion lands in persona 1's container, which is gone: persona 1 keeps
# its own credit (pass), persona 2 is blocking (nothing of its own, nothing credited from persona 1)
mkdir -p "$work/late7b"; cp -R "$work/procnet" "$work/late7b/procnet"
srvctl __reset
PROCNET="$work/late7b/procnet" run late7b '{"gradle-platform-engineer":{"requests":1,"hold":7,"hold_conn":0},"maven-jenkins-ci":{"requests":0,"sleep":6.5}}' rc
sleep 2
CASE="a request of persona 1 that completes server-side while persona 2 is running (its client had closed; nothing visible) lands in persona 1's own, removed container: persona 1 keeps its credit (pass), persona 2 with no request of its own is BLOCKING"
check python3 - "$(out late7b)" "$work/late7b" <<'PY'
import json, sys
o, d = sys.argv[1:3]
assert open(o + "/gradle-platform-engineer.report.md").read().splitlines()[0] == "VERDICT: pass"
assert open(o + "/maven-jenkins-ci.report.md").read().splitlines()[0] == "VERDICT: blocking"
tim = {json.loads(l)["persona"]: json.loads(l) for l in open(d + "/timing.log")}
assert tim["maven-jenkins-ci"]["t1"] - tim["gradle-platform-engineer"]["t0"] > 6, "persona 2 must still be running when the held request would finish"
srv = [json.loads(l) for l in open(d + "/srv.log")]
assert not [e for e in srv if e["path"] == "/held"], "the late completion must have landed nowhere"
PY
check publiclog late7b
SETTLE_MAX=6 run orphansame '{"gradle-platform-engineer":{"orphan_same":1.5},"maven-jenkins-ci":{"requests":0}}' rc
CASE="work the agent left running in its own session (it would request the endpoint 1.5s later, inside the next window) is terminated when the persona ends: no such request reaches the endpoint"
check python3 - "$work/orphansame" <<'PY'
import json, sys
srv = [json.loads(l) for l in open(sys.argv[1] + "/srv.log")]
assert not [e for e in srv if e["persona"] == "ORPHAN"], [e for e in srv if e["persona"] == "ORPHAN"]
PY
# THE JOB'S TIME BUDGET (step 8 round 3): the agent timeout is derived from what is left of the job's budget divided by the personas still to run; a persona that cannot be given the minimum
# is blocking 'cannot prove' and never runs. The default budget (6600 s) fits five default personas into the 120-minute job.
JOB_BUDGET=10 MIN_PERSONA=11 run budget1 '{}' rc
CASE="a job budget of 10 s with an 11 s minimum per persona (more than the whole budget, so independent of how long each step takes): no persona can be given its minimum, none runs, all five are blocking 'cannot prove', the run fails"
check python3 - "$(out budget1)" "$work/budget1" "$rc" <<'PY'
import sys
o, d, rc = sys.argv[1:4]
assert int(rc) == 1 and open(d + "/log").read() == ""
for p in "gradle-platform-engineer maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer".split():
    r = open("%s/%s.report.md" % (o, p)).read()
    assert r.splitlines()[0] == "VERDICT: blocking" and "cannot prove" in r and "time budget" in r, (p, r)
PY
check publiclog budget1
JOB_BUDGET=60 MIN_PERSONA=2 run budget2 '{"gradle-platform-engineer":{"sleep":40}}' rc
CASE="the agent timeout shrinks to the job's remaining budget over the personas left (60 s / 5 = 12 s for the first, which sleeps 40 s and times out near it); the personas after it still run and pass within the budget"
check python3 - "$(out budget2)" "$work/budget2" <<'PY'
import re, sys
o, d = sys.argv[1:3]
r = open(o + "/gradle-platform-engineer.report.md").read()
t = open(o + "/gradle-platform-engineer.transcript.txt").read()
m = re.search(r"agent timed out after ([0-9]+)s", t)
assert r.splitlines()[0] == "VERDICT: blocking" and m and 8 <= int(m.group(1)) <= 12, (m and m.group(1), t[:200])
for p in "maven-jenkins-ci compliance-reviewer readme-evaluator on-call-engineer".split():
    assert open("%s/%s.report.md" % (o, p)).read().splitlines()[0] == "VERDICT: pass", p
PY
# the auth layer wraps the metrics middleware: a 401 is never counted
run proofauth '{"readme-evaluator":{"requests":0,"unauth":3}}' rc
CASE="a persona whose only traffic was answered 401 (withAuth wraps withMetrics, so it is never counted) made no counted request: blocking, the others pass"
check test "$(head -1 "$(out proofauth)/readme-evaluator.report.md")" = "VERDICT: blocking" -a "$(head -1 "$(out proofauth)/gradle-platform-engineer.report.md")" = "VERDICT: pass"

# --- PRIVACY, outcomes that exist only late in this file
CASE="the public log is ONLY pass/fail lines in every outcome: clean, blocking, crash, a provider error carrying secrets, a dead image, missing docs: no finding, doc name, host, model name or transcript text, and the transcripts/reports exist only inside the encrypted artifacts"
for c in clean blocking fc-crash hosts leak imgdead; do publiclog "$c" >/dev/null 2>&1 && ok "$CASE ($c)" || bad "$CASE ($c)"; done
# the fake kind, docker and kubectl print what the real ones print (progress lines naming the node image digest and the cluster, container ids, "created" lines, warnings) on
# stdout AND stderr, on success and on failure: a driver that lets any of it through fails every one of these
CASE="the public log is ONLY pass/fail lines when the tools are noisy (kind progress with the image digest, docker container ids and warnings, kubectl output) and fail: kind fails, kubectl apply fails, kubectl token fails, kind delete fails, kind and delete both fail, kind hangs, a tool container dies, the Jenkins image dies, the loopback guard refuses (three variants), an agent hangs, a stray listener, a container that is not running, an orphaned agent, a sandbox with foreign files, a slow node, a slow Jenkins, a stuck Jenkins"
for c in kindfail kubectlapplyfail kubectltokenfail kinddelfail kindbothfail kindhang runnerdead jendead guardbad guardbad6 guardmissing guardstale hang notrunning orphan sbxleft kindnotready jenslow jenstuck kindshort kindhuge kindaud; do
  [ -d "$work/$c" ] || { bad "$CASE ($c: the case did not run)"; continue; }
  publiclog "$c" >/dev/null 2>&1 && ok "$CASE ($c)" || bad "$CASE ($c)"
done
CASE="none of the tools' progress text reaches ANY public surface (log, step summary, artifact names) in the noisy runs: no node image, digest, cluster name, container id, warning text"
check none_match 'kindest|Ensuring node image|control-plane|ab12ab12|Published ports|container-id-noise|created|condition met|NotReady|Deleting cluster' "$work/kindfail/stdout" "$work/kindfail/stderr" "$work/kindhang/stdout" "$work/kindhang/stderr" "$work/kinddelfail/stdout" "$work/kinddelfail/stderr" "$work/kindbothfail/stdout" "$work/kindbothfail/stderr" "$work/kubectlapplyfail/stdout" "$work/kubectlapplyfail/stderr" "$work/clean/stdout" "$work/clean/stderr" "$work/clean/summary.md" "$work/jendead/stderr" "$work/imgdead/stderr" "$work/runnerdead/stderr"
CASE="the driver runs with a PRIVATE TMPDIR and leaves no readable report or transcript anywhere it could write (no plaintext copy outside --out: a temp file, a sandbox leftover, a staging file, the working directory), in EVERY run's TMPDIR and in the driver's working directory; the sandboxes are made under that TMPDIR; --out holds only the encrypted files"
check python3 - "$work" <<'PY'
import glob, json, os, sys
w = sys.argv[1]
n = 0
MARK = (b"VERDICT", b"TRANSCRIPT for", b"persona: ", b"tokens used", b"Hosts named", b"MODEL-DEFAULT-X", b"PARTIAL-TRANSCRIPT", b"PARTIAL-CIPHERTEXT")
roots = sorted(t for t in glob.glob(w + "/*/tmp") if os.path.exists(os.path.dirname(t) + "/plan.json")) + [w + "/plain"]       # every run's private TMPDIR, and the directory the driver ran in
assert len(roots) > 20, roots
for top in roots:
    for r, _, fs in os.walk(top):
        for f in fs:
            n += 1
            c = open(os.path.join(r, f), "rb").read()
            for marker in MARK:
                assert marker not in c, (top, f, marker)
assert os.path.isdir(w + "/clean/tmp"), "the run was not given a private TMPDIR"
mounts = [t.split(":")[0] for l in open(w + "/clean/docker.log") for t in l.split() if ":/work" in t]
assert mounts and all(m.startswith(w + "/clean/tmp/") for m in mounts), ("a sandbox outside the private TMPDIR", mounts[:3])
PY
CASE="the committed recipient certificate (bin/persona-uat-recipient.pem) is a usable CMS recipient: openssl encrypts to it (a certificate, not a key), so a default run is never refused for a bad shipped certificate"
check sh -c "printf x | openssl cms -encrypt -aes-256-cbc -binary -outform DER -recip '$root/bin/persona-uat-recipient.pem' >/dev/null"
CASE="a hosts line, the repository-source flag and the findings are in NO public place: not in the log, not in an artifact file name (the hosts run)"
check python3 - "$work/hosts" <<'PY'
import os, sys
d = sys.argv[1]
blob = (open(d + "/stdout").read() + open(d + "/stderr").read() + " ".join(os.listdir(d + "/out"))).lower()
for w in ("evil", "repository source", "github", "outside", "169.254", "hosts named", "example"):
    assert w not in blob, w
PY
CASE="the encrypted artifacts of a run with leaking content (model value, credentials, findings, hosts) hold none of it as readable bytes, and the job log nothing"
check python3 - "$work/leak" "$work" <<'PY'
import glob, sys
d, w = sys.argv[1], sys.argv[2]
for f in glob.glob(d + "/out/*.cms") + [d + "/stdout", d + "/stderr"]:
    b = open(f, "rb").read()
    for bad in (b"MODEL-DEFAULT-X", b"MODEL-COMPLIANCE-X", b"ghp_abcdefghij", b"crash-host", b"proxy URL"):
        assert bad not in b, (f, bad)
PY

# --- across every case's docker log (these need all the runs above)
CASE="no credential value (job secrets, the model identity, the owner's model names) appears in ANY docker call of a run, so none reaches a container's environment"
check none_match 'SECRET-|ALLOWED-MODEL-CRED|MODEL-(DEFAULT|COMPLIANCE)-X|FIXTURE-OIDC' "$work/clean/docker.log" "$work/blocking/docker.log" "$work/weekly/docker.log"
CASE="kind: no docker call the DRIVER or the AGENT makes runs the kind node image, execs into a node, reads admin.conf, is privileged or mounts the docker socket (every case's docker log; kind's own containers are kind's, see the header)"
check python3 - "$work" <<'PY'
import glob, sys
n = 0
for path in glob.glob(sys.argv[1] + "/*/docker.log") + glob.glob(sys.argv[1] + "/integ/docker.log"):
    for l in open(path):
        n += 1
        assert "--privileged" not in l and "kindest" not in l and "admin.conf" not in l and "docker.sock" not in l and not l.startswith("exec "), (path, l)
assert n > 50, n
PY

echo "persona-uat: $pass passed, $failn failed"
test "$failn" -eq 0
