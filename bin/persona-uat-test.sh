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
#   (2) tools file: eight entries (cosign, gitlab-runner, gradle, jenkins, kind, kubectl, maven, shell). The agent is started with
#       `--tools <that file>` (not --shell-image). Jenkins: `run -d -p 127.0.0.1:<port+1>:8080 -e JAVA_OPTS=-Djenkins.install.runSetupWizard=false
#       <digest>` and no other -e; the GitLab runner: `run -d -p 127.0.0.1:<port+2>:9252 <digest> run --listen-address=0.0.0.0:9252` (the flag
#       enables its metrics HTTP server) and no -e; readiness is tied to THAT container: the recording docker serves port+2 only when it was
#       started with exactly that argument vector. Both are reached over http://127.0.0.1:<port> by the persona's shell tool. The kind node image
#       is never run through docker by the driver. The sandbox directories are mode 0777 (the tool images run as other non-root uids and must be
#       able to create files); the docs files stay 0644 (read-only for others).
#   (3) the answer's optional `commands` list is where the driver derives each report's single line `Hosts contacted outside the docs: a, b`
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
#       immediately after it returns; persona_requests = after - before (no correction); a persona that finished with NO findings and
#       persona_requests <= 0 (counter backwards, or a scrape that cannot be taken or parsed) is blocking: "the endpoint was never exercised".
#       The windows of two personas never overlap, in rc and in weekly mode alike, and nothing the persona's agent started survives its window
#       (a timed-out agent's leftovers are terminated). The fixture counts a request BEFORE it flushes the response (deterministic; the real
#       server counts just after the handler returns, a race the tests cannot model: a very late request may miss the after-scrape). The stub
#       agent makes plan["requests"] counted requests (default 1; plan["methods"] varies the verb) and plan["uncounted"] uncounted ones.
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
#       The gradle/maven entrypoint models are the FAKE's (program first; the exact exit status and text of a real digest's failure cannot be checked offline).
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
driver="$root/bin/persona-uat.py"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()   { pass=$((pass+1)); echo "ok   $1"; }
bad()  { failn=$((failn+1)); echo "FAIL $1"; }
CASE=""
check() { if "$@" >/dev/null 2>&1; then ok "$CASE"; else bad "$CASE"; fi; }
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
echo "SECRET-RELEASING"    >"$repo/RELEASING.md"
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
cat >"$work/tools.json" <<EOF
{"cosign": "$CSG", "gitlab-runner": "$GLR", "gradle": "$GRD", "jenkins": "$JEN", "kind": "$KND", "kubectl": "$KCT", "maven": "$MVN", "shell": "$SHL"}
EOF
TOOLKEYS="cosign gitlab-runner gradle jenkins kind kubectl maven shell"
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
import time, urllib.request, urllib.error
kc = os.path.join(req["docs_dir"], "kubeconfig")
LEAK = "ghp_abcdefghij0123456789ABCDEF"      # a credential-looking marker, and the request's own model value: neither may survive in a retained artifact
CORPUS = [LEAK, "github_pat_11ABCDEFG0abcdefghijkl_xyz", "AKIAABCDEFGHIJKLMNOP", "sk-abcdefghijklmnopqrstuvwx", "Authorization: Bearer abcdefghijklmnop", "password=hunter2xyz", "-----BEGIN " "PRIVATE KEY-----"]
if p.get("daemon"):         # a tool container managed by the DAEMON, started through the recording docker; its client is killed at once (a shell timeout, a teardown)
    av = sys.argv[2:]
    tools = json.load(open(av[av.index("--tools") + 1]))
    cl = subprocess.Popen(shlex.split(av[av.index("--docker") + 1]) + ["run", "--rm", "--network", "host"] + (["--label", av[av.index("--label") + 1]] if "--label" in av else []) +
                          ["-v", req["docs_dir"] + ":/work", "-w", "/work", tools["shell"], "sh", "-c", "DAEMON"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.7)
    cl.kill()
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
if p.get("orphan"):         # work the agent started in its OWN session, outliving it: it requests the endpoint after this many seconds
    subprocess.Popen([sys.executable, "-c", "import sys,time,urllib.request;time.sleep(float(sys.argv[2]));urllib.request.urlopen(urllib.request.Request(sys.argv[1]+'/orphan-work',headers={'X-Persona':'ORPHAN'}),timeout=5)\n", req["endpoint"], str(p["orphan"])],
                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if p.get("readonly_dir"):   # what a container of another uid leaves behind: a directory the runner cannot empty (the real thing, a directory OWNED BY ANOTHER UID, cannot be modelled)
    os.makedirs(os.path.join(req["docs_dir"], "created"), exist_ok=True)
    open(os.path.join(req["docs_dir"], "created", "x"), "w").write("x")
    os.chmod(os.path.join(req["docs_dir"], "created"), 0o555)
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
if "commands" in p:
    ans["commands"] = p["commands"]
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
if [ -n "${DOCKER_FAIL_MATCH:-}" ] && [[ "$*" == *"$DOCKER_FAIL_MATCH"* ]]; then echo "docker: simulated failure" >&2; exit 125; fi
if [ -n "${DOCKER_NOISE:-}" ] && { [ "$1" = rm ] || { [ "$1" = run ] && [ "$2" = -d ]; }; }; then
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
if [ "$1" = run ] && [ "$2" = --rm ]; then
  python3 - "$CONTAINERS" "$@" <<'PYX'
import json, os, subprocess, sys, time
reg, a = sys.argv[1], sys.argv[2:]
host = next(x.split(":")[0] for i, x in enumerate(a) if i and a[i - 1] == "-v")
img = next((i for i, x in enumerate(a) if "@sha256:" in x), None)
rest = a[img + 1:] if img is not None else []
repo = a[img] if img is not None else ""
if a[a.index("--user") + 1:][:1] == ["0:0"] if "--user" in a else False:
    # a CLEANUP container: it runs as root over the mounted sandbox and empties it (what a root-owned file a tool image left behind needs)
    import shutil
    for child in os.listdir(host):
        p = os.path.join(host, child)
        shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
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
    open(D + "/alive", "w").write("1")        # the cluster exists until `kind delete cluster`: the fake kubectl answers the persona's calls only while it does
    if pn:      # the API server of a real kind cluster LISTENS on the loopback: show it in the kernel table the driver's guard reads
        raw = "%08X" % struct.unpack("<I", socket.inet_aton("127.0.0.1"))[0]
        open(pn + "/tcp", "a").write("   9: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9999 1 0\n" % (raw, port))
elif a[:2] == ["delete", "cluster"] and cfg.get("kind_delete_fail"):
    sys.stderr.write("kind: simulated delete failure\n"); sys.exit(1)
elif a[:2] == ["delete", "cluster"]:
    if os.path.exists(D + "/alive"):
        os.remove(D + "/alive")
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
API_AUD = "https://kubernetes.default.svc"
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
    """Go time.ParseDuration restricted to s, m, h; kubectl create token refuses sub-second precision"""
    if not re.fullmatch(r"(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:s|m|h))+", d):
        return None
    v = sum(float(n) * {"s": 1, "m": 60, "h": 3600}[u] for n, u in re.findall(r"([0-9]+\.?[0-9]*|\.[0-9]+)(s|m|h)", d))
    return v if v > 0 and abs(v - round(v)) < 1e-9 else None
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
    secs = go_seconds(dur) if dur is not None else 600
    if not secs:
        finish(1, "error: invalid duration %r (whole seconds, Go syntax)" % dur)
    if secs > 86400:
        finish(1, "error: the requested lifetime exceeds this cluster's maximum (24h)")
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
open(d + "/hostbin/openssl", "w").write("#!/usr/bin/env python3\nimport json, os, sys\nopen(%r, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n"
    "if %r and sys.argv[1:3] == ['cms', '-encrypt']:\n    sys.stderr.write('openssl: simulated failure\\n'); sys.exit(1)\nos.execv(%r, [%r] + sys.argv[1:])\n" % (d + "/openssl.log", fail, real, real))
os.chmod(d + "/hostbin/openssl", 0o755); open(d + "/openssl.log", "w").close()
PYO
  sed "s#__DIR__#$d#" "$work/kind.tmpl" >"$d/hostbin/kind"; sed "s#__DIR__#$d#" "$work/kubectl.tmpl" >"$d/hostbin/kubectl"; chmod +x "$d/hostbin/kind" "$d/hostbin/kubectl"
  python3 - "$d/host.cfg" "${KIND_FAIL:-}" "${KUBECTL_FAIL_MATCH:-}" "${KIND_PORT:-18090}" "${KIND_PROCNET:-}" "${KIND_DELETE_FAIL:-}" "${KIND_HANG:-}" "${KIND_TOKEN_LIFETIME:-}" <<'PYC'
import json, sys
json.dump({"kind_fail": sys.argv[2], "kubectl_fail_match": sys.argv[3], "kind_port": int(sys.argv[4]), "procnet": sys.argv[5], "kind_delete_fail": sys.argv[6], "kind_hang": sys.argv[7], "token_lifetime": sys.argv[8]}, open(sys.argv[1], "w"))
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
lines = [l for f in ("stdout", "stderr") for l in open(d + "/" + f).read().splitlines() if l.strip()]
pat = re.compile(r"^persona-uat: (%s|overall): (pass|fail)$" % "|".join(personas))
bad = [l for l in lines if not pat.match(l)]
assert not bad, ("the job log carries more than a pass/fail line per persona and overall", bad[:3])
got = {}
for l in lines:
    m = pat.match(l); assert m.group(1) not in got, ("a duplicate line", l); got[m.group(1)] = m.group(2)
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
S = {"c": {}, "mode": "ok", "dir": "", "silent": False, "seen": False, "queue": [], "unc": 0, "delay": 0.0}
UNCOUNTED = ("/metrics", "/healthz", "/statusz")
def total():
    return sum(S["c"].values())
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
            if u.path == "/__reset":
                S["c"].clear(); S["unc"] = 0; return self.reply(200, "ok")
            known = u.path in UNCOUNTED or (self.command in ("GET", "HEAD") and os.path.isfile(os.path.join(root, u.path.lstrip("/"))))
            code = "201" if self.command == "PUT" else ("200" if known else "404")
            who = self.headers.get("X-Persona")
            if who and who != "NOISE":
                S["seen"] = True
            unauth = self.headers.get("X-Unauthorized") == "1"      # withAuth wraps withMetrics: a 401 is never counted
            if unauth:
                code = "401"
            counted = u.path not in UNCOUNTED and not unauth and not (S["silent"] and (not who or (who == "NOISE" and not S["seen"])))
            later = None
            if counted:
                if S["delay"] > 0:
                    later = (self.command, code)
                else:
                    S["c"][(self.command, code)] = S["c"].get((self.command, code), 0) + 1
            if u.path in UNCOUNTED:
                S["unc"] += 1
            if S["dir"]:
                open(os.path.join(S["dir"], "srv.log"), "a").write(json.dumps({"t": time.time(), "path": u.path, "method": self.command, "counted": counted,
                                                                               "persona": who, "total": total()}) + "\n")
            if later:
                def bump(k=later):
                    with lock:
                        S["c"][k] = S["c"].get(k, 0) + 1
                threading.Timer(S["delay"], bump).start()
            if unauth:
                return self.reply(401, "unauthorized")
            if u.path == "/metrics" and self.command == "GET":
                mode = S["queue"].pop(0) if S["queue"] else S["mode"]
                if mode == "garbage":
                    return self.reply(200, "<html>not prometheus</html>")
                if mode == "status500":
                    return self.reply(500, "boom")
                n = total()
                lines = []
                fam = "fscache_http_requests_total"
                if mode == "nofamily":
                    pass                      # a real fresh server: the whole family (HELP, TYPE and samples) is absent
                elif mode == "nometric":
                    lines += ["# HELP %s Requests served (%s 999999 is not a sample)." % (fam, fam), "# TYPE %s counter" % fam]     # HELP and TYPE, no sample
                elif S["c"]:
                    lines += ["# HELP %s Requests served (%s 999999 is not a sample)." % (fam, fam), "# TYPE %s counter" % fam]
                    for (m, c), v in sorted(S["c"].items()):
                        lines.append('%s{method="%s",status="%s"} %s' % (fam, m, c, ("%d.0" % v) if (m, c) == ("GET", "200") else v))
                lines += ["# TYPE go_goroutines gauge", "go_goroutines 9",
                          "# TYPE fscache_http_requests_total_uncounted counter", 'fscache_http_requests_total_uncounted{path="all"} %d' % S["unc"],     # a decoy that moves on uncounted traffic
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
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 & SRV2=$!
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
  mkdir -p "$work/plain" "$work/$name"; echo "$plan" >"$work/$name/plan.json"; : >"$work/$name/log"; : >"$work/$name/docker.log"; : >"$work/$name/gh.log"
  # the stub's failure switches are baked into the case's own docker script (the driver passes the docker client only its allowlisted DOCKER_* variables)
  sed "s#__LOG__#$work/$name/docker.log#" "$work/docker.tmpl" >"$work/$name/docker"; chmod +x "$work/$name/docker"
  { echo "DOCKER_FAIL_MATCH=$(printf %q "${DOCKER_FAIL_MATCH:-}"); DOCKER_INSPECT_FALSE=$(printf %q "${DOCKER_INSPECT_FALSE:-}"); DOCKER_NOISE=$(printf %q "${DOCKER_NOISE:-}"); DOCKER_RUNNER_DEAD=$(printf %q "${DOCKER_RUNNER_DEAD:-}")"; } >"$work/$name/docker.env"
  # the host binaries (kind, kubectl) first on PATH; KIND_LISTEN=1: the kind API port shows up in (a per-case copy of) the proc-net table while the cluster exists
  local pnet="${PROCNET:-$work/procnet}"
  if [ -n "${KIND_LISTEN:-}" ]; then rm -rf "$work/$name/procnet"; cp -R "$pnet" "$work/$name/procnet"; pnet="$work/$name/procnet"; fi
  KIND_PROCNET="${KIND_LISTEN:+$pnet}" mkhost "$work/$name"
  rm -f "$work/$name/srv.log"; srvctl __case dir "$work/$name"
  sed -i.bak "2i\\
. \"$work/$name/docker.env\"" "$work/$name/docker"; rm -f "$work/$name/docker.bak"
  rc=0
  local tw=(); [ -n "${RUN_TIMEOUT:-}" ] && tw=(perl -e 'alarm shift; exec @ARGV' "$RUN_TIMEOUT")
  local t_start=$SECONDS
  env -u PERSONA_UAT_TOKEN_BUDGET GITHUB_RUN_ID=4242 GITHUB_REPOSITORY=own/cache \
      GITHUB_TOKEN=SECRET-GH-TOKEN GH_TOKEN=SECRET-GH2 AWS_SECRET_ACCESS_KEY=SECRET-AWS-KEY REPO_CHECKOUT="$repo" \
      GITHUB_WORKSPACE="$repo" ACTIONS_ID_TOKEN_REQUEST_TOKEN=SECRET-OIDC ACTIONS_ID_TOKEN_REQUEST_URL=http://oidc.invalid \
      ACTIONS_RUNTIME_TOKEN=SECRET-RT ANTHROPIC_API_KEY=ALLOWED-MODEL-CRED ANTHROPIC_IDENTITY_TOKEN_FILE=/x/token SOME_UNKNOWN_SECRET=SECRET-UNK AWS_SESSION_TOKEN=SECRET-AWS2 \
      ANTHROPIC_FEDERATION_RULE_ID=f1 ANTHROPIC_ORGANIZATION_ID=o1 ANTHROPIC_SERVICE_ACCOUNT_ID=s1 ANTHROPIC_WORKSPACE_ID=w1 \
      GITHUB_SERVER_URL=https://github.com RUNNER_TEMP=/r ACTIONS_CACHE_URL=http://c.invalid GH_ENTERPRISE_TOKEN=SECRET-GHE \
      PERSONA_UAT_MODEL=MODEL-DEFAULT-X PERSONA_UAT_COMPLIANCE_MODEL=MODEL-COMPLIANCE-X PATH="$work/$name/hostbin:$PATH" "$@" \
      ${tw[@]+"${tw[@]}"} bash -c 'cd "$1" && shift && exec "$@"' _ "$work/plain" python3 "$driver" --mode "$mode" --image "${IMAGE:-$IMG}" --repo "$repo" --out "$work/$name/out" \
        --tools "${TOOLS:-$work/tools.json}" --docker "$work/$name/docker" --recipient "${RECIPIENT:-$work/test.pem}" --port "${PORT:-18080}" --ready-timeout "${READY_TIMEOUT:-5}" \
        --agent "python3 $work/stub.py $work/$name" --proc-net "$pnet" ${ALLOW_LISTEN:+--allow-listen $ALLOW_LISTEN} ${AGENT_TIMEOUT:+--agent-timeout $AGENT_TIMEOUT} >"$work/$name/stdout" 2>"$work/$name/stderr" || rc=$?
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
    # steps that need a tool the environment does not have (gh, docker, jq, kubectl exec) are ENVIRONMENT LIMITS, reported as friction, never 'fails as written'
    for w in ("environment limit", "docker", "jq", "kubectl exec", "not as blocking", "friction"):
        assert w in text.lower(), (p, w, "the persona is not told that missing tools are environment limits")
    assert re.search(r"\bgh\b", text.lower()), (p, "gh")
PY
CASE="a clean run leaves no issue file anywhere and calls gh never: --out holds only <persona>.cms"
check test ! -e "$work/clean/out/friction-issue.md" -a ! -e "$work/clean/out/blocking-issue.md" -a ! -s "$work/clean/gh.log"
CASE="each report states its verdict in the first line"
check test "$(head -1 "$(out clean)/on-call-engineer.report.md")" = "VERDICT: pass"

# --- AC1: the image under test starts BY DIGEST and everything is removed afterwards ------------------------------
CASE="the driver starts the image under test by digest, on loopback only, and hands that endpoint to every agent"
check python3 - "$work/clean/docker.log" "$work/clean/log" "$IMG" <<'PY'
import json, sys
runs = [l for l in open(sys.argv[1]) if l.startswith("run ")]
img = [l for l in runs if sys.argv[3] in l]
assert len(img) == 1, runs
assert "127.0.0.1:18080" in img[0], img[0]
for l in open(sys.argv[2]):
    assert json.loads(l)["request"]["endpoint"] == "http://127.0.0.1:18080"
    assert json.loads(l)["request"]["image"] == sys.argv[3]
PY
CASE="every container started is removed (rm -f) before the driver exits, even after a failure"
run blockrm '{"maven-jenkins-ci":{"findings":[{"kind":"blocking","text":"x"}]}}' rc
check python3 - "$work/clean/docker.log" "$work/blockrm/docker.log" <<'PY'
import sys
for path in sys.argv[1:]:
    lines = open(path).read().splitlines()
    started = [f"cid-{i+1}" for i, l in enumerate(x for x in lines if x.startswith("run -d "))]
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
assert rows["maven-jenkins-ci"]["jenkins"]["endpoint"] == "http://127.0.0.1:18081", rows
assert rows["maven-jenkins-ci"]["gitlab-runner"]["endpoint"] == "http://127.0.0.1:18082", rows
k = rows["on-call-engineer"]["kind"]
assert "container" not in k, ("kind is no container any more", k)
assert k["endpoint"] == "https://127.0.0.1:18090" and k["kubeconfig"] == "kubeconfig", k
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
assert not [l for l in open(sys.argv[2]) if l.startswith("run -d ") and sys.argv[3] in l], "the driver itself must not START the shell image as a service: the agent does, per action (the driver's only use is the cleanup container)"
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
        elif f == "-p":
            assert re.fullmatch(r"127\.0\.0\.1:\d+:\d+", flags[i + 1]), ("only loopback publishing", l)
            host, cport = flags[i + 1].split(":")[1:]
            maps[ref] = (host, cport)
            i += 2
        elif f == "-e":
            assert ref == jen, ("-e is for Jenkins only", l)
            envs.setdefault(ref, []).append(flags[i + 1]); i += 2
        else: raise AssertionError(("a flag outside the allowlist (no -v/--mount/--env/--env-file/-eX/--network/--cap-add/--user ...)", f, l))
assert sorted(seen) == sorted(allowed), seen
for ref, want in ((img, ("18080", "8080")), (jen, ("18081", "8080")), (glr, ("18082", "9252"))):
    assert maps.get(ref) == want, ("this container must publish exactly its endpoint's port", ref, maps.get(ref), want)
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
  CASE="the tools file without its $key entry refuses the run (exit 2) and nothing starts: the key set is exactly the eight"
  TOOLS="$work/tools-missing-$key.json" run "missing-$key" '{}' rc
  check test "$rc" -eq 2 -a ! -s "$work/missing-$key/docker.log" -a ! -s "$work/missing-$key/log" -a ! -s "$work/missing-$key/host.log"
done
python3 - "$work/tools.json" "$work/tools-extra.json" <<'PY'
import json, sys
t = json.load(open(sys.argv[1])); t["terraform"] = "docker.io/hashicorp/terraform@sha256:" + "9" * 64
json.dump(t, open(sys.argv[2], "w"))
PY
CASE="a tools file with a ninth entry (terraform) refuses the run (exit 2) and nothing starts"
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
assert c["server"] == "https://127.0.0.1:18090" and c.get("certificate-authority-data") == "CA-DATA-MARKER-PUBLIC", c
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
KIND_LISTEN=1 run kindlisten '{}' rc
CASE="guard: the kind API port (the admin kubeconfig's server, 18090) is a known listener for the on-call persona while its cluster exists: the run is clean"
check test "$rc" -eq 0
check python3 - "$work/kindlisten" <<'PY'
import sys
tcp = open(sys.argv[1] + "/procnet/tcp").read()
assert not [l for l in tcp.splitlines() if l.rstrip().endswith(" 9999 1 0")], "the cluster was not deleted before the run ended"
PY
mkprocnet "$work/pn-bad" "0A:127.0.0.1:9999"
KIND_PORT=18123 KIND_LISTEN=1 run kindport '{}' rc
CASE="kind port varies (kind picks a random loopback port): with the admin kubeconfig's server on 18123 the guard, the request's kind endpoint and the persona kubeconfig all follow it and the run is clean (a hard-coded 18090 fails)"
check test "$rc" -eq 0
check python3 - "$work/kindport" "$work" <<'PY'
import json, sys, yaml
sys.path.insert(0, sys.argv[2]); import kh
d = sys.argv[1]
r = kh.persona_row(d)[0]
assert r["request"]["tools"]["kind"]["endpoint"] == "https://127.0.0.1:18123", r["request"]["tools"]
kc = yaml.safe_load(r["content"]["kubeconfig"])
assert kc["clusters"][0]["cluster"]["server"] == "https://127.0.0.1:18123", kc
assert "18090" not in r["content"]["kubeconfig"]
PY
mkprocnet "$work/pn-kindstatic" "0A:127.0.0.1:18090"
PROCNET="$work/pn-kindstatic" run kindscoped '{}' rc
CASE="guard scope: the kind API port is excused only for the on-call persona while its cluster exists: a listener on 18090 that is there from the start makes the four personas before it did-not-run (naming the port), and only the on-call persona runs"
check python3 - "$work/kindscoped" "$(out kindscoped)" <<'PY'
import json, sys
rows = [json.loads(l)["persona"] for l in open(sys.argv[1] + "/log")]
assert rows == ["on-call-engineer"], rows
for p in ("gradle-platform-engineer", "maven-jenkins-ci", "compliance-reviewer", "readme-evaluator"):
    r = open(sys.argv[2] + "/" + p + ".report.md").read()
    assert r.splitlines()[0] == "VERDICT: blocking" and "did not run" in r.lower() and "18090" in r, (p, r)
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
PY
KIND_FAIL=1 KIND_DELETE_FAIL=1 run kindbothfail '{}' rc
CASE="kind lifecycle: kind create AND delete failing: the on-call persona did not run, no traceback, the other four are unaffected, the run fails"
check python3 - "$work/kindbothfail" "$(out kindbothfail)" "$rc" <<'PY'
import glob, sys
assert "Traceback" not in open(sys.argv[1] + "/stderr").read() and int(sys.argv[3]) != 0
assert "did not run" in open(sys.argv[2] + "/on-call-engineer.report.md").read().lower()
assert open(sys.argv[2] + "/gradle-platform-engineer.report.md").read().splitlines()[0] == "VERDICT: pass"
PY
PROCNET="$work/pn-bad" KIND_LISTEN=1 run kindstray '{}' rc
CASE="guard: the kind port does not excuse an unrelated listener: with 127.0.0.1:9999 also listening no persona runs"
check python3 - "$work/kindstray" "$rc" <<'PY'
import os, sys
assert int(sys.argv[2]) != 0 and os.path.getsize(sys.argv[1] + "/log") == 0
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
        assert l.split()[0] in ("run", "rm", "inspect", "exec", "ps", "stop", "kill"), l
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
assert sum(1 for l in open(sys.argv[4]) if l.startswith("run -d ") and sys.argv[3] in l) == 1
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
    for marker in (b"VERDICT", b"persona:", b"TRANSCRIPT for", b"tokens used", b"Hosts contacted"):
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
    for inf in ("DER", "PEM", "SMIME"):
        r = subprocess.run(["openssl", "cms", "-decrypt", "-inform", inf, "-inkey", key, "-in", f], capture_output=True)
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
CASE="the driver encrypts with openssl cms -encrypt (aes-256-cbc or aes256) to the --recipient certificate in a PIPELINE: exactly one such call per persona, the report and transcript on stdin (no -in, no plaintext file name in any argument), the certificate file as the recipient"
check python3 - "$work/clean" "$work/test.pem" <<'PY'
import json, sys
d, pem = sys.argv[1], sys.argv[2]
calls = [json.loads(l) for l in open(d + "/openssl.log")]
enc = [c for c in calls if c[:2] == ["cms", "-encrypt"]]
assert len(enc) == 5, calls
for c in enc:
    assert "-aes-256-cbc" in c or "-aes256" in c, c
    assert pem in c, ("the recipient certificate is not an argument", c)
    assert "-in" not in c and not [x for x in c if x.endswith((".md", ".txt", ".payload", ".report", ".transcript"))], ("plaintext handed over as a file", c)
    assert not [x for x in c if x.startswith("-passin") or x.startswith("-pass")], c
PY
CASE="openssl failing means NO artifact and a failing run: the driver never falls back to plaintext (exit non-zero, --out holds no .md/.txt/.json/.payload file, five fail lines)"
OPENSSL_FAIL=1 run encfail '{}' rc
check python3 - "$work/encfail" "$rc" "$PERSONAS" <<'PY'
import glob, os, re, sys
d, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0
assert not [f for f in os.listdir(d + "/out") if not f.endswith(".cms")], os.listdir(d + "/out")
lines = [l for f in ("stdout", "stderr") for l in open(d + "/" + f).read().splitlines() if l.strip()]
assert all(re.match(r"^persona-uat: ([a-z-]+|overall): (pass|fail)$", l) for l in lines), lines
assert "persona-uat: overall: fail" in lines
PY
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

# --- the local decryption script (bin/persona-uat-decrypt.sh <run id> [key path]) with a fake gh and the test key -----------------------------------
dsh="$root/bin/persona-uat-decrypt.sh"
mkdir -p "$work/dsh/bin" "$work/dsh/art"
cp "$work/clean/out/"*.cms "$work/dsh/art/" 2>/dev/null || true
cat >"$work/dsh/bin/gh" <<'SH'
#!/bin/sh
# fake gh: `gh run download <id> [-D|--dir DIR] [-n|--name NAME]` copies the fixture artifact into DIR; logs the call; FAKE_GH_FAIL=1 fails
echo "$*" >>"$FAKE_GH_LOG"
[ -z "${FAKE_GH_FAIL:-}" ] || { echo "gh: simulated failure" >&2; exit 1; }
[ "$1 $2" = "run download" ] || { echo "unexpected gh call" >&2; exit 1; }
dir=.
while [ $# -gt 0 ]; do case "$1" in -D|--dir) dir=$2; shift;; esac; shift; done
mkdir -p "$dir"; cp "$FAKE_ART"/* "$dir"/
SH
chmod +x "$work/dsh/bin/gh"
dsh_run() { # <run id> [key path or NOKEY] ; env FAKE_GH_FAIL ; sets drc, stdout/stderr in $work/dsh/{o,e}
  rm -rf "${work:?}/dsh/tmp"; mkdir -p "$work/dsh/tmp"; : >"$work/dsh/gh.log"; drc=0
  if [ "${2:-}" = NOKEY ]; then
    env HOME="$work/dsh/home" PATH="$work/dsh/bin:$PATH" FAKE_GH_LOG="$work/dsh/gh.log" FAKE_ART="$work/dsh/art" TMPDIR="$work/dsh/tmp" bash "$dsh" "$1" >"$work/dsh/o" 2>"$work/dsh/e" || drc=$?
  else
    env HOME="$work/dsh/home" PATH="$work/dsh/bin:$PATH" FAKE_GH_LOG="$work/dsh/gh.log" FAKE_ART="$work/dsh/art" TMPDIR="$work/dsh/tmp" bash "$dsh" "$1" ${2:+"$2"} >"$work/dsh/o" 2>"$work/dsh/e" || drc=$?
  fi
}
mkdir -p "$work/dsh/home" "$work/dsh/tmp"
dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh: a run id and the right key: gh run download <id> is called, every artifact is decrypted, the plaintext is exactly what the test run's reports and transcripts were, and it says where"
check python3 - "$work" "$drc" <<'PY'
import glob, os, re, sys
w, rc = sys.argv[1], int(sys.argv[2])
assert rc == 0, open(w + "/dsh/e").read()
gh = open(w + "/dsh/gh.log").read().split("\n")
assert any(l.startswith("run download 4242") for l in gh), gh
m = re.search(r"decrypted into (\S+)", open(w + "/dsh/o").read())
assert m, open(w + "/dsh/o").read()
d = m.group(1)
assert os.path.isdir(d), d
want = {os.path.basename(f)[:-len(".payload")]: open(f).read() for f in glob.glob(w + "/clean/plain/*.payload")}
got = {os.path.basename(f).rsplit(".", 1)[0]: open(f).read() for f in glob.glob(d + "/*") if os.path.isfile(f)}
assert sorted(got) == sorted(want) and all(got[k] == want[k] for k in want), (sorted(got), sorted(want))
PY
CASE="persona-uat-decrypt.sh: the plaintext lives ONLY under a mode-700 directory the script creates with mktemp (inside TMPDIR), its files are not readable by others, and the directory it names is that one"
check python3 - "$work" <<'PY'
import os, re, stat, sys
w = sys.argv[1]
d = re.search(r"decrypted into (\S+)", open(w + "/dsh/o").read()).group(1)
assert os.path.dirname(d.rstrip("/")) == w + "/dsh/tmp" or d.startswith(w + "/dsh/tmp"), d
assert stat.S_IMODE(os.stat(d).st_mode) == 0o700, oct(os.stat(d).st_mode)
for f in os.listdir(d):
    assert stat.S_IMODE(os.stat(os.path.join(d, f)).st_mode) & 0o077 == 0, f
# nothing else in TMPDIR or HOME holds plaintext markers
for root_, _, fs in os.walk(w + "/dsh/home"):
    for f in fs:
        assert b"VERDICT" not in open(os.path.join(root_, f), "rb").read(), f
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
CASE="persona-uat-decrypt.sh: the WRONG key fails (non-zero, says so), and leaves no plaintext behind"
check python3 - "$work" "$drc" <<'PY'
import glob, os, sys
w, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0
assert not glob.glob(w + "/dsh/tmp/*/*") , glob.glob(w + "/dsh/tmp/*/*")
blob = open(w + "/dsh/o").read() + open(w + "/dsh/e").read()
assert "VERDICT" not in blob and "PRIVATE" not in blob
PY
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
check test "$drc" -ne 0 -a -z "$(ls "$work"/dsh/tmp/*/* 2>/dev/null | head -1)"
mv "$work/dsh/art" "$work/dsh/art-keep"; mkdir -p "$work/dsh/art"; echo plain >"$work/dsh/art/notes.txt"
dsh_run 4242 "$work/test.key"
CASE="persona-uat-decrypt.sh: an artifact without any .cms file is an error (non-zero), never an empty success"
check test "$drc" -ne 0
rm -rf "${work:?}/dsh/art"; mv "$work/dsh/art-keep" "$work/dsh/art"
CASE="persona-uat-decrypt.sh is a plain bash script of the repository (executable), takes no key from the environment and writes no plaintext outside its mktemp directory (static)"
check python3 - "$dsh" <<'PY'
import os, re, sys
t = open(sys.argv[1]).read()
assert t.startswith("#!") and os.access(sys.argv[1], os.X_OK), "bin/persona-uat-decrypt.sh must be an executable script"
assert "mktemp -d" in t and "chmod 700" in t or "umask 077" in t, "no private directory"
assert "gh run download" in t and "openssl cms -decrypt" in t, "the two commands the ruling names"
assert not re.search(r"cat[^\n]*\$\{?key\b|echo[^\n]*\$\(\s*cat|<\s*\"?\$\{?key", t), "the key's CONTENT must never be echoed or catted"
PY

# --- AC5: the agent reads only the public docs and the endpoint ------------------------------------------------
CASE="the sandbox holds README.md and the top-level docs for four personas, and ONLY README.md for the README evaluator"
check python3 - "$work/clean/log" <<'PY'
import json, sys
for ln in open(sys.argv[1]):
    r = json.loads(ln)
    want = ["README.md"] if r["persona"] == "readme-evaluator" else ["README.md", "docs/gradle.md", "docs/install.md"]
    if r["persona"] == "on-call-engineer":
        want = ["README.md", "docs/gradle.md", "docs/install.md", "kubeconfig"]
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
    assert all(f == "README.md" or (f.startswith("docs/") and f.endswith(".md") and f.count("/") == 1) or (r["persona"] == "on-call-engineer" and f == "kubeconfig") for f in r["content"]), list(r["content"])
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
PORT=18099 READY_TIMEOUT=1 run notready '{}' rc
CASE="an image that never answers on its endpoint: the run fails, no agent is started against nothing, every persona did not run"
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
assert runs and all(any(f"cid-{i+1}" in l for l in insp) for i in range(len(runs))), (runs, insp)
PY

CASE="the driver provisions nothing in a cloud (a docker log with only run, rm, inspect, exec), also for a friction run"
check python3 - "$work/friction/docker.log" <<'PY'
import sys
for l in open(sys.argv[1]):
    assert l.split()[0] in ("run", "rm", "inspect", "exec", "ps", "stop", "kill"), l
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
ROLE_WORDS = (("gradle", ("first-time", "gradle", "proxy")), ("maven", ("maven", "jenkins")), ("compliance", ("signature", "sbom", "vex")),
              ("readme", ("only the readme", "ten minutes")), ("oncall", ("upgrade", "rollback", "logs")))   # each persona's own instruction words

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
        open(LOG, "a").write(json.dumps({"model": kw["model"], "turn": len(kw["messages"]), "system": kw.get("system", ""),
            "first": kw["messages"][0]["content"] if isinstance(kw["messages"][0]["content"], str) else json.dumps(kw["messages"][0]["content"])}) + "\n")
        msgs = kw["messages"]
        if len(msgs) == 1:
            ctx = (kw.get("system", "") + " " + (msgs[0]["content"] if isinstance(msgs[0]["content"], str) else json.dumps(msgs[0]["content"]))).lower()
            role = next((n for n, ws in ROLE_WORDS if all(w in ctx for w in ws)), "none")      # which persona's instructions did THIS request carry
            return _Msg(json.dumps({"action": "shell", "command": "cat README.md; echo $((6*7)); echo ROLE-" + role + "; python3 -c \"import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:18080/').status)\""}))
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
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
inits = [r["init"] for r in rows if "init" in r]
assert len(inits) == 15, len(inits)
assert all(not i["has_key"] and i["fed"] == ["f1", "o1", "s1", "w1"] and i["token_file"].endswith("integ/token") and i["leaked"] == [] for i in inits), inits
calls = [r for r in rows if "model" in r]
for r in calls:
    ctx = (r["system"] + " " + r["first"]).lower()
    assert "http://127.0.0.1:18080" in ctx, "the persona is never told its endpoint"
    assert "only the public documentation" in ctx and "do not clone" in ctx and "source" in ctx, "the restriction is not in the prompt"
assert any("http://127.0.0.1:18081" in (r["system"] + r["first"]) for r in calls), "Jenkins' endpoint never reaches the Maven persona"
assert any("kubeconfig" in (r["system"] + r["first"]).lower() for r in calls), "the kubeconfig never reaches the on-call persona"
models = [r["model"] for r in rows if "model" in r]
assert len(models) == 15 and models.count("INTEG-COMPLIANCE") == 3 and models.count("INTEG-DEFAULT") == 12, models
PY
CASE="integrated: no GitHub credential reached the shell containers or the provider's environment"
check none_match 'SECRET-GH-TOKEN' "$work/integ/plain" "$work/integ/out" "$work/integ/docker.log"

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
        if t[1] == "-d":
            opts = t[2:-1]
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
CASE="fence 3: every request names only a 127.0.0.1 endpoint (the image's and every tool's), and the default --port is 8080"
check python3 - "$work/clean/log" <<'PY'
import json, re, sys
for l in open(sys.argv[1]):
    r = json.loads(l)["request"]
    urls = [r["endpoint"]] + [v["endpoint"] for v in r["tools"].values() if v["endpoint"]]
    assert all(re.fullmatch(r"https?://127\.0\.0\.1:\d+", u) for u in urls), urls
    assert not re.search(r"localhost|0\.0\.0\.0|\.invalid|amazonaws|github", json.dumps(r)), r
PY
CASE="fence 3: without --port the image is published on 127.0.0.1:8080 and handed to the agent as http://127.0.0.1:8080"
mkdir -p "$work/defport"; : >"$work/defport/log"; : >"$work/defport/docker.log"; echo '{}' >"$work/defport/plan.json"
sed "s#__LOG__#$work/defport/docker.log#" "$work/docker.tmpl" >"$work/defport/docker"; chmod +x "$work/defport/docker"; rc=0
PERSONA_UAT_MODEL=M1 PERSONA_UAT_COMPLIANCE_MODEL=M2 python3 "$driver" --mode rc --proc-net "$work/procnet" --image "$IMG" --repo "$repo" --out "$work/defport/out" --tools "$work/tools.json" \
  --docker "$work/defport/docker" --recipient "$work/test.pem" --ready-timeout 1 --agent "python3 $work/stub.py $work/defport" >/dev/null 2>&1 || rc=$?
check grep -q '127.0.0.1:8080:8080' "$work/defport/docker.log"
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
# --- advisor 0206: host networking stays (the agent's shell containers reach the loopback endpoint), so the driver GUARDS the loopback:
# before each persona's agent runs it reads the listening sockets from /proc/net/tcp and tcp6 and refuses (fail closed, the persona is
# "did not run", the run is blocking) when a loopback-bound listener exists that is not one of its own (the endpoint port, the Jenkins and
# kind ports above it), DNS (53) or one the caller names with --allow-listen. Wildcard binds and non-listening sockets are not loopback listeners.
mkprocnet "$work/pn-bad" "0A:127.0.0.1:9999"
PROCNET="$work/pn-bad" run guardbad '{}' rc
CASE="guard: an unexpected loopback listener (127.0.0.1:9999) makes every persona 'did not run' (blocking, exit nonzero), and no agent ran"
check python3 - "$work/guardbad" "$rc" <<'PY'
import os, sys
d, rc = sys.argv[1], int(sys.argv[2])
assert rc != 0, rc
assert os.path.getsize(d + "/log") == 0, "an agent ran next to an unexpected loopback listener"
reports = [open(d + "/plain/" + f).read() for f in sorted(os.listdir(d + "/plain")) if f.endswith(".report.md")]
assert len(reports) == 5 and all("did not run" in r and "9999" in r for r in reports), reports
PY
mkprocnet "$work/pn-bad6" "0A:ip6loop:9998"
PROCNET="$work/pn-bad6" run guardbad6 '{}' rc
CASE="guard: an IPv6 loopback listener (::1:9998) is refused too"
check python3 - "$work/guardbad6" "$rc" <<'PY'
import os, sys
assert int(sys.argv[2]) != 0 and os.path.getsize(sys.argv[1] + "/log") == 0
PY
mkprocnet "$work/pn-ok" "0A:127.0.0.1:18080" "0A:127.0.0.1:18081" "0A:127.0.0.1:18082" "0A:127.0.0.53:53" "0A:0.0.0.0:22" "0A:ip6any:22" "01:127.0.0.1:9999"
PROCNET="$work/pn-ok" run guardok '{}' rc
CASE="guard: the endpoint and the two tool ports, DNS, a wildcard bind (0.0.0.0:22, ::22) and a non-listening loopback connection are NOT unexpected: the run is clean"
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
run sbxleft '{"gradle-platform-engineer":{"readonly_dir":true},"maven-jenkins-ci":{"readonly_dir":true}}' rc
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
lines = [l for l in open(sys.argv[1]).read().splitlines() if l.startswith("Hosts contacted outside the docs:")]
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
                                           "# https://commentonly.example/x\necho hi", "# see http://another-comment.example\n# and wget https://third-comment.example/z",
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
CASE="hosts: every report carries ONE 'Hosts contacted outside the docs:' line"
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
line = lambda t: t.split("Hosts contacted outside the docs:")[1].splitlines()[0]
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
CASE="proof: a persona with findings of its own and no counted requests is not given a second finding: friction-only without requests stays friction, a blocking one stays blocking (the rule is: NO findings and no counted requests)"
run proof2 '{"readme-evaluator":{"requests":0,"findings":[{"kind":"friction","text":"the README is vague"}]},"gradle-platform-engineer":{"requests":0,"findings":[{"kind":"blocking","text":"step 1 fails as written"}]}}' rc
check test "$(head -1 "$(out proof2)/readme-evaluator.report.md")" = "VERDICT: friction"
check none_match 'never exercised' "$(out proof2)/readme-evaluator.report.md" "$(out proof2)/gradle-platform-engineer.report.md"
check test "$(head -1 "$(out proof2)/gradle-platform-engineer.report.md")" = "VERDICT: blocking"
run proofreset '{"gradle-platform-engineer":{"requests":3},"maven-jenkins-ci":{"requests":3},"compliance-reviewer":{"reset":true,"requests":1}}' rc
CASE="proof: a counter that went BACKWARDS during the window (the server restarted: fewer samples after than before) is no proof: that persona, with no findings, is blocking; the others pass"
check test "$(head -1 "$(out proofreset)/compliance-reviewer.report.md")" = "VERDICT: blocking" -a "$(head -1 "$(out proofreset)/gradle-platform-engineer.report.md")" = "VERDICT: pass"
check grep -qi 'endpoint' "$(out proofreset)/compliance-reviewer.report.md"
for ma in garbage nometric; do
  run "proofafter-$ma" "{\"on-call-engineer\":{\"requests\":2,\"mode_after\":\"$ma\"}}" rc
  srvctl __mode m "ok"
  CASE="proof: an AFTER-scrape that cannot be parsed or holds no sample while the before-scrape had one ($ma) is no proof: blocking, never a pass"
  check test "$(head -1 "$(out "proofafter-$ma")/on-call-engineer.report.md")" = "VERDICT: blocking" -a "$rc" -ne 0
done
for m in garbage status500 nometric nofamily; do
  srvctl __mode m "$m"
  run "proofmode-$m" '{}' rc
  srvctl __mode m "ok"
  CASE="proof ($m): when /metrics cannot be read or holds no fscache_http_requests_total sample at all, no persona may finish clean: all five are blocking and the run fails"
  check python3 - "$(out "proofmode-$m")" "$rc" <<'PY'
import glob, sys
assert int(sys.argv[2]) != 0
rs = sorted(glob.glob(sys.argv[1] + "/*.report.md"))
assert len(rs) == 5 and all(open(r).read().splitlines()[0] == "VERDICT: blocking" for r in rs), rs
PY
done
cat >"$work/windows.py" <<'PY'
import json, sys
# windows.py <case dir> [n personas that wrote timing] [settle]: from the stub agents' own instants and the server's scrape instants
d = sys.argv[1]
n_expect = int(sys.argv[2]) if len(sys.argv) > 2 else 5
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
    if settle:
        nxt = tim[i + 1]["t0"] if i + 1 < len(tim) else float("inf")
        between = [e for e in scr if r["t1"] < e["t"] < nxt]
        assert between and (i + 1 == len(tim) or len(between) >= 2), ("no settled after-scrape between the personas", r["persona"], len(between))
        a = between[-2] if i + 1 < len(tim) else between[-1]
    else:
        after = [e for e in scr if e["t"] > r["t1"]]
        assert after, ("a persona window without a scrape after it", r["persona"])
        a = after[0]
    inside = [e for e in srv if b["t"] < e["t"] < a["t"] and e["path"] != "/metrics"]
    if not settle:
        assert not [e for e in scr if b["t"] < e["t"] < a["t"]], ("another scrape inside the window", r["persona"])
    own = {r["persona"]} | ({"CONTAINER"} if r.get("daemon") else set())
    assert all(e["persona"] in own for e in inside), ("a request of another party inside the window: it would be attributed to this persona", r["persona"], [e for e in inside if e["persona"] not in own][:3])
    if not r.get("daemon"):
        counted = [e for e in inside if e["counted"]]
        assert len(counted) == r["requests"] and len(inside) == r["requests"] + r["uncounted"], ("the requests inside the scrape window are not exactly the persona's", r["persona"], len(counted), r["requests"])
        assert a["total"] - b["total"] == r["requests"], ("after - before is not the persona's counted requests", r["persona"], a["total"], b["total"], r["requests"])
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
for ba in garbage status500 nometric nofamily; do
  run "proofbefore-$ba" "{\"gradle-platform-engineer\":{\"requests\":2},\"maven-jenkins-ci\":{\"requests\":2},\"compliance-reviewer\":{\"requests\":2,\"break_next\":\"$ba\"},\"readme-evaluator\":{\"requests\":3,\"restore\":true}}" rc
  srvctl __mode m ok
  CASE="before-scrape failure alone ($ba): the readme persona's BEFORE-scrape is $ba (after a prior persona's samples) and its after-scrape is fine: that persona is BLOCKING (a failed or sample-less before-scrape is never read as 0 against the earlier personas' totals); the others pass"
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
                  "maven-jenkins-ci": {"crash": True, "leak": True, "crash_lines": ["$ curl https://crash-host.example/x", "exit status: 0"]}, "on-call-engineer": {"leak": True}}))
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
CASE="fake kubectl create token (self-test): a whole-second Go duration of at most 24h is issued; 1h0.5s (sub-second precision), 100ms, 25h, abc, -1h and 0s are refused; --ttl and --bogus are unknown flags; a bound Secret that does not exist is an error; --audience, --duration and the bound-object flags are the ONLY token flags"
check python3 - "$fk" <<'PY'
import subprocess, sys
d = sys.argv[1]
k = d + "/hostbin/kubectl"
def call(args):
    r = subprocess.run([k, "--kubeconfig", d + "/admin", "create", "token", "persona", "-n", "persona"] + args, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()
for ok in (["--duration", "1h"], ["--duration=90m"], ["--duration", "86400s"], ["--duration", "1.5h"], ["--duration", "1h0.0s"], []):
    rc, out = call(ok)
    assert rc == 0 and out.count(".") == 2, ("refused a valid request", ok)
for bad in (["--duration", "1h0.5s"], ["--duration", "100ms"], ["--duration", "25h"], ["--duration", "abc"], ["--duration", "-1h"], ["--duration", "0s"], ["--ttl", "1h"], ["--bogus"],
            ["--bound-object-kind", "Secret", "--bound-object-name", "nope"], ["--bound-object-name", "nope"]):
    assert call(bad)[0] != 0, ("accepted", bad)
PY
CASE="fake kubectl persona credential (self-test): only a token this API server issued for the persona's ServiceAccount, unexpired, with the API audience, while the cluster exists, is answered; a token for another audience, a token never issued, an expired token and a deleted cluster are all refused"
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
short = issue(["--duration", "1s"]); time.sleep(1.3)
assert use(short) != 0, "an expired token was accepted"
os.remove(d + "/alive")
assert use(good) != 0, "a token was accepted although the cluster is gone"
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
assert "https://kubernetes.default.svc" in pl["aud"], pl
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
    assert tail[:2] == ["rm", "-rf"] or (tail[:2] == ["sh", "-c"] and "rm -rf" in " ".join(tail[2:])), tail
    assert "/work" in " ".join(tail), tail
    sweep = [k for k, x in enumerate(dl) if x[:1] == ["ps"] and "label=" + lab in x]
    assert sweep and sweep[0] < i, ("the cleanup must follow the label sweep", sweep, i)
PY
CASE="cross-tool sandbox (driver side): a persona that leaves a read-only directory is cleaned up with the cleanup container (the sandbox is gone), and the read-only tree is removed by the container's root run"
check python3 - "$work/sbxleft" <<'PY'
import json, os, sys
d = sys.argv[1]
dirs = {json.loads(l)["request"]["docs_dir"] for l in open(d + "/log")}
assert dirs and not [x for x in dirs if os.path.exists(x)]
assert [l for l in open(d + "/docker.log") if l.startswith("run --rm") and "--user 0:0" in l and "rm -rf" in l.replace("'", "")], "no cleanup container ran"
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
run delayed '{"gradle-platform-engineer":{"requests":1},"maven-jenkins-ci":{"requests":0,"uncounted":["/healthz"]},"compliance-reviewer":{"requests":2},"readme-evaluator":{"requests":1},"on-call-engineer":{"requests":1}}' rc
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
check python3 "$work/windows.py" "$work/delayed" 5 settle
# the auth layer wraps the metrics middleware: a 401 is never counted
run proofauth '{"readme-evaluator":{"requests":0,"unauth":3}}' rc
CASE="a persona whose only traffic was answered 401 (withAuth wraps withMetrics, so it is never counted) made no counted request: blocking, the others pass"
check test "$(head -1 "$(out proofauth)/readme-evaluator.report.md")" = "VERDICT: blocking" -a "$(head -1 "$(out proofauth)/gradle-platform-engineer.report.md")" = "VERDICT: pass"

# --- PRIVACY, outcomes that exist only late in this file
CASE="the public log is ONLY pass/fail lines in every outcome: clean, blocking, crash, a provider error carrying secrets, a dead image, missing docs: no finding, doc name, host, model name or transcript text, and the transcripts/reports exist only inside the encrypted artifacts"
for c in clean blocking fc-crash hosts leak imgdead; do publiclog "$c" >/dev/null 2>&1 && ok "$CASE ($c)" || bad "$CASE ($c)"; done
CASE="a hosts line, the repository-source flag and the findings are in NO public place: not in the log, not in an artifact file name (the hosts run)"
check python3 - "$work/hosts" <<'PY'
import os, sys
d = sys.argv[1]
blob = (open(d + "/stdout").read() + open(d + "/stderr").read() + " ".join(os.listdir(d + "/out"))).lower()
for w in ("evil", "repository source", "github", "outside", "169.254", "hosts contacted", "example"):
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
