"""bin/acceptance-k8s-smoke.py: step 5 of the Kubernetes suite (REQ-DEPLOY-003-AC1): extracts the documented runner env block and smoke commands of docs/kubernetes.md and writes /tmp/runner-pod.yaml, /tmp/pf-forward and /tmp/smoke-assert. Needs CLIENT_LOCAL. Moved out of bin/acceptance-k8s.sh unchanged except that the two generated scripts have no file suffix."""
import re, os, shlex
doc = open("docs/kubernetes.md").read()

# --- The documented "In-cluster runners" env block ---------------
# The runner-side secretKeyRef mapping a CI runner pod uses to
# receive FSCACHE_USERNAME / FSCACHE_PASSWORD. We graft this block
# VERBATIM into a client pod: if the doc regresses (e.g. back to an
# envFrom shortcut, or a wrong secret key), the grafted pod's env
# is wrong and the assertions below fail.
i = doc.index("## In-cluster runners")
section = doc[i:]
yaml_blocks = re.findall(r"```yaml\n(.*?)```", section, re.S)
runner_block = next((b for b in yaml_blocks if "name: runner" in b), None)
if runner_block is None:
    raise SystemExit("no runner pod-spec yaml block under 'In-cluster runners'")
rlines = runner_block.splitlines()
env_idx = next((n for n, l in enumerate(rlines) if l.strip() == "env:"), None)
if env_idx is None:
    raise SystemExit("documented runner block has no 'env:' list (regressed to envFrom?)")
env_block = "\n".join(l for l in rlines[env_idx:] if l.strip() != "")
for name in ("FSCACHE_USERNAME", "FSCACHE_PASSWORD"):
    if name not in env_block:
        raise SystemExit("documented runner env block does not map " + name)

# The doc block's `env:` sits at 6-space indent under
# `- name: runner`; that is exactly where our container needs it,
# so it grafts in unchanged.
pod = (
    "apiVersion: v1\n"
    "kind: Pod\n"
    "metadata:\n"
    "  name: fscache-runner\n"
    "  labels:\n"
    "    app.kubernetes.io/name: fscache-runner\n"
    "spec:\n"
    "  restartPolicy: Never\n"
    "  containers:\n"
    "    - name: runner\n"
    "      image: " + os.environ["CLIENT_LOCAL"] + "\n"
    "      imagePullPolicy: Never\n"
    '      command: ["sleep", "3600"]\n'
    + env_block + "\n"
)
open("/tmp/runner-pod.yaml", "w").write(pod)
print("=== runner client pod (documented env block grafted) ===")
print(pod)

# --- The documented port-forward smoke commands ------------------
# Taken from their published text; the port-forward is backgrounded
# for CI and each curl's expected result is read from the doc's own
# `# -> ...` annotations, so a broken documented command/credential
# fails here.
sh_blocks = re.findall(r"```sh\n(.*?)```", doc, re.S)
pf_block = next(b for b in sh_blocks if "port-forward" in b)
curl_block = next(b for b in sh_blocks if "curl -s localhost" in b)
pf_cmd = next(l.strip() for l in pf_block.splitlines()
              if l.strip() and not l.strip().startswith("#"))
open("/tmp/pf-forward", "w").write("#!/usr/bin/env bash\n" + pf_cmd + "\n")

raw = re.sub(r"\\\n\s*", " ", curl_block)   # join line continuations
cmds = [l.rstrip() for l in raw.splitlines()
        if l.strip() and not l.strip().startswith("#")]
lines = ["#!/usr/bin/env bash", "set -euo pipefail"]
lines.append('curl() { sh bin/loopback-get.sh "$@"; }   # the documented commands run through the loopback helper (REQ-SUP-001-AC24); the step runs at the repository root')
lines.append('assert_out() { got=$(eval "$1" 2>/dev/null) || true; [ "$got" = "$2" ] || { echo "::error::documented smoke command failed: [$1] got [$got] want [$2]" >&2; exit 1; }; }')
lines.append('assert_ok() { eval "$1" >/dev/null 2>&1 || { echo "::error::documented smoke command failed: [$1]" >&2; exit 1; }; }')
for c in cmds:
    m = re.search(r"#\s*->\s*(\S+)", c)
    if m:
        lines.append("assert_out " + shlex.quote(c) + " " + shlex.quote(m.group(1)))
    else:
        lines.append("assert_ok " + shlex.quote(c))
open("/tmp/smoke-assert", "w").write("\n".join(lines) + "\n")
print("=== documented port-forward: " + pf_cmd)
print("=== documented smoke assertions ===")
print("\n".join(lines))
