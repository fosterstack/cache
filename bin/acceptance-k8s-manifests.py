"""bin/acceptance-k8s-manifests.py: step 3 of the Kubernetes suite (REQ-DEPLOY-003-AC1): extracts the documented manifests of docs/kubernetes.md verbatim (image substituted) into /tmp/fscache-k8s.yaml. Needs CANDIDATE_LOCAL. Moved out of bin/acceptance-k8s.sh unchanged (REQ-CHAIN-006-AC8: a listed script runs only listed scripts)."""
import re, os
doc = open("docs/kubernetes.md").read()
# Grab the first fenced yaml block under each documented H2.
want = ["## Secret (credentials)", "## PersistentVolumeClaim",
        "## Deployment", "## Service"]
blocks = []
for heading in want:
    i = doc.index(heading)
    m = re.search(r"```yaml\n(.*?)```", doc[i:], re.S)
    if not m:
        raise SystemExit(f"no yaml block under {heading!r}")
    blocks.append(m.group(1).rstrip())
manifest = "\n---\n".join(blocks)
# Substitute ONLY the image tag with the loaded candidate; keep
# imagePullPolicy Never so kind uses the loaded image.
manifest = manifest.replace("ghcr.io/fosterstack/cache:X.Y.Z", os.environ["CANDIDATE_LOCAL"])
manifest = manifest.replace(
    "image: " + os.environ["CANDIDATE_LOCAL"],
    "image: " + os.environ["CANDIDATE_LOCAL"] + "\n          imagePullPolicy: Never")
open("/tmp/fscache-k8s.yaml", "w").write(manifest)
print(manifest)
