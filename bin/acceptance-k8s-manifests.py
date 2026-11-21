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
image = os.environ["CANDIDATE_LOCAL"]
# each placeholder must occur exactly once, or the suite would test the published image instead of the candidate
if manifest.count("ghcr.io/fosterstack/cache:X.Y.Z") != 1:
    raise SystemExit("the image placeholder must occur exactly once in the manifests")
manifest = manifest.replace("ghcr.io/fosterstack/cache:X.Y.Z", image)
if manifest.count("image: " + image) != 1:
    raise SystemExit("the image line must occur exactly once in the manifests")
manifest = manifest.replace("image: " + image, "image: " + image + "\n          imagePullPolicy: Never")
open("/tmp/fscache-k8s.yaml", "w").write(manifest)
print(manifest)
