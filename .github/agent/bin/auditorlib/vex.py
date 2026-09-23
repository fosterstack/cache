"""OpenVEX writing + conformance (REQ-AUD-4, R10). Produced documents conform to the
published OpenVEX schema: evidence and target dates live in a SIDECAR
`<cve>.evidence.json`, never as custom statement properties. `validate()` rejects a
document with any non-schema statement key."""
import json, os
from . import policy

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fixtures",
                      "testlib", "openvex-schema.json")
_ALLOWED = None
_TOP = None


def _load_schema():
    global _ALLOWED, _TOP
    if _ALLOWED is None:
        d = json.load(open(SCHEMA))
        _ALLOWED = set(d["properties"]["statements"]["items"]["properties"])
        _TOP = set(d.get("required", []))
    return _ALLOWED, _TOP


def doc(fid, status, timestamp, justification=None, action=None, subcomponents=None):
    product = {"@id": policy.VEX_PRODUCT}
    if subcomponents:
        # scope the statement to the exact package purls it is backed for (R11 rank 1:
        # a not_affected clears only the package(s) its evidence names, never a sibling
        # package flagged for the same CVE).
        product["subcomponents"] = [{"@id": p} for p in subcomponents]
    st = {"@id": policy.stmt_id(fid), "vulnerability": {"name": fid}, "timestamp": timestamp,
          "products": [product], "status": status}
    if justification:
        st["justification"] = justification
    if action:
        st["action_statement"] = action
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": policy.VEX_BASE,
            "author": "FosterStack LLC", "role": "vendor", "timestamp": timestamp,
            "version": 1, "statements": [st]}


def validate(document):
    """Raise ValueError if the document is not OpenVEX-conformant."""
    allowed, top = _load_schema()
    for k in top:
        if k not in document:
            raise ValueError("VEX missing required top-level %r" % k)
    for st in document.get("statements", []):
        extra = set(st) - allowed
        if extra:
            raise ValueError("VEX statement has non-schema keys: %s" % sorted(extra))
        if "vulnerability" not in st or "status" not in st:
            raise ValueError("VEX statement missing vulnerability/status")


def write(out_dir, fid, status, timestamp, justification=None, action=None,
          evidence=None, target_date=None, vex_name=None, subcomponents=None):
    """Write a conformant VEX and its evidence sidecar. Returns the VEX path."""
    document = doc(fid, status, timestamp, justification, action, subcomponents)
    validate(document)
    vpath = os.path.join(out_dir, "vex", (vex_name or fid) + ".openvex.json")
    os.makedirs(os.path.dirname(vpath), exist_ok=True)
    json.dump(document, open(vpath, "w"), indent=1)
    side = {"statement_id": policy.stmt_id(fid), "vulnerability": fid}
    if evidence is not None:
        side["evidence"] = evidence
    if target_date is not None:
        side["target_date"] = target_date
    # key the sidecar by the VEX name so a CVE with two dispositions (not_affected for one
    # package, affected for a sibling) does not overwrite its own evidence.
    spath = os.path.join(out_dir, "evidence", (vex_name or fid) + ".evidence.json")
    os.makedirs(os.path.dirname(spath), exist_ok=True)
    json.dump(side, open(spath, "w"), indent=1)
    return vpath
