#!/usr/bin/env python3
"""Test-owned workflow-shape reader — parses the workflow with VENDORED PyYAML
(fixtures/testlib/pyyaml/, a pure-Python copy with its LICENSE) and extracts every
fact from the PARSED DOCUMENT, never from raw text. Comments cannot satisfy any
check. This is test code (a checked-in test double), never part of the auditor;
the suite validates it against two real committed workflows and a quoted-`on`
variant before trusting it.

    yamlshape.py load  <file>   -> the parsed document as JSON
    yamlshape.py shape <file>   -> the extracted shape as JSON
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pyyaml as yaml  # vendored pure-Python PyYAML

def _scalars(node):
    """yield every string scalar in the parsed document (values only, no comments)"""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _scalars(v)
    elif isinstance(node, list):
        for v in node:
            yield from _scalars(v)

def shape(text):
    d = yaml.safe_load(text) or {}
    on = d.get("on", d.get(True, {}))     # YAML resolves the bareword on -> True
    if isinstance(on, list): triggers = sorted(on)
    elif isinstance(on, dict): triggers = sorted(on.keys())
    elif isinstance(on, str): triggers = [on]
    else: triggers = []
    cron = []
    if isinstance(on, dict) and isinstance(on.get("schedule"), list):
        for e in on["schedule"]:
            if isinstance(e, dict) and "cron" in e: cron.append(e["cron"])
    dispatch_inputs = {}
    if isinstance(on, dict) and isinstance(on.get("workflow_dispatch"), dict):
        dispatch_inputs = on["workflow_dispatch"].get("inputs") or {}
    jobs = d.get("jobs") or {}
    job = None
    if isinstance(jobs, dict):
        for jb in jobs.values():
            if isinstance(jb, dict) and jb.get("environment") == "agent":
                job = jb; break
        if job is None and jobs:
            job = list(jobs.values())[0]
    job = job if isinstance(job, dict) else {}
    perms = job.get("permissions")
    if not isinstance(perms, dict):
        perms = d.get("permissions") if isinstance(d.get("permissions"), dict) else {}
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    # OIDC: find the github-script step and read its with.script value structurally
    audience = None; ghscript = False; token_file = False
    for st in steps:
        if not isinstance(st, dict): continue
        uses = st.get("uses", "") or ""
        if uses.startswith("actions/github-script"):
            ghscript = True
            script = ((st.get("with") or {}).get("script") or "")
            if "getIDToken" in script and "https://api.anthropic.com" in script:
                audience = "https://api.anthropic.com"
    # token-file + api-key + vars, all over PARSED string scalars (never comments)
    all_scalars = list(_scalars(d))
    token_file = any("ANTHROPIC_IDENTITY_TOKEN_FILE" in s for s in all_scalars) or \
                 any("ANTHROPIC_IDENTITY_TOKEN_FILE" in (st.get("env") or {}) for st in steps if isinstance(st, dict))
    api_key = any("ANTHROPIC_API_KEY" in s for s in all_scalars) or \
              any("ANTHROPIC_API_KEY" in (st.get("env") or {}) for st in steps if isinstance(st, dict))
    vars_refs = set()
    for s in all_scalars:
        vars_refs.update(re.findall(r"vars\.([A-Z0-9_]+)", s))
    return {
        "triggers": triggers,
        "cron": cron,
        "dispatch_inputs": dispatch_inputs,
        "job_environment": job.get("environment"),
        "permissions": perms,
        "has_pull_request_target": "pull_request_target" in triggers,
        "oidc_audience": audience,
        "uses_github_script_idtoken": ghscript and audience is not None,
        "sets_identity_token_file": token_file,
        "references_anthropic_api_key": api_key,
        "identifier_env_vars": sorted(vars_refs),
    }

if __name__ == "__main__":
    op, path = sys.argv[1], sys.argv[2]
    txt = open(path).read()
    print(json.dumps(shape(txt) if op == "shape" else (yaml.safe_load(txt))))
