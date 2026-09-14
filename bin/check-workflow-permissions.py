#!/usr/bin/env python3
"""Static release-workflow permission checks (audit R01 + B01).

Two classes of failure that GitHub only surfaces by dispatching a real
run (which PR CI never does for the release chain):

1. Reusable-workflow permission ceilings. A reusable workflow cannot
   raise its caller's grant, so a caller job that omits a scope a callee
   job needs makes the whole run a startup_failure with zero jobs. The
   grant a callee receives is the CALLER JOB's effective permissions:
   the job's own `permissions:` when it declares one, otherwise the
   caller workflow's top-level `permissions:`. The callee job's NEED is
   its own `permissions:` when declared, otherwise the callee workflow's
   top-level default.

2. Action-level requirements. Some actions persist records through the
   GitHub API and need specific scopes regardless of the reusable-workflow
   graph: actions/attest* need `attestations: write` + `id-token: write`.
   A job that runs one without the grant fails at that step, after
   side effects (tags pushed, draft release created) may already exist.
"""
import glob
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required (present on ubuntu-latest system Python)\n")
    sys.exit(2)

RANK = {"none": 0, "read": 1, "write": 2}

# action prefix -> {scope: level} it requires in the running job.
ACTION_REQUIREMENTS = {
    "actions/attest": {"attestations": "write", "id-token": "write"},
    "actions/attest-build-provenance": {"attestations": "write", "id-token": "write"},
    "actions/attest-sbom": {"attestations": "write", "id-token": "write"},
}


def norm(perms):
    """Return {scope: level} from a `permissions:` value, or None if unspecified."""
    if perms is None:
        return None
    if isinstance(perms, str):
        if perms == "read-all":
            return {"__all__": "read"}
        if perms == "write-all":
            return {"__all__": "write"}
        return {}  # "{}" or anything else -> everything none
    return {k: str(v) for k, v in perms.items()}


def level_of(perms, scope):
    """Effective level of `scope` in a normalized perms dict (default none)."""
    if perms is None:
        return None  # unspecified: not constrained here
    if "__all__" in perms:
        return perms["__all__"]
    return perms.get(scope, "none")


def covers(have_level, needed):
    if have_level is None:
        return True  # caller left it unspecified: inherits; not our gap to prove
    return RANK.get(have_level, 0) >= RANK[needed]


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def effective(job_perms, workflow_perms):
    """A job's effective permissions: its own when declared, else the
    workflow default. Returns a normalized dict or None (unspecified)."""
    jp = norm(job_perms)
    if jp is not None:
        return jp
    return norm(workflow_perms)


def job_steps(job):
    steps = job.get("steps") if isinstance(job, dict) else None
    return steps if isinstance(steps, list) else []


def action_id(uses):
    # "actions/attest@sha # v4" -> "actions/attest"
    return uses.split("@", 1)[0].strip()


def main():
    failures = []
    for path in sorted(glob.glob(".github/workflows/*.yml")):
        doc = load(path)
        if not isinstance(doc, dict):
            continue
        wf_perms = doc.get("permissions")
        jobs = doc.get("jobs") or {}
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            eff = effective(job.get("permissions"), wf_perms)

            # (2) action-level requirements in THIS job.
            for step in job_steps(job):
                uses = step.get("uses") if isinstance(step, dict) else None
                if not uses:
                    continue
                req = ACTION_REQUIREMENTS.get(action_id(uses))
                if not req:
                    continue
                for scope, level in req.items():
                    if not covers(level_of(eff, scope), level):
                        have = level_of(eff, scope)
                        failures.append(
                            f"{path}: job '{job_name}' runs {action_id(uses)} which needs "
                            f"{scope}={level} but the job's effective grant is "
                            f"{scope}={have if have is not None else 'unspecified'}"
                        )

            # (1) reusable-workflow ceiling.
            uses = job.get("uses")
            if not uses or not uses.startswith("./"):
                continue
            caller_eff = eff  # the grant the callee receives
            callee_path = uses.split("@")[0].removeprefix("./")
            try:
                callee = load(callee_path)
            except FileNotFoundError:
                failures.append(f"{path}: job '{job_name}' calls missing {callee_path}")
                continue
            callee_wf_perms = callee.get("permissions") if isinstance(callee, dict) else None
            for cj_name, cj in (callee.get("jobs") or {}).items():
                if not isinstance(cj, dict):
                    continue
                needed = effective(cj.get("permissions"), callee_wf_perms)
                if not needed:
                    continue
                for scope, level in (needed.items() if "__all__" not in needed
                                     else [("__all__", needed["__all__"])]):
                    if level == "none":
                        continue
                    # a callee needing __all__ read/write must be covered on every real scope;
                    # approximate by requiring the caller grant __all__ too.
                    have = level_of(caller_eff, scope) if scope != "__all__" else (
                        caller_eff.get("__all__") if caller_eff and "__all__" in caller_eff else None)
                    if scope == "__all__" and caller_eff is not None and "__all__" not in caller_eff:
                        # caller enumerates scopes; a blanket callee need can't be proven covered
                        failures.append(
                            f"{path}: caller '{job_name}' enumerates scopes but "
                            f"{callee_path} job '{cj_name}' needs {level}-all")
                        continue
                    if not covers(have, level):
                        cur = have if have is not None else "unspecified"
                        failures.append(
                            f"{path}: caller '{job_name}' grants {scope}={cur} but "
                            f"{callee_path} job '{cj_name}' needs {scope}={level}"
                        )
    if failures:
        sys.stderr.write("::error::workflow permission gaps (a release run would fail at startup or at an action):\n")
        for f in failures:
            sys.stderr.write("  " + f + "\n")
        sys.exit(1)
    print("workflow permissions: caller/callee ceilings and action requirements satisfied")


if __name__ == "__main__":
    main()
