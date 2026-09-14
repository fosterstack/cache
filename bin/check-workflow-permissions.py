#!/usr/bin/env python3
"""Assert every reusable-workflow caller grants at least the permissions
its callees' jobs request. A reusable workflow cannot raise its caller's
grant, so a caller that omits a scope a callee needs makes the whole run
a startup_failure with zero jobs (the R01 defect). GitHub can only report
this by dispatching a release; this check reports it in PR CI, which
never calls the release chain.
"""
import glob
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML required (present on ubuntu-latest system Python)\n")
    sys.exit(2)

RANK = {"none": 0, "read": 1, "write": 2}


def norm(perms):
    """Return {scope: level} from a workflow/job `permissions:` value."""
    if perms is None:
        return None  # unspecified: inherits / not constrained here
    if isinstance(perms, str):
        # read-all / write-all / {}
        if perms in ("read-all",):
            return {"__all__": "read"}
        if perms in ("write-all",):
            return {"__all__": "write"}
        return {}  # e.g. "{}" -> everything none
    return {k: str(v) for k, v in perms.items()}


def covers(caller, scope, needed):
    if caller is None:
        return True  # caller left permissions unspecified: not our gap to prove here
    if "__all__" in caller:
        return RANK[caller["__all__"]] >= RANK[needed]
    have = caller.get(scope, "none")
    return RANK.get(have, 0) >= RANK[needed]


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    failures = []
    for caller_path in sorted(glob.glob(".github/workflows/*.yml")):
        doc = load(caller_path)
        if not isinstance(doc, dict):
            continue
        caller_perms = norm(doc.get("permissions"))
        jobs = doc.get("jobs") or {}
        for job_name, job in jobs.items():
            uses = job.get("uses") if isinstance(job, dict) else None
            if not uses or not uses.startswith("./"):
                continue  # only local reusable workflows
            callee_path = uses.split("@")[0].removeprefix("./")
            try:
                callee = load(callee_path)
            except FileNotFoundError:
                failures.append(f"{caller_path}: job '{job_name}' calls missing {callee_path}")
                continue
            for cj_name, cj in (callee.get("jobs") or {}).items():
                if not isinstance(cj, dict):
                    continue
                needed = norm(cj.get("permissions"))
                if not needed:
                    continue
                for scope, level in needed.items():
                    if level == "none":
                        continue
                    if not covers(caller_perms, scope, level):
                        failures.append(
                            f"{caller_path}: caller '{job_name}' grants "
                            f"{scope}={(caller_perms or {}).get(scope, 'none') if caller_perms else 'unspecified'} "
                            f"but {callee_path} job '{cj_name}' needs {scope}={level}"
                        )
    if failures:
        sys.stderr.write("::error::reusable-workflow permission gaps (a release run would startup_failure):\n")
        for f in failures:
            sys.stderr.write("  " + f + "\n")
        sys.exit(1)
    print("reusable-workflow permissions: every caller covers its callees' requests")


if __name__ == "__main__":
    main()
