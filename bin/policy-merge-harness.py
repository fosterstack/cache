#!/usr/bin/env python3
"""Run the real text of a workflow step that merges the two policy lists, against a fixture origin/main, and check
that a bad policy file is refused and leaves no shorter merged list behind.
usage: policy-merge-harness.py <repo root> <workflow file> <step name fragment> <merged list path in the fixture> <label>"""
import json, os, shutil, subprocess, sys, tempfile, yaml

root, wfname, needle, merged_rel, label = sys.argv[1:6]
step = next(s for j in yaml.load(open(f"{root}/.github/workflows/{wfname}"), Loader=yaml.BaseLoader)["jobs"].values()
            for s in j.get("steps") or [] if needle in s.get("name", ""))
pol = f"{root}/.github/policy"


def contexts(path):
    return [c["context"] for c in json.load(open(path))["required_checks"]]


want = sorted(contexts(f"{pol}/required-checks.json") + contexts(f"{pol}/release-only-checks.json"))


def run_step(files):
    w = tempfile.mkdtemp()
    origin, clone, stub, seed = f"{w}/origin.git", f"{w}/clone", f"{w}/stub", f"{w}/seed"
    os.makedirs(f"{seed}/.github/policy")
    os.makedirs(f"{seed}/bin")
    os.makedirs(stub)
    for f in os.listdir(pol):
        shutil.copy(f"{pol}/{f}", f"{seed}/.github/policy/{f}")
    for f in ("admission-tag-signer.py", "install-scanner.sh", "patch-decide.py"):
        shutil.copy(f"{root}/bin/{f}", f"{seed}/bin/{f}")
    for f, text in files.items():
        p = f"{seed}/.github/policy/{f}"
        if text is None:
            os.remove(p)
        else:
            open(p, "w").write(text)
    g = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", origin], check=True)
    for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-qm", "c"], ["push", "-q", origin, "main"]):
        subprocess.run(g + cmd if cmd[0] == "commit" else ["git"] + cmd, cwd=seed, check=True)
    subprocess.run(["git", "clone", "-q", origin, clone], check=True)
    # no check runs: the release step, once it accepts the lists, waits; the stub ends that wait with 99
    open(f"{stub}/gh", "w").write("#!/bin/bash\nexit 0\n")
    open(f"{stub}/sleep", "w").write("#!/bin/bash\nexit 99\n")
    for s in ("gh", "sleep"):
        os.chmod(f"{stub}/{s}", 0o755)
    os.makedirs(f"{w}/tmp")
    os.makedirs(f"{w}/policy")
    text = step["run"].replace("/tmp/policy", f"{w}/policy")
    env = dict(os.environ, PATH=f"{stub}:{os.environ['PATH']}", RUNNER_TEMP=f"{w}/tmp", GH_TOKEN="x",
               GITHUB_REPOSITORY="o/r", GITHUB_SHA="0" * 40, GITHUB_OUTPUT=f"{w}/out")
    r = subprocess.run(["bash", "-c", text], cwd=clone, env=env, capture_output=True, text=True, timeout=60)
    try:
        merged = contexts(f"{w}/{merged_rel}")
    except (OSError, ValueError, KeyError, TypeError):
        merged = None
    shutil.rmtree(w)
    return r.returncode, merged


failed = 0


def report(ok, name, got):
    global failed
    failed += not ok
    print(("PASS" if ok else "FAIL"), f"{label}: {name}", "" if ok else f"-> {got}")


rc, merged = run_step({})
report(sorted(merged or []) == want and rc in (0, 99), f"a good pair merges to all {len(want)} contexts", (rc, merged))
bad_forms = {"empty-object": "{}", "empty-file": "", "null-list": '{"required_checks": null}',
             "empty-list": '{"required_checks": []}', "top-level-array": "[]", "missing": None}
for f in ("release-only-checks.json", "required-checks.json"):
    for form, text in bad_forms.items():
        rc, merged = run_step({f: text})
        short = merged is not None and len(merged) < len(want)
        report(rc not in (0, 99) and not short, f"{f} {form} is refused",
               f"exit {rc}, merged {len(merged) if merged is not None else None} contexts")
sys.exit(1 if failed else 0)
