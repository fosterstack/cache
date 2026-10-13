#!/usr/bin/env python3
"""The marker-only pull request gate (REQ-CHAIN-001-AC6 "whose CI verifies"; orchestrator ruling Oct 13).

    marker-pr-gate.py --base-dir DIR --head-dir DIR --files FILE --repository OWNER/NAME

Run by the `marker-gate` job of ci.yml on a pull request, from the BASE branch's checkout (DIR of --base-dir); the head checkout is data. FILE holds the pull request's
changed paths, one per line (the API's list).

  * A pull request that does not change .github/policy/rc-proof.json is not this gate's business: exit 0, nothing read.
  * One that does must change exactly that file and test-evidence/known-red.json, and the known-red.json of the head must be the base's with the one entry KR-CUTOVER
    removed and every other entry equal and in the same order (AC6: the marker pull request carries the marker and the removal of that one entry, nothing else).
  * The run the marker names must be a completed, successful push of this repository's release.yml on the marker's rc tag, at the commit that tag names in the head
    checkout. Its artifacts are downloaded, laid out as `chain-verify.py rc-proof` reads them, and that command (the base's copy) is run; its exit status is the gate's.

LIMIT, in plain words: this gate stops a marker pull request that carries anything else or names a run that does not verify. A pull request that also rewrites this gate's
own job in ci.yml is stopped by the existing workflow-change rule (both reviews and the owner's merge), not by this job. The job's text is pinned by bin/marker-gate-test.sh.

Standard library and the gh and git programs only; every program is run with an argument list, never a shell.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

MARKER = ".github/policy/rc-proof.json"
KNOWN_RED = "test-evidence/known-red.json"
ENTRY = "KR-CUTOVER"
WORKFLOW = ".github/workflows/release.yml"
RC_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+")
RUN_ID = re.compile(r"[0-9]{1,20}")
# the artifacts of the run and where each one lands in the layout rc-proof reads (the layout of Release's own directories)
ARTIFACTS = (
    ("witness-build", "witness-build"),
    ("digests", "witness-build"),
    ("items", "witness-build"),
    ("provenance", "provenance"),
    ("witness-rebuild", "witness-rebuild"),
    ("witness-check", "witness-check"),
    ("witness-check-arm64", "witness-check"),
    ("hostile-results", "hostile-results"),
)


class Refusal(Exception):
    pass


def refuse(reason):
    raise Refusal(reason)


def run(cmd, what, env=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    except OSError as ex:
        refuse("%s: %s cannot be run (%s)" % (what, cmd[0], type(ex).__name__))
    return p


def load_json(path, what):
    try:
        with open(path, "rb") as f:
            return json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError) as ex:
        refuse("%s is missing or not JSON (%s)" % (what, type(ex).__name__))


def check_files(files):
    want = {MARKER, KNOWN_RED}
    if set(files) != want:
        extra = sorted(set(files) - want)
        missing = sorted(want - set(files))
        refuse("a marker pull request changes exactly %s and %s: %s" % (MARKER, KNOWN_RED, ("also changes " + ", ".join(extra)) if extra else ("does not change " + ", ".join(missing))))


def entries_of(doc, what):
    ents = doc.get("entries") if isinstance(doc, dict) else None
    if not isinstance(ents, list) or not all(isinstance(e, dict) and isinstance(e.get("id"), str) for e in ents):
        refuse("%s has no entries list of objects with an id" % what)
    ids = [e["id"] for e in ents]
    if len(set(ids)) != len(ids):
        refuse("%s lists an id twice" % what)
    return ents


def check_known_red(base_dir, head_dir):
    b = entries_of(load_json(os.path.join(base_dir, KNOWN_RED), "the base's " + KNOWN_RED), "the base's " + KNOWN_RED)
    h = entries_of(load_json(os.path.join(head_dir, KNOWN_RED), "the head's " + KNOWN_RED), "the head's " + KNOWN_RED)
    if ENTRY not in {e["id"] for e in b}:
        refuse("the base's %s has no %s entry to remove" % (KNOWN_RED, ENTRY))
    if ENTRY in {e["id"] for e in h}:
        refuse("the head's %s still lists %s: the marker pull request removes it" % (KNOWN_RED, ENTRY))
    want = [e for e in b if e["id"] != ENTRY]
    if h != want:
        bids, hids = [e["id"] for e in want], [e["id"] for e in h]
        added = [i for i in hids if i not in bids]
        gone = [i for i in bids if i not in hids]
        changed = [i for i in hids if i in bids and h[hids.index(i)] != want[bids.index(i)]]
        refuse("the head's %s differs from the base's by more than the removal of %s: %s" % (
            KNOWN_RED, ENTRY, "; ".join(x for x in (("added " + ", ".join(added)) if added else "", ("removed " + ", ".join(gone)) if gone else "",
                                                    ("changed " + ", ".join(changed)) if changed else "", "reordered" if not (added or gone or changed) else "") if x)))


def read_marker(head_dir):
    m = load_json(os.path.join(head_dir, MARKER), "the marker " + MARKER)
    if not isinstance(m, dict) or not isinstance(m.get("rc_tag"), str) or not RC_TAG.fullmatch(m["rc_tag"]) or not isinstance(m.get("run_id"), str) or not RUN_ID.fullmatch(m["run_id"]):
        refuse("the marker is not an object with an rc tag vX.Y.Z-rcN and a numeric run id")
    return m


def tag_commit(head_dir, tag):
    p = run(["git", "-C", head_dir, "rev-parse", "--verify", "-q", "refs/tags/%s^{commit}" % tag], "the rc tag")
    out = p.stdout.strip()
    if p.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", out):
        refuse("the rc tag %s named by the marker does not exist in the checkout" % tag)
    return out


def check_run(repository, marker, tag_sha):
    p = run(["gh", "api", "repos/%s/actions/runs/%s" % (repository, marker["run_id"])], "the run")
    if p.returncode != 0:
        refuse("the run %s named by the marker cannot be read: %s" % (marker["run_id"], (p.stderr.strip().splitlines() or ["no answer"])[0][:160]))
    try:
        r = json.loads(p.stdout)
    except ValueError:
        refuse("the run %s answer is not JSON" % marker["run_id"])
    if not isinstance(r, dict):
        refuse("the run %s answer is not an object" % marker["run_id"])
    repo = (r.get("repository") or {}).get("full_name") if isinstance(r.get("repository"), dict) else None
    checks = (
        ("repository", repo == repository, "the run belongs to %r, not this repository %r" % (repo, repository)),
        ("path", r.get("path") == WORKFLOW, "the run is of %r, not %s" % (r.get("path"), WORKFLOW)),
        ("event", r.get("event") == "push", "the run's event is %r, not push" % r.get("event")),
        ("head_branch", r.get("head_branch") == marker["rc_tag"], "the run ran on %r, not the marker's rc tag %s" % (r.get("head_branch"), marker["rc_tag"])),
        ("head_sha", r.get("head_sha") == tag_sha, "the run's commit %r is not the commit %s the rc tag names" % (r.get("head_sha"), tag_sha)),
        ("status", r.get("status") == "completed", "the run's status is %r, not completed" % r.get("status")),
        ("conclusion", r.get("conclusion") == "success", "the run's conclusion is %r, not success" % r.get("conclusion")),
    )
    for name, good, why in checks:
        if not good:
            refuse("run: %s: %s" % (name, why))


def download(repository, run_id, records):
    for name, dest in ARTIFACTS:
        target = os.path.join(records, dest)
        os.makedirs(target, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix="art-", dir=records)
        p = run(["gh", "run", "download", run_id, "-R", repository, "-n", name, "-D", tmp], "the artifact " + name)
        if p.returncode != 0:
            refuse("the artifact %s of run %s cannot be downloaded: %s" % (name, run_id, (p.stderr.strip().splitlines() or ["no answer"])[0][:160]))
        for entry in sorted(os.listdir(tmp)):
            dst = os.path.join(target, entry)
            if os.path.exists(dst):
                refuse("the artifact %s holds %s, which another artifact already placed" % (name, entry))
            shutil.move(os.path.join(tmp, entry), dst)
        os.rmdir(tmp)


def main(argv):
    ap = argparse.ArgumentParser(prog="marker-pr-gate")
    ap.add_argument("--base-dir", required=True)
    ap.add_argument("--head-dir", required=True)
    ap.add_argument("--files", required=True)
    ap.add_argument("--repository", required=True)
    a = ap.parse_args(argv)
    try:
        try:
            with open(a.files) as f:
                files = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        except OSError:
            refuse("the pull request's file list cannot be read")
        if not files:
            refuse("the pull request's file list is empty: nothing can be judged (an empty answer is never read as 'no marker')")
        if MARKER not in files:
            print("marker-pr-gate: this pull request does not change %s: not applicable" % MARKER)
            return 0
        check_files(files)
        check_known_red(a.base_dir, a.head_dir)
        marker = read_marker(a.head_dir)
        check_run(a.repository, marker, tag_commit(a.head_dir, marker["rc_tag"]))
        records = tempfile.mkdtemp(prefix="records-")
        try:
            download(a.repository, marker["run_id"], records)
            head_sha = run(["git", "-C", a.head_dir, "rev-parse", "HEAD"], "the head commit").stdout.strip()
            if not re.fullmatch(r"[0-9a-f]{40}", head_sha):
                refuse("the head commit cannot be read")
            cmd = [sys.executable, "-I", "-B", os.path.join(a.base_dir, "bin/chain-verify.py"), "rc-proof",
                   "--marker", os.path.join(a.head_dir, MARKER), "--commit", head_sha, "--repo", a.head_dir, "--records", records,
                   "--template", os.path.join(a.base_dir, ".github/policy/release-policy.template.json"), "--repository", a.repository]
            p = subprocess.run(cmd)
            if p.returncode != 0:
                refuse("rc-proof: the verifier refused the run's records (exit %d)" % p.returncode)
        finally:
            shutil.rmtree(records, ignore_errors=True)
    except Refusal as r:
        print("marker-pr-gate: refused: %s" % r, file=sys.stderr)
        return 1
    print("marker-pr-gate: the marker, the removal of %s and the run %s verify" % (ENTRY, marker["run_id"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
