"""The tag observer: what our own scheduled runs have seen of the tags of the actions we use (handoffs 0183, 0184).

Self-contained and shared verbatim between the cache and ops repos. A release's publish date says nothing about the commit its tag
points to today (the tj-actions pattern moved tags under old releases), so an action's age is the first time OUR scheduled run on
main saw that tag point at that exact commit. The state is cumulative and kept as an artifact of those runs; only runs that are
event=schedule, branch main, completed (success or failure), from our daily workflow's path are ever read, so a PR can never forge it.

state = {"version": 1, "first_seen": {"owner/repo@tag@commit": "2026-10-05T12:00:00Z", ...}}
"""
import io
import json
import zipfile

STATE_NAME = "tag-observations"
STATE_FILE = "state.json"
# The daily workflow allowed to write the state (the only edit from the ops copy).
WORKFLOW_PATHS = (".github/workflows/supply-chain.yml",)


def update_state(prev, current, now_iso):
    """Add today's {"owner/repo@tag": commit} mappings. A mapping keeps the time it was first seen; a tag that moves is a NEW
    mapping (a new commit) with a new time; nothing is ever forgotten."""
    state = {"version": 1, "first_seen": dict((prev or {}).get("first_seen", {}))}
    for key, commit in current.items():
        repo_tag = key.rsplit("@", 1)
        state["first_seen"].setdefault(f"{repo_tag[0]}@{repo_tag[1]}@{commit}", now_iso)
    return state


def first_seen(state, repo, tag, commit):
    """The time we first saw `tag` of `repo` at exactly `commit`, or None."""
    return ((state or {}).get("first_seen") or {}).get(f"{repo}@{tag}@{commit}")


def accept_run(run):
    """Only a completed scheduled run on main of our daily workflow may supply the state. A run that FAILED still counts: the daily job
    writes the state first, and a real hit fails the run by design, so success-only would throw the state away exactly when it matters."""
    return (run.get("event") == "schedule" and run.get("head_branch") == "main" and run.get("conclusion") in ("success", "failure")
            and run.get("path") in WORKFLOW_PATHS)


def pack(state):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(STATE_FILE, json.dumps(state, sort_keys=True))
    return buf.getvalue()


def unpack(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return json.loads(z.read(STATE_FILE))
