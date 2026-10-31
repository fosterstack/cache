#!/usr/bin/env bash
# The scheduled input refresh (REQ-REFRESH-001; rules 44-49 and 73 of the v0.3.0 rules).
#
#   refresh-inputs.sh refresh     --repo-dir DIR --archive DIR
#   refresh-inputs.sh fips-module --go-root DIR  --repo-dir DIR
#
# This job is the only updater of image recipes, apk packages and lock files: Dependabot does not watch them (rule 45).
#
# refresh (daily, rule 44): compare the live Wolfi signing key to the archived one first (rules 32, 46: a difference
#   stops the job for a human, exit 3, no PR); re-make the image lock files and re-resolve melange's build tools against
#   live Wolfi; archive each NEW package by digest (verified against the lock's checksums before anything is kept, rule
#   48: no waiting period, signature and checksum checks still apply); update the base locks (archive paths) and the
#   melange lock and recipe pins; resolve and lock the host tools too (build/host-tools.yaml -> build/locks/host-tools.lock, REQ-REFRESH-001-AC35); if anything changed, push a branch and open a PR, never merge it and never push to
#   main (rule 49: the PR goes through every normal check). An old version that disappears from live Wolfi is noted, not
#   an error: the archive is the source of truth (rule 47). Nothing changed: nothing is committed, pushed or opened.
# fips-module (daily, rule 73; the daily job runs it after `refresh`): read the Go toolchain's own lib/fips140/certified.txt; if it names a newer certified
#   module than build/melange-fips.yaml builds, move the recipe to it and open a PR. A missing, empty or unreadable file
#   fails closed.
#
# Exit codes: 0 ok (changed or not), 1 verification failed, 2 refused (bad input), 3 the Wolfi signing key changed.
# The git identity is the caller's (the workflow job sets it); this script never sets one and never skips a hook.
set -euo pipefail
unset PYTHONOPTIMIZE   # python -O would drop every assert; the checks below are explicit anyway

WOLFI=https://packages.wolfi.dev/os
SELF=refresh-inputs.sh

# ---- fixed locations (REQ-REFRESH-001-AC23): every call names its tool by the literal fixed path (the fetch tool and git, gh,
# /usr/local/bin/apko, /usr/bin/openssl, /usr/bin/python3, /usr/bin/cmp, /usr/bin/mktemp, /bin/rm, /bin/mkdir), never through the caller's search path,
# and there is no test hook in this file: bin/refresh-inputs-test.sh runs a COPY that differs from this file only in occurrences of those ten paths,
# each replaced one for one by a dispatcher.
case $0 in */*) HERE=${0%/*} ;; *) HERE=. ;; esac   # this script's directory, without dirname
dir_empty() { local e; for e in "$1"/* "$1"/.[!.]* "$1"/..?*; do { [ -e "$e" ] || [ -L "$e" ]; } && return 1; done; return 0; }   # no ls

die() { echo "$SELF: $1" >&2; exit "${2:-2}"; }

usage() { die "usage: $SELF refresh --repo-dir DIR --archive DIR [--plan-dir DIR] | $SELF fips-module --go-root DIR --repo-dir DIR [--plan-dir DIR] | $SELF open-pr --plan-dir DIR --repo-dir DIR [--archive DIR --archive-digest sha256:HEX] | $SELF bootstrap --repo-dir DIR --archive DIR"; }

# open_pr BRANCH TITLE BODY PATH...: branch, commit, push the branch (never main), open the PR (never merge it)
# REQ-REFRESH-001-AC34: every planned path must be a regular file of the repository (no symlink, nothing real-pathed outside it, not under .git), checked before any branch is
# pushed; the commit builder and the restoration after the commit rely on this one check
check_paths() {
  /usr/bin/python3 -I -B - "$repo" "$@" <<'PY'
import os, sys
repo = sys.argv[1]; root = os.path.realpath(repo); bad = 0
for p in sys.argv[2:]:
    full = repo + "/" + p
    n_ = os.path.normpath(p)
    if p.startswith("/") or ".." in p.split("/") or n_ == ".git" or n_.startswith((".git/", "../")) or os.path.islink(full) or not os.path.isfile(full) or os.path.commonpath([root, os.path.realpath(full)]) != root:
        print("refresh-inputs.sh: %r is not a regular file of the repository (a symlink, a path outside it or its .git is refused); no branch was pushed" % p, file=sys.stderr); bad = 1
sys.exit(bad)
PY
}
# REQ-REFRESH-001-AC34: the pull request's commit through the API. $1 branch (already pushed), $2 the commit it points at, $3 headline, $4 body, then the repository paths.
signed_commit() {
  local branch=$1 base=$2 headline=$3 cbody=$4 oid ver; shift 4
  /usr/bin/python3 -I -B - "$repo" "$tmp/commit-input.json" "$branch" "$base" "$headline" "$cbody" "$@" <<'PY' || return 1
import base64, json, os, sys
repo, out, branch, base, headline, body = sys.argv[1:7]
adds, seen = [], set()
root = os.path.realpath(repo)
for p in sys.argv[7:]:
    full = repo + "/" + p
    n_ = os.path.normpath(p)
    if p.startswith("/") or ".." in p.split("/") or n_ == ".git" or n_.startswith((".git/", "../")) or os.path.islink(full) or not os.path.isfile(full) or os.path.commonpath([root, os.path.realpath(full)]) != root:
        print("refresh-inputs.sh: %r is not a regular file of the repository (a symlink, a path outside it or its .git is refused); no commit was made" % p, file=sys.stderr); sys.exit(1)
    if p in seen:
        continue                                   # the API refuses a path twice: the plan may already name build/archive.json when open-pr adds the pointer
    seen.add(p)
    adds.append({"path": p, "contents": base64.b64encode(open(full, "rb").read()).decode()})
q = "mutation($input: CreateCommitOnBranchInput!){createCommitOnBranch(input:$input){commit{oid}}}"
inp = {"branch": {"repositoryNameWithOwner": os.environ.get("GITHUB_REPOSITORY", "fosterstack/cache"), "branchName": branch}, "message": {"headline": headline, "body": body},
       "fileChanges": {"additions": adds}, "expectedHeadOid": base}
json.dump({"query": q, "variables": {"input": inp}}, open(out, "w"))
PY
  oid=$(cd "$repo" && /usr/bin/gh api graphql --input "$tmp/commit-input.json" -q '.data.createCommitOnBranch.commit.oid') \
    || { echo "refresh-inputs.sh: the API could not create the commit on $branch; opening no pull request" >&2; return 1; }
  case $oid in *[!0-9a-f]*|'') echo "refresh-inputs.sh: the API returned no commit id; opening no pull request" >&2; return 1;; esac
  [ "${#oid}" -eq 40 ] || { echo "refresh-inputs.sh: the API returned no commit id; opening no pull request" >&2; return 1; }
  ver=$(cd "$repo" && /usr/bin/gh api "repos/{owner}/{repo}/commits/$oid" -q '.commit.verification.verified') \
    || { echo "refresh-inputs.sh: could not ask whether commit $oid is verified; opening no pull request" >&2; return 1; }
  [ "$ver" = true ] || { echo "refresh-inputs.sh: commit $oid on $branch is not verified by GitHub (main requires signed commits); opening no pull request" >&2; return 1; }
  echo "signed commit $oid on $branch (verified by GitHub)"
}
open_pr() {
  local branch=$1 title=$2 body=$3; shift 3
  if [ -n "$plan_dir" ] && [ "$cmd" != open-pr ]; then   # staged: the pull request is written down and opened later by `open-pr`, once the archive is stored (rules 6 and 7)
    local seq pd
    /bin/mkdir -p "$plan_dir" || die "could not create $plan_dir" 1
    seq=1; for _e in "$plan_dir"/*; do [ -e "$_e" ] && seq=$((seq+1)); done; pd=$plan_dir/$seq-$cmd
    /bin/mkdir -p "$pd" && printf '%s\n' "$branch" >"$pd/branch" && printf '%s\n' "$title" >"$pd/title" && printf '%s\n' "$body" >"$pd/body" \
      && printf '%s\n' "$@" >"$pd/paths" || die "could not write the plan to $plan_dir" 1
    echo "planned: $branch (opened later by open-pr)"
    return 0
  fi
  # Asked again immediately before the branch is created: two overlapping runs can both have passed the staging check (REQ-REFRESH-001-AC29). Only a
  # pull request of this repository counts; the list not being readable stops the job (an unknown state is not "no pull request").
  local _open _rc=0
  _open=$(cd "$repo" && /usr/bin/gh pr list --state open --limit 1000 --json number,headRefName,isCrossRepository,author) \
    || die "cannot list the open pull requests (gh pr list failed); changing nothing, pushing nothing, opening nothing" 1
  printf '%s' "$_open" >"$tmp/open-prs.json"
  /usr/bin/python3 -I -B - "$branch" "$pr_author" "$tmp/open-prs.json" <<'PY' || _rc=$?
import json, sys
def norm(x):
    y = x.lower()
    while True:
        z = y[4:] if y.startswith("app/") else (y[:-5] if y.endswith("[bot]") else y)
        if z == y:
            return y
        y = z
for pr in json.load(open(sys.argv[3])):
    h = pr.get("headRefName", "")
    who = (pr.get("author") or {}).get("login") or ""
    if pr.get("isCrossRepository") or not h.startswith("refresh/") or (sys.argv[2] and norm(who) != norm(sys.argv[2])):
        continue
    # AC29 names no kind: any refresh/ pull request of this repository stops a second one
    print("an earlier pull request (#%s, %s) is already open; opening no second one" % (pr.get("number"), h)); sys.exit(4)
PY
  [ "$_rc" != 4 ] || return 0
  [ "$_rc" = 0 ] || die "cannot read the open pull request list; changing nothing" 1
  local base=$branch n=1
  # a branch name already taken on the remote (a closed or merged PR) gets a -2, -3, ... suffix instead of a failed push
  while [ -n "$(/usr/bin/git -C "$repo" ls-remote --heads origin "refs/heads/$branch" 2>/dev/null)" ]; do
    n=$((n+1)); [ $n -le 9 ] || die "the branch name $base and its numbered variants are all taken on the remote" 1
    branch=$base-$n
  done
  local startbr startsha rc=0 pushed=
  startbr=$(/usr/bin/git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  startsha=$(/usr/bin/git -C "$repo" rev-parse HEAD 2>/dev/null || true)
  # REQ-REFRESH-001-AC34: main requires signed commits, so the one commit is made through the API (GitHub signs what the job's App token creates), on a branch that was
  # pushed at the commit the job started from (nothing new to sign locally); the pull request is opened only for a commit the API reports as verified
  { [ -n "$startsha" ] && check_paths "$@" && /usr/bin/git -C "$repo" checkout -b "$branch" \
    && { PENDING_BRANCH=$branch; /usr/bin/git -C "$repo" push -q origin "$branch" || { PENDING_BRANCH=; false; }; } && pushed=1 \
    && signed_commit "$branch" "$startsha" "$title" "$body" "$@" \
    && (cd "$repo" && /usr/bin/gh pr create --base main --head "$branch" --title "$title" --body "$body"); } || rc=$?
  if [ "$rc" = 0 ]; then PENDING_BRANCH=; elif [ -n "$pushed" ]; then PENDING_BRANCH=; drop_branch "$branch"; fi   # no half-made branch is left behind, and a failed deletion is reported
  # the commit was made through the API, so the files the job edited are still in the working tree: put them back to the start commit (a later invocation in the same
  # checkout must see the start state, as it did when the edits were committed to the branch)
  if [ -n "$startsha" ] && check_paths "$@" 2>/dev/null; then   # only paths that passed the check are touched: a refused path (.git, a link, an outside file) is never restored or removed
    for _p in "$@"; do
      if /usr/bin/git -C "$repo" ls-files --error-unmatch -- "$_p" >/dev/null 2>&1; then /usr/bin/git -C "$repo" checkout -q "$startsha" -- "$_p" || { echo "refresh-inputs.sh: could not restore $_p to $startsha" >&2; rc=1; }
      else /bin/rm -f -- "$repo/$_p" || { echo "refresh-inputs.sh: could not remove $_p" >&2; rc=1; }; fi
    done
  fi
  # back to where the job started, whether or not a step failed: a later step of the same job (the FIPS check) must not branch from this commit.
  # A detached start is restored by its commit.
  if [ -n "$startbr" ] && [ "$startbr" != HEAD ]; then /usr/bin/git -C "$repo" checkout -q "$startbr" || { echo "refresh-inputs.sh: could not go back to $startbr; a later step would branch from the refresh commit" >&2; rc=1; }
  elif [ -n "$startsha" ]; then /usr/bin/git -C "$repo" checkout -q --detach "$startsha" || { echo "refresh-inputs.sh: could not go back to $startsha; a later step would branch from the refresh commit" >&2; rc=1; }; fi
  return $rc
}

cmd=${1:-}; [ -n "$cmd" ] || usage; shift
repo= archive= goroot= pr_author= plan_dir= archive_digest=
while [ $# -gt 0 ]; do
  case $1 in
    --repo-dir) [ $# -ge 2 ] || usage; repo=$2; shift 2;;
    --archive) [ $# -ge 2 ] || usage; archive=$2; shift 2;;
    --go-root) [ $# -ge 2 ] || usage; goroot=$2; shift 2;;
    --pr-author) [ $# -ge 2 ] || usage; pr_author=$2; shift 2;;
    --plan-dir) [ $# -ge 2 ] || usage; plan_dir=$2; shift 2;;
    --archive-digest) [ $# -ge 2 ] || usage; archive_digest=$2; shift 2;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$repo" ] && [ -d "$repo" ] || die "--repo-dir must be an existing directory"
case $cmd in key-check) [ -z "$archive$goroot$pr_author$plan_dir$archive_digest" ] || die "key-check takes only --repo-dir";; esac
case $cmd in archive-key-check) { [ -n "$archive" ] && [ -d "$archive" ]; } || die "archive-key-check needs --archive (the pulled or seeded archive)"; [ -z "$goroot$pr_author$plan_dir$archive_digest" ] || die "archive-key-check takes only --repo-dir and --archive";; esac
case $cmd in refresh|fips-module) [ -n "$pr_author" ] || die "--pr-author is required (the Auditor App's name; gh reports it as app/<name>, both spellings are accepted): without it a stranger's pull request on a refresh/ branch could be counted";; esac

tmp=$(/usr/bin/mktemp -d)
PENDING_BRANCH=
drop_branch() { /usr/bin/git -C "$repo" push -q origin --delete "$1" >/dev/null 2>&1 || echo "refresh-inputs.sh: could not delete the branch $1 from the remote; delete it by hand" >&2; }
# a signal can arrive after `gh pr create` succeeded and before PENDING_BRANCH is cleared: the branch of a live pull request is never deleted (deleting it would close the PR); if the
# open pull requests of the branch cannot be read the branch is kept too (a leftover branch is harmless, a closed pull request is not)
drop_unless_pr() {
  local n
  n=$(cd "$repo" && /usr/bin/gh pr list --state open --head "$1" --json number -q length 2>/dev/null) || n=unknown
  if [ "$n" = 0 ]; then drop_branch "$1"; else echo "refresh-inputs.sh: kept the branch $1: it has an open pull request, or its pull requests could not be read ($n)" >&2; fi
}
cleanup() { local rc=$?; set +e; [ -z "$PENDING_BRANCH" ] || drop_unless_pr "$PENDING_BRANCH"; /bin/rm -rf "$tmp" 2>/dev/null || true; exit $rc; }   # cleanup never changes the exit status; a branch pushed for a pull request that was not opened (an interrupted run) is removed
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

case $cmd in
archive-key-check)
  # After the archive is pulled or seeded and before the App token is minted: the live Wolfi signing key must be the pinned key AND the key the archive
  # holds (keys/wolfi-signing.rsa.pub); the stop then precedes every later step also when the archive carries another key (rule 6, AC30). A difference, a missing or a repeated line stops for a human (exit 3, rule 6); nothing is written.
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B - "$repo" "$tmp/live-key.pub" "$archive" <<'PY' || exit $?
import hashlib, re, sys
repo, live, archive = sys.argv[1:4]
def stop(msg):
    print("refresh-inputs.sh: %s; stopping, a human must look" % msg, file=sys.stderr); sys.exit(3)
try:
    rows = [l for l in open(repo + "/build/locks/archive-keys.sha256", "rb").read().decode("utf-8", "strict").split("\n") if l.strip()]
except (OSError, UnicodeError):
    stop("build/locks/archive-keys.sha256 is missing or unreadable, so there is no pinned Wolfi key to check the live one against")
mine = [l for l in rows if l.split(" ")[0] == "wolfi-signing.rsa.pub"]
if len(mine) != 1 or not re.fullmatch(r"wolfi-signing\.rsa\.pub sha256:[0-9a-f]{64}", mine[0]):
    stop("build/locks/archive-keys.sha256 must hold exactly one line 'wolfi-signing.rsa.pub sha256:<64 hex>'")
if hashlib.sha256(open(live, "rb").read()).hexdigest() != mine[0].split("sha256:")[1]:
    stop("the live Wolfi signing key is not the key pinned in build/locks/archive-keys.sha256")
try:
    archived = open(archive + "/keys/wolfi-signing.rsa.pub", "rb").read()
except OSError:
    stop("the archive holds no keys/wolfi-signing.rsa.pub")
if archived != open(live, "rb").read():
    stop("the live Wolfi signing key differs from the key in the archive")
print("archive-key-check: the live Wolfi signing key is the pinned one and the archive's key")
PY
  ;;
key-check)
  # The first step of the daily job, before any tool is installed, any registry is touched or any token is minted: the live Wolfi signing key must be
  # the key pinned in build/locks/archive-keys.sha256. A difference, a missing or a repeated line stops for a human (exit 3, rule 6); nothing is written.
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B - "$repo" "$tmp/live-key.pub" <<'PY' || exit $?
import hashlib, re, sys
repo, live = sys.argv[1:3]
def stop(msg):
    print("refresh-inputs.sh: %s; stopping, a human must look" % msg, file=sys.stderr); sys.exit(3)
try:
    rows = [l for l in open(repo + "/build/locks/archive-keys.sha256", "rb").read().decode("utf-8", "strict").split("\n") if l.strip()]
except (OSError, UnicodeError):
    stop("build/locks/archive-keys.sha256 is missing or unreadable, so there is no pinned Wolfi key to check the live one against")
mine = [l for l in rows if l.split(" ")[0] == "wolfi-signing.rsa.pub"]
if len(mine) != 1 or not re.fullmatch(r"wolfi-signing\.rsa\.pub sha256:[0-9a-f]{64}", mine[0]):
    stop("build/locks/archive-keys.sha256 must hold exactly one line 'wolfi-signing.rsa.pub sha256:<64 hex>'")
if hashlib.sha256(open(live, "rb").read()).hexdigest() != mine[0].split("sha256:")[1]:
    stop("the live Wolfi signing key is not the key pinned in build/locks/archive-keys.sha256")
print("key-check: the live Wolfi signing key is the pinned one")
PY
  ;;

bootstrap)
  # The archive does not exist yet (build/archive.json is absent on main). The one trust anchor is the key line committed in
  # build/locks/archive-keys.sha256: the live Wolfi key is fetched, its sha256 must be that line, and only then is it the new archive's
  # key. A missing or repeated line, or a different key, stops for a human (exit 3): there is no trust on first use.
  [ -n "$archive" ] || die "--archive is required"
  if [ -e "$archive" ] || [ -L "$archive" ]; then
    { [ -d "$archive" ] && [ ! -L "$archive" ] && dir_empty "$archive"; } || die "$archive already exists and is not an empty directory: bootstrap never touches an existing archive" 2
  fi
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  /usr/bin/python3 -I -B - "$repo" "$tmp/live-key.pub" "$archive" <<'PY' || exit $?
import hashlib, os, re, sys
repo, live, archive = sys.argv[1:4]
def stop(msg):
    print("refresh-inputs.sh: %s; stopping, a human must look" % msg, file=sys.stderr); sys.exit(3)
try:
    rows = [l for l in open(repo + "/build/locks/archive-keys.sha256", "rb").read().decode("utf-8", "strict").split("\n") if l.strip()]
except (OSError, UnicodeError):
    stop("build/locks/archive-keys.sha256 is missing or unreadable, so there is no pinned Wolfi key to check the live one against")
mine = [l for l in rows if l.split(" ")[0] == "wolfi-signing.rsa.pub"]
if len(mine) != 1 or not re.fullmatch(r"wolfi-signing\.rsa\.pub sha256:[0-9a-f]{64}", mine[0]):
    stop("build/locks/archive-keys.sha256 must hold exactly one line 'wolfi-signing.rsa.pub sha256:<64 hex>'")
raw = open(live, "rb").read()
if hashlib.sha256(raw).hexdigest() != mine[0].split("sha256:")[1]:
    stop("the live Wolfi signing key is not the key pinned in build/locks/archive-keys.sha256")
os.makedirs(archive + "/keys", exist_ok=True)
with open(archive + "/keys/wolfi-signing.rsa.pub", "xb") as f:
    f.write(raw); f.flush(); os.fsync(f.fileno())
print("bootstrap: the archive was seeded with the pinned Wolfi signing key")
PY
  ;;

open-pr)
  # Opens the pull requests that `refresh` / `fips-module --plan-dir` staged, after the archive was stored. The refresh pull request also carries
  # build/archive.json, the pointer naming the stored digest (advisor 0440 (3)). Nothing is opened unless every plan validates first.
  [ -n "$plan_dir" ] && [ -d "$plan_dir" ] || die "--plan-dir must be an existing directory"
  if [ -n "$archive_digest" ]; then
    { [ "${archive_digest#sha256:}" != "$archive_digest" ] && [ "${#archive_digest}" -eq 71 ]; } || die "--archive-digest must be sha256:<64 hex>"
    case ${archive_digest#sha256:} in *[!0-9a-f]*) die "--archive-digest must be sha256:<64 lower-case hex>";; esac
    [ -n "$archive" ] && [ -d "$archive" ] || die "--archive is required with --archive-digest"
  fi
  /usr/bin/python3 -I -B - "$repo" "$plan_dir" "$archive" "$archive_digest" "$(cd "$HERE" && pwd)" "$tmp" <<'PY' || exit $?
import json, os, re, subprocess, sys
repo, plan_dir, archive, digest, BINDIR, tmp = sys.argv[1:7]
def fail(msg, code=2): print("refresh-inputs.sh: " + msg, file=sys.stderr); sys.exit(code)
plans = []
for name in sorted(os.listdir(plan_dir), key=lambda n: (int(n.split("-")[0]) if n.split("-")[0].isdigit() else 10**9, n)):
    d = plan_dir + "/" + name
    if not os.path.isdir(d): fail("plan %s is not a directory" % name)
    try:
        branch, title, body = (open(d + "/" + f).read().rstrip("\n") for f in ("branch", "title", "body"))
        paths = [l for l in open(d + "/paths").read().split("\n") if l]
    except OSError as e:
        fail("plan %s is incomplete (%s)" % (name, e))
    if not re.fullmatch(r"refresh/[A-Za-z0-9._-]+", branch): fail("plan %s names the branch %r, not one under refresh/" % (name, branch))
    if not paths: fail("plan %s names no file" % name)
    for p in paths:
        if p.startswith("/") or ".." in p.split("/") or not os.path.isfile(repo + "/" + p): fail("plan %s names %r, which is not a file of the repository" % (name, p))
    plans.append((branch, title, body, paths, branch.startswith("refresh/fips-module-")))
if not plans:
    print("open-pr: nothing planned, nothing opened"); open(tmp + "/ncount", "w").write("0\n"); sys.exit(0)
if digest and not any(not p[4] for p in plans):
    print("open-pr: the plan holds no refresh pull request, so the pointer is not written")
out = []
for branch, title, body, paths, fips in plans:
    if digest and not fips:
        r = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/archive-verify.py", "make-pointer", "--dir", archive, "--digest", digest,
                            "--out", repo + "/build/archive.json"], capture_output=True, text=True)
        if r.returncode != 0: fail("the pointer for %s could not be made: %s" % (digest, (r.stderr or r.stdout).strip()), 1)
        paths = paths + ["build/archive.json"]
        body += "\n\nThe archive was stored in our registry at %s; this pull request moves build/archive.json to it." % digest
    out.append("\0".join([branch, title, body] + paths))
open(tmp + "/plans", "w").write("\n\1\n".join(out))
open(tmp + "/ncount", "w").write("%d\n" % len(out))
PY
  nc=0; read -r nc <"$tmp/ncount" 2>/dev/null || nc=0
  [ "$nc" != 0 ] || exit 0
  # the validated plans, one open_pr each, in plan order
  /usr/bin/python3 -I -B - "$tmp/plans" "$tmp" <<'PY' || exit $?
import sys
parts = open(sys.argv[1]).read().split("\n\1\n")
for i, p in enumerate(parts, 1):
    f = p.split("\0")
    open("%s/p%d.branch" % (sys.argv[2], i), "w").write(f[0])
    open("%s/p%d.title" % (sys.argv[2], i), "w").write(f[1])
    open("%s/p%d.body" % (sys.argv[2], i), "w").write(f[2])
    open("%s/p%d.paths" % (sys.argv[2], i), "w").write("\n".join(f[3:]) + "\n")
PY
  n=$nc; i=1; rc_all=0
  while [ "$i" -le "$n" ]; do
    paths=(); while IFS= read -r l; do [ -n "$l" ] && paths+=("$l"); done <"$tmp/p$i.paths"
    open_pr "$(<"$tmp/p$i.branch")" "$(<"$tmp/p$i.title")" "$(<"$tmp/p$i.body")" "${paths[@]}" || rc_all=1
    i=$((i+1))
  done
  exit $rc_all
  ;;

refresh)
  [ -n "$archive" ] && [ -d "$archive" ] || die "--archive must be an existing directory"
  archived_key=$archive/keys/wolfi-signing.rsa.pub
  [ -x /usr/bin/openssl ] || die "openssl is required to verify the package index signature and was not found (/usr/bin/openssl)"
  [ -s "$archived_key" ] || die "the archive has no Wolfi signing key at keys/wolfi-signing.rsa.pub"

  # rules 32 and 46: every run, before anything else, compare the live key to the archived one
  /usr/bin/curl -q -fsSL -g --max-filesize 65536 --max-time 60 --proto =https --tlsv1.2 -o "$tmp/live-key.pub" https://packages.wolfi.dev/os/wolfi-signing.rsa.pub || die "could not fetch the live Wolfi signing key" 1
  # the live key's sha256 must be the one pinned in build/locks/archive-keys.sha256, checked right after the fetch and before the key is used for anything
  /usr/bin/python3 -I -B - "$repo" "$tmp/live-key.pub" <<'PY' || exit $?
import hashlib, re, sys
repo, live = sys.argv[1:3]
def stop(msg):
    print("refresh-inputs.sh: %s; stopping, a human must look" % msg, file=sys.stderr); sys.exit(3)
try:
    rows = [l for l in open(repo + "/build/locks/archive-keys.sha256", "rb").read().decode("utf-8", "strict").split("\n") if l.strip()]
except (OSError, UnicodeError):
    stop("build/locks/archive-keys.sha256 is missing or unreadable, so there is no pinned Wolfi key to check the live one against")
mine = [l for l in rows if l.split(" ")[0] == "wolfi-signing.rsa.pub"]
if len(mine) != 1 or not re.fullmatch(r"wolfi-signing\.rsa\.pub sha256:[0-9a-f]{64}", mine[0]):
    stop("build/locks/archive-keys.sha256 must hold exactly one line 'wolfi-signing.rsa.pub sha256:<64 hex>'")
if hashlib.sha256(open(live, "rb").read()).hexdigest() != mine[0].split("sha256:")[1]:
    stop("the live Wolfi signing key is not the key pinned in build/locks/archive-keys.sha256")
PY
  if ! /usr/bin/cmp -s "$tmp/live-key.pub" "$archived_key"; then
    echo "$SELF: the live Wolfi signing key differs from the archived one; stopping, no pull request, a human must decide whether to trust the new key" >&2
    exit 3
  fi

  for f in build/apko.yaml build/apko-fips.yaml build/melange.yaml build/melange-fips.yaml build/locks/apko.base.lock.json \
           build/locks/apko-fips.base.lock.json build/locks/melange.lock build/melange.yaml.tmpl build/locks/fips-module.txt build/host-tools.yaml build/locks/host-tools.lock; do
    [ -f "$repo/$f" ] || die "missing $f in $repo"
  done

  # configs that resolve against live Wolfi: no local repositories or keys, and not our own apk (the base lock holds none)
  /bin/mkdir -p "$tmp/production" "$tmp/fips" "$tmp/melange" "$tmp/host"
  /usr/bin/python3 -I -B - "$repo" "$tmp" <<'PY'
import re, sys, yaml
repo, tmp = sys.argv[1:3]
for src, out in (("apko.yaml", "production/apko.yaml"), ("apko-fips.yaml", "fips/apko-fips.yaml")):
    d = yaml.safe_load(open("%s/build/%s" % (repo, src)))
    c = d.setdefault("contents", {})
    c["repositories"] = []; c["keyring"] = []
    c["packages"] = [p for p in c.get("packages", []) if not str(p).startswith("fscache")]
    yaml.safe_dump(d, open("%s/%s" % (tmp, out), "w"))
m = yaml.safe_load(open(repo + "/build/melange.yaml"))
names = [str(p).split("=")[0] for p in m["environment"]["contents"]["packages"]]
yaml.safe_dump({"contents": {"repositories": [], "keyring": [], "packages": names}, "archs": ["x86_64", "aarch64"]},
               open(tmp + "/melange/melange-env.yaml", "w"))
# REQ-REFRESH-001-AC35: the packages the Build jobs run on the runner itself (bubblewrap and its libraries), resolved like melange's build tools
def refuse(msg):
    print("refresh-inputs.sh: refused: %s" % msg, file=sys.stderr); sys.exit(2)
class StrictLoader(yaml.SafeLoader):
    pass
def _no_dup(loader, node, deep=False):
    seen = set()
    for k, _ in node.value:
        key = loader.construct_object(k, deep=True)
        if not isinstance(key, str):
            refuse("build/host-tools.yaml has a key that is not a plain string: %r" % (key,))
        if key in seen:
            refuse("build/host-tools.yaml has the key %r twice" % (key,))
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)
StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup)
try:
    h = yaml.load(open(repo + "/build/host-tools.yaml"), Loader=StrictLoader)
except yaml.YAMLError as e:
    refuse("build/host-tools.yaml is not valid YAML (%s)" % str(e).splitlines()[0])
# a closed shape: exactly one key, packages, a non-empty list of unique plain package names (no version, no path: the lock pins the versions)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
if not isinstance(h, dict) or set(h) != {"packages"}:
    refuse("build/host-tools.yaml must hold exactly one key, packages")
hnames = h["packages"]
if not isinstance(hnames, list) or not hnames or not all(isinstance(n, str) and NAME.fullmatch(n) and ".." not in n for n in hnames) or len(set(hnames)) != len(hnames):
    refuse("build/host-tools.yaml packages must be a non-empty list of unique plain package names (no version, no path)")
# the committed lock: name=version rows in the closed grammar, each name once
seen_n = set()
_lock_text = open(repo + "/build/locks/host-tools.lock", newline="").read()   # no newline translation: a carriage return is a bad row, not a line end
if _lock_text and not _lock_text.endswith("\n"):
    refuse("build/locks/host-tools.lock must end with a line end")
for _row in (_lock_text.split("\n")[:-1] if _lock_text else []):
    _n, _eq, _v = _row.partition("=")
    if not _eq or not NAME.fullmatch(_n) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", _v) or ".." in _n or ".." in _v or _n in seen_n:
        refuse("build/locks/host-tools.lock has a row that is not a name=version of the closed grammar, or a name twice: %r" % _row)
    seen_n.add(_n)
yaml.safe_dump({"contents": {"repositories": [], "keyring": [], "packages": hnames}, "archs": ["x86_64", "aarch64"]},
               open(tmp + "/host/host-tools-env.yaml", "w"))
PY
  lock() { /usr/local/bin/apko lock --arch x86_64,aarch64 --repository-append "$WOLFI" --keyring-append "$archived_key" --output "$2" "$1"; }
  lock "$tmp/production/apko.yaml" "$tmp/production.lock.json"
  lock "$tmp/fips/apko-fips.yaml" "$tmp/fips.lock.json"
  lock "$tmp/melange/melange-env.yaml" "$tmp/melange.lock.json"
  lock "$tmp/host/host-tools-env.yaml" "$tmp/host-tools.lock.json"

  # The embedded program asks for downloads by exit status 75 and a list (`<url path> <stage file>` per line); the shell fetches them with the
  # ruled download lines below and runs the program again (it starts from the same state each time, up to three passes: packages, index, the rest).
  refresh_py() { /usr/bin/python3 -I -B - "$repo" "$archive" "$tmp" "$pr_author" "$(cd "$HERE" && pwd)" <<'PY'
import base64, hashlib, io, json, os, re, secrets, shutil, subprocess, sys, tarfile, urllib.parse, yaml, zlib
repo, archive, tmp, PR_AUTHOR, BINDIR = sys.argv[1:6]
ARCHS = ["x86_64", "aarch64"]


def norm_login(x):
    """lower case (GitHub logins are not case-sensitive), then strip the decorations until none is left: app/bot, bot[bot], app/bot[bot]"""
    y = x.lower()
    while True:
        z = y[4:] if y.startswith("app/") else (y[:-5] if y.endswith("[bot]") else y)
        if z == y:
            return y
        y = z


def open_prs_guard(kind):
    """Looked up before the FIRST archive or repository change. The open pull requests are listed once; if the list cannot be read the job fails
    (an unknown state is not "no PR"). If any pull request of this kind (input refresh, or FIPS module) is open, whether it is this very change
    or an earlier one, nothing more is done: no change, no push, no second PR. The stall is visible: the log and the job summary name it."""
    r = subprocess.run(["/usr/bin/gh", "pr", "list", "--state", "open", "--limit", "1000", "--json", "number,headRefName,isCrossRepository,author"],
                       cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        fail("cannot list the open pull requests (gh pr list failed); changing nothing, pushing nothing, opening nothing")
    pfx = "refresh/"   # AC29 names no kind: a package refresh and a certified-module pull request stop each other
    try:
        prs = json.loads(r.stdout)
    except ValueError:
        fail("cannot read the open pull request list (not JSON); changing nothing")
    for pr in prs:
        # only OUR pull requests count: from this repository (not a fork) and, when the job's identity is given, authored by it
        who = ((pr.get("author") or {}).get("login") or "")
        if pr.get("isCrossRepository") or (PR_AUTHOR and norm_login(who) != norm_login(PR_AUTHOR)):
            continue
        num, head = pr.get("number"), pr.get("headRefName", "")
        if head.startswith(pfx):
            msg = "an earlier pull request (#%s, %s) of this kind is still open (already open); changing nothing, pushing nothing and opening no second one (it is merged or closed first)" % (num, head)
            print(msg)
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                open(os.environ["GITHUB_STEP_SUMMARY"], "a").write("- %s: %s\n" % (kind, msg))
            sys.exit(0)


HINT = ""   # appended to a failure while a file that was already in the archive is being checked


def fail(msg, code=1):
    print("refresh-inputs.sh: " + msg + HINT, file=sys.stderr)
    sys.exit(code)


INFLATE_CAP = 128 * 1024 * 1024   # the live index is about 42 MiB decompressed today


def inflate(rest, what, cap=None):
    """one gzip stream from the front of rest, decompressed to at most cap (default 128 MiB): (compressed bytes, data, remaining bytes)"""
    cap = INFLATE_CAP if cap is None else cap
    d = zlib.decompressobj(31)
    data = d.decompress(rest, cap + 1)
    if len(data) > cap or d.unconsumed_tail:
        fail("%s decompresses to more than 128 MiB (too large; refusing before anything is checked)" % what)
    if not d.eof:
        fail("%s is not a complete gzip stream (its trailer is missing); a human must look" % what)
    used = len(rest) - len(d.unused_data) - len(d.unconsumed_tail)
    return rest[:used], data, d.unused_data


def b64(raw): return base64.b64encode(raw).decode()


def digest(kind, raw):
    return {"sha1": hashlib.sha1, "sha256": hashlib.sha256}[kind](raw).digest()


def verify(path, e):
    """The bytes must match every checksum the lock records for this package; control and data ranges are REQUIRED (a package with
    nothing to check is not accepted), and the datahash in the control section must equal the sha256 of the data stream."""
    raw = open(path, "rb").read()
    for part in ("signature", "control", "data"):
        p = e.get(part) or {}
        if not p.get("range"):
            if part == "signature":
                continue   # Wolfi's individual apks carry no per-package signature (the signed index does)
            fail("the lock has no %s range for %s-%s (%s); refusing a package with nothing to check" % (part, e["name"], e["version"], e["architecture"]))
        m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", p["range"])
        kind, _, want = p["checksum"].partition("-")
        if not m or kind not in ("sha1", "sha256"):
            fail("cannot read the %s checksum of %s" % (part, e["name"]), 2)
        got = b64(digest(kind, raw[int(m.group(1)):int(m.group(2)) + 1]))
        if got != want:
            fail("checksum mismatch: %s-%s.apk (%s) %s section is %s-%s, the lock says %s-%s"
                 % (e["name"], e["version"], e["architecture"], part, kind, got, kind, want))
    spans = []
    for part in ("signature", "control", "data"):
        pr = e.get(part) or {}
        if pr.get("range"):
            mm = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", pr["range"])
            spans.append((part, int(mm.group(1)), int(mm.group(2))))
    pos = 0
    for part, lo, hi in spans:
        if lo != pos:
            fail("%s-%s.apk (%s): the %s range starts at byte %d, the previous section ends at %d (ranges must be contiguous)" % (e["name"], e["version"], e["architecture"], part, lo, pos))
        pos = hi + 1
    if pos != len(raw):
        fail("%s-%s.apk (%s): the lock's ranges end at byte %d but the file has %d bytes (bytes after the last range, or a short file: the end of the file is not covered)" % (e["name"], e["version"], e["architecture"], pos, len(raw)))
    ctrl = e["control"]; m = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", ctrl["range"])
    cbytes = raw[int(m.group(1)):int(m.group(2)) + 1]
    if "Q1" + b64(hashlib.sha1(cbytes).digest()) != e["checksum"]:
        fail("checksum mismatch: %s-%s.apk (%s) package identity differs from the lock" % (e["name"], e["version"], e["architecture"]))
    dm = re.fullmatch(r"bytes=([0-9]+)-([0-9]+)", e["data"]["range"])
    try:
        pk = tarfile.open(fileobj=io.BytesIO(inflate(cbytes, "the control section")[1])).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        if len(dhs) != 1:
            fail("%s-%s.apk (%s): the control section must hold exactly one datahash line (found %d)" % (e["name"], e["version"], e["architecture"], len(dhs)))
        dh = dhs[0]
    except SystemExit:
        raise
    except Exception:
        fail("%s-%s.apk (%s): the control section has no readable .PKGINFO datahash" % (e["name"], e["version"], e["architecture"]))
    if hashlib.sha256(raw[int(dm.group(1)):int(dm.group(2)) + 1]).hexdigest() != dh:
        fail("%s-%s.apk (%s): the data stream does not hash to the datahash in its (checksummed) control section" % (e["name"], e["version"], e["architecture"]))


def ident(e):
    # every field a lock records about the bytes: the package identity checksum, the signature, control and data checksums and their ranges
    sig = e.get("signature") or {}
    return (e["name"], e["version"], e["architecture"], e.get("checksum"), sig.get("checksum"), sig.get("range"),
            e["control"]["checksum"], e["control"].get("range"), e["data"]["checksum"], e["data"].get("range"))


NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]*")


WOLFI_URL = "https://packages.wolfi.dev/os/"


def check_entry(e, where):
    """Names, versions and architectures become archive paths: nothing with a slash, a dot-dot or an unknown architecture gets that far."""
    for k, rx in (("name", NAME_RE), ("version", VERSION_RE)):
        if not isinstance(e.get(k), str) or not rx.fullmatch(e[k]) or ".." in e[k]:
            fail("refused: invalid package %s %r in %s" % (k, e.get(k), where), 2)
    if e.get("architecture") not in ARCHS:
        fail("refused: invalid architecture %r for %s in %s" % (e.get("architecture"), e.get("name"), where), 2)
    u = str(e.get("url", ""))
    if not re.fullmatch(r"https://packages\.wolfi\.dev/os/[A-Za-z0-9._+~/-]+", u):
        fail("refused: the url of %s in %s holds a character outside the plain set (letters, digits and . _ + ~ - /) or is not a packages.wolfi.dev/os address" % (e.get("name"), where), 2)
    try:
        pu = urllib.parse.urlsplit(u)
        port = pu.port
    except ValueError:
        pu, port = None, 0
    if (pu is None or pu.scheme != "https" or pu.hostname != "packages.wolfi.dev" or port is not None or pu.username or pu.password or "@" in u
            or "\\" in u or not pu.path.startswith("/os/") or ".." in pu.path.split("/") or pu.query or pu.fragment or not u.startswith(WOLFI_URL)):
        fail("refused: the url of %s in %s is not a plain https://packages.wolfi.dev/os/ address (host check before anything is fetched)" % (e.get("name"), where), 2)


def load_live(path):
    pk = json.load(open(path))["contents"]["packages"]
    for e in pk:
        check_entry(e, os.path.basename(path))
    per = {a: {e["name"]: e["version"] for e in pk if e["architecture"] == a} for a in ARCHS}
    for a in ARCHS:
        if not per[a]:
            fail("the live lock %s has no package for %s" % (os.path.basename(path), a))
    if per["x86_64"] != per["aarch64"]:
        diff = sorted(n for n in set(per["x86_64"]) | set(per["aarch64"]) if per["x86_64"].get(n) != per["aarch64"].get(n))
        fail("the live lock %s resolves different versions on the two architectures (%s)" % (os.path.basename(path), ", ".join(diff)))
    return pk


def local_url(e): return "/work/archive/%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"])


# ---- what the repository holds now ----
base = {}
for kind, f in (("production", "apko.base.lock.json"), ("fips", "apko-fips.base.lock.json")):
    path = "%s/build/locks/%s" % (repo, f)
    base[kind] = {"path": path, "doc": json.load(open(path))}
old_mel = [l for l in open(repo + "/build/locks/melange.lock").read().splitlines() if l]
old_host = [l for l in open(repo + "/build/locks/host-tools.lock").read().splitlines() if l]

live = {"production": load_live(tmp + "/production.lock.json"), "fips": load_live(tmp + "/fips.lock.json")}
live_mel = load_live(tmp + "/melange.lock.json")
live_host = load_live(tmp + "/host-tools.lock.json")

# ---- the archive's index is re-checked on EVERY run against build/locks/archive-index.sha256 ----
# Damage is unconditional: a stored index that does not hash to its own name, a pointer file that is not the recorded index, or a missing
# pointer stops the job (a human must look). A pointer that is intact but NEWER than the record is the normal state while a refresh PR waits (the archive
# is outside git, so it is always ahead of main until that PR is merged): then an open refresh PR of ours means "wait" (the guard below, nothing changed),
# and with no such PR (it was closed unmerged) the run reconciles: it stores the verified live index and rewrites the record in a new PR.
stage = tmp + "/dl"
archived_key = archive + "/keys/wolfi-signing.rsa.pub"

def check_signature(path, arch, what):
    """an apk index is exactly TWO gzip members (the signature stream, then the index stream), inflated within ONE cumulative limit; a third member is refused
    before it is inflated. The signature is checked against the ARCHIVED Wolfi key. Returns the two decompressed streams' (compressed, data) parts."""
    raw = open(path, "rb").read()
    parts, rest, budget = [], raw, INFLATE_CAP
    try:
        while rest:
            if len(parts) == 2:
                fail("the %s %s package index has more than two gzip members (refused before the rest is inflated)" % (what, arch))
            comp, data, rest = inflate(rest, "the %s %s package index" % (what, arch), budget)
            budget -= len(data)
            parts.append((comp, data))
        tf = tarfile.open(fileobj=io.BytesIO(parts[0][1])); m = tf.getmembers()[0]; sig = tf.extractfile(m).read()
        if len(parts) != 2:
            raise ValueError("an apk index is a signature stream and an index stream")
    except SystemExit:
        raise
    except Exception:
        fail("the %s %s package index is not a signed apk index (a signature stream, then the index stream); signature not verified" % (what, arch))
    mm = re.fullmatch(r"\.SIGN\.RSA(256|512)\.(.+)", m.name)
    if not mm:
        fail("the %s %s package index signature %s is not an RSA-256/512 signature; refused" % (what, arch, m.name))
    alg = "sha" + mm.group(1)
    sp, ip = "%s/index-%s.sig" % (stage, arch), "%s/index-%s.stream" % (stage, arch)
    os.makedirs(stage, exist_ok=True)
    open(sp, "wb").write(sig); open(ip, "wb").write(parts[1][0])
    r = subprocess.run(["/usr/bin/openssl", "dgst", "-" + alg, "-verify", archived_key, "-signature", sp, ip], capture_output=True)
    if r.returncode != 0:
        fail("the %s %s package index signature does not verify against the archived Wolfi key; refused" % (what, arch))
    return parts


def verify_integrity(path, what):
    """For a package that only a committed lock without checksums names (build/locks/melange.lock is name=version): the file must exist and be whole. Every gzip stream
    inflates (the gzip CRC catches truncation and bit flips), there are two or three streams, and the control section's datahash equals the sha256 of the data stream.
    (Authenticity against a checksum is the job of the apko locks; this is the integrity floor for what has none.)"""
    raw = open(path, "rb").read()
    parts, rest, budget = [], raw, INFLATE_CAP
    try:
        while rest:
            if len(parts) == 3:
                raise ValueError("more than three gzip streams")
            comp, data, rest = inflate(rest, what, budget)
            budget -= len(data)
            parts.append((comp, data))
        if len(parts) not in (2, 3):
            raise ValueError("an apk has two or three gzip streams")
        pk = tarfile.open(fileobj=io.BytesIO(parts[-2][1])).extractfile(".PKGINFO").read().decode()
        dhs = re.findall(r"^datahash = ([0-9a-f]{64})$", pk, re.M)
        if len(dhs) != 1 or hashlib.sha256(parts[-1][0]).hexdigest() != dhs[0]:
            raise ValueError("the data stream does not hash to the datahash of the control section")
    except SystemExit:
        raise
    except Exception as ex:
        fail("checksum mismatch: %s is damaged, truncated or not an apk (%s)%s" % (what, str(ex)[:120], HINT))


# ---- whatever the record says (even when there is none yet): every index file in the archive hashes to its own name, a pointer is a plain file or a link to such a file ----
for _a in ARCHS:
    _idir, _cur = "%s/%s/index" % (archive, _a), "%s/%s/APKINDEX.tar.gz" % (archive, _a)
    if os.path.islink(_idir) or os.path.islink("%s/%s" % (archive, _a)):
        fail("%s/%s (or its index/ directory) is a symlink; every directory on the way into the archive must be a real directory (symlink)" % (archive, _a))
    if os.path.isdir(_idir):
        for _f in sorted(os.listdir(_idir)):
            _mm = re.fullmatch(r"APKINDEX-([0-9a-f]{64})\.tar\.gz", _f)
            if _mm:
                _p = "%s/%s" % (_idir, _f)
                if os.path.islink(_p) or not os.path.isfile(_p) or hashlib.sha256(open(_p, "rb").read()).hexdigest() != _mm.group(1):
                    fail("the index file %s is a link, not a regular file, or does not hash to its own name (hash mismatch); restore it or delete it and run again" % _p)
    if os.path.islink(_cur):   # the pointer is a regular-file COPY of index/APKINDEX-<sha256>.tar.gz (REQ-REFRESH-001-AC13); a link is never followed
        fail("the archive's %s pointer %s is a symlink; it must be a regular-file copy of its index/APKINDEX-<sha256>.tar.gz (symlink)" % (_a, _cur))
    if os.path.isfile(_cur):
        check_signature(_cur, _a, "legacy archived")   # the pointer must be a SIGNED index, whatever the record says and before any early exit
_rec_path = repo + "/build/locks/archive-index.sha256"
ahead = False
ahead_info = []
if os.path.exists(_rec_path):
    _text = open(_rec_path, newline="").read()   # newline="" keeps a carriage return visible: the record is exactly what the job writes
    if not _text.endswith("\n") or "\r" in _text:
        fail("build/locks/archive-index.sha256 is malformed: it must be exactly two lines, each ending in a plain newline (no carriage return, no missing final newline)", 2)
    _lines = _text[:-1].split("\n")
    _rec = {}
    for _l in _lines:
        _mm = re.fullmatch(r"(x86_64|aarch64) sha256:([0-9a-f]{64})", _l)
        if not _mm or _mm.group(1) in _rec:
            fail("build/locks/archive-index.sha256 is malformed (line %r): exactly one 'x86_64 sha256:<hex>' and one 'aarch64 sha256:<hex>' line are expected" % _l, 2)
        _rec[_mm.group(1)] = _mm.group(2)
    if sorted(_rec) != sorted(ARCHS):
        fail("build/locks/archive-index.sha256 is malformed: it must have exactly the two lines x86_64 and aarch64", 2)
    for _a in ARCHS:
        _cur = "%s/%s/APKINDEX.tar.gz" % (archive, _a)
        _idir = "%s/%s/index" % (archive, _a)
        if os.path.islink(_idir) or os.path.islink("%s/%s" % (archive, _a)):
            fail("%s/%s (or its index/ directory) is a symlink; every directory on the way into the archive must be a real directory (symlink)" % (archive, _a))
        # the recorded index itself (what assembly uses) is checked whatever the pointer is: if the file is there it must be a regular file that hashes to its name;
        # if it is absent only a plain pointer that IS the recorded index (the legacy state before the first versioned file) is accepted
        _rf = "%s/APKINDEX-%s.tar.gz" % (_idir, _rec[_a])
        if os.path.lexists(_rf):
            if os.path.islink(_rf) or not os.path.isfile(_rf) or hashlib.sha256(open(_rf, "rb").read()).hexdigest() != _rec[_a]:
                fail("the recorded %s package index %s is a symlink, not a regular file, or does not hash to its name (hash mismatch); assembly would refuse it: a human must look" % (_a, _rf))
        elif os.path.islink(_cur) or not os.path.isfile(_cur) or hashlib.sha256(open(_cur, "rb").read()).hexdigest() != _rec[_a]:
            fail("the recorded %s package index %s is missing (missing index) and the pointer is not a plain file holding it (hash mismatch); restore it from backup: a human must look" % (_a, _rf))
        if os.path.isfile(_cur):
            _ps = hashlib.sha256(open(_cur, "rb").read()).hexdigest()
            if _ps != _rec[_a]:
                # a copy that is not the record is the normal "ahead" state while a refresh PR waits, but only when it is the copy of a stored version
                # (index/APKINDEX-<its sha256>.tar.gz exists; the directory scan above proved it hashes to its name)
                if os.path.isfile("%s/APKINDEX-%s.tar.gz" % (_idir, _ps)) and not os.path.islink("%s/APKINDEX-%s.tar.gz" % (_idir, _ps)):
                    ahead = True
                    ahead_info.append((_a, _ps, _rec[_a]))
                else:
                    fail("the archive's %s package index %s is a plain file that is not the one recorded in build/locks/archive-index.sha256 (hash mismatch); it was replaced or damaged: a human must look" % (_a, _cur))
        else:
            fail("the archive has no %s package index at %s although a record exists (missing index); restore it from index/ and run again" % (_a, _cur))
if ahead:
    print("note: the archive's package index is ahead of build/locks/archive-index.sha256 (a refresh PR is waiting, or one was closed unmerged); looking for an open refresh PR, otherwise reconciling")

# ---- every package any live lock names: verify the archived copy, or fetch the missing one ----
# The archive is checked on EVERY run, for production, FIPS and melange alike: a damaged or truncated file under an unchanged lock is found here
# (a human stop naming the file), not later at build time. The locks must agree with each other about the same package.
groups = {}
for lk in (live["production"], live["fips"], live_mel, live_host):
    for e in lk:
        groups.setdefault((e["name"], e["version"], e["architecture"]), []).append(e)
seen_file = {}
for (n_, v_, a_) in groups:
    f_ = ("%s/%s-%s.apk" % (a_, n_, v_)).lower()   # compared case-insensitively: some file systems would merge them
    if f_ in seen_file and seen_file[f_] != (n_, v_):
        fail("two different packages map to the same archive file %s (%s %s and %s %s); refusing" % (f_.split("/")[1], seen_file[f_][0], seen_file[f_][1], n_, v_))
    seen_file[f_] = (n_, v_)
fresh = {}
for k, es in groups.items():
    if len({ident(e) for e in es}) != 1:
        fail("the production, FIPS, melange and host-tools locks disagree about %s-%s (%s): the same package has different checksums; refusing" % k)
    fresh[k] = es[0]

# the archived inputs the COMMITTED locks (main's) require are checked too: damage to an old version that an upgrade PR leaves behind is found before any guard can return
committed = {}
for kind in ("production", "fips"):
    for e in base[kind]["doc"]["contents"]["packages"]:
        committed.setdefault((e["name"], e["version"], e["architecture"]), []).append(e)
# REQ-REFRESH-001-AC32, the first fill: an archive that holds nothing but the pinned key and a main with no pointer cannot already hold the versions the committed
# locks name, so the ones Wolfi still serves are fetched below and verified before they are archived. Any other state keeps the rule: a missing version stops the job.
def first_fill_state():
    """exactly the key and nothing else: a real archive directory holding one real keys directory that holds one regular file, the pinned key (any other entry,
    whatever its type, a symlinked archive or keys directory, or a listing that cannot be read is not the first-fill state)"""
    if os.path.lexists(repo + "/build/archive.json"):
        return False
    try:
        if os.path.islink(archive) or not os.path.isdir(archive) or os.listdir(archive) != ["keys"]:
            return False
        kd = archive + "/keys"
        if os.path.islink(kd) or not os.path.isdir(kd) or os.listdir(kd) != ["wolfi-signing.rsa.pub"]:
            return False
        return (os.lstat(archived_key).st_mode & 0o170000) == 0o100000
    except OSError:
        return False


FIRST_FILL = first_fill_state()
ff_locked = {}   # (name, version, arch) -> the committed lock entry (checksums): verified like any package
ff_mel = []      # (name, version, arch) named only by the committed melange.lock (name=version): verified against the signed live index
ff_host = []     # the same for the committed host-tools.lock (REQ-REFRESH-001-AC35, AC36)
for k, es in sorted(committed.items()):
    if len({ident(e) for e in es}) != 1:
        fail("the committed production and FIPS locks disagree about %s-%s (%s): the same package has different checksums; refusing" % k)
    if k in fresh:
        if ident(fresh[k]) != ident(es[0]):
            fail("the committed lock and the live resolution disagree about %s-%s (%s): the same version has different checksums; refusing" % k)
        continue   # also checked below, from the live entry
    dest = "%s/%s/%s-%s.apk" % (archive, k[2], k[0], k[1])
    if not os.path.exists(dest) and FIRST_FILL:
        if not NAME_RE.fullmatch(k[0]) or not VERSION_RE.fullmatch(k[1]) or ".." in k[0] or ".." in k[1] or k[2] not in ARCHS:
            fail("refused: invalid package name, version or architecture %r in the committed lock" % (k,), 2)
        ff_locked[k] = es[0]
        continue
    if not os.path.exists(dest):
        fail("the committed lock names %s-%s.apk (%s), which the archive does not hold; an older version the archive must keep (restore it from backup): a human must look" % k)
    HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
    verify(dest, es[0])
    HINT = ""
# the committed melange.lock and host-tools.lock (name=version, no checksums) name archived packages too: while an upgrade PR waits, the OLD versions they name are still what main builds from
for _lockname, _old, _ff in (("melange.lock", old_mel, ff_mel), ("host-tools.lock", old_host, ff_host)):
  for _l in _old:
    _n, _, _v = _l.partition("=")
    for _a in ARCHS:
        if (_n, _v, _a) in committed or (_n, _v, _a) in fresh:
            continue   # checked against its lock checksums
        dest = "%s/%s/%s-%s.apk" % (archive, _a, _n, _v)
        if not os.path.exists(dest) and FIRST_FILL:
            if not NAME_RE.fullmatch(_n) or not VERSION_RE.fullmatch(_v) or ".." in _n or ".." in _v:
                fail("refused: invalid package name or version %r in the committed %s" % (_l, _lockname), 2)
            _ff.append((_n, _v, _a))
            continue
        if not os.path.exists(dest):
            fail("the committed %s names %s-%s.apk (%s), which the archive does not hold; an older version the archive must keep (restore it from backup): a human must look" % (_lockname, _n, _v, _a))
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify_integrity(dest, "%s-%s.apk (%s)" % (_n, _v, _a))
        HINT = ""
# the archived files are checked on EVERY run, also while a refresh PR waits (REQ-REFRESH-001-AC17): a damaged file stops the job, whatever else is going on
for (name, ver, arch), e in sorted(fresh.items()):
    dest = "%s/%s/%s-%s.apk" % (archive, arch, name, ver)
    if os.path.exists(dest):
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify(dest, e)
        HINT = ""
# REQ-REFRESH-001-AC33 (rule 12: Go is kept in the archive): the Go tarballs that the committed recipes pin. A pin is the go.dev file name and its sha256; the recipes must agree.
GO_FILE = re.compile(r"go[0-9]+(?:\.[0-9]+){1,2}\.linux-(?:amd64|arm64)\.tar\.gz")
GO_URL = "https://go.dev/dl/"


def go_pins():
    """{file: sha256} of the Go tarballs pinned by build/melange.yaml and build/melange-fips.yaml; every fetch step must be a go.dev/dl uri with a 64-hex pin, and the two
    recipes may not pin one file with two checksums (a pin that is missing, malformed or in conflict stops the job)"""
    pins, seen_in = {}, {}
    for rf in ("melange.yaml", "melange-fips.yaml"):
        try:
            doc = yaml.safe_load(open("%s/build/%s" % (repo, rf)))
            steps = [st for st in (doc.get("pipeline") or []) if isinstance(st, dict) and st.get("uses") == "fetch"]
        except Exception as e_:
            fail("build/%s cannot be read for its Go pins: %s" % (rf, e_), 2)
        for st in steps:
            w_ = st.get("with") if isinstance(st.get("with"), dict) else {}
            uri, sha = str(w_.get("uri", "")), w_.get("expected-sha256")
            if not uri.startswith(GO_URL) or not GO_FILE.fullmatch(uri[len(GO_URL):]):
                fail("build/%s: a fetch step names %r, which is not %s followed by a Go tarball file name; refusing" % (rf, uri, GO_URL), 2)
            f_ = uri[len(GO_URL):]
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
                fail("build/%s: the Go fetch of %s has no valid expected-sha256 pin (64 lower-case hex); refusing" % (rf, f_), 2)
            if f_ in pins and pins[f_] != sha:
                fail("build/%s and build/%s pin %s with two different sha256 values; refusing" % (seen_in[f_], rf, f_), 1)
            pins[f_], seen_in[f_] = sha, rf
    return pins


def sha256_file(path):
    h_ = hashlib.sha256()
    with open(path, "rb") as fh_:
        for chunk in iter(lambda: fh_.read(1 << 20), b""):
            h_.update(chunk)
    return h_.hexdigest()


go_pin = go_pins()
go_dir = archive + "/go"
if os.path.lexists(go_dir) and (os.path.islink(go_dir) or not os.path.isdir(go_dir)):
    fail("%s is a symlink or not a directory; the archive's Go directory must be a real directory (nothing was written)" % go_dir, 1)
go_missing = []
for f_, sha_ in sorted(go_pin.items()):
    dest_ = "%s/%s" % (go_dir, f_)
    if os.path.lexists(dest_):
        if os.path.islink(dest_) or not os.path.isfile(dest_) or sha256_file(dest_) != sha_:
            fail("go/%s is in the archive but does not have the sha256 its recipe pins (%s): delete that file and run again, or find out how it got damaged" % (f_, sha_), 1)
    else:
        go_missing.append(f_)
# only now, before any download: a waiting refresh PR means "wait" (a missing package is fetched by that PR's own run), so a flaky download can never turn a wait into a red run
if ahead or go_missing or any(not os.path.exists("%s/%s/%s-%s.apk" % (archive, a_, n_, v_)) for (n_, v_, a_) in fresh):
    open_prs_guard("refresh")


def check_dirs():
    """every directory on the way into the archive is a real directory, nothing sits where a temporary name goes"""
    if os.path.islink(archive.rstrip("/") or archive):
        fail("%s is a symlink; the archive directory itself must be a real directory (nothing was written)" % archive)
    for arch in ARCHS:
        for comp in ("%s/%s" % (archive, arch), "%s/%s/index" % (archive, arch)):
            if os.path.islink(comp):
                fail("%s is a symlink; every directory on the way into the archive must be a real directory (nothing was written)" % comp)
        pointer_tmp = "%s/%s/APKINDEX.tar.gz.new" % (archive, arch)
        if os.path.isdir(pointer_tmp) and not os.path.islink(pointer_tmp):
            fail("%s is a directory where the pointer's temporary name goes; remove it (nothing was written)" % pointer_tmp)


def writable(path):
    """every file is written under a temp name in its directory and renamed over its final name: what matters is the DIRECTORY (write and search),
    not the file (a read-only file is simply replaced). A path that is itself a directory cannot be written."""
    if os.path.isdir(path) and not os.path.islink(path):
        return False
    d = os.path.dirname(path)
    while not os.path.exists(d):
        d = os.path.dirname(d)
    return os.path.isdir(d) and os.access(d, os.W_OK | os.X_OK)


def preflight(targets):
    check_dirs()
    for t_ in targets:
        if not writable(t_):
            fail("%s cannot be written: its directory %s is not writable; refusing before anything is changed (nothing was written)" % (t_, os.path.dirname(t_)))


# ---- download, verify, and only then keep ----
stage = tmp + "/dl"
keep = []
want_pk = []
for (name, ver, arch), e in sorted(list(fresh.items()) + list(ff_locked.items())):
    dest = "%s/%s/%s-%s.apk" % (archive, arch, name, ver)
    if os.path.exists(dest):
        HINT = " (%s is in the archive but is wrong or truncated: delete that file and run again, or find out how it got damaged)" % dest
        verify(dest, e)   # same name and version already archived: the bytes must be the same bytes
        HINT = ""
        continue
    part = "%s/%s/%s-%s.apk" % (stage, arch, name, ver)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):   # the shell fetches it (download lines of the ruled grammar), then runs this program again
        want_pk.append("%s/%s-%s.apk %s/%s-%s.apk" % (arch, name, ver, arch, name, ver))   # name, version and architecture passed the plain-set check above
        continue
    verify(part, e)
    keep.append((part, dest, name, ver, arch))
ff_mel_parts = []
for (name, ver, arch) in sorted(set(ff_mel) | set(ff_host)):
    part = "%s/%s/%s-%s.apk" % (stage, arch, name, ver)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):
        want_pk.append("%s/%s-%s.apk %s/%s-%s.apk" % (arch, name, ver, arch, name, ver))
        continue
    verify_integrity(part, "%s-%s.apk (%s)" % (name, ver, arch))
    ff_mel_parts.append((part, "%s/%s/%s-%s.apk" % (archive, arch, name, ver), name, ver, arch))
if want_pk:
    open(tmp + "/want-packages", "w").write("".join(l + "\n" for l in want_pk))
    sys.exit(75)
keep_go, want_go = [], []
for f_ in go_missing:
    part = "%s/go/%s" % (stage, f_)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):
        want_go.append(f_)       # the file name passed GO_FILE above
        continue
    if sha256_file(part) != go_pin[f_]:
        fail("checksum mismatch: %s fetched from go.dev does not have the sha256 its recipe pins (%s); nothing was stored" % (f_, go_pin[f_]), 1)
    keep_go.append((part, "%s/%s" % (go_dir, f_), f_))
if want_go:
    open(tmp + "/want-go", "w").write("".join(f + "\n" for f in want_go))
    sys.exit(75)


def place(src, dest):
    """copy to an exclusively created temp name (unpredictable, in the destination directory), fsync, then rename: nothing ever appears under
    a final name half-written, and a planted symlink at the temp name is never followed"""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    t = "%s.tmp-%s" % (dest, secrets.token_hex(8))
    with open(src, "rb") as s_, open(t, "xb") as d_:   # "x" = O_CREAT|O_EXCL
        shutil.copyfileobj(s_, d_)
        d_.flush()
        os.fsync(d_.fileno())
    os.replace(t, dest)


def write_atomic(path, text):
    """the same for a repository file (O_EXCL temp name, fsync, rename)"""
    t = "%s.tmp-%s" % (path, secrets.token_hex(8))
    with open(t, "xb") as d_:
        shutil.copyfileobj(io.BytesIO(text.encode()), d_)
        d_.flush()
        os.fsync(d_.fileno())
    os.replace(t, path)


# ---- the new locks ----
changed = []
notes = []
for kind in ("production", "fips"):
    doc = base[kind]["doc"]
    old_pk = doc["contents"]["packages"]
    new_pk = []
    for e in live[kind]:
        e = dict(e); e["url"] = local_url(e); new_pk.append(e)
    if sorted(map(ident, old_pk)) != sorted(map(ident, new_pk)):
        doc["contents"]["packages"] = new_pk
        changed.append(base[kind]["path"])
        newset = {(e["name"], e["version"]) for e in new_pk}
        for e in old_pk:
            if (e["name"], e["version"]) not in newset and e["architecture"] == "x86_64":
                notes.append("%s %s is no longer in live Wolfi's resolution (%s lock); the archived copy is kept" % (e["name"], e["version"], kind))
mel_names = {e["name"]: e["version"] for e in live_mel if e["architecture"] == "x86_64"}
new_mel = sorted("%s=%s" % p for p in mel_names.items())
mel_path = repo + "/build/locks/melange.lock"
host_names = {e["name"]: e["version"] for e in live_host if e["architecture"] == "x86_64"}
new_host = sorted("%s=%s" % p for p in host_names.items())
host_path = repo + "/build/locks/host-tools.lock"
if sorted(old_host) != new_host:
    changed.append(host_path)
    for n, v in sorted(dict(l.split("=", 1) for l in old_host).items()):
        if host_names.get(n) != v:
            notes.append("%s %s is no longer in live Wolfi's resolution (host tools); the archived copy is kept" % (n, v))
recipes = {}
if sorted(old_mel) != new_mel:
    changed.append(mel_path)
    old_names = dict(l.split("=", 1) for l in old_mel)
    for n, v in sorted(old_names.items()):
        if mel_names.get(n) != v:
            notes.append("%s %s is no longer in live Wolfi's resolution (melange build tools); the archived copy is kept" % (n, v))
# the recipes are regenerated and compared on EVERY run, whether or not the lock changed: a run interrupted between the lock write and the recipe writes is
# repaired by the next one (the lock is already current, the recipes are not)
# the recipes are GENERATED from the template and the two data files (the melange lock and the FIPS module file): the job edits only the lock, then asks the
# generator what the recipes become. The template and its pin are never touched by an automated change.
gen_dir = tmp + "/gen"
os.makedirs(gen_dir, exist_ok=True)
open(tmp + "/melange.lock.new", "w").write("".join(l + "\n" for l in new_mel))
r_ = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/gen-recipes.py", "--template", repo + "/build/melange.yaml.tmpl", "--baselayout-template", repo + "/build/melange-baselayout.yaml.tmpl", "--melange-lock", tmp + "/melange.lock.new",
                     "--fips-module", repo + "/build/locks/fips-module.txt", "--emit", gen_dir], capture_output=True, text=True)
if r_.returncode != 0:
    fail("the recipe generator refused (%s): %s" % (r_.returncode, r_.stderr.strip()[:300]), 1)
for rf in ("melange.yaml", "melange-fips.yaml", "melange-baselayout.yaml"):
    path = "%s/build/%s" % (repo, rf)
    out = open("%s/%s" % (gen_dir, rf)).read()
    if out != open(path).read():
        recipes[path] = out
        changed.append(path)

for n in notes:
    print("note: " + n)
if go_missing:
    notes.append("the archive gains the Go toolchain tarball(s) the recipes pin: %s" % ", ".join(go_missing))
    _ptr = repo + "/build/archive.json"
    if os.path.exists(_ptr):
        if _ptr not in changed:
            changed.append(_ptr)      # the pointer is rewritten by open-pr once the archive is stored; the pull request exists because the archive gained files
    elif not changed:
        fail("the archive gains Go tarballs but there is no pointer and nothing else changes, so no pull request could carry it; a human must look", 1)
record_path = repo + "/build/locks/archive-index.sha256"
if not changed and os.path.exists(record_path) and not ahead:
    if keep:
        preflight([dest for _, dest, *_ in keep])
        open_prs_guard("refresh")
    for part, dest, *_ in keep:   # archived packages that were missing are put back (the archive is not in git: there is nothing to commit)
        place(part, dest)
    print("nothing changed against live Wolfi; no commit, no pull request" + ("; %d missing archived package(s) were fetched again" % len(keep) if keep else ""))
    open(tmp + "/changed", "w").write("")
    sys.exit(0)

open_prs_guard("refresh")   # something will change: a waiting refresh PR means "wait", decided BEFORE the live index is downloaded and checked

# the archive's package index is the ORIGINAL Wolfi-signed index (apko reads it from the archive without re-signing). It is kept
# IMMUTABLE and VERSIONED by its sha256 (index/APKINDEX-<sha256>.tar.gz) and never overwritten; APKINDEX.tar.gz is a regular-file COPY (never a symlink) of
# the newest one, and the digests are recorded in build/locks/archive-index.sha256. Each index must verify against the ARCHIVED key.
def verify_index(path, arch):
    parts = check_signature(path, arch, "live")
    # the signed index must back the locks: every locked package (name, version, Q1 checksum) of this architecture must be listed in it
    try:
        text = tarfile.open(fileobj=io.BytesIO(parts[1][1])).extractfile("APKINDEX").read().decode()
    except Exception:
        fail("the live %s package index has no readable APKINDEX member" % arch)
    listed = set()
    for st in text.split("\n\n"):
        f = dict(l.split(":", 1) for l in st.split("\n") if len(l) > 2 and l[1] == ":")
        if "P" in f and "V" in f and "C" in f:
            listed.add((f["P"], f["V"], f["C"]))
    index_listed[arch] = listed
    for (_n, _v, _a), _e in sorted(ff_locked.items()):   # a committed version fetched by the first fill is backed by the signed index like every locked package
        if _a == arch and (_n, _v, _e["checksum"]) not in listed:
            fail("the signed %s package index does not list the committed package %s-%s (%s); it cannot be checked against the index, a human must look" % (arch, _n, _v, _e["checksum"]))
    for lockpk in (live["production"], live["fips"], live_mel, live_host):
        for e in lockpk:
            if e["architecture"] == arch and (e["name"], e["version"], e["checksum"]) not in listed:
                fail("the signed %s package index does not list the locked package %s-%s (%s); the lock is not backed by the index, refused" % (arch, e["name"], e["version"], e["checksum"]))


index_parts = {}
index_listed = {}
want_ix = []
for arch in ARCHS:
    part = "%s/index/%s/APKINDEX.tar.gz" % (stage, arch)
    os.makedirs(os.path.dirname(part), exist_ok=True)
    if not os.path.exists(part):
        want_ix.append("%s/APKINDEX.tar.gz index/%s/APKINDEX.tar.gz" % (arch, arch))
        continue
    verify_index(part, arch)
    index_parts[arch] = (part, hashlib.sha256(open(part, "rb").read()).hexdigest())
if want_ix:
    open(tmp + "/want-index", "w").write("".join(l + "\n" for l in want_ix))
    sys.exit(75)
# the first fill of a version only the committed melange.lock names (it has no checksums): the package's identity checksum (Q1 + sha1 of its control section) must be
# the one the SIGNED live index lists for that name, version and architecture (the signature was checked against the archived key above)
for part, dest, name, ver, arch in ff_mel_parts:
    wants = {c_ for (p_, v_, c_) in index_listed[arch] if p_ == name and v_ == ver}
    if not wants:
        fail("the signed %s package index has no entry for %s-%s, which only a committed melange.lock or host-tools.lock names; it cannot be checked, a human must look" % (arch, name, ver))
    raw_ = open(part, "rb").read(); parts_, rest_, budget_ = [], raw_, INFLATE_CAP
    while rest_:
        comp_, data_, rest_ = inflate(rest_, "%s-%s.apk" % (name, ver), budget_)
        budget_ -= len(data_)
        parts_.append((comp_, data_))
    if "Q1" + b64(hashlib.sha1(parts_[-2][0]).digest()) not in wants:
        fail("checksum mismatch: %s-%s.apk (%s) does not have the package checksum the signed live index lists for it" % (name, ver, arch))
    keep.append((part, dest, name, ver, arch))
# an existing file under a digest name is trusted only if it hashes to that name (a garbage or truncated file from an earlier run fails closed)
for arch in ARCHS:
    vdir, cur = "%s/%s/index" % (archive, arch), "%s/%s/APKINDEX.tar.gz" % (archive, arch)
    cands = ["%s/APKINDEX-%s.tar.gz" % (vdir, index_parts[arch][1])]
    if os.path.islink(cur):   # defence in depth (the every-run check refuses it first): a pointer is never a link
        fail("the previous pointer %s is a symlink; it must be a regular-file copy (symlink); refusing, nothing changed" % cur)
    if os.path.exists(cur):
        check_signature(cur, arch, "legacy archived")   # a plain pointer is kept under its own digest only if it is a signed index (the archived Wolfi key)
        cands.append("%s/APKINDEX-%s.tar.gz" % (vdir, hashlib.sha256(open(cur, "rb").read()).hexdigest()))
    for c in cands:
        if os.path.lexists(c):
            named = os.path.basename(c)[len("APKINDEX-"):-len(".tar.gz")]
            if os.path.islink(c) or not os.path.isfile(c) or hashlib.sha256(open(c, "rb").read()).hexdigest() != named:
                fail("the existing index file %s does not hash to its name (garbage, truncated or replaced); refusing, nothing changed" % c)
record_text = "".join("%s sha256:%s\n" % (a, index_parts[a][1]) for a in ARCHS)
if not os.path.exists(record_path) or open(record_path).read() != record_text:
    changed.append(record_path)

# before ANY change: directories, temp names and writability (the same checks the re-fetch path ran)
targets = list(changed) + [dest for _, dest, *_ in keep] + [dest for _, dest, _f in keep_go]
for arch in ARCHS:
    targets += ["%s/%s/APKINDEX.tar.gz" % (archive, arch), "%s/%s/index/APKINDEX-%s.tar.gz" % (archive, arch, index_parts[arch][1])]
preflight(targets)

# everything verified: now the archive and the repository change (each file is written under a temp name and renamed)
for part, dest, *_ in keep:
    place(part, dest)
for part, dest, _f in keep_go:
    place(part, dest)
for arch in ARCHS:
    part, sha = index_parts[arch]
    vdir, cur = "%s/%s/index" % (archive, arch), "%s/%s/APKINDEX.tar.gz" % (archive, arch)
    os.makedirs(vdir, exist_ok=True)
    if os.path.exists(cur):   # the old pointer copy: keep it under its own digest first (a no-op when that version is already stored)
        keepold = "%s/APKINDEX-%s.tar.gz" % (vdir, hashlib.sha256(open(cur, "rb").read()).hexdigest())
        if not os.path.exists(keepold):
            place(cur, keepold)
    dest = "%s/APKINDEX-%s.tar.gz" % (vdir, sha)
    if not os.path.exists(dest):   # absent: write it atomically (a temp file in the same directory, then rename); an existing one was hashed above
        place(part, dest)
    place(dest, cur)   # the pointer is a regular-file COPY of the versioned index (same sha256), written atomically; never a symlink
if record_path in changed:
    write_atomic(record_path, record_text)
for kind in ("production", "fips"):
    if base[kind]["path"] in changed:
        write_atomic(base[kind]["path"], json.dumps(base[kind]["doc"], indent=2) + "\n")
if mel_path in changed:
    write_atomic(mel_path, "".join(l + "\n" for l in new_mel))
if host_path in changed:
    write_atomic(host_path, "".join(l + "\n" for l in new_host))
for path, out in recipes.items():
    write_atomic(path, out)

lines = ["- archived go/%s (the Go toolchain a recipe pins, checked against that pin)" % f for _, _, f in keep_go] + ["- archived %s-%s.apk (%s)" % (n, v, a) for _, _, n, v, a in keep] + ["- stored the live signed package index (%s) as index/APKINDEX-%s.tar.gz" % (a, index_parts[a][1]) for a in ARCHS]
supersedes = []
if ahead:   # the reconcile PR says why the index record jumps: it supersedes a refresh PR that was closed unmerged
    prev = None
    r_ = subprocess.run(["/usr/bin/gh", "pr", "list", "--state", "closed", "--limit", "100", "--json", "number,headRefName,mergedAt,isCrossRepository,author"], cwd=repo, capture_output=True, text=True)
    if r_.returncode == 0:
        try:
            cands = [p_ for p_ in json.loads(r_.stdout) if not p_.get("isCrossRepository") and not p_.get("mergedAt")
                     and str(p_.get("headRefName", "")).startswith("refresh/") and not str(p_.get("headRefName", "")).startswith("refresh/fips-module-")
                     and (not PR_AUTHOR or norm_login((p_.get("author") or {}).get("login") or "") == norm_login(PR_AUTHOR))]
            if cands:
                prev = max(cands, key=lambda p_: int(p_["number"]))
                prev = {"number": int(prev["number"]), "headRefName": str(prev["headRefName"])}
        except (ValueError, TypeError, KeyError, AttributeError):   # any reply shape we do not understand: fall back to the generic sentence
            prev = None
    digs = "; ".join("%s: the record named sha256:%s, the archive held sha256:%s" % (a_, rec_, arch_) for a_, arch_, rec_ in ahead_info)
    if prev:
        supersedes = ["No open refresh pull request was found. The previous refresh pull request #%d (%s) was closed unmerged; this one supersedes it, which is why the index record jumps (%s)." % (prev["number"], prev["headRefName"], digs), ""]
    else:
        supersedes = ["No open refresh pull request was found. A previous refresh pull request was closed unmerged (its number could not be determined); this one supersedes it, which is why the index record jumps (%s)." % digs, ""]
body = "\n".join(["The daily input refresh found changes against live Wolfi.", ""] + supersedes + lines + [""] + ["- " + n for n in notes] + [""] +
                 ["Files: " + ", ".join(os.path.relpath(p, repo) for p in changed), "",
                  "This pull request was only opened, not merged. It goes through all the normal checks and the rebuild-from-archive test; there is no shortcut."])
sig = hashlib.sha256("".join(open(p).read() for p in sorted(changed)).encode()).hexdigest()[:8]
open(tmp + "/changed", "w").write(("\n".join(os.path.relpath(p, repo) for p in changed) + "\n") if changed else "")   # nothing to commit: no PR
open(tmp + "/sig", "w").write(sig)
open(tmp + "/body", "w").write(body)
PY
  }
  for _pass in 1 2 3 4; do
    _rc=0; refresh_py || _rc=$?
    [ "$_rc" = 75 ] || break
    if [ -s "$tmp/want-packages" ]; then
      while read -r p f; do
        echo "refresh-inputs.sh: fetching $p"
        /usr/bin/curl -q -fsSL -g --max-filesize 536870912 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download a package from live Wolfi" 1
      done <"$tmp/want-packages"
      /bin/rm -f "$tmp/want-packages"
    elif [ -s "$tmp/want-go" ]; then
      while read -r f; do
        echo "refresh-inputs.sh: fetching the Go toolchain $f"
        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 900 --proto =https --tlsv1.2 -o "$tmp/dl/go/$f" "https://go.dev/dl/$f" || die "could not download a Go toolchain from go.dev" 1
      done <"$tmp/want-go"
      /bin/rm -f "$tmp/want-go"
    elif [ -s "$tmp/want-index" ]; then
      while read -r p f; do
        /usr/bin/curl -q -fsSL -g --max-filesize 268435456 --max-time 600 --proto =https --tlsv1.2 -o "$tmp/dl/$f" "https://packages.wolfi.dev/os/$p" || die "could not download the live package index" 1
      done <"$tmp/want-index"
      /bin/rm -f "$tmp/want-index"
    else
      die "the refresh program asked for downloads and named none" 1
    fi
  done
  [ "$_rc" = 0 ] || exit "$_rc"
  [ -s "$tmp/changed" ] || exit 0
  branch="refresh/$(<"$tmp/sig")"
  paths=(); while IFS= read -r l; do paths+=("$l"); done <"$tmp/changed"
  open_pr "$branch" "Refresh the image inputs against live Wolfi (daily job)" "$(<"$tmp/body")" "${paths[@]}"
  ;;

fips-module)
  [ -n "$goroot" ] || die "--go-root is required"
  # The refresh and this check edit the same recipe files in one working tree and their pull requests are opened only after the archive is stored: a
  # second plan would be built on the first one's uncommitted edits. With a plan already staged this check stages nothing and runs again tomorrow.
  # REQ-REFRESH-001-AC12 (rc-3 astra F4): the strict reading of the certified-module file and of build/locks/fips-module.txt below runs in this case too;
  # the staged case then only says pending / nothing pending and stages nothing.
  staged=0
  if [ -n "$plan_dir" ] && [ -d "$plan_dir" ] && ! dir_empty "$plan_dir"; then
    echo "fips-module: a pull request is already staged in $plan_dir; this check stages nothing now and runs again tomorrow (each pull request is built from the committed files alone)"
    staged=1
  fi
  modfile=$repo/build/locks/fips-module.txt
  [ -f "$modfile" ] || die "missing build/locks/fips-module.txt in $repo"
  [ "$staged" = 1 ] || [ -f "$repo/build/melange.yaml.tmpl" ] || die "missing build/melange.yaml.tmpl in $repo"
  /usr/bin/python3 -I -B - "$goroot" "$modfile" "$tmp" "$repo" "$pr_author" "$(cd "$HERE" && pwd)" "$staged" <<'PY' || exit $?
import io, json, os, re, secrets, shutil, subprocess, sys
goroot, modfile, tmp, repo, PR_AUTHOR, BINDIR, STAGED = sys.argv[1:8]
STAGED = STAGED == "1"   # a plan is already staged: the checks below run, then the answer is only pending / nothing pending
cert = os.path.join(goroot, "lib", "fips140", "certified.txt")


def fail(msg, code=2): print("refresh-inputs.sh: " + msg, file=sys.stderr); sys.exit(code)


if not os.path.isfile(cert):
    fail("%s is missing; cannot tell which Go Cryptographic Module is certified" % cert)
NUM = r"(0|[1-9][0-9]*)"   # no leading zeros: v1.0.00 is not another spelling of v1.0.0
PAT = re.compile(r"^v%s\.%s\.%s-[0-9a-f]{8}$" % (NUM, NUM, NUM))
mods = []
try:
    cert_text = open(cert, "rb").read().decode("utf-8")
except (OSError, UnicodeDecodeError) as e:
    fail("%s is not readable as UTF-8 text (%s); cannot tell which Go Cryptographic Module is certified" % (cert, e))
for ln in cert_text.splitlines():
    ln = ln.strip()
    if not ln or ln.startswith("#"):
        continue
    m = PAT.match(ln)
    if not m:
        fail("%s: unreadable module value %r (expected vMAJOR.MINOR.PATCH-<8 hex>)" % (cert, ln))
    mods.append((tuple(int(x) for x in m.groups()), ln))
if not mods:
    fail("%s is empty; cannot tell which Go Cryptographic Module is certified" % cert)
if len(mods) != 1:
    fail("%s must hold exactly one module line (found %d); which one counts is a human decision" % (cert, len(mods)))
newest = mods[0][1]
# the module the FIPS build uses now is DATA (build/locks/fips-module.txt), read with the same closed grammar the certified file is
try:
    raw_cur = open(modfile, "rb").read().decode("ascii")
except (OSError, UnicodeDecodeError):
    fail("%s is not readable as plain ASCII text" % modfile)
if not raw_cur.endswith("\n") or "\r" in raw_cur or raw_cur.count("\n") != 1 or not PAT.match(raw_cur[:-1]):
    fail("%s must hold exactly one line vMAJOR.MINOR.PATCH-<8 hex> and a plain newline; refusing" % modfile)
cur = raw_cur[:-1]
cm = PAT.match(cur)
if tuple(int(x) for x in cm.groups()) > max(mods)[0]:
    fail("%s names %s, older than the %s the FIPS build uses; refusing to move backward" % (cert, newest, cur))
if cm.groups() == PAT.match(newest).groups() and cur != newest:
    fail("%s names %s, the SAME version as the %s the FIPS build uses with a different hash; refusing, a human must look" % (cert, newest, cur))
if STAGED:
    if cur != newest:
        print("fips-module: pending: Go's certified module file names %s, the FIPS build uses %s; its pull request is staged on the next run without a staged refresh" % (newest, cur))
    else:
        print("fips-module: nothing pending: the certified module is the one the FIPS build uses (%s)" % cur)
    sys.exit(0)
if cur == newest:
    print("up to date: Go's certified module %s is the one the FIPS build already uses; no pull request" % cur)
    open(tmp + "/new", "w").write("")
    sys.exit(0)
def fail_gh(msg): print("refresh-inputs.sh: " + msg, file=sys.stderr); sys.exit(1)
def norm_login(x):
    """lower case (GitHub logins are not case-sensitive), then strip the decorations until none is left: app/bot, bot[bot], app/bot[bot]"""
    y = x.lower()
    while True:
        z = y[4:] if y.startswith("app/") else (y[:-5] if y.endswith("[bot]") else y)
        if z == y:
            return y
        y = z


def open_prs_guard(kind):
    """Looked up before the FIRST archive or repository change. The open pull requests are listed once; if the list cannot be read the job fails
    (an unknown state is not "no PR"). If any pull request of this kind (input refresh, or FIPS module) is open, whether it is this very change
    or an earlier one, nothing more is done: no change, no push, no second PR. The stall is visible: the log and the job summary name it."""
    r = subprocess.run(["/usr/bin/gh", "pr", "list", "--state", "open", "--limit", "1000", "--json", "number,headRefName,isCrossRepository,author"],
                       cwd=repo, capture_output=True, text=True)
    if r.returncode != 0:
        fail_gh("cannot list the open pull requests (gh pr list failed); changing nothing, pushing nothing, opening nothing")
    pfx = "refresh/"   # AC29 names no kind: a package refresh and a certified-module pull request stop each other
    try:
        prs = json.loads(r.stdout)
    except ValueError:
        fail("cannot read the open pull request list (not JSON); changing nothing")
    for pr in prs:
        # only OUR pull requests count: from this repository (not a fork) and, when the job's identity is given, authored by it
        who = ((pr.get("author") or {}).get("login") or "")
        if pr.get("isCrossRepository") or (PR_AUTHOR and norm_login(who) != norm_login(PR_AUTHOR)):
            continue
        num, head = pr.get("number"), pr.get("headRefName", "")
        if head.startswith(pfx):
            msg = "an earlier pull request (#%s, %s) of this kind is still open (already open); changing nothing, pushing nothing and opening no second one (it is merged or closed first)" % (num, head)
            print(msg)
            if os.environ.get("GITHUB_STEP_SUMMARY"):
                open(os.environ["GITHUB_STEP_SUMMARY"], "a").write("- %s: %s\n" % (kind, msg))
            sys.exit(0)

open_prs_guard("fips-module")   # before any file is changed
# only the DATA file changes; the recipes are what the generator makes of it (the template and its pin are never touched by an automated change)
gen_dir = tmp + "/gen"
os.makedirs(gen_dir, exist_ok=True)
open(tmp + "/fips-module.new", "w").write(newest + "\n")
r_ = subprocess.run(["/usr/bin/python3", "-I", "-B", BINDIR + "/gen-recipes.py", "--template", repo + "/build/melange.yaml.tmpl", "--baselayout-template", repo + "/build/melange-baselayout.yaml.tmpl", "--melange-lock", repo + "/build/locks/melange.lock",
                     "--fips-module", tmp + "/fips-module.new", "--emit", gen_dir], capture_output=True, text=True)
if r_.returncode != 0:
    fail("the recipe generator refused (%s): %s" % (r_.returncode, r_.stderr.strip()[:300]), 1)
writes = []
for rf in ("melange.yaml", "melange-fips.yaml", "melange-baselayout.yaml"):
    path = "%s/build/%s" % (repo, rf)
    out = open("%s/%s" % (gen_dir, rf)).read()
    if out != open(path).read():
        writes.append((path, out))
writes.append((modfile, newest + "\n"))   # the DATA file last: a run killed half-way leaves the old data, so the next run does the whole job again
for path, _ in writes:
    pdir = os.path.dirname(path)
    if os.path.isdir(path) or not os.access(pdir, os.W_OK | os.X_OK):   # each file is replaced by a rename: the DIRECTORY must take it
        fail("%s cannot be written: its directory %s is not writable; changing nothing" % (path, pdir), 1)
for path, content in writes:
    t_ = "%s.tmp-%s" % (path, secrets.token_hex(8))
    with open(t_, "xb") as d_:   # O_EXCL temp name, fsync, rename: a kill leaves the old file whole
        shutil.copyfileobj(io.BytesIO(content.encode()), d_)
        d_.flush()
        os.fsync(d_.fileno())
    os.replace(t_, path)
open(tmp + "/paths", "w").write("".join(os.path.relpath(p_, repo) + "\n" for p_, _ in writes))
open(tmp + "/new", "w").write(newest + "\n" + cur + "\n")
print("a newer certified module: %s (the FIPS build uses %s)" % (newest, cur))
PY
  [ -s "$tmp/new" ] || exit 0
  { IFS= read -r newest; IFS= read -r cur; } <"$tmp/new"
  paths=(); while IFS= read -r l; do paths+=("$l"); done <"$tmp/paths"
  open_pr "refresh/fips-module-$newest" "Move the FIPS build to the newer certified Go Cryptographic Module $newest" \
    "The daily check found $newest in Go's own certified-module file; the FIPS build used $cur. This pull request was only opened, not merged. It goes through all the normal checks and the rebuild-from-archive test; there is no shortcut. A new certificate number is a human fact that no tool can read from Go, so this pull request cannot pass the release checks until a person also changes these files: bin/check-artifacts.sh (the GOFIPS140 value it requires), bin/check-fips.sh (the certificate note), internal/buildinfo/buildinfo.go (the module it recognises and the certificate note), internal/buildinfo/buildinfo_test.go (the certificate it expects), .github/workflows/ci.yml (the GOFIPS140 value of the fips140-only job; a workflow file, so its pin rules and review apply) and docs/install.md (the certificate it names), bin/check-govulncheck.py (the GOFIPS140 value its recipe grammar requires and sets), and the public pages that name the module or certificate: SECURITY.md, RELEASING.md, docs/offline-install.md and docs/verify-images.md; the requirement text that names the certificate (requirements/requirements.yaml, REQ-FIPS-001) is an owner-ratified rule, so a change to its words goes to the owner. Search the tree for the current module and certificate number and review every hit." \
    "${paths[@]}"
  ;;

*) usage;;
esac
