#!/usr/bin/env bash
# Local prune (REQ-REPO-001 AC22-AC24): drop stale worktree records and local branches whose upstream is gone and whose
# work is merged or closed. Dry run unless --apply. usage: local-prune.sh [--apply]
set -uo pipefail
apply=0
case "${1:-}" in
  "") ;;
  --apply) apply=1 ;;
  *) echo "usage: local-prune.sh [--apply]" >&2; exit 2 ;;
esac
# Only --apply may change anything: it refreshes the remote-tracking refs first. A dry run reads the remote itself.
if [ "$apply" = 1 ]; then
  git fetch --prune --quiet origin 2>/dev/null || true
  git worktree prune
else
  git worktree prune --dry-run -v | sed 's/^/would prune worktree: /'
  echo "dry-run: nothing changed (use --apply)"
fi
# What the remote has right now, read-only. If it cannot be read, or has nothing, no upstream can be called gone.
if ! heads=$(git ls-remote --heads origin 2>/dev/null) || [ -z "$heads" ]; then
  echo "remote heads unreadable: keeping every branch"
  exit 0
fi
remote_refs=$(printf '%s\n' "$heads" | awk '{print $2}')
main_sha=$(printf '%s\n' "$heads" | awk '$2=="refs/heads/main" {print $1}')
# branches checked out in a live (not prunable) worktree
checked=$(git worktree list --porcelain | awk 'BEGIN{RS="";FS="\n"} { if ($0 ~ /\nprunable/) next; for(i=1;i<=NF;i++) if ($i ~ /^branch refs\/heads\//) {sub("branch refs/heads/","",$i); print $i} }')
# ... and branches being rebased in any live worktree (HEAD is detached then)
while IFS= read -r wt; do
  gd=$(git -C "$wt" rev-parse --absolute-git-dir 2>/dev/null) || continue
  for f in "$gd/rebase-merge/head-name" "$gd/rebase-apply/head-name"; do
    [ -f "$f" ] && checked="$checked"$'\n'"$(sed 's#^refs/heads/##' "$f")"
  done
done < <(git worktree list --porcelain | sed -n 's/^worktree //p')
git for-each-ref --format='%(refname:short)' refs/heads | while read -r b; do
  remote=$(git config "branch.$b.remote" || true)
  merge=$(git config "branch.$b.merge" || true)
  if [ "$remote" != origin ] || [ -z "$merge" ] || printf '%s\n' "$remote_refs" | grep -Fxq -- "$merge"; then
    echo "kept $b: upstream present or none"; continue
  fi
  if printf '%s\n' "$checked" | grep -Fxq -- "$b"; then echo "kept $b: checked out"; continue; fi
  sha=$(git rev-parse "refs/heads/$b")
  reason=""
  if [ -n "$main_sha" ] && git merge-base --is-ancestor "$sha" "$main_sha" 2>/dev/null; then
    reason=merged-into-main
  elif out=$(gh pr list --head "$b" --state all --json state,headRefOid,isCrossRepository 2>/dev/null); then
    reason=$(printf '%s' "$out" | SHA="$sha" python3 -c '
import json,os,sys
ps=[p for p in json.load(sys.stdin) if not p.get("isCrossRepository")]
if any(p["state"]=="OPEN" for p in ps): print(""); sys.exit()
s=[p["state"] for p in ps if p.get("headRefOid")==os.environ["SHA"]]
print("pr-merged" if "MERGED" in s else ("pr-closed" if "CLOSED" in s else ""))' 2>/dev/null || true)
  fi
  [ -n "$reason" ] || { echo "kept $b: unmerged commits and no closed pull request"; continue; }
  if [ "$apply" = 1 ]; then
    git branch -D "$b" >/dev/null && echo "deleted branch $b $sha $reason"
  else
    echo "would delete branch $b $sha $reason"
  fi
done
