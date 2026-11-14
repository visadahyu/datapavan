#!/usr/bin/env bash
# Brings several approved branches into one integration branch, so that one CI run checks them together
# before main is fast-forwarded to it (ADR 0043: main moves only to a commit whose CI passed). Each branch
# comes in with a merge commit of its own, signed like every commit, so its approved commits stay as they
# were reviewed. Nothing is pushed: the script says what to push and what to check.
#
#   [ASSISTED_BY="Claude (Anthropic)"] scripts/batch-merge.sh <integration branch> <branch>...
#
# ASSISTED_BY adds the "Assisted-by:" trailer (CONTRIBUTING.md) to the merge commits an assistant makes.
#
# The integration branch starts from origin/main as last fetched (run "git fetch origin" first) and must
# not exist yet. The branches are merged in the order given; a conflict stops the script with the merge
# aborted and the branches merged so far kept, so the conflicting branch can be rebased on main and
# approved again, or the order changed. Then:
#
#   1. push the integration branch, and wait for its CI run to finish;
#   2. read that run's result for its exact tip (gh run view <id> --json status,conclusion must say
#      "completed" and "success"), not a watcher's exit code;
#   3. fast-forward main to the tip: git push origin <tip>:main. The scope job sees that the commit passed
#      on a working branch and runs nothing twice.
#
# If the integration branch's run fails, main stays where it was: the failing branch is found from the run,
# fixed on its own branch, and the batch made again. The branches merged need no run of their own.
set -euo pipefail

[ $# -ge 2 ] || { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2; }
target=$1
shift

git diff --quiet && git diff --cached --quiet || { echo "the working tree has changes: commit or stash them first" >&2; exit 1; }
if git rev-parse -q --verify "refs/heads/$target" >/dev/null; then
    echo "the branch $target exists already: name a new one" >&2
    exit 1
fi
for branch in "$@"; do
    git rev-parse -q --verify "$branch^{commit}" >/dev/null || { echo "no branch or commit named $branch" >&2; exit 1; }
done
base=$(git rev-parse origin/main)
echo "== $target from origin/main at $(git log -1 --format='%h %s' "$base")"
git switch -q -c "$target" "$base"

merged=()
for branch in "$@"; do
    if [ -z "$(git rev-list "HEAD..$branch")" ]; then
        echo "   $branch: already in, nothing to merge"
        continue
    fi
    # The commit's time in UTC, like every commit here; signing and sign-off as the repository's settings and
    # rules ask.
    message=(-m "Bring $branch into $target")
    [ -z "${ASSISTED_BY:-}" ] || message+=(-m "Assisted-by: $ASSISTED_BY")
    if ! TZ=UTC git merge --no-ff --signoff "${message[@]}" "$branch" >/dev/null; then
        git merge --abort
        echo "!! $branch does not merge cleanly into $target after: ${merged[*]:-nothing}; the merge was aborted" >&2
        echo "   rebase $branch on main and have it approved again, or change the order" >&2
        exit 1
    fi
    merged+=("$branch")
    echo "   $branch: $(git rev-list --count "HEAD^1..$branch") commits, merged as $(git rev-parse --short HEAD)"
done
[ ${#merged[@]} -gt 0 ] || { echo "nothing to merge: every branch is in main already" >&2; exit 1; }
# Every commit that main would gain must be signed (the ruleset on main refuses the push otherwise): one
# with no signature or a bad one stops here; one this computer cannot judge (no key for it here) is named.
signatures=$(git log --format='%h %G?' "$base..HEAD")
unsigned=$(awk '$2 == "N" || $2 == "B" { print $1 }' <<<"$signatures")
[ -z "$unsigned" ] || { echo "!! commits with no signature or a bad one: $(echo $unsigned)" >&2; exit 1; }
unknown=$(awk '$2 != "G" && $2 != "N" && $2 != "B" { print $1 "(" $2 ")" }' <<<"$signatures")
[ -z "$unknown" ] || echo "   signatures this computer cannot check: $(echo $unknown); GitHub checks them on the push"
echo "== $target is ready at $(git rev-parse --short HEAD), with ${#merged[@]} branches: ${merged[*]}"
echo "   next: git push origin $target, then wait for its CI on $(git rev-parse HEAD) and read its conclusion,"
echo "   then git push origin $(git rev-parse HEAD):main"
