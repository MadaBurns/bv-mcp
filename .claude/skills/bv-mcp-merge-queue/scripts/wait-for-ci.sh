#!/usr/bin/env bash
# wait-for-ci.sh <pr-number> [--timeout-min N] [--interval SEC] [--no-wait]
#
# Waits for the CI that actually gates a bv-mcp PR, then prints one verdict.
#
# Why this exists: `build-and-test` is reported by BOTH ci.yml (the real suite) and
# ci-docs.yml (docs paths). On a PR that touches code and a .md file the docs one goes
# green minutes before the real one finishes, and `gh pr checks`, `mergeStateStatus` and
# `gh pr merge` all accept it. This script reads ci.yml's OWN run for the PR's full head
# SHA, so that green cannot be mistaken for the suite.
#
# Exit status:
#   0  READY      ci.yml's run succeeded (or the PR is docs-only), every required check-run
#                 completed green, and the PR head still contains main
#   1  FAILED     ci.yml's run or a required check-run did not succeed
#   2  usage, a prerequisite (gh, repo, PR lookup) failed, or the PR is not open
#   3  BEHIND     checks are green but main moved; run `gh pr update-branch` and wait again
#   4  TIMEOUT    still running when the time ran out (or --no-wait and not finished)
#
# It prints the head SHA it measured. Merge with that SHA so a later push cannot ride in:
#   gh pr merge <n> --merge --match-head-commit <sha>
#
# Limits: it reads GitHub's view at the moment it prints. `mergeStateStatus` is recomputed
# asynchronously after another merge, so re-run with --no-wait just before merging. It does
# not judge advisory checks; they are listed only when not green.

set -u

REQUIRED_CHECKS='build-and-test|Secret & PII scan|Dependency audit|File hygiene check'
CI_WORKFLOW='ci.yml'

usage() {
	sed -n '2,3p' "$0" | sed 's/^# \{0,1\}//' >&2
	exit 2
}

pr=''
timeout_min=30
interval=20
wait_for_run=1
while [ $# -gt 0 ]; do
	case "$1" in
		--timeout-min) [ $# -ge 2 ] || usage; timeout_min=$2; shift 2 ;;
		--interval) [ $# -ge 2 ] || usage; interval=$2; shift 2 ;;
		--no-wait) wait_for_run=0; shift ;;
		-h | --help) usage ;;
		-*) echo "unknown option: $1" >&2; usage ;;
		*) [ -z "$pr" ] || usage; pr=$1; shift ;;
	esac
done
case "$pr" in '' | *[!0-9]*) usage ;; esac
case "$timeout_min" in '' | *[!0-9]*) usage ;; esac
case "$interval" in '' | *[!0-9]*) usage ;; esac

command -v gh >/dev/null 2>&1 || { echo 'PREREQ: gh CLI not found' >&2; exit 2; }
repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null) || repo=''
[ -n "$repo" ] || { echo 'PREREQ: could not resolve the repository (run inside the checkout, gh authenticated)' >&2; exit 2; }

pr_field() { gh pr view "$pr" --repo "$repo" --json "$1" --jq "$2" 2>/dev/null; }

sha=$(pr_field headRefOid .headRefOid) || sha=''
case "$sha" in
	[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
	*) echo "PREREQ: could not read the head SHA of PR #$pr" >&2; exit 2 ;;
esac
base=$(pr_field baseRefName .baseRefName)
[ -n "$base" ] || { echo "PREREQ: could not read the base branch of PR #$pr" >&2; exit 2; }

# Same rule as ci.yml's paths-ignore: the suite is skipped only when EVERY file is docs.
code_files=$(pr_field files '[.files[].path | select((endswith(".md") or startswith("docs/") or . == "LICENSE") | not)] | length')
case "$code_files" in '' | *[!0-9]*) echo "PREREQ: could not list the files of PR #$pr" >&2; exit 2 ;; esac

echo "PR #$pr  repo=$repo  base=$base"
echo "head=$sha"
if [ "$code_files" -eq 0 ]; then
	echo "scope: docs-only (no $CI_WORKFLOW run is expected; ci-docs.yml reports build-and-test)"
else
	echo "scope: $code_files non-docs file(s), so $CI_WORKFLOW must run and pass"
fi

run_state() { gh run view "$1" --repo "$repo" --json status,conclusion --jq '"\(.status) \(.conclusion)"' 2>/dev/null; }
find_run() {
	gh run list --repo "$repo" --commit "$sha" --workflow "$CI_WORKFLOW" --limit 5 \
		--json databaseId,createdAt --jq 'sort_by(.createdAt) | last | .databaseId // empty' 2>/dev/null
}

deadline=$(($(date +%s) + timeout_min * 60))
run_id=''
state=''
suite='n/a'
if [ "$code_files" -gt 0 ]; then
	suite='pending'
	while :; do
		[ -n "$run_id" ] || run_id=$(find_run)
		if [ -n "$run_id" ]; then
			state=$(run_state "$run_id")
			case "$state" in completed*) break ;; esac
		fi
		[ "$wait_for_run" -eq 1 ] || break
		[ "$(date +%s)" -lt "$deadline" ] || break
		sleep "$interval"
	done
	if [ -z "$run_id" ]; then
		echo "$CI_WORKFLOW run: none found for this SHA yet"
	else
		echo "$CI_WORKFLOW run: $run_id  ${state:-unknown}"
		gh run view "$run_id" --repo "$repo" --json jobs \
			--jq '.jobs[] | select(.name == "build-and-test" or .conclusion != "success") | "  job \(.name): \(.status) \(.conclusion // "-")"' 2>/dev/null
	fi
	case "$state" in
		'completed success') suite='success' ;;
		completed*) suite='failed' ;;
	esac
fi

# A check-run is finished when its status is completed, or when it carries both a conclusion
# and a completion time: GitHub has left a finished required check listed as in_progress
# for minutes (measured on #1421) while branch protection already accepted it. Those rows
# are marked so the reader can see it. A row with no conclusion is still pending.
# Every check-run of a required name must be completed and green: GitHub has no "or"
# across same-named checks, and neither does this.
runs=$(gh api "repos/$repo/commits/$sha/check-runs" --paginate \
	--jq '.check_runs[] | (.status != "completed" and .conclusion != null and .completed_at != null) as $stale
		| [.name, (if $stale then "completed" else .status end), (.conclusion // "-"), (if $stale then "stale" else "-" end)] | @tsv' 2>/dev/null) || runs=''
if [ -z "$runs" ]; then
	echo 'PREREQ: could not read check-runs for the head SHA' >&2
	exit 2
fi

required_bad=0
echo 'required checks:'
old_ifs=$IFS
IFS='|'
for name in $REQUIRED_CHECKS; do
	IFS=$old_ifs
	rows=$(printf '%s\n' "$runs" | awk -F '\t' -v n="$name" '$1 == n')
	if [ -z "$rows" ]; then
		echo "  $name: NOT REPORTED"
		required_bad=1
	else
		total=$(printf '%s\n' "$rows" | wc -l | tr -d ' ')
		green=$(printf '%s\n' "$rows" | awk -F '\t' '$2 == "completed" && ($3 == "success" || $3 == "skipped" || $3 == "neutral")' | wc -l | tr -d ' ')
		detail=$(printf '%s\n' "$rows" | awk -F '\t' '{ printf "%s%s/%s%s", (NR > 1 ? ", " : ""), $2, $3, ($4 == "stale" ? " [GitHub still lists it in_progress]" : "") }')
		echo "  $name: $green/$total green ($detail)"
		[ "$green" -eq "$total" ] || required_bad=1
	fi
	IFS='|'
done
IFS=$old_ifs

other=$(printf '%s\n' "$runs" | awk -F '\t' -v req="$REQUIRED_CHECKS" '
	BEGIN { n = split(req, r, "|"); for (i = 1; i <= n; i++) required[r[i]] = 1 }
	!($1 in required) && !($2 == "completed" && ($3 == "success" || $3 == "skipped" || $3 == "neutral")) { print "  " $1 ": " $2 " " $3 }')
if [ -n "$other" ]; then
	echo 'advisory checks not green (do not block the merge):'
	printf '%s\n' "$other"
fi

base_sha=$(gh api "repos/$repo/git/ref/heads/$base" --jq .object.sha 2>/dev/null) || base_sha=''
behind=''
if [ -n "$base_sha" ]; then
	behind=$(gh api "repos/$repo/compare/$base_sha...$sha" --jq .behind_by 2>/dev/null) || behind=''
fi
pr_state=$(pr_field state,mergeStateStatus '"\(.state) \(.mergeStateStatus)"')
echo "$base=${base_sha:-unknown}  head is behind by ${behind:-unknown} commit(s)"
echo "PR state: ${pr_state:-unknown}"
case "$pr_state" in
	OPEN*) ;;
	*) echo 'VERDICT: NOT OPEN (nothing to merge)'; exit 2 ;;
esac

if [ "$suite" = 'failed' ]; then
	echo "VERDICT: FAILED ($CI_WORKFLOW run $run_id did not succeed)"
	exit 1
fi
if [ "$suite" = 'pending' ]; then
	echo "VERDICT: TIMEOUT ($CI_WORKFLOW has not finished; a green build-and-test above is NOT the suite)"
	exit 4
fi
if [ "$required_bad" -ne 0 ]; then
	pending=$(printf '%s\n' "$runs" | awk -F '\t' -v req="$REQUIRED_CHECKS" '
		BEGIN { n = split(req, r, "|"); for (i = 1; i <= n; i++) required[r[i]] = 1 }
		($1 in required) && $2 != "completed"' | wc -l | tr -d ' ')
	if [ "$pending" -gt 0 ]; then
		echo 'VERDICT: TIMEOUT (a required check is still running)'
		exit 4
	fi
	echo 'VERDICT: FAILED (a required check is missing or not green)'
	exit 1
fi
case "$behind" in
	0) ;;
	'' | *[!0-9]*) echo "VERDICT: BEHIND (could not confirm the head contains $base; re-run)"; exit 3 ;;
	*) echo "VERDICT: BEHIND (run: gh pr update-branch $pr, then wait again)"; exit 3 ;;
esac
echo "VERDICT: READY  gh pr merge $pr --merge --match-head-commit $sha"
exit 0
