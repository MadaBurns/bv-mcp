#!/usr/bin/env bash
# local-preflight.sh [--wasm] [--base <ref>]
#
# Runs, locally, the Node-side steps of ci.yml's `preflight` and `fast-checks` jobs, so a
# red PR is caught before the push instead of ten minutes after it. `npm run ci:local`.
#
# Every step runs even when an earlier one fails; the summary lists each result and the
# exit status is 1 when any step failed.
#
# What it does NOT run, so a green result is not over-read:
#   - the test shards (`npm test`) and the typecheck-tests ratchet: run those yourself;
#   - the Rust/WASM build and test/wasm-integration.test.ts, unless --wasm is passed
#     (needs cargo and wasm-pack). `check:wasm-permissions` runs in their place by default:
#     it loads the same schema modules under plain Node, which is what breaks first;
#   - the four required security and hygiene workflows (secret scan, dependency audit,
#     file hygiene) and anything that only exists on the runner.
#
# The step list is a hand-kept mirror of .github/workflows/ci.yml. Step 0 re-reads that
# file and fails when either job has gained an `npm run` step this script does not know,
# so the mirror cannot silently fall behind.

set -u

root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo 'PREREQ: not inside a git checkout' >&2; exit 2; }
cd "$root" || exit 2

with_wasm=0
base_ref=''
while [ $# -gt 0 ]; do
	case "$1" in
		--wasm) with_wasm=1; shift ;;
		--base) [ $# -ge 2 ] || { echo 'usage: local-preflight.sh [--wasm] [--base <ref>]' >&2; exit 2; }; base_ref=$2; shift 2 ;;
		*) echo 'usage: local-preflight.sh [--wasm] [--base <ref>]' >&2; exit 2 ;;
	esac
done

[ -d node_modules ] || { echo 'PREREQ: node_modules is missing; run scripts/worktree-setup.sh (never symlink it)' >&2; exit 2; }

# CI compares against the PR base SHA. Locally that is where this branch left main.
if [ -z "$base_ref" ]; then
	base_ref=$(git merge-base origin/main HEAD 2>/dev/null) || base_ref=''
fi
[ -n "$base_ref" ] || { echo 'PREREQ: could not resolve a base ref (git fetch origin, or pass --base <ref>)' >&2; exit 2; }

# npm scripts this file runs (or deliberately leaves to --wasm). Step 0 compares the
# workflow against this list.
KNOWN_NPM_SCRIPTS='lint check:bindings check:scoring-contract-change check:dns-checks-version-bump check:tool-surface build build:wasm'

results=''
failed=0
record() {
	results="${results}$1	$2
"
	[ "$1" = 'ok' ] || [ "$1" = 'skip' ] || failed=1
}
step() {
	label=$1
	shift
	echo
	echo "==> $label"
	if "$@"; then record ok "$label"; else record FAIL "$label"; fi
}

workflow_drift() {
	wf=.github/workflows/ci.yml
	[ -f "$wf" ] || { echo "missing $wf"; return 1; }
	unknown=$(awk -v known="$KNOWN_NPM_SCRIPTS" '
		BEGIN { n = split(known, k, " "); for (i = 1; i <= n; i++) ok[k[i]] = 1 }
		/^  [A-Za-z0-9_-]+:[[:space:]]*$/ { job = $1; sub(":", "", job) }
		(job == "preflight" || job == "fast-checks") && /npm run / {
			line = $0
			sub(/.*npm run /, "", line)
			split(line, w, " ")
			if (!(w[1] in ok)) print job ": npm run " w[1]
		}' "$wf")
	if [ -n "$unknown" ]; then
		echo "ci.yml has steps this script does not mirror; add them here and to KNOWN_NPM_SCRIPTS:"
		echo "$unknown"
		return 1
	fi
	echo 'ci.yml preflight and fast-checks npm steps are all accounted for'
}

echo "base ref: $base_ref"
step 'workflow mirror is current' workflow_drift
step 'build dns-checks' npm run build --workspace=packages/dns-checks
step 'lint' npm run lint
step 'offline chaos harness tests' python3 -m unittest discover -s scripts/chaos -p 'test_*.py'
step 'check:bindings' npm run check:bindings
step 'check:scoring-contract-change' env SCORING_CONTRACT_BASE_REF="$base_ref" npm run check:scoring-contract-change
step 'check:dns-checks-version-bump' env DNS_CHECKS_BASE_REF="$base_ref" npm run check:dns-checks-version-bump
step 'check:tool-surface' npm run check:tool-surface
if [ "$with_wasm" -eq 1 ]; then
	step 'build:wasm' npm run build:wasm
	step 'wasm integration test' npx vitest run test/wasm-integration.test.ts
else
	step 'check:wasm-permissions (stand-in for the WASM build)' npm run check:wasm-permissions
	record skip 'build:wasm + wasm integration test (pass --wasm)'
fi

echo
echo '== summary =='
printf '%s' "$results" | awk -F '\t' '{ printf "  %-5s %s\n", $1, $2 }'
if [ "$failed" -ne 0 ]; then
	echo 'RESULT: FAILED'
	exit 1
fi
echo 'RESULT: OK (not run: test shards, typecheck-tests, the security workflows)'
exit 0
