#!/bin/sh
# Scoped CRAP oracle (US-13).
# TEMPORARY: exists because quality-gate runs coverageCommand under a hard-coded 300 s timeout
# (lib/lcov.mjs runCoverage) and this suite needs ~13 min under istanbul, so the configured
# whole-repo gate can never measure coverage here. Remove once that upstream defect is fixed.
# Tracking: eigenwise-toolshed SQ-4.
#
# Usage: crap-scope.sh <file>... [-- <function-name>...]
# Coverage comes from `vitest related` for the given files only. Green when all three hold:
#   1. every new or complexity-raised body vs origin/main scores below the gate ceiling;
#   2. no FAIL row with cc < 6 remains in the files (the tests-only targets);
#   3. every named function has a PASS row and no FAIL row.
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
files=""
names=""
mode=files
for a; do
	if [ "$a" = "--" ]; then mode=names; continue; fi
	if [ "$mode" = files ]; then files="$files $a"; else names="$names $a"; fi
done
[ -n "$files" ] || { echo "usage: $0 <file>... [-- <function-name>...]" >&2; exit 2; }

QG="$(ls -d "$HOME"/.claude/plugins/cache/eigenwise-toolshed/quality-gate/*/ | sort -V | tail -1)bin/quality-gate.js"
inc=""
src=""
for f in $files; do
	inc="$inc --coverage.include=$f"
	src="$src --source $f"
done
cmd="node scripts/vitest-filter-workerd.mjs related --run$files --coverage.enabled --coverage.provider=istanbul --coverage.reporter=lcov$inc --coverage.reportsDirectory=\"\$QUALITY_GATE_COVERAGE_DIR\""

echo "== new or complexity-raised bodies vs origin/main"
# shellcheck disable=SC2086
node "$QG" crap --base origin/main $src --coverage-command "$cmd" || { echo "crap-scope: RED (changed bodies)"; exit 1; }

echo "== all bodies at HEAD"
# shellcheck disable=SC2086
out=$(node "$QG" crap --base HEAD $src --coverage-command "$cmd" 2>&1)
if ! printf '%s\n' "$out" | grep -q '^CRAP gate'; then
	printf '%s\n' "$out" | tail -20
	echo "crap-scope: RED (gate produced no result)"
	exit 1
fi
if printf '%s\n' "$out" | grep -q '^UNVERIFIED <gate>'; then
	printf '%s\n' "$out" | grep '^UNVERIFIED <gate>'
	echo "crap-scope: RED (coverage not measured)"
	exit 1
fi

rc=0
low=$(printf '%s\n' "$out" | grep -E '^FAIL [^ ]+ [^ ]+ cc=[1-5] ' || true)
if [ -n "$low" ]; then
	printf '%s\n' "$low"
	echo "-- functions below complexity 6 still lack coverage"
	rc=1
fi
for n in $names; do
	rows=$(printf '%s\n' "$out" | grep -E "^(PASS|FAIL|UNVERIFIED|LEGACY) [^ ]+ $n( |:)" || true)
	if [ -z "$rows" ]; then
		echo "MISSING $n (renamed or removed? keep the original entry-point name)"
		rc=1
	elif printf '%s\n' "$rows" | grep -qv '^PASS'; then
		printf '%s\n' "$rows" | grep -v '^PASS'
		rc=1
	else
		echo "ok $n"
	fi
done
[ "$rc" -eq 0 ] && echo "crap-scope: GREEN" || echo "crap-scope: RED"
exit "$rc"
