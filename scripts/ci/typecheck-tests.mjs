// SPDX-License-Identifier: BUSL-1.1
//
// Test-tree typecheck RATCHET (issue #645).
//
// Why this exists
// ---------------
// Neither tsconfig that CI runs covers a test file:
//   * `tsconfig.json`                   -> "exclude": ["test"]
//   * `packages/dns-checks/tsconfig.json` -> "exclude": ["src/**/__tests__/**"]
// and Vitest transpiles through esbuild, which strips types WITHOUT checking them. So a type
// error in a spec is invisible to `npm run typecheck`, to `npm test`, and to every CI job.
//
// That is not merely untidy. The error that surfaced #645 was `toBeLessThan()` applied to a
// possibly-`null` `ScanScore.overall`; because `null < n` coerces to `true`, the assertion would
// have passed VACUOUSLY on an ungraded scan. Nullable-vs-number confusion in a spec is exactly
// the shape that makes an assertion stop asserting, so test type errors are disproportionately
// likely to BE vacuity bugs.
//
// Burning down the accumulated drift in one pass is not reviewable, so this is a ratchet, not a
// burndown: the current per-file error counts are committed as a baseline and the check fails
// only when a file's count INCREASES (or when a previously clean file starts erroring). New and
// edited specs are therefore typechecked from day one while the existing drift stays parked.
//
// Anti-fudge properties
// ---------------------
//  * The baseline is PER FILE, not a single global number. You cannot absorb a new error in one
//    spec by fixing an unrelated one, and raising the ceiling shows up as a named-file diff.
//  * On regression the script prints the offending file, its old and new counts, AND the raw tsc
//    error lines for that file, so the CI log shows exactly what was introduced.
//  * A decrease never fails, but it is reported loudly with the tightening command.
//
// Usage
//   npm run typecheck:tests              # check against the committed baseline
//   npm run typecheck:tests -- --update  # rewrite the baseline (deliberate, reviewable diff)

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const BASELINE_PATH = path.join(REPO_ROOT, 'test', 'typecheck-baseline.json');

/**
 * The tsconfig projects that cover a test tree.
 *
 * `test/tsconfig.json` also drags in the `packages/dns-checks/src/__tests__/scoring/*.suite.ts`
 * files transitively (the thin `test/scoring-*.spec.ts` wrappers import them), which is why a
 * handful of package files appear under both projects. Counts are kept per project rather than
 * merged so neither project's settings can mask the other's errors.
 */
const PROJECTS = ['test/tsconfig.json', 'packages/dns-checks/tsconfig.test.json'];

/** Key used for diagnostics tsc reports without a file (e.g. a missing type-library entry point). */
const GLOBAL_KEY = '<no-file>';

/** Matches a non-pretty tsc diagnostic line: `path/to/file.ts(12,34): error TS1234: message`. */
const ERROR_LINE = /^(.+?)\((\d+),(\d+)\): error (TS\d+): (.*)$/;
/** Matches a file-less diagnostic: `error TS2688: message`. */
const GLOBAL_ERROR_LINE = /^error (TS\d+): (.*)$/;

/**
 * Run `tsc --noEmit --pretty false` for one project and bucket its diagnostics by file.
 *
 * @param {string} project tsconfig path, relative to the repo root.
 * @returns {{ counts: Record<string, number>, lines: Record<string, string[]>, raw: string }}
 */
function runProject(project) {
	const tsc = path.join(REPO_ROOT, 'node_modules', 'typescript', 'bin', 'tsc');
	if (!existsSync(tsc)) {
		fail(`typescript is not installed at ${tsc} — run \`npm ci\` first.`);
	}

	// Capture stdout/stderr off the spawn result directly. Deliberately NOT a shell pipeline:
	// `grep -c` exits 1 on zero matches and zsh has no `${PIPESTATUS[0]}`, so a piped count can
	// silently read a red gate as green.
	const result = spawnSync(process.execPath, [tsc, '--noEmit', '--pretty', 'false', '-p', project], {
		cwd: REPO_ROOT,
		encoding: 'utf8',
		maxBuffer: 64 * 1024 * 1024,
	});

	if (result.error) {
		fail(`failed to spawn tsc for ${project}: ${result.error.message}`);
	}

	const raw = `${result.stdout ?? ''}${result.stderr ?? ''}`;

	// tsc exits 0 (clean) or 1/2 (diagnostics). Anything else is a tooling failure, and reporting
	// "0 errors" for a crashed compiler would turn this gate into a rubber stamp.
	if (result.status !== 0 && result.status !== 1 && result.status !== 2) {
		fail(`tsc exited ${result.status} for ${project}:\n${raw}`);
	}

	/** @type {Record<string, number>} */
	const counts = {};
	/** @type {Record<string, string[]>} */
	const lines = {};

	for (const line of raw.split('\n')) {
		// Continuation lines of a multi-line diagnostic are indented; only the first line counts.
		if (line.startsWith(' ') || line.startsWith('\t')) continue;

		const match = ERROR_LINE.exec(line);
		const key = match ? normalize(match[1]) : GLOBAL_ERROR_LINE.test(line) ? GLOBAL_KEY : null;
		if (key === null) continue;

		counts[key] = (counts[key] ?? 0) + 1;
		(lines[key] ??= []).push(line);
	}

	// A clean exit with parsed errors (or vice versa) means the output shape changed under us.
	const total = Object.values(counts).reduce((sum, n) => sum + n, 0);
	if (result.status === 0 && total !== 0) {
		fail(`tsc reported success for ${project} but ${total} diagnostics were parsed — output format changed?`);
	}

	return { counts, lines, raw };
}

/** Normalize a tsc-reported path to a repo-root-relative POSIX path so baselines are portable. */
function normalize(filePath) {
	const absolute = path.isAbsolute(filePath) ? filePath : path.join(REPO_ROOT, filePath);
	return path.relative(REPO_ROOT, absolute).split(path.sep).join('/');
}

function fail(message) {
	console.error(`typecheck:tests: ${message}`);
	process.exit(2);
}

function totalOf(counts) {
	return Object.values(counts).reduce((sum, n) => sum + n, 0);
}

// ---------------------------------------------------------------------------------------------

const update = process.argv.includes('--update');

// `test/tsconfig.json` resolves `@blackveil/dns-checks/*` through the workspace package's built
// `dist/`. Without it, module resolution collapses and the run reports hundreds of phantom
// errors that have nothing to do with the diff — so fail loudly instead of scoring the noise.
if (!existsSync(path.join(REPO_ROOT, 'packages', 'dns-checks', 'dist', 'index.d.ts'))) {
	fail(
		'packages/dns-checks/dist is not built — run `npm run build --workspace=packages/dns-checks` first.\n' +
			'  (Counting against an unbuilt dist would report hundreds of unrelated resolution errors.)',
	);
}

// `test/tsconfig.json` includes the generated `../worker-configuration.d.ts` (gitignored).
if (!existsSync(path.join(REPO_ROOT, 'worker-configuration.d.ts'))) {
	fail('worker-configuration.d.ts is missing — run `npx wrangler types` first.');
}

/** @type {{ projects: Record<string, Record<string, number>> }} */
const results = { projects: {} };
/** @type {Record<string, Record<string, string[]>>} */
const errorLines = {};

for (const project of PROJECTS) {
	if (!existsSync(path.join(REPO_ROOT, project))) {
		fail(`project ${project} does not exist.`);
	}
	const { counts, lines } = runProject(project);
	results.projects[project] = Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
	errorLines[project] = lines;
}

const currentTotal = PROJECTS.reduce((sum, p) => sum + totalOf(results.projects[p]), 0);

if (update) {
	const payload = {
		$comment:
			'Ratchet baseline for `npm run typecheck:tests` (issue #645). Per-file tsc error counts for the test trees, which no other gate typechecks. An INCREASE fails CI; a decrease is reported and should be banked by re-running with `-- --update`. Regenerate deliberately — never to silence a new error.',
		generatedBy: 'scripts/ci/typecheck-tests.mjs --update',
		typescript: JSON.parse(readFileSync(path.join(REPO_ROOT, 'node_modules', 'typescript', 'package.json'), 'utf8')).version,
		total: currentTotal,
		projects: results.projects,
	};
	writeFileSync(BASELINE_PATH, `${JSON.stringify(payload, null, '\t')}\n`);
	console.log(
		`typecheck:tests: baseline written to test/typecheck-baseline.json (${currentTotal} errors across ${PROJECTS.length} projects).`,
	);
	process.exit(0);
}

if (!existsSync(BASELINE_PATH)) {
	fail('test/typecheck-baseline.json is missing — generate it with `npm run typecheck:tests -- --update`.');
}

/** @type {{ typescript?: string, total?: number, projects: Record<string, Record<string, number>> }} */
const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8'));
const baselineTotal = PROJECTS.reduce((sum, p) => sum + totalOf(baseline.projects?.[p] ?? {}), 0);

/** @type {{ project: string, file: string, was: number, now: number }[]} */
const regressions = [];
/** @type {{ project: string, file: string, was: number, now: number }[]} */
const improvements = [];

for (const project of PROJECTS) {
	const base = baseline.projects?.[project] ?? {};
	const now = results.projects[project];
	for (const file of new Set([...Object.keys(base), ...Object.keys(now)])) {
		const was = base[file] ?? 0;
		const is = now[file] ?? 0;
		if (is > was) regressions.push({ project, file, was, now: is });
		else if (is < was) improvements.push({ project, file, was, now: is });
	}
}

const installedTs = JSON.parse(readFileSync(path.join(REPO_ROOT, 'node_modules', 'typescript', 'package.json'), 'utf8')).version;

console.log('typecheck:tests — test-tree type errors (ratchet, issue #645)');
for (const project of PROJECTS) {
	const was = totalOf(baseline.projects?.[project] ?? {});
	const is = totalOf(results.projects[project]);
	console.log(`  ${project}: ${is} (baseline ${was}, delta ${is - was >= 0 ? '+' : ''}${is - was})`);
}
console.log(
	`  TOTAL: ${currentTotal} (baseline ${baselineTotal}, delta ${currentTotal - baselineTotal >= 0 ? '+' : ''}${currentTotal - baselineTotal})`,
);
if (baseline.typescript && baseline.typescript !== installedTs) {
	console.log(
		`  note: baseline recorded under TypeScript ${baseline.typescript}, running ${installedTs} — counts can shift across compiler versions.`,
	);
}

if (improvements.length > 0) {
	console.log(`\n${improvements.length} file(s) IMPROVED — bank it so the ratchet tightens:`);
	for (const { project, file, was, now } of improvements.sort((a, b) => a.now - a.was - (b.now - b.was))) {
		console.log(`  ${file}  ${was} -> ${now}   [${project}]`);
	}
	console.log('  Run: npm run typecheck:tests -- --update');
}

if (regressions.length === 0) {
	console.log('\nOK — no test file exceeds its baseline.');
	process.exit(0);
}

console.error(`\nFAIL — ${regressions.length} file(s) gained type errors:\n`);
for (const { project, file, was, now } of regressions.sort((a, b) => b.now - b.was - (a.now - a.was))) {
	console.error(`  ${file}  ${was} -> ${now}  (+${now - was})   [${project}]`);
	for (const line of errorLines[project][file] ?? []) {
		console.error(`      ${line}`);
	}
	console.error('');
}
console.error('Fix the new errors. Type errors in specs are disproportionately likely to be VACUITY bugs');
console.error('(e.g. `expect(possiblyNull).toBeLessThan(n)` passes for null), so a green test here may be');
console.error('proving nothing. Raising the baseline with `-- --update` is a deliberate, reviewable diff —');
console.error('not the default response to this failure.');
process.exit(1);
