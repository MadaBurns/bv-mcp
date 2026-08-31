// SPDX-License-Identifier: BUSL-1.1

import { execFileSync } from 'node:child_process';

const SCORING_SENSITIVE_PREFIXES = [
	'packages/dns-checks/src/checks/',
	'packages/dns-checks/src/scoring/',
];
const SCORING_VERSION_FILE = 'src/lib/scoring-version.ts';
const OPT_OUT_MARKER = '[no-scoring-change]';

export function evaluateScoringVersionGate(files, labels = [], pullRequestBody = '') {
	const touchesScoring = files.some(
		(file) =>
			SCORING_SENSITIVE_PREFIXES.some((prefix) => file.startsWith(prefix)) ||
			(file.startsWith('src/lib/scoring-') && file.endsWith('.ts')),
	);
	const versionChanged = files.includes(SCORING_VERSION_FILE);
	const optedOut = labels.includes('no-scoring-change') || pullRequestBody.toLowerCase().includes(OPT_OUT_MARKER);

	return { touchesScoring, versionChanged, optedOut, needsAttention: touchesScoring && !versionChanged && !optedOut };
}

function changedFiles(baseSha, headSha) {
	return execFileSync('git', ['diff', '--name-only', `${baseSha}...${headSha}`], { encoding: 'utf8' })
		.split('\n')
		.map((file) => file.trim())
		.filter(Boolean);
}

function main() {
	const [baseSha, headSha] = process.argv.slice(2);
	if (!baseSha || !headSha) {
		throw new Error('Usage: node scripts/ci/check-scoring-version.mjs <base-sha> <head-sha>');
	}

	const labels = JSON.parse(process.env.PR_LABELS_JSON || '[]');
	const result = evaluateScoringVersionGate(changedFiles(baseSha, headSha), labels, process.env.PR_BODY || '');
	if (!result.needsAttention) return;

	const message =
		'Scoring-sensitive files changed without a SCORING_MODEL_VERSION update. ' +
		'Confirm the change is score-neutral with the no-scoring-change label or [no-scoring-change] in the PR body.';
	if (process.env.SCORING_GATE_ENFORCE === 'true') {
		throw new Error(message);
	}
	process.stdout.write(`::warning title=Scoring model version review::${message}\n`);
}

if (process.argv[1]?.endsWith('check-scoring-version.mjs')) main();
