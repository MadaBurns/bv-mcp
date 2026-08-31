// SPDX-License-Identifier: BUSL-1.1

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { assessScoringContractChange } from '../scoring-contract-change';

function git(args: string[]): string {
	return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function versionFromJson(text: string): string | null {
	try {
		const value = (JSON.parse(text) as { version?: unknown }).version;
		return typeof value === 'string' ? value : null;
	} catch {
		return null;
	}
}

const baseRef =
	process.env.SCORING_CONTRACT_BASE_REF ??
	(process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : undefined);

if (!baseRef) {
	console.log('scoring-contract change gate: no base ref supplied; source contract self-tests remain active.');
	process.exit(0);
}

const packagePath = 'packages/dns-checks/package.json';
const changedPaths = git(['diff', '--name-only', `${baseRef}...HEAD`]).split('\n').filter(Boolean);
const violations = assessScoringContractChange({
	changedPaths,
	baseVersion: versionFromJson(git(['show', `${baseRef}:${packagePath}`])),
	headVersion: versionFromJson(readFileSync(packagePath, 'utf8')),
});

if (violations.length > 0) {
	console.error(`scoring-contract change gate: BLOCKED\n- ${violations.join('\n- ')}`);
	process.exit(1);
}

console.log('scoring-contract change gate: OK');
