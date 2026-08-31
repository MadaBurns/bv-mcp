// SPDX-License-Identifier: BUSL-1.1

export interface ScoringChangeInput {
	changedPaths: string[];
	baseVersion: string | null;
	headVersion: string | null;
}

const BEHAVIOR_PATHS = [
	'packages/dns-checks/src/scoring/',
	'packages/dns-checks/src/parity-fixtures.ts',
	'packages/dns-checks/src/types.ts',
];

export function assessScoringContractChange(input: ScoringChangeInput): string[] {
	const behaviorChanged = input.changedPaths.some((path) =>
		BEHAVIOR_PATHS.some((prefix) => path === prefix || path.startsWith(prefix)),
	);
	if (!behaviorChanged) return [];
	if (!input.baseVersion || !input.headVersion) {
		return ['could not resolve both base and head dns-checks versions'];
	}
	if (input.baseVersion === input.headVersion) {
		return [
			`scoring behavior changed while @blackveil/dns-checks remained at ${input.headVersion}`,
			'bump packages/dns-checks/package.json and PARITY_CORPUS_VERSION in the same PR',
		];
	}
	return [];
}
