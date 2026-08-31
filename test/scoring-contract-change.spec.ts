// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { assessScoringContractChange } from '../scripts/scoring-contract-change';

describe('scoring-contract change gate', () => {
	it('blocks a scoring behavior change without a package version bump', () => {
		expect(
			assessScoringContractChange({
				changedPaths: ['packages/dns-checks/src/scoring/profiles.ts'],
				baseVersion: '1.28.0',
				headVersion: '1.28.0',
			}),
		).not.toEqual([]);
	});

	it('allows a behavior change accompanied by a version bump', () => {
		expect(
			assessScoringContractChange({
				changedPaths: ['packages/dns-checks/src/scoring/profiles.ts'],
				baseVersion: '1.28.0',
				headVersion: '1.29.0',
			}),
		).toEqual([]);
	});

	it('does not require a package bump for unrelated changes', () => {
		expect(
			assessScoringContractChange({
				changedPaths: ['src/oauth/token.ts'],
				baseVersion: '1.28.0',
				headVersion: '1.28.0',
			}),
		).toEqual([]);
	});
});
