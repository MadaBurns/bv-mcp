// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { evaluateScoringVersionGate } from '../../scripts/ci/check-scoring-version.mjs';

describe('scoring-version PR advisory', () => {
	it('flags scoring-sensitive changes without a model-version decision', () => {
		expect(evaluateScoringVersionGate(['packages/dns-checks/src/checks/check-dnssec.ts']).needsAttention).toBe(true);
	});

	it('accepts a scoring-model version change in the same diff', () => {
		const result = evaluateScoringVersionGate([
			'packages/dns-checks/src/scoring/engine.ts',
			'src/lib/scoring-version.ts',
		]);
		expect(result.needsAttention).toBe(false);
		expect(result.versionChanged).toBe(true);
	});

	it('accepts either explicit opt-out mechanism', () => {
		expect(evaluateScoringVersionGate(['src/lib/scoring-policy.ts'], ['no-scoring-change']).needsAttention).toBe(false);
		expect(evaluateScoringVersionGate(['packages/dns-checks/src/checks/check-caa.ts'], [], '[no-scoring-change]').needsAttention).toBe(
			false,
		);
	});

	it('ignores unrelated changes', () => {
		expect(evaluateScoringVersionGate(['docs/scoring.md']).needsAttention).toBe(false);
	});
});
