// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { PARITY_CORPUS_VERSION } from '../parity-fixtures';
import { PROFILE_SEMANTICS, SCORING_CONTRACT, canonicalScoringContractJson } from '../scoring/contract';

describe('machine-readable scoring contract', () => {
	it('identifies the exact package behavior version', () => {
		expect(SCORING_CONTRACT.packageVersion).toBe(PARITY_CORPUS_VERSION);
	});

	it('defines comparison and selection semantics for every profile', () => {
		expect(Object.keys(SCORING_CONTRACT.profiles).sort()).toEqual(Object.keys(PROFILE_SEMANTICS).sort());
		// true since model 1.20.0 — web_only weights the non-sender lockdown.
		expect(PROFILE_SEMANTICS.web_only.emailPostureIncluded).toBe(true);
		expect(PROFILE_SEMANTICS.minimal.comparisonClass).toBe('limited-footprint');
		expect(PROFILE_SEMANTICS.authoritative_dns_infra.autoSelectable).toBe(false);
	});

	it('serializes deterministically with sorted object keys', () => {
		const first = canonicalScoringContractJson();
		expect(canonicalScoringContractJson()).toBe(first);
		expect(first.endsWith('\n')).toBe(true);
		expect(first.indexOf('enterprise_mail')).toBeLessThan(first.indexOf('mail_enabled'));
	});
});
