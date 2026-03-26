// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { parseScoringConfig, DEFAULT_SCORING_CONFIG, toImportanceRecord } from '../../scoring';
import { PROFILE_WEIGHTS } from '../../scoring/profiles';

describe('parseScoringConfig', () => {
	it('returns defaults when input is undefined', () => {
		const config = parseScoringConfig(undefined);
		expect(config).toEqual(DEFAULT_SCORING_CONFIG);
	});

	it('returns defaults when input is empty string', () => {
		const config = parseScoringConfig('');
		expect(config).toEqual(DEFAULT_SCORING_CONFIG);
	});

	it('returns defaults when input is invalid JSON', () => {
		const config = parseScoringConfig('not json');
		expect(config).toEqual(DEFAULT_SCORING_CONFIG);
	});

	it('returns defaults when input is a JSON array', () => {
		const config = parseScoringConfig('[1, 2, 3]');
		expect(config).toEqual(DEFAULT_SCORING_CONFIG);
	});

	it('merges partial weight overrides with defaults', () => {
		const config = parseScoringConfig(JSON.stringify({
			weights: { spf: 15, dmarc: 30 },
		}));
		expect(config.weights.spf).toBe(15);
		expect(config.weights.dmarc).toBe(30);
		expect(config.weights.dkim).toBe(DEFAULT_SCORING_CONFIG.weights.dkim);
	});

	it('merges partial profile weight overrides', () => {
		const config = parseScoringConfig(JSON.stringify({
			profileWeights: {
				enterprise_mail: { dmarc: 30 },
			},
		}));
		expect(config.profileWeights.enterprise_mail.dmarc).toBe(30);
		expect(config.profileWeights.enterprise_mail.dkim).toBe(DEFAULT_SCORING_CONFIG.profileWeights.enterprise_mail.dkim);
		expect(config.profileWeights.mail_enabled).toEqual(DEFAULT_SCORING_CONFIG.profileWeights.mail_enabled);
	});

	it('merges threshold overrides', () => {
		const config = parseScoringConfig(JSON.stringify({
			thresholds: { emailBonusImportance: 10, criticalGapCeiling: 70 },
		}));
		expect(config.thresholds.emailBonusImportance).toBe(10);
		expect(config.thresholds.criticalGapCeiling).toBe(70);
		expect(config.thresholds.spfStrongThreshold).toBe(DEFAULT_SCORING_CONFIG.thresholds.spfStrongThreshold);
	});

	it('merges grade overrides', () => {
		const config = parseScoringConfig(JSON.stringify({
			grades: { aPlus: 95 },
		}));
		expect(config.grades.aPlus).toBe(95);
		expect(config.grades.a).toBe(DEFAULT_SCORING_CONFIG.grades.a);
	});

	it('merges baseline failure rate overrides', () => {
		const config = parseScoringConfig(JSON.stringify({
			baselineFailureRates: { dmarc: 0.50, spf: 0.30 },
		}));
		expect(config.baselineFailureRates.dmarc).toBe(0.50);
		expect(config.baselineFailureRates.spf).toBe(0.30);
		expect(config.baselineFailureRates.ssl).toBe(DEFAULT_SCORING_CONFIG.baselineFailureRates.ssl);
	});

	it('ignores unknown top-level keys', () => {
		const config = parseScoringConfig(JSON.stringify({
			unknownKey: 'value',
			weights: { spf: 15 },
		}));
		expect(config.weights.spf).toBe(15);
		expect(config).not.toHaveProperty('unknownKey');
	});

	it('clamps negative weights to 0', () => {
		const config = parseScoringConfig(JSON.stringify({
			weights: { spf: -5 },
		}));
		expect(config.weights.spf).toBe(0);
	});

	it('ignores non-numeric weight values', () => {
		const config = parseScoringConfig(JSON.stringify({
			weights: { spf: 'high' },
		}));
		expect(config.weights.spf).toBe(DEFAULT_SCORING_CONFIG.weights.spf);
	});

	it('ignores non-numeric threshold values', () => {
		const config = parseScoringConfig(JSON.stringify({
			thresholds: { emailBonusImportance: true },
		}));
		expect(config.thresholds.emailBonusImportance).toBe(DEFAULT_SCORING_CONFIG.thresholds.emailBonusImportance);
	});

	it('ignores Infinity and NaN weights', () => {
		const config = parseScoringConfig(JSON.stringify({
			weights: { spf: null },
		}));
		expect(config.weights.spf).toBe(DEFAULT_SCORING_CONFIG.weights.spf);
	});

	it('ignores unknown weight categories', () => {
		const config = parseScoringConfig(JSON.stringify({
			weights: { unknown_check: 99, spf: 15 },
		}));
		expect(config.weights.spf).toBe(15);
		expect(config.weights).not.toHaveProperty('unknown_check');
	});
});

describe('scoring v2 config', () => {
	it('DEFAULT_SCORING_CONFIG has tierSplit summing to 100', () => {
		const { tierSplit } = DEFAULT_SCORING_CONFIG;
		expect(tierSplit.core + tierSplit.protective + tierSplit.hardening).toBe(100);
	});

	it('DEFAULT_SCORING_CONFIG has coreWeights', () => {
		expect(DEFAULT_SCORING_CONFIG.coreWeights).toEqual({
			dmarc: 16, dkim: 10, spf: 10, dnssec: 10, ssl: 8,
		});
	});

	it('DEFAULT_SCORING_CONFIG has protectiveWeights', () => {
		expect(DEFAULT_SCORING_CONFIG.protectiveWeights.subdomain_takeover).toBe(4);
		expect(Object.values(DEFAULT_SCORING_CONFIG.protectiveWeights).reduce((a, b) => a + b, 0)).toBe(20);
	});

	it('DEFAULT_SCORING_CONFIG has emailBonusFull/Mid/Partial', () => {
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusFull).toBe(5);
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusMid).toBe(3);
		expect(DEFAULT_SCORING_CONFIG.thresholds.emailBonusPartial).toBe(2);
	});

	it('DEFAULT_SCORING_CONFIG has no E grade', () => {
		expect(DEFAULT_SCORING_CONFIG.grades).not.toHaveProperty('e');
	});

	it('DEFAULT_SCORING_CONFIG has providerDkimConfidence', () => {
		expect(DEFAULT_SCORING_CONFIG.providerDkimConfidence.amazonses).toBe(0.8);
		expect(DEFAULT_SCORING_CONFIG.providerDkimConfidence.google).toBe(0.9);
	});

	it('parseScoringConfig migrates legacy weights to coreWeights/protectiveWeights', () => {
		const legacy = JSON.stringify({ weights: { dmarc: 30, spf: 15 } });
		const config = parseScoringConfig(legacy);
		expect(config.coreWeights.dmarc).toBe(30);
		expect(config.coreWeights.spf).toBe(15);
	});

	it('parseScoringConfig migrates emailBonusImportance to three fields', () => {
		const legacy = JSON.stringify({ thresholds: { emailBonusImportance: 10 } });
		const config = parseScoringConfig(legacy);
		expect(config.thresholds.emailBonusFull).toBe(10);
		expect(config.thresholds.emailBonusMid).toBe(6);
		expect(config.thresholds.emailBonusPartial).toBe(4);
	});

	it('parseScoringConfig rejects tierSplit not summing to 100', () => {
		const bad = JSON.stringify({ tierSplit: { core: 80, protective: 20, hardening: 10 } });
		const config = parseScoringConfig(bad);
		expect(config.tierSplit.core).toBe(70);
	});
});

describe('toImportanceRecord', () => {
	it('wraps flat numbers in { importance } objects', () => {
		const result = toImportanceRecord({ spf: 10, dmarc: 22 });
		expect(result.spf).toEqual({ importance: 10 });
		expect(result.dmarc).toEqual({ importance: 22 });
	});
});

describe('config profileWeights consistency', () => {
	it('DEFAULT_SCORING_CONFIG.profileWeights matches PROFILE_WEIGHTS for all profiles', () => {
		for (const profile of Object.keys(PROFILE_WEIGHTS) as Array<keyof typeof PROFILE_WEIGHTS>) {
			const configWeights = DEFAULT_SCORING_CONFIG.profileWeights[profile];
			const profileWeights = PROFILE_WEIGHTS[profile];
			for (const [key, value] of Object.entries(profileWeights)) {
				expect(configWeights[key as keyof typeof configWeights],
					`${profile}.${key}: config=${configWeights[key as keyof typeof configWeights]}, profiles=${value.importance}`
				).toBe(value.importance);
			}
		}
	});
});
