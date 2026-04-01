// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { applyInteractionPenalties, INTERACTION_RULES } from '../src/lib/category-interactions';
import type { ScanScore, CheckCategory } from '../src/lib/scoring-model';

/** Build a minimal ScanScore with specified category scores. */
function buildScore(categoryScores: Partial<Record<CheckCategory, number>>, overall = 75): ScanScore {
	const defaults: Record<CheckCategory, number> = {
		spf: 100, dmarc: 100, dkim: 100, dnssec: 100, ssl: 100, mta_sts: 100,
		ns: 100, caa: 100, subdomain_takeover: 100, mx: 100, bimi: 100,
		tlsrpt: 100, lookalikes: 100, shadow_domains: 100, txt_hygiene: 100,
		http_security: 100, dane: 100, mx_reputation: 100, srv: 100, zone_hygiene: 100,
	};
	const merged = { ...defaults, ...categoryScores };
	return {
		overall,
		grade: 'B',
		categoryScores: merged,
		findings: [],
		summary: `Grade: B`,
	};
}

describe('INTERACTION_RULES', () => {
	it('has unique rule IDs', () => {
		const ids = INTERACTION_RULES.map((r) => r.id);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it('all rules have positive penalties', () => {
		for (const rule of INTERACTION_RULES) {
			expect(rule.overallPenalty).toBeGreaterThan(0);
		}
	});

	it('all rules have conditions and narratives', () => {
		for (const rule of INTERACTION_RULES) {
			expect(rule.conditions.length).toBeGreaterThanOrEqual(2);
			expect(rule.narrative.length).toBeGreaterThan(0);
		}
	});
});

describe('applyInteractionPenalties', () => {
	it('returns no effects when all categories score well', () => {
		const score = buildScore({});
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		expect(effects).toHaveLength(0);
		expect(adjustedScore.overall).toBe(score.overall);
	});

	it('applies weak_dkim_permissive_dmarc penalty', () => {
		const score = buildScore({ dkim: 30, dmarc: 50 }, 65);
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'weak_dkim_permissive_dmarc');
		expect(rule).toBeDefined();
		expect(rule!.penalty).toBe(5);
		expect(adjustedScore.overall).toBe(60);
	});

	it('applies no_spf_no_dmarc penalty', () => {
		const score = buildScore({ spf: 0, dmarc: 0 }, 50);
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'no_spf_no_dmarc');
		expect(rule).toBeDefined();
		expect(rule!.penalty).toBe(10);
		// Also triggers no_spf_no_dkim since dkim defaults to 100 — actually no, dkim is 100
		// Only no_spf_no_dmarc should fire
		expect(adjustedScore.overall).toBeLessThan(50);
	});

	it('weak_dnssec_enforcing_dmarc fires when DNSSEC <= 40 and DMARC >= 80', () => {
		const score = buildScore({ dmarc: 90, dnssec: 35 }, 80);
		const { effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'weak_dnssec_enforcing_dmarc');
		expect(rule).toBeDefined();
		expect(rule!.penalty).toBe(3);
	});

	it('old strong_auth_no_dnssec rule no longer exists', () => {
		const score = buildScore({ dmarc: 90, dnssec: 0 }, 80);
		const { effects } = applyInteractionPenalties(score);
		expect(effects.find((e) => e.ruleId === 'strong_auth_no_dnssec')).toBeUndefined();
	});

	it('weak_dnssec_enforcing_dmarc does not fire when DNSSEC > 40', () => {
		const score = buildScore({ dmarc: 90, dnssec: 85 }, 80);
		const { effects } = applyInteractionPenalties(score);
		expect(effects.find((e) => e.ruleId === 'weak_dnssec_enforcing_dmarc')).toBeUndefined();
	});

	it('applies no_spf_no_dkim penalty', () => {
		const score = buildScore({ spf: 0, dkim: 0 }, 60);
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'no_spf_no_dkim');
		expect(rule).toBeDefined();
		expect(rule!.penalty).toBe(5);
		expect(adjustedScore.overall).toBeLessThan(60);
	});

	it('applies weak_ssl_no_http_security penalty', () => {
		const score = buildScore({ ssl: 30, http_security: 20 }, 70);
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'weak_ssl_no_http_security');
		expect(rule).toBeDefined();
		expect(rule!.penalty).toBe(3);
		expect(adjustedScore.overall).toBe(67);
	});

	it('stacks multiple penalties', () => {
		// SPF=0, DMARC=0, DKIM=0 triggers: no_spf_no_dmarc (10) + no_spf_no_dkim (5) + weak_dkim_permissive_dmarc (5)
		const score = buildScore({ spf: 0, dmarc: 0, dkim: 0 }, 40);
		const { adjustedScore, effects } = applyInteractionPenalties(score);
		expect(effects.length).toBeGreaterThanOrEqual(2);
		const totalPenalty = effects.reduce((sum, e) => sum + e.penalty, 0);
		expect(adjustedScore.overall).toBe(Math.max(0, 40 - totalPenalty));
	});

	it('clamps score to 0', () => {
		const score = buildScore({ spf: 0, dmarc: 0, dkim: 0 }, 5);
		const { adjustedScore } = applyInteractionPenalties(score);
		expect(adjustedScore.overall).toBe(0);
	});

	it('updates grade when overall changes', () => {
		// 85 = A, penalty of 10 should drop to 75 = B
		const score = buildScore({ spf: 0, dmarc: 0 }, 85);
		score.grade = 'A';
		score.summary = 'Grade: A';
		const { adjustedScore } = applyInteractionPenalties(score);
		expect(adjustedScore.grade).not.toBe('A');
		expect(adjustedScore.summary).not.toContain('Grade: A');
	});

	it('preserves categoryScores unchanged', () => {
		const catScores: Partial<Record<CheckCategory, number>> = { spf: 0, dmarc: 0 };
		const score = buildScore(catScores, 60);
		const originalCatScores = { ...score.categoryScores };
		const { adjustedScore } = applyInteractionPenalties(score);
		expect(adjustedScore.categoryScores).toEqual(originalCatScores);
	});

	it('effects contain narratives', () => {
		const score = buildScore({ spf: 0, dmarc: 0 }, 50);
		const { effects } = applyInteractionPenalties(score);
		for (const effect of effects) {
			expect(effect.narrative.length).toBeGreaterThan(0);
			expect(effect.ruleId.length).toBeGreaterThan(0);
			expect(effect.penalty).toBeGreaterThan(0);
		}
	});

	it('does not fire when conditions are not met', () => {
		// DKIM=50 (above 40 threshold), DMARC=70 (above 60 threshold)
		const score = buildScore({ dkim: 50, dmarc: 70 }, 80);
		const { effects } = applyInteractionPenalties(score);
		const rule = effects.find((e) => e.ruleId === 'weak_dkim_permissive_dmarc');
		expect(rule).toBeUndefined();
	});

	it('minScore condition works correctly', () => {
		// weak_dnssec_enforcing_dmarc requires dmarc >= 80 and dnssec <= 40
		const score1 = buildScore({ dmarc: 79, dnssec: 0 }, 70);
		const { effects: e1 } = applyInteractionPenalties(score1);
		expect(e1.find((e) => e.ruleId === 'weak_dnssec_enforcing_dmarc')).toBeUndefined();

		const score2 = buildScore({ dmarc: 80, dnssec: 0 }, 70);
		const { effects: e2 } = applyInteractionPenalties(score2);
		expect(e2.find((e) => e.ruleId === 'weak_dnssec_enforcing_dmarc')).toBeDefined();
	});
});
