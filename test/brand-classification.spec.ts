// SPDX-License-Identifier: BUSL-1.1

/**
 * Regression coverage for #1037.
 *
 * `classifyCandidate()`'s Rule 8 (brand-classification.ts, "low confidence, no
 * strong infra signal") only fires when `c.confidence < INDETERMINATE_CONFIDENCE_THRESHOLD`
 * (0.5) — anything `>= 0.5` is already caught by Rule 7. At every production
 * caller's DEFAULT min_confidence (also 0.5 — discover-brand-domains.ts's
 * DEFAULT_MIN_CONFIDENCE, inherited by brand-audit-pipeline.ts and
 * prioritize-portfolio-leads.ts), the discoverer drops every candidate with
 * `combined < minConfidence` before classifyCandidate() ever sees it, so Rule 8
 * cannot fire under default configuration.
 *
 * It IS reachable-by-configuration, not dead code: `min_confidence` is a public
 * MCP tool parameter (`z.number().min(0).max(1).optional()`, src/schemas/tool-args.ts)
 * on discover_brand_domains, brand_audit_single, and brand_audit_batch_start,
 * with no floor above 0. Any caller that explicitly passes e.g. `min_confidence: 0.3`
 * lets candidates in [min_confidence, 0.5) survive discovery's confidence filter
 * and reach classifyCandidate() with `confidence < 0.5`, landing on Rule 8. This
 * suite pins that Rule 8 still classifies correctly at the unit level so a future
 * refactor can't silently delete or reorder it out from under that configured path.
 */
import { describe, expect, it } from 'vitest';
import { classifyCandidate, type CandidateInput, type TargetContext } from '../src/lib/brand-classification';

const TARGET: TargetContext = {
	domain: '[redacted-domain]',
	registrar: 'MarkMonitor Inc.',
	registrarFamily: 'MarkMonitor',
};

function candidate(overrides: Partial<CandidateInput> & { domain: string }): CandidateInput {
	return {
		confidence: 0.45,
		signals: ['markov_gen'],
		registrar: 'NameCheap, Inc.',
		registrarSource: 'rdap',
		...overrides,
	};
}

describe('#1037: Rule 8 (low-confidence fallback) reachability', () => {
	it('fires below INDETERMINATE_CONFIDENCE_THRESHOLD (0.5) — the configured-min_confidence path', () => {
		// confidence 0.45 < 0.5: below Rule 7's floor, so a candidate with no strong
		// infra signal and no other rule match falls through to Rule 8. Under default
		// discovery settings (min_confidence 0.5) this candidate would never have
		// survived discovery to reach classifyCandidate() — this pins the shape a
		// caller sees once they explicitly lower min_confidence below 0.5.
		const result = classifyCandidate(candidate({ domain: 'unrelated-domain.example' }), TARGET);
		expect(result.bucket).toBe('impersonation');
		expect(result.relationshipType).toBe('impersonation_risk');
		expect(result.reasons.join(' ')).toMatch(/low confidence, no strong infra signal/);
	});

	it('does NOT fire at confidence exactly 0.5 — Rule 7 (indeterminate) takes it first', () => {
		// Pins the Rule 7/8 boundary: 0.5 is caught by Rule 7's `>=`, matching
		// DEFAULT_MIN_CONFIDENCE (discover-brand-domains.ts) exactly, which is why
		// Rule 8 needs a sub-default min_confidence to ever be reached in production.
		const result = classifyCandidate(candidate({ domain: 'unrelated-domain.example', confidence: 0.5 }), TARGET);
		expect(result.bucket).toBe('indeterminate');
		expect(result.reasons.join(' ')).toMatch(/medium confidence, no strong infra signal/);
	});

	it('does NOT fire when an earlier rule already matches (Rule 8 is a fallback, not a priority path)', () => {
		// Same confidence band as the first case, but same registrar family as the
		// target with 2+ corroborating signals — Rule 4 intercepts before Rule 8 is
		// ever reached, proving Rule 8 is strictly the last resort.
		const result = classifyCandidate(
			candidate({
				domain: 'paypal-support.example',
				confidence: 0.3,
				registrar: 'MarkMonitor Inc.',
				signals: ['ns', 'san'],
			}),
			TARGET,
		);
		expect(result.bucket).toBe('consolidated');
		expect(result.reasons.join(' ')).not.toMatch(/low confidence, no strong infra signal/);
	});
});
