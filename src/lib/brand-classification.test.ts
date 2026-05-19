// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the brand-audit classification module.
 *
 * TDD-first: these tests define the desired behaviour. The classifier
 * (`brand-classification.ts`) must satisfy each rule below.
 *
 * Rules in priority order (first match wins):
 *   1. Subdomain of target → consolidated, 'Organizational Subdomain'
 *   2. Strong deterministic ownership signal (DKIM, redirect, SPF, CNAME, recursive SAN, app/bounty declarations) → consolidated
 *   3. DMARC RUA reports to target's domain → consolidated
 *   4. Same registrar family AND ≥2 corroborating signals → consolidated
 *   5. Registrar source is redacted/notfound AND no strong signals → indeterminate
 *   6. High confidence (≥0.85) + dmarc_rua-only signal (no infra share) → shadowIt
 *   7. Medium confidence (0.5–0.85), no strong signals → indeterminate
 *   8. Low confidence (<0.5), no strong signals → impersonation
 */

import { describe, it, expect } from 'vitest';
import {
	classifyCandidate,
	confidenceTier,
	isSubdomainOf,
	normalizeRegistrar,
	type CandidateInput,
	type TargetContext,
} from './brand-classification';

function target(overrides: Partial<TargetContext> = {}): TargetContext {
	return {
		domain: 'apple.com',
		registrar: 'MarkMonitor Inc.',
		registrarFamily: 'MarkMonitor',
		...overrides,
	};
}

function candidate(overrides: Partial<CandidateInput> = {}): CandidateInput {
	return {
		domain: 'apple.net',
		confidence: 0.5,
		signals: [],
		registrar: 'Unknown',
		registrarSource: 'unknown',
		...overrides,
	};
}

describe('normalizeRegistrar', () => {
	it('collapses MarkMonitor variants', () => {
		expect(normalizeRegistrar('MarkMonitor Inc.')).toBe('MarkMonitor');
		expect(normalizeRegistrar('markmonitor international canada ltd.')).toBe('MarkMonitor');
	});

	it('collapses Com Laude / NomIQ variants', () => {
		expect(normalizeRegistrar('Com Laude')).toBe('Com Laude');
		expect(normalizeRegistrar('Nom-IQ Ltd. dba Com Laude')).toBe('Com Laude');
	});

	it('collapses CSC Corporate Domains variants to "CSC" (not the legacy "BrandAudit" placeholder)', () => {
		// Surfaced 2026-05-19: production PDFs for brand-eta.com showed
		// `shared registrar family (BrandAudit) + 3 corroborating signals` when
		// CSC was the actual registrar. The legacy regex used 'BrandAudit' as a
		// placeholder name; rename to the real family identifier so analyst
		// reasons read truthfully.
		expect(normalizeRegistrar('CSC Corporate Domains, Inc.')).toBe('CSC');
		expect(normalizeRegistrar('CSC Corporate Domains Inc')).toBe('CSC');
		expect(normalizeRegistrar('CSC CORPORATE DOMAINS INC.')).toBe('CSC');
		expect(normalizeRegistrar('CSC Corporate Domains (Canada) Company')).toBe('CSC');
	});

	it('returns Unknown for empty / Unknown', () => {
		expect(normalizeRegistrar('')).toBe('Unknown');
		expect(normalizeRegistrar('Unknown')).toBe('Unknown');
	});

	it('preserves unrecognized registrars trimmed', () => {
		expect(normalizeRegistrar('  Random Registrar Ltd.  ')).toBe('Random Registrar Ltd.');
	});
});

describe('confidenceTier', () => {
	it('high tier for >= 0.85', () => {
		expect(confidenceTier(0.85)).toBe('high');
		expect(confidenceTier(0.95)).toBe('high');
		expect(confidenceTier(1)).toBe('high');
	});

	it('medium tier for 0.5–0.85', () => {
		expect(confidenceTier(0.5)).toBe('medium');
		expect(confidenceTier(0.84)).toBe('medium');
	});

	it('low tier for < 0.5', () => {
		expect(confidenceTier(0)).toBe('low');
		expect(confidenceTier(0.49)).toBe('low');
	});
});

describe('isSubdomainOf', () => {
	it('exact match returns true', () => {
		expect(isSubdomainOf('apple.com', 'apple.com')).toBe(true);
	});

	it('subdomain returns true', () => {
		expect(isSubdomainOf('dmarc.apple.com', 'apple.com')).toBe(true);
		expect(isSubdomainOf('mail.dmarc.apple.com', 'apple.com')).toBe(true);
	});

	it('sibling domain returns false', () => {
		expect(isSubdomainOf('apple.net', 'apple.com')).toBe(false);
		expect(isSubdomainOf('badapple.com', 'apple.com')).toBe(false);
	});
});

describe('classifyCandidate', () => {
	describe('Rule 1: subdomain of target', () => {
		it('subdomain → consolidated with Organizational Subdomain note', () => {
			const c = candidate({ domain: 'dmarc.apple.com', confidence: 0.5 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.note).toBe('Organizational Subdomain');
		});

		it('subdomain wins even when registrar is Unknown', () => {
			const c = candidate({ domain: 'dmarc.apple.com', registrar: 'Unknown' });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
		});

		it('subdomain wins even when confidence is very low', () => {
			const c = candidate({ domain: 'mail.apple.com', confidence: 0.01 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
		});
	});

	describe('Rule 2: deterministic ownership signal', () => {
		it('SAN signal alone is medium evidence, not an automatic consolidation shortcut', () => {
			const c = candidate({
				domain: 'apple.io',
				signals: ['san'],
				confidence: 0.64,
				registrar: 'Tucows.com Co.',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.reasons.join(' ')).toMatch(/medium confidence/i);
		});

		it('NS signal alone is medium evidence, not an automatic consolidation shortcut', () => {
			const c = candidate({ domain: 'apple.de', signals: ['ns'], confidence: 0.78 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.reasons.join(' ')).toMatch(/medium confidence/i);
		});

		it('DKIM key reuse → consolidated', () => {
			const c = candidate({ domain: 'apple.fr', signals: ['dkim_key_reuse'], confidence: 0.8 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/DKIM/i);
		});

		it('HTTP redirect to the seed → consolidated', () => {
			const c = candidate({
				domain: 'apple.co',
				signals: ['http_redirect', 'markov_gen'],
				confidence: 0.95,
				registrar: 'Unknown',
				registrarSource: 'lookup_failed',
				lookalikeScore: 0.96,
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/redirect/i);
		});

		it('CNAME alignment to the seed → consolidated', () => {
			const c = candidate({ domain: 'appleapp.net', signals: ['cname_alignment'], confidence: 0.9 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/CNAME/i);
		});

		it('candidate SPF include of seed policy → consolidated', () => {
			const c = candidate({ domain: 'apple-mail.net', signals: ['spf_include'], confidence: 0.85 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/SPF/i);
		});

		it('seed SPF delegation to another apex → shadowIt', () => {
			const c = candidate({ domain: 'vendor-mail.example', signals: ['spf_include_seed'], confidence: 0.85 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('shadowIt');
			expect(result.reasons.join(' ')).toMatch(/SPF/i);
		});

		it('strong signal wins even when registrarSource is redacted', () => {
			const c = candidate({
				domain: 'apple.de',
				signals: ['dkim_key_reuse'],
				confidence: 0.95,
				registrarSource: 'redacted',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('consolidated');
		});
	});

	describe('Rule 3: DMARC RUA signal alone is consolidation evidence', () => {
		it('high-confidence dmarc_rua alone → consolidated', () => {
			const c = candidate({ domain: 'apple.es', signals: ['dmarc_rua'], confidence: 0.95 });
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/DMARC/i);
		});

		it('low-confidence dmarc_rua does NOT consolidate alone', () => {
			const c = candidate({ domain: 'apple.es', signals: ['dmarc_rua'], confidence: 0.3 });
			expect(classifyCandidate(c, target()).bucket).not.toBe('consolidated');
		});
	});

	describe('Rule 4: same registrar family + ≥2 corroborating signals', () => {
		it('matching family + generated seed plus one real signal does not consolidate', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['markov_gen', 'dmarc_rua'],
				confidence: 0.6,
				registrar: 'MarkMonitor Inc.',
				registrarSource: 'rdap',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.reasons.join(' ')).toMatch(/medium confidence/i);
		});

		it('matching family + 2 non-generated corroborating signals → consolidated', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['ns', 'dmarc_rua'],
				confidence: 0.84,
				registrar: 'MarkMonitor Inc.',
				registrarSource: 'rdap',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/registrar family/i);
		});

		it('matching family + only 1 signal does NOT consolidate (MarkMonitor manages many brands)', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['markov_gen'],
				confidence: 0.3,
				registrar: 'MarkMonitor Inc.',
				registrarSource: 'rdap',
			});
			expect(classifyCandidate(c, target()).bucket).not.toBe('consolidated');
		});

		it('both Unknown registrar → does NOT consolidate even with multiple signals', () => {
			const c = candidate({
				domain: 'apple.kr',
				signals: ['markov_gen', 'dmarc_rua'],
				confidence: 0.5,
				registrar: 'Unknown',
				registrarSource: 'unknown',
			});
			const t = target({ registrarFamily: 'Unknown', registrar: 'Unknown' });
			expect(classifyCandidate(c, t).bucket).not.toBe('consolidated');
		});

		it('same IANA registrar ID + 2 signals → consolidated even when registrar names differ', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['ns', 'mx_overlap'],
				confidence: 0.6,
				registrar: 'Corporation Service Company',
				registrarIanaId: '299',
				registrarSource: 'rdap',
			});
			const t = target({
				registrar: 'CSC Corporate Domains, Inc.',
				registrarFamily: 'CSC',
				registrarIanaId: '299',
			});

			const result = classifyCandidate(c, t);
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/registrar family/i);
		});

		it('different IANA registrar IDs do not consolidate despite similar registrar names', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['ns', 'mx_overlap'],
				confidence: 0.6,
				registrar: 'Example Corporate Domains LLC',
				registrarIanaId: '146',
				registrarSource: 'rdap',
			});
			const t = target({
				registrar: 'CSC Corporate Domains, Inc.',
				registrarFamily: 'CSC',
				registrarIanaId: '299',
			});

			expect(classifyCandidate(c, t).bucket).not.toBe('consolidated');
		});

		it('absent IANA registrar IDs do not create false positive family matches from weak tokens', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['ns', 'mx_overlap'],
				confidence: 0.6,
				registrar: 'Example Consumer Domains LLC',
				registrarSource: 'rdap',
			});
			const t = target({
				registrar: 'Example Corporate Domains Inc.',
				registrarFamily: 'Example Corporate Domains Inc.',
			});

			expect(classifyCandidate(c, t).bucket).not.toBe('consolidated');
		});
	});

	describe('Rule 5: redacted / notfound → indeterminate when no strong signals', () => {
		it('redacted source + no strong signals → indeterminate', () => {
			const c = candidate({
				domain: 'apple.de',
				signals: ['markov_gen'],
				confidence: 0.6,
				registrar: 'Unknown',
				registrarSource: 'redacted',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
		});

		it('notfound source + no strong signals → indeterminate', () => {
			const c = candidate({
				domain: 'apple.kp',
				signals: [],
				confidence: 0.6,
				registrar: 'Unknown',
				registrarSource: 'notfound',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('indeterminate');
		});
	});

	describe('Rule 6: high-confidence non-infra signal → shadowIt', () => {
		it('high confidence + only dmarc_rua + different registrar → shadowIt', () => {
			// Edge case: candidate REPORTS DMARC to seed but doesn't share certs/NS/DKIM.
			// Could be a 3rd-party operator (legitimate sprawl) or noise — flag for review.
			const c = candidate({
				domain: 'apple-partner.com',
				signals: ['dmarc_rua'],
				confidence: 0.78,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('shadowIt');
		});

		it('markov plus broad MX platform alone stays indeterminate instead of ARR-bearing shadowIt', () => {
			const c = candidate({
				domain: 'upps.com',
				signals: ['markov_gen', 'mx_platform'],
				confidence: 0.5545,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
				sharedMxPlatform: 'm365',
				lookalikeScore: 0,
			});
			const t = target({
				domain: 'brand-zeta.com',
				registrar: 'CSC Corporate Domains, Inc.',
				registrarFamily: 'CSC',
			});

			expect(classifyCandidate(c, t).bucket).toBe('indeterminate');
		});

		it('weak-only evidence observations stay indeterminate with a clear ownership-gate reason', () => {
			const c = candidate({
				domain: 'upps.com',
				signals: ['markov_gen', 'mx_platform'],
				confidence: 0.5545,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
				sharedMxPlatform: 'm365',
				evidenceObservations: [
					{ signal: 'markov_gen' },
					{ signal: 'mx_platform', metadata: { sharedMxPlatform: 'm365' } },
				],
			});
			const result = classifyCandidate(c, target({ domain: 'brand-zeta.com' }));

			expect(result.bucket).toBe('indeterminate');
			expect(result.reasons.join(' ')).toMatch(/weak evidence did not clear ownership gate/i);
		});

		it('same registrar plus generated lookalike, broad MX, and NS stays indeterminate when ownership gate fails', () => {
			const c = candidate({
				domain: 'walmart.org',
				signals: ['active_lookalike', 'mx_platform', 'ns'],
				confidence: 0.775,
				registrar: 'MarkMonitor Inc.',
				registrarSource: 'rdap',
				sharedMxPlatform: 'm365',
				evidenceObservations: [
					{ signal: 'active_lookalike' },
					{ signal: 'mx_platform', confidence: 0.55, metadata: { sharedMxPlatform: 'm365' } },
					{ signal: 'ns', confidence: 0.5 },
				],
			});
			const t = target({
				domain: 'brand-alpha.com',
				registrar: 'MarkMonitor Inc.',
				registrarFamily: 'MarkMonitor',
			});
			const result = classifyCandidate(c, t);

			expect(result.bucket).toBe('indeterminate');
			expect(result.reasons.join(' ')).toMatch(/weak evidence did not clear ownership gate/i);
		});

		it('shared MX platform can become shadowIt when corroborated by strong visual similarity and another signal', () => {
			const c = candidate({
				domain: 'examp1e-pay.com',
				signals: ['markov_gen', 'mx_platform'],
				confidence: 0.5545,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
				sharedMxPlatform: 'proofpoint',
				lookalikeScore: 0.91,
			});
			const t = target({ domain: 'example.com', registrarFamily: 'MarkMonitor' });

			const result = classifyCandidate(c, t);
			expect(result.bucket).toBe('shadowIt');
			expect(result.reasons).toContain('lookalike score 0.91 corroborates shared MX platform');
		});

		it('shared MX platform can become shadowIt when the caller explicitly asserted the candidate', () => {
			const c = candidate({
				domain: 'example-vendor.net',
				signals: ['mx_platform'],
				confidence: 0.55,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
				sharedMxPlatform: 'm365',
				callerAsserted: true,
			});

			expect(classifyCandidate(c, target({ domain: 'example.com' })).bucket).toBe('shadowIt');
		});
	});

	describe('Rule 7: medium confidence + no strong signals → indeterminate', () => {
		it('medium confidence + only markov_gen → indeterminate', () => {
			const c = candidate({
				domain: 'apple-shop.com',
				signals: ['markov_gen'],
				confidence: 0.55,
				registrar: 'GoDaddy.com, LLC',
				registrarSource: 'rdap',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('indeterminate');
		});
	});

	describe('Rule 8: low confidence + no strong signals → impersonation', () => {
		it('low confidence → impersonation', () => {
			const c = candidate({
				domain: 'apple-fake.xyz',
				signals: ['markov_gen'],
				confidence: 0.15,
				registrar: 'Namecheap, Inc.',
				registrarSource: 'rdap',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('impersonation');
		});
	});

	describe('Confidence tier metadata', () => {
		it('tier matches the candidate combined confidence', () => {
			expect(classifyCandidate(candidate({ confidence: 0.95 }), target()).confidenceTier).toBe('high');
			expect(classifyCandidate(candidate({ confidence: 0.6 }), target()).confidenceTier).toBe('medium');
			expect(classifyCandidate(candidate({ confidence: 0.2 }), target()).confidenceTier).toBe('low');
		});
	});

	describe('Signal 4: registrant organization match', () => {
		it('exact registrant org match → consolidated, regardless of registrar family', () => {
			const c = candidate({
				domain: 'apple.uk',
				signals: ['markov_gen'],
				confidence: 0.3,
				registrar: 'Different Registrar Ltd.',
				registrant: 'Apple Inc.',
			});
			const t = target({ registrant: 'Apple Inc.' });
			const result = classifyCandidate(c, t);
			expect(result.bucket).toBe('consolidated');
			expect(result.reasons.join(' ')).toMatch(/registrant/i);
		});

		it('normalized registrant match (Inc/Ltd/Corp variants)', () => {
			const c = candidate({ domain: 'apple.it', registrant: 'apple, inc' });
			const t = target({ registrant: 'Apple Inc.' });
			expect(classifyCandidate(c, t).bucket).toBe('consolidated');
		});

		it('different registrants → no consolidation boost', () => {
			const c = candidate({
				domain: 'apple-not.com',
				signals: ['markov_gen'],
				confidence: 0.3,
				registrant: 'Someone Else LLC',
			});
			const t = target({ registrant: 'Apple Inc.' });
			expect(classifyCandidate(c, t).bucket).not.toBe('consolidated');
		});

		it('redacted (null) registrant on candidate → no registrant rule fires (falls through to other rules)', () => {
			const c = candidate({
				domain: 'apple.de',
				signals: ['markov_gen'],
				confidence: 0.6,
				registrar: 'Unknown',
				registrarSource: 'redacted',
				registrant: null,
			});
			const t = target({ registrant: 'Apple Inc.' });
			// Falls through to Rule 5 (redacted source → indeterminate)
			expect(classifyCandidate(c, t).bucket).toBe('indeterminate');
		});
	});

	// Phase 3 of registrar-coverage-tdd-plan.md — classifier learns the difference
	// between deterministic 'unknown' states (redacted, notfound) and a transient
	// failure that should be retried (lookup_failed). The bucket stays
	// `indeterminate` for both deterministic cases (no new buckets — keeps the
	// downstream API stable), but `note` differentiates them so analysts and the
	// retry hook (Phase 2b) can act.
	describe('Phase 3: registrarSource differentiation', () => {
		it('lookup_failed (no strong signals, medium confidence) → indeterminate with note=needs_retry', () => {
			const c = candidate({
				domain: 'flaky.net',
				confidence: 0.6,
				signals: ['markov_gen'],
				registrar: 'Unknown',
				registrarSource: 'lookup_failed',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.note).toBe('needs_retry');
			expect(result.reasons.join(' ').toLowerCase()).toMatch(/retry|lookup/);
		});

		it('lookup_failed with deterministic ownership signal → consolidated (Rule 2 still wins; retry is moot)', () => {
			const c = candidate({
				domain: 'redirected.com',
				signals: ['http_redirect'],
				registrarSource: 'lookup_failed',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('consolidated');
		});

		it('lookup_failed with high lookalike score → impersonation (Rule 4.6 still fires before Rule 5)', () => {
			const c = candidate({
				domain: 'appel.com',
				confidence: 0.4,
				lookalikeScore: 0.92,
				registrar: 'Different Registrar Ltd.',
				registrarSource: 'lookup_failed',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('impersonation');
		});

		it('redacted (no strong signals) → indeterminate with note=redacted (distinguishable from notfound)', () => {
			const c = candidate({
				domain: 'apple.de',
				confidence: 0.6,
				signals: ['markov_gen'],
				registrar: 'Unknown',
				registrarSource: 'redacted',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.note).toBe('redacted');
		});

		it('notfound (no strong signals) → indeterminate with note=notfound (distinguishable from redacted)', () => {
			const c = candidate({
				domain: 'apple-cz.com',
				confidence: 0.6,
				signals: ['markov_gen'],
				registrar: 'Unknown',
				registrarSource: 'notfound',
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('indeterminate');
			expect(result.note).toBe('notfound');
		});

		it('redacted + high lookalike score → impersonation (Rule 4.6 fires before Rule 5)', () => {
			const c = candidate({
				domain: 'appel.de',
				confidence: 0.4,
				lookalikeScore: 0.92,
				registrar: 'Unknown',
				registrarSource: 'redacted',
			});
			expect(classifyCandidate(c, target()).bucket).toBe('impersonation');
		});
	});

	// Task 8 — brand-discovery tier routing.
	// When `evidenceObservations` carry a `tier` field (0/1/2/4), the classifier
	// short-circuits BEFORE the legacy rules and routes by tier provenance.
	// Tier-less observations preserve the existing Tier 3 behaviour byte-identically.
	describe('brand-discovery tier routing (Task 8)', () => {
		it('routes tier 0 observation to consolidated with tier=0', () => {
			const c = candidate({
				domain: 'apple-sub.example',
				confidence: 0.4,
				signals: [],
				evidenceObservations: [{ signal: 'http_redirect', confidence: 1.0, tier: 0 }],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBe(0);
		});

		it('routes tier 1 + specificityScore >= 0.5 to consolidated with tier=1', () => {
			const c = candidate({
				domain: 'apple-graph.example',
				confidence: 0.3,
				signals: [],
				evidenceObservations: [{ signal: 'ns', confidence: 0.8, tier: 1, specificityScore: 0.9 }],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBe(1);
		});

		it('falls through to legacy rules when tier 1 obs has specificityScore < 0.5', () => {
			// Low specificity → not enough confidence to claim graph ownership;
			// the legacy classifier path takes over and routes by other rules.
			const c = candidate({
				domain: 'apple-weakgraph.example',
				confidence: 0.3,
				signals: [],
				registrar: 'Unknown',
				registrarSource: 'unknown',
				evidenceObservations: [{ signal: 'ns', confidence: 0.5, tier: 1, specificityScore: 0.2 }],
			});
			const result = classifyCandidate(c, target());
			// With no strong signals and low confidence + unknown registrar, the legacy
			// Rule 8 path lands on impersonation. The key invariant: tier is NOT set.
			expect(result.tier).toBeUndefined();
		});

		it('routes tier 2 observation to consolidated with tier=2', () => {
			const c = candidate({
				domain: 'apple-rdap.example',
				confidence: 0.6,
				signals: [],
				evidenceObservations: [{ signal: 'dmarc_rua', confidence: 0.9, tier: 2 }],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBe(2);
		});

		it('routes only-tier-4 observations to impersonationSurface with tier=4', () => {
			const c = candidate({
				domain: 'appel.example',
				confidence: 0.3,
				signals: [],
				registrar: 'Different Reg',
				lookalikeScore: 0.9,
				evidenceObservations: [{ signal: 'active_lookalike', confidence: 0.3, tier: 4 }],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('impersonationSurface');
			expect(result.tier).toBe(4);
		});

		it('mutual exclusion: tier 2 + tier 4 together → consolidated (owned wins over impersonation)', () => {
			const c = candidate({
				domain: 'apple-mixed.example',
				confidence: 0.5,
				signals: [],
				evidenceObservations: [
					{ signal: 'dmarc_rua', confidence: 0.9, tier: 2 },
					{ signal: 'active_lookalike', confidence: 0.3, tier: 4 },
				],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBe(2);
		});

		it('mutual exclusion: tier 0 + tier 4 together → consolidated tier=0 (highest provenance wins)', () => {
			const c = candidate({
				domain: 'apple-mixed0.example',
				confidence: 0.5,
				signals: [],
				evidenceObservations: [
					{ signal: 'active_lookalike', confidence: 0.3, tier: 4 },
					{ signal: 'http_redirect', confidence: 1.0, tier: 0 },
				],
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBe(0);
		});

		it('preserves legacy classifier output for observations with no tier field (Tier 3 fallback)', () => {
			// Without any tier-tagged observation, the new routing block is bypassed
			// entirely and the existing rules apply unchanged. This is the byte-identical
			// regression guard against the "do not change legacy paths" hard rule.
			const c = candidate({
				domain: 'apple.net',
				confidence: 0.9,
				signals: ['dkim_key_reuse'],
				registrar: 'MarkMonitor Inc.',
				registrarSource: 'rdap',
				// No evidenceObservations / no tier on them.
			});
			const result = classifyCandidate(c, target());
			expect(result.bucket).toBe('consolidated');
			expect(result.tier).toBeUndefined();
			expect(result.reasons).toContain('shared DKIM key');
		});
	});
});
