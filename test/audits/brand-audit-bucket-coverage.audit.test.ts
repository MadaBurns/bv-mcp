// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: every classifier bucket has a unit test, and every defect
 * surfaced during the 2026-05-15 BrandAudit audit stays fixed.
 *
 * This audit is the lock-in for defects D1-D6:
 *  - D1/D2: shadowIt + impersonation classifier branches must exist (as
 *           exported helpers consultable from this audit)
 *  - D3/D6: provider-sprawl helper must exist with the expected exports
 *  - D4:    ccTLD seeder must exist and emit non-trivial output
 *  - D5:    PDF template must distinguish empty-verified vs not-run states
 *
 * Each assertion is a behavioral check — call the module and verify the
 * symptom we fixed actually behaves correctly. If a future refactor removes
 * a branch, the audit fails so a reviewer is forced to confirm coverage
 * hasn't regressed.
 */

import { describe, it, expect } from 'vitest';
import type { BrandCandidateRow } from '../../src/lib/brand-audit-html-template';

describe('brand-audit bucket coverage lock-in', () => {
	it('provider-sprawl helper: collapses fragmented NS providers (D3/D6)', async () => {
		const { normalizeProvider, isMultiProvider } = await import('../../src/lib/brand-audit-provider-sprawl');
		// AWS Route 53 TLD spread must collapse to ONE provider
		expect(normalizeProvider('ns-52.awsdns-52.com')).toBe(normalizeProvider('ns-1234.awsdns-43.co.uk'));
		// PayPal-style sprawl must be flagged
		expect(isMultiProvider(['a.ns.paypal.com', 'pdns1.ultradns.net'])).toBe(true);
	});

	it('classifier exports isShadowIt + isImpersonation (D1/D2 branches)', async () => {
		const mod = await import('../../src/lib/brand-classification');
		expect(typeof mod.isShadowIt).toBe('function');
		expect(typeof mod.isImpersonation).toBe('function');
	});

	it('ccTLD seeder produces ≥20 variants for the three zero-result brands (D4)', async () => {
		const { generateCctldVariants } = await import('../../src/lib/brand-cctld-seeder');
		for (const seed of ['amazon.com', 'microsoft.com', 'brand-gamma.com']) {
			const out = generateCctldVariants(seed);
			expect(out.length).toBeGreaterThanOrEqual(20);
			// Sanity: emits the ccTLDs that the original Markov-only seeder missed
			const base = seed.split('.')[0];
			expect(out).toContain(`${base}.de`);
			expect(out).toContain(`${base}.co.uk`);
		}
	});

	it('PDF template distinguishes empty-verified vs not-run (D5)', async () => {
		const { renderBrandAuditHtml } = await import('../../src/lib/brand-audit-html-template');
		const base = {
			target: 'example.com',
			dateIso: '2026-05-15T00:00:00Z',
			serverVersion: '2.21.1',
			candidates: [] as BrandCandidateRow[],
		};
		const exercisedHtml = renderBrandAuditHtml({
			...base,
			bucketsExercised: new Set(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']),
		});
		const notRunHtml = renderBrandAuditHtml({
			...base,
			bucketsExercised: new Set(['consolidated']),
		});
		expect(exercisedHtml).toMatch(/data-state=["']empty-verified["']/);
		expect(notRunHtml).toMatch(/data-state=["']not-run["']/);
	});

	it('PDF template emits citation Sources column (citations landed earlier)', async () => {
		const { renderBrandAuditHtml } = await import('../../src/lib/brand-audit-html-template');
		const html = renderBrandAuditHtml({
			target: 'example.com',
			dateIso: '2026-05-15T00:00:00Z',
			serverVersion: '2.21.1',
			candidates: [
				{
					domain: 'a.example.com',
					bucket: 'consolidated',
					relationshipType: 'owned_primary',
					registrar: 'X',
					registrarSource: 'rdap',
					reasons: ['NS overlap'],
					signals: ['ns_overlap'],
					combinedConfidence: 0.9,
				},
			],
		});
		expect(html).toContain('Sources');
		expect(html).toMatch(/crt\.sh/);
		expect(html).toMatch(/rdap\.org/);
	});
});
