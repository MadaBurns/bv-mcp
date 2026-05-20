// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `renderBrandAuditHtml` — pure HTML template.
 *
 * Focus: empty-bucket transparency. Reviewers reading a brand-audit PDF
 * must be able to distinguish "classifier ran and found nothing" from
 * "this code path didn't fire" — surfaced via `data-state` on each
 * bucket's <table>.
 */

import { describe, it, expect } from 'vitest';
import { renderBrandAuditHtml, type BrandCandidateRow } from '../src/lib/brand-audit-html-template';

const baseInput = {
	target: 'example.com',
	dateIso: '2026-05-15T00:00:00Z',
	serverVersion: '2.21.1',
};

const consolidatedRow: BrandCandidateRow = {
	domain: 'a.example.com',
	bucket: 'consolidated',
	relationshipType: 'owned_primary',
	registrar: 'X',
	registrarSource: 'rdap',
	reasons: ['NS overlap'],
	signals: ['ns_overlap'],
	combinedConfidence: 0.9,
};

describe('empty-bucket transparency', () => {
	it('marks an empty bucket that the classifier exercised as empty-verified', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [consolidatedRow],
			bucketsExercised: new Set(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']),
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="empty-verified"/);
		expect(html).toMatch(/data-bucket="impersonation"[^>]*data-state="empty-verified"/);
	});

	it('marks an empty bucket that the classifier did NOT exercise as not-run', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [],
			bucketsExercised: new Set(['consolidated']),
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="not-run"/);
	});

	it('omits the data-state attribute when the bucket has candidates', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [
				{
					domain: 'a.example.com',
					bucket: 'shadowIt',
					relationshipType: 'owned_off_primary_registrar',
					registrar: 'X',
					registrarSource: 'rdap',
					reasons: [],
					signals: [],
					combinedConfidence: 0.9,
				},
			],
			bucketsExercised: new Set(['shadowIt']),
		});
		// The shadowIt section has rows, so no empty-state badge
		expect(html).not.toMatch(/data-bucket="shadowIt"[^>]*data-state=/);
	});

	it('back-compat: input without bucketsExercised treats every empty bucket as empty-verified', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [],
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="empty-verified"/);
	});

	it('does NOT regress existing structure (citations column still present)', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
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
		expect(html).toContain('Sources'); // header
		expect(html).toContain('crt.sh'); // citation link
		expect(html).toContain('rdap');
	});
});
