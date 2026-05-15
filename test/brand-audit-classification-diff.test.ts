// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the classification hash + diff helpers used by the brand-audit
 * watch webhook delivery path.
 *
 * Both functions are pure — no I/O, no clock. The hash is deterministic for
 * any reordering of the input candidate list; the diff compares two hashes
 * implicitly via the candidate sets they describe.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

function makeResult(candidates: Array<{ domain: string; bucket: string }>): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: candidates.map((c) => ({
			category: 'brand_discovery',
			title: `Candidate: ${c.domain}`,
			severity: 'info',
			detail: '',
			metadata: { candidate: c.domain, bucket: c.bucket, signals: ['ns'], combinedConfidence: 0.9, registrar: 'X', registrarSource: 'rdap' },
		})),
	};
}

describe('computeClassificationHash', () => {
	it('returns a 64-char hex string', async () => {
		const { computeClassificationHash } = await import('../src/lib/brand-audit-classification-diff');
		const result = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const hash = await computeClassificationHash(result);
		expect(hash).toMatch(/^[a-f0-9]{64}$/);
	});

	it('is order-independent (same set of candidates → same hash)', async () => {
		const { computeClassificationHash } = await import('../src/lib/brand-audit-classification-diff');
		const a = makeResult([
			{ domain: 'a.com', bucket: 'consolidated' },
			{ domain: 'b.com', bucket: 'shadowIt' },
		]);
		const b = makeResult([
			{ domain: 'b.com', bucket: 'shadowIt' },
			{ domain: 'a.com', bucket: 'consolidated' },
		]);
		expect(await computeClassificationHash(a)).toBe(await computeClassificationHash(b));
	});

	it('differs when bucket changes for the same domain', async () => {
		const { computeClassificationHash } = await import('../src/lib/brand-audit-classification-diff');
		const a = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const b = makeResult([{ domain: 'a.com', bucket: 'shadowIt' }]);
		expect(await computeClassificationHash(a)).not.toBe(await computeClassificationHash(b));
	});

	it('differs when candidates are added or removed', async () => {
		const { computeClassificationHash } = await import('../src/lib/brand-audit-classification-diff');
		const a = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const b = makeResult([
			{ domain: 'a.com', bucket: 'consolidated' },
			{ domain: 'b.com', bucket: 'shadowIt' },
		]);
		expect(await computeClassificationHash(a)).not.toBe(await computeClassificationHash(b));
	});

	it('ignores non-candidate findings (summary rows)', async () => {
		const { computeClassificationHash } = await import('../src/lib/brand-audit-classification-diff');
		const withCandidate = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const withSummary: CheckResult = {
			...withCandidate,
			findings: [
				{ category: 'brand_discovery', title: 'summary', severity: 'info', detail: '', metadata: { summary: true } },
				...withCandidate.findings,
			],
		};
		expect(await computeClassificationHash(withCandidate)).toBe(await computeClassificationHash(withSummary));
	});
});

describe('computeDiff', () => {
	it('finds added candidates (in current but not previous)', async () => {
		const { computeDiff } = await import('../src/lib/brand-audit-classification-diff');
		const previous = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const current = makeResult([
			{ domain: 'a.com', bucket: 'consolidated' },
			{ domain: 'b.com', bucket: 'shadowIt' },
		]);
		const diff = computeDiff(previous, current);
		expect(diff.added).toEqual([{ domain: 'b.com', bucket: 'shadowIt' }]);
		expect(diff.removed).toEqual([]);
		expect(diff.modified).toEqual([]);
	});

	it('finds removed candidates (in previous but not current)', async () => {
		const { computeDiff } = await import('../src/lib/brand-audit-classification-diff');
		const previous = makeResult([
			{ domain: 'a.com', bucket: 'consolidated' },
			{ domain: 'b.com', bucket: 'shadowIt' },
		]);
		const current = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const diff = computeDiff(previous, current);
		expect(diff.removed).toEqual([{ domain: 'b.com', bucket: 'shadowIt' }]);
		expect(diff.added).toEqual([]);
		expect(diff.modified).toEqual([]);
	});

	it('finds modified candidates (same domain, different bucket)', async () => {
		const { computeDiff } = await import('../src/lib/brand-audit-classification-diff');
		const previous = makeResult([{ domain: 'a.com', bucket: 'shadowIt' }]);
		const current = makeResult([{ domain: 'a.com', bucket: 'consolidated' }]);
		const diff = computeDiff(previous, current);
		expect(diff.modified).toEqual([{ domain: 'a.com', bucket: 'consolidated', previousBucket: 'shadowIt' }]);
		expect(diff.added).toEqual([]);
		expect(diff.removed).toEqual([]);
	});

	it('handles all three change types in one diff', async () => {
		const { computeDiff } = await import('../src/lib/brand-audit-classification-diff');
		const previous = makeResult([
			{ domain: 'stay-same.com', bucket: 'consolidated' },
			{ domain: 'gone.com', bucket: 'shadowIt' },
			{ domain: 'shifted.com', bucket: 'shadowIt' },
		]);
		const current = makeResult([
			{ domain: 'stay-same.com', bucket: 'consolidated' },
			{ domain: 'new.com', bucket: 'impersonation' },
			{ domain: 'shifted.com', bucket: 'consolidated' },
		]);
		const diff = computeDiff(previous, current);
		expect(diff.added).toEqual([{ domain: 'new.com', bucket: 'impersonation' }]);
		expect(diff.removed).toEqual([{ domain: 'gone.com', bucket: 'shadowIt' }]);
		expect(diff.modified).toEqual([{ domain: 'shifted.com', bucket: 'consolidated', previousBucket: 'shadowIt' }]);
	});

	it('empty diff when classifications are identical', async () => {
		const { computeDiff } = await import('../src/lib/brand-audit-classification-diff');
		const both = makeResult([
			{ domain: 'a.com', bucket: 'consolidated' },
			{ domain: 'b.com', bucket: 'shadowIt' },
		]);
		const diff = computeDiff(both, both);
		expect(diff).toEqual({ added: [], removed: [], modified: [] });
	});
});
