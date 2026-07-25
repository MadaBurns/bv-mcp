import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

describe('compareDomains', () => {
	beforeEach(() => {
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('OK', { status: 200 }));
	});

	it('should compare 2 domains and return structured result', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'test.com'], { kv: env.SCAN_CACHE });
		expect(result.domains).toHaveLength(2);
		expect(typeof result.winner === 'string' || result.winner === null).toBe(true);
		expect(Array.isArray(result.commonGaps)).toBe(true);
		expect(Array.isArray(result.categoryComparison)).toBe(true);
	});

	it('should reject fewer than 2 domains', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		await expect(compareDomains(['only.com'])).rejects.toThrow(/at least 2/i);
	});

	it('should reject more than 5 domains', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		await expect(compareDomains(['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com'])).rejects.toThrow(/max.*5/i);
	});

	it('should include errors for invalid domains without throwing', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'invalid!@#domain'], { kv: env.SCAN_CACHE });
		expect(Object.keys(result.errors).length).toBeGreaterThan(0);
	});

	it('returns null winner when only 1 domain scanned successfully', async () => {
		const { compareDomains } = await import('../src/tools/compare-domains');
		const result = await compareDomains(['example.com', 'invalid!@#domain'], { kv: env.SCAN_CACHE });
		// Only example.com scans successfully; winner should be null (< 2 valid results)
		expect(result.winner).toBeNull();
	});

	it('excludes an ungraded domain from ranking and never renders a fabricated F for it', async () => {
		const { compareDomains, formatDomainComparison } = await import('../src/tools/compare-domains');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const scanStub = (async (domain: string): Promise<any> => ({
			domain,
			score:
				domain === 'ungraded.com'
					? { overall: 0, grade: 'N/A', summary: 'unscored', categoryScores: {}, findings: [] }
					: { overall: 80, grade: 'B', summary: 'ok', categoryScores: {}, findings: [] },
			checks: domain === 'ungraded.com' ? [] : [{ category: 'spf', passed: true, score: 80, findings: [] }],
			maturity: { stage: 2, label: 'Baseline', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		})) as any;

		const result = await compareDomains(['graded.com', 'ungraded.com'], { scanFn: scanStub });

		// `measured: false` for the unscored domain must exclude it from the winner race,
		// so a 2-domain compare has only ONE rankable entry and therefore no winner.
		expect(result.winner).toBeNull();
		expect(result.grades['graded.com']).toBe('B');

		const text = formatDomainComparison(result, 'compact');
		expect(text).toContain('not measured');
		expect(text).not.toContain('ungraded.com                              0/100');
	});
});
