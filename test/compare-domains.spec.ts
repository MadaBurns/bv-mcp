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
});
