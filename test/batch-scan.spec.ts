import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

describe('batchScan', () => {
	beforeEach(() => {
		globalThis.fetch = vi.fn().mockResolvedValue(new Response('OK', { status: 200, headers: { 'content-type': 'text/plain' } }));
	});

	it('should scan multiple domains and return one result per domain', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com', 'test.com'], { kv: env.SCAN_CACHE });
		expect(results).toHaveLength(2);
		expect(results[0].domain).toBe('example.com');
		expect(results[1].domain).toBe('test.com');
		expect(typeof results[0].score).toBe('number');
		expect(typeof results[0].grade).toBe('string');
	});

	it('should reject more than 10 domains', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const tooMany = Array.from({ length: 11 }, (_, i) => `domain${i}.com`);
		await expect(batchScan(tooMany)).rejects.toThrow(/max.*10/i);
	});

	it('should return error result for invalid domain without throwing', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');
		const results = await batchScan(['example.com', 'not--valid--domain!@#'], { kv: env.SCAN_CACHE });
		const errorResult = results.find((r) => r.error);
		expect(errorResult).toBeDefined();
		expect(errorResult!.score).toBe(0);
	});
});
