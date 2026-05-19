// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { createDiscoveryDnsContext } from '../../../src/tenants/discovery/dns-context';
import type { DohResponse } from '../../../src/lib/dns-types';

const ok = (data: string): DohResponse => ({
	Status: 0,
	TC: false,
	RD: true,
	RA: true,
	AD: false,
	CD: false,
	Question: [],
	Answer: [{ name: 'example.com', type: 2, TTL: 300, data }],
});

describe('createDiscoveryDnsContext', () => {
	it('deduplicates concurrent identical queries within one audit', async () => {
		let calls = 0;
		const ctx = createDiscoveryDnsContext({
			maxConcurrent: 2,
			baseQuery: async () => {
				calls++;
				await new Promise((resolve) => setTimeout(resolve, 5));
				return ok('ns1.example.net.');
			},
		});

		const [a, b] = await Promise.all([ctx.query('example.com', 'NS'), ctx.query('example.com', 'NS')]);

		expect(a).toEqual(b);
		expect(calls).toBe(1);
		expect(ctx.metrics()).toMatchObject({ queries: 2, cacheHits: 1, errors: 0 });
	});

	it('reuses cached results for sequential normalized queries', async () => {
		let calls = 0;
		const ctx = createDiscoveryDnsContext({
			maxConcurrent: 2,
			baseQuery: async () => {
				calls++;
				return ok('ns1.example.net.');
			},
		});

		const first = await ctx.query('Example.COM.', 'NS');
		const second = await ctx.query('example.com', 'NS');

		expect(second).toEqual(first);
		expect(calls).toBe(1);
		expect(ctx.metrics()).toMatchObject({ queries: 2, cacheHits: 1, errors: 0 });
	});

	it('evicts rejected promises and allows retry', async () => {
		let calls = 0;
		const ctx = createDiscoveryDnsContext({
			maxConcurrent: 2,
			baseQuery: async () => {
				calls++;
				if (calls === 1) throw new Error('temporary DNS failure');
				return ok('ns1.example.net.');
			},
		});

		await expect(ctx.query('example.com', 'NS')).rejects.toThrow('temporary DNS failure');
		const result = await ctx.query('example.com', 'NS');

		expect(result).toEqual(ok('ns1.example.net.'));
		expect(calls).toBe(2);
		expect(ctx.metrics()).toMatchObject({ queries: 2, cacheHits: 0, errors: 1 });
	});

	it('bounds concurrent outbound DNS fetches', async () => {
		let active = 0;
		let maxActive = 0;
		const ctx = createDiscoveryDnsContext({
			maxConcurrent: 3,
			baseQuery: async (name) => {
				active++;
				maxActive = Math.max(maxActive, active);
				await new Promise((resolve) => setTimeout(resolve, 10));
				active--;
				return ok(`${name}.`);
			},
		});

		await Promise.all(Array.from({ length: 10 }, (_, i) => ctx.query(`candidate-${i}.example.com`, 'NS')));

		expect(maxActive).toBeLessThanOrEqual(3);
		expect(ctx.metrics().queries).toBe(10);
	});

	it('clamps maxConcurrent to at least one', async () => {
		let active = 0;
		let maxActive = 0;
		const ctx = createDiscoveryDnsContext({
			maxConcurrent: 0,
			baseQuery: async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				await new Promise((resolve) => setTimeout(resolve, 5));
				active--;
				return ok('ns1.example.net.');
			},
		});

		const result = await Promise.race([
			ctx.query('example.com', 'NS').then(() => 'resolved'),
			new Promise<'timed out'>((resolve) => setTimeout(() => resolve('timed out'), 20)),
		]);

		expect(result).toBe('resolved');
		expect(maxActive).toBe(1);
	});
});
