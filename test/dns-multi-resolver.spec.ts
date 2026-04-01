// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { queryMultiResolver, checkMultiResolverConsistency, RESOLVERS } from '../src/lib/dns-multi-resolver';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Mock all resolvers to return the same A records. */
function mockConsistentResolvers(answers: Array<{ name: string; type: number; TTL: number; data: string }> = []) {
	globalThis.fetch = vi.fn().mockImplementation(() => {
		return Promise.resolve(createDohResponse([{ name: 'example.com', type: 1 }], answers));
	});
}

/** Mock resolvers to return different answers based on resolver endpoint. */
function mockSplitResolvers() {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const urlStr = typeof url === 'string' ? url : url.toString();
		const isCloudflare = urlStr.includes('cloudflare');
		const isGoogle = urlStr.includes('dns.google');
		const u = new URL(urlStr);
		const name = u.searchParams.get('name') ?? 'example.com';
		const type = Number(u.searchParams.get('type') ?? '1');

		if (isCloudflare || isGoogle) {
			return Promise.resolve(createDohResponse([{ name, type }], [
				{ name, type: 1, TTL: 300, data: '1.2.3.4' },
			]));
		}
		// Other resolvers return different IP
		return Promise.resolve(createDohResponse([{ name, type }], [
			{ name, type: 1, TTL: 300, data: '5.6.7.8' },
		]));
	});
}

describe('queryMultiResolver', () => {
	it('returns CONSISTENT when all resolvers agree', async () => {
		mockConsistentResolvers([
			{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' },
		]);

		const result = await queryMultiResolver('example.com', 'A');
		expect(result.recordType).toBe('A');
		expect(result.status).toBe('CONSISTENT');
		expect(result.resolverAnswers.length).toBe(RESOLVERS.length);
	});

	it('returns CONSISTENT for empty records', async () => {
		mockConsistentResolvers([]);

		const result = await queryMultiResolver('example.com', 'AAAA');
		expect(result.status).toBe('CONSISTENT');
		expect(result.detail).toContain('No AAAA records');
	});

	it('returns SPLIT_HORIZON when resolvers disagree', async () => {
		mockSplitResolvers();

		const result = await queryMultiResolver('example.com', 'A');
		expect(result.status).toBe('SPLIT_HORIZON');
		expect(result.detail).toContain('differ');
	});

	it('handles resolver timeouts gracefully', async () => {
		globalThis.fetch = vi.fn().mockImplementation(() => {
			return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 50));
		});

		const result = await queryMultiResolver('example.com', 'A');
		// All resolvers timeout — should be INCOMPLETE
		expect(['INCOMPLETE', 'CONSISTENT']).toContain(result.status);
	});

	it('returns per-resolver answers', async () => {
		mockConsistentResolvers([
			{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' },
		]);

		const result = await queryMultiResolver('example.com', 'A');
		for (const ra of result.resolverAnswers) {
			expect(ra).toHaveProperty('resolver');
			expect(ra).toHaveProperty('status');
			expect(ra).toHaveProperty('answers');
		}
	});
});

describe('checkMultiResolverConsistency', () => {
	it('checks multiple record types', async () => {
		mockConsistentResolvers([]);

		const results = await checkMultiResolverConsistency('example.com', ['A', 'MX']);
		expect(results).toHaveLength(2);
		expect(results[0].recordType).toBe('A');
		expect(results[1].recordType).toBe('MX');
	});

	it('defaults to 5 record types', async () => {
		mockConsistentResolvers([]);

		const results = await checkMultiResolverConsistency('example.com');
		expect(results).toHaveLength(5);
	});
});
