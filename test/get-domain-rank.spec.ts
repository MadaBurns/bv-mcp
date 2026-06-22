// SPDX-License-Identifier: BUSL-1.1
// RED test first — commit before implementation.

import { describe, it, expect, beforeEach } from 'vitest';
import { vi } from 'vitest';

/**
 * Stub the C1 endpoint shape per contracts-frozen.md:
 *   POST /api/internal/mcp/benchmark
 *   { percentile, cohort, cohortSize, asOf (nullable), representative, scaleId }
 */

function makeC1Response(overrides: Partial<{
	percentile: number;
	cohort: string;
	cohortSize: number;
	asOf: string | null;
	representative: boolean;
	scaleId: string;
}> = {}) {
	return {
		percentile: 65,
		cohort: 'NZ',
		cohortSize: 1200,
		asOf: '2026-06-15',
		representative: false,
		scaleId: 'benchmark',
		...overrides,
	};
}

/** Minimal fake BV_WEB Fetcher binding. */
function makeFakeProxy(response: unknown, status = 200) {
	return {
		fetch: vi.fn().mockResolvedValue(
			new Response(JSON.stringify(response), {
				status,
				headers: { 'Content-Type': 'application/json' },
			}),
		),
	};
}

/** Fake proxy that throws (network failure). */
function makeUnreachableProxy() {
	return {
		fetch: vi.fn().mockRejectedValue(new Error('connection refused')),
	};
}

/** Fake proxy that returns a non-200. */
function makeErrorProxy(status: number) {
	return {
		fetch: vi.fn().mockResolvedValue(new Response('Internal Server Error', { status })),
	};
}

describe('getDomainRank', () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it('returns cohort percentile from C1 for a domain with a country', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(makeC1Response({ percentile: 72, cohort: 'NZ', cohortSize: 1200 }));
		const result = await getDomainRank('example.com', 55, { country: 'NZ' }, proxy, { authToken: 'test-key' });

		expect(result.status).toBe('ok');
		expect(result.percentile).toBe(72);
		expect(result.cohort).toBe('NZ');
		expect(result.cohortSize).toBe(1200);
		expect(result.representative).toBe(false);
		expect(result.scaleId).toBe('benchmark');
	});

	it('returns a valid asOf when C1 provides it', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(makeC1Response({ asOf: '2026-06-15' }));
		const result = await getDomainRank('example.com', 55, {}, proxy, { authToken: 'test-key' });

		expect(result.asOf).toBe('2026-06-15');
	});

	it('handles null asOf without throwing', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(makeC1Response({ asOf: null }));
		const result = await getDomainRank('example.com', 55, {}, proxy, { authToken: 'test-key' });

		expect(result.status).toBe('ok');
		expect(result.asOf).toBeNull();
	});

	it('returns representative result when C1 says representative=true', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(
			makeC1Response({ representative: true, cohort: 'global', cohortSize: 0, asOf: null }),
		);
		const result = await getDomainRank('example.com', 30, {}, proxy, { authToken: 'test-key' });

		expect(result.representative).toBe(true);
		expect(result.cohort).toBe('global');
		expect(result.cohortSize).toBe(0);
		expect(result.asOf).toBeNull();
		// status should still indicate something meaningful
		expect(['ok', 'representative']).toContain(result.status);
	});

	it('fail-softs when bvWeb proxy is absent (unprovisioned)', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const result = await getDomainRank('example.com', 55, {}, undefined, {});

		expect(result.status).toBe('unavailable');
		expect(result.representative).toBe(true);
		// should not throw, should be a valid object
		expect(typeof result.percentile).toBe('number');
	});

	it('fail-softs when C1 is unreachable (network error)', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeUnreachableProxy();
		const result = await getDomainRank('example.com', 55, {}, proxy, { authToken: 'test-key' });

		expect(result.status).toBe('unavailable');
		expect(result.representative).toBe(true);
	});

	it('fail-softs when C1 returns non-2xx (e.g. 503)', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeErrorProxy(503);
		const result = await getDomainRank('example.com', 55, {}, proxy, { authToken: 'test-key' });

		expect(result.status).toBe('unavailable');
		expect(result.representative).toBe(true);
	});

	it('forwards country and sector args to C1 body', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(makeC1Response({ cohort: 'AU' }));
		await getDomainRank('example.com', 70, { country: 'AU', sector: 'finance' }, proxy, { authToken: 'key' });

		expect(proxy.fetch).toHaveBeenCalledOnce();
		const [url, init] = proxy.fetch.mock.calls[0] as [string, RequestInit];
		expect(url).toContain('/api/internal/mcp/benchmark');
		const body = JSON.parse(init.body as string) as Record<string, unknown>;
		expect(body.domain).toBe('example.com');
		expect(body.score).toBe(70);
		expect(body.country).toBe('AU');
		expect(body.sector).toBe('finance');
	});

	it('sends Bearer auth token in Authorization header', async () => {
		const { getDomainRank } = await import('../src/tools/get-domain-rank');
		const proxy = makeFakeProxy(makeC1Response());
		await getDomainRank('example.com', 55, {}, proxy, { authToken: 'secret-key' });

		const [, init] = proxy.fetch.mock.calls[0] as [string, RequestInit];
		const headers = init.headers as Record<string, string>;
		expect(headers['Authorization']).toBe('Bearer secret-key');
	});
});

describe('formatDomainRank', () => {
	it('formats a full result with country cohort', async () => {
		const { formatDomainRank } = await import('../src/tools/get-domain-rank');
		const result = {
			status: 'ok' as const,
			domain: 'example.com',
			score: 72,
			percentile: 65,
			cohort: 'NZ',
			cohortSize: 1200,
			asOf: '2026-06-15',
			representative: false,
			scaleId: 'benchmark',
		};
		const text = formatDomainRank(result, 'full');
		expect(text).toContain('example.com');
		expect(text).toContain('65');
		expect(text).toContain('NZ');
		// cohortSize is locale-formatted — match the n= prefix rather than the raw number
		expect(text).toContain('n=');
	});

	it('formats a compact result', async () => {
		const { formatDomainRank } = await import('../src/tools/get-domain-rank');
		const result = {
			status: 'ok' as const,
			domain: 'example.com',
			score: 72,
			percentile: 65,
			cohort: 'NZ',
			cohortSize: 1200,
			asOf: '2026-06-15',
			representative: false,
			scaleId: 'benchmark',
		};
		const text = formatDomainRank(result, 'compact');
		expect(text).toContain('65%');
		expect(text).toContain('NZ');
	});

	it('formats an unavailable result gracefully', async () => {
		const { formatDomainRank } = await import('../src/tools/get-domain-rank');
		const result = {
			status: 'unavailable' as const,
			domain: 'example.com',
			score: 55,
			percentile: 50,
			cohort: 'global',
			cohortSize: 0,
			asOf: null,
			representative: true,
			scaleId: 'benchmark',
		};
		const text = formatDomainRank(result, 'full');
		expect(text).toContain('unavailable');
	});

	it('does not throw when asOf is null', async () => {
		const { formatDomainRank } = await import('../src/tools/get-domain-rank');
		const result = {
			status: 'ok' as const,
			domain: 'example.com',
			score: 55,
			percentile: 40,
			cohort: 'global',
			cohortSize: 500,
			asOf: null,
			representative: false,
			scaleId: 'benchmark',
		};
		expect(() => formatDomainRank(result, 'full')).not.toThrow();
		expect(() => formatDomainRank(result, 'compact')).not.toThrow();
	});
});
