// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// DNS mock helpers (mirrors check-fast-flux.spec.ts)
// ---------------------------------------------------------------------------

function aResponse(domain: string, ips: string[], ttl = 300) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: ttl, data: ip })),
	);
}

function aaaaResponse(domain: string, ips: string[], ttl = 300) {
	return createDohResponse(
		[{ name: domain, type: 28 }],
		ips.map((ip) => ({ name: domain, type: 28, TTL: ttl, data: ip })),
	);
}

function emptyResponse(domain: string, type = 1) {
	return createDohResponse([{ name: domain, type }], []);
}

/** Mocks a stable, resolving domain (same IPs every round, high TTL) so the tool reaches its main return. */
function buildStableFetchMock(domain: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('type=AAAA')) {
			return Promise.resolve(aaaaResponse(domain, ['2606:2800:220:1:248:1893:25c8:1946'], 3600));
		}
		if (url.includes('type=A')) {
			return Promise.resolve(aResponse(domain, ['93.184.216.34'], 3600));
		}
		return Promise.resolve(emptyResponse(domain));
	});
}

// ---------------------------------------------------------------------------
// Recon binding mock helper
// ---------------------------------------------------------------------------

function makeReconHitBinding(detail: string) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify({ checkType: 'ATTACKER_INFRASTRUCTURE', status: 'warning', details: detail }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
	};
}

function makeReconBenignBinding() {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify({ checkType: 'ATTACKER_INFRASTRUCTURE', status: 'info', details: 'nothing serious' }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkFastFlux recon enrichment', () => {
	it('fail-soft guard: no reconEnriched finding when binding is absent', async () => {
		buildStableFetchMock('example.com');

		const { checkFastFlux } = await import('../src/tools/check-fast-flux');
		const result = await checkFastFlux('example.com', 3, undefined, 0);

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: adds corroboration finding when recon returns a hit status', async () => {
		buildStableFetchMock('example.com');

		const reconBinding = makeReconHitBinding('Infrastructure linked to known threat actor.');

		const { checkFastFlux } = await import('../src/tools/check-fast-flux');
		const result = await checkFastFlux('example.com', 3, undefined, 0, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('medium');
		expect(enriched[0].title).toBe('Attacker-infrastructure intel corroboration');
		expect(enriched[0].detail).toContain('Infrastructure linked to known threat actor.');
	});

	it('enriched: no corroboration finding when recon returns a benign status', async () => {
		buildStableFetchMock('example.com');

		const reconBinding = makeReconBenignBinding();

		const { checkFastFlux } = await import('../src/tools/check-fast-flux');
		const result = await checkFastFlux('example.com', 3, undefined, 0, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: no corroboration finding when recon binding fetch fails (fail-soft)', async () => {
		buildStableFetchMock('example.com');

		const reconBinding = {
			fetch: vi.fn(async () => {
				throw new Error('network error');
			}),
		};

		const { checkFastFlux } = await import('../src/tools/check-fast-flux');
		const result = await checkFastFlux('example.com', 3, undefined, 0, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});
});
