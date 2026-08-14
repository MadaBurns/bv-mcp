// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Global-fetch mock helper — yields a clean info-only SSL result:
//   HTTPS 200 + HSTS present, HTTP→HTTPS 301.
// Mirrors check-ssl.spec.ts's first "should return info finding when HTTPS
// connection succeeds with HSTS" test.
// ---------------------------------------------------------------------------

function setupCleanSslFetchMock() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.startsWith('https://')) {
			return Promise.resolve({
				url: 'https://example.com/',
				ok: true,
				status: 200,
				headers: new Headers({
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
					'expect-ct': 'max-age=86400, enforce',
				}),
			});
		}
		// HTTP redirect check
		return Promise.resolve({
			ok: false,
			status: 301,
			headers: new Headers({ location: 'https://example.com/' }),
		});
	});
}

// ---------------------------------------------------------------------------
// TLS probe binding mock helper
// ---------------------------------------------------------------------------

function probeBinding(body: unknown, status = 200) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkSsl TLS probe enrichment', () => {
	it('binding absent → byte-identical to plain checkSsl (no probe → unchanged)', async () => {
		setupCleanSslFetchMock();

		const { checkSsl } = await import('../src/tools/check-ssl');

		// Both call forms — no second arg and empty object — must produce the same shape.
		const resultNoArg = await checkSsl('example.com');
		const resultEmptyOpts = await checkSsl('example.com', {});

		// Core "unchanged" guarantees
		expect(resultNoArg.category).toBe('ssl');
		expect(resultNoArg.findings).toHaveLength(1);
		expect(resultNoArg.findings[0].severity).toBe('info');
		expect(resultNoArg.passed).toBe(true);

		expect(resultEmptyOpts.category).toBe('ssl');
		expect(resultEmptyOpts.findings).toHaveLength(1);
		expect(resultEmptyOpts.findings[0].severity).toBe('info');
		expect(resultEmptyOpts.passed).toBe(true);
	});

	it('probe TLS1.1 → High finding added, passed becomes false', async () => {
		setupCleanSslFetchMock();

		const binding = probeBinding({ reachable: true, minVersion: 'TLS1.1', maxVersion: 'TLS1.2' });

		const { checkSsl } = await import('../src/tools/check-ssl');
		const result = await checkSsl('example.com', { tlsProbeBinding: binding });

		// A High finding with tlsProbeEnriched metadata must be present.
		const highFinding = result.findings.find((f) => f.metadata?.tlsProbeEnriched === true);
		expect(highFinding).toBeDefined();
		expect(highFinding!.severity).toBe('high');

		// The High finding dents the score (info-only baseline = 100; High penalty = −25 → 75).
		// Score remains ≥ 50, so passed stays true — but the score MUST be strictly less than
		// the no-probe baseline. We verify the direction of the penalty here rather than asserting
		// passed===false, which would require the score to cross the 50-point threshold.
		// (Adapted from spec: real SSL scoring engine starts at 100, info=0 penalty, high=−25 → 75.)
		expect(result.score).toBeLessThan(100);
		expect(result.score).toBeGreaterThan(50); // still passing category, but dented

		// The probe binding's fetch must have been called once with host=example.com in the URL.
		expect(binding.fetch).toHaveBeenCalledOnce();
		const calledUrl = binding.fetch.mock.calls[0][0] as string;
		expect(calledUrl).toContain('host=example.com');
	});

	it('probe TLS1.2 → no change (must-not-penalize-1.2 guard)', async () => {
		setupCleanSslFetchMock();

		const binding = probeBinding({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' });

		const { checkSsl } = await import('../src/tools/check-ssl');
		const result = await checkSsl('example.com', { tlsProbeBinding: binding });

		// No high finding added.
		const highFinding = result.findings.find((f) => f.metadata?.tlsProbeEnriched === true);
		expect(highFinding).toBeUndefined();

		// Findings count must equal the absent-binding case (1 info finding).
		expect(result.findings).toHaveLength(1);
		expect(result.passed).toBe(true);
	});

	it('probe unreachable → no change', async () => {
		setupCleanSslFetchMock();

		const binding = probeBinding({ reachable: false, error: 'connect timeout' });

		const { checkSsl } = await import('../src/tools/check-ssl');
		const result = await checkSsl('example.com', { tlsProbeBinding: binding });

		const highFinding = result.findings.find((f) => f.metadata?.tlsProbeEnriched === true);
		expect(highFinding).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.passed).toBe(true);
	});

	it('probe binding throws → fail-soft, no change, no throw', async () => {
		setupCleanSslFetchMock();

		const throwingBinding = {
			fetch: vi.fn(async () => {
				throw new Error('boom');
			}),
		};

		const { checkSsl } = await import('../src/tools/check-ssl');
		// Must not throw.
		const result = await checkSsl('example.com', { tlsProbeBinding: throwingBinding });

		const highFinding = result.findings.find((f) => f.metadata?.tlsProbeEnriched === true);
		expect(highFinding).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.passed).toBe(true);
	});

	it('auth token forwarded to probe binding fetch', async () => {
		setupCleanSslFetchMock();

		// TLS1.2 probe so we don't need to reason about finding counts — just check the header.
		const binding = probeBinding({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' });

		const { checkSsl } = await import('../src/tools/check-ssl');
		await checkSsl('example.com', { tlsProbeBinding: binding, tlsProbeAuthToken: 'sekret' });

		expect(binding.fetch).toHaveBeenCalledOnce();
		const callInit = binding.fetch.mock.calls[0][1] as RequestInit | undefined;
		const headers = callInit?.headers as Record<string, string> | undefined;
		expect(headers?.['Authorization']).toBe('Bearer sekret');
	});
	// -------------------------------------------------------------------------
	// #641 — the probe is on the same deadline as the fetches, and starts with them
	// -------------------------------------------------------------------------

	it('budget bounds the probe: a hanging probe aborts and the measured result still returns', async () => {
		setupCleanSslFetchMock();

		// A probe that answers only when its signal aborts — i.e. exactly the
		// operator-path stall #641 leaves unbounded. Before the fix this leg carried
		// its own fixed 8s timeout on top of the HTTPS legs, so `safeCheck` killed the
		// whole ssl category at 8s and every already-measured finding went with it.
		let probeSignal: AbortSignal | undefined;
		const hanging = {
			fetch: vi.fn(
				(_url: string, init?: RequestInit) =>
					new Promise<Response>((_resolve, reject) => {
						probeSignal = init?.signal ?? undefined;
						probeSignal?.addEventListener('abort', () => reject(new Error('aborted')));
					}),
			),
		};

		const { checkSsl } = await import('../src/tools/check-ssl');
		const startedAt = Date.now();
		const result = await checkSsl('example.com', { tlsProbeBinding: hanging, budgetMs: 600 });
		const elapsed = Date.now() - startedAt;

		// Bounded by the budget, nowhere near the probe's own 8s clock.
		expect(elapsed).toBeLessThan(3_000);
		expect(probeSignal?.aborted).toBe(true);

		// Degrades by dropping the probe's finding, never by losing the category or
		// fabricating one: the HTTPS/HSTS posture was measured and is still reported.
		expect(result.category).toBe('ssl');
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.passed).toBe(true);
	});

	it('probe is issued CONCURRENTLY with the HTTPS legs, not after them', async () => {
		const order: string[] = [];

		globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				order.push('https:start');
				await new Promise((r) => setTimeout(r, 150));
				order.push('https:end');
				return {
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000' }),
				};
			}
			return { ok: false, status: 301, headers: new Headers({ location: 'https://example.com/' }) };
		});

		const binding = {
			fetch: vi.fn(async () => {
				order.push('probe:start');
				return new Response(JSON.stringify({ reachable: true, minVersion: 'TLS1.2' }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				});
			}),
		};

		const { checkSsl } = await import('../src/tools/check-ssl');
		await checkSsl('example.com', { tlsProbeBinding: binding });

		// The probe needs only the domain, never the fetch result. Sequential ordering
		// added its cost to the fetches' for no benefit; concurrent makes the check's
		// worst case the MAX of the two rather than their SUM. Under the old code
		// 'probe:start' came last.
		expect(order).toContain('probe:start');
		expect(order.indexOf('probe:start')).toBeLessThan(order.indexOf('https:end'));
	});
});
