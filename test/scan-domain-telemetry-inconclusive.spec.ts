// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-287 item 3 — timed-out / errored checks must not reach the ProfileAccumulator
 * telemetry as failed controls.
 *
 * `safeCheck` stamps an inconclusive check `score: 0, passed: false, checkStatus:
 * 'error' | 'timeout'`. `computeScanScore` already EXCLUDES such a check from the
 * reported score (renormalised denominator, shown n/a), but the telemetry POSTed to
 * `/ingest` mapped every `checkResults` entry, so each one was recorded as a
 * `{ score: 0, passed: false }` failed control. That skews the adaptive-weight
 * deltas and the benchmark `topFailingCategories` cohort statistics toward whichever
 * category happened to time out — a measurement gap reported as a security failure.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-spf');
	vi.resetModules();
});

/** A ProfileAccumulator stub: records /ingest bodies, misses on /weights. */
function accumulatorStub(ingestBodies: string[]) {
	return {
		idFromName: (name: string) => name,
		get: () => ({
			fetch: async (request: Request) => {
				if (request.url.includes('/ingest')) {
					ingestBodies.push(await request.text());
					return new Response('{}', { status: 200 });
				}
				return new Response('{}', { status: 500 });
			},
		}),
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any;
}

/** Healthy defaults for every check (same fixture shape as scan-domain-spf-timeout-scoring.spec.ts). */
function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.'))
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				if (url.includes('default._bimi.'))
					return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			if (url.includes('type=CAA') || url.includes('type=257'))
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known'))
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
		return Promise.resolve(httpResponse('OK'));
	});
}

async function scanWithSpfThrowing() {
	vi.resetModules();
	vi.doMock('../src/tools/check-spf', () => ({
		checkSpf: vi.fn().mockImplementation(async () => {
			throw new Error('SPF check timed out');
		}),
	}));
	mockAllChecks();
	IN_MEMORY_CACHE.clear();

	const ingestBodies: string[] = [];
	const pending: Promise<unknown>[] = [];
	const { scanDomain } = await import('../src/tools/scan-domain');
	const result = await scanDomain('example.com', undefined, {
		forceRefresh: true,
		profileAccumulator: accumulatorStub(ingestBodies),
		waitUntil: (p: Promise<unknown>) => pending.push(p),
	});
	await Promise.allSettled(pending);
	return { result, ingestBodies };
}

describe('SQ-287 scanDomain telemetry — inconclusive checks are not failed controls', () => {
	it('omits an errored check from the accumulator categoryFindings but keeps measured ones', async () => {
		const { result, ingestBodies } = await scanWithSpfThrowing();

		// Control facts: spf really is an inconclusive check (score 0 / passed false are the
		// safeCheck stamp, NOT a measurement) and the scan is still graded.
		const spf = result.checks.find((c) => c.category === 'spf');
		expect(spf?.checkStatus).toBe('error');
		expect(spf?.score).toBe(0);
		expect(result.score.overall).not.toBeNull();

		expect(ingestBodies.length).toBeGreaterThan(0);
		const telemetry = JSON.parse(ingestBodies[0]) as { categoryFindings: Array<{ category: string; score: number; passed: boolean }> };
		const categories = telemetry.categoryFindings.map((cf) => cf.category);

		expect(categories).not.toContain('spf');
		// Measured checks still report (the exclusion is targeted, not a wipe).
		expect(categories).toContain('dmarc');
	});
});
