// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
const TLS_PROBE_AUTH_TOKEN = 'tls-probe-integration-key-32-bytes-minimum';

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

	it.each(['TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3'])('does not consume intercepted %s or spend a probe call', async (version) => {
		setupCleanSslFetchMock();
		const binding = probeBinding({ reachable: true, minVersion: version });
		const { checkSsl } = await import('../src/tools/check-ssl');
		const { TLS_VERSION_ENRICHMENT_ENABLED } = await import('../src/lib/tls-probe-binding');
		expect(TLS_VERSION_ENRICHMENT_ENABLED).toBe(false);
		const baseline = await checkSsl('example.com');
		const result = await checkSsl('example.com', { tlsProbeBinding: binding, tlsProbeAuthToken: TLS_PROBE_AUTH_TOKEN, budgetMs: 600 });
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(result.score).toBe(baseline.score);
		expect(result.findings).toEqual(baseline.findings);
		expect(result.metadata?.tlsVersionAssessment).toEqual({ status: 'not_assessed', reason: 'probe_vantage_intercepted' });
	});
});
