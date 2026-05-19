// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 4 of registrar-coverage-tdd-plan.md — RDAP bootstrap caching:
 *   - Successful bootstrap fetch is cached for BOOTSTRAP_TTL_MS (6h)
 *   - Failed bootstrap fetch is cached for BOOTSTRAP_FAILURE_TTL_MS (1m) so
 *     repeated calls during an IANA outage fall through to FALLBACK_RDAP_SERVERS
 *     without hammering the bootstrap endpoint
 *   - FALLBACK_RDAP_SERVERS covers the top-N gTLDs, so a cold-start fetch
 *     failure doesn't blackhole common TLDs
 *
 * Tests run in isolation via `vi.resetModules()` so each fresh import gets an
 * empty module-level cache. Fake timers drive the TTL boundaries.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.useRealTimers();
});

function bootstrapJson(services: [string[], string[]][] = [[['com'], ['https://rdap.verisign.com/com/v1/']]]) {
	return { version: '1.0', publication: '2024-01-01T00:00:00Z', services };
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

async function freshModule() {
	vi.resetModules();
	return import('../src/tools/check-rdap-lookup');
}

describe('RDAP bootstrap cache', () => {
	it('caches a successful bootstrap fetch — second resolveRdapServer call does not re-fetch IANA', async () => {
		const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.resolve(jsonResponse(bootstrapJson([[['com'], ['https://rdap.verisign.com/com/v1/']]])));
			}
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});
		globalThis.fetch = fetchSpy;

		const mod = await freshModule();
		await mod.checkRdapLookup('a.com');
		await mod.checkRdapLookup('b.com');

		const bootstrapCalls = fetchSpy.mock.calls.filter((c) => String(c[0]).includes('data.iana.org/rdap/dns.json'));
		expect(bootstrapCalls.length).toBe(1);
	});

	it('re-fetches bootstrap after BOOTSTRAP_TTL_MS elapses', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

		const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.resolve(jsonResponse(bootstrapJson()));
			}
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});
		globalThis.fetch = fetchSpy;

		const mod = await freshModule();
		await mod.checkRdapLookup('a.com');

		// Advance 7 hours — past 6h TTL.
		vi.advanceTimersByTime(7 * 60 * 60 * 1000);

		await mod.checkRdapLookup('b.com');

		const bootstrapCalls = fetchSpy.mock.calls.filter((c) => String(c[0]).includes('data.iana.org/rdap/dns.json'));
		expect(bootstrapCalls.length).toBe(2);
	});

	it('caches a failed bootstrap fetch briefly — no IANA hammering during outage', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

		const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.reject(new TypeError('bootstrap unreachable'));
			}
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});
		globalThis.fetch = fetchSpy;

		const mod = await freshModule();
		// 3 sequential RDAP lookups during outage — bootstrap should only be tried once.
		await mod.checkRdapLookup('a.com');
		await mod.checkRdapLookup('b.com');
		await mod.checkRdapLookup('c.com');

		const bootstrapCalls = fetchSpy.mock.calls.filter((c) => String(c[0]).includes('data.iana.org/rdap/dns.json'));
		expect(bootstrapCalls.length, 'failed bootstrap should be cached briefly to avoid hammering IANA').toBe(1);
	});

	it('retries bootstrap after BOOTSTRAP_FAILURE_TTL_MS elapses', async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));

		const fetchSpy = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) {
				return Promise.reject(new TypeError('bootstrap unreachable'));
			}
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});
		globalThis.fetch = fetchSpy;

		const mod = await freshModule();
		await mod.checkRdapLookup('a.com');

		// Advance past the failure-cache TTL (>60s).
		vi.advanceTimersByTime(2 * 60 * 1000);
		await mod.checkRdapLookup('b.com');

		const bootstrapCalls = fetchSpy.mock.calls.filter((c) => String(c[0]).includes('data.iana.org/rdap/dns.json'));
		expect(bootstrapCalls.length, 'after failure-TTL elapses, retry bootstrap').toBe(2);
	});

	it('FALLBACK_RDAP_SERVERS covers the most common gTLDs (cold-start IANA outage safety net)', async () => {
		const mod = await freshModule();
		// Use the exported constant directly so the audit test in Phase 6 can pin
		// the snapshot. Phase 4 just asserts the minimum-viable coverage.
		const fallback = mod.FALLBACK_RDAP_SERVERS;
		for (const tld of ['com', 'net', 'org', 'info', 'io', 'biz', 'co', 'me', 'app', 'dev']) {
			expect(fallback[tld], `expected fallback RDAP server for .${tld}`).toMatch(/^https:\/\//);
		}
	});
});
