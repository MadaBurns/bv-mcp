// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 7 of registrar-coverage-tdd-plan.md — checkRdapLookup must accept a
 * caller AbortSignal and short-circuit / cancel in-flight RDAP + WHOIS fetches
 * when the deadline aborts. Pre-Phase-7 the RDAP fetch only respected its own
 * 10s timeout — an audit-budget abort couldn't cancel the in-flight request,
 * so the budget overrun didn't unwind for up to 10s per pending lookup.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

function bootstrapJson() {
	return {
		version: '1.0',
		publication: '2024-01-01T00:00:00Z',
		services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
	};
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

describe('checkRdapLookup — AbortSignal threading', () => {
	it('short-circuits to lookup_failed when caller signal is already aborted', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});

		const controller = new AbortController();
		controller.abort();

		const mod = await freshModule();
		const result = await mod.checkRdapLookup('example.com', { signal: controller.signal });

		const finding = result.findings.find((f) => f.metadata?.registrarSource === 'lookup_failed');
		expect(finding, 'pre-aborted signal should fast-path to lookup_failed').toBeDefined();
		expect(finding!.metadata!.registrarFailureReason).toMatch(/abort/i);
	});

	it('forwards signal into the RDAP fetch RequestInit so an in-flight abort cancels the request', async () => {
		const seenSignals: Array<AbortSignal | undefined> = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			seenSignals.push(init?.signal ?? undefined);
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.resolve(jsonResponse({ objectClassName: 'domain', entities: [], events: [], status: [] }));
		});

		const controller = new AbortController();
		const mod = await freshModule();
		await mod.checkRdapLookup('example.com', { signal: controller.signal });

		// All fetches MUST carry a signal — either the caller's, or a composed one.
		// (RDAP_TIMEOUT plus caller signal composed via AbortSignal.any is acceptable.)
		for (const sig of seenSignals) {
			expect(sig, 'every fetch in checkRdapLookup should pass a signal').toBeDefined();
		}
	});
});
