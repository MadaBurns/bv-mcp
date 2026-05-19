// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 1 of registrar-coverage-tdd-plan.md — distinguish transient failures
 * ('lookup_failed') from deterministic 'unknown' / 'notfound'. Drives the new
 * RegistrarSource value and the registrarFailureReason metadata field that the
 * consumer retry path (Phase 2) consumes.
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

function rdapDomainResponse(overrides: Record<string, unknown> = {}) {
	return {
		objectClassName: 'domain',
		ldhName: 'example.com',
		entities: [],
		events: [],
		status: [],
		...overrides,
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

async function freshModule() {
	// Reset Vitest's module registry so check-rdap-lookup re-evaluates and its
	// module-level bootstrap cache starts empty per test (instead of reaching
	// into an underscored reset helper).
	vi.resetModules();
	return import('../src/tools/check-rdap-lookup');
}

describe('checkRdapLookup — lookup_failed (transient-failure) source', () => {
	it('tags RDAP HTTP 5xx + WHOIS error as lookup_failed with rdap_http_503 reason', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.resolve(new Response('Service Unavailable', { status: 503 }));
		});
		const whoisBinding = {
			fetch: vi.fn(async () => jsonResponse({ registrar: null, source: 'error' })),
		};

		const mod = await freshModule();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const finding = result.findings.find((f) => f.metadata?.registrarSource === 'lookup_failed');
		expect(finding, 'RDAP 5xx + WHOIS error should yield registrarSource=lookup_failed').toBeDefined();
		expect(finding!.metadata!.registrarFailureReason).toMatch(/rdap_http_503/);
	});

	it('tags RDAP fetch throw without WHOIS binding as lookup_failed with rdap_fetch_error', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.reject(new TypeError('network down'));
		});

		const mod = await freshModule();
		const result = await mod.checkRdapLookup('example.com');

		const finding = result.findings.find((f) => f.metadata?.registrarSource === 'lookup_failed');
		expect(finding, 'RDAP fetch throw without WHOIS should yield lookup_failed').toBeDefined();
		expect(finding!.metadata!.registrarFailureReason).toBe('rdap_fetch_error');
	});

	it('keeps notfound deterministic — no registrarFailureReason set', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.resolve(jsonResponse(rdapDomainResponse({ entities: [] })));
		});
		const whoisBinding = {
			fetch: vi.fn(async () => jsonResponse({ registrar: null, source: 'notfound' })),
		};

		const mod = await freshModule();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const finding = result.findings.find((f) => f.metadata?.registrarSource === 'notfound');
		expect(finding, 'WHOIS notfound is deterministic').toBeDefined();
		expect(finding!.metadata!.registrarFailureReason).toBeUndefined();
	});

	it('keeps redacted deterministic — no registrarFailureReason set', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
			return Promise.resolve(jsonResponse(rdapDomainResponse({ entities: [] })));
		});
		const whoisBinding = {
			fetch: vi.fn(async () => jsonResponse({ registrar: null, source: 'redacted' })),
		};

		const mod = await freshModule();
		const result = await mod.checkRdapLookup('example.com', { whoisBinding });

		const finding = result.findings.find((f) => f.metadata?.registrarSource === 'redacted');
		expect(finding).toBeDefined();
		expect(finding!.metadata!.registrarFailureReason).toBeUndefined();
	});
});
