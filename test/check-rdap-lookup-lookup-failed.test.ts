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

/**
 * #982 — four paths that pinned a transient condition for an hour as if it were a
 * deterministic answer. The chokepoint is `result.partial`: the `rdap_lookup` registry entry
 * in `src/handlers/tools.ts` caches on `!r.partial` with a 3600s TTL, so `partial === true`
 * is the whole difference between "re-ask next time" and "publish our flake as the
 * registry's answer for an hour". Each test also asserts the definitive counterpart still
 * caches, so the fix cannot be satisfied by making everything uncacheable.
 */
describe('checkRdapLookup — transient conditions are not cached as answers (#982)', () => {
	it('marks a non-retryable 5xx (HTTP 530) uncacheable, while a 404 stays a cacheable answer', async () => {
		async function runWithStatus(status: number) {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
				return Promise.resolve(new Response('origin error', { status }));
			});
			const whoisBinding = { fetch: vi.fn(async () => jsonResponse({ registrar: null, source: 'error' })) };
			const mod = await freshModule();
			return mod.checkRdapLookup('example.com', { whoisBinding });
		}

		// 530 is the Cloudflare origin-error family a .co registry really returns. Pure
		// infrastructure — it says nothing about the domain.
		const originError = await runWithStatus(530);
		expect(originError.partial, 'HTTP 530 is an origin error, never an answer about the domain').toBe(true);
		const plainFive = await runWithStatus(500);
		expect(plainFive.partial).toBe(true);

		// 404 is a real "no such registration" and must keep today's caching.
		const notFound = await runWithStatus(404);
		expect(notFound.partial, 'HTTP 404 is a deterministic answer and stays cacheable').toBeFalsy();
	});

	it('marks the opaque whois_error uncacheable, while a concrete deterministic WHOIS token still caches', async () => {
		async function runWithWhois(body: unknown) {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				// A TLD the bootstrap registry does not cover — the no-RDAP-server path, where
				// the RDAP-side outcome is 'unknown' and WHOIS decides the verdict.
				if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
				return Promise.resolve(jsonResponse({}, 404));
			});
			const whoisBinding = { fetch: vi.fn(async () => jsonResponse(body)) };
			const mod = await freshModule();
			return mod.checkRdapLookup('example.xx', { whoisBinding });
		}

		// The shim emits a bare `error` with no failureReason for a past deadline, a non-2xx,
		// an over-cap body and any throw — every one of them transient.
		const opaque = await runWithWhois({ registrar: null, source: 'error' });
		const opaqueFinding = opaque.findings.find((f) => f.metadata?.registrarFailureReason === 'whois_error');
		expect(opaqueFinding, 'opaque shim error should still be reported as whois_error').toBeDefined();
		expect(opaque.partial, 'the opaque whois_error is transient — registrar-retry.ts has always said so').toBe(true);

		// A shim that knows the TLD has no WHOIS server gave a real answer.
		const deterministic = await runWithWhois({ registrar: null, source: 'error', failureReason: 'no_whois_server' });
		const detFinding = deterministic.findings.find((f) => f.metadata?.registrarFailureReason === 'whois_no_whois_server');
		expect(detFinding).toBeDefined();
		expect(deterministic.partial, 'a concrete deterministic WHOIS token stays cacheable').toBeFalsy();
	});

	it('does not relabel a WHOIS timeout as the deterministic verdict "redacted"', async () => {
		// RDAP answers 200 with no registrar entity, so the tool falls back to WHOIS. A WHOIS
		// timeout used to be rewritten to `{source: 'redacted'}`, asserting "withheld by
		// registry" — a policy statement never measured — and dropping the failure reason so
		// the caching chokepoint could not see the flake.
		async function runWithWhois(body: unknown) {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) return Promise.resolve(jsonResponse(bootstrapJson()));
				return Promise.resolve(jsonResponse(rdapDomainResponse()));
			});
			const whoisBinding = { fetch: vi.fn(async () => jsonResponse(body)) };
			const mod = await freshModule();
			return mod.checkRdapLookup('example.com', { whoisBinding });
		}

		const timedOut = await runWithWhois({ registrar: null, source: 'error', failureReason: 'timeout' });
		const timedOutFinding = timedOut.findings.find((f) => f.metadata?.registrarSource !== undefined);
		expect(timedOutFinding!.metadata!.registrarSource, 'a timeout is not a redaction').not.toBe('redacted');
		expect(timedOutFinding!.metadata!.registrarFailureReason).toBe('whois_timeout');
		expect(timedOut.partial).toBe(true);
		expect(timedOutFinding!.detail).not.toContain('withheld by registry');

		// A deterministic WHOIS non-answer still supports the redaction reading and still caches.
		const unrecognised = await runWithWhois({ registrar: null, source: 'error', failureReason: 'unrecognised_response' });
		const unrecognisedFinding = unrecognised.findings.find((f) => f.metadata?.registrarSource !== undefined);
		expect(unrecognisedFinding!.metadata!.registrarSource).toBe('redacted');
		expect(unrecognised.partial).toBeFalsy();
	});

	it('marks an IANA bootstrap transport failure uncacheable instead of claiming the TLD has no RDAP server', async () => {
		async function run(bootstrapOk: boolean, domain: string) {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.includes('data.iana.org/rdap/dns.json')) {
					return bootstrapOk ? Promise.resolve(jsonResponse(bootstrapJson())) : Promise.reject(new TypeError('network down'));
				}
				return Promise.resolve(jsonResponse(rdapDomainResponse()));
			});
			const mod = await freshModule();
			// No WHOIS binding — the BSL self-host case, where nothing rescues the lookup.
			return mod.checkRdapLookup(domain, {});
		}

		const flake = await run(false, 'example.xx');
		const failed = flake.findings.find((f) => f.metadata?.registrarFailureReason === 'rdap_bootstrap_error');
		expect(failed, 'an unread bootstrap registry is a failed lookup, not a fact about the TLD').toBeDefined();
		expect(flake.partial).toBe(true);
		expect(flake.findings.some((f) => f.detail.includes('No RDAP server found for TLD'))).toBe(false);

		// Registry read, TLD genuinely absent from it: a real answer, still cacheable.
		const measured = await run(true, 'example.xx');
		expect(measured.findings.some((f) => f.detail.includes('No RDAP server found for TLD'))).toBe(true);
		expect(measured.partial).toBeFalsy();
	});
});
