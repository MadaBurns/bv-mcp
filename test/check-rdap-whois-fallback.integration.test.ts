// SPDX-License-Identifier: BUSL-1.1
/**
 * Integration: checkRdapLookup with BV_WHOIS service binding fallback.
 *
 * One external dep mocked at a time (per testing-methodology.md):
 *   - globalThis.fetch (RDAP)
 *   - Fetcher.fetch (BV_WHOIS service binding)
 *
 * Each test asserts ONE observable behavior. Unit-level concerns
 * (parser correctness, response shape) are covered in the dns-checks package.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

/** Fresh module per test — gives a clean bootstrap cache without exporting reset hooks. */
async function freshChecker() {
	const mod = await import('../src/tools/check-rdap-lookup');
	return mod.checkRdapLookup;
}

function mockIanaAndRdap(bootstrap: unknown, rdap?: unknown) {
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input.toString();
		if (url.includes('data.iana.org')) {
			return new Response(JSON.stringify(bootstrap), { status: 200 });
		}
		if (rdap && url.includes('rdap.verisign.com')) {
			return new Response(JSON.stringify(rdap), { status: 200, headers: { 'Content-Type': 'application/rdap+json' } });
		}
		return new Response('Not Found', { status: 404 });
	}) as never;
}

function makeWhoisBinding(payload: { registrar: string | null; source: 'whois' | 'redacted' | 'notfound' | 'error' }) {
	return {
		fetch: vi.fn(async () =>
			new Response(JSON.stringify(payload), { status: 200, headers: { 'Content-Type': 'application/json' } }),
		),
	};
}

const COM_BOOTSTRAP = { services: [[['com'], ['https://rdap.verisign.com/com/v1/']]] };
const EMPTY_BOOTSTRAP = { services: [] };
const RDAP_WITH_REGISTRAR = {
	entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'RDAP Registrar Inc.']]] }],
};

describe('checkRdapLookup WHOIS fallback', () => {
	it('records registrarSource=rdap when RDAP succeeds (no WHOIS call)', async () => {
		mockIanaAndRdap(COM_BOOTSTRAP, RDAP_WITH_REGISTRAR);
		const whoisBinding = makeWhoisBinding({ registrar: 'WhoisReg', source: 'whois' });

		const result = await (await freshChecker())('example.com', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource).toBe('rdap');
	});

	it('does not invoke WHOIS when RDAP succeeds', async () => {
		mockIanaAndRdap(COM_BOOTSTRAP, RDAP_WITH_REGISTRAR);
		const whoisBinding = makeWhoisBinding({ registrar: 'WhoisReg', source: 'whois' });

		await (await freshChecker())('example.com', { whoisBinding });

		expect(whoisBinding.fetch).not.toHaveBeenCalled();
	});

	it('records registrarSource=whois when RDAP lacks a server for the TLD', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: 'WhoisReg', source: 'whois' });

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource).toBe('whois');
	});

	it('records registrarSource=whois when RDAP returns HTTP 404', async () => {
		mockIanaAndRdap(COM_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: 'WhoisReg', source: 'whois' });

		const result = await (await freshChecker())('example.com', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource).toBe('whois');
	});

	it('records registrarSource=lookup_failed when RDAP has no server and WHOIS errors', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: null, source: 'error' });

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		// Phase 1 contract: WHOIS error is transient → lookup_failed (not 'unknown'),
		// which lets the consumer retry path pick this up. registrarFailureReason
		// pins the cause so the retry policy can target shim flaps specifically.
		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg).toBeDefined();
		expect(reg!.metadata!.registrarFailureReason).toBe('whois_error');
	});

	it('records registrarSource=redacted when WHOIS reports DENIC redaction', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: null, source: 'redacted' });

		const result = await (await freshChecker())('example.de', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource).toBe('redacted');
	});

	it('omits WHOIS fallback when no binding is provided', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);

		const result = await (await freshChecker())('example.fakefaketld');

		expect(result.findings.some(f => f.title.includes('No RDAP server'))).toBe(true);
	});

	it('fails open when whoisBinding throws (registrarSource=lookup_failed, no exception)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = { fetch: vi.fn(async () => { throw new Error('binding down'); }) };

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		// Phase 1: shim throwing is the same shape as `source:'error'` — transient,
		// retryable. Reason='whois_error' pins it.
		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg, 'binding throw should yield lookup_failed').toBeDefined();
		expect(reg!.metadata!.registrarFailureReason).toBe('whois_error');
	});

	it('treats malformed shim payload as lookup_failed (Zod-validates the response shape)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = {
			fetch: vi.fn(async () =>
				new Response(JSON.stringify({ registrar: { evil: '<script>' }, source: 'arbitrary' }), { status: 200 }),
			),
		};

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		// Malformed payload → Zod rejects → fetchWhoisRegistrar returns source:'error',
		// which Phase 1 reconciles as lookup_failed (transient: the shim is misbehaving).
		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg, 'malformed shim payload should yield lookup_failed').toBeDefined();
		expect(reg!.metadata!.registrarFailureReason).toBe('whois_error');
	});
});
