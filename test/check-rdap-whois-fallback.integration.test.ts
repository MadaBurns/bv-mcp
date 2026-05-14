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

		const result = await (await freshChecker())('example.me', { whoisBinding });

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

	it('records registrarSource=unknown when both RDAP and WHOIS fail', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: null, source: 'error' });

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource).toBe('unknown');
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

		const result = await (await freshChecker())('example.me');

		expect(result.findings.some(f => f.title.includes('No RDAP server'))).toBe(true);
	});

	it('fails open when whoisBinding throws (returns unknown, not an exception)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = { fetch: vi.fn(async () => { throw new Error('binding down'); }) };

		const result = await (await freshChecker())('example.me', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource);
		expect(reg?.metadata?.registrarSource ?? 'unknown').toBe('unknown');
	});
});
