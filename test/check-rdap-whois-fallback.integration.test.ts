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

interface WhoisPayload {
	registrar: string | null;
	registrarIanaId?: string | null;
	creationDate?: string | null;
	updatedDate?: string | null;
	expiryDate?: string | null;
	registrantOrg?: string | null;
	registrantPrivacy?: boolean | null;
	source: 'whois' | 'redacted' | 'notfound' | 'error';
	failureReason?: string;
}

function makeWhoisBinding(payload: WhoisPayload) {
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

	it('surfaces WHOIS-sourced creation/updated/expiry dates + privacy when RDAP returns HTTP 530 (.co case)', async () => {
		// Real production shape: rdap.nic.co returns 530; WHOIS carries the dates.
		mockIanaAndRdap({ services: [[['co'], ['https://rdap.verisign.com/co/v1/']]] });
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : input.toString();
			if (url.includes('data.iana.org')) {
				return new Response(JSON.stringify({ services: [[['co'], ['https://rdap.nic.co/']]] }), { status: 200 });
			}
			// RDAP server 530s for .co.
			return new Response('unavailable', { status: 530 });
		}) as never;
		const whoisBinding = makeWhoisBinding({
			registrar: 'NameCheap, Inc.',
			creationDate: '2025-12-29T20:37:51.0Z',
			updatedDate: '2026-02-03T12:00:51.0Z',
			expiryDate: '2026-12-29T23:59:59.0Z',
			registrantOrg: 'Privacy service provided by Withheld for Privacy ehf',
			registrantPrivacy: true,
			source: 'whois',
		});

		const result = await (await freshChecker())('example.co', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'whois');
		expect(reg, 'a WHOIS-sourced Registration details finding should exist').toBeDefined();
		expect(reg!.metadata!.creationDate).toBe('2025-12-29T20:37:51.000Z');
		expect(reg!.metadata!.expirationDate).toBe('2026-12-29T23:59:59.000Z');
		expect(reg!.metadata!.updatedDate).toBe('2026-02-03T12:00:51.000Z');
		expect(reg!.metadata!.registrantPrivacy).toBe(true);
		expect(reg!.metadata!.registrar).toBe('NameCheap, Inc.');
		// The detail line presents the dates, not just the registrar.
		expect(reg!.detail).toContain('Created: 2025-12-29');
		expect(reg!.detail).toContain('Expires: 2026-12-29');
		// The primary finding no longer asserts the data is unavailable.
		const primary = result.findings.find(f => f.title === 'RDAP lookup failed');
		expect(primary!.detail).not.toContain('Registration data unavailable');
		expect(primary!.detail).toContain('sourced from WHOIS');
	});

	it('surfaces the WHOIS creation date when the TLD has no RDAP server (.nz case)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({
			registrar: 'Example NZ Registrar Ltd',
			creationDate: '2010-03-07T02:29:35Z',
			source: 'whois',
		});

		const result = await (await freshChecker())('example.nz', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'whois');
		expect(reg!.metadata!.creationDate).toBe('2010-03-07T02:29:35.000Z');
		expect(reg!.metadata!.registrar).toBe('Example NZ Registrar Ltd');
		expect(reg!.detail).toContain('Created: 2010-03-07');
		const primary = result.findings.find(f => f.title === 'No RDAP server found');
		expect(primary!.detail).toContain('sourced from WHOIS');
		expect(primary!.detail).not.toContain('RDAP data unavailable');
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

/**
 * #931 — the `.dk` case. Punktum dk (formerly DK Hostmaster) answers on
 * whois.punktum.dk:43 but omits `Registrar:` for registrant-managed domains by
 * policy; the shim now classifies that as `redacted` with the public dates
 * riding along. And on a lookup that FAILED, `registrantPrivacy` must read as
 * unknown (null) — never a confident `false`.
 */
describe('checkRdapLookup WHOIS fallback — #931 (.dk / failed-lookup honesty)', () => {
	it('never reports registrantPrivacy=false on a failed lookup (null = not measured)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		// Old-shim shape: bare error, no detail fields at all.
		const whoisBinding = makeWhoisBinding({ registrar: null, source: 'error' });

		const result = await (await freshChecker())('example.dk', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg).toBeDefined();
		expect(reg!.metadata!.registrantPrivacy).toBeNull();
		expect(reg!.detail).not.toContain('privacy');
	});

	it('reports registrantPrivacy=null even when a pre-#931 shim sends a confident false on its error path', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		// main-branch shim before this fix: EMPTY_REGISTRATION_DETAILS carried registrantPrivacy:false on error.
		const whoisBinding = makeWhoisBinding({ registrar: null, registrantPrivacy: false, source: 'error' });

		const result = await (await freshChecker())('example.dk', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg!.metadata!.registrantPrivacy).toBeNull();
	});

	it('reports registrantPrivacy=null when no WHOIS binding is provided at all', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);

		const result = await (await freshChecker())('example.dk');

		const reg = result.findings.find(f => f.title === 'Registration details');
		expect(reg).toBeDefined();
		expect(reg!.metadata!.registrantPrivacy).toBeNull();
	});

	it('keeps a MEASURED registrantPrivacy=false from a successful WHOIS answer', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: 'WhoisReg', registrantPrivacy: false, source: 'whois' });

		const result = await (await freshChecker())('example.nz', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'whois');
		expect(reg!.metadata!.registrantPrivacy).toBe(false);
	});

	it('surfaces the shim\'s concrete failure cause as registrarFailureReason=whois_<reason>', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: null, registrantPrivacy: null, source: 'error', failureReason: 'timeout' });

		const result = await (await freshChecker())('example.dk', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg!.metadata!.registrarFailureReason).toBe('whois_timeout');
		expect(reg!.detail).toContain('Reason: whois_timeout');
	});

	it('distinguishes an unrouted TLD (no_whois_server) from a transport failure', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const whoisBinding = makeWhoisBinding({ registrar: null, registrantPrivacy: null, source: 'error', failureReason: 'no_whois_server' });

		const result = await (await freshChecker())('example.fakefaketld', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'lookup_failed');
		expect(reg!.metadata!.registrarFailureReason).toBe('whois_no_whois_server');
	});

	it('tolerates an unrecognised failureReason token without discarding the rest of the payload (.catch → undefined)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		// Without `.catch(undefined)` the whole payload would fail Zod and read as a
		// transport error — the registrar must survive, and the token must not be echoed.
		const whoisBinding = makeWhoisBinding({ registrar: 'Survivor Registrar', source: 'whois', failureReason: 'Totally <b>Unexpected</b> Token!' });

		const result = await (await freshChecker())('example.dk', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'whois');
		expect(reg, 'payload with a garbage failureReason must still validate').toBeDefined();
		expect(reg!.metadata!.registrar).toBe('Survivor Registrar');
		expect(reg!.metadata!.registrarFailureReason).toBeUndefined();
		expect(reg!.detail).not.toContain('Unexpected');
	});

	it('marks a transient WHOIS failure (timeout / connect_error) partial so the 3600s registry cache skips it', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const check = await freshChecker();

		const timedOut = await check('example.dk', { whoisBinding: makeWhoisBinding({ registrar: null, source: 'error', failureReason: 'timeout' }) });
		const refused = await check('example.dk', { whoisBinding: makeWhoisBinding({ registrar: null, source: 'error', failureReason: 'connect_error' }) });

		expect(timedOut.partial).toBe(true);
		expect(refused.partial).toBe(true);
	});

	it('does NOT mark deterministic WHOIS outcomes partial (they are safe to cache)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		const check = await freshChecker();

		const noServer = await check('example.fakefaketld', { whoisBinding: makeWhoisBinding({ registrar: null, source: 'error', failureReason: 'no_whois_server' }) });
		const opaque = await check('example.dk', { whoisBinding: makeWhoisBinding({ registrar: null, source: 'error' }) });
		const redacted = await check('example.de', { whoisBinding: makeWhoisBinding({ registrar: null, source: 'redacted' }) });

		expect(noServer.partial).toBeUndefined();
		expect(opaque.partial).toBeUndefined();
		expect(redacted.partial).toBeUndefined();
	});

	it('presents a registrant-managed .dk answer as redacted WITH its public dates (policy omission, not a failure)', async () => {
		mockIanaAndRdap(EMPTY_BOOTSTRAP);
		// Post-fix shim shape for a Punktum registrant-managed domain. No
		// `registrantPrivacy` key: the parser has no Punktum markers, so the shim
		// omits it rather than emit a confident false.
		const whoisBinding = makeWhoisBinding({
			registrar: null,
			creationDate: '1999-09-29',
			expiryDate: '2026-09-30',
			registrantOrg: 'Example ApS',
			source: 'redacted',
		});

		const result = await (await freshChecker())('example.dk', { whoisBinding });

		const reg = result.findings.find(f => f.metadata?.registrarSource === 'redacted');
		expect(reg, 'registrar omitted by registry policy should read as redacted').toBeDefined();
		expect(reg!.metadata!.registrarFailureReason).toBeUndefined();
		expect(reg!.metadata!.creationDate).toBe('1999-09-29T00:00:00.000Z');
		expect(reg!.metadata!.expirationDate).toBe('2026-09-30T00:00:00.000Z');
		// Unmeasured → null, never false (#931).
		expect(reg!.metadata!.registrantPrivacy).toBeNull();
		expect(reg!.detail).toContain('Created: 1999-09-29');
		expect(reg!.detail).toContain('Registrar: withheld by registry');
		// The primary finding acknowledges WHOIS answered instead of asserting the data is unavailable.
		const primary = result.findings.find(f => f.title === 'No RDAP server found');
		expect(primary!.detail).toContain('sourced from WHOIS');
	});
});
