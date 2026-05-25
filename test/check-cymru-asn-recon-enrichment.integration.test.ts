// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// DNS mock helpers (mirrors check-cymru-asn.spec.ts)
// ---------------------------------------------------------------------------

function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

function txtResponse(name: string, values: string[]) {
	return createDohResponse(
		[{ name, type: 16 }],
		values.map((v) => ({ name, type: 16, TTL: 300, data: `"${v}"` })),
	);
}

function emptyResponse(name: string) {
	return createDohResponse([{ name, type: 1 }], []);
}

/** Build a fetch mock that routes standard cymru-asn queries for a single IP. */
function buildCymruFetchMock(domain: string, ip: string, originTxtValue: string, asnNum: string, orgTxtValue: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if ((url.includes(`name=${domain}`) || url.includes(`name=${encodeURIComponent(domain)}`)) && url.includes('type=A')) {
			return Promise.resolve(aResponse(domain, [ip]));
		}

		if (url.includes('origin.asn.cymru.com') && url.includes('type=TXT')) {
			const reversed = ip.split('.').reverse().join('.');
			if (url.includes(reversed)) {
				return Promise.resolve(txtResponse(`${reversed}.origin.asn.cymru.com`, [originTxtValue]));
			}
			return Promise.resolve(emptyResponse('origin-query'));
		}

		if (url.includes('asn.cymru.com') && url.includes('type=TXT')) {
			if (url.includes(`AS${asnNum}.asn.cymru.com`)) {
				return Promise.resolve(txtResponse(`AS${asnNum}.asn.cymru.com`, [orgTxtValue]));
			}
			return Promise.resolve(emptyResponse('org-query'));
		}

		return Promise.resolve(emptyResponse('unknown'));
	});
}

// ---------------------------------------------------------------------------
// Recon binding mock helper
// ---------------------------------------------------------------------------

function makeReconBinding(findings: Array<{ severity: string; title?: string; detail?: string }>) {
	return {
		fetch: vi.fn(async () => new Response(JSON.stringify({ findings }), { status: 200, headers: { 'Content-Type': 'application/json' } })),
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkCymruAsn recon enrichment', () => {
	it('fail-soft guard: no reconEnriched finding when binding is absent', async () => {
		buildCymruFetchMock(
			'example.com',
			'93.184.216.34',
			'15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			'15169',
			'15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
		);

		const { checkCymruAsn } = await import('../src/tools/check-cymru-asn');
		const result = await checkCymruAsn('example.com');

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: adds corroboration finding when recon returns a high-severity hit', async () => {
		buildCymruFetchMock(
			'example.com',
			'93.184.216.34',
			'15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			'15169',
			'15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
		);

		const reconBinding = makeReconBinding([{ severity: 'high', title: 'Known malicious ASN', detail: 'ASN 15169 flagged in threat feed' }]);

		const { checkCymruAsn } = await import('../src/tools/check-cymru-asn');
		const result = await checkCymruAsn('example.com', undefined, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(1);
		expect(enriched[0].severity).toBe('medium');
		expect(enriched[0].title).toBe('Malicious-ASN intel corroboration');
		expect(enriched[0].detail).toContain('ASN 15169 flagged in threat feed');
	});

	it('enriched: no corroboration finding when recon returns only info-severity hits', async () => {
		buildCymruFetchMock(
			'example.com',
			'93.184.216.34',
			'15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			'15169',
			'15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
		);

		const reconBinding = makeReconBinding([{ severity: 'info', title: 'Low priority note', detail: 'nothing serious' }]);

		const { checkCymruAsn } = await import('../src/tools/check-cymru-asn');
		const result = await checkCymruAsn('example.com', undefined, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});

	it('enriched: no corroboration finding when recon binding fetch fails (fail-soft)', async () => {
		buildCymruFetchMock(
			'example.com',
			'93.184.216.34',
			'15169 | 93.184.216.0/24 | US | arin | 2007-03-19',
			'15169',
			'15169 | US | arin | 2007-03-19 | GOOGLE - Google LLC, US',
		);

		const reconBinding = { fetch: vi.fn(async () => { throw new Error('network error'); }) };

		const { checkCymruAsn } = await import('../src/tools/check-cymru-asn');
		const result = await checkCymruAsn('example.com', undefined, { reconBinding, reconAuthToken: 'tok' });

		const enriched = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(enriched).toHaveLength(0);
	});
});
