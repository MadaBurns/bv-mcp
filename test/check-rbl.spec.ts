// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a DoH A-record response. */
function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

/** Build a DoH MX-record response. */
function mxResponse(domain: string, entries: Array<{ priority: number; exchange: string }>) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		entries.map((e) => ({ name: domain, type: 15, TTL: 300, data: `${e.priority} ${e.exchange}.` })),
	);
}

/** Build an empty DoH response (NXDOMAIN / no answers). */
function emptyResponse(name: string) {
	return createDohResponse([{ name, type: 1 }], []);
}

/**
 * The 7 RBL zones used by check_rbl. Spamhaus ZEN is intentionally excluded —
 * bv-mcp has no reliable ZEN query path, so it is never queried or counted.
 * `zen.spamhaus.org` is kept in this fixture list ONLY so the mock can assert
 * it is never queried.
 */
const RBL_ZONES = [
	'bl.spamcop.net',
	'dnsbl-1.uceprotect.net',
	'dnsbl-2.uceprotect.net',
	'bl.mailspike.net',
	'b.barracudacentral.org',
	'psbl.surriel.com',
	'dnsbl.sorbs.net',
];

/** ZEN zone — must NEVER appear in a query. Tracked separately from RBL_ZONES. */
const ZEN_ZONE = 'zen.spamhaus.org';

/**
 * Build a fetch mock that routes MX, A, and RBL queries.
 *
 * @param mxEntries - MX records returned for the domain
 * @param mxIps - Map of MX hostname to IP addresses
 * @param rblAnswers - Map of "reversed.zone" to RBL response IPs (empty = clean)
 * @param domainAIps - Fallback A records for domain itself (when no MX)
 * @param dnsErrors - Set of zone names that should return DNS errors
 */
function buildFetchMock(opts: {
	domain?: string;
	mxEntries?: Array<{ priority: number; exchange: string }>;
	mxIps?: Record<string, string[]>;
	rblAnswers?: Record<string, string[]>;
	domainAIps?: string[];
	dnsErrors?: Set<string>;
}) {
	const domain = opts.domain ?? 'example.com';
	const mxEntries = opts.mxEntries ?? [];
	const mxIps = opts.mxIps ?? {};
	const rblAnswers = opts.rblAnswers ?? {};
	const domainAIps = opts.domainAIps ?? [];
	const dnsErrors = opts.dnsErrors ?? new Set();

	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		// MX query for the domain
		if (url.includes(`name=${domain}`) && url.includes('type=MX')) {
			return Promise.resolve(mxResponse(domain, mxEntries));
		}
		// Also match URL-encoded MX query
		if (url.includes(`name=${encodeURIComponent(domain)}`) && url.includes('type=MX')) {
			return Promise.resolve(mxResponse(domain, mxEntries));
		}

		// A record queries for MX hostnames
		for (const [host, ips] of Object.entries(mxIps)) {
			if (url.includes(`name=${host}`) && url.includes('type=A')) {
				return Promise.resolve(aResponse(host, ips));
			}
		}

		// A record query for domain itself (fallback when no MX)
		if (url.includes(`name=${domain}`) && url.includes('type=A')) {
			return Promise.resolve(aResponse(domain, domainAIps));
		}

		// RBL queries — check for reversed IP + zone patterns
		for (const zone of RBL_ZONES) {
			if (url.includes(zone)) {
				// Check DNS error zones
				if (dnsErrors.has(zone)) {
					return Promise.reject(new Error('DNS timeout'));
				}

				// Find matching rbl answer
				for (const [key, ips] of Object.entries(rblAnswers)) {
					if (url.includes(key)) {
						const queryName = key;
						return Promise.resolve(aResponse(queryName, ips));
					}
				}

				// Default: not listed (empty)
				return Promise.resolve(emptyResponse('rbl-query'));
			}
		}

		// Default empty response
		return Promise.resolve(emptyResponse('unknown'));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkRbl', () => {
	async function run(domain = 'example.com', dnsOptions?: import('../src/lib/dns-types').QueryDnsOptions) {
		const { checkRbl } = await import('../src/tools/check-rbl');
		return checkRbl(domain, dnsOptions);
	}

	it('NEVER queries Spamhaus ZEN — it is dropped unconditionally (neither queried nor counted)', async () => {
		const queriedZones = new Set<string>();
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const name = new URL(url).searchParams.get('name') ?? '';
			const type = new URL(url).searchParams.get('type') ?? '';
			if (name === 'example.com' && type === 'MX') {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			if (name === 'mail.example.com' && type === 'A') {
				return Promise.resolve(aResponse('mail.example.com', ['203.0.113.1']));
			}
			if (name.endsWith(`.${ZEN_ZONE}`)) {
				// ZEN must NEVER be queried — record it so the assertion below fails if it is.
				queriedZones.add(ZEN_ZONE);
				return Promise.resolve(aResponse(name, ['127.0.0.2']));
			}
			for (const zone of RBL_ZONES) {
				if (name.endsWith(`.${zone}`)) {
					queriedZones.add(zone);
					return Promise.resolve(emptyResponse(name));
				}
			}
			return Promise.resolve(emptyResponse('unknown'));
		});

		const result = await run(); // ZEN is dropped regardless of dnsOptions
		// ZEN never queried.
		expect(queriedZones.has(ZEN_ZONE)).toBe(false);
		// No ZEN/Spamhaus verdict emitted (no high listing, no quota finding).
		expect(result.findings.some((f) => /spamhaus/i.test(f.title) || /spamhaus/i.test(f.detail))).toBe(false);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		// Clean message counts only the 7 active (non-ZEN) zones.
		const cleanFinding = result.findings.find((f) => /clean|not listed/i.test(f.title));
		expect(cleanFinding).toBeDefined();
		expect(cleanFinding!.detail).toContain('7 RBLs');
		expect((cleanFinding!.metadata?.zones as string[]) ?? []).not.toContain(ZEN_ZONE);
	});

	it('NEVER queries Spamhaus ZEN even when a secondary-resolver token is supplied', async () => {
		const queriedZones = new Set<string>();
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const name = new URL(url).searchParams.get('name') ?? '';
			const type = new URL(url).searchParams.get('type') ?? '';
			if (name === 'example.com' && type === 'MX') {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			if (name === 'mail.example.com' && type === 'A') {
				return Promise.resolve(aResponse('mail.example.com', ['203.0.113.1']));
			}
			if (name.endsWith(`.${ZEN_ZONE}`)) {
				queriedZones.add(ZEN_ZONE);
				return Promise.resolve(aResponse(name, ['127.0.0.2']));
			}
			for (const zone of RBL_ZONES) {
				if (name.endsWith(`.${zone}`)) {
					queriedZones.add(zone);
					return Promise.resolve(emptyResponse(name));
				}
			}
			return Promise.resolve(emptyResponse('unknown'));
		});

		// A secondary-resolver token used to gate ZEN; it no longer does — ZEN is gone.
		const result = await run('example.com', {
			secondaryDoh: { endpoint: 'https://doh.bv.example/dns-query', token: 'test-token' },
		});
		expect(queriedZones.has(ZEN_ZONE)).toBe(false);
		expect(result.findings.some((f) => /spamhaus/i.test(f.title) || /spamhaus/i.test(f.detail))).toBe(false);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('should report multiple listing findings when listed on multiple RBLs', async () => {
		buildFetchMock({
			mxEntries: [{ priority: 10, exchange: 'mail.example.com' }],
			mxIps: { 'mail.example.com': ['203.0.113.1'] },
			rblAnswers: {
				'1.113.0.203.bl.spamcop.net': ['127.0.0.2'],
				'1.113.0.203.dnsbl-1.uceprotect.net': ['127.0.0.2'],
				'1.113.0.203.b.barracudacentral.org': ['127.0.0.2'],
			},
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		// 3 non-Spamhaus listings for same IP → first should be elevated to medium (2+ rule)
		const listingFindings = result.findings.filter((f) => f.title.match(/Listed on/i));
		expect(listingFindings.length).toBeGreaterThanOrEqual(3);
		// At least one should be medium (severity escalation for 2+ non-Spamhaus)
		const mediumFindings = listingFindings.filter((f) => f.severity === 'medium');
		expect(mediumFindings.length).toBeGreaterThanOrEqual(1);
	});

	it('should report info finding when clean on all RBLs', async () => {
		buildFetchMock({
			mxEntries: [{ priority: 10, exchange: 'mail.example.com' }],
			mxIps: { 'mail.example.com': ['203.0.113.1'] },
			// No rblAnswers = clean on all
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		expect(result.passed).toBe(true);
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.title).toMatch(/clean|not listed/i);
	});

	it('should treat Mailspike 127.0.0.10 as positive reputation (info, clean)', async () => {
		buildFetchMock({
			mxEntries: [{ priority: 10, exchange: 'mail.example.com' }],
			mxIps: { 'mail.example.com': ['203.0.113.1'] },
			rblAnswers: {
				'1.113.0.203.bl.mailspike.net': ['127.0.0.10'],
			},
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		// No high/medium/low finding for Mailspike positive reputation
		const negativeFinding = result.findings.find(
			(f) => (f.severity === 'high' || f.severity === 'medium' || f.severity === 'low') && f.title.includes('Mailspike'),
		);
		expect(negativeFinding).toBeUndefined();
		// Should have info finding about positive reputation
		const positiveFinding = result.findings.find((f) => f.detail.includes('positive') || f.detail.includes('Mailspike'));
		expect(positiveFinding).toBeDefined();
		expect(positiveFinding!.severity).toBe('info');
	});

	it('should return partial results when one RBL has DNS error', async () => {
		buildFetchMock({
			mxEntries: [{ priority: 10, exchange: 'mail.example.com' }],
			mxIps: { 'mail.example.com': ['203.0.113.1'] },
			rblAnswers: {
				'1.113.0.203.bl.spamcop.net': ['127.0.0.2'],
			},
			dnsErrors: new Set(['dnsbl.sorbs.net']),
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		// Should still have SpamCop finding despite Spamhaus failure
		const spamcopFinding = result.findings.find((f) => f.title.includes('SpamCop'));
		expect(spamcopFinding).toBeDefined();
	});

	it('should fall back to domain A records when no MX records', async () => {
		buildFetchMock({
			mxEntries: [], // No MX records
			domainAIps: ['198.51.100.1'],
			// All clean
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		// Should have a finding about using A record fallback
		const fallbackFinding = result.findings.find((f) => f.detail.includes('A record') || f.detail.includes('fallback') || f.detail.includes('No MX'));
		expect(fallbackFinding).toBeDefined();
	});

	it('should report info finding when no MX and no A records', async () => {
		buildFetchMock({
			mxEntries: [], // No MX
			domainAIps: [], // No A records either
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toMatch(/no.*IP|no.*address|unable/i);
	});

	it('should warn about private MX IP', async () => {
		buildFetchMock({
			mxEntries: [{ priority: 10, exchange: 'mail.example.com' }],
			mxIps: { 'mail.example.com': ['192.168.1.1'] },
		});

		const result = await run();
		expect(result.category).toBe('rbl');
		const privateFinding = result.findings.find((f) => f.detail.includes('private') || f.detail.includes('192.168'));
		expect(privateFinding).toBeDefined();
		expect(privateFinding!.severity).toBe('info');
	});

	it('should not report clean reputation for malformed IPv4-like MX A data', async () => {
		const queriedNames: string[] = [];
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			const parsed = new URL(url);
			const name = parsed.searchParams.get('name') ?? '';
			const type = parsed.searchParams.get('type') ?? '';
			queriedNames.push(`${name}:${type}`);

			if (name === 'example.com' && type === 'MX') {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mail.example.com' }]));
			}
			if (name === 'mail.example.com' && type === 'A') {
				return Promise.resolve(aResponse('mail.example.com', ['999.0.2.1']));
			}
			return Promise.resolve(emptyResponse('unknown'));
		});

		const result = await run();

		expect(queriedNames).toEqual(['example.com:MX', 'mail.example.com:A']);
		expect(result.findings.find((f) => f.title === 'No valid public IPv4 addresses found')).toBeDefined();
		expect(result.findings.find((f) => f.title.includes('clean'))).toBeUndefined();
	});
});
