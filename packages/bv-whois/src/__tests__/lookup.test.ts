// SPDX-License-Identifier: BUSL-1.1
/**
 * Unit tests for the lookup composer — wires resolver + transport + parser.
 */

import { describe, it, expect, vi } from 'vitest';
import { lookupRegistrar, type LookupDeps, type WhoisLookupResult } from '../lookup';

function makeKV() {
	const data = new Map<string, string>();
	return {
		get: vi.fn(async (k: string) => (data.has(k) ? data.get(k)! : null)),
		put: vi.fn(async (k: string, v: string) => { data.set(k, v); }),
	};
}

/** Registration-detail fields are absent for the registrar-only fixtures below. */
const NO_DETAILS = { creationDate: null, updatedDate: null, expiryDate: null, registrantOrg: null, registrantPrivacy: false } as const;

const REGISTRAR_RESPONSE = `Domain Name: example.com\nRegistrar: TestRegistrar Inc.\nDomain Status: ok\n`;
const DATED_RESPONSE = `Domain Name: example.com\nRegistrar: TestRegistrar Inc.\nCreation Date: 2020-01-15T00:00:00Z\nUpdated Date: 2024-03-10T00:00:00Z\nRegistry Expiry Date: 2027-01-15T00:00:00Z\nRegistrant Organization: Withheld for Privacy ehf\n`;
const REGISTRAR_IANA_RESPONSE = `Domain Name: example.com\nRegistrar: TestRegistrar Inc.\nRegistrar IANA ID: 299\nDomain Status: ok\n`;
const REDACTED_DENIC_RESPONSE = `% The DENIC whois service on port 43 doesn't disclose any information concerning the domain holder.\nDomain: example.de\nStatus: connect\n`;
const NOT_FOUND_RESPONSE = `No match for domain "no-such-domain.com".\n`;

describe('lookupRegistrar', () => {
	it('returns a whois-sourced registrar for a valid domain', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string, query: string): Promise<string> => {
				if (server === 'whois.iana.org') return 'whois:        whois.nic.example\n';
				if (server === 'whois.nic.example' && query === 'example.example') return REGISTRAR_RESPONSE;
				throw new Error(`unexpected query: ${server} ${query}`);
			}),
		};

		const result = await lookupRegistrar('example.example', deps);

		expect(result).toEqual<WhoisLookupResult>({
			registrar: 'TestRegistrar Inc.',
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'whois',
		});
	});

	it('surfaces creation / updated / expiry dates + privacy registrant from a dated WHOIS response', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string, query: string): Promise<string> => {
				if (server === 'whois.iana.org') return 'whois:        whois.nic.example\n';
				if (server === 'whois.nic.example' && query === 'example.example') return DATED_RESPONSE;
				throw new Error(`unexpected query: ${server} ${query}`);
			}),
		};

		const result = await lookupRegistrar('example.example', deps);

		expect(result).toEqual<WhoisLookupResult>({
			registrar: 'TestRegistrar Inc.',
			registrarIanaId: null,
			creationDate: '2020-01-15T00:00:00Z',
			updatedDate: '2024-03-10T00:00:00Z',
			expiryDate: '2027-01-15T00:00:00Z',
			registrantOrg: 'Withheld for Privacy ehf',
			registrantPrivacy: true,
			source: 'whois',
		});
	});

	it('returns the parsed registrar IANA ID when available', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string, query: string): Promise<string> => {
				if (server === 'whois.iana.org') return 'whois:        whois.nic.example\n';
				if (server === 'whois.nic.example' && query === 'example.example') return REGISTRAR_IANA_RESPONSE;
				throw new Error(`unexpected query: ${server} ${query}`);
			}),
		};

		const result = await lookupRegistrar('example.example', deps);

		expect(result).toEqual<WhoisLookupResult>({
			registrar: 'TestRegistrar Inc.',
			registrarIanaId: '299',
			...NO_DETAILS,
			source: 'whois',
		});
	});

	it('returns source=redacted for DENIC privacy response', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string) => {
				if (server === 'whois.denic.de') return REDACTED_DENIC_RESPONSE;
				return '';
			}),
		};

		const result = await lookupRegistrar('example.de', deps);

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...NO_DETAILS, source: 'redacted' });
	});

	it('short-circuits .de domains to source=redacted without any whoisQuery (DENIC blocks CF egress + always-redacted by law)', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		const result = await lookupRegistrar('example.de', deps);

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...NO_DETAILS, source: 'redacted' });
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('short-circuits registries that do not publish registrar attribution', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		await expect(lookupRegistrar('example.ph', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.co.jp', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.ch', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.pt', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.gr', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('parses Korean WHOIS Authorized Agency as the registrar', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string, query: string): Promise<string> => {
				if (server === 'whois.kr' && query === 'google.kr') return 'Domain Name: google.kr\nAuthorized Agency           : Whois Corp.(http://whois.co.kr)\n';
				throw new Error(`unexpected query: ${server} ${query}`);
			}),
		};

		const result = await lookupRegistrar('google.kr', deps);

		expect(result).toEqual<WhoisLookupResult>({
			registrar: 'Whois Corp.(http://whois.co.kr)',
			registrarIanaId: null,
			...NO_DETAILS,
			source: 'whois',
		});
	});

	it('returns source=notfound when registry says no match', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string) => {
				if (server === 'whois.verisign-grs.com') return NOT_FOUND_RESPONSE;
				return '';
			}),
		};

		const result = await lookupRegistrar('no-such-domain.com', deps);

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...NO_DETAILS, source: 'notfound' });
	});

	it('returns source=error when registry unreachable', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async () => {
				throw new Error('connect ETIMEDOUT');
			}),
		};

		const result = await lookupRegistrar('example.com', deps);

		expect(result.source).toBe('error');
		expect(result.registrar).toBeNull();
	});

	it('returns source=error when TLD has no IANA record and no hardcoded server', async () => {
		const kv = makeKV();
		const deps: LookupDeps = {
			kv: kv as never,
			whoisQuery: vi.fn(async (server: string) => {
				if (server === 'whois.iana.org') return '% returned 0 objects\n';
				return '';
			}),
		};

		const result = await lookupRegistrar('thing.totallymadeuptld', deps);

		expect(result.source).toBe('error');
		expect(result.registrar).toBeNull();
	});

	it('extracts TLD from multi-label domain correctly', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn(async () => REGISTRAR_RESPONSE);
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		await lookupRegistrar('sub.deep.example.com', deps);

		// .com → whois.verisign-grs.com via hardcoded fast path; query = the full domain.
		expect(whoisQuery).toHaveBeenCalledWith('whois.verisign-grs.com', 'sub.deep.example.com');
	});

	it('rejects invalid domain strings without making any calls', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		const result = await lookupRegistrar('not a domain!!!', deps);

		expect(result.source).toBe('error');
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('rejects single-label TLD-only input', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		const result = await lookupRegistrar('com', deps);

		expect(result.source).toBe('error');
		expect(whoisQuery).not.toHaveBeenCalled();
	});
});
