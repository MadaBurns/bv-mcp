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

/** Registration-detail fields are absent for the registrar-only fixtures below; a parsed record MEASURED privacy as false. */
const NO_DETAILS = { creationDate: null, updatedDate: null, expiryDate: null, registrantOrg: null, registrantPrivacy: false } as const;
/** Paths that never read a registrant record (short-circuit, not-found, error) leave privacy UNMEASURED = null (#931). */
const UNMEASURED_DETAILS = { ...NO_DETAILS, registrantPrivacy: null } as const;

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

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...UNMEASURED_DETAILS, source: 'redacted' });
	});

	it('short-circuits .de domains to source=redacted without any whoisQuery (DENIC blocks CF egress + always-redacted by law)', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		const result = await lookupRegistrar('example.de', deps);

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...UNMEASURED_DETAILS, source: 'redacted' });
		expect(whoisQuery).not.toHaveBeenCalled();
	});

	it('short-circuits registries that do not publish registrar attribution', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn();
		const deps: LookupDeps = { kv: kv as never, whoisQuery };

		await expect(lookupRegistrar('example.ph', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...UNMEASURED_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.co.jp', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...UNMEASURED_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.ch', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...UNMEASURED_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.pt', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...UNMEASURED_DETAILS,
			source: 'redacted',
		} satisfies WhoisLookupResult);
		await expect(lookupRegistrar('example.gr', deps)).resolves.toEqual({
			registrar: null,
			registrarIanaId: null,
			...UNMEASURED_DETAILS,
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

		expect(result).toEqual<WhoisLookupResult>({ registrar: null, registrarIanaId: null, ...UNMEASURED_DETAILS, source: 'notfound' });
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

/**
 * #931 — `.dk` (Punktum dk, formerly DK Hostmaster). The registry's port-43
 * template carries `Registered:` / `Expires:` but omits `Registrar:` for
 * registrant-managed domains BY POLICY (spec:
 * github.com/Punktum-dk/whois-service-specification — "the field is omitted if
 * the domain name is under registrant management"). Fixture values are
 * synthetic; the SHAPE mirrors a live whois.punktum.dk answer measured
 * 2026-09-09. Pre-fix the composer fell through to `source: 'error'`, which
 * bv-mcp reported as the retryable `whois_error` — a deterministic policy
 * omission dressed as a transport failure.
 */
const PUNKTUM_REGISTRANT_MANAGED_RESPONSE = `# Hello 192.0.2.1. Your session has been logged.
#
# Copyright (c) 2002 - 2026 by Punktum dk A/S
#
# Version: 6.3.0

Domain:               example.dk
DNS:                  example.dk
Registered:           1999-09-29
Expires:              2026-09-30
Registration period:  1 year
VID:                  no
DNSSEC:               Signed delegation
Status:               Active

Registrant
Handle:               DATA REDACTED
Name:                 Example ApS
Address:              Example Street 1
Postalcode:           1000
City:                 Copenhagen
Country:              DK

Nameservers
Hostname:             ns1.example.net
Hostname:             ns2.example.net

`;

const PUNKTUM_NOT_FOUND_RESPONSE = `# Hello 192.0.2.1. Your session has been logged.
#
# Copyright (c) 2002 - 2026 by Punktum dk A/S

No entries found for the selected source.

`;

function punktumDeps(body: string, whoisQuery = vi.fn()) {
	const kv = makeKV();
	whoisQuery.mockImplementation(async (server: string, query: string): Promise<string> => {
		if (server === 'whois.iana.org') return 'whois:        whois.punktum.dk\n';
		if (server === 'whois.punktum.dk' && query === 'example.dk') return body;
		throw new Error(`unexpected query: ${server} ${query}`);
	});
	const deps: LookupDeps = { kv: kv as never, whoisQuery };
	return deps;
}

describe('lookupRegistrar — registry omits registrar by policy (#931, .dk)', () => {
	it('classifies a registration record WITHOUT a Registrar line as source=redacted, not error', async () => {
		const result = await lookupRegistrar('example.dk', punktumDeps(PUNKTUM_REGISTRANT_MANAGED_RESPONSE));

		expect(result.source).toBe('redacted');
		expect(result.failureReason).toBeUndefined();
	});

	it('still surfaces the public Registered/Expires dates alongside the redacted registrar', async () => {
		const result = await lookupRegistrar('example.dk', punktumDeps(PUNKTUM_REGISTRANT_MANAGED_RESPONSE));

		expect(result.creationDate).toBe('1999-09-29');
		expect(result.expiryDate).toBe('2026-09-30');
		expect(result.registrar).toBeNull();
	});

	it('reports registrantPrivacy as a MEASURED false when the registrant record is present with no privacy-proxy marker', async () => {
		const result = await lookupRegistrar('example.dk', punktumDeps(PUNKTUM_REGISTRANT_MANAGED_RESPONSE));

		expect(result.registrantPrivacy).toBe(false);
	});

	it('classifies Punktum "No entries found" as notfound', async () => {
		const result = await lookupRegistrar('example.dk', punktumDeps(PUNKTUM_NOT_FOUND_RESPONSE));

		expect(result.source).toBe('notfound');
	});
});

describe('lookupRegistrar — unmeasured registrantPrivacy reads null, never false (#931)', () => {
	it('is null on the always-redacted short-circuit (no wire exchange happened)', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.de', { kv: kv as never, whoisQuery: vi.fn() });

		expect(result.source).toBe('redacted');
		expect(result.registrantPrivacy).toBeNull();
	});

	it('is null when the registry is unreachable', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.com', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => {
				throw new Error('connect ECONNREFUSED');
			}),
		});

		expect(result.source).toBe('error');
		expect(result.registrantPrivacy).toBeNull();
	});

	it('is null when the TLD has no WHOIS server', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('thing.totallymadeuptld', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => '% returned 0 objects\n'),
		});

		expect(result.source).toBe('error');
		expect(result.registrantPrivacy).toBeNull();
	});

	it('is null when the domain does not exist (there is no registrant to measure)', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('no-such-domain.com', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => NOT_FOUND_RESPONSE),
		});

		expect(result.source).toBe('notfound');
		expect(result.registrantPrivacy).toBeNull();
	});

	it('is null for invalid input', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('not a domain!!!', { kv: kv as never, whoisQuery: vi.fn() });

		expect(result.registrantPrivacy).toBeNull();
	});
});

describe('lookupRegistrar — concrete failureReason on source=error (#931)', () => {
	it('reports invalid_domain for malformed input', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('not a domain!!!', { kv: kv as never, whoisQuery: vi.fn() });

		expect(result).toMatchObject({ source: 'error', failureReason: 'invalid_domain' });
	});

	it('reports no_whois_server when IANA has no referral for the TLD', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('thing.totallymadeuptld', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => '% returned 0 objects\n'),
		});

		expect(result).toMatchObject({ source: 'error', failureReason: 'no_whois_server' });
	});

	it('reports timeout when the transport times out', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.com', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => {
				throw new Error('WHOIS timeout after 5000ms');
			}),
		});

		expect(result).toMatchObject({ source: 'error', failureReason: 'timeout' });
	});

	it('reports connect_error for any other transport throw', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.com', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => {
				throw new Error('connect ECONNREFUSED');
			}),
		});

		expect(result).toMatchObject({ source: 'error', failureReason: 'connect_error' });
	});

	it('reports unrecognised_response when the registry answered with nothing parseable', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.com', {
			kv: kv as never,
			whoisQuery: vi.fn(async () => '% rate limit exceeded, try again later\n'),
		});

		expect(result).toMatchObject({ source: 'error', failureReason: 'unrecognised_response' });
	});

	it('carries no failureReason on a successful lookup', async () => {
		const kv = makeKV();
		const result = await lookupRegistrar('example.com', { kv: kv as never, whoisQuery: vi.fn(async () => REGISTRAR_RESPONSE) });

		expect(result.source).toBe('whois');
		expect('failureReason' in result).toBe(false);
	});
});
