// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the DMARC rua/ruf miner (Phase-4 brand-discovery, tier-1 signal).
 *
 * Parses `_dmarc.<seed>` TXT records to extract `rua=` and `ruf=` URIs,
 * classifies each addressee domain as self / processor / related, and surfaces
 * 'related' domains as candidate co-owned with confidence 0.6.
 */

import { describe, it, expect, vi } from 'vitest';
import { mineDmarcRua } from '../../../src/tenants/discovery/dmarc-rua-miner';
import type { DohResponse } from '../../../src/lib/dns-types';

function txtResponse(records: string[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: '_dmarc.example.com', type: 16 }],
		Answer: records.map((r) => ({ name: '_dmarc.example.com', type: 16, TTL: 3600, data: `"${r}"` })),
	};
}

function emptyDnsResponse(): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: '_dmarc.example.com', type: 16 }],
		Answer: [],
	};
}

describe('mineDmarcRua', () => {
	it('extracts rua mailto URIs and classifies seed-domain mailbox as self (happy path)', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse(['v=DMARC1; p=reject; rua=mailto:dmarc@foo.com']),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.dmarcPresent).toBe(true);
		expect(result.ruaUris).toEqual(['mailto:dmarc@foo.com']);
		expect(result.ruaDomains).toEqual([
			{ domain: 'foo.com', classification: 'self', externalAuthorization: 'same_domain', confidence: 0 },
		]);
	});

	it('classifies known DMARC processor as processor (no co-owned signal)', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse(['v=DMARC1; p=quarantine; rua=mailto:reports@dmarcian.com']),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains).toEqual([
			{ domain: 'dmarcian.com', classification: 'processor', externalAuthorization: 'processor', confidence: 0 },
		]);
	});

	it('classifies an unrelated domain as related with confidence 0.6', async () => {
		const dnsQuery = vi.fn(async (name: string) =>
			name === '_dmarc.foo.com'
				? txtResponse(['v=DMARC1; p=reject; rua=mailto:soc@parentbrand.com'])
				: emptyDnsResponse(),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains).toEqual([
			{ domain: 'parentbrand.com', classification: 'related', externalAuthorization: 'missing', confidence: 0.45 },
		]);
	});

	it('confirms authorized external rua destinations via destination report authorization record', async () => {
		const queries: string[] = [];
		const dnsQuery = vi.fn(async (name: string, type: string) => {
			queries.push(`${name}:${type}`);
			if (name === '_dmarc.example.com') {
				return txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@reports.example.net']);
			}
			if (name === 'example.com._report._dmarc.reports.example.net') {
				return txtResponse(['v=DMARC1']);
			}
			return emptyDnsResponse();
		});

		const result = await mineDmarcRua('example.com', { dnsQuery });

		expect(queries).toContain('example.com._report._dmarc.reports.example.net:TXT');
		expect(result.ruaDomains).toEqual([
			{ domain: 'reports.example.net', classification: 'related', externalAuthorization: 'confirmed', confidence: 0.75 },
		]);
	});

	it('marks missing external rua authorization with lower confidence', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			if (name === '_dmarc.example.com') {
				return txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@reports.example.net']);
			}
			return emptyDnsResponse();
		});

		const result = await mineDmarcRua('example.com', { dnsQuery });

		expect(result.ruaDomains).toEqual([
			{ domain: 'reports.example.net', classification: 'related', externalAuthorization: 'missing', confidence: 0.45 },
		]);
	});

	it('treats external rua authorization lookup errors as missing authorization', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			if (name === '_dmarc.example.com') {
				return txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@reports.example.net']);
			}
			throw new Error('temporary dns failure');
		});

		const result = await mineDmarcRua('example.com', { dnsQuery });

		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains).toEqual([
			{ domain: 'reports.example.net', classification: 'related', externalAuthorization: 'missing', confidence: 0.45 },
		]);
	});

	it('parses both rua= and ruf= and classifies each', async () => {
		const dnsQuery = vi.fn(async (name: string) =>
			name === '_dmarc.foo.com'
				? txtResponse([
					'v=DMARC1; p=reject; rua=mailto:reports@dmarcian.com,mailto:soc@parentbrand.com; ruf=mailto:forensics@parentbrand.com',
				])
				: emptyDnsResponse(),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		// dedup: parentbrand.com listed once even though appears in rua and ruf
		const byDomain = result.ruaDomains.map((d) => d.domain).sort();
		expect(byDomain).toEqual(['dmarcian.com', 'parentbrand.com']);
		const parent = result.ruaDomains.find((d) => d.domain === 'parentbrand.com');
		expect(parent).toMatchObject({ classification: 'related', externalAuthorization: 'missing', confidence: 0.45 });
	});

	it('handles missing DMARC record (no_dmarc status with empty arrays)', async () => {
		const dnsQuery = vi.fn(async () => emptyDnsResponse());
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('no_dmarc');
		expect(result.dmarcPresent).toBe(false);
		expect(result.ruaUris).toEqual([]);
		expect(result.ruaDomains).toEqual([]);
	});

	it('handles DMARC present but no rua/ruf tags (ok with empty uri list)', async () => {
		const dnsQuery = vi.fn(async () => txtResponse(['v=DMARC1; p=reject']));
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.dmarcPresent).toBe(true);
		expect(result.ruaUris).toEqual([]);
		expect(result.ruaDomains).toEqual([]);
	});

	it('skips malformed mailto entries without throwing', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse([
				'v=DMARC1; p=reject; rua=mailto:soc@parentbrand.com,mailto:notanemail,mailto:@nouser.com,httpsnotmailto',
			]),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		// Only the valid mailto survives
		expect(result.ruaDomains.map((d) => d.domain)).toEqual(['parentbrand.com']);
	});

	it('returns failed status when DNS query throws', async () => {
		const dnsQuery = vi.fn(async () => {
			throw new Error('DNS error');
		});
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('failed');
		expect(result.dmarcPresent).toBe(false);
		expect(result.ruaUris).toEqual([]);
		expect(result.ruaDomains).toEqual([]);
	});

	it('uses the first DMARC record when multi-record (RFC violation)', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse([
				'v=DMARC1; p=reject; rua=mailto:first@brand-one.com',
				'v=DMARC1; p=quarantine; rua=mailto:second@brand-two.com',
			]),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains.map((d) => d.domain)).toEqual(['brand-one.com']);
	});

	it('ignores TXT records that are not DMARC (junk before v=DMARC1)', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse([
				'random TXT not a dmarc record',
				'v=DMARC1; p=reject; rua=mailto:soc@parentbrand.com',
			]),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.dmarcPresent).toBe(true);
		expect(result.ruaDomains.map((d) => d.domain)).toEqual(['parentbrand.com']);
	});

	it('matches case-insensitively for self vs other', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse(['v=DMARC1; p=reject; rua=mailto:DMARC@FOO.COM']),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains).toEqual([
			{ domain: 'foo.com', classification: 'self', externalAuthorization: 'same_domain', confidence: 0 },
		]);
	});

	it('classifies subdomains of the seed as self (e.g. dmarc.amazon.com for amazon.com)', async () => {
		const dnsQuery = vi.fn(async () =>
			txtResponse(['v=DMARC1; p=reject; rua=mailto:reports@dmarc.foo.com']),
		);
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.ruaDomains).toEqual([
			{ domain: 'dmarc.foo.com', classification: 'self', externalAuthorization: 'same_domain', confidence: 0 },
		]);
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(mineDmarcRua('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('handles entirely junk TXT (no v=DMARC1 anywhere) as no_dmarc', async () => {
		const dnsQuery = vi.fn(async () => txtResponse(['totally unrelated TXT']));
		const result = await mineDmarcRua('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('no_dmarc');
		expect(result.dmarcPresent).toBe(false);
	});
});
