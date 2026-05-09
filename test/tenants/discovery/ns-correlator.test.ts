// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the NS-correlator (Phase-4 brand-discovery, tier-1 signal).
 *
 * Correlates seed and candidate domains by NS-record overlap. A perfect overlap
 * (confidence 1.0) is a near-deterministic ownership signal; partial overlap
 * (>=0.5) flags a shared infrastructure cluster (registrar / managed DNS).
 *
 * Tests inject a `dnsQuery` function rather than spying on the DNS facade — the
 * implementation accepts the dependency for exactly this reason.
 */

import { describe, it, expect, vi } from 'vitest';
import { correlateNs } from '../../../src/tenants/discovery/ns-correlator';
import type { DohResponse } from '../../../src/lib/dns-types';

interface NsAnswerFixture {
	name: string;
	data: string;
}

function nsResponse(answers: NsAnswerFixture[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: 'example.com', type: 2 }],
		Answer: answers.map((a) => ({ name: a.name, type: 2, TTL: 3600, data: a.data })),
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
		Question: [{ name: 'x', type: 2 }],
		Answer: [],
	};
}

/** Build a dnsQuery mock keyed by domain → NS-data array. */
function dnsQueryFromMap(map: Record<string, string[]>): (name: string, type: string) => Promise<DohResponse> {
	return vi.fn(async (name: string, _type: string) => {
		const key = name.toLowerCase().replace(/\.$/, '');
		const ns = map[key];
		if (!ns) return emptyDnsResponse();
		return nsResponse(ns.map((d) => ({ name: key, data: d })));
	});
}

describe('correlateNs', () => {
	it('returns the seed NS list and empty co-owned domains when no candidates given (happy path)', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.seedDomain).toBe('foo.com');
		expect(result.seedNs).toEqual(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('detects full NS overlap as confidence 1.0', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'],
			'bar.com': ['ns1.cloudflare.com.', 'ns2.cloudflare.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0]).toMatchObject({
			domain: 'bar.com',
			confidence: 1,
		});
		expect(result.coOwnedDomains[0].sharedNs.sort()).toEqual(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
	});

	it('classifies partial overlap as 0.5 (one of two shared)', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.example-dns.com.', 'ns2.example-dns.com.'],
			'bar.com': ['ns1.example-dns.com.', 'ns9.other-dns.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0]).toMatchObject({ domain: 'bar.com', confidence: 0.5 });
		expect(result.coOwnedDomains[0].sharedNs).toEqual(['ns1.example-dns.com']);
	});

	it('omits candidates with zero NS overlap', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.cloudflare.com.'],
			'bar.com': ['ns1.godaddy.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns failed status with empty arrays when seed has no NS records', async () => {
		const dnsQuery = dnsQueryFromMap({}); // empty answers for everything
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('failed');
		expect(result.seedNs).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns failed status without throwing when seed query throws', async () => {
		const dnsQuery = vi.fn(async () => {
			throw new Error('DNS down');
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('failed');
		expect(result.seedNs).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('marks queryStatus partial when at least one candidate query fails but seed succeeded', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			if (key === 'foo.com') return nsResponse([{ name: 'foo.com', data: 'ns1.cloudflare.com.' }]);
			if (key === 'bar.com') return nsResponse([{ name: 'bar.com', data: 'ns1.cloudflare.com.' }]);
			throw new Error('flaky');
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com', 'baz.com'] });
		expect(result.queryStatus).toBe('partial');
		// bar.com still matched
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['bar.com']);
	});

	it('deduplicates and lower-cases NS hostnames', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['NS1.CLOUDFLARE.COM.', 'ns1.cloudflare.com.', 'ns2.cloudflare.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.seedNs.sort()).toEqual(['ns1.cloudflare.com', 'ns2.cloudflare.com']);
	});

	it('skips invalid candidate domains without failing the run', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.cloudflare.com.'],
			'bar.com': ['ns1.cloudflare.com.'],
		});
		const result = await correlateNs('foo.com', {
			dnsQuery,
			candidateDomains: ['bar.com', 'not a domain', ''],
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['bar.com']);
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(correlateNs('not a domain')).rejects.toThrow(/^Domain validation failed:/);
	});

	it('confidence rounded to a stable two-decimal granularity', async () => {
		// Seed has 3 NS, candidate shares 1 → 1/3 ≈ 0.333..., expect 0.33
		const dnsQuery = dnsQueryFromMap({
			'foo.com': ['ns1.a.com.', 'ns2.a.com.', 'ns3.a.com.'],
			'bar.com': ['ns1.a.com.', 'ns9.b.com.'],
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['bar.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains[0].confidence).toBeCloseTo(0.33, 2);
	});

	it('handles candidate with no NS records (skips, does not throw)', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			if (key === 'foo.com') return nsResponse([{ name: 'foo.com', data: 'ns1.cloudflare.com.' }]);
			return emptyDnsResponse();
		});
		const result = await correlateNs('foo.com', { dnsQuery, candidateDomains: ['empty.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});
});
