// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for CAA account-ID clustering (Phase-5, corroboration signal).
 */

import { describe, it, expect, vi } from 'vitest';
import {
	parseCaaIssueValue,
	extractCaaAccounts,
	detectCaaAccountCluster,
	type CaaDnsQueryFn,
} from '../../../src/tenants/discovery/caa-account-detector';
import type { DohResponse } from '../../../src/lib/dns-types';

function caaResponse(name: string, entries: string[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: 257 }],
		Answer: entries.map((data) => ({ name, type: 257, TTL: 3600, data })),
	};
}

function emptyResponse(name: string): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: 257 }],
		Answer: [],
	};
}

describe('parseCaaIssueValue', () => {
	it('extracts ca and account from a value with extensions', () => {
		const out = parseCaaIssueValue('"digicert.com; account=12345; policy=ev"');
		expect(out).toEqual({ ca: 'digicert.com', accounts: ['12345'] });
	});

	it('lowercases ca and account', () => {
		const out = parseCaaIssueValue('"DigiCert.COM; account=ABC123"');
		expect(out?.ca).toBe('digicert.com');
		expect(out?.accounts).toEqual(['abc123']);
	});

	it('returns no accounts for bare CA values', () => {
		const out = parseCaaIssueValue('letsencrypt.org');
		expect(out).toEqual({ ca: 'letsencrypt.org', accounts: [] });
	});

	it('returns null for the "no CA" sentinel', () => {
		expect(parseCaaIssueValue(';')).toBeNull();
		expect(parseCaaIssueValue('')).toBeNull();
	});

	it('honors the accounturi key as a synonym for account', () => {
		const out = parseCaaIssueValue('digicert.com; accounturi=https://digicert.com/account/42');
		expect(out?.accounts).toEqual(['https://digicert.com/account/42']);
	});
});

describe('extractCaaAccounts', () => {
	it('extracts (ca, account) tuples from issue + issuewild records', () => {
		const out = extractCaaAccounts(
			caaResponse('example.com', [
				'0 issue "digicert.com; account=12345"',
				'0 issuewild "letsencrypt.org; account=abc"',
			]),
		);
		expect(out).toEqual([
			{ ca: 'digicert.com', account: '12345' },
			{ ca: 'letsencrypt.org', account: 'abc' },
		]);
	});

	it('skips issue records without account=', () => {
		const out = extractCaaAccounts(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
		expect(out).toEqual([]);
	});

	it('skips iodef records', () => {
		const out = extractCaaAccounts(
			caaResponse('example.com', ['0 iodef "mailto:security@example.com"']),
		);
		expect(out).toEqual([]);
	});

	it('dedupes identical tuples', () => {
		const out = extractCaaAccounts(
			caaResponse('example.com', [
				'0 issue "digicert.com; account=12345"',
				'0 issue "digicert.com; account=12345"',
			]),
		);
		expect(out).toHaveLength(1);
	});
});

describe('detectCaaAccountCluster', () => {
	function dnsFromMap(map: Record<string, string[]>): CaaDnsQueryFn {
		return vi.fn(async (name) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			const entries = map[key];
			if (!entries) return emptyResponse(key);
			return caaResponse(key, entries);
		});
	}

	it('flags candidates sharing a (ca, account) tuple with the seed', async () => {
		const dnsQuery = dnsFromMap({
			'example.com': ['0 issue "digicert.com; account=42"'],
			'sibling.com': ['0 issue "digicert.com; account=42"'],
			'unrelated.com': ['0 issue "digicert.com; account=99"'],
		});
		const result = await detectCaaAccountCluster('example.com', {
			dnsQuery,
			candidateDomains: ['sibling.com', 'unrelated.com'],
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0]).toMatchObject({
			domain: 'sibling.com',
			confidence: 0.95,
			sharedAccounts: [{ ca: 'digicert.com', account: '42' }],
		});
	});

	it('returns ok with no matches when seed has no account-bearing CAA', async () => {
		const dnsQuery = dnsFromMap({
			'example.com': ['0 issue "letsencrypt.org"'],
			'sibling.com': ['0 issue "letsencrypt.org; account=42"'],
		});
		const result = await detectCaaAccountCluster('example.com', {
			dnsQuery,
			candidateDomains: ['sibling.com'],
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.seedAccounts).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns failed when the seed DNS query throws', async () => {
		const dnsQuery: CaaDnsQueryFn = vi.fn(async () => {
			throw new Error('boom');
		});
		const result = await detectCaaAccountCluster('example.com', { dnsQuery });
		expect(result.queryStatus).toBe('failed');
	});

	it('returns partial when a candidate query throws but seed succeeded', async () => {
		const dnsQuery: CaaDnsQueryFn = vi.fn(async (name) => {
			if (name === 'example.com') return caaResponse('example.com', ['0 issue "digicert.com; account=42"']);
			throw new Error('candidate-fail');
		});
		const result = await detectCaaAccountCluster('example.com', {
			dnsQuery,
			candidateDomains: ['sibling.com'],
		});
		expect(result.queryStatus).toBe('partial');
	});

	it('skips the seed if accidentally included in candidate list', async () => {
		const dnsQuery = dnsFromMap({
			'example.com': ['0 issue "digicert.com; account=42"'],
		});
		const result = await detectCaaAccountCluster('example.com', {
			dnsQuery,
			candidateDomains: ['example.com'],
		});
		expect(result.coOwnedDomains).toEqual([]);
	});
});
