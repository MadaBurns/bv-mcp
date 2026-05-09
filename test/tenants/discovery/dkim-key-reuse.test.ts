// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the DKIM key-reuse detector (Phase-4 brand-discovery, tier-1 signal).
 *
 * Probes common DKIM selectors at the standard DKIM TXT location, extracts the
 * `p=` public-key parameter, and reports candidate domains that share at least
 * one key with the seed (key reuse implies same private key → same operator).
 *
 * Public-key bytes never appear in the output — only a 16-hex-char SHA-256
 * truncation. This avoids logging plaintext key material.
 */

import { describe, it, expect, vi } from 'vitest';
import { detectDkimKeyReuse } from '../../../src/tenants/discovery/dkim-key-reuse';
import type { DohResponse } from '../../../src/lib/dns-types';

const KEY_A =
	'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tHaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const KEY_B =
	'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1tHbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function txtAnswer(domain: string, value: string): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: domain, type: 16 }],
		Answer: [{ name: domain, type: 16, TTL: 3600, data: `"${value}"` }],
	};
}

function emptyDnsResponse(domain: string): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: domain, type: 16 }],
		Answer: [],
	};
}

/**
 * Build a dnsQuery mock that returns DKIM-style TXT for selector+domain pairs.
 * `map[domain][selector] = pValue`.
 */
function dnsQueryFromMap(map: Record<string, Record<string, string>>): (name: string, type: string) => Promise<DohResponse> {
	return vi.fn(async (name: string) => {
		const m = name.toLowerCase().match(new RegExp('^([^.]+)\\.' + '_' + 'domainkey\\.(.+)$'));
		if (!m) return emptyDnsResponse(name);
		const [, sel, domain] = m;
		const p = map[domain]?.[sel];
		if (!p) return emptyDnsResponse(name);
		return txtAnswer(name, `v=DKIM1; k=rsa; p=${p}`);
	});
}

describe('detectDkimKeyReuse', () => {
	it('flags candidate sharing same DKIM public key as co-owned (happy path)', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A },
			'bar.com': { default: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0]).toMatchObject({ domain: 'bar.com', confidence: 0.95 });
		expect(result.coOwnedDomains[0].sharedSelectors).toEqual(['default']);
		// 16 hex chars
		expect(result.coOwnedDomains[0].sharedKeys[0]).toMatch(/^[0-9a-f]{16}$/);
		// Raw key never returned
		expect(result.coOwnedDomains[0].sharedKeys[0]).not.toContain(KEY_A);
	});

	it('omits candidate with different DKIM keys', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A },
			'bar.com': { default: KEY_B },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('reports the selector(s) at which the shared key was observed', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A, google: KEY_B },
			'bar.com': { google: KEY_B, selector1: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], {
			dnsQuery,
			selectors: ['default', 'google', 'selector1'],
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		const candidate = result.coOwnedDomains[0];
		// Both KEY_A (foo:default ↔ bar:selector1) and KEY_B (foo:google ↔ bar:google) shared.
		expect(candidate.sharedKeys).toHaveLength(2);
		expect(candidate.sharedSelectors.sort()).toEqual(['default', 'google', 'selector1']);
	});

	it('returns ok with empty co-owned when seed has no DKIM records', async () => {
		const dnsQuery = dnsQueryFromMap({
			'bar.com': { default: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.seedSelectors).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns ok with empty co-owned when candidate has no DKIM records', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.seedSelectors).toEqual(['default']);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('uses the default selector list when none provided', async () => {
		// Default list includes 'default' and 'google'
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { google: KEY_A },
			'bar.com': { google: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['bar.com']);
	});

	it('returns failed when seed dnsQuery throws on every selector', async () => {
		const dnsQuery = vi.fn(async () => {
			throw new Error('DNS down');
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('failed');
		expect(result.seedSelectors).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('continues when individual selector queries throw (partial seed probing)', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			const m = name.toLowerCase().match(new RegExp('^([^.]+)\\.' + '_' + 'domainkey\\.(.+)$'));
			if (!m) return emptyDnsResponse(name);
			const [, sel, domain] = m;
			if (sel === 'default' && domain === 'foo.com') throw new Error('flaky');
			if (domain === 'foo.com' && sel === 'google') return txtAnswer(name, `v=DKIM1; k=rsa; p=${KEY_A}`);
			if (domain === 'bar.com' && sel === 'google') return txtAnswer(name, `v=DKIM1; k=rsa; p=${KEY_A}`);
			return emptyDnsResponse(name);
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default', 'google'] });
		expect(result.queryStatus).toBe('partial');
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['bar.com']);
	});

	it('skips DKIM TXT records without a p= tag', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			const m = name.toLowerCase().match(new RegExp('^([^.]+)\\.' + '_' + 'domainkey\\.(.+)$'));
			if (!m) return emptyDnsResponse(name);
			return txtAnswer(name, 'v=DKIM1; k=rsa; n=key revoked');
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.seedSelectors).toEqual([]);
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('skips revoked p= (empty value) consistently', async () => {
		const dnsQuery = vi.fn(async (name: string) => {
			const m = name.toLowerCase().match(new RegExp('^([^.]+)\\.' + '_' + 'domainkey\\.(.+)$'));
			if (!m) return emptyDnsResponse(name);
			return txtAnswer(name, 'v=DKIM1; k=rsa; p=');
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('skips invalid candidate domains', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A },
			'bar.com': { default: KEY_A },
		});
		const result = await detectDkimKeyReuse('foo.com', ['bar.com', 'not a domain', ''], {
			dnsQuery,
			selectors: ['default'],
		});
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['bar.com']);
	});

	it('throws on invalid seed input with the expected error prefix', async () => {
		await expect(detectDkimKeyReuse('not a domain', [])).rejects.toThrow(/^Domain validation failed:/);
	});

	it('hashed key is deterministic across runs', async () => {
		const dnsQuery = dnsQueryFromMap({
			'foo.com': { default: KEY_A },
			'bar.com': { default: KEY_A },
		});
		const r1 = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		const r2 = await detectDkimKeyReuse('foo.com', ['bar.com'], { dnsQuery, selectors: ['default'] });
		expect(r1.coOwnedDomains[0].sharedKeys).toEqual(r2.coOwnedDomains[0].sharedKeys);
	});
});
