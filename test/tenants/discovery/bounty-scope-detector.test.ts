// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the bug-bounty scope detector (Phase-5, ground-truth signal).
 *
 * Tests inject a fetcher mock (no real network). Parser tests are pure — they
 * accept synthetic JSON and assert the canonical {@link BountyScopeAsset}
 * shape comes out the other side.
 */

import { describe, it, expect, vi } from 'vitest';
import {
	parseHackerOneScope,
	parseBugcrowdScope,
	parseIntigritiScope,
	detectBountyScope,
	type BountyFetchFn,
} from '../../../src/tenants/discovery/bounty-scope-detector';
import { StrictDiscoverySignalResultSchema } from '../../../src/schemas/discovery-signal-result';

describe('parseHackerOneScope', () => {
	it('extracts URL assets as concrete domains', () => {
		const out = parseHackerOneScope({
			structured_scopes: [
				{ asset_identifier: 'brand-gamma.example.com', asset_type: 'URL', eligible_for_submission: true },
			],
		});
		expect(out).toEqual([
			expect.objectContaining({
				domain: 'brand-gamma.example.com',
				assetType: 'url',
				isWildcard: false,
				inScope: true,
				platform: 'hackerone',
			}),
		]);
	});

	it('marks wildcard scopes', () => {
		const out = parseHackerOneScope({
			structured_scopes: [
				{ asset_identifier: '*.brand-gamma.example.com', asset_type: 'WILDCARD', eligible_for_submission: true },
			],
		});
		expect(out[0]).toMatchObject({ isWildcard: true, domain: 'brand-gamma.example.com', assetType: 'wildcard' });
	});

	it('flags out-of-scope assets with inScope=false', () => {
		const out = parseHackerOneScope({
			structured_scopes: [
				{ asset_identifier: 'old.example.com', asset_type: 'URL', eligible_for_submission: false },
			],
		});
		expect(out[0].inScope).toBe(false);
	});

	it('classifies CIDR and app-store assets without a domain', () => {
		const out = parseHackerOneScope({
			structured_scopes: [
				{ asset_identifier: '10.0.0.0/8', asset_type: 'CIDR', eligible_for_submission: true },
				{ asset_identifier: 'com.example.app', asset_type: 'GOOGLE_PLAY_APP_ID', eligible_for_submission: true },
			],
		});
		expect(out[0]).toMatchObject({ assetType: 'cidr', domain: null });
		expect(out[1]).toMatchObject({ assetType: 'app_store', domain: null });
	});

	it('returns [] for malformed input (never throws)', () => {
		expect(parseHackerOneScope(null)).toEqual([]);
		expect(parseHackerOneScope({})).toEqual([]);
		expect(parseHackerOneScope({ structured_scopes: 'not an array' })).toEqual([]);
		expect(parseHackerOneScope({ structured_scopes: [{ asset_identifier: '', asset_type: 'URL' }] })).toEqual([]);
	});

	it('accepts a top-level array (legacy shape)', () => {
		const out = parseHackerOneScope([
			{ asset_identifier: 'example.com', asset_type: 'URL', eligible_for_submission: true },
		]);
		expect(out).toHaveLength(1);
	});
});

describe('parseBugcrowdScope', () => {
	it('extracts website targets', () => {
		const out = parseBugcrowdScope({
			targets: [{ name: 'brand-gamma.example.com', category: 'website', in_scope: true }],
		});
		expect(out[0]).toMatchObject({ domain: 'brand-gamma.example.com', assetType: 'url', inScope: true, platform: 'bugcrowd' });
	});

	it('handles wildcard website targets', () => {
		const out = parseBugcrowdScope({
			targets: [{ name: '*.brand-gamma.example.com', category: 'website', in_scope: true }],
		});
		expect(out[0]).toMatchObject({ isWildcard: true, domain: 'brand-gamma.example.com', assetType: 'wildcard' });
	});

	it('treats mobile category as app_store', () => {
		const out = parseBugcrowdScope({
			targets: [{ name: 'Marriott Mobile App', category: 'mobile', in_scope: true }],
		});
		expect(out[0].assetType).toBe('app_store');
	});

	it('honors target_type=out_of_scope when in_scope is absent', () => {
		const out = parseBugcrowdScope({
			targets: [{ name: 'old.example.com', category: 'website', target_type: 'out_of_scope' }],
		});
		expect(out[0].inScope).toBe(false);
	});

	it('returns [] on malformed input', () => {
		expect(parseBugcrowdScope(null)).toEqual([]);
		expect(parseBugcrowdScope({ wrong: 'shape' })).toEqual([]);
	});
});

describe('parseIntigritiScope', () => {
	it('extracts endpoint domains', () => {
		const out = parseIntigritiScope({
			domains: [{ endpoint: 'https://brand-gamma.example.com', type: 'url' }],
		});
		expect(out[0]).toMatchObject({ domain: 'brand-gamma.example.com', assetType: 'url', platform: 'intigriti' });
	});

	it('extracts wildcard endpoints', () => {
		const out = parseIntigritiScope({
			domains: [{ endpoint: '*.brand-gamma.example.com', type: 'url' }],
		});
		expect(out[0]).toMatchObject({ isWildcard: true, domain: 'brand-gamma.example.com' });
	});

	it('respects tier=out_of_scope', () => {
		const out = parseIntigritiScope({
			domains: [{ endpoint: 'old.example.com', type: 'url', tier: 'out_of_scope' }],
		});
		expect(out[0].inScope).toBe(false);
	});

	it('returns [] for missing endpoint identifier', () => {
		expect(parseIntigritiScope({ domains: [{ type: 'url' }] })).toEqual([]);
	});
});

describe('detectBountyScope (orchestrator)', () => {
	function fetcherFromMap(map: Record<string, { status: number; body: unknown }>): BountyFetchFn {
		return vi.fn(async (url: string) => map[url] ?? null);
	}

	it('returns ok + canonical schema-conforming result when all platforms succeed', async () => {
		const fetcher = fetcherFromMap({
			'https://hackerone.com/marriott.json': {
				status: 200,
				body: {
					structured_scopes: [
						{ asset_identifier: 'brand-gamma.example.com', asset_type: 'URL', eligible_for_submission: true },
						{ asset_identifier: '*.brand-gamma.example.com', asset_type: 'WILDCARD', eligible_for_submission: true },
					],
				},
			},
		});

		const result = await detectBountyScope('brand-gamma.example.com', {
			handles: { hackerone: 'marriott' },
			fetcher,
		});

		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		expect(result.coOwnedDomains[0]).toMatchObject({
			domain: 'brand-gamma.example.com',
			confidence: 1,
			evidence: { platform: 'hackerone', programHandle: 'marriott', assetType: 'url' },
		});
		expect(result.wildcardScopes).toEqual(['brand-gamma.example.com']);
		expect(result.fetchedPlatforms).toEqual(['hackerone']);
		expect(result.failedPlatforms).toEqual([]);
		expect(StrictDiscoverySignalResultSchema.safeParse(result).success).toBe(true);
	});

	it('returns partial when one platform fails and another succeeds', async () => {
		const fetcher = fetcherFromMap({
			'https://hackerone.com/marriott.json': {
				status: 200,
				body: { structured_scopes: [{ asset_identifier: 'brand-gamma.example.com', asset_type: 'URL', eligible_for_submission: true }] },
			},
			'https://bugcrowd.com/marriott.json': { status: 404, body: null },
		});

		const result = await detectBountyScope('brand-gamma.example.com', {
			handles: { hackerone: 'marriott', bugcrowd: 'marriott' },
			fetcher,
		});

		expect(result.queryStatus).toBe('partial');
		expect(result.fetchedPlatforms).toEqual(['hackerone']);
		expect(result.failedPlatforms).toEqual(['bugcrowd']);
	});

	it('returns failed when every platform errors', async () => {
		const fetcher: BountyFetchFn = vi.fn(async () => ({ status: 503, body: null }));
		const result = await detectBountyScope('brand-gamma.example.com', {
			handles: { hackerone: 'marriott', bugcrowd: 'marriott' },
			fetcher,
		});
		expect(result.queryStatus).toBe('failed');
		expect(result.coOwnedDomains).toEqual([]);
		expect(result.failedPlatforms).toEqual(['hackerone', 'bugcrowd']);
	});

	it('returns failed when no handles are supplied (nothing to query)', async () => {
		const fetcher: BountyFetchFn = vi.fn();
		const result = await detectBountyScope('brand-gamma.example.com', { handles: {}, fetcher });
		expect(result.queryStatus).toBe('failed');
		expect(fetcher).not.toHaveBeenCalled();
	});

	it('dedupes a domain that appears across multiple platforms', async () => {
		const fetcher = fetcherFromMap({
			'https://hackerone.com/marriott.json': {
				status: 200,
				body: { structured_scopes: [{ asset_identifier: 'brand-gamma.example.com', asset_type: 'URL', eligible_for_submission: true }] },
			},
			'https://bugcrowd.com/marriott.json': {
				status: 200,
				body: { targets: [{ name: 'brand-gamma.example.com', category: 'website', in_scope: true }] },
			},
		});
		const result = await detectBountyScope('brand-gamma.example.com', {
			handles: { hackerone: 'marriott', bugcrowd: 'marriott' },
			fetcher,
		});
		expect(result.coOwnedDomains).toHaveLength(1);
		// First-platform-wins for evidence; HackerOne queried first.
		expect(result.coOwnedDomains[0].evidence.platform).toBe('hackerone');
	});

	it('separates out-of-scope domains from coOwnedDomains', async () => {
		const fetcher = fetcherFromMap({
			'https://hackerone.com/marriott.json': {
				status: 200,
				body: {
					structured_scopes: [
						{ asset_identifier: 'in.example.com', asset_type: 'URL', eligible_for_submission: true },
						{ asset_identifier: 'out.example.com', asset_type: 'URL', eligible_for_submission: false },
					],
				},
			},
		});
		const result = await detectBountyScope('example.com', {
			handles: { hackerone: 'marriott' },
			fetcher,
		});
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['in.example.com']);
		expect(result.outOfScopeDomains).toEqual(['out.example.com']);
	});

	it('never throws on fetcher rejection — surfaces failed', async () => {
		const fetcher: BountyFetchFn = vi.fn(async () => null);
		const result = await detectBountyScope('brand-gamma.example.com', {
			handles: { hackerone: 'marriott' },
			fetcher,
		});
		expect(result.queryStatus).toBe('failed');
		expect(result.failedPlatforms).toEqual(['hackerone']);
	});
});
