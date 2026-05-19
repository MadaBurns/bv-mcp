// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the app-links detector (Phase-5, ground-truth signal).
 *
 * Parsers are pure — accept synthetic JSON, assert canonical shape. The
 * orchestrator injects a fetcher mock — no real network is touched.
 */

import { describe, it, expect, vi } from 'vitest';
import {
	parseAppleAasa,
	parseAssetLinks,
	detectAppLinks,
	type AppLinksFetchFn,
} from '../../../src/tenants/discovery/app-links-detector';
import { StrictDiscoverySignalResultSchema } from '../../../src/schemas/discovery-signal-result';

describe('parseAppleAasa', () => {
	it('extracts appIDs from applinks.details', () => {
		const out = parseAppleAasa({
			applinks: {
				details: [
					{ appID: 'ABCD1234.com.example.app', paths: ['*'] },
					{ appIDs: ['EFGH5678.com.example.tv'] },
				],
			},
		});
		expect(out.appIds).toEqual(['ABCD1234.com.example.app', 'EFGH5678.com.example.tv']);
		expect(out.hasApplinks).toBe(true);
	});

	it('includes webcredentials.apps in the app id set', () => {
		const out = parseAppleAasa({
			webcredentials: { apps: ['IJKL9012.com.example.password'] },
		});
		expect(out.appIds).toContain('IJKL9012.com.example.password');
		expect(out.hasApplinks).toBe(false);
	});

	it('returns empty on missing applinks key', () => {
		const out = parseAppleAasa({});
		expect(out.appIds).toEqual([]);
		expect(out.hasApplinks).toBe(false);
	});

	it('returns empty for malformed input (never throws)', () => {
		expect(parseAppleAasa(null)).toEqual({ appIds: [], hasApplinks: false });
		expect(parseAppleAasa('not an object')).toEqual({ appIds: [], hasApplinks: false });
	});
});

describe('parseAssetLinks', () => {
	it('extracts web sites from web-namespace statements', () => {
		const out = parseAssetLinks([
			{
				relation: ['delegate_permission/common.handle_all_urls'],
				target: { namespace: 'web', site: 'https://www.example.com' },
			},
			{
				relation: ['delegate_permission/common.handle_all_urls'],
				target: { namespace: 'web', site: 'https://sibling.example.org' },
			},
		]);
		expect(out.webSites).toEqual(['sibling.example.org', 'www.example.com']);
	});

	it('extracts android package names from android_app-namespace statements', () => {
		const out = parseAssetLinks([
			{
				relation: ['delegate_permission/common.handle_all_urls'],
				target: { namespace: 'android_app', package_name: 'com.example.app' },
			},
		]);
		expect(out.androidPackages).toEqual(['com.example.app']);
		expect(out.webSites).toEqual([]);
	});

	it('skips statements with unknown namespace', () => {
		const out = parseAssetLinks([
			{ relation: [], target: { namespace: 'weird', site: 'https://x.com' } },
		]);
		expect(out.webSites).toEqual([]);
	});

	it('returns empty on malformed input', () => {
		expect(parseAssetLinks(null)).toEqual({ webSites: [], androidPackages: [] });
		expect(parseAssetLinks({})).toEqual({ webSites: [], androidPackages: [] });
	});
});

describe('detectAppLinks (orchestrator)', () => {
	function fetcherFromMap(map: Record<string, { status: number; body: unknown } | null>): AppLinksFetchFn {
		return vi.fn(async (url: string) => {
			if (Object.prototype.hasOwnProperty.call(map, url)) return map[url];
			return null;
		});
	}

	const AASA_URL = 'https://example.com/.well-known/apple-app-site-association';
	const ASSETLINKS_URL = 'https://example.com/.well-known/assetlinks.json';

	it('returns ok + canonical schema-conforming result when both sources resolve', async () => {
		const fetcher = fetcherFromMap({
			[AASA_URL]: {
				status: 200,
				body: { applinks: { details: [{ appID: 'TEAM1.com.example.app' }] } },
			},
			[ASSETLINKS_URL]: {
				status: 200,
				body: [
					{ relation: [], target: { namespace: 'web', site: 'https://sibling.example.org' } },
					{ relation: [], target: { namespace: 'android_app', package_name: 'com.example.app' } },
				],
			},
		});

		const result = await detectAppLinks('example.com', { fetcher });

		expect(result.queryStatus).toBe('ok');
		// Both seed (via AASA + assetlinks) and the sibling site
		const domains = result.coOwnedDomains.map((c) => c.domain).sort();
		expect(domains).toContain('example.com');
		expect(domains).toContain('sibling.example.org');
		expect(result.fetchedSources).toEqual(['apple_app_site_association', 'android_asset_links']);
		expect(result.failedSources).toEqual([]);
		expect(StrictDiscoverySignalResultSchema.safeParse(result).success).toBe(true);
	});

	it('treats 404 as ok-with-empty (common case for non-app brands)', async () => {
		const fetcher = fetcherFromMap({
			[AASA_URL]: { status: 404, body: null },
			[ASSETLINKS_URL]: { status: 404, body: null },
		});
		const result = await detectAppLinks('example.com', { fetcher });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});

	it('returns failed when both sources error with 5xx', async () => {
		const fetcher = fetcherFromMap({
			[AASA_URL]: { status: 503, body: null },
			[ASSETLINKS_URL]: { status: 502, body: null },
		});
		const result = await detectAppLinks('example.com', { fetcher });
		expect(result.queryStatus).toBe('failed');
		expect(result.failedSources).toEqual(['apple_app_site_association', 'android_asset_links']);
	});

	it('returns partial when one source fails and the other returns 200', async () => {
		const fetcher = fetcherFromMap({
			[AASA_URL]: { status: 200, body: { applinks: { details: [{ appID: 'T.x' }] } } },
			[ASSETLINKS_URL]: { status: 503, body: null },
		});
		const result = await detectAppLinks('example.com', { fetcher });
		expect(result.queryStatus).toBe('partial');
		expect(result.fetchedSources).toEqual(['apple_app_site_association']);
		expect(result.failedSources).toEqual(['android_asset_links']);
	});

	it('separates wildcard sibling sites from concrete candidates', async () => {
		const fetcher = fetcherFromMap({
			[AASA_URL]: { status: 404, body: null },
			[ASSETLINKS_URL]: {
				status: 200,
				body: [
					{ relation: [], target: { namespace: 'web', site: '*.example.org' } },
					{ relation: [], target: { namespace: 'web', site: 'concrete.example.net' } },
				],
			},
		});
		const result = await detectAppLinks('example.com', { fetcher });
		expect(result.coOwnedDomains.map((c) => c.domain)).toEqual(['concrete.example.net']);
		expect(result.wildcardScopes).toEqual(['example.org']);
	});

	it('never throws on fetcher rejection — surfaces failed sources', async () => {
		const fetcher: AppLinksFetchFn = vi.fn(async () => null);
		const result = await detectAppLinks('example.com', { fetcher });
		expect(result.queryStatus).toBe('failed');
		expect(result.failedSources).toEqual(['apple_app_site_association', 'android_asset_links']);
	});
});
