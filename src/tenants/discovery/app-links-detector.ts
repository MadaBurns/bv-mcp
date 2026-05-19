// SPDX-License-Identifier: BUSL-1.1

/**
 * App-links detector (Phase-5 brand-discovery, ground-truth signal).
 *
 * Mobile apps declare their associated web domains in two well-known files:
 *
 *  - `/.well-known/apple-app-site-association` (iOS Universal Links)
 *  - `/.well-known/assetlinks.json` (Android App Links)
 *
 * Apple/Google verify these before app publication, so listed domains are
 * brand-authoritative — confidence=1.0 ownership signal. Wildcards
 * (`*.brand.com`) are surfaced separately as expansion hints rather than
 * concrete candidates.
 *
 * Failure convention (per project): NEVER throw. Surface via `queryStatus`.
 * 404 is the common case (most seeds aren't mobile app domains) and counts as
 * `ok` with empty results — NOT `failed`.
 */

import { z } from 'zod';

export type AppLinkSource = 'apple_app_site_association' | 'android_asset_links';

export interface AppLinkAsset {
	identifier: string;
	domain: string | null;
	isWildcard: boolean;
	source: AppLinkSource;
}

export interface AppLinkEvidence {
	source: AppLinkSource;
	appId: string | null;
}

export interface AppLinkCandidate {
	domain: string;
	confidence: 1;
	evidence: AppLinkEvidence;
}

export interface AppLinksResult {
	seedDomain: string;
	coOwnedDomains: AppLinkCandidate[];
	queryStatus: 'ok' | 'partial' | 'failed';
	wildcardScopes: string[];
	fetchedSources: AppLinkSource[];
	failedSources: AppLinkSource[];
}

export type AppLinksFetchFn = (url: string) => Promise<{ status: number; body: unknown } | null>;

export interface AppLinksOptions {
	fetcher?: AppLinksFetchFn;
}

// ---------------------------------------------------------------------------
// Parsers — pure, tolerant.
// ---------------------------------------------------------------------------

const AppleDetailSchema = z
	.object({
		appID: z.string().optional(),
		appIDs: z.array(z.string()).optional(),
		paths: z.array(z.string()).optional(),
		components: z.array(z.unknown()).optional(),
	})
	.passthrough();

const AppleAasaSchema = z
	.object({
		applinks: z
			.object({
				details: z.array(AppleDetailSchema).default([]),
			})
			.passthrough()
			.optional(),
		webcredentials: z
			.object({
				apps: z.array(z.string()).default([]),
			})
			.passthrough()
			.optional(),
	})
	.passthrough();

/**
 * Parse an Apple `apple-app-site-association` payload.
 *
 * Returns the app IDs (`team.bundle`) and an empty domain field — AASA doesn't
 * embed sibling-domain lists; the file's *location* is the proof that the
 * fetched host is brand-claimed. The orchestrator wraps the seed host as a
 * confirmed candidate.
 */
export function parseAppleAasa(raw: unknown): { appIds: string[]; hasApplinks: boolean } {
	const parsed = AppleAasaSchema.safeParse(raw);
	if (!parsed.success) return { appIds: [], hasApplinks: false };
	const data = parsed.data;
	const ids = new Set<string>();
	for (const d of data.applinks?.details ?? []) {
		if (d.appID) ids.add(d.appID);
		for (const id of d.appIDs ?? []) ids.add(id);
	}
	for (const id of data.webcredentials?.apps ?? []) ids.add(id);
	return { appIds: Array.from(ids).sort(), hasApplinks: Boolean(data.applinks) };
}

const AssetLinkStatementSchema = z
	.object({
		relation: z.array(z.string()).default([]),
		target: z
			.object({
				namespace: z.string().optional(),
				site: z.string().optional(),
				package_name: z.string().optional(),
			})
			.passthrough(),
	})
	.passthrough();

const AssetLinksFileSchema = z.array(AssetLinkStatementSchema).default([]);

/**
 * Parse an Android `assetlinks.json` payload.
 *
 * Statements with `target.namespace=web` declare an associated web domain.
 * Statements with `target.namespace=android_app` link an Android package; we
 * surface both — the package name becomes evidence on the seed-host candidate.
 */
export function parseAssetLinks(raw: unknown): {
	webSites: string[];
	androidPackages: string[];
} {
	const parsed = AssetLinksFileSchema.safeParse(raw);
	if (!parsed.success) return { webSites: [], androidPackages: [] };
	const sites = new Set<string>();
	const pkgs = new Set<string>();
	for (const stmt of parsed.data) {
		const t = stmt.target;
		if (t.namespace === 'web' && t.site) {
			const host = extractHost(t.site);
			if (host) sites.add(host);
		} else if (t.namespace === 'android_app' && t.package_name) {
			pkgs.add(t.package_name);
		}
	}
	return { webSites: Array.from(sites).sort(), androidPackages: Array.from(pkgs).sort() };
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

const AASA_PATH = '/.well-known/apple-app-site-association';
const ASSETLINKS_PATH = '/.well-known/assetlinks.json';

/** Per-fetch wall budget. The detector runs inside the 300s consumer cap
 * alongside ~12 downstream signal probes — every external fetch here must
 * time out fast. 404 is the common case for non-app brands; a 5s ceiling on
 * the others preserves budget for the rest of the audit. */
const APP_LINKS_FETCH_TIMEOUT_MS = 5000;

async function defaultFetcher(url: string): Promise<{ status: number; body: unknown } | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), APP_LINKS_FETCH_TIMEOUT_MS);
	try {
		const res = await fetch(url, {
			redirect: 'manual',
			headers: { accept: 'application/json' },
			signal: controller.signal,
		});
		let body: unknown = null;
		try {
			body = await res.json();
		} catch {
			body = null;
		}
		return { status: res.status, body };
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

export async function detectAppLinks(
	seedDomain: string,
	options: AppLinksOptions = {},
): Promise<AppLinksResult> {
	const fetcher = options.fetcher ?? defaultFetcher;
	const seed = seedDomain.toLowerCase().replace(/\.$/, '');
	const candidates = new Map<string, AppLinkCandidate>();
	const wildcards = new Set<string>();
	const fetched: AppLinkSource[] = [];
	const failed: AppLinkSource[] = [];

	const aasaRes = await fetcher(`https://${seed}${AASA_PATH}`);
	if (aasaRes && aasaRes.status < 400) {
		const { appIds, hasApplinks } = parseAppleAasa(aasaRes.body);
		fetched.push('apple_app_site_association');
		if (hasApplinks) {
			candidates.set(seed, {
				domain: seed,
				confidence: 1,
				evidence: { source: 'apple_app_site_association', appId: appIds[0] ?? null },
			});
		}
	} else if (aasaRes && aasaRes.status === 404) {
		// 404 is the common case (seed has no app). Treat as success-with-empty.
		fetched.push('apple_app_site_association');
	} else {
		failed.push('apple_app_site_association');
	}

	const alRes = await fetcher(`https://${seed}${ASSETLINKS_PATH}`);
	if (alRes && alRes.status < 400) {
		const { webSites, androidPackages } = parseAssetLinks(alRes.body);
		fetched.push('android_asset_links');
		// Web sites declared in assetlinks are sibling domains the brand publishes.
		for (const site of webSites) {
			if (site === seed) continue;
			if (site.startsWith('*.')) {
				wildcards.add(site.slice(2));
				continue;
			}
			if (!candidates.has(site)) {
				candidates.set(site, {
					domain: site,
					confidence: 1,
					evidence: { source: 'android_asset_links', appId: androidPackages[0] ?? null },
				});
			}
		}
		// The seed itself is confirmed if it served an assetlinks file at all.
		if (androidPackages.length > 0 && !candidates.has(seed)) {
			candidates.set(seed, {
				domain: seed,
				confidence: 1,
				evidence: { source: 'android_asset_links', appId: androidPackages[0] },
			});
		}
	} else if (alRes && alRes.status === 404) {
		fetched.push('android_asset_links');
	} else {
		failed.push('android_asset_links');
	}

	let queryStatus: AppLinksResult['queryStatus'];
	if (fetched.length === 0) queryStatus = 'failed';
	else if (failed.length > 0) queryStatus = 'partial';
	else queryStatus = 'ok';

	return {
		seedDomain: seed,
		coOwnedDomains: Array.from(candidates.values()).sort((a, b) => a.domain.localeCompare(b.domain)),
		queryStatus,
		wildcardScopes: Array.from(wildcards).sort(),
		fetchedSources: fetched,
		failedSources: failed,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractHost(value: string): string | null {
	const trimmed = value.trim();
	if (!trimmed) return null;
	try {
		const withProto = /^[a-z]+:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
		const url = new URL(withProto);
		return url.hostname.toLowerCase() || null;
	} catch {
		const naive = trimmed.toLowerCase().split('/')[0].split(':')[0];
		return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(naive) ? naive : null;
	}
}
