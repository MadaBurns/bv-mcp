// SPDX-License-Identifier: BUSL-1.1

/**
 * Bug-bounty scope detector (Phase-5 brand-discovery, ground-truth signal).
 *
 * Public bug-bounty platforms (HackerOne, Bugcrowd, Intigriti) publish the
 * domains a brand has *explicitly* declared in scope for security testing.
 * That declaration is brand-authoritative — strongest possible ownership
 * signal, equivalent to a registrar API saying "we manage these."
 *
 * Returns scope domains as `coOwnedDomains` with confidence=1.0. Wildcard
 * scopes (`*.brand.com`) are surfaced separately because they expand the
 * candidate-universe search space rather than naming concrete domains.
 *
 * Failure convention (per project): NEVER throw on network errors. Surface
 * via `queryStatus`.
 */

import { z } from 'zod';

export type BountyPlatform = 'hackerone' | 'bugcrowd' | 'intigriti';

export interface BountyScopeAsset {
	/** Raw identifier as published by the platform. */
	identifier: string;
	/** Extracted host, or `null` if the identifier isn't a URL/host. */
	domain: string | null;
	/** True for `*.brand.com` style entries. */
	isWildcard: boolean;
	/** True when the platform marks this asset as in-scope. */
	inScope: boolean;
	/** Coarse classification — drives downstream handling. */
	assetType: 'url' | 'wildcard' | 'cidr' | 'app_store' | 'other';
	platform: BountyPlatform;
}

export interface BountyScopeEvidence {
	platform: BountyPlatform;
	programHandle: string;
	assetType: BountyScopeAsset['assetType'];
}

export interface BountyScopeCandidate {
	domain: string;
	confidence: 1;
	evidence: BountyScopeEvidence;
}

/**
 * Conforms to {@link StrictDiscoverySignalResultSchema} at runtime (asserted
 * in `bounty-scope-detector.test.ts` and `discovery-signals.contract.test.ts`).
 * Not declared as a TS extension because Zod `.passthrough()` introduces an
 * index signature that our typed candidate shape doesn't satisfy structurally.
 */
export interface BountyScopeResult {
	seedDomain: string;
	coOwnedDomains: BountyScopeCandidate[];
	queryStatus: 'ok' | 'partial' | 'failed';
	/** Wildcard scopes (`*.brand.com`) — surfaced separately, not added to candidates. */
	wildcardScopes: string[];
	/** Asset identifiers marked out-of-scope (telemetry only). */
	outOfScopeDomains: string[];
	/** Platforms successfully queried. */
	fetchedPlatforms: BountyPlatform[];
	/** Platforms that failed (4xx, 5xx, network) — drives `partial` vs `ok`. */
	failedPlatforms: BountyPlatform[];
}

export type BountyFetchFn = (url: string) => Promise<{ status: number; body: unknown } | null>;

export interface BountyScopeOptions {
	/**
	 * Per-platform program handle for the seed brand. Without a handle the
	 * detector has nothing to query for that platform.
	 */
	handles: Partial<Record<BountyPlatform, string>>;
	/** Injectable fetcher — defaults to a real `fetch` wrapper. */
	fetcher?: BountyFetchFn;
}

// ---------------------------------------------------------------------------
// Parsers — pure functions, easy to unit test. Tolerant of shape drift: skip
// records they don't understand rather than throwing.
// ---------------------------------------------------------------------------

const HackerOneAssetSchema = z
	.object({
		asset_identifier: z.string().min(1),
		asset_type: z.string().min(1),
		eligible_for_submission: z.boolean().optional(),
	})
	.passthrough();
const HackerOneScopesSchema = z.array(HackerOneAssetSchema).default([]);

/** Parse a HackerOne `<handle>.json` payload's structured scope array. */
export function parseHackerOneScope(raw: unknown): BountyScopeAsset[] {
	// HackerOne nests scopes under `structured_scopes` on the program object,
	// but some older responses return the array directly. Tolerate both.
	let candidates: unknown = raw;
	if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
		const obj = raw as Record<string, unknown>;
		candidates = obj.structured_scopes ?? obj.scopes ?? raw;
	}
	const parsed = HackerOneScopesSchema.safeParse(candidates);
	if (!parsed.success) return [];

	const out: BountyScopeAsset[] = [];
	for (const entry of parsed.data) {
		const inScope = entry.eligible_for_submission !== false;
		const id = entry.asset_identifier.trim();
		const type = entry.asset_type.toUpperCase();
		if (type === 'URL') {
			const host = extractHost(id);
			out.push({ identifier: id, domain: host, isWildcard: false, inScope, assetType: 'url', platform: 'hackerone' });
		} else if (type === 'WILDCARD') {
			const host = stripWildcardPrefix(id);
			out.push({ identifier: id, domain: host, isWildcard: true, inScope, assetType: 'wildcard', platform: 'hackerone' });
		} else if (type === 'CIDR' || type === 'IP_ADDRESS') {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'cidr', platform: 'hackerone' });
		} else if (/APP|APPLE|GOOGLE/.test(type)) {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'app_store', platform: 'hackerone' });
		} else {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'other', platform: 'hackerone' });
		}
	}
	return out;
}

const BugcrowdTargetSchema = z
	.object({
		name: z.string().min(1),
		category: z.string().min(1).optional(),
		target_type: z.string().optional(),
		in_scope: z.boolean().optional(),
	})
	.passthrough();
const BugcrowdTargetsSchema = z.array(BugcrowdTargetSchema).default([]);

/** Parse a Bugcrowd public scope payload (`targets` array). */
export function parseBugcrowdScope(raw: unknown): BountyScopeAsset[] {
	let candidates: unknown = raw;
	if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
		const obj = raw as Record<string, unknown>;
		candidates = obj.targets ?? obj.in_scope ?? raw;
	}
	const parsed = BugcrowdTargetsSchema.safeParse(candidates);
	if (!parsed.success) return [];

	const out: BountyScopeAsset[] = [];
	for (const entry of parsed.data) {
		const inScope = entry.in_scope ?? entry.target_type !== 'out_of_scope';
		const id = entry.name.trim();
		const cat = (entry.category ?? '').toLowerCase();
		if (cat === 'website' || cat === 'api') {
			if (id.startsWith('*.')) {
				out.push({ identifier: id, domain: stripWildcardPrefix(id), isWildcard: true, inScope, assetType: 'wildcard', platform: 'bugcrowd' });
			} else {
				out.push({ identifier: id, domain: extractHost(id), isWildcard: false, inScope, assetType: 'url', platform: 'bugcrowd' });
			}
		} else if (cat === 'mobile' || cat === 'android' || cat === 'ios') {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'app_store', platform: 'bugcrowd' });
		} else {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'other', platform: 'bugcrowd' });
		}
	}
	return out;
}

const IntigritiAssetSchema = z
	.object({
		endpoint: z.string().min(1).optional(),
		identifier: z.string().min(1).optional(),
		type: z.string().min(1).optional(),
		tier: z.string().optional(),
	})
	.passthrough();
const IntigritiAssetsSchema = z.array(IntigritiAssetSchema).default([]);

/** Parse an Intigriti `domains` / `assets` array. */
export function parseIntigritiScope(raw: unknown): BountyScopeAsset[] {
	let candidates: unknown = raw;
	if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
		const obj = raw as Record<string, unknown>;
		candidates = obj.domains ?? obj.assets ?? obj.targets ?? raw;
	}
	const parsed = IntigritiAssetsSchema.safeParse(candidates);
	if (!parsed.success) return [];

	const out: BountyScopeAsset[] = [];
	for (const entry of parsed.data) {
		const id = (entry.endpoint ?? entry.identifier ?? '').trim();
		if (!id) continue;
		const type = (entry.type ?? '').toLowerCase();
		// Intigriti `tier === 'out_of_scope'` is the disqualifier when present.
		const inScope = entry.tier !== 'out_of_scope';
		if (id.startsWith('*.')) {
			out.push({ identifier: id, domain: stripWildcardPrefix(id), isWildcard: true, inScope, assetType: 'wildcard', platform: 'intigriti' });
		} else if (type === 'cidr' || type === 'ip') {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'cidr', platform: 'intigriti' });
		} else if (type.includes('app')) {
			out.push({ identifier: id, domain: null, isWildcard: false, inScope, assetType: 'app_store', platform: 'intigriti' });
		} else {
			out.push({ identifier: id, domain: extractHost(id), isWildcard: false, inScope, assetType: 'url', platform: 'intigriti' });
		}
	}
	return out;
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

const PLATFORM_URLS: Record<BountyPlatform, (handle: string) => string> = {
	hackerone: (h) => `https://hackerone.com/${encodeURIComponent(h)}.json`,
	bugcrowd: (h) => `https://bugcrowd.com/${encodeURIComponent(h)}.json`,
	intigriti: (h) => `https://api.intigriti.com/external/researcher/program/${encodeURIComponent(h)}`,
};

const PLATFORM_PARSERS: Record<BountyPlatform, (raw: unknown) => BountyScopeAsset[]> = {
	hackerone: parseHackerOneScope,
	bugcrowd: parseBugcrowdScope,
	intigriti: parseIntigritiScope,
};

/** Per-fetch wall budget. The detector runs inside the 300s consumer cap
 * alongside ~12 downstream signal probes — every external fetch here must
 * time out fast to preserve the budget. A slow / unresponsive bounty
 * platform loses its scope contribution for this audit but never wedges it. */
const BOUNTY_FETCH_TIMEOUT_MS = 5000;

async function defaultFetcher(url: string): Promise<{ status: number; body: unknown } | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), BOUNTY_FETCH_TIMEOUT_MS);
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

export async function detectBountyScope(
	seedDomain: string,
	options: BountyScopeOptions,
): Promise<BountyScopeResult> {
	const fetcher = options.fetcher ?? defaultFetcher;
	const seed = seedDomain.toLowerCase().replace(/\.$/, '');

	const allCandidates = new Map<string, BountyScopeCandidate>();
	const wildcards = new Set<string>();
	const outOfScope = new Set<string>();
	const fetched: BountyPlatform[] = [];
	const failed: BountyPlatform[] = [];
	let programHandle: string | null = null;

	const platforms: BountyPlatform[] = ['hackerone', 'bugcrowd', 'intigriti'];
	for (const platform of platforms) {
		const handle = options.handles[platform];
		if (!handle) continue;
		programHandle = programHandle ?? handle;
		const url = PLATFORM_URLS[platform](handle);
		const response = await fetcher(url);
		if (!response || response.status >= 400) {
			failed.push(platform);
			continue;
		}
		const assets = PLATFORM_PARSERS[platform](response.body);
		fetched.push(platform);
		for (const asset of assets) {
			if (!asset.inScope) {
				if (asset.domain) outOfScope.add(asset.domain);
				continue;
			}
			if (asset.isWildcard && asset.domain) {
				wildcards.add(asset.domain);
				continue;
			}
			if (asset.domain && !allCandidates.has(asset.domain)) {
				allCandidates.set(asset.domain, {
					domain: asset.domain,
					confidence: 1,
					evidence: {
						platform: asset.platform,
						programHandle: handle,
						assetType: asset.assetType,
					},
				});
			}
		}
	}

	let queryStatus: BountyScopeResult['queryStatus'];
	if (fetched.length === 0) queryStatus = 'failed';
	else if (failed.length > 0) queryStatus = 'partial';
	else queryStatus = 'ok';

	return {
		seedDomain: seed,
		coOwnedDomains: Array.from(allCandidates.values()).sort((a, b) => a.domain.localeCompare(b.domain)),
		queryStatus,
		wildcardScopes: Array.from(wildcards).sort(),
		outOfScopeDomains: Array.from(outOfScope).sort(),
		fetchedPlatforms: fetched,
		failedPlatforms: failed,
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
		const host = url.hostname.toLowerCase();
		return host || null;
	} catch {
		// Fall back to a naive parse for bare hostnames the URL constructor rejects.
		const naive = trimmed.toLowerCase().split('/')[0].split(':')[0];
		return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(naive) ? naive : null;
	}
}

function stripWildcardPrefix(value: string): string | null {
	const trimmed = value.trim().toLowerCase().replace(/^\*\./, '');
	return extractHost(trimmed);
}
