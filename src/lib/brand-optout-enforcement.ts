// SPDX-License-Identifier: BUSL-1.1

/**
 * Consumer-side opt-out enforcement filter for brand discovery.
 *
 * Third defensive layer (after `bv-infrastructure-graph` and `bv-intel-gateway`
 * source-side filters). Even if both upstream layers miss an opted-out apex,
 * bv-mcp redacts it here before surfacing.
 *
 * Pure logic: no Cloudflare bindings or network calls. The opt-out fetcher is
 * injected so the consumer (a tool or pipeline) wires it to a service binding
 * or KV later. This keeps the filter fully testable in isolation.
 *
 * Cache: module-scoped, 5-minute TTL on the fetched opt-out set.
 */

/** Cached opt-out set TTL in milliseconds (5 minutes). */
const OPTOUT_CACHE_TTL_MS = 5 * 60 * 1000;

interface OptoutCacheEntry {
	readonly domains: ReadonlySet<string>;
	readonly expiresAt: number;
}

let cache: OptoutCacheEntry | null = null;

/**
 * Result of applying the consumer-side opt-out filter to a candidate list.
 *
 * `filtered` preserves the original candidate strings (including their casing
 * and surrounding whitespace) for entries that survive the filter. Only the
 * comparison itself is case-insensitive and whitespace-trimmed.
 */
export interface OptoutFilterResult {
	readonly filtered: string[];
	readonly redactedCount: number;
}

/** Function type for the injected opt-out fetcher. */
export type OptoutFetcher = () => Promise<Set<string>>;

/**
 * Normalise a domain for comparison: trim surrounding whitespace and lowercase.
 *
 * Aligns with the design rule that apex comparison must be case-insensitive
 * and resilient to trivial input noise.
 */
function normaliseApex(domain: string): string {
	return domain.trim().toLowerCase().replace(/\.$/, '');
}

async function loadOptoutSet(fetcher: OptoutFetcher): Promise<ReadonlySet<string>> {
	const now = Date.now();
	if (cache && cache.expiresAt > now) {
		return cache.domains;
	}

	const raw = await fetcher();
	const normalised = new Set<string>();
	for (const entry of raw) {
		normalised.add(normaliseApex(entry));
	}

	cache = {
		domains: normalised,
		expiresAt: now + OPTOUT_CACHE_TTL_MS,
	};
	return cache.domains;
}

/**
 * Filter a candidate list against the opt-out set produced by `fetcher`.
 *
 * The opt-out set is cached module-wide for 5 minutes. After the TTL expires
 * the fetcher is invoked again on the next call.
 */
export async function applyOptoutFilter(
	candidates: string[],
	fetcher: OptoutFetcher,
): Promise<OptoutFilterResult> {
	if (candidates.length === 0) {
		return { filtered: [], redactedCount: 0 };
	}

	const optouts = await loadOptoutSet(fetcher);

	if (optouts.size === 0) {
		return { filtered: [...candidates], redactedCount: 0 };
	}

	const filtered: string[] = [];
	let redactedCount = 0;
	for (const candidate of candidates) {
		if (optouts.has(normaliseApex(candidate))) {
			redactedCount += 1;
			continue;
		}
		filtered.push(candidate);
	}

	return { filtered, redactedCount };
}

/**
 * Test-only hook to reset the module-scoped opt-out cache.
 *
 * Not exported from any production entrypoint; consumed only by Vitest specs
 * that need a clean cache between cases.
 */
export function __resetOptoutCacheForTests(): void {
	cache = null;
}
