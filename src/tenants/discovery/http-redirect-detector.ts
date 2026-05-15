// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP-redirect ownership detector.
 *
 * For each caller-asserted candidate, follow up to `maxHops` HTTP redirects
 * starting at `https://<candidate>/`. If the chain terminates at the seed's
 * apex or any subdomain of the seed, treat as near-deterministic ownership
 * evidence — defensive ccTLD registrations almost universally 301-redirect
 * to the canonical brand site.
 *
 * Failure modes (timeouts, non-redirect responses, fetch throws) record
 * silently per candidate; the overall queryStatus stays `ok` so a few flaky
 * candidates don't poison the whole signal.
 */

import { safeFetch } from '../../lib/safe-fetch';
import { validateDomain } from '../../lib/sanitize';

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_HOPS = 3;
const DEFAULT_CONFIDENCE = 0.95;

export interface HttpRedirectOptions {
	/** Caller-asserted candidate domains to probe. */
	candidateDomains: string[];
	/** Override fetch (test hook). Defaults to safeFetch. */
	fetchFn?: typeof fetch;
	/** Max redirect hops to follow. Defaults to 3. */
	maxHops?: number;
	/** Per-fetch timeout in ms. Defaults to 5000. */
	timeoutMs?: number;
}

export interface HttpRedirectResult {
	coOwnedDomains: Array<{
		domain: string;
		confidence: number;
		evidence: { finalUrl: string; hops: number };
	}>;
	queryStatus: 'ok' | 'error';
}

/**
 * True if `host` is the seed apex or a subdomain of the seed.
 */
function alignsWithSeed(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return h === s || h.endsWith('.' + s);
}

/**
 * Follow up to `maxHops` redirects starting at the candidate's HTTPS apex.
 * Returns `{ finalUrl, hops }` on success, `null` on any error.
 */
async function followChain(
	candidate: string,
	fetchFn: typeof fetch,
	maxHops: number,
	timeoutMs: number,
): Promise<{ finalUrl: string; hops: number } | null> {
	let url = `https://${candidate}/`;
	let hops = 0;
	const seenUrls = new Set<string>();

	while (hops < maxHops) {
		if (seenUrls.has(url)) return null; // loop detected
		seenUrls.add(url);

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

		let response: Response;
		try {
			response = await fetchFn(url, {
				method: 'HEAD',
				redirect: 'manual',
				signal: controller.signal,
			});
		} catch {
			clearTimeout(timeoutId);
			return null;
		}
		clearTimeout(timeoutId);

		const status = response.status;
		if (status >= 300 && status < 400) {
			const loc = response.headers.get('Location') ?? response.headers.get('location');
			if (!loc) return null;
			// Resolve relative URLs
			let nextUrl: string;
			try {
				nextUrl = new URL(loc, url).href;
			} catch {
				return null;
			}
			url = nextUrl;
			hops++;
			continue;
		}

		// Non-redirect terminal response — the current URL's hostname is where we landed.
		return { finalUrl: url, hops };
	}

	// Hit maxHops without terminating
	return null;
}

/**
 * Run HTTP-redirect detection across the caller-asserted candidate list.
 * Candidates are probed in parallel with `Promise.allSettled` so a few
 * timeouts don't block the rest.
 */
export async function detectHttpRedirect(
	seedDomain: string,
	options: HttpRedirectOptions,
): Promise<HttpRedirectResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}

	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const fetchFn = options.fetchFn ?? safeFetch;
	const maxHops = options.maxHops ?? DEFAULT_MAX_HOPS;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const candidates = options.candidateDomains;

	if (candidates.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const settled = await Promise.allSettled(
		candidates.map(async (cand) => {
			const candLower = cand.trim().toLowerCase().replace(/\.$/, '');
			if (!validateDomain(candLower).valid) return null;
			const chain = await followChain(candLower, fetchFn, maxHops, timeoutMs);
			if (!chain) return null;
			let host: string;
			try {
				host = new URL(chain.finalUrl).hostname;
			} catch {
				return null;
			}
			if (!alignsWithSeed(host, seedLower)) return null;
			return {
				domain: candLower,
				confidence: DEFAULT_CONFIDENCE,
				evidence: { finalUrl: chain.finalUrl, hops: chain.hops },
			};
		}),
	);

	const coOwnedDomains = settled
		.filter((r): r is PromiseFulfilledResult<NonNullable<Awaited<ReturnType<typeof followChain>>> & { domain: string; confidence: number; evidence: { finalUrl: string; hops: number } }> => r.status === 'fulfilled' && r.value !== null)
		.map((r) => r.value);

	return { coOwnedDomains, queryStatus: 'ok' };
}
