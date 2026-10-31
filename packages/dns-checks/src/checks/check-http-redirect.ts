// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction } from '../types';
import { buildCheckResult, buildNotAssessedResult, sanitizeDnsData } from '../check-utils';
import { SCANNER_USER_AGENT } from '../robots-gate';
import { analyzeHttpRedirects, MAX_REDIRECT_HOPS, notAssessedFinding, nothingMeasured } from './http-redirect-analysis';
import type { HostWalk, RedirectChain, RedirectStep } from './http-redirect-analysis';

/** Time budget (ms) for each chain, all of its requests included, when the caller sets none. */
const DEFAULT_TIMEOUT_MS = 5_000;

export interface CheckHttpRedirectOptions {
	/** Time budget (ms) for each redirect chain. Default 5000. */
	timeout?: number;
}

/**
 * The absolute http(s) URL a response redirects to, or `null` when it is not a followable
 * redirect: not a 3xx (status 0 is the opaque redirect some runtimes return), no `Location`, or a
 * target that is not http(s). A relative `Location` resolves against the URL that was requested.
 */
function redirectTarget(response: Response, requestUrl: string): string | null {
	const location = response.headers.get('location');
	const redirects = response.status === 0 || (response.status >= 300 && response.status < 400);
	if (location === null || !redirects) return null;
	const target = URL.parse(location, response.url || requestUrl);
	return target?.protocol === 'http:' || target?.protocol === 'https:' ? target.href : null;
}

function request(url: string, fetchFn: FetchFunction, deadlineAt: number): Promise<Response> {
	return fetchFn(url, {
		method: 'GET',
		redirect: 'manual',
		headers: { 'User-Agent': SCANNER_USER_AGENT },
		signal: AbortSignal.timeout(Math.max(1, deadlineAt - Date.now())),
	});
}

/**
 * Walk one redirect chain by hand, recording every response. Unlike `fetchPageCapped` this follows
 * `http:` hops too: observing them is the point of the check. Bodies are never read.
 *
 * Returns `null` when the first request fails, so the start URL counts as not measured. A later
 * request that fails ends the chain as `interrupted` and keeps the steps already seen.
 */
async function walkChain(startUrl: string, fetchFn: FetchFunction, timeout: number): Promise<RedirectChain | null> {
	const deadlineAt = Date.now() + timeout;
	const steps: RedirectStep[] = [];
	const visited = new Set<string>();
	let url = startUrl;
	for (;;) {
		visited.add(url);
		let response: Response;
		try {
			response = await request(url, fetchFn, deadlineAt);
		} catch {
			return steps.length === 0 ? null : { startUrl, steps, end: 'interrupted' };
		}
		void response.body?.cancel().catch(() => undefined);
		const next = redirectTarget(response, url);
		steps.push({ url, status: response.status, next });
		if (next === null) return { startUrl, steps, end: 'final' };
		if (visited.has(next)) return { startUrl, steps, end: 'loop' };
		if (steps.length > MAX_REDIRECT_HOPS) return { startUrl, steps, end: 'exhausted' };
		url = next;
	}
}

async function walkHost(label: 'apex' | 'www', hostname: string, fetchFn: FetchFunction, timeout: number): Promise<HostWalk> {
	const [http, https] = await Promise.all([walkChain(`http://${hostname}/`, fetchFn, timeout), walkChain(`https://${hostname}/`, fetchFn, timeout)]);
	return { label, hostname, http, https };
}

/** Compact, sanitized record of one chain for consumers; `null` where the chain was not measured. */
function chainSummary(chain: RedirectChain | null): Record<string, unknown> | null {
	if (chain === null) return null;
	return {
		end: chain.end,
		steps: chain.steps.map((step) => ({ url: sanitizeDnsData(step.url), status: step.status })),
	};
}

function resultMetadata(apex: HostWalk, www: HostWalk): Record<string, unknown> {
	return {
		apex: { http: chainSummary(apex.http), https: chainSummary(apex.https) },
		www: { http: chainSummary(www.http), https: chainSummary(www.https) },
	};
}

/**
 * Non-scoring HTTP redirect check: where `http://` and `https://` on the apex and on `www` lead,
 * and whether the two hosts agree.
 *
 * A host that cannot be fetched is reported as not assessed, never as a missing redirect. When no
 * request on either host gets an answer, the whole result is the not-assessed shape.
 */
export async function checkHttpRedirect(domain: string, fetchFn: FetchFunction, options?: CheckHttpRedirectOptions): Promise<CheckResult> {
	const host = domain.toLowerCase();
	const timeout = options?.timeout ?? DEFAULT_TIMEOUT_MS;
	const [apex, www] = await Promise.all([walkHost('apex', host, fetchFn, timeout), walkHost('www', `www.${host}`, fetchFn, timeout)]);
	if (nothingMeasured(apex, www)) {
		return buildNotAssessedResult('http_redirect', notAssessedFinding('HTTP redirects not assessed', `neither ${host} nor www.${host} could be fetched`, 'fetch_failed'));
	}
	return buildCheckResult('http_redirect', analyzeHttpRedirects(apex, www), undefined, undefined, resultMetadata(apex, www));
}
