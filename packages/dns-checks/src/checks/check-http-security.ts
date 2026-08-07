// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeSecurityHeaders } from './http-security-analysis';
import { SCANNER_USER_AGENT, RobotsDisallowedError } from '../robots-gate';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/** Maximum redirect hops to follow */
const MAX_REDIRECT_HOPS = 3;

/**
 * Follow redirects manually to get the final response with security headers.
 * Redirect responses (e.g., nist.gov → www.nist.gov) typically lack security
 * headers, causing false negatives if we analyze the 301 instead of the 200.
 *
 * Handles Cloudflare Workers opaque redirect responses (status 0) and standard
 * 3xx redirects. Only follows HTTPS redirects (no protocol downgrade).
 *
 * SSRF note (H3 fix, 2026-05-08): the redirect target hostname is attacker-
 * controlled (it's whatever the origin's `Location:` header says). Callers must
 * pass a `fetchFn` that validates the destination before issuing the request —
 * the bv-mcp Worker passes `safeFetch` which gates the URL via
 * validateOutboundUrl(). Embedders that pass raw `fetch` are responsible for
 * their own SSRF protection.
 */
async function followRedirects(
	response: Response,
	fetchFn: FetchFunction,
	timeoutMs: number,
): Promise<Response> {
	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const status = response.status;
		const isRedirect = (status >= 300 && status < 400) || response.type === 'opaqueredirect' || (status === 0 && response.headers.get('location'));
		if (!isRedirect) break;

		const location = response.headers.get('location');
		if (!location) break;

		let nextUrl: string;
		try {
			nextUrl = new URL(location, response.url || undefined).href;
		} catch {
			break;
		}

		// Only follow HTTPS redirects
		if (!nextUrl.startsWith('https://')) break;

		try {
			// Release the body of the response we're about to abandon (e.g. a GET
			// fallback that itself redirects) so workerd doesn't cancel a stalled stream.
			void response.body?.cancel();
			response = await fetchFn(nextUrl, {
				method: 'HEAD',
				redirect: 'manual',
				headers: { 'User-Agent': SCANNER_USER_AGENT },
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch {
			// Includes SSRF rejection from a safeFetch wrapper — fall out of the
			// redirect loop and let analysis run with whatever headers we already
			// have, treating the hostile redirect target as a network failure.
			break;
		}
	}

	return response;
}

/**
 * Attempt a GET request as fallback when HEAD is blocked (403/405).
 * Returns null on any fetch error.
 */
async function tryGetFallback(url: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Response | null> {
	try {
		return await fetchFn(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch {
		return null;
	}
}

/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkHTTPSecurity(
	domain: string,
	fetchFn: FetchFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];
	// Set when the headers could not actually be evaluated (inconclusive execution, not a real
	// header gap). The scoring engine treats checkStatus 'timeout'/'error' as a transient failure
	// and EXCLUDES the category from scoring (renormalized) rather than zeroing it — so a flaky
	// fetch can't make the overall score fluctuate between a real value and 0.
	let inconclusive: 'timeout' | 'error' | undefined;
	// Set on every branch where THE PROBE NEVER COMPLETED, so no header was ever observed:
	// the WAF/appliance block, the 401, the residual 4xx, and the connection failure/timeout.
	// All four used to stamp their finding with `missingControl: true` — but that flag means
	// "we measured, and the control is ABSENT", which none of them established (issue #638).
	// The flag was doing double duty: it was ALSO the only thing forcing the score-0 /
	// passed-false shape, so dropping it alone would let these findings compute to a PASS
	// (an `info` finding → 100/passed, a `medium` → 85/passed) — i.e. an unmeasured check
	// reported as a clean one, the opposite defect. The zeroing is therefore expressed
	// directly here, with no false claim of absence attached.
	//
	// The `checkStatus` set alongside is what makes the scoring engine EXCLUDE the category
	// rather than score the 0 — see `transientFailures` in scoring/engine.ts.
	//
	// Deliberately NOT set on the two other `inconclusive` branches, which never carried
	// `missingControl` and so are not part of this defect:
	//   - the 5xx "Server error" branch — the origin WAS reached and answered (score 85);
	//   - the robots.txt skip — a voluntary abstention, not a failed probe (score 100).
	// Generalising "inconclusive ⇒ zero" would silently rescore both. It is scoped to the
	// branches that made the contradictory claim.
	let unmeasuredZero = false;

	try {
		let response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});

		// Follow redirects to get the final destination's headers
		response = await followRedirects(response, fetchFn, timeoutMs);

		if (response.ok) {
			// 200-299: analyze headers normally
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 0 || response.status >= 500) {
			inconclusive = 'error';
			findings.push(
				createFinding(
					'http_security',
					'Server error',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
				),
			);
		} else if (response.status >= 300 && response.status < 400) {
			// Still a redirect after max hops — analyze whatever headers we have
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 403 || response.status === 405) {
			// WAF block or HEAD not allowed — retry with GET to get real headers
			const getResponse = await tryGetFallback(`https://${domain}`, fetchFn, timeoutMs);
			if (getResponse && (getResponse.ok || (getResponse.status >= 300 && getResponse.status < 400))) {
				const followed = await followRedirects(getResponse, fetchFn, timeoutMs);
				findings.push(...analyzeSecurityHeaders(followed.headers));
				// GET fallback returns a real body we never read (followRedirects only
				// cancels it when it redirects); release it so workerd doesn't cancel a
				// stalled stream.
				void followed.body?.cancel();
			} else {
				inconclusive = 'error';
				unmeasuredZero = true;
				findings.push(
					createFinding(
						'http_security',
						'HTTP check blocked by security appliance',
						'info',
						`The site returned HTTP ${response.status} for ${domain}. A WAF or firewall is blocking external header inspection. Security headers cannot be verified.`,
						// No `missingControl` (issue #638) — a blocked probe measured nothing, so it must not
						// also claim the control is absent. `inconclusive: true` is the honest marker; the
						// score-0/passed-false shape is applied via `unmeasuredZero` at the return below.
						{ inconclusive: true },
					),
				);
			}
		} else if (response.status === 401) {
			inconclusive = 'error';
			unmeasuredZero = true;
			findings.push(
				createFinding(
					'http_security',
					'HTTP check requires authentication',
					'info',
					`The site returned HTTP 401 for ${domain}. The endpoint requires authentication; security headers cannot be verified externally.`,
					// No `missingControl` (issue #638) — an auth-gated endpoint refused the probe, which
					// says nothing about whether the headers exist behind it. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		} else {
			// Other 4xx (404, 429, etc.) — blocked or rejected
			inconclusive = 'error';
			unmeasuredZero = true;
			findings.push(
				createFinding(
					'http_security',
					'HTTP request rejected',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
					// No `missingControl` (issue #638) — the request was rejected before any header was
					// observed. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		}
	} catch (err) {
		if (err instanceof RobotsDisallowedError) {
			inconclusive = 'error';
			findings.push(
				createFinding(
					'http_security',
					'HTTP security check skipped (robots.txt)',
					'info',
					`${domain}'s robots.txt disallows BlackVeil-Security-Scanner, so HTTP security headers could not be independently verified. Not scored — see https://www.blackveilsecurity.com/bot-policy.`,
				),
			);
		} else {
			// AbortSignal.timeout throws a DOMException named 'TimeoutError' (message "The operation
			// timed out"); also match abort/timeout phrasings from other runtimes.
			const e = err as { name?: string; message?: string };
			const isTimeout = e?.name === 'TimeoutError' || /timed?\s*out|abort|timeout/i.test(e?.message ?? '');
			inconclusive = isTimeout ? 'timeout' : 'error';
			unmeasuredZero = true;
			const message = isTimeout ? 'Connection timed out' : 'Connection failed';
			findings.push(
				createFinding(
					'http_security',
					`HTTPS ${message.toLowerCase()}`,
					'medium',
					`Could not fetch https://${domain} to check security headers: ${message}.`,
					// No `missingControl` (issue #638) — the connection never delivered a response, so
					// nothing about the headers was established. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		}
	}

	const base = buildCheckResult('http_security', findings);
	// Preserves the exact score-0/passed-false shape the removed `missingControl` flags used to
	// produce on the four never-completed-probe paths, without asserting the control is absent
	// (issue #638).
	const result = unmeasuredZero ? { ...base, score: 0, passed: false } : base;
	return inconclusive ? { ...result, checkStatus: inconclusive } : result;
}
